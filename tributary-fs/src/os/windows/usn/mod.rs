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

use decode::{UsnName, UsnRecord};
use map::{FrnMap, LearnOutcome};

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
  pub(self) cap: usize,
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
    // CLOSE itself is session GC, never a reportable fact. The reparse
    // bit is TOPOLOGY: an add-then-remove within one session carries the
    // same bit twice, and suppressing the second would skip the
    // boundary-removed learn-and-walk — so it always passes through (its
    // map actions are safe to re-run).
    (fresh & !reason::CLOSE) | (record.reason & reason::REPARSE_POINT_CHANGE)
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

/// A resolved event target: the subject's root-relative components, or the
/// deepest location the escalation can still name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UsnTarget {
  /// The subject, root-relative (empty = the root itself — a self-event).
  Resolved(Vec<String>),
  /// The subject's name has no Unicode spelling: cover the PARENT.
  EscalateAt(Vec<String>),
}

/// One admitted journal event — membership-checked, map-mutated, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UsnAdmitted {
  /// A single-subject event with its fresh reason bits.
  Single {
    /// The fresh (delta) reason bits.
    delta: u32,
    /// The resolved target.
    target: UsnTarget,
    /// Whether the subject is a directory.
    is_dir: bool,
  },
  /// An in-root rename, both ends resolved.
  Renamed {
    /// The departing end.
    old: UsnTarget,
    /// The arriving end.
    new: UsnTarget,
    /// Whether the subject is a directory.
    is_dir: bool,
  },
  /// The subject IS the root anchor and the record is structural: the
  /// scope's death (delete or rename of the watched root).
  RootDeath,
  /// A directory moved IN from outside the root: its subtree is unmapped
  /// until the source walks it, and the walk window is covered by a located
  /// rescan at the target. The lowering emits the cover; the source runs
  /// the walk (or escalates to a full reseed when it cannot complete).
  MovedInSubtree {
    /// The directory's FRN — the walk's map anchor.
    frn: u128,
    /// The directory's root-relative components — the walk's path anchor
    /// and the rescan's location.
    target: Vec<String>,
  },
  /// The map could no longer stay complete (a live learn overflowed the
  /// directory cap): the source must die rather than go blind.
  MapOverflow,
}

/// The admission state one journal source owns.
#[derive(Debug)]
pub(crate) struct UsnAdmission {
  map: FrnMap,
  sessions: SessionTable,
  pairer: UsnPairer,
}

impl UsnAdmission {
  /// A fresh admission over a seeded map.
  pub(crate) fn new(map: FrnMap, session_cap: usize) -> Self {
    Self {
      map,
      sessions: SessionTable::new(session_cap),
      pairer: UsnPairer::new(),
    }
  }

  /// The map, for the reseed swap.
  pub(crate) fn map_mut(&mut self) -> &mut FrnMap {
    &mut self.map
  }

  /// Whether a rename OLD half is parked (the read-wait bound cue).
  pub(crate) fn holds_old(&self) -> bool {
    self.pairer.holds_old()
  }

  /// Admits one decoded record in journal order, appending admitted events.
  pub(crate) fn admit(&mut self, record: UsnRecord, out: &mut Vec<UsnAdmitted>) {
    let delta = self.sessions.delta(&record);
    let fresh = delta & !reason::FILTERED;
    if fresh == 0 {
      return;
    }
    // The record forwards its FRESH bits only: cumulative masks would
    // re-report every prior session fact on each new record, and structural
    // priority would then eat the genuinely new content bit.
    let record = UsnRecord {
      reason: fresh,
      ..record
    };
    let mut paired = Vec::new();
    self.pairer.push(record, fresh, &mut paired);
    for event in paired {
      self.lower_paired(event, out);
    }
  }

  /// Widows the pairing carry (read boundary / loss barrier / teardown).
  pub(crate) fn flush(&mut self, out: &mut Vec<UsnAdmitted>) {
    let mut paired = Vec::new();
    self.pairer.flush(&mut paired);
    for event in paired {
      self.lower_paired(event, out);
    }
  }

  /// Resets the cumulative-reason history — the reseed boundary's duty.
  /// The cursor jumps across an unobserved interval, so a session's
  /// remembered bits may describe an open that CLOSEd inside the gap; a
  /// post-gap session re-reporting the same bit must not be suppressed.
  pub(crate) fn reset_sessions(&mut self) {
    self.sessions = SessionTable::new(self.sessions.cap);
  }

  fn lower_paired(&mut self, event: UsnEvent, out: &mut Vec<UsnAdmitted>) {
    match event {
      UsnEvent::Single(record) => self.admit_single(record, out),
      UsnEvent::Renamed { old, new } => self.admit_rename(old, new, out),
      // A widowed OLD names an object that LEFT its slot with no arriving
      // end: membership-wise it is a delete (out-of-root moves and deletes
      // are indistinguishable from inside), and the lowering degrades the
      // same way.
      UsnEvent::WidowOld(record) => {
        let synthetic = UsnRecord {
          reason: reason::FILE_DELETE | (record.reason & (reason::MODIFY | reason::ATTRIB)),
          ..record
        };
        self.admit_single(synthetic, out);
      }
      // A widowed NEW arrived from nowhere visible: a create — and for a
      // directory, a MOVE-IN: whatever subtree it carried was never
      // mapped (a startup or reseed cursor can fall between rename
      // halves), so the walk must be demanded like any other arrival.
      UsnEvent::WidowNew(record) => {
        let is_dir = record.is_dir();
        let frn = record.frn;
        let synthetic = UsnRecord {
          reason: reason::FILE_CREATE | (record.reason & (reason::MODIFY | reason::ATTRIB)),
          ..record
        };
        self.admit_single(synthetic, out);
        if is_dir && let Some(components) = self.map.resolve_dir(frn) {
          out.push(UsnAdmitted::MovedInSubtree {
            frn,
            target: components,
          });
        }
      }
    }
  }

  fn admit_single(&mut self, record: UsnRecord, out: &mut Vec<UsnAdmitted>) {
    if self.map.is_root(record.frn) {
      // Structural facts about the root anchor are the scope's death; pure
      // metadata on the root is an ordinary self-event.
      if record.reason & (reason::FILE_DELETE | reason::RENAME_OLD_NAME) != 0 {
        out.push(UsnAdmitted::RootDeath);
        return;
      }
      out.push(UsnAdmitted::Single {
        delta: record.reason,
        target: UsnTarget::Resolved(Vec::new()),
        is_dir: true,
      });
      return;
    }

    // Membership: the parent decides. An unmapped parent is outside the
    // root — dropped, not an error (the superblock-firehose admission).
    let Some(parent_components) = self.map.resolve_dir(record.parent) else {
      return;
    };
    let target = match &record.name {
      UsnName::Utf8(name) => {
        let mut components = parent_components;
        components.push(name.clone());
        UsnTarget::Resolved(components)
      }
      UsnName::Escalate => UsnTarget::EscalateAt(parent_components),
    };

    // Map maintenance BEFORE emission order does not matter here (the map
    // answers membership for LATER records; this record's own resolution
    // used the pre-state), but keeping it adjacent keeps journal order and
    // map state in lockstep.
    if record.is_dir() {
      if record.reason & reason::FILE_CREATE != 0 {
        let UsnName::Utf8(name) = &record.name else {
          // A structural directory whose name the vocabulary cannot carry
          // can never anchor resolvable children: the map cannot stay
          // complete, so the source dies under the root cover.
          out.push(UsnAdmitted::MapOverflow);
          return;
        };
        if self.map.learn(record.frn, record.parent, name.clone()) == LearnOutcome::OverCapacity {
          out.push(UsnAdmitted::MapOverflow);
          return;
        }
      }
      if record.reason & reason::FILE_DELETE != 0 {
        self.map.forget(record.frn);
      }
      if record.reason & reason::REPARSE_POINT_CHANGE != 0 {
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if record.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
          // The directory BECAME a reparse boundary: drop the subtree; the
          // located rescan re-establishes what is really below.
          self.map.forget(record.frn);
        } else {
          // The boundary was REMOVED — an ordinary directory now stands
          // where the map holds nothing: learn the anchor and demand its
          // walk, exactly like a move-in, or the subtree stays blind. A
          // name the vocabulary cannot carry cannot anchor children — map
          // death, never a silent skip.
          let UsnName::Utf8(name) = &record.name else {
            out.push(UsnAdmitted::MapOverflow);
            return;
          };
          if self.map.learn(record.frn, record.parent, name.clone()) == LearnOutcome::OverCapacity {
            out.push(UsnAdmitted::MapOverflow);
            return;
          }
          if let UsnTarget::Resolved(components) = &target {
            out.push(UsnAdmitted::MovedInSubtree {
              frn: record.frn,
              target: components.clone(),
            });
          }
        }
      }
    }

    out.push(UsnAdmitted::Single {
      delta: record.reason,
      target,
      is_dir: record.is_dir(),
    });
  }

  fn admit_rename(&mut self, old: UsnRecord, new: UsnRecord, out: &mut Vec<UsnAdmitted>) {
    if self.map.is_root(new.frn) {
      out.push(UsnAdmitted::RootDeath);
      return;
    }
    let old_parent = self.map.resolve_dir(old.parent);
    let new_parent = self.map.resolve_dir(new.parent);
    let is_dir = new.is_dir();

    let resolve_end = |parent: Option<Vec<String>>, name: &UsnName| {
      parent.map(|components| match name {
        UsnName::Utf8(text) => {
          let mut full = components;
          full.push(text.clone());
          UsnTarget::Resolved(full)
        }
        UsnName::Escalate => UsnTarget::EscalateAt(components),
      })
    };
    let old_end = resolve_end(old_parent.clone(), &old.name);
    let new_end = resolve_end(new_parent.clone(), &new.name);

    // Map maintenance mirrors the boundary shape.
    if is_dir {
      match (old_parent.is_some(), new_parent.is_some()) {
        (true, true) => {
          if let UsnName::Utf8(name) = &new.name {
            if !self.map.reparent(new.frn, new.parent, name.clone()) {
              // The FRN was absent (a directory the seed walk raced past —
              // renamed between its parent's enumeration and its own): its
              // descendants were never mapped, so learning the top alone
              // would leave a blind subtree. Demand the walk exactly like
              // an out-to-in move.
              if self.map.learn(new.frn, new.parent, name.clone()) == LearnOutcome::OverCapacity {
                out.push(UsnAdmitted::MapOverflow);
                return;
              }
              if let Some(UsnTarget::Resolved(components)) = &new_end {
                out.push(UsnAdmitted::MovedInSubtree {
                  frn: new.frn,
                  target: components.clone(),
                });
              }
            }
          } else {
            // An in-root directory whose new name has no spelling cannot
            // stay mapped — and the STANDING tree below it would go blind
            // the moment it is forgotten. The map cannot stay complete:
            // map death under the root cover.
            out.push(UsnAdmitted::MapOverflow);
            return;
          }
        }
        (true, false) => self.map.forget(new.frn),
        (false, true) => {
          // A directory arriving from outside with a name the vocabulary
          // cannot carry could never anchor its standing tree: map death,
          // exactly like its in-root sibling cells.
          let UsnName::Utf8(name) = &new.name else {
            out.push(UsnAdmitted::MapOverflow);
            return;
          };
          if self.map.learn(new.frn, new.parent, name.clone()) == LearnOutcome::OverCapacity {
            out.push(UsnAdmitted::MapOverflow);
            return;
          }
          // A directory moved IN brings an unmapped subtree: demand the
          // walk and cover its window with a located rescan at the target.
          if let Some(new_target) = &new_end
            && let UsnTarget::Resolved(components) = new_target
          {
            out.push(UsnAdmitted::MovedInSubtree {
              frn: new.frn,
              target: components.clone(),
            });
          }
        }
        (false, false) => {}
      }
    }

    match (old_end, new_end) {
      (Some(old_target), Some(new_target)) => out.push(UsnAdmitted::Renamed {
        old: old_target,
        new: new_target,
        is_dir,
      }),
      // Boundary renames: the in-root end alone, as a single (the lowering
      // covers it — a located rescan for a moved-in dir, the plain verb
      // otherwise).
      (Some(old_target), None) => out.push(UsnAdmitted::Single {
        delta: reason::FILE_DELETE,
        target: old_target,
        is_dir,
      }),
      (None, Some(new_target)) => out.push(UsnAdmitted::Single {
        delta: reason::FILE_CREATE,
        target: new_target,
        is_dir,
      }),
      (None, None) => {}
    }
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

#[cfg(test)]
mod admission_tests {
  use super::{
    UsnAdmission, UsnAdmitted, UsnTarget,
    decode::{UsnName, UsnRecord},
    map::FrnMap,
    reason,
  };

  const ROOT: u128 = 1;

  fn admission() -> UsnAdmission {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "a".into()), (20, 10, "b".into())]);
    UsnAdmission::new(map, 64)
  }

  fn record(frn: u128, parent: u128, reason_mask: u32, attrs: u32, name: &str) -> UsnRecord {
    UsnRecord {
      frn,
      parent,
      usn: 0,
      reason: reason_mask,
      source_info: 0,
      attributes: attrs,
      name: UsnName::Utf8(name.into()),
    }
  }

  #[test]
  fn membership_is_the_parent_map() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(record(50, 20, reason::FILE_CREATE, 0x20, "f.txt"), &mut out);
    assert_eq!(out.len(), 1);
    assert!(
      matches!(&out[0], UsnAdmitted::Single { target: UsnTarget::Resolved(c), is_dir: false, .. }
      if c == &["a".to_owned(), "b".to_owned(), "f.txt".to_owned()])
    );

    out.clear();
    adm.admit(
      record(60, 999, reason::FILE_CREATE, 0x20, "alien"),
      &mut out,
    );
    assert!(out.is_empty(), "an unmapped parent is outside the root");
  }

  #[test]
  fn directory_lifecycle_maintains_the_map() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(record(30, 20, reason::FILE_CREATE, 0x10, "c"), &mut out);
    out.clear();
    adm.admit(
      record(70, 30, reason::FILE_CREATE, 0x20, "under-c"),
      &mut out,
    );
    assert_eq!(out.len(), 1, "the freshly-learned dir admits its children");

    out.clear();
    adm.admit(
      record(30, 20, reason::FILE_DELETE | reason::CLOSE, 0x10, "c"),
      &mut out,
    );
    assert_eq!(out.len(), 1);
    out.clear();
    adm.admit(record(80, 30, reason::FILE_CREATE, 0x20, "ghost"), &mut out);
    assert!(out.is_empty(), "the forgotten dir no longer admits");
  }

  #[test]
  fn an_in_root_rename_resolves_both_ends_and_reparents() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(record(20, 10, reason::RENAME_OLD_NAME, 0x10, "b"), &mut out);
    assert!(out.is_empty(), "the OLD half parks");
    adm.admit(
      record(20, ROOT, reason::RENAME_NEW_NAME, 0x10, "b2"),
      &mut out,
    );
    assert_eq!(out.len(), 1);
    assert!(
      matches!(&out[0], UsnAdmitted::Renamed { old: UsnTarget::Resolved(o), new: UsnTarget::Resolved(n), is_dir: true }
      if o == &["a".to_owned(), "b".to_owned()] && n == &["b2".to_owned()])
    );

    out.clear();
    adm.admit(record(90, 20, reason::FILE_CREATE, 0x20, "x"), &mut out);
    assert!(
      matches!(&out[0], UsnAdmitted::Single { target: UsnTarget::Resolved(c), .. }
      if c == &["b2".to_owned(), "x".to_owned()]),
      "children resolve through the reparented chain: {out:?}"
    );
  }

  #[test]
  fn root_structural_records_are_the_scopes_death() {
    // A root delete is immediate.
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(ROOT, 999, reason::FILE_DELETE | reason::CLOSE, 0x10, "root"),
      &mut out,
    );
    assert!(matches!(out.as_slice(), [UsnAdmitted::RootDeath]));

    // A root rename's OLD half parks like any other; whether its NEW pairs
    // or the carry widows (the synthetic delete), the death still surfaces.
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(ROOT, 999, reason::RENAME_OLD_NAME, 0x10, "root"),
      &mut out,
    );
    assert!(out.is_empty(), "the OLD half parks first");
    adm.flush(&mut out);
    assert!(matches!(out.as_slice(), [UsnAdmitted::RootDeath]));
  }

  #[test]
  fn widows_degrade_to_membership_verbs() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(record(20, 10, reason::RENAME_OLD_NAME, 0x10, "b"), &mut out);
    let mut flushed = Vec::new();
    adm.flush(&mut flushed);
    assert_eq!(flushed.len(), 1);
    assert!(
      matches!(&flushed[0], UsnAdmitted::Single { delta, is_dir: true, .. }
      if delta & reason::FILE_DELETE != 0),
      "a widowed OLD is membership-wise a delete: {flushed:?}"
    );
  }

  #[test]
  fn filtered_bits_never_admit() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(
        50,
        20,
        reason::INDEXABLE_CHANGE | reason::OBJECT_ID_CHANGE,
        0x20,
        "f",
      ),
      &mut out,
    );
    assert!(out.is_empty());
  }
}

#[cfg(test)]
mod r1_regressions {
  use super::{
    UsnAdmission, UsnAdmitted, UsnTarget,
    decode::{UsnName, UsnRecord},
    map::FrnMap,
    reason,
  };

  const ROOT: u128 = 1;

  fn admission() -> UsnAdmission {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "a".into())]);
    UsnAdmission::new(map, 64)
  }

  fn record(frn: u128, parent: u128, reason_mask: u32, attrs: u32, name: &str) -> UsnRecord {
    UsnRecord {
      frn,
      parent,
      usn: 0,
      reason: reason_mask,
      source_info: 0,
      attributes: attrs,
      name: UsnName::Utf8(name.into()),
    }
  }

  /// A cumulative CREATE|DATA_EXTEND after an emitted CREATE reports the
  /// Modified fact — never a second Created that eats it.
  #[test]
  fn cumulative_masks_forward_fresh_bits_only() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(record(50, 10, reason::FILE_CREATE, 0x20, "f"), &mut out);
    assert!(matches!(&out[0], UsnAdmitted::Single { delta, .. }
      if *delta == reason::FILE_CREATE));

    out.clear();
    adm.admit(
      record(50, 10, reason::FILE_CREATE | reason::DATA_EXTEND, 0x20, "f"),
      &mut out,
    );
    assert_eq!(out.len(), 1);
    assert!(
      matches!(&out[0], UsnAdmitted::Single { delta, .. }
      if *delta == reason::DATA_EXTEND),
      "only the fresh content bit forwards: {out:?}"
    );
  }

  /// A widowed half keeps its fresh content bits alongside the synthetic
  /// membership verb.
  #[test]
  fn widows_keep_their_content_bits() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(
        50,
        10,
        reason::RENAME_OLD_NAME | reason::DATA_OVERWRITE,
        0x20,
        "f",
      ),
      &mut out,
    );
    adm.flush(&mut out);
    assert_eq!(out.len(), 1);
    assert!(
      matches!(&out[0], UsnAdmitted::Single { delta, .. }
      if delta & reason::FILE_DELETE != 0 && delta & reason::DATA_OVERWRITE != 0),
      "{out:?}"
    );
  }

  /// A directory moved IN from outside demands its subtree walk and the
  /// covering located rescan at the target.
  #[test]
  fn a_moved_in_directory_demands_its_walk() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      record(70, 999, reason::RENAME_OLD_NAME, 0x10, "ext"),
      &mut out,
    );
    adm.admit(
      record(70, 10, reason::RENAME_NEW_NAME, 0x10, "in"),
      &mut out,
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::MovedInSubtree { frn: 70, target }
        if target == &["a".to_owned(), "in".to_owned()])
      ),
      "{out:?}"
    );
    // The moved-in top is mapped: its children admit immediately.
    out.clear();
    adm.admit(record(80, 70, reason::FILE_CREATE, 0x20, "child"), &mut out);
    assert!(
      matches!(&out[0], UsnAdmitted::Single { target: UsnTarget::Resolved(c), .. }
      if c == &["a".to_owned(), "in".to_owned(), "child".to_owned()])
    );
  }
}

#[cfg(test)]
mod r2_regressions {
  use super::{
    UsnAdmission, UsnAdmitted,
    decode::{UsnName, UsnRecord},
    map::FrnMap,
    reason,
  };

  const ROOT: u128 = 1;

  fn record(frn: u128, parent: u128, reason_mask: u32, name: &str) -> UsnRecord {
    UsnRecord {
      frn,
      parent,
      usn: 0,
      reason: reason_mask,
      source_info: 0,
      attributes: 0x20,
      name: UsnName::Utf8(name.into()),
    }
  }

  /// A pre-loss bit whose CLOSE fell inside the gap must re-report after
  /// the reseed boundary resets the session history.
  #[test]
  fn reseed_resets_cumulative_history() {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "a".into())]);
    let mut adm = UsnAdmission::new(map, 64);
    let mut out = Vec::new();
    adm.admit(record(50, 10, reason::DATA_EXTEND, "f"), &mut out);
    assert_eq!(out.len(), 1);

    // The gap: the CLOSE was skipped, the reseed boundary resets.
    adm.reset_sessions();
    out.clear();
    adm.admit(record(50, 10, reason::DATA_EXTEND, "f"), &mut out);
    assert!(
      matches!(&out[0], UsnAdmitted::Single { delta, .. }
        if *delta == reason::DATA_EXTEND),
      "the post-gap session re-reports: {out:?}"
    );
  }

  /// A move-in followed by an in-root rename in the SAME buffer: the map's
  /// resolution (the walk's anchor) tracks the rename, not the stale
  /// move-in target.
  #[test]
  fn same_buffer_move_in_then_rename_tracks_the_map() {
    let mut map = FrnMap::new(ROOT, None);
    map.seed([(10, ROOT, "a".into())]);
    let mut adm = UsnAdmission::new(map, 64);
    let mut out = Vec::new();
    let dir = |frn, parent, mask, name: &str| UsnRecord {
      attributes: 0x10,
      ..record(frn, parent, mask, name)
    };
    adm.admit(dir(70, 999, reason::RENAME_OLD_NAME, "ext"), &mut out);
    adm.admit(dir(70, 10, reason::RENAME_NEW_NAME, "in"), &mut out);
    adm.admit(dir(70, 10, reason::RENAME_OLD_NAME, "in"), &mut out);
    adm.admit(dir(70, ROOT, reason::RENAME_NEW_NAME, "b"), &mut out);

    let stale = out.iter().find_map(|e| match e {
      UsnAdmitted::MovedInSubtree { frn, target } => Some((*frn, target.clone())),
      _ => None,
    });
    assert_eq!(
      stale,
      Some((70, vec!["a".to_owned(), "in".to_owned()])),
      "the EVENT keeps its historical target (the rescan's location)"
    );
    assert_eq!(
      adm.map_mut().resolve_dir(70),
      Some(vec!["b".to_owned()]),
      "the MAP (the walk's anchor) already tracks the rename"
    );
  }
}

#[cfg(test)]
mod r9_regressions {
  use super::{
    UsnAdmission, UsnAdmitted, UsnTarget,
    decode::{UsnName, UsnRecord},
    map::FrnMap,
    reason,
  };

  /// A directory the seed walk raced past (renamed between its parent's
  /// enumeration and its own): the in-root rename replay learns the absent
  /// FRN AND demands the subtree walk — never a mapped top over a blind
  /// subtree.
  #[test]
  fn an_unmapped_in_root_rename_demands_its_walk() {
    let mut map = FrnMap::new(1, None);
    map.seed([(10, 1, "a".into()), (20, 1, "b".into())]);
    let mut adm = UsnAdmission::new(map, 64);
    let mut out = Vec::new();
    let dir = |frn, parent, mask, name: &str| UsnRecord {
      frn,
      parent,
      usn: 0,
      reason: mask,
      source_info: 0,
      attributes: 0x10,
      name: UsnName::Utf8(name.into()),
    };
    // FRN 70 was never seeded (the race), yet both rename ends are in-root.
    adm.admit(dir(70, 10, reason::RENAME_OLD_NAME, "raced"), &mut out);
    adm.admit(dir(70, 20, reason::RENAME_NEW_NAME, "landed"), &mut out);
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::MovedInSubtree { frn: 70, target }
        if target == &["b".to_owned(), "landed".to_owned()])
      ),
      "{out:?}"
    );
    // And its children admit through the learned chain.
    out.clear();
    adm.admit(dir(80, 70, reason::FILE_CREATE, "child"), &mut out);
    assert!(
      matches!(&out[0], UsnAdmitted::Single { target: UsnTarget::Resolved(c), .. }
      if c == &["b".to_owned(), "landed".to_owned(), "child".to_owned()])
    );
  }
}

#[cfg(test)]
mod r10_regressions {
  use super::{
    UsnAdmission, UsnAdmitted, UsnTarget,
    decode::{UsnName, UsnRecord},
    map::FrnMap,
    reason,
  };

  /// A reparse boundary REMOVED mid-stream: the now-ordinary directory is
  /// learned and its walk demanded — never a permanently blind subtree.
  #[test]
  fn a_removed_reparse_boundary_demands_its_walk() {
    let mut map = FrnMap::new(1, None);
    map.seed([(10, 1, "a".into())]);
    let mut adm = UsnAdmission::new(map, 64);
    let mut out = Vec::new();
    // FRN 70 was a junction under a: excluded from the map. The boundary
    // is removed (no reparse attribute anymore).
    adm.admit(
      UsnRecord {
        frn: 70,
        parent: 10,
        usn: 0,
        reason: reason::REPARSE_POINT_CHANGE | reason::CLOSE,
        source_info: 0,
        attributes: 0x10,
        name: UsnName::Utf8("was-junction".into()),
      },
      &mut out,
    );
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::MovedInSubtree { frn: 70, target }
        if target == &["a".to_owned(), "was-junction".to_owned()])
      ),
      "{out:?}"
    );
    out.clear();
    adm.admit(
      UsnRecord {
        frn: 80,
        parent: 70,
        usn: 0,
        reason: reason::FILE_CREATE,
        source_info: 0,
        attributes: 0x20,
        name: UsnName::Utf8("child".into()),
      },
      &mut out,
    );
    assert!(
      matches!(&out[0], UsnAdmitted::Single { target: UsnTarget::Resolved(c), .. }
      if c == &["a".to_owned(), "was-junction".to_owned(), "child".to_owned()])
    );
  }
}

#[cfg(test)]
mod r11_regressions {
  use super::{
    UsnAdmission, UsnAdmitted, UsnTarget,
    decode::{UsnName, UsnRecord},
    map::FrnMap,
    reason,
  };

  fn dir(frn: u128, parent: u128, mask: u32, name: &str) -> UsnRecord {
    UsnRecord {
      frn,
      parent,
      usn: 0,
      reason: mask,
      source_info: 0,
      attributes: 0x10,
      name: UsnName::Utf8(name.into()),
    }
  }

  fn admission() -> UsnAdmission {
    let mut map = FrnMap::new(1, None);
    map.seed([(10, 1, "a".into())]);
    UsnAdmission::new(map, 64)
  }

  /// A reparse add-then-remove within ONE open session: the cumulative
  /// second bit must still run the boundary-removed learn-and-walk.
  #[test]
  fn a_reparse_toggle_in_one_session_still_walks() {
    let mut adm = admission();
    let mut out = Vec::new();
    // Boundary added (reparse attribute set): the mapped dir drops.
    adm.admit(
      UsnRecord {
        attributes: 0x410,
        ..dir(10, 1, reason::REPARSE_POINT_CHANGE, "a")
      },
      &mut out,
    );
    out.clear();
    // Same session (no CLOSE between): boundary removed again.
    adm.admit(
      dir(10, 1, reason::REPARSE_POINT_CHANGE | reason::CLOSE, "a"),
      &mut out,
    );
    assert!(
      out
        .iter()
        .any(|e| matches!(e, UsnAdmitted::MovedInSubtree { frn: 10, .. })),
      "the cumulative bit must not suppress the removal's walk: {out:?}"
    );
  }

  /// A structural directory whose name has no spelling is map death.
  #[test]
  fn an_unnameable_directory_creation_is_map_death() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(
      UsnRecord {
        name: UsnName::Escalate,
        ..dir(70, 10, reason::FILE_CREATE, "")
      },
      &mut out,
    );
    assert!(
      out.iter().any(|e| matches!(e, UsnAdmitted::MapOverflow)),
      "{out:?}"
    );
  }

  /// A widowed directory NEW half is a move-in: the anchor learns AND the
  /// subtree walk is demanded (a cursor can start between rename halves).
  #[test]
  fn a_widowed_directory_new_half_demands_its_walk() {
    let mut adm = admission();
    let mut out = Vec::new();
    adm.admit(dir(70, 10, reason::RENAME_NEW_NAME, "arrived"), &mut out);
    assert!(
      out.iter().any(
        |e| matches!(e, UsnAdmitted::MovedInSubtree { frn: 70, target }
        if target == &["a".to_owned(), "arrived".to_owned()])
      ),
      "{out:?}"
    );
    out.clear();
    adm.admit(dir(80, 70, reason::FILE_CREATE, "child"), &mut out);
    assert!(
      matches!(&out[0], UsnAdmitted::Single { target: UsnTarget::Resolved(c), .. }
      if c == &["a".to_owned(), "arrived".to_owned(), "child".to_owned()])
    );
  }
}

#[cfg(test)]
mod r12_regressions {
  use super::{
    UsnAdmission, UsnAdmitted,
    decode::{UsnName, UsnRecord},
    map::FrnMap,
    reason,
  };

  /// An out-to-in directory move whose NEW name has no spelling is map
  /// death — never a bare parent rescan over a standing unmapped tree.
  #[test]
  fn an_unnameable_move_in_is_map_death() {
    let mut map = FrnMap::new(1, None);
    map.seed([(10, 1, "a".into())]);
    let mut adm = UsnAdmission::new(map, 64);
    let mut out = Vec::new();
    let dir = |frn, parent, mask, name| UsnRecord {
      frn,
      parent,
      usn: 0,
      reason: mask,
      source_info: 0,
      attributes: 0x10,
      name,
    };
    adm.admit(
      dir(
        70,
        999,
        reason::RENAME_OLD_NAME,
        UsnName::Utf8("ext".into()),
      ),
      &mut out,
    );
    adm.admit(
      dir(70, 10, reason::RENAME_NEW_NAME, UsnName::Escalate),
      &mut out,
    );
    assert!(
      out.iter().any(|e| matches!(e, UsnAdmitted::MapOverflow)),
      "{out:?}"
    );
  }
}
