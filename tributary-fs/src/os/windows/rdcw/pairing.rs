//! The pump-side rename pairing state machine.
//!
//! `ReadDirectoryChangesW` reports a rename as an adjacent
//! `RENAMED_OLD_NAME`/`RENAMED_NEW_NAME` record pair, and the pair can split
//! across two completion buffers. This pure module pairs them: an OLD half is
//! held (at most ONE — the carry slot), the immediately-following NEW half
//! completes it into an atomic [`RdcwEvent::Renamed`], and anything else —
//! an intervening record, a NEW with no held OLD, an extended-record file-id
//! disagreement, a pairing-window timeout, teardown, or an overflow boundary —
//! widows the held half instead of guessing. A widow is the already-legal
//! degrade: the core lowers it to a cookie-less move half the Monitor
//! resolves immediately as a `Removed`/`Created`.
//!
//! Pure data only — no FFI — so the twins pin the pairing contract on every
//! host, including under miri, before the pump exists.

use super::decode::{RdcwAction, RdcwRecord};

/// One RDCW event after pairing — what the pump forwards to the driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RdcwEvent {
  /// A non-rename record, forwarded as it decoded.
  Single(RdcwRecord),
  /// An atomically paired rename: the OLD and NEW halves in kernel order.
  Renamed {
    /// The departing half (`FILE_ACTION_RENAMED_OLD_NAME`).
    old: RdcwRecord,
    /// The arriving half (`FILE_ACTION_RENAMED_NEW_NAME`).
    new: RdcwRecord,
  },
  /// An OLD half whose NEW never arrived.
  WidowOld(RdcwRecord),
  /// A NEW half with no OLD held.
  WidowNew(RdcwRecord),
}

/// The pairing state: at most one OLD half carried between records (and
/// across completion-buffer boundaries).
#[derive(Debug, Default)]
pub(crate) struct RdcwPairer {
  pending_old: Option<RdcwRecord>,
}

// The pump owns the pairer once it lands behind this seam; until then the
// twins are the only caller of the constructor and the timeout cue.
#[cfg_attr(not(test), allow(dead_code))]
impl RdcwPairer {
  /// A fresh pairer with an empty carry slot.
  pub(crate) const fn new() -> Self {
    Self { pending_old: None }
  }

  /// Feeds one decoded record in kernel order, appending the completed
  /// events to `out`. A record may complete zero events (an OLD parks in the
  /// carry slot), one, or two (an intervening record first widows the held
  /// OLD).
  pub(crate) fn push(&mut self, record: RdcwRecord, out: &mut Vec<RdcwEvent>) {
    match record.action {
      RdcwAction::RenamedOld => {
        // Two OLDs in a row: the first can no longer pair (its NEW would
        // have been adjacent), so it widows and the new OLD takes the slot.
        self.flush(out);
        self.pending_old = Some(record);
      }
      RdcwAction::RenamedNew => match self.pending_old.take() {
        Some(old) => {
          // Extended records ground the pair in the object itself: a rename
          // keeps its file reference number, so a disagreement means these
          // halves belong to DIFFERENT renames — widow both rather than
          // fabricate a move that never happened. Basic records carry no id
          // and pair by adjacency alone.
          let ids_disagree = match (old.file_id, record.file_id) {
            (Some(old_id), Some(new_id)) => old_id != new_id,
            _ => false,
          };
          if ids_disagree {
            out.push(RdcwEvent::WidowOld(old));
            out.push(RdcwEvent::WidowNew(record));
          } else {
            out.push(RdcwEvent::Renamed { old, new: record });
          }
        }
        None => out.push(RdcwEvent::WidowNew(record)),
      },
      _ => {
        // Any intervening record breaks adjacency: the held OLD widows
        // BEFORE the record, preserving kernel order.
        self.flush(out);
        out.push(RdcwEvent::Single(record));
      }
    }
  }

  /// Widows the held OLD, if any. The pump calls this at the pairing-window
  /// timeout, at an overflow boundary (the widow must precede the loss
  /// signal it predates), and at teardown — the carry slot never outlives
  /// its wait.
  pub(crate) fn flush(&mut self, out: &mut Vec<RdcwEvent>) {
    if let Some(old) = self.pending_old.take() {
      out.push(RdcwEvent::WidowOld(old));
    }
  }

  /// Whether an OLD half is parked in the carry slot — the pump's cue to arm
  /// the pairing-window timeout after a buffer ends mid-pair.
  pub(crate) fn holds_old(&self) -> bool {
    self.pending_old.is_some()
  }
}

#[cfg(test)]
mod tests {
  use super::{super::decode::RdcwName, *};

  fn record(action: RdcwAction, name: &str, file_id: Option<u64>) -> RdcwRecord {
    RdcwRecord {
      action,
      name: RdcwName::Utf8(name.split('\\').map(str::to_owned).collect()),
      file_id,
      parent_id: None,
      attributes: None,
      reparse_tag: None,
    }
  }

  #[test]
  fn adjacent_halves_pair() {
    let mut pairer = RdcwPairer::new();
    let mut out = Vec::new();
    pairer.push(record(RdcwAction::RenamedOld, "a", None), &mut out);
    assert!(out.is_empty(), "the OLD parks");
    assert!(pairer.holds_old());
    pairer.push(record(RdcwAction::RenamedNew, "b", None), &mut out);
    assert_eq!(out.len(), 1);
    assert!(matches!(&out[0], RdcwEvent::Renamed { .. }));
    assert!(!pairer.holds_old());
  }

  #[test]
  fn the_pair_survives_a_buffer_boundary() {
    let mut pairer = RdcwPairer::new();
    let mut out = Vec::new();
    pairer.push(record(RdcwAction::RenamedOld, "a", None), &mut out);
    // The buffer ends here; the pump forwards `out` (empty) and keeps the
    // pairer. The next buffer opens with the NEW half.
    assert!(out.is_empty());
    pairer.push(record(RdcwAction::RenamedNew, "b", None), &mut out);
    assert!(matches!(&out[0], RdcwEvent::Renamed { .. }));
  }

  #[test]
  fn an_intervening_record_widows_the_old_in_order() {
    let mut pairer = RdcwPairer::new();
    let mut out = Vec::new();
    pairer.push(record(RdcwAction::RenamedOld, "a", None), &mut out);
    pairer.push(record(RdcwAction::Modified, "c", None), &mut out);
    assert_eq!(out.len(), 2);
    assert!(matches!(&out[0], RdcwEvent::WidowOld(rec) if rec.action == RdcwAction::RenamedOld));
    assert!(matches!(&out[1], RdcwEvent::Single(rec) if rec.action == RdcwAction::Modified));
  }

  #[test]
  fn a_new_without_an_old_is_a_widow() {
    let mut pairer = RdcwPairer::new();
    let mut out = Vec::new();
    pairer.push(record(RdcwAction::RenamedNew, "b", None), &mut out);
    assert_eq!(out.len(), 1);
    assert!(matches!(&out[0], RdcwEvent::WidowNew(_)));
  }

  #[test]
  fn two_olds_widow_the_first() {
    let mut pairer = RdcwPairer::new();
    let mut out = Vec::new();
    pairer.push(record(RdcwAction::RenamedOld, "a", None), &mut out);
    pairer.push(record(RdcwAction::RenamedOld, "b", None), &mut out);
    assert_eq!(out.len(), 1);
    assert!(
      matches!(&out[0], RdcwEvent::WidowOld(rec) if rec.name == RdcwName::Utf8(vec!["a".into()]))
    );
    assert!(pairer.holds_old(), "the second OLD takes the slot");
  }

  #[test]
  fn matching_file_ids_pair_and_disagreeing_ones_widow_both() {
    let mut pairer = RdcwPairer::new();
    let mut out = Vec::new();
    pairer.push(record(RdcwAction::RenamedOld, "a", Some(7)), &mut out);
    pairer.push(record(RdcwAction::RenamedNew, "b", Some(7)), &mut out);
    assert!(matches!(&out[0], RdcwEvent::Renamed { .. }));

    out.clear();
    pairer.push(record(RdcwAction::RenamedOld, "c", Some(7)), &mut out);
    pairer.push(record(RdcwAction::RenamedNew, "d", Some(9)), &mut out);
    assert_eq!(out.len(), 2);
    assert!(matches!(&out[0], RdcwEvent::WidowOld(_)));
    assert!(matches!(&out[1], RdcwEvent::WidowNew(_)));
  }

  #[test]
  fn a_basic_half_pairs_with_an_extended_half_by_adjacency() {
    let mut pairer = RdcwPairer::new();
    let mut out = Vec::new();
    pairer.push(record(RdcwAction::RenamedOld, "a", None), &mut out);
    pairer.push(record(RdcwAction::RenamedNew, "b", Some(7)), &mut out);
    assert!(matches!(&out[0], RdcwEvent::Renamed { .. }));
  }

  #[test]
  fn flush_widows_the_carry() {
    let mut pairer = RdcwPairer::new();
    let mut out = Vec::new();
    pairer.push(record(RdcwAction::RenamedOld, "a", None), &mut out);
    pairer.flush(&mut out);
    assert_eq!(out.len(), 1);
    assert!(matches!(&out[0], RdcwEvent::WidowOld(_)));
    assert!(!pairer.holds_old());
    pairer.flush(&mut out);
    assert_eq!(out.len(), 1, "flush is idempotent");
  }
}
