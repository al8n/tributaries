//! The USN lowering: admitted journal events on a kernel-recursive stream,
//! already membership-checked and resolved by the source's admission layer.
//!
//! Like fanotify and RDCW there are NO grounding probes and NO parking
//! (every item is immediate). Renames arrive atomically paired (FRN-keyed by
//! the admission) and plan through the fanotify counter-cookie path
//! verbatim; boundary renames arrive pre-degraded to their in-root end's
//! membership verb. Reason deltas are already noise-filtered — the lowering
//! only picks the verb by the partition priority (structural over content
//! over metadata) and covers escalations with located rescans.

use std::{collections::BTreeMap, vec::Vec};

use tributary_proto::{Location, OsRecord, RecordKind, Scope, Segment};

use crate::os::windows::usn::{UsnAdmitted, UsnTarget, reason};

use super::super::{DriverCore, Item, PendingBatch, Planned, ScopeId, ScopeState, located};

fn location_of(components: &[String]) -> Location {
  Location::from_segments(components.iter().map(Segment::new))
}

impl DriverCore {
  /// Lowers one admitted USN batch. Every item is immediate
  /// (`awaiting == 0`), so the batch settles inline.
  pub(in crate::core) fn compile_usn(
    &mut self,
    state: &mut ScopeState,
    scope: ScopeId,
    events: Vec<UsnAdmitted>,
  ) -> PendingBatch {
    let mut items = Vec::with_capacity(events.len());
    for event in events {
      items.push(Item {
        planned: self.plan_usn(state, scope, event),
        probe: None,
        cookie_candidate: None,
      });
    }
    PendingBatch {
      items,
      awaiting: 0,
      trailing: Vec::new(),
      deferred_unmounts: Vec::new(),
      evidenced: BTreeMap::new(),
      permit: None,
    }
  }

  /// Plans one admitted USN event into Monitor records.
  fn plan_usn(&mut self, state: &ScopeState, scope: ScopeId, event: UsnAdmitted) -> Vec<Planned> {
    match event {
      // The scope's death: the same terminal lifecycle every KR backend
      // uses — the Monitor's DeleteSelf ends the scope with its owed
      // Removed + Rescan.
      UsnAdmitted::RootDeath => {
        vec![Planned::Rec(OsRecord::new(
          state.watch,
          RecordKind::DeleteSelf,
        ))]
      }
      // The map can no longer stay complete: a blind subtree is never
      // acceptable, so the whole root degrades to the covering rescan (the
      // source dies alongside; this record is the in-band cover).
      UsnAdmitted::MapOverflow => vec![Planned::Over(Scope::Root(scope))],
      // A moved-in directory's subtree is unmapped until the source's walk
      // completes: the located rescan owns that window (and re-enumerates
      // whatever the walk could not see happen).
      UsnAdmitted::MovedInSubtree { target, .. } => {
        vec![Planned::Over(located(
          state.watch,
          Some(location_of(&target)),
        ))]
      }
      UsnAdmitted::Renamed { old, new, is_dir } => {
        match (old, new) {
          (UsnTarget::Resolved(old_c), UsnTarget::Resolved(new_c)) => {
            // Both ends are in-root, already root-relative: mint the
            // counter cookie and emit the adjacent pair directly (host
            // path separators must never decide a lowering). A directory
            // moved IN from outside arrives as a pre-degraded Single
            // (never here); the reparent carried the subtree, and the
            // Monitor's own class handling threads `is_dir` through.
            let cookie = self.next_cookie();
            let from_rec = OsRecord::new(state.watch, RecordKind::MovedFrom)
              .with_target(location_of(&old_c))
              .with_cookie(cookie)
              .with_is_dir(is_dir);
            let to_rec = OsRecord::new(state.watch, RecordKind::MovedTo)
              .with_target(location_of(&new_c))
              .with_cookie(cookie)
              .with_is_dir(is_dir);
            vec![Planned::Rec(from_rec), Planned::Rec(to_rec)]
          }
          // An escalated end covers its deepest named location; the other
          // end still plans as its half's membership verb through the
          // located cover (the admission pre-degrades true boundary cases,
          // so both ends here are in-root but one is unnameable).
          (old, new) => {
            let mut planned = Vec::with_capacity(2);
            for end in [old, new] {
              planned.push(match end {
                UsnTarget::Resolved(c) if c.is_empty() => Planned::Over(Scope::Root(scope)),
                UsnTarget::Resolved(c) => {
                  Planned::Over(located(state.watch, Some(location_of(&c))))
                }
                UsnTarget::EscalateAt(c) if c.is_empty() => {
                  Planned::Over(located(state.watch, None))
                }
                UsnTarget::EscalateAt(c) => {
                  Planned::Over(located(state.watch, Some(location_of(&c))))
                }
              });
            }
            planned
          }
        }
      }
      UsnAdmitted::Single {
        delta,
        target,
        is_dir,
      } => {
        let location = match target {
          UsnTarget::Resolved(c) if c.is_empty() => {
            // A metadata self-event on the root object itself.
            None
          }
          UsnTarget::Resolved(c) => Some(location_of(&c)),
          UsnTarget::EscalateAt(c) => {
            // The subject's own name is unnameable: cover the parent.
            return vec![Planned::Over(located(
              state.watch,
              (!c.is_empty()).then(|| location_of(&c)),
            ))];
          }
        };

        // The verb partition, structural first: a delta carrying both a
        // structural verb and content/metadata bits reports the structural
        // one (the others are its side effects within one session).
        let kind = if delta & reason::FILE_CREATE != 0 {
          RecordKind::Created
        } else if delta & reason::FILE_DELETE != 0 {
          RecordKind::Removed
        } else if delta & reason::HARD_LINK_CHANGE != 0 {
          // A link count change at a resolved path: whether this names the
          // appearing or the vanishing link is unknowable from the record
          // alone — the located rescan grounds it.
          return vec![Planned::Over(located(state.watch, location))];
        } else if delta & reason::MODIFY != 0 {
          RecordKind::Modified
        } else if delta & (reason::ATTRIB | reason::REPARSE_POINT_CHANGE) != 0 {
          RecordKind::Attrib
        } else {
          // Only CLOSE/filtered residue: nothing to report.
          return Vec::new();
        };

        let mut rec = OsRecord::new(state.watch, kind).with_is_dir(is_dir);
        if let Some(location) = location {
          rec = rec.with_target(location);
        }
        vec![Planned::Rec(rec)]
      }
    }
  }
}
