//! The fanotify lowering: precise verbs on a kernel-recursive stream, lowered
//! to root-relative targets.
//!
//! Everything the FSEvents path needs a probe for, fanotify already knows:
//! events are precise verbs (never OR'd hints), so there are NO grounding
//! probes, NO evidence grants, NO chain belts, and NO parking (every item is
//! immediate). A `FAN_RENAME` arrives atomically — both directory FIDs and
//! both names in ONE event — so the driver mints a counter cookie and emits
//! `MovedFrom`/`MovedTo` adjacently, with no pairing window and no
//! classification. Records carry NO node identity: under the kernel-recursive
//! profile record identity is inert (design §4.9 — `Monitor::reconcile_slot`
//! early-returns for a non-descending scope, and `FAN_RENAME` carries its own
//! atomic addressing), so the lowering attaches none, exactly as the FSEvents
//! kernel-recursive lowering does. `MOVE_SELF`/`DELETE_SELF` at the root is the
//! scope's death, exactly the FSEvents unmount lifecycle.

use std::{collections::BTreeMap, path::Path, vec::Vec};

use tributary_proto::{OsRecord, RecordKind, Scope};

use crate::os::linux::fanotify::AdmittedEvent;

use super::super::{
  DriverCore, Item, Lowered, PendingBatch, Planned, ScopeId, ScopeState, located, lower,
};

impl DriverCore {
  /// Lowers one admitted fanotify batch. Every item is immediate
  /// (`awaiting == 0`), so the batch settles inline and the park never engages
  /// under this profile.
  pub(in crate::core) fn compile_fanotify(
    &mut self,
    state: &mut ScopeState,
    scope: ScopeId,
    events: Vec<AdmittedEvent>,
  ) -> PendingBatch {
    let mut items = Vec::with_capacity(events.len());
    for event in events {
      items.push(Item {
        planned: self.plan_fanotify(state, scope, &event),
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

  /// Plans one admitted fanotify event into Monitor records.
  fn plan_fanotify(
    &mut self,
    state: &ScopeState,
    scope: ScopeId,
    event: &AdmittedEvent,
  ) -> Vec<Planned> {
    let mask = event.mask;
    if let Some(rename) = &event.rename {
      return self.plan_rename(state, scope, &rename.old_path, &rename.new_path);
    }

    // classify routes an ambiguous merged mask (two or more structural verbs) to the
    // loss barrier upstream, so a non-rename event that admitted this far names AT
    // MOST ONE structural verb. The verb selectors below (the self-event branch and
    // `verb`) therefore treat the mask as naming ONE action; a multi-structural mask
    // reaching here is a classify/reader bug. In release the selectors still degrade
    // safely — they pick the highest-priority verb, never panic — but assert the
    // invariant in debug so a future admission regression trips a test, not the field.
    debug_assert!(
      !mask.multi_structural(),
      "a multi-structural fanotify mask reached lowering; classify must route it to Lossy"
    );

    let Some(path) = &event.path else {
      // An admitted event with no resolved path carries no addressable target;
      // the admission layer never produces one, so this is a seam bug —
      // degrade to a root rescan rather than fabricate a record.
      debug_assert!(false, "an admitted fanotify event has no path");
      return vec![Planned::Over(Scope::Root(scope))];
    };

    // A self-event on the root object is the scope's death — the same death
    // lifecycle the FSEvents unmount uses, but PRESERVING the verb: a `DELETE_SELF`
    // lowers to `DeleteSelf` (the Monitor's terminal Removed + Rescan), a `MOVE_SELF`
    // to `MoveSelf` (a terminal Rescan only — a moved root's new path is unknowable,
    // so there is no Removed). Collapsing both to `Ignored` here dropped the
    // user-visible Removed a real root deletion owes. On an inner object it
    // duplicates the parent's dirent record; degrade it to a located rescan so
    // nothing is ever silently dropped, but do not fabricate a second delete.
    if mask.delete_self() || mask.move_self() {
      return match lower(state, path) {
        Lowered::Root => {
          let kind = if mask.delete_self() {
            RecordKind::DeleteSelf
          } else {
            RecordKind::MoveSelf
          };
          vec![Planned::Rec(OsRecord::new(state.watch, kind))]
        }
        Lowered::Target(location) => vec![Planned::Over(located(state.watch, Some(location)))],
        Lowered::Outside => vec![Planned::Over(Scope::Root(scope))],
      };
    }

    let target = match lower(state, path) {
      Lowered::Root => None,
      Lowered::Target(location) => Some(location),
      // A path that admitted (its directory FID is in-root) but does not lower
      // under the canonical root is a byte-form disagreement; a root rescan is
      // the honest cover.
      Lowered::Outside => return vec![Planned::Over(Scope::Root(scope))],
    };

    let Some(kind) = verb(event) else {
      // A mask carrying none of the subscribed dirent verbs is kernel noise
      // for this vocabulary; skip it rather than fabricate a record.
      return Vec::new();
    };

    let mut rec = OsRecord::new(state.watch, kind).with_is_dir(mask.ondir());
    if let Some(location) = target {
      rec = rec.with_target(location);
    }
    vec![Planned::Rec(rec)]
  }

  /// Plans a `FAN_RENAME` into an adjacent `MovedFrom`/`MovedTo` pair sharing a
  /// freshly-minted counter cookie. Both halves are always present, so the
  /// Monitor pairs them with no window; a half whose end lies outside the root
  /// degrades to a located rescan of the in-root end (a move across the root
  /// boundary), never a half-move.
  fn plan_rename(
    &mut self,
    state: &ScopeState,
    scope: ScopeId,
    old_path: &Path,
    new_path: &Path,
  ) -> Vec<Planned> {
    let old = lower(state, old_path);
    let new = lower(state, new_path);
    // A rename touching the root object itself is the scope's death.
    if matches!(old, Lowered::Root) || matches!(new, Lowered::Root) {
      return vec![Planned::Rec(OsRecord::new(
        state.watch,
        RecordKind::Ignored,
      ))];
    }

    match (old, new) {
      (Lowered::Target(from), Lowered::Target(to)) => {
        let cookie = self.next_cookie();
        let from_rec = OsRecord::new(state.watch, RecordKind::MovedFrom)
          .with_target(from)
          .with_cookie(cookie);
        let to_rec = OsRecord::new(state.watch, RecordKind::MovedTo)
          .with_target(to)
          .with_cookie(cookie);
        vec![Planned::Rec(from_rec), Planned::Rec(to_rec)]
      }
      // One end is outside the root: a move across the boundary. Cover the
      // in-root end with a located rescan (its content changed) rather than
      // pairing a half that has no partner under the root.
      (Lowered::Target(inside), _) | (_, Lowered::Target(inside)) => {
        vec![Planned::Over(located(state.watch, Some(inside)))]
      }
      _ => vec![Planned::Over(Scope::Root(scope))],
    }
  }
}

/// The record verb an admitted event's mask names, if any. fanotify masks are
/// bitmasks, but classify routes an ambiguous multi-structural mask to the loss
/// barrier upstream, so at most ONE structural verb (create or delete) reaches here;
/// a coexisting metadata bit (modify/attrib) is subsumed by the structural verb via
/// the priority order below, and a pure metadata mask picks its single metadata verb.
fn verb(event: &AdmittedEvent) -> Option<RecordKind> {
  let mask = event.mask;
  if mask.created() {
    Some(RecordKind::Created)
  } else if mask.removed() {
    Some(RecordKind::Removed)
  } else if mask.modified() {
    Some(RecordKind::Modified)
  } else if mask.attrib() {
    Some(RecordKind::Attrib)
  } else {
    None
  }
}
