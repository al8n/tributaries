//! The `ReadDirectoryChangesW` lowering: precise verbs on a kernel-recursive
//! stream, lowered from watch-relative record names.
//!
//! Like fanotify there are NO grounding probes, NO evidence grants, and NO
//! parking (every item is immediate) — actions are single verbs, never OR'd
//! hints. Renames arrive already paired by the pump's carry-slot state
//! machine and plan through the fanotify counter-cookie path verbatim; a
//! widowed half lowers to a cookie-less move half the Monitor resolves
//! immediately as its honest degrade (an unpairable FROM is a `Removed`, an
//! unpairable TO a `Created` — the window parks only cookied halves). Records carry NO node identity: under the kernel-recursive
//! profile record identity is inert (design §4.9) — extended-record file ids
//! ground pump-side pairing, never registry identity. A name component the
//! [`Segment`](tributary_proto::Segment) vocabulary cannot carry (WTF-16 with
//! no Unicode spelling) escalates to a located rescan at its deepest
//! decodable ancestor, never a lossy transliteration.

use std::{collections::BTreeMap, vec::Vec};

use tributary_proto::{Location, OsRecord, RecordKind, Scope, Segment};

use crate::os::windows::{RdcwAction, RdcwEvent, RdcwName, RdcwRecord};

use super::super::{DriverCore, Item, PendingBatch, Planned, ScopeId, ScopeState, located};

/// A record name resolved against the watch: RDCW names are already
/// root-relative, so resolution is pure vocabulary — no byte-prefix lowering.
enum Resolved {
  /// The record names the root itself (an empty relative name) — RDCW never
  /// reports the root as its own dirent, so callers treat this as a seam
  /// surprise and cover the root.
  Root,
  /// A descendant, as a root-relative location.
  Target(Location),
  /// The name escalated: the location is the deepest decodable ancestor
  /// (`None` = the root).
  Escalate(Option<Location>),
}

fn resolve(name: &RdcwName) -> Resolved {
  match name {
    RdcwName::Utf8(components) if components.is_empty() => Resolved::Root,
    RdcwName::Utf8(components) => {
      Resolved::Target(Location::from_segments(components.iter().map(Segment::new)))
    }
    RdcwName::Escalate { prefix } => Resolved::Escalate(if prefix.is_empty() {
      None
    } else {
      Some(Location::from_segments(prefix.iter().map(Segment::new)))
    }),
  }
}

impl DriverCore {
  /// Lowers one pump-paired RDCW batch. Every item is immediate
  /// (`awaiting == 0`), so the batch settles inline and the park never
  /// engages under this profile.
  pub(in crate::core) fn compile_rdcw(
    &mut self,
    state: &mut ScopeState,
    scope: ScopeId,
    events: Vec<RdcwEvent>,
  ) -> PendingBatch {
    let mut items = Vec::with_capacity(events.len());
    for event in events {
      items.push(Item {
        planned: self.plan_rdcw(state, scope, event),
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

  /// Plans one pump-paired RDCW event into Monitor records.
  fn plan_rdcw(&mut self, state: &ScopeState, scope: ScopeId, event: RdcwEvent) -> Vec<Planned> {
    match event {
      RdcwEvent::Renamed { old, new } => self.plan_rdcw_rename(state, scope, &old, &new),
      // A widow is the pairing machine's honest give-up: a cookie-less move
      // half, which the Monitor resolves immediately (an unpairable FROM is
      // the Removed degrade, an unpairable TO the Created one) — exactly
      // what a real rename torn across the pairing window earns.
      RdcwEvent::WidowOld(record) => plan_single(state, scope, &record, RecordKind::MovedFrom),
      RdcwEvent::WidowNew(record) => plan_single(state, scope, &record, RecordKind::MovedTo),
      RdcwEvent::Single(record) => match record.action {
        RdcwAction::Added => plan_single(state, scope, &record, RecordKind::Created),
        RdcwAction::Removed => plan_single(state, scope, &record, RecordKind::Removed),
        RdcwAction::Modified => plan_single(state, scope, &record, RecordKind::Modified),
        // The pairer never emits a rename half as Single; treat a leak like
        // its widow rather than drop it.
        RdcwAction::RenamedOld => {
          debug_assert!(false, "an unpaired OLD half escaped the pairer as Single");
          plan_single(state, scope, &record, RecordKind::MovedFrom)
        }
        RdcwAction::RenamedNew => {
          debug_assert!(false, "an unpaired NEW half escaped the pairer as Single");
          plan_single(state, scope, &record, RecordKind::MovedTo)
        }
        // An action word outside the vocabulary: the object is named, the
        // verb is not — a located rescan is the honest cover.
        RdcwAction::Unknown(_) => match resolve(&record.name) {
          Resolved::Root => vec![Planned::Over(Scope::Root(scope))],
          Resolved::Target(location) | Resolved::Escalate(Some(location)) => {
            vec![Planned::Over(located(state.watch, Some(location)))]
          }
          Resolved::Escalate(None) => vec![Planned::Over(located(state.watch, None))],
        },
      },
    }
  }

  /// Plans a paired rename. Both names decodable → the fanotify
  /// counter-cookie path, fed the absolute forms it lowers; an escalated end
  /// covers its side with a located rescan instead (and the decodable end
  /// still plans, so nothing under it is dropped).
  fn plan_rdcw_rename(
    &mut self,
    state: &ScopeState,
    scope: ScopeId,
    old: &RdcwRecord,
    new: &RdcwRecord,
  ) -> Vec<Planned> {
    let (old_resolved, new_resolved) = (resolve(&old.name), resolve(&new.name));
    if let (Resolved::Target(from), Resolved::Target(to)) = (old_resolved, new_resolved) {
      // Both ends are in-root, already root-relative: mint the counter
      // cookie and emit the adjacent pair directly — the fanotify path's
      // (Target, Target) arm, without a lossy absolute-path round-trip
      // (host path separators must never decide a lowering).
      let cookie = self.next_cookie();
      let from_rec = OsRecord::new(state.watch, RecordKind::MovedFrom)
        .with_target(from)
        .with_cookie(cookie);
      let to_rec = OsRecord::new(state.watch, RecordKind::MovedTo)
        .with_target(to)
        .with_cookie(cookie);
      return vec![Planned::Rec(from_rec), Planned::Rec(to_rec)];
    }
    let (old_resolved, new_resolved) = (resolve(&old.name), resolve(&new.name));
    // At least one end escalated (or named the root — the seam surprise):
    // cover each end at the tightest location it still names.
    let mut planned = Vec::with_capacity(2);
    for resolved in [old_resolved, new_resolved] {
      match resolved {
        Resolved::Root => planned.push(Planned::Over(Scope::Root(scope))),
        Resolved::Target(location) | Resolved::Escalate(Some(location)) => {
          planned.push(Planned::Over(located(state.watch, Some(location))));
        }
        Resolved::Escalate(None) => planned.push(Planned::Over(located(state.watch, None))),
      }
    }
    planned
  }
}

/// Plans a single-object record as `kind` at its resolved target. Extended
/// records carry directory-ness; basic records leave it unknown, exactly the
/// FSEvents no-hint default.
fn plan_single(
  state: &ScopeState,
  scope: ScopeId,
  record: &RdcwRecord,
  kind: RecordKind,
) -> Vec<Planned> {
  match resolve(&record.name) {
    // RDCW dirent names are never empty; an empty one is a seam surprise —
    // cover the root rather than fabricate a self-event.
    Resolved::Root => vec![Planned::Over(Scope::Root(scope))],
    Resolved::Target(location) => {
      let mut rec = OsRecord::new(state.watch, kind).with_target(location);
      if let Some(is_dir) = record.is_dir() {
        rec = rec.with_is_dir(is_dir);
      }
      vec![Planned::Rec(rec)]
    }
    Resolved::Escalate(location) => vec![Planned::Over(located(state.watch, location))],
  }
}
