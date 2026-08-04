//! The inotify lowering: depth-one records with precise verbs and native
//! kernel cookies — no grounding probes, no evidence grants, no parking. Each
//! anchor-attributed record fans out into one [`OsRecord`] per anchor (an
//! aliased inode is several independent Monitor nodes; duplicate state-facts
//! are idempotent under the emit dedup).

use std::{num::NonZeroU64, vec::Vec};

use tributary_proto::{Evidence, MoveCookie, OsRecord, RecordKind, Scope, Segment, WatchId};

use crate::os::linux::{RawInotifyEvent, RawLinuxEvent};

use super::super::{
  DriverCore, Item, PendingBatch, Planned, ScopeId, ScopeState, TaintCause, located,
};

impl DriverCore {
  /// Lowers one inotify batch. Every item is immediate (`awaiting == 0`), so
  /// the batch settles inline and the park never engages under this profile.
  ///
  /// That completeness is what licenses the profile's feeding discipline: with no
  /// item left standing on a probe, the exclusion fence may hand each kept record
  /// to the Monitor as it classifies it rather than buffering the read
  /// (`feeds_at_classify`). Nothing here may start minting probes without moving
  /// that discipline too — the coupling is asserted where the fence runs.
  pub(in crate::core) fn compile_inotify(
    &mut self,
    state: &mut ScopeState,
    scope: ScopeId,
    events: Vec<RawLinuxEvent>,
  ) -> PendingBatch {
    let mut items = Vec::with_capacity(events.len());
    for ev in events {
      // The dispatch only ever routes inotify events here; a fanotify event
      // would be a seam bug (`compile` asserts it and covers the batch with a
      // root rescan), so skip it rather than mis-lower.
      let RawLinuxEvent::Inotify { anchors, event } = ev else {
        continue;
      };
      items.push(Item {
        planned: plan_inotify(state, scope, &anchors, &event),
        probe: None,
        cookie_candidate: None,
      });
    }
    PendingBatch {
      items,
      awaiting: 0,
      trailing: Vec::new(),
      deferred_unmounts: Vec::new(),
      evidenced: std::collections::BTreeMap::new(),
      permit: None,
    }
  }
}

/// Plans one attributed inotify record, fanned out per anchor.
fn plan_inotify(
  state: &mut ScopeState,
  scope: ScopeId,
  anchors: &[WatchId],
  event: &RawInotifyEvent,
) -> Vec<Planned> {
  let mask = event.mask;
  // The reader converts overflow sentinels to the in-order loss signal, so
  // one reaching the lowering is a seam bug; degrade to the root rescan the
  // loss path would have produced rather than dropping it.
  if mask.is_overflow() {
    debug_assert!(false, "the reader strips overflow sentinels");
    return vec![Planned::Over(Scope::Root(scope))];
  }
  let mut planned = Vec::with_capacity(anchors.len());
  for &anchor in anchors {
    // The witnessed window's record leg (INV-ROOT): a record attributed to a
    // pending widen's RESERVED root is consumed HERE — before the Monitor's
    // unknown-watch guard would drop it silently. A death record (`Ignored`
    // ⊇ unmount, `MoveSelf`, `DeleteSelf`) taints the window, so the commit
    // gate refuses the same-fd splice and the fallback's spawn barrier
    // re-establishes the binding; benign churn is counted and converges
    // through the post-commit cold read exactly as it always did. Nothing is
    // ever planned for the reserved anchor — pre-commit it has no node, and
    // the taint is the record's entire meaning.
    if let Some(pending) = state.pending_widen.as_mut()
      && pending.reserved == anchor
    {
      if mask.is_ignored() || mask.unmount() {
        pending.taint(TaintCause::RootDeath(RecordKind::Ignored));
      } else if mask.move_self() {
        pending.taint(TaintCause::RootDeath(RecordKind::MoveSelf));
      } else if mask.delete_self() {
        pending.taint(TaintCause::RootDeath(RecordKind::DeleteSelf));
      } else {
        pending.benign = pending.benign.saturating_add(1);
      }
      continue;
    }
    // Self-events first: they carry no name and resolve the watch itself.
    // An unmount ends the watch's coverage exactly like the kernel's own
    // trailing IN_IGNORED (which then finds the node already gone — a no-op).
    if mask.is_ignored() || mask.unmount() {
      planned.push(Planned::Rec(OsRecord::new(anchor, RecordKind::Ignored)));
      continue;
    }
    if mask.move_self() {
      planned.push(Planned::Rec(OsRecord::new(anchor, RecordKind::MoveSelf)));
      continue;
    }
    if mask.delete_self() {
      planned.push(Planned::Rec(OsRecord::new(anchor, RecordKind::DeleteSelf)));
      continue;
    }
    let Some(kind) = verb(event) else {
      // A mask carrying none of the subscribed verbs is kernel noise for
      // this vocabulary; skip it rather than fabricate a record.
      continue;
    };
    let segment = match &event.name {
      None => None,
      Some(bytes) => match core::str::from_utf8(bytes) {
        Ok(name) => Some(Segment::new(name)),
        Err(_) => {
          // A non-UTF-8 name cannot become a `Segment` (the documented v1
          // limitation): escalate a located rescan of the watched directory
          // so the consumer re-reads it — coverage-honest, never silent.
          planned.push(Planned::Over(located(anchor, None)));
          continue;
        }
      },
    };
    let mut rec = OsRecord::new(anchor, kind)
      .with_is_dir(mask.is_dir())
      .also_proved(proven(event));
    if let Some(segment) = segment {
      rec = rec.with_name(segment);
    }
    if kind.is_move_half()
      && let Some(cookie) = NonZeroU64::new(u64::from(event.cookie))
    {
      rec = rec.with_cookie(MoveCookie::new(cookie));
    }
    planned.push(Planned::Rec(rec));
  }
  planned
}

/// Everything a mask PROVES, mapped bit by bit. inotify verbs are precise — the
/// kernel queues one record per verb, so this is normally the singleton
/// [`verb`] already names. It is carried anyway, and as a total map rather than
/// a chain, so a mask that ever does report two facts admits both subscriptions
/// instead of losing whichever the priority below did not pick.
fn proven(event: &RawInotifyEvent) -> Evidence {
  let mask = event.mask;
  Evidence::new()
    .maybe_created(mask.created())
    .maybe_removed(mask.removed())
    .maybe_modified(mask.modified())
    .maybe_attrib(mask.attrib())
    .maybe_moved(mask.moved_from() || mask.moved_to())
}

/// The record verb a mask names, if any. inotify verbs are precise — exactly
/// one of these bits is set per queued record for the subscribed mask.
fn verb(event: &RawInotifyEvent) -> Option<RecordKind> {
  let mask = event.mask;
  if mask.created() {
    Some(RecordKind::Created)
  } else if mask.removed() {
    Some(RecordKind::Removed)
  } else if mask.moved_from() {
    Some(RecordKind::MovedFrom)
  } else if mask.moved_to() {
    Some(RecordKind::MovedTo)
  } else if mask.modified() {
    Some(RecordKind::Modified)
  } else if mask.attrib() {
    Some(RecordKind::Attrib)
  } else {
    None
  }
}
