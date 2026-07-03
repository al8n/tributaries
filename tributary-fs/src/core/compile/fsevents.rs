//! The FSEvents lowering: flag words are hints, so everything ambiguous is
//! probe-grounded before the Monitor sees a record. Moved verbatim from the
//! core when the per-scope backend profiles landed; the logic is unchanged.

use std::{
  collections::{BTreeMap, BTreeSet},
  num::NonZeroU64,
  path::PathBuf,
  vec::Vec,
};

use tributary_proto::{OsRecord, RecordKind, Scope};

use super::super::{
  DriverCore, Effect, Item, ItemPlan, Lowered, PendingBatch, Planned, ProbePurpose, ScopeId,
  ScopeState, apply_mount_add, dir_hint, located, lower, record_from_event,
};
use crate::os::RawOsEvent;

impl DriverCore {
  /// Compiles one raw batch into planned Monitor inputs, minting probes for
  /// everything a flag word alone cannot ground.
  ///
  /// Rename pairing is probe-grounded per half — there is no same-batch
  /// no-probe fast path. Each half's probe establishes existence AND the
  /// authoritative device that decides its cookie, and the pairing itself is
  /// the Monitor's `(scope, cookie)` window. The cost is one `lstat` per
  /// rename half on the blocking pool, accepted by design: an event-side
  /// pre-pair must trust device facts it cannot observe, which is exactly how
  /// a fabricated cross-device move happens.
  pub(in crate::core) fn compile_fsevents(
    &mut self,
    state: &mut ScopeState,
    scope: ScopeId,
    events: Vec<RawOsEvent>,
  ) -> PendingBatch {
    // Device-trust mutations are MONOTONE WITHIN THE BATCH. A mount ADD only
    // ever reduces trust, so it applies before anything is classified — a
    // rename sharing its batch with the MOUNT that makes its path foreign
    // must already see the prefix. An unmount REMOVE only ever increases
    // trust, so it is deferred to the batch's settlement, strictly after
    // every classification and cookie decision (including probe resolutions
    // and the vanished-half grant): a rename coalesced just before its
    // volume unmounted still fails closed.
    let mut deferred_unmounts: Vec<PathBuf> = Vec::new();
    for ev in &events {
      if ev.flags.mount() {
        apply_mount_add(state, ev);
      } else if ev.flags.unmount() && matches!(lower(state, &ev.path), Lowered::Target(_)) {
        deferred_unmounts.push(ev.path.clone());
      }
    }
    // Same-fileID grouping decides chain SUPPRESSION only. A group larger
    // than a pair is a chain or coalesced reuse: existence probes see only
    // the FINAL state of several operations, so its members never mint the
    // shared cookie and the whole group is covered by one trailing located
    // rescan. A pair or a singleton needs no belt — its probes ground each
    // half completely, and the Monitor's displacement semantics keep even a
    // mis-ordered pair a safe degrade.
    let mut rename_groups: BTreeMap<NonZeroU64, Vec<usize>> = BTreeMap::new();
    for (idx, ev) in events.iter().enumerate() {
      // Only a PURE rename word groups: a word also carrying
      // create/remove/modify/attrib bits routes through the probing grounding
      // table with its extra operation surfaced.
      if ev.flags.is_pure_rename()
        && let Some(fid) = ev.file_id
      {
        rename_groups.entry(fid).or_default().push(idx);
      }
    }
    let mut suppressed: BTreeSet<usize> = BTreeSet::new();
    let mut trailing: Vec<Planned> = Vec::new();
    for group in rename_groups.values() {
      if group.len() > 2 {
        suppressed.extend(group.iter().copied());
        trailing.push(Self::covering_rescan(
          state,
          scope,
          group.iter().map(|idx| &events[*idx].path),
        ));
      }
    }

    let mut items = Vec::with_capacity(events.len());
    let mut awaiting = 0usize;
    for (idx, ev) in events.iter().enumerate() {
      match self.plan_event(state, scope, idx, ev, !suppressed.contains(&idx)) {
        ItemPlan::Immediate(planned) => items.push(Item {
          planned,
          probe: None,
          cookie_candidate: None,
        }),
        ItemPlan::Await { probe, path } => {
          awaiting += 1;
          self.effects.push_back(Effect::Probe { probe, path });
          items.push(Item {
            planned: Vec::new(),
            probe: Some(probe),
            cookie_candidate: None,
          });
        }
      }
    }
    PendingBatch {
      items,
      awaiting,
      trailing,
      deferred_unmounts,
      evidenced: BTreeMap::new(),
      permit: None,
    }
  }

  /// Plans one non-paired event. See the design's grounding table: flags are
  /// hints; a single-verb word maps directly, everything ambiguous probes,
  /// and everything un-groundable escalates to a located rescan.
  fn plan_event(
    &mut self,
    state: &mut ScopeState,
    scope: ScopeId,
    idx: usize,
    ev: &RawOsEvent,
    allow_cookie: bool,
  ) -> ItemPlan {
    let flags = ev.flags;
    if flags.history_done() {
      return ItemPlan::Immediate(Vec::new());
    }
    if flags.root_changed() {
      let probe = self.mint_probe(scope, ProbePurpose::RootAlive { item: idx });
      let path = state
        .root
        .as_deref()
        .cloned()
        .unwrap_or_else(|| state.requested.clone());
      return ItemPlan::Await { probe, path };
    }
    if flags.event_ids_wrapped() {
      state.resume_poisoned = true;
      Self::trust_lost(&mut self.effects, scope, state);
      return ItemPlan::Immediate(vec![Planned::Over(Scope::Root(scope))]);
    }
    if flags.lost_sync() {
      Self::trust_lost(&mut self.effects, scope, state);
      return ItemPlan::Immediate(vec![Planned::Over(Scope::Root(scope))]);
    }
    if flags.must_scan_subdirs() {
      // Kernel-side loss like the drops above: the coalesced-away window may
      // have carried a mount transition. Synthesized coverage rescans (an
      // appeared directory, a chain belt) lose no events and do NOT revoke.
      Self::trust_lost(&mut self.effects, scope, state);
      return ItemPlan::Immediate(vec![Planned::Over(Self::clamp(state, scope, &ev.path))]);
    }
    if flags.mount() || flags.unmount() {
      return ItemPlan::Immediate(self.plan_mount(state, scope, ev));
    }

    let lowered = lower(state, &ev.path);
    let target = match lowered {
      Lowered::Root => None,
      Lowered::Target(location) => Some(location),
      Lowered::Outside => {
        return ItemPlan::Immediate(vec![Planned::Over(Scope::Root(scope))]);
      }
    };

    let modified = flags.item_modified();
    let attrib = flags.item_inode_meta_mod()
      || flags.item_change_owner()
      || flags.item_xattr_mod()
      || flags.item_finder_info_mod();

    if flags.item_renamed() {
      let probe = self.mint_probe(
        scope,
        ProbePurpose::Rename {
          item: idx,
          file_id: ev.file_id,
          target,
          path: ev.path.clone(),
          allow_cookie,
          content_changed: modified || attrib,
        },
      );
      return ItemPlan::Await {
        probe,
        path: ev.path.clone(),
      };
    }

    let created = flags.item_created();
    let removed = flags.item_removed();
    match u8::from(created) + u8::from(removed) + u8::from(modified) + u8::from(attrib) {
      0 => {
        // A flag-less event means "something changed at this directory" with
        // no per-item detail: only a located rescan is honest.
        let over = Planned::Over(located(state.watch, target));
        ItemPlan::Immediate(vec![over])
      }
      1 => {
        let kind = if created {
          RecordKind::Created
        } else if removed {
          RecordKind::Removed
        } else if modified {
          RecordKind::Modified
        } else {
          RecordKind::Attrib
        };
        let rec = record_from_event(state, kind, target, dir_hint(flags), ev.file_id, &ev.path);
        ItemPlan::Immediate(vec![Planned::Rec(rec)])
      }
      _ => {
        let probe = self.mint_probe(
          scope,
          ProbePurpose::Ambiguous {
            item: idx,
            flags,
            target,
            path: ev.path.clone(),
          },
        );
        ItemPlan::Await {
          probe,
          path: ev.path.clone(),
        }
      }
    }
  }

  /// Plans a mount-table update plus the located rescan the volume change
  /// obliges; an unmount of the root itself is the scope's death.
  fn plan_mount(
    &mut self,
    state: &mut ScopeState,
    scope: ScopeId,
    ev: &RawOsEvent,
  ) -> Vec<Planned> {
    match lower(state, &ev.path) {
      Lowered::Root if ev.flags.unmount() => {
        vec![Planned::Rec(OsRecord::new(
          state.watch,
          RecordKind::Ignored,
        ))]
      }
      Lowered::Root => vec![Planned::Over(Scope::Root(scope))],
      Lowered::Target(location) => {
        // The trust mutation already ran in `compile`'s pre-scan; the volume
        // change here plans only the coverage obligation it creates.
        vec![Planned::Over(located(state.watch, Some(location)))]
      }
      Lowered::Outside => vec![Planned::Over(Scope::Root(scope))],
    }
  }
}
