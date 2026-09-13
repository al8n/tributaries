//! The FSEvents lowering: flag words are hints, so everything ambiguous is
//! probe-grounded before the Monitor sees a record. Moved verbatim from the
//! core when the per-scope backend profiles landed; the logic is unchanged.

use std::{
  collections::{BTreeMap, BTreeSet},
  num::NonZeroU64,
  path::{Path, PathBuf},
  vec::Vec,
};

use tributary_proto::{Evidence, Location, OsRecord, RecordKind, Scope};

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
  ///
  /// What a half CAN be spared is a probe whose every verdict the common-layer
  /// fence would discard: ground the per-root seat closes is asked about before
  /// the probe is minted ([`under_closed_ground`](Self::under_closed_ground)),
  /// not after it answers.
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
          self.effects.push_back(Effect::Probe {
            scope,
            incarnation: state.incarnation,
            probe,
            path,
          });
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
      deferred_consumptions: Vec::new(),
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
    let created = flags.item_created();
    let removed = flags.item_removed();

    if flags.item_renamed() {
      // ASK THE FENCE FIRST. A rename word whose ground the seat closes, and
      // whose class the word itself proves not to be a directory, has no
      // verdict left for a probe to establish: every `Planned` the resolution
      // could yield is one the common-layer fence drops. The probe would be
      // pure waste, and while it is awaited the batch is parked and every later
      // batch of the root queues behind it — so the record is dropped here,
      // where the post-probe fence would have dropped it.
      //
      // The seat is read class-independently ([`DriverCore::is_pruned`] with
      // `directory` false): it speaks for the ANCESTORS alone and never for the
      // last component, so a path whose own name matches a word keeps its probe
      // — its class is exactly what the probe is for, and a directory renamed
      // into the seat owes the widened-cover repair the post-probe arm
      // performs. That is also why the class must be PROVEN here: an unproven
      // class is read as a directory, because the profiles that report the
      // fewest classes are exactly the ones that move whole subtrees silently.
      //
      // The drop strands no pairing, and needs no consumption to say so. A half
      // is parked only for a rename's SOURCE, and this profile grants a
      // vanished source its cookie solely on the probe evidence of exactly one
      // same-batch PRESENT partner — evidence a record dropped before its probe
      // never publishes. So a rename INTO closed ground leaves its unpruned
      // source uncookied and the Monitor resolves it as an immediate removal,
      // and a rename OUT of closed ground leaves nothing parked for its
      // unpruned destination to wait on, which arrives as an appearance. Both
      // surviving halves resolve at once rather than after the pairing window.
      if dir_hint(flags) == Some(false)
        && Self::under_closed_ground(state, target.as_ref(), &ev.path)
      {
        return ItemPlan::Immediate(Vec::new());
      }
      let probe = self.mint_probe(
        scope,
        ProbePurpose::Rename {
          item: idx,
          file_id: ev.file_id,
          target,
          path: ev.path.clone(),
          allow_cookie,
          // Two distinct proven facts, kept distinct: OR-ing them into one
          // bool made a metadata-only word mint a `Modified` record, which an
          // attrib-only subscription does not admit.
          content: Evidence::new()
            .maybe_modified(modified)
            .maybe_attrib(attrib),
        },
      );
      return ItemPlan::Await {
        probe,
        path: ev.path.clone(),
      };
    }

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
        // The same pre-probe fence, and here it needs no class proof: this
        // purpose's outcomes are built from an existence verdict and the word's
        // own content and metadata bits, so none of them can be the rename
        // destination the fence widens instead of dropping. Every verdict under
        // closed ground is a drop for any class, and nothing pairs.
        if Self::under_closed_ground(state, target.as_ref(), &ev.path) {
          return ItemPlan::Immediate(Vec::new());
        }
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

  /// Whether `path` lies UNDER ground the per-root seat closes — asked ahead of
  /// the probe that would otherwise ground it.
  ///
  /// Two questions, in the order the common-layer fence asks them and through
  /// the fence's own predicates, so the two seats cannot drift apart:
  ///
  /// - the marker exemption. A location whose last segment is an ACTIVE marker
  ///   leaf of this scope stands whatever the seat says: its event is what a
  ///   barrier waits on, and a seat that suppressed it would leave the caller
  ///   waiting on an event that can no longer exist.
  /// - the seat itself, read CLASS-INDEPENDENTLY. `directory` is the caller's
  ///   PROOF that the last segment is a directory, never its suspicion, and
  ///   nothing is proven before the probe — so the walk is asked about the
  ///   ancestors alone. That is the same reading the fence applies to a
  ///   vanished half's record, and it implies the reading it applies to a
  ///   present one, whose walk asks a superset of these prefixes under the same
  ///   exemption window. Nothing is dropped here that the fence would keep.
  ///
  /// The EXCLUSION half of the fence is absent on purpose: this profile hands
  /// its exclusions to the OS, which drops those events before the process sees
  /// them, so the common layer stands that half down and a test here would be
  /// suppression the fence itself does not perform.
  ///
  /// Costs nothing on a root that configured no seat: the walk returns at once
  /// on an empty pattern set, as the marker question does on an empty map.
  fn under_closed_ground(state: &ScopeState, target: Option<&Location>, path: &Path) -> bool {
    !Self::names_active_marker(state, target) && Self::is_pruned(state, false, path)
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
