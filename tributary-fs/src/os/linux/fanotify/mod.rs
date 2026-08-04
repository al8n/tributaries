//! The fanotify-FILESYSTEM backend: kernel-recursive, privileged, riding the
//! same DriverCore shape the FSEvents loop hardened.
//!
//! Pure machinery — the FID wire decode ([`fid`]) and the admission/intern map
//! ([`map`]) — compiles everywhere tests run (including miri), mirroring the
//! inotify precedent; the FFI Source (the superblock mark, its reader thread,
//! and the seeding walk) is `cfg(all(target_os = "linux", not(miri)))`.
//!
//! A single `FAN_MARK_FILESYSTEM` mark scopes to the whole superblock, so the
//! reader admits by directory-FID membership in a per-root [`FidMap`] before an
//! event ever reaches the seam: an unknown handle is provably outside the root
//! and dropped. Admitted events cross the driver's queue as
//! [`AdmittedEvent`]s inside [`RawLinuxEvent::Fanotify`](super::RawLinuxEvent),
//! carrying paths already resolved against the map — the compile path only
//! lowers each absolute path to its root-relative form. No node identity rides
//! with them: under the kernel-recursive profile record identity is inert
//! (design §4.9), exactly as the FSEvents lowering attaches none.
//!
//! Root UNMOUNT carries NO in-tree fanotify signal — an unmounted
//! `FAN_MARK_FILESYSTEM` superblock stays alive under the mark and the fd simply
//! goes quiet (design §7, container-validated L4.1). Detection is the mount
//! refresh's folded-in root re-stat (`FsOps::refresh_mounts` →
//! `MountRefresh.root`), compared against the barrier identity in
//! `DriverCore::on_mounts_refreshed`: a missing/replaced root lowers the same
//! `DeleteSelf`/`MoveSelf` death lifecycle a macOS `RootChanged` probe uses.
//! (An in-tree delete/replace of the ROOT object itself, by contrast, DOES
//! arrive as `FAN_DELETE_SELF`/`FAN_MOVE_SELF`.)
//!
//! That refresh runs at scope birth and on every loss signal — but a QUIET
//! unmount produces neither, so those triggers alone would never observe it.
//! The composition therefore adds ONE timer: the periodic root-liveness tick
//! (`WatcherOptions::root_liveness_interval`, fanotify-only — see the
//! per-backend death-signal table in the `core` module docs), which re-stats the
//! root on a bounded cadence so a signal-silent unmount is detected within the
//! interval. A loss-triggered refresh still catches it immediately when one
//! occurs; the tick only bounds the otherwise-unobservable quiet case, and
//! `Duration::ZERO` disables it (back to quiet-but-alive until re-access fails).

pub(crate) mod fid;
pub(crate) mod map;

#[cfg(test)]
mod tests;

use std::{
  collections::BTreeMap,
  path::{Path, PathBuf},
};

pub(crate) use fid::{FanMask, RawFanotifyEvent};
use fid::{Fid, RenameInfo};
use map::FidMap;

/// One `FAN_RENAME`'s two admitted halves: each resolved absolute path. Both
/// halves are always present (the kernel reports the atomic pair in one event),
/// so the lowering emits adjacent `MovedFrom`/`MovedTo` with no pairing window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmittedRename {
  /// The source's absolute path (old directory + old name).
  pub(crate) old_path: PathBuf,
  /// The destination's absolute path (new directory + new name).
  pub(crate) new_path: PathBuf,
}

/// One fanotify event after admission: its mask, the affected object's absolute
/// path (resolved from the directory FID + name against the [`FidMap`]), and —
/// for a rename — the atomic pair. No node identity: under the kernel-recursive
/// profile record identity is inert (design §4.9).
///
/// A single-object dirent event carries `path`; a `FAN_RENAME` carries `rename`
/// and leaves the single-object fields empty; a self-event
/// (`DELETE_SELF`/`MOVE_SELF`) whose object is the admitted directory carries
/// that directory's `path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmittedEvent {
  pub(crate) mask: FanMask,
  pub(crate) path: Option<PathBuf>,
  pub(crate) rename: Option<AdmittedRename>,
}

/// A per-read-batch admission memo (design §4.9): caches the ADMITTED
/// `(directory handle → resolved absolute path)` of the events in one
/// [`decode_events`](fid::decode_events) buffer, the storm win when many events
/// address few directories (a rename storm under one parent).
///
/// Soundness rests on the [`FidMap`]'s generation counter. Each cached entry is
/// tagged with the map generation it was resolved against; a lookup is a hit only
/// when the tag still equals the map's current generation. Because EVERY map
/// mutation (`learn`/`forget`/`reseed`/an orphan eviction) bumps that counter,
/// any mutation `admit` performs mid-batch invalidates the whole memo by making
/// every prior tag stale — so the memo can never serve a path the map has since
/// re-parented or pruned. The reader is single-threaded and owns both the map and
/// the memo, so no other writer exists; a fresh `MemoBatch` is used per buffer, so
/// it is also cleared at batch end by construction.
pub(crate) struct MemoBatch {
  /// The admitted `directory handle → (generation, resolved path)` cache. A miss
  /// (an out-of-root directory) is never inserted, so the memo stays bounded by
  /// the distinct in-root directories the batch touched.
  entries: BTreeMap<Box<[u8]>, (u64, PathBuf)>,
  /// How many lookups were served from the cache — an operator-facing counter.
  pub(crate) hits: u64,
  /// How many lookups fell through to a fresh [`FidMap::admit`] (a cold directory
  /// or a stale-generation entry).
  pub(crate) misses: u64,
}

impl MemoBatch {
  /// A fresh, empty memo for one read batch.
  pub(crate) fn new() -> Self {
    Self {
      entries: BTreeMap::new(),
      hits: 0,
      misses: 0,
    }
  }

  /// Resolves a directory FID to its admitted path THROUGH the memo. A cached
  /// entry whose generation still matches the map's is returned directly (a hit);
  /// otherwise the lookup falls to [`FidMap::admit`] (which resolves-or-evicts and
  /// may itself bump the generation), and a resolved path is cached under the
  /// map's post-lookup generation. A miss (`None`) is not cached — the next event
  /// under that handle re-checks membership, honoring a later `learn` of it.
  fn admit(&mut self, map: &mut FidMap, fid: &Fid) -> Option<PathBuf> {
    let generation = map.generation();
    if let Some((tagged, path)) = self.entries.get(fid.handle())
      && *tagged == generation
    {
      self.hits += 1;
      return Some(path.clone());
    }
    self.misses += 1;
    let path = map.admit(fid)?;
    // `admit` may have evicted an orphan on a miss and bumped the generation, but
    // this is the hit branch (a path resolved), which mutates nothing — so the
    // post-call generation still equals the one captured above and correctly tags
    // the entry.
    self
      .entries
      .insert(fid.handle().into(), (map.generation(), path.clone()));
    Some(path)
  }
}

/// The single ACTION one decoded event is classified into — the seam's single
/// source of truth. [`classify`] consults the mask, the event's field PRESENCE,
/// and the map (directory membership + the root anchor) to select EXACTLY one
/// variant, and the variant's OWN required fields are the validation: an action
/// whose field is absent is [`Lossy`](Self::Lossy) by construction, so there is no
/// separate decode-side required-field matrix to drift out of step with the field
/// consumers. The classifier applies each action's map self-maintenance inline
/// (learn/forget/re-parent), so the returned event is already resolved against the
/// post-mutation map; the reader only forwards it (and, for a move-in, walks the
/// subtree). Decode, admission, and the death path therefore cannot disagree —
/// every event shape resolves to one action here.
#[derive(Debug)]
pub(crate) enum Admission {
  /// An admitted event whose admission mutated NO directory node — a file
  /// (non-`ONDIR`) create/delete/modify/attrib, a non-structural directory
  /// modify/attrib (reported as a dirent, OR name-less on the directory's own
  /// admitted FID), or a directory's own name-less `MOVE_SELF` (a self-move rescan;
  /// the moved node is re-parented by its rename/dirent, not here). Forward the
  /// resolved path. REQUIRES an admitted addressing FID and — for a dirent — a name.
  ///
  /// This also carries the ONE merged mask the universal gate exempts (a plain file's
  /// create+delete, [`map_neutral_merge`]): map-neutral like every other member, but
  /// verb-ambiguous, which compile resolves by lowering it to a located `Rescan`
  /// rather than a record. Admission asks only whether the map is safe; the record
  /// vocabulary is the lowering's question.
  Forward(AdmittedEvent),
  /// A new in-root child directory `learn`ed into the map (ALREADY applied), then
  /// forwarded — an `ONDIR` create. REQUIRES dir_fid (admitted) + name + the
  /// child's own `target_fid` (the node key); absent → [`Lossy`](Self::Lossy),
  /// because a create whose child cannot enter the map would blind that subtree.
  LearnDir(AdmittedEvent),
  /// A departed in-root directory `forget`/pruned from the map (ALREADY applied),
  /// then forwarded — a parent-reported `DELETE|ONDIR`/move-out dirent, or a
  /// directory's own name-less `DELETE_SELF`. REQUIRES the departing directory's
  /// FID (a dirent's `target_fid`; a self-event's own FID); a dirent absent it →
  /// [`Lossy`](Self::Lossy), because an un-pruned subtree resolves stale forever.
  ForgetDir(AdmittedEvent),
  /// A `FAN_RENAME` resolved and its map self-maintenance applied (in-root
  /// re-parent / move-out `forget` / move-in `learn`). `seed` is the moved
  /// directory's FID when the reader must walk its descendants in before forwarding —
  /// it arrived from OUTSIDE the root, or it was re-parented across a change in
  /// exclusion geometry ([`exclusion_geometry_changed`]) that makes the map's picture
  /// of the subtree disagree with the fence's. `None` for a geometry-preserving
  /// in-root re-parent, a move-out, or a file/boundary rename. REQUIRES both halves (+
  /// `target_fid` when `ONDIR`, else → [`Lossy`](Self::Lossy)).
  ///
  /// The move-in `seed` carries the moved FID, NOT a captured path: the reader
  /// resolves the directory's CURRENT path through the map at walk time, because an
  /// in-root rename in the SAME batch may have re-parented it since this admission.
  Rename {
    /// The resolved move to forward once any subtree is mapped.
    event: AdmittedEvent,
    /// The moved directory's own FID when its subtree must be walked in (a move-IN
    /// from outside), else `None`.
    seed: Option<Fid>,
  },
  /// The WATCHED ROOT's own terminal death, from EITHER shape it can be reported in: a
  /// self-event (`DELETE_SELF`/`MOVE_SELF`) whose self-FID (the `DFID` shape's `dir_fid`,
  /// or the `FID`-only shape's `target_fid`) resolves to the map's root anchor
  /// ([`FidMap::is_root`](map::FidMap::is_root)); OR a dirent/rename reporting the root
  /// deleted/moved FROM ITS FOREIGN PARENT (`dir_fid`, or both rename ends, out-of-root
  /// while `target_fid` is the root — see [`classify_foreign_parent`]). Forward the root's
  /// OWN path, restated to the self form ([`root_death_mask`]) so compile lowers it to the
  /// death lifecycle — a delete to a terminal Removed + Rescan, a move to a terminal
  /// Rescan. Because every carried FID is consulted the same way for every mask, a FID-only
  /// root self-event (`dir_fid = None`) OR a foreign-parent root dirent reaches death even
  /// when the periodic liveness tick is disabled, rather than being dropped and left
  /// forever blind.
  RootDeath(AdmittedEvent),
  /// Provably outside the watched root, and not a root self-event: no admitted
  /// directory FID matched (or the self-FID is unknown to the map). The
  /// superblock-firehose filter — a clean drop, never a loss, so the sb's constant
  /// foreign self/attrib traffic never reseeds.
  ForeignDrop,
  /// Outside the REPORTED tree — the root MINUS the caller's exclusions: NO path
  /// the event names lies in that tree (each is either at or under an exclusion,
  /// or off the watched root entirely), NO object it acts on is one the map holds
  /// inside that tree, and the event cannot be the root's own death. Decided by
  /// [`fence`] at the
  /// TOP of [`classify`] — ahead of the multi-structural gate and ahead of every
  /// shape dispatch — so the action never runs and the map is provably untouched:
  /// no `learn`, no `learn_moved_in`, no re-parent, no `forget`, no move-in
  /// subtree walk, and no orphan eviction. That ordering is the whole point. An
  /// exclusion is a load-shedding instruction, so an excluded subtree must cost
  /// the source NOTHING; classifying first and suppressing afterwards let live
  /// creates and populated move-ins under an excluded path grow the admission map
  /// until it hit [`FidMap::over_capacity`](map::FidMap::over_capacity) and killed
  /// the source, dropping coverage for every subscription that had nothing to do
  /// with the exclusion.
  ///
  /// A clean drop like [`ForeignDrop`](Self::ForeignDrop), never a loss: the
  /// event mutated nothing, so no co-batched neighbour can misresolve because of
  /// it and there is nothing for a reseed to repair. That last clause is a
  /// PROPERTY OF THE OBJECT, not of the paths — which is why the fence proves it
  /// separately ([`affects_reported_object`]) instead of inferring it from the
  /// paths being unreported.
  ExcludedDrop,
  /// The buffer must take the ordered `Overflow` barrier (reseed + covering rescan),
  /// for one of two reasons, both decided AT the action rather than by a separate
  /// decode matrix:
  ///
  /// - an ADMITTED event whose merged mask names two or more structural verbs (the
  ///   kernel merges consecutive events for one object — a directory renamed AND
  ///   deleted, a delete_self+move_self of one object) is AMBIGUOUS: no single tree
  ///   mutation is correct, and the universal gate in [`classify`] routes it here
  ///   before any shape can apply a one-sided mutation. The ONE exception is the
  ///   MAP-NEUTRAL merge ([`map_neutral_merge`]) — a plain file's create+delete under
  ///   an admitted parent, which mutates no node at all and so is [`Forward`](Self::Forward)ed
  ///   for compile to cover with a located `Rescan`; OR
  /// - the single action the mask names needs a field the event does not carry (a
  ///   named dirent with no/empty name; a directory create/delete/move/rename with no
  ///   child `target_fid`) — a missing field would silently mishandle the map.
  ///
  /// Either way the reader takes the barrier and reseeds, exactly as a wire-level
  /// decode loss.
  Lossy,
}

/// Classifies one decoded event into its [`Admission`] action against the per-root
/// map: resolves the ADDRESSING object's FID to a path through the batch
/// [`MemoBatch`], and applies the action's map self-maintenance inline (learn on a
/// directory create, forget on a delete/move-out, re-parent on a rename). PURE — the
/// reader calls this single-threaded between reads; the FFI side owns nothing but the
/// fd and the seeding walk. No node identity is produced; admission is membership +
/// path resolution only (design §4.9).
///
/// The classification is EXHAUSTIVE and TOTAL: every `(mask, field-presence,
/// map-state)` maps to exactly one action, with no catch-all silent fall-through —
/// an unrecognized shape is explicitly [`Admission::ForeignDrop`] or
/// [`Admission::Lossy`], never a wrong forward.
///
/// A UNIVERSAL multi-structural gate runs FIRST, before any shape dispatch: an
/// admitted event whose merged mask names two or more structural verbs (the kernel
/// merges consecutive events for one object — a directory renamed AND deleted, a
/// create+delete of one name) is ambiguous and takes the loss barrier
/// ([`Admission::Lossy`]). This is the ONE place the ambiguity guard lives, and every
/// shape — rename included — flows through it, so no event can reach a single-verb map
/// mutation on an ambiguous mask BY CONSTRUCTION (not by each shape remembering to
/// re-check). `FAN_RENAME` counts as a structural verb for this
/// ([`FanMask::multi_structural`]), so a PURE rename (exactly one structural verb)
/// still dispatches to [`classify_rename`] while a merged rename+delete is barred.
///
/// Resolution is UNIFORM across masks: past the gate, the addressing object is resolved
/// and its admittance checked the SAME way for every mask, and only THEN does the mask
/// select the action. There is no mask special-cased to consult a FID ahead of a
/// membership gate, and no pre-classification `dir_fid`-absent drop — so no event
/// whose addressing object is admitted can be dropped, for ANY mask. The three shapes:
///
/// 1. a `FAN_RENAME` is its own event shape ([`classify_rename`], resolved from its
///    two addressing directory FIDs);
/// 2. a NAMED event addresses a child under its parent directory (`dir_fid`) —
///    [`classify_dirent`];
/// 3. a NAME-LESS event addresses its OWN object by its self-FID (the `DFID` shape's
///    `dir_fid`, or the `FID`-only shape's `target_fid`) — [`classify_nameless`].
///
/// This GENERALIZES the earlier root-death-before-the-gate special case (a root
/// self-event routing to [`Admission::RootDeath`] even in the `dir_fid = None`
/// FID-only shape) to every mask: the root death is now just the name-less shape whose
/// resolved self-object is the map's root anchor, and the same uniform admittance that
/// saves it saves every other admitted-FID event too.
///
/// The EXCLUSION fence runs FIRST, ahead of even the multi-structural gate
/// ([`fence`]): an event that names NO path in the reported tree AND acts on no object
/// the map holds inside it is [`Admission::ExcludedDrop`] before any shape can learn,
/// re-parent, forget, or hand the reader a subtree to walk. Deciding it here — rather
/// than suppressing the forwarded event at the seam — is what keeps excluded churn from
/// growing the admission map at all, and it is safe to place ahead of the ambiguity gate
/// precisely because the drop mutates nothing: the barrier exists to stop an ambiguous
/// event from staling the map its buffer-mates resolve through, and an event the fence
/// never classifies cannot stale anything.
///
/// The fence's OTHER verdict is why that placement stays honest. An event whose paths are
/// all unreported may still be about an object the map holds AT A REPORTED PATH, and
/// dropping THAT strands the map's picture of a subtree the event destroyed or moved. So
/// the fence answers [`Admission::Lossy`] for it — the same barrier the multi-structural
/// gate and every shape's missing-field arm take — rather than a clean drop it has not
/// earned. The fence stays FIRST and READ-ONLY either way: the barrier is a verdict, not
/// a mutation, and taking it here instead of after the gate keeps the "a fenced event
/// never classifies" property that makes the whole ordering sound.
pub(crate) fn classify(
  map: &mut FidMap,
  event: &RawFanotifyEvent,
  memo: &mut MemoBatch,
  exclusions: &[PathBuf],
) -> Admission {
  // THE EXCLUSION fence, ahead of every mutation site in this function. Read-only
  // (`resolve_path`, never `admit`), so the decision is made against the map state the
  // shapes will act on and nothing is mutated to reach it.
  if let Some(fenced) = fence(map, event, exclusions) {
    return fenced;
  }

  // THE UNIVERSAL multi-structural gate — the ONE place the ambiguity guard lives, and
  // EVERY event shape passes through it before the rename-vs-dirent-vs-nameless
  // dispatch below. A merged bitmask naming two or more structural verbs (man 7
  // fanotify merges consecutive events for one object: a directory renamed AND deleted,
  // a create+delete of one name, a delete_self+move_self of one object) has no single
  // correct tree mutation — applying one verb and dropping the rest is a one-sided map
  // mutation (a departed directory left learned; a rename's re-parent that silently
  // drops its co-merged delete). So an ADMITTED multi-structural event takes the loss
  // barrier (`Lossy` → reseed + covering `Overflow`) here, BY CONSTRUCTION, before any
  // shape can reach a single-verb mutation — the rename shape included, which
  // `FAN_RENAME`-as-a-structural-verb folds into the same count.
  //
  // The gate is admittance-scoped, and its admittance is ACTION-AWARE: an event takes the
  // barrier when ANY structural-verb FID it carries — the rename parents, `dir_fid`, or the
  // moved/self `target_fid` — is in-root (`addresses_in_root`), so a merged rename+self
  // whose only in-root FID is `target_fid` (its rename parents foreign, the moved object
  // itself the root) is barred here rather than dropped by the rename shape's both-ends-out
  // check. A fully-foreign multi-structural event (no carried FID in-root) flows to the
  // dispatch and `ForeignDrop`s through its shape's own membership gate, so the superblock
  // firehose's constant foreign multi-structural traffic never reseeds.
  //
  // The ONE merge exempted is the provably MAP-NEUTRAL one
  // ([`map_neutral_merge`]) — a plain file's create+delete under an admitted
  // parent, which no verb in the mask can mutate the map from. The barrier's
  // whole rationale is that a map staled by the ambiguous event misresolves its
  // CO-BATCHED neighbours, so where nothing can be staled it buys nothing and
  // costs every unrelated event in the same read. Its residual ambiguity is one
  // NAME's verb, and compile covers exactly that name with a located `Rescan`.
  if event.mask.multi_structural()
    && addresses_in_root(map, event)
    && !map_neutral_merge(map, event)
  {
    return Admission::Lossy;
  }

  if let Some(rename) = &event.rename {
    return classify_rename(map, event, rename, memo, exclusions);
  }

  // A named event addresses a CHILD under its parent directory (`dir_fid`); a
  // name-less event addresses its OWN object by its self-FID. Either shape resolves
  // its ADDRESSING object and checks admittance the SAME way before the mask selects
  // an action, so no event whose addressing object is admitted is ever dropped, for
  // any mask.
  match event.name.as_ref() {
    Some(name) => classify_dirent(map, event, name, memo),
    None => classify_nameless(map, event, memo),
  }
}

/// The EXCLUSION fence: the verdict for an event the caller asked to hear nothing about,
/// or `None` when the event belongs to the reported tree and must classify normally. Made
/// READ-ONLY and BEFORE any map mutation, at the top of [`classify`].
///
/// Suppression is TWO questions, not one, and conflating them is what let an unrelated
/// exclusion silence a required barrier:
///
/// 1. does the event name any path in the reported tree ([`names_no_reported_path`])? and
/// 2. does it act on any OBJECT the map holds in the reported tree
///    ([`affects_reported_object`])?
///
/// A path an event names and the object it acts on are different things, and a fanotify
/// event routinely reports one without reporting the other: a dirent names
/// `<parent>/<name>` but acts on the child its `target_fid` identifies, and a
/// `FAN_RENAME` names its two endpoint paths but acts on the moved object its
/// `target_fid` identifies. When the endpoints resolve nothing — the parents are off the
/// watched root — the FIRST question answers "no path is reported" while the object the
/// event destroys or relocates is an admitted directory sitting at a perfectly reportable
/// path. Answering only the first question dropped that event as excluded churn, and the
/// map kept resolving the departed subtree at its stale path: later events under it were
/// misdelivered under names that no longer exist, and the nodes went on consuming the
/// admission cap the exclusion exists to protect. Worse, the outcome DEPENDED on an
/// exclusion that had nothing to do with the event — with no exclusions at all the same
/// event correctly took the loss barrier through the action-aware multi-structural gate
/// or [`classify_foreign_parent`].
///
/// So the fence suppresses only what it can suppress for FREE. With no reported path and
/// no reported object, the drop is free exactly as [`Admission::ForeignDrop`] is: nothing
/// was mutated, nothing is stale, nothing is owed. With no reported path but a REPORTED
/// OBJECT, the drop is not free — the map's picture of that object is now unproven — and
/// the fence answers [`Admission::Lossy`]. It cannot answer anything else: forwarding
/// would hand the lowering only unreported paths to name, and mutating the map here would
/// break the read-only ordering the fence's placement depends on. The barrier drops the
/// buffer, reseeds the map through the WALK fence (which re-applies the exclusions), and
/// covers the scope with one `Overflow` — coverage-honest, and never a terminal.
///
/// The cap guarantee survives because excluded CHURN acts on objects the map does not
/// hold: a create's child is new, and a subtree moved in from outside the root is
/// unmapped by construction. Those stop at [`FidMap::contains`](map::FidMap::contains) —
/// one hash lookup, no path built — and still drop clean, so an excluded subtree still
/// costs the source nothing. What newly takes the barrier is only the case where the map
/// itself says an admitted, reportable object was destroyed.
fn fence(map: &FidMap, event: &RawFanotifyEvent, exclusions: &[PathBuf]) -> Option<Admission> {
  // Exclusions are rare and this runs per decoded event: answer the empty set without
  // resolving anything. With no exclusions the fence has no opinion at all, so the
  // action is bit-for-bit what it was before exclusions existed.
  if exclusions.is_empty() {
    return None;
  }
  // The root's own death outranks every exclusion, including one covering the watched
  // root itself.
  if reports_root_death(map, event) {
    return None;
  }
  if !names_no_reported_path(map, event, exclusions) {
    return None;
  }
  // Every path the event NAMES is outside the reported tree. That is not yet a licence to
  // drop it: the object it ACTS ON is a separate question, and an admitted one at a
  // reported path makes this event destructive to state the map holds rather than merely
  // unreported. Take the barrier for it and let the reseed rebuild the truth.
  if affects_reported_object(map, event, exclusions) {
    return Some(Admission::Lossy);
  }
  Some(Admission::ExcludedDrop)
}

/// Whether any FID `event` carries for the OBJECT it acts on — as opposed to the
/// directories it merely addresses THROUGH — resolves to a path inside the reported tree.
///
/// This is the fence's second question, and the one that keeps an exclusion from changing
/// the outcome of an event it does not describe. "The map holds this object at a reported
/// path" is decided by the map, not by the paths the event happened to name: the event's
/// endpoints can be entirely off the watched root while `target_fid` names a directory the
/// seed walk mapped under the root.
///
/// Ordered so the hot path is one hash lookup: [`FidMap::contains`](map::FidMap::contains)
/// answers membership WITHOUT building a path, and every shape of ordinary excluded churn
/// — a create under an excluded name, a populated move-in from outside the root landing on
/// one — acts on an object the map does not hold, so it stops there. Only a hit pays the
/// [`FidMap::resolve_path`](map::FidMap::resolve_path) walk and the exclusion match, which
/// together decide "reported" by the SAME [`super::excluded`] predicate everything else
/// uses. An object the map holds at an EXCLUDED path (a state the walk fence makes
/// unreachable) is correctly not reported, so a self-event on it still drops clean.
fn affects_reported_object(map: &FidMap, event: &RawFanotifyEvent, exclusions: &[PathBuf]) -> bool {
  affected_object_fids(event).any(|fid| {
    map.contains(fid)
      && map
        .resolve_path(fid)
        .is_some_and(|path| !super::excluded(exclusions, &path))
  })
}

/// The FIDs naming the OBJECT(s) an event acts on, in every shape it can arrive in.
///
/// `target_fid` is the affected object in all three shapes — a dirent's child, a
/// `FAN_RENAME`'s moved object, a `FID`-only self-event's own object — so it always
/// counts. `dir_fid` is the affected object ONLY in the NAME-LESS shape, where it is the
/// self-FID [`classify_nameless`] resolves (and where a rename merged with a self-event
/// carries the dying object). With a name it is the addressing PARENT, whose own
/// admittance says nothing about the child the event is about; counting it there would
/// make every ordinary dirent under an excluded name — the load-shedding case — take a
/// barrier.
///
/// Deliberately a SUPERSET of what each shape's classifier would consult: a name-less
/// event carrying both a self `dir_fid` and a `target_fid` yields both, so an
/// inconsistent event still errs toward the barrier rather than a silent drop.
fn affected_object_fids(event: &RawFanotifyEvent) -> impl Iterator<Item = &Fid> {
  let self_fid = event
    .name
    .is_none()
    .then_some(event.dir_fid.as_ref())
    .flatten();
  [event.target_fid.as_ref(), self_fid].into_iter().flatten()
}

/// Whether NO path this event names lies in the reported tree — the fence's first
/// question, made READ-ONLY and BEFORE any map mutation.
///
/// The walk fence (`descend`) keeps excluded subtrees out of the map, so a directory at
/// or under an exclusion is never seeded and its own events never resolve. Two shapes
/// still reach an in-root resolution and are exactly the boundary cases:
///
/// - an event about the excluded directory ITSELF — its PARENT is mapped, so a create,
///   delete, modify, or move-in of that one name resolves and would act;
/// - a rename with one or both ends inside the excluded subtree.
///
/// The predicate resolves the same path(s) the shape dispatch would build — a dirent's
/// `<parent>/<name>`, a name-less event's own path, a rename's two ends — through
/// [`FidMap::resolve_path`](map::FidMap::resolve_path), which answers `Some` exactly
/// when `admit` would but evicts nothing.
///
/// A SINGLE-OBJECT event names one path, so "does it resolve, and is it excluded" is
/// the whole question HERE: an addressing FID that does not resolve names no path at
/// all, and the shape dispatch has nothing to DELIVER for it either (it falls to
/// [`classify_foreign_parent`], which can only reach a root death, the loss barrier, or
/// the firehose drop). Whether it still owes the map something is the fence's other
/// question, which [`affects_reported_object`] answers from the FIDs rather than from
/// the paths — this predicate is deliberately about paths alone. A RENAME is different,
/// and that difference is this predicate's one sharp edge: it names TWO paths, so an end
/// that resolves nothing does not end the question — the OTHER end can still carry a
/// delivery.
///
/// So a rename's ends are classified THREE ways ([`RenameEnd`]) and the rename is
/// suppressed when NEITHER end is [`RenameEnd::Reported`]. That is deliberately not the
/// same test as "both ends are excluded": an end fails to be excluded either because it
/// is genuinely in the reported tree OR because it resolves nothing, and treating the
/// second as "not excluded" let a rename with NO reportable end through admission. An
/// outside-root source degraded to a bare filename, which no exclusion prefix matches,
/// so the conjunction failed and the pair was forwarded — and the lowering, seeing one
/// end outside the root and one end inside it, emitted a located rescan naming the
/// EXCLUDED destination. The common-layer fence stands down for this backend
/// (`backend_enforces_exclusions`), so that rescan reached consumers with neither of
/// its endpoints in the tree they subscribed to. Asking whether an end is REPORTED
/// collapses the two ways of not being reported into one answer and closes it.
///
/// A move ACROSS the boundary — one end reported, the other not — is a real change to
/// the reported tree: an object leaving the excluded subtree appears, one entering it
/// disappears, and the consumer needs the half it can see; reporting the pair is how it
/// learns which. The MAP side of a crossing move is handled where the mutation is, in
/// [`classify_rename`]: a destination outside the reported tree is a departure, so the
/// moved directory is forgotten rather than re-parented or walked in. The same is true
/// of a move that merely STRADDLES an exclusion — both endpoints reportable, but an
/// exclusion beneath one of them, so the moved subtree's own descendants change sides
/// ([`exclusion_geometry_changed`]) — which is a map question, not a suppression one:
/// the pair is reported either way, and the subtree is relearned and re-walked there.
///
/// The ROOT'S OWN DEATH is exempted by the caller ([`fence`] consults
/// [`reports_root_death`] before ever asking this): an exclusion covering the watched
/// root — a caller excluding the very tree it asked to watch — would otherwise silence
/// the one record that says the watch is over.
fn names_no_reported_path(map: &FidMap, event: &RawFanotifyEvent, exclusions: &[PathBuf]) -> bool {
  let excluded = |path: &Path| super::excluded(exclusions, path);
  if let Some(rename) = &event.rename {
    let reported = |dir: &Fid, name: &[u8]| {
      rename_end(map.resolve_path(dir).as_deref(), name, exclusions).is_reported()
    };
    return !reported(&rename.old_dir, &rename.old_name)
      && !reported(&rename.new_dir, &rename.new_name);
  }
  match event.name.as_ref() {
    // A dirent addresses `<parent>/<name>`; an unresolvable parent is out-of-root.
    Some(name) => event
      .dir_fid
      .as_ref()
      .and_then(|dir| map.resolve_path(dir))
      .is_some_and(|dir| excluded(&join_name(&dir, name))),
    // A name-less event addresses its OWN object, `dir_fid` first — the same self-FID
    // [`classify_nameless`] resolves.
    None => event
      .dir_fid
      .as_ref()
      .or(event.target_fid.as_ref())
      .and_then(|fid| map.resolve_path(fid))
      .is_some_and(|path| excluded(&path)),
  }
}

/// Which of the THREE trees one end of a `FAN_RENAME` lies in, once its parent directory
/// has been resolved against the map: the reported tree, the excluded remainder of the
/// watched root, or neither.
///
/// The third state is the one a boolean cannot hold, and holding it is the entire point.
/// "Excluded" and "reported" are not complements: an end can fail the exclusion test
/// simply because there is no path to test — its parent directory resolves nothing, so
/// the end lies off the watched root, or under an exclusion whose subtree the walk fence
/// deliberately never mapped (the map cannot tell those two apart, and does not need
/// to — neither is in the reported tree). Every rule the fence and
/// [`classify_rename`] need is phrased on [`Reported`](Self::Reported), never on its
/// negation-of-a-negation.
enum RenameEnd {
  /// The parent resolves in-root AND no exclusion covers the joined path: this end is
  /// in the tree the caller subscribed to, and carries that path.
  Reported(PathBuf),
  /// The parent resolves in-root but the joined path lies at or under an exclusion —
  /// inside the watched root, outside the reported tree. Reachable for exactly the
  /// exclusion's own top name, whose parent IS mapped; anything deeper resolves nothing
  /// and arrives as [`Outside`](Self::Outside) instead.
  Excluded,
  /// The parent resolves nothing, so this end names no path in the map's tree at all.
  Outside,
}

impl RenameEnd {
  /// Whether this end lies in the REPORTED tree — the one question every rule about a
  /// rename end is phrased on.
  fn is_reported(&self) -> bool {
    matches!(self, Self::Reported(_))
  }
}

/// Classifies one rename end from its ALREADY-RESOLVED parent directory (`None` when the
/// parent resolved nothing) and the child name the event carries.
///
/// Both call sites resolve the parent themselves and for their own reasons — the fence
/// through the read-only [`FidMap::resolve_path`](map::FidMap::resolve_path) because it
/// must not mutate, [`classify_rename`] through the batch memo because it is about to
/// act — so the resolution is the caller's and only the CLASSIFICATION lives here. That
/// keeps one rule for what "reported" means across both, and it is the shared
/// [`super::excluded`] predicate doing the matching, never a second one.
fn rename_end(dir: Option<&Path>, name: &[u8], exclusions: &[PathBuf]) -> RenameEnd {
  let Some(dir) = dir else {
    return RenameEnd::Outside;
  };
  let path = join_name(dir, name);
  if super::excluded(exclusions, &path) {
    RenameEnd::Excluded
  } else {
    RenameEnd::Reported(path)
  }
}

/// Whether `event` could classify as the watched root's own death — the ONE outcome the
/// exclusion fence must never suppress, whatever the caller excluded.
///
/// Enumerates the two shapes [`Admission::RootDeath`] is reachable from, so the guard is
/// a superset of them by construction rather than by coincidence:
///
/// - the NAME-LESS self shape ([`classify_nameless`]): a `DELETE_SELF`/`MOVE_SELF` whose
///   self-FID (`dir_fid`, else the `FID`-only shape's `target_fid`) is the map's root
///   anchor;
/// - the FOREIGN-PARENT shape ([`classify_foreign_parent`]): any structural-death mask
///   ([`root_death_mask`]) whose `target_fid` is the root anchor — the root deleted or
///   moved as reported from its own out-of-root parent.
///
/// Deliberately NOT narrowed by whether the shape's own addressing FID resolves: the
/// guard costs one `is_root` on a mask that names a structural death, and erring toward
/// delivering a root death is the only safe direction.
fn reports_root_death(map: &FidMap, event: &RawFanotifyEvent) -> bool {
  let is_root = |fid: &Fid| map.is_root(fid);
  if event.rename.is_none()
    && event.name.is_none()
    && (event.mask.delete_self() || event.mask.move_self())
    && event
      .dir_fid
      .as_ref()
      .or(event.target_fid.as_ref())
      .is_some_and(is_root)
  {
    return true;
  }
  root_death_mask(event.mask).is_some() && event.target_fid.as_ref().is_some_and(is_root)
}

/// Whether a multi-structural `event` is provably MAP-NEUTRAL: no verb its merged
/// mask carries can mutate the admission map, so the ambiguity it leaves is confined
/// to ONE name and owes no reseed barrier.
///
/// The map mutates on exactly three shapes, and this predicate excludes all of them:
/// an `ONDIR` create (`learn`), an `ONDIR` delete/move-out (`forget`), and a
/// `FAN_RENAME` (re-parent / move-in walk / move-out forget). What is left is a
/// NAMED, non-`ONDIR` dirent whose structural verbs are confined to
/// `FAN_CREATE`/`FAN_DELETE` under a parent already resolved in-root — for which
/// [`classify_dirent`] reaches ONLY its mutation-free [`Admission::Forward`] arm,
/// whatever order the kernel merged the verbs in. Requiring the parent to resolve is
/// what keeps the exemption from diverting a foreign-parent event away from
/// [`classify_foreign_parent`], where an in-map `target_fid` still owes the barrier
/// (or a root death) rather than a forward.
///
/// So this is NOT a relaxation of the no-one-sided-mutation rule: the rule guards map
/// mutations, and the exempted shape performs none. It is the recognition that the
/// barrier's cost — dropping the whole read buffer, reseeding the map, and covering
/// the entire scope with one `Overflow` — is charged for a hazard that cannot arise
/// here, while a create+delete of one file is ordinary churn. What genuinely stays
/// unknowable is that one name's ending state: create-then-delete and
/// delete-then-create carry identical bits. That is a LOCATED question, and
/// `plan_fanotify` answers it locally with a located `Rescan` over the name, which
/// covers either ending while every other event in the same read is still delivered.
fn map_neutral_merge(map: &FidMap, event: &RawFanotifyEvent) -> bool {
  let mask = event.mask;
  event.rename.is_none()
    && event.name.is_some()
    && !mask.ondir()
    && !mask.rename()
    && !mask.delete_self()
    && !mask.move_self()
    && event
      .dir_fid
      .as_ref()
      .is_some_and(|dir| map.resolve_path(dir).is_some())
}

/// Whether `event` REACHES an in-root object by ANY structural-verb FID it carries — the
/// ACTION-AWARE admittance the universal multi-structural gate in [`classify`] consults
/// before any shape dispatch. Admittance for the gate is "in-root by ANY carried
/// structural-verb FID": a merged mask names two or more structural verbs, and each verb
/// addresses through its OWN FID, so the event touches the root when ANY of those FIDs
/// does. It therefore enumerates EVERY FID the event carries and answers `true` if any
/// resolves in-root:
///
/// - a `FAN_RENAME`'s two directory ends (`old_dir`, `new_dir`) — the rename parents;
/// - `target_fid` — the child FID of a create/delete, AND the SELF-FID of a
///   move-self/delete-self (the moved/dying object itself);
/// - `dir_fid` — a named dirent's parent, or a name-less event's own self object.
///
/// This is a SUPERSET of each shape's own membership gate, so it never bars a shape's
/// classifier from admitting a fully-foreign event: with no carried FID in-root the event
/// still falls through to its shape's [`Admission::ForeignDrop`]. Crucially, a merged
/// rename+self whose ONLY in-root FID is the moved/self `target_fid` — its rename parents
/// both foreign — is now correctly seen in-root, so the gate routes the ambiguity to
/// [`Admission::Lossy`] rather than letting [`classify_rename`]'s both-ends-out check drop
/// an in-root (possibly ROOT) death. The per-shape gates ([`classify_rename`],
/// [`classify_dirent`], [`classify_nameless`]) each check a SUBSET of these FIDs and are
/// unchanged; only the ambiguity gate needs the action-complete union.
///
/// Read-only ([`FidMap::resolve_path`], not [`FidMap::admit`]): the gate must decide
/// Lossy-vs-drop WITHOUT mutating the map before the shape dispatch resolves and acts.
/// `resolve_path` answers `Some` exactly when `admit` would.
fn addresses_in_root(map: &FidMap, event: &RawFanotifyEvent) -> bool {
  let rename_ends = event
    .rename
    .iter()
    .flat_map(|rename| [&rename.old_dir, &rename.new_dir]);
  let singles = [event.dir_fid.as_ref(), event.target_fid.as_ref()]
    .into_iter()
    .flatten();
  rename_ends
    .chain(singles)
    .any(|fid| map.resolve_path(fid).is_some())
}

/// Classifies a NAMED event: a dirent addressing `<dir>/<name>` under its parent
/// directory. The parent's `dir_fid` is the primary admittance gate: in-root, the
/// action's own required field (a directory create/delete/move needs the child's
/// `target_fid`) decides forward vs [`Admission::Lossy`], and a plain file dirent needs
/// none. When the parent is out-of-root or absent the event is NOT dropped on the parent
/// alone — the named child can still be the watched root deleted/moved from its own
/// foreign parent — so it falls to [`classify_foreign_parent`], which consults the
/// affected object's `target_fid` (a root death → [`Admission::RootDeath`], else the
/// clean firehose [`Admission::ForeignDrop`]).
fn classify_dirent(
  map: &mut FidMap,
  event: &RawFanotifyEvent,
  name: &[u8],
  memo: &mut MemoBatch,
) -> Admission {
  let mask = event.mask;
  // The parent `dir_fid` is the primary gate — but out-of-root or absent, the named
  // child can still be the WATCHED ROOT deleted/moved from its own (foreign) parent
  // (`dir_fid` = that foreign parent, `target_fid` = the root itself). So a failed
  // parent falls to `classify_foreign_parent` (which consults `target_fid`) rather than
  // dropping on the parent alone and losing the root's death to the liveness tick.
  let Some(dir_fid) = event.dir_fid.as_ref() else {
    return classify_foreign_parent(map, event);
  };
  let Some(dir_path) = memo.admit(map, dir_fid) else {
    return classify_foreign_parent(map, event);
  };
  let path = Some(join_name(&dir_path, name));

  // The universal multi-structural gate in `classify` already routed an admitted
  // ambiguous merged mask (a create+delete of the same name) to `Lossy` before this
  // dispatch, so the parent is in-root (gated above) AND the mask names at most one
  // structural verb here — the invariant the single-verb selection below relies on.

  if mask.ondir() {
    if mask.created() {
      // Learn the new child directory — REQUIRES its own FID to key the node, else
      // the create would forward while its subtree stays unmapped (blind).
      let Some(child) = event.target_fid.as_ref() else {
        return Admission::Lossy;
      };
      map.learn(dir_fid, name, Some(child));
      return Admission::LearnDir(AdmittedEvent {
        mask,
        path,
        rename: None,
      });
    }
    if mask.removed() || mask.move_self() {
      // Forget/prune the departing child subtree — REQUIRES the child's own FID,
      // else the departed subtree would resolve through stale links forever.
      let Some(child) = event.target_fid.as_ref() else {
        return Admission::Lossy;
      };
      map.forget(child);
      return Admission::ForgetDir(AdmittedEvent {
        mask,
        path,
        rename: None,
      });
    }
    // An `ONDIR` modify/attrib changes content/metadata, not the tree — no mutation.
  }

  // A file (non-`ONDIR`) dirent, or a non-structural directory modify/attrib.
  Admission::Forward(AdmittedEvent {
    mask,
    path,
    rename: None,
  })
}

/// Classifies a NAME-LESS event: one that names no child and so addresses its OWN
/// object. The self-FID arrives as a bare `DFID` (`dir_fid`) or a bare `FID`
/// (`target_fid`), and is resolved the SAME way the dirent gate resolves its parent —
/// no FID consulted ahead of the membership check, and no `dir_fid`-absent pre-drop. No
/// addressing FID → [`Admission::ForeignDrop`]; a self-FID out-of-root falls to
/// [`classify_foreign_parent`] (a name-less event can still carry the root's own
/// `target_fid` beside a foreign `dir_fid`), else — admitted — the mask selects the
/// action:
///
/// - a `DELETE_SELF`/`MOVE_SELF` on the map's ROOT anchor is the watched root's own
///   death → [`Admission::RootDeath`], reached uniformly even in the `dir_fid = None`
///   FID-only shape the periodic liveness tick would otherwise be the sole detector
///   of;
/// - a `DELETE_SELF` on an admitted non-root directory `forget`s it →
///   [`Admission::ForgetDir`]; a `MOVE_SELF` is a self-rescan that leaves the node
///   for its rename to re-parent → [`Admission::Forward`];
/// - a name-less `MODIFY`/`ATTRIB` is the admitted object's OWN content/metadata
///   change → [`Admission::Forward`] of that object's path (an admitted object is
///   never dropped — the completion of the inversion);
/// - a name-less create/delete lost the child name it requires → [`Admission::Lossy`]
///   (the loss barrier reseeds), never a silent drop.
fn classify_nameless(
  map: &mut FidMap,
  event: &RawFanotifyEvent,
  memo: &mut MemoBatch,
) -> Admission {
  let mask = event.mask;
  // The object's own handle: a bare `DFID` (`dir_fid`) or a bare `FID`
  // (`target_fid`), `dir_fid` first. No handle at all is unaddressable noise.
  let Some(self_fid) = event.dir_fid.as_ref().or(event.target_fid.as_ref()) else {
    return Admission::ForeignDrop;
  };
  let is_root = map.is_root(self_fid);
  let Some(path) = memo.admit(map, self_fid) else {
    // The self-object is out-of-root — but a name-less event can still carry the
    // root's own `target_fid` alongside a foreign `dir_fid`, so consult the other
    // carried FID before dropping rather than blind on the first handle alone.
    return classify_foreign_parent(map, event);
  };

  // The universal multi-structural gate in `classify` already routed an admitted
  // ambiguous merged mask (a delete_self+move_self of one object, or the same on the
  // root) to `Lossy` before this dispatch, so the self-object is in-root (gated above)
  // AND the mask names at most one structural verb here — never a one-sided self-death
  // or root mutation from an ambiguous mask. A genuinely-departed root is still
  // observed by the reseed walk (and the liveness tick), so routing an ambiguous root
  // event to the barrier masks no real death.

  if mask.delete_self() || mask.move_self() {
    if is_root {
      // The watched root's own death — compile lowers it to the terminal lifecycle
      // (a delete's Removed + Rescan, a move's Rescan).
      return Admission::RootDeath(self_event(mask, path));
    }
    if mask.delete_self() {
      map.forget(self_fid);
      return Admission::ForgetDir(self_event(mask, path));
    }
    // A move_self does NOT forget: the node is re-parented by its rename/dirent.
    return Admission::Forward(self_event(mask, path));
  }

  // A name-less create/delete has lost the child name it addresses through — the
  // action's required field is absent, so the buffer is lossy rather than a silent
  // drop of an admitted object.
  if mask.created() || mask.removed() {
    return Admission::Lossy;
  }

  // A name-less modify/attrib on the admitted object is that object's OWN
  // content/metadata change — forward its own path.
  Admission::Forward(self_event(mask, path))
}

/// Builds the admitted form of a resolved self-event (its own path, no child).
fn self_event(mask: FanMask, path: PathBuf) -> AdmittedEvent {
  AdmittedEvent {
    mask,
    path: Some(path),
    rename: None,
  }
}

/// The action for a structural event whose addressing PARENT(s) are foreign — a named
/// dirent's out-of-root/absent `dir_fid`, a name-less event's out-of-root self-FID, or a
/// rename's BOTH ends out-of-root. Each per-shape gate above checks only its OWN
/// addressing FID, so it would drop an event that still carries an in-map object in its
/// `target_fid`. Before honoring that drop, consult the affected object itself.
///
/// The reachability that makes this exact and not a guess: on a consistent
/// single-superblock tree an in-root directory's parent is ITSELF in-root (the map is a
/// connected subtree of the root anchor). So the ONLY in-map object that can be reported
/// under a foreign parent is the ROOT ANCHOR — whose real parent lies OUTSIDE the watched
/// root. Therefore:
///
/// - a structural DEATH (delete/move) of the root reported from its foreign parent is the
///   root's terminal death → [`Admission::RootDeath`] on the root's own path, normalized
///   to the self form compile lowers to the death lifecycle ([`root_death_mask`]). This is
///   observed WITHOUT the periodic liveness tick, exactly as the self-event shape observes
///   it;
/// - any OTHER in-map target under a foreign parent is unreachable on a consistent tree
///   (an in-root non-root directory cannot be reported under a foreign one), so it is
///   never guessed into a one-sided mutation — the loss barrier ([`Admission::Lossy`])
///   reseeds instead;
/// - a target that is itself foreign or absent is genuinely outside the root: the clean
///   firehose [`Admission::ForeignDrop`].
///
/// Read-only ([`FidMap::resolve_path`]/[`FidMap::is_root`], no mutation), so it decides
/// against the same map state the per-shape gate just failed to resolve against.
fn classify_foreign_parent(map: &FidMap, event: &RawFanotifyEvent) -> Admission {
  let Some(target) = event.target_fid.as_ref() else {
    return Admission::ForeignDrop;
  };
  let Some(path) = map.resolve_path(target) else {
    return Admission::ForeignDrop;
  };
  if map.is_root(target)
    && let Some(mask) = root_death_mask(event.mask)
  {
    return Admission::RootDeath(self_event(mask, path));
  }
  // In-map but not the root anchor (unreachable under a foreign parent), or the root
  // under a non-death mask: never a single correct mutation — take the loss barrier.
  Admission::Lossy
}

/// The self-death mask a root's structural event lowers as, or `None` when the mask
/// names no structural death. A removal — a parent-reported `FAN_DELETE`, or the root's
/// own `FAN_DELETE_SELF` — is the root's `DELETE_SELF` (compile's terminal Removed +
/// Rescan); a move — a `FAN_MOVE_SELF`, or a `FAN_RENAME` relocating the root out of its
/// parent — is its `MOVE_SELF` (terminal Rescan). The root death reported from a
/// dirent/rename carries `FAN_DELETE`/`FAN_RENAME`, NOT the self-bit compile's death
/// lowering keys on, so it is restated to the self form here — letting the ONE compile
/// death path serve every reporting shape. Reached only PAST the universal
/// multi-structural gate, so the mask names at most one structural verb and the
/// delete/move arms cannot both apply.
fn root_death_mask(mask: FanMask) -> Option<FanMask> {
  if mask.removed() || mask.delete_self() {
    Some(FanMask::new(fid::FAN_DELETE_SELF | fid::FAN_ONDIR))
  } else if mask.move_self() || mask.rename() {
    Some(FanMask::new(fid::FAN_MOVE_SELF | fid::FAN_ONDIR))
  } else {
    None
  }
}

/// Classifies a `FAN_RENAME`: resolves both directory FIDs and applies the moved
/// DIRECTORY's map self-maintenance (no identity — see [`classify`]).
///
/// Membership is the filter: BOTH ends outside the root is a rename elsewhere on
/// the superblock — but the MOVED object may itself be the root (renamed between two
/// foreign parents), so this falls to [`classify_foreign_parent`] (a root move →
/// [`Admission::RootDeath`], else [`Admission::ForeignDrop`]) rather than dropping on
/// the two ends alone. With at least one end in-root, an
/// `ONDIR` rename mutates the tree and so REQUIRES the moved object's own
/// `target_fid` (absent → [`Admission::Lossy`], for every move shape — decode
/// cannot know which end is in-root, but classification can, so a targetless ONDIR
/// rename that would re-parent / walk / forget a subtree it cannot key is refused).
/// The four move flavors, keyed on whether the destination parent is in-root and
/// whether the MOVED OBJECT was already a known directory (its descendants already
/// mapped):
///
/// - **in-root rename** (moved dir known, destination in-root, exclusion geometry
///   unchanged): re-parent the one node in place; every descendant follows via the
///   updated parent link — complete by construction, no walk (`seed = None`).
/// - **move-in from outside** (moved dir unknown, destination in-root): the moved
///   directory carries pre-existing descendants the seed walk never saw, so after
///   learning the moved dir itself as a `pending_walk` top this returns `seed =
///   Some(moved)` — the reader resolves the dir's current path through the map and
///   walks the subtree in before forwarding, keeping the completeness invariant even
///   if a later in-root rename in the same batch re-parents the node first.
/// - **re-parent across a change in exclusion geometry** (moved dir known,
///   destination in-root, an exclusion beneath EITHER endpoint —
///   [`exclusion_geometry_changed`]): the carried-across descendants are no longer the
///   set the fence describes, so the node is `forget`-ten and relearned as a move-in
///   top and the subtree is walked in afresh under the destination's geometry. This is
///   the ONE re-parent that owes a walk; see the helper for why both directions of the
///   crossing need it.
/// - **move-out** (moved dir known, destination outside): forget the moved dir; its
///   descendants' parent links now point at an absent handle, so their walks break
///   and they evict lazily — the map stops admitting the departed subtree naturally.
/// - **move-out of an already-unknown subtree** (moved dir unknown, destination
///   outside): nothing to maintain; only the in-root SOURCE end resolves, and the
///   move forwards as a boundary crossing.
///
/// An EXCLUDED destination is a move-out too. The reported tree is the root MINUS the
/// caller's exclusions, so a directory renamed to a path at or under an exclusion has
/// left it exactly as surely as one renamed off the root — and the map must follow it
/// out. Re-parenting the node instead would park a live subtree (and its already-mapped
/// descendants) inside the exclusion, where every later create under it grows the
/// admission map toward the cap for a subtree the caller asked not to hear about. So a
/// destination that is not [`RenameEnd::Reported`] takes the move-out arm: `forget` the
/// moved directory, walk nothing, and still FORWARD the pair — the crossing is precisely
/// what tells the consumer the object is gone.
///
/// Forwarding is sound BECAUSE of what the fence proved: a rename reaches here only with
/// at least one end in the reported tree, so a move-out always has a visible source and
/// a move-in always has a visible destination. A rename with NEITHER end reported —
/// including one arriving from off the root and landing inside an exclusion — never
/// reaches this function at all; [`fence`] answered it before any resolution here could
/// hand the lowering a pair to describe, dropping it clean when it moved nothing the map
/// holds and taking the loss barrier when it moved something the map holds at a reported
/// path (whose departure this function would otherwise never be told about).
fn classify_rename(
  map: &mut FidMap,
  event: &RawFanotifyEvent,
  rename: &RenameInfo,
  memo: &mut MemoBatch,
  exclusions: &[PathBuf],
) -> Admission {
  let old_dir = memo.admit(map, &rename.old_dir);
  let new_dir = memo.admit(map, &rename.new_dir);
  if old_dir.is_none() && new_dir.is_none() {
    // Both ends outside the root — but the MOVED object might still be the root
    // itself (the watched root renamed between two foreign parents), so consult its
    // `target_fid` before dropping as superblock noise.
    return classify_foreign_parent(map, event);
  }

  // The DELIVERED pair. An end whose parent resolved nothing degrades to the bare child
  // name, which is a RELATIVE path and therefore cannot strip the canonical root's
  // prefix: the lowering reads it as `Lowered::Outside` and covers the in-root end with
  // a located rescan instead of pairing a half that has no partner under the root. That
  // fallback is delivery-only and must stay out of any admission decision — a bare name
  // matches no exclusion prefix, so testing one against the exclusion set answers
  // "reported" for a path that is nothing of the sort. `rename_end` is where that
  // question is asked, and it never sees this form.
  let old_path = old_dir
    .as_ref()
    .map(|dir| join_name(dir, &rename.old_name))
    .unwrap_or_else(|| PathBuf::from(&os_name(&rename.old_name)));
  let new_path = new_dir
    .as_ref()
    .map(|dir| join_name(dir, &rename.new_name))
    .unwrap_or_else(|| PathBuf::from(&os_name(&rename.new_name)));

  let admitted = AdmittedEvent {
    mask: event.mask,
    path: None,
    rename: Some(AdmittedRename { old_path, new_path }),
  };

  if event.mask.ondir() {
    // An `ONDIR` rename mutates the directory tree — it REQUIRES the moved object's
    // own FID to re-parent / walk-in / forget the node. Absent (with at least one
    // end in-root, proven above) → the buffer is lossy, exactly as the pre-inversion
    // decode matrix made a targetless ONDIR rename lossy — now caught AT the action.
    let Some(moved) = event.target_fid.as_ref() else {
      return Admission::Lossy;
    };
    // The destination is classified by the SAME three-way rule the fence used
    // ([`rename_end`]), so "the map may follow the subtree here" and "the fence would
    // report this path" cannot drift apart. Only a REPORTED destination is followed;
    // both other states — inside an exclusion, or off the watched root — take the
    // move-out arm below rather than learning or re-parenting the node into a subtree
    // the caller asked not to hear about (and whose later creates would then grow the
    // map against the cap). The reported arm carries the destination PATH, which is what
    // lets the geometry test below name the tree the subtree is landing in.
    let destination = match rename_end(new_dir.as_deref(), &rename.new_name, exclusions) {
      RenameEnd::Reported(destination) => Some(destination),
      RenameEnd::Excluded | RenameEnd::Outside => None,
    };
    if let Some(destination) = destination {
      // Destination in-root and reported. Whether the moved object was ALREADY a known
      // in-root directory (its descendants already mapped) splits the flavors — read it
      // BEFORE `learn` overwrites the node.
      if map.contains(moved) && !exclusion_geometry_changed(map, moved, &destination, exclusions) {
        // In-root re-parent: `learn` overwrites the node in place, and its
        // already-mapped descendants follow via the updated parent link — no walk. Sound
        // ONLY because the descendants the map holds are still exactly the descendants
        // the fence reports; the guard above is what proves that.
        map.learn(&rename.new_dir, &rename.new_name, Some(moved));
        return Admission::Rename {
          event: admitted,
          seed: None,
        };
      }
      // Moved IN from outside — or re-parented across a change in exclusion geometry,
      // where what the map holds for this subtree is no longer what the fence reports.
      // Either way the mapped subtree is discarded (`forget`, a no-op for a moved-in dir
      // the map never knew) and the top is relearned as a `pending_walk` node, then the
      // reader is handed its FID to walk the descendants in — the walk applies the SAME
      // exclusion fence to the destination's paths, so what it maps is exactly what the
      // reported tree now contains. Discarding first is what keeps a subtree that moved
      // INTO an exclusion from being left behind in the map.
      map.forget(moved);
      map.learn_moved_in(&rename.new_dir, &rename.new_name, moved);
      return Admission::Rename {
        event: admitted,
        seed: Some(moved.clone()),
      };
    }
    // Moved OUT of the reported tree — off the root, or into an excluded subtree the
    // map must not follow it into: forget the departed subtree. A later move back is a
    // fresh move-in — walked in — the conservative direction.
    map.forget(moved);
    return Admission::Rename {
      event: admitted,
      seed: None,
    };
  }

  // A file / boundary rename: no directory-tree mutation.
  Admission::Rename {
    event: admitted,
    seed: None,
  }
}

/// Whether moving the already-mapped directory `moved` to `destination` CHANGES which
/// of its descendants the exclusion fence covers — the ONE condition under which an
/// in-root re-parent is not complete without a walk.
///
/// Exclusions match on PATH PREFIXES, so which descendants of a subtree lie under one is
/// a function of the subtree's OWN path. A re-parent rewrites exactly that path while
/// carrying every mapped descendant across untouched (that is the whole point of the
/// parent-relative representation), so a move whose endpoints sit on different sides of
/// an exclusion leaves the map describing a tree the fence no longer agrees with — in
/// BOTH directions, and permanently, because nothing later re-walks it:
///
/// - **out of an exclusion.** With `/root/a/cache` excluded, the seed walk never mapped
///   it. Renaming `/root/a` to `/root/b` makes `cache` reportable, yet a bare re-parent
///   adds nothing: the directory stays absent from the map, so every event beneath it
///   resolves no addressing FID and is dropped as foreign — a newly visible subtree that
///   is blind forever.
/// - **into an exclusion.** With `/root/b/cache` excluded, `/root/a/cache` IS mapped.
///   Renaming `/root/a` to `/root/b` leaves those nodes in the map, so the map retains —
///   and resolves paths through — directories the fence says are not in the reported
///   tree, holding admission-map capacity the exclusion exists to shed.
///
/// The test is the fence's own prefix containment run the other way round: an exclusion
/// is relevant exactly when it lies at or under one of the two endpoint paths, which is
/// [`super::excluded`] with the endpoints as the exclusion set and the exclusion as the
/// path. Reusing that one predicate is deliberate — a second matching rule here could
/// drift out of step with the fence and re-open the hole from the other side.
///
/// Deliberately CONSERVATIVE: an exclusion sitting under BOTH endpoints at the same
/// relative offset (`/root/a/cache` and `/root/b/cache`, renaming `a` to `b`) leaves the
/// geometry genuinely unchanged yet answers `true` here, costing one subtree walk.
/// Comparing the two sides exactly would buy nothing on a path this rare — exclusions
/// are rare, and a rename with one beneath either end rarer still — while adding the
/// second rule this deliberately avoids.
///
/// The empty-exclusion fast path keeps the common case at zero cost: with no exclusions
/// there is no geometry, so no rename ever pays a resolution for this.
///
/// A `moved` whose ancestry no longer reaches the root has no old path to compare
/// against and answers `true`: relearning it as a move-in top rebuilds the subtree from
/// the destination rather than re-parenting an orphan.
fn exclusion_geometry_changed(
  map: &FidMap,
  moved: &Fid,
  destination: &Path,
  exclusions: &[PathBuf],
) -> bool {
  if exclusions.is_empty() {
    return false;
  }
  let Some(source) = map.resolve_path(moved) else {
    return true;
  };
  let endpoints = [source, destination.to_path_buf()];
  exclusions
    .iter()
    .any(|exclusion| super::excluded(&endpoints, exclusion))
}

/// Joins a raw fanotify child name onto its resolved directory path. A
/// non-UTF-8 or non-component name still produces a path the lowering can
/// escalate to a located rescan (coverage-honest), never a panic.
fn join_name(dir: &std::path::Path, name: &[u8]) -> PathBuf {
  dir.join(os_name(name))
}

/// Interprets a raw fanotify name as an `OsString` path component. On unix the
/// bytes pass through verbatim; elsewhere (test builds) a lossy form keeps the
/// pure paths decodable.
fn os_name(name: &[u8]) -> std::ffi::OsString {
  #[cfg(unix)]
  {
    use std::os::unix::ffi::OsStringExt;
    std::ffi::OsString::from_vec(name.to_vec())
  }
  #[cfg(not(unix))]
  {
    std::ffi::OsString::from(String::from_utf8_lossy(name).into_owned())
  }
}

/// The composite `fanotify_init` flag set (design §4.1, container-validated):
/// `FAN_CLASS_NOTIF | FAN_REPORT_FID | FAN_REPORT_DFID_NAME |
/// FAN_REPORT_TARGET_FID`. `TARGET_FID` without `REPORT_FID` is `EINVAL` — the
/// full composite is mandatory. Restated locally so the pure module carries no
/// libc dependency; the FFI layer cross-asserts it against the composite.
///
/// `FAN_CLASS_NOTIF` is `0x0` (the notification class is the flag word's
/// default), so it contributes no bits and is omitted from the OR.
#[cfg(all(target_os = "linux", not(miri)))]
pub(super) const FAN_INIT_FLAGS: u32 = 0x0000_0200 // FAN_REPORT_FID
  | 0x0000_0400 // FAN_REPORT_DIR_FID  (half of DFID_NAME)
  | 0x0000_0800 // FAN_REPORT_NAME     (half of DFID_NAME)
  | 0x0000_1000; // FAN_REPORT_TARGET_FID

/// The mark mask armed on the superblock (design §4.1): every dirent verb plus
/// the self-events and `FAN_ONDIR` so directory events are reported.
#[cfg(all(target_os = "linux", not(miri)))]
pub(super) const FAN_MARK_MASK: u64 = fid::FAN_CREATE
  | fid::FAN_DELETE
  | fid::FAN_MODIFY
  | fid::FAN_ATTRIB
  | fid::FAN_RENAME
  | fid::FAN_DELETE_SELF
  | fid::FAN_MOVE_SELF
  | fid::FAN_ONDIR;

/// Encodes the file handle of the directory `dirfd` ITSELF via
/// `name_to_handle_at(dirfd, "", AT_EMPTY_PATH)` — the fd-relative encoder every
/// caller uses (the pre-live `Backend::Auto` probe on the pinned root, and the
/// live seed/reseed walk on each pinned directory). Because it names no path, no
/// name resolution can redirect it: the handle is taken from exactly the object
/// the caller pinned (opened `O_NOFOLLOW`/`RESOLVE_NO_SYMLINKS` and
/// fstat-verified), so neither a swap of the root path at spawn nor a foreign
/// directory swapped in for a listed name post-live can have its handle seed the
/// admission map (the scope-fence invariant on [`source`]). See
/// [`encode_handle_sized`] for the dynamic `EOVERFLOW`-retry sizing and the
/// returned byte layout.
#[cfg(all(target_os = "linux", not(miri)))]
pub(super) fn encode_handle_at(
  dirfd: std::os::fd::BorrowedFd<'_>,
) -> Option<std::boxed::Box<[u8]>> {
  use std::os::fd::AsRawFd;

  // SAFETY: the empty C string literal lives for the call; `dirfd` is a live open
  // directory fd (the caller pins it before this); AT_EMPTY_PATH makes the call
  // operate on `dirfd` directly rather than resolving a name under it.
  unsafe { encode_handle_sized(dirfd.as_raw_fd(), c"".as_ptr(), libc::AT_EMPTY_PATH) }
}

/// The shared `name_to_handle_at` core, DYNAMICALLY sizing the buffer: `struct
/// file_handle` is a flexible-array type, and a filesystem whose handle exceeds
/// the initial `MAX_HANDLE_SZ` request answers `EOVERFLOW` with the true size
/// written back into `handle_bytes` — so a single fixed buffer would turn an
/// oversized-handle filesystem (which CAN export handles) into a spurious
/// "unsupported". The loop grows to the reported size and retries exactly once;
/// a second `EOVERFLOW` is a lying kernel and fails.
///
/// `dirfd`/`cpath`/`at_flags` are passed straight to `name_to_handle_at`: the
/// path encoder passes `(AT_FDCWD, path, 0)`, the fd encoder passes `(fd, "",
/// AT_EMPTY_PATH)`. Returns the FID handle bytes — `handle_type` (native-endian)
/// followed by the opaque bytes — byte-identical to the event-side decode, so a
/// seed FID matches the kernel's event FIDs exactly. `None` when the filesystem
/// cannot encode a handle for this object (a non-exporting fs, a
/// permission/transient failure, or the double-`EOVERFLOW` broken-kernel case).
///
/// # Safety
///
/// `cpath` must be a valid NUL-terminated pointer that stays live for the call,
/// and `dirfd` must be `AT_FDCWD` or a valid open directory fd matching
/// `at_flags` (an empty path requires `AT_EMPTY_PATH`).
#[cfg(all(target_os = "linux", not(miri)))]
unsafe fn encode_handle_sized(
  dirfd: libc::c_int,
  cpath: *const libc::c_char,
  at_flags: libc::c_int,
) -> Option<std::boxed::Box<[u8]>> {
  let prefix = std::mem::size_of::<libc::file_handle>();
  // Start at MAX_HANDLE_SZ (the common case fits in one try); a larger handle
  // grows the buffer to the kernel-reported size on the single retry below.
  let mut cap = libc::MAX_HANDLE_SZ as usize;
  let mut grown = false;
  loop {
    // The backing buffer is `u64` so the pointer is 8-aligned — a `Vec<u8>` is
    // only 1-aligned, and writing a `file_handle` (align 4) through such a
    // pointer would be undefined behavior.
    let words = prefix.div_ceil(8) + cap.div_ceil(8) + 1;
    let mut storage = vec![0u64; words];
    let mut mount_id: libc::c_int = 0;
    let handle = storage.as_mut_ptr().cast::<libc::file_handle>();
    // SAFETY: storage is 8-aligned and sized for the fixed prefix plus `cap`
    // opaque bytes; this write stays within it.
    unsafe {
      (*handle).handle_bytes = cap as libc::c_uint;
    }
    // SAFETY: handle points at a correctly-sized, aligned file_handle; cpath is
    // a valid NUL-terminated pointer for `at_flags`; mount_id is a valid
    // out-param; dirfd is AT_FDCWD or a live directory fd (caller contract).
    let rc = unsafe { libc::name_to_handle_at(dirfd, cpath, handle, &mut mount_id, at_flags) };
    let errno = (rc != 0)
      .then(|| std::io::Error::last_os_error().raw_os_error())
      .flatten();
    match fid::classify_handle_attempt(rc, errno, grown) {
      fid::HandleAttempt::Encoded => {
        // SAFETY: the call succeeded, so the prefix and `handle_bytes` opaque
        // bytes are initialized.
        let (handle_bytes, handle_type) =
          unsafe { ((*handle).handle_bytes as usize, (*handle).handle_type) };
        if handle_bytes > cap {
          // The kernel reported success yet a length past the buffer it filled:
          // structurally impossible, refuse rather than read out of bounds.
          return None;
        }
        // SAFETY: the opaque handle begins right after the prefix and spans
        // handle_bytes (bounded by cap above); reading it as bytes is in-range.
        let opaque = unsafe {
          std::slice::from_raw_parts(storage.as_ptr().cast::<u8>().add(prefix), handle_bytes)
        };
        let mut bytes = Vec::with_capacity(4 + opaque.len());
        bytes.extend_from_slice(&handle_type.to_ne_bytes());
        bytes.extend_from_slice(opaque);
        return Some(bytes.into_boxed_slice());
      }
      fid::HandleAttempt::Grow => {
        // EOVERFLOW wrote the required size back into handle_bytes; retry once
        // at exactly that size.
        // SAFETY: the prefix is initialized on an EOVERFLOW return (the kernel
        // fills handle_bytes with the needed length).
        cap = unsafe { (*handle).handle_bytes as usize };
        grown = true;
      }
      fid::HandleAttempt::Unsupported => return None,
    }
  }
}

#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) mod reader;

#[cfg(all(target_os = "linux", not(miri)))]
#[allow(unused_imports)]
pub(crate) use source::{FanotifySpawn, Source, SourceHandle};

#[cfg(all(target_os = "linux", not(miri)))]
mod source;
