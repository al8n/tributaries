//! The primitive-agnostic top half: the `Monitor` state machine.

use core::{num::NonZeroU64, time::Duration};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::{
  action::Action,
  capabilities::Capabilities,
  change::{Change, ChangeKind},
  error::WatchError,
  id::{ArmAttempt, ChangeId, Epoch, Identity, MoveCookie, ReqId, ScopeId, Sequence, WatchId},
  interest::Interest,
  path::{Location, Segment},
  record::{DirEntry, EnumerateResult, Evidence, FileKind, OsRecord, RecordKind, StatResult},
  scope::Scope,
  time::Instant,
};

/// The default window within which the two halves of a rename must arrive to be
/// paired into a single move; an unpaired half older than this is resolved on
/// its own (a stranded source becomes a removal, a stranded destination a
/// creation).
pub const DEFAULT_MOVE_WINDOW: Duration = Duration::from_millis(100);

/// How many times a rescan re-arm enumerate that cannot fully reconcile a directory
/// (a `Partial` or `Failed` read) is retried before the Monitor escalates to a
/// `Rescan` for that subtree — so a permanently-unreadable directory cannot spin a
/// fixpoint-draining driver. Per-directory backoff / degraded state is a later
/// refinement; this bound keeps the foundation from looping.
const REARM_MAX_RETRIES: u8 = 2;

/// Which enumerate a watch has outstanding: a cold discovery read (emits `Created`
/// for each entry) or a rescan re-arm read (reconciles coverage, `Created`-suppressed).
///
/// A REGISTRATION's crawl is the second kind, not the first: the contract reports
/// no inventory for state that merely pre-existed the grant, so the root is born
/// re-arm-flavored and the flavor descends through the crawl's own installs. A
/// cold read is therefore what a LIVE discovery gets — a `Created` record's
/// install, a widen's post-commit read — where the entries really are changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnumKind {
  /// Discovery of a freshly-armed directory — each entry is a new `Created`.
  Cold,
  /// A rescan re-arm — reconcile the watch set without emitting `Created`.
  /// `reprove` carries the binding-re-proof flavor down the retained chain
  /// (see [`NodeState::Arming`]): a reprove-flavored read's kept survivors are
  /// re-added, not merely re-read — a whole-tree kernel death (an unmount)
  /// leaves every retained descendant identity-matched yet unbound, so the
  /// flavor must reach the leaves.
  Rearm {
    /// Whether kept survivors of this read must re-prove their bindings.
    reprove: bool,
  },
}

/// The coverage lifecycle of one watched directory. Exactly one variant holds at a
/// time, which is what replaces the four hand-synchronized side-tables
/// (`rearm_dirs` / `rearming` / `rearm_attempts` / `rearm_reqs`) plus the `live`
/// flag: a node cannot both owe a re-arm and have one outstanding, because those are
/// distinct variants rather than independent set memberships.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeState {
  /// The `Action::Watch` is queued but not yet acknowledged. `rearm` records that the
  /// post-arm enumerate must continue a rescan re-arm (the old `rearming` membership),
  /// so it is `Created`-suppressed rather than a cold discovery.
  ///
  /// `reprove` marks the arm as a binding RE-PROOF of an already-tracked node
  /// on a [`lossy_watch_teardown`](Capabilities::lossy_watch_teardown)
  /// backend: the node's kernel binding may have died with its teardown
  /// record swallowed by a queue loss, so only the re-add's acknowledgement —
  /// stamped against the scope's loss generation — may return it to `Live`.
  /// A reprove arm is always re-arm-flavored (`reprove` implies `rearm`), and
  /// unlike a fresh install it does NOT mark the bridge window at entry: the
  /// window's `fresh_rearm` bit is set at the ACK, iff the outcome was
  /// [`Installed`](crate::WatchAck::Installed) (a genuinely re-established
  /// binding — there was a dark window to close). An all-`Aliased` recovery
  /// therefore costs no closing `Rescan`.
  Arming { rearm: bool, reprove: bool },
  /// Live (armed), with no enumerate outstanding.
  Live,
  /// Live, with an enumerate outstanding under `req`. `kind` selects discovery vs
  /// re-arm handling of the result; `attempts` counts consecutive incomplete re-arm
  /// reads toward [`REARM_MAX_RETRIES`]. Accepting a result requires the node to still
  /// name the arriving `req`, so a superseded read is dropped rather than reconciled.
  /// `dirty` records that a slot-changing record raced this read: the listing is then a
  /// possibly-stale snapshot (it may re-arm a since-removed child), so the result is not
  /// trusted — it is handled like an incomplete read (`Rescan` + retry).
  Enumerating {
    req: ReqId,
    kind: EnumKind,
    attempts: u8,
    dirty: bool,
  },
}

impl NodeState {
  /// Whether this state carries outstanding re-arm work: a pending arm that must
  /// continue a re-arm, or an in-flight re-arm read. These are the states the
  /// per-scope pending counter behind [`Monitor::rearm_settled`] tracks, and the
  /// obligation [`Monitor::has_rearm_obligation`] transfers to a replacement watch.
  const fn is_rearm(self) -> bool {
    matches!(
      self,
      Self::Arming { rearm: true, .. }
        | Self::Enumerating {
          kind: EnumKind::Rearm { .. },
          ..
        }
    )
  }
}

/// What a [`Monitor::reparent`] re-key does to the ABSOLUTE paths under it —
/// the one question the placement clock
/// ([`Monitor::placement_now`](Monitor::placement_now)) turns on, and one the
/// re-key itself cannot answer: both flavors re-key exactly the same links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reparent {
  /// A rename landed: the subtree occupies a different path than it did, so
  /// every coordinate lowered against it is now addressed at a location it has
  /// left.
  Moved,
  /// A widen splice re-described the same objects from a higher root. The new
  /// chain exactly compensates the new root, so no absolute path changed and no
  /// lowered coordinate went stale — recording a move here would re-issue every
  /// round trip in flight under the old root, for a splice whose whole contract
  /// is that it disturbs nothing.
  Rerooted,
}

/// What a completing round trip's LOWERED path is worth — the single statement
/// of the trust test every arm, read and stat completion applies, answered by
/// [`Monitor::fence_lowering`](Monitor::fence_lowering).
///
/// # One invariant
///
/// Every round trip is issued as an identity-relative coordinate the driver
/// LOWERS to an absolute path before the I/O, and its result describes that
/// path. The path is the node's only when BOTH clauses hold:
///
/// - the anchor's chain has not moved since the round trip was stamped, and
/// - the path was not ALREADY knowingly stale when it was stamped.
///
/// The placement clock answers the first. The second is the hold: a
/// detached-and-held move source reconstructs at its pre-move path for the whole
/// pairing window BY DESIGN, so a coordinate lowered anywhere in its subtree is
/// born addressed at a slot the object has left — and no move happens after such
/// an issue, which is exactly why the clock alone can never see it.
///
/// # Why two fields and not one verdict
///
/// Both clauses can fail at once (a stat issued before a `MovedFrom` completing
/// during the hold fails both), and they are separately actionable: the clock
/// says the RESULT is not evidence, the hold says the PATH may not be addressed.
/// Collapsing them into one prioritized answer loses whichever the winner does
/// not imply — a held-and-moved read would keep reconciling a listing taken
/// somewhere else. They are asked together, once, so a site cannot answer half
/// the invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Lowering {
  /// The detached-and-held move source whose subtree this coordinate lowers
  /// inside, if any. Its recovery belongs to the hold's pairing — which
  /// [`fence_lowering`](Monitor::fence_lowering) books by dirtying it — so
  /// nothing here may be ADDRESSED at the reconstruction. The coverage the round
  /// trip carries is still performed, best-effort, exactly as every other
  /// held-subtree activity is: the design deliberately arms, reads and
  /// reconciles under a hold so the subtree is complete when it reparents.
  held: Option<WatchId>,
  /// Whether a node on the anchor's CURRENT chain changed placement after the
  /// stamp. The driver then read somebody else's path, so the payload is not
  /// evidence about this node at all and is discarded; the recovery is
  /// re-addressed at wherever the node has landed. A round trip that INSTALLED
  /// something at that path owes more than the discard — see
  /// [`Monitor::ingest_watch_result`], which retires the binding a stale arm
  /// reports and rebuilds the slot counted behind a cover.
  moved: bool,
}

impl Lowering {
  /// Whether this result may be ADDRESSED at the reconstruction — a located
  /// `Rescan`, a `Created`, a delivered cover. False under a hold, where the
  /// reconstruction names the vacated pre-move path and the pairing owes the
  /// destination's `Rescan` and re-arm instead.
  const fn locatable(&self) -> bool {
    self.held.is_none()
  }

  /// Whether the result's payload is evidence about the node it names — a
  /// listing that may be reconciled as an inventory, an acknowledgement that may
  /// certify a binding.
  ///
  /// BOTH clauses must be clean. A moved chain means the driver read somebody
  /// else's path; a hold means the path was ALREADY the vacated pre-move one
  /// when the round trip was stamped, so the payload describes whatever occupies
  /// the slot the subtree has left. Detecting a stale lowering is not the same
  /// as making its payload safe to act on: booking the hold's debt says the
  /// pairing owes a recovery, it does not say this listing may prune, this
  /// answer may retire, or this acknowledgement may certify.
  const fn is_evidence(&self) -> bool {
    !self.moved && self.held.is_none()
  }
}

/// Fine-grained [`DeficitBook`] entries per scope before the book collapses to a
/// whole-scope marker. Bounds re-signal work and memory under mass failure (an
/// inotify watch-limit exhaustion mid-crawl records one hole per refused arm).
const DEFICIT_CAP: usize = 16;

/// Per-scope bridge-window bookkeeping: an entry exists only while at least one
/// bit is set, and only ever for a descending scope.
///
/// `saw_rescan` records that a `Rescan` passed for the scope since its last
/// settle edge; `fresh_rearm` that a node entered `Arming { rearm: true }` (a
/// `Created`-suppressed fresh install) in the same window. At the settle edge
/// ([`Monitor::settle_bridges`]) the CONJUNCTION emits one closing `Rescan`:
/// the window was both lossy and armed suppressed coverage, so a change that
/// landed after the window's opening `Rescan` but before a bridge directory's
/// watch armed — recorded by nothing, suppressed by the re-arm read — is ≤ the
/// closing `Rescan` a sync barrier's fence must observe. Either bit alone must
/// NOT fire: `saw_rescan` alone is a lossy window that armed nothing fresh
/// (every watch stayed armed, post-`Rescan` changes were recorded live), and
/// `fresh_rearm` alone is a pure set-cover regrow of pruned coverage (the
/// region was outside every committed claim; firing would degrade every
/// prune/regrow cycle).
///
/// `bootstrap` is the REGISTRATION window's own mark, and it is not a half of
/// that conjunction. It is seeded at
/// [`register_root_with_profile`](Monitor::register_root_with_profile) — the
/// same birth site the suppression itself keys on, so the two cannot drift
/// apart — and says that the scope's initial crawl is still running. While it
/// stands, a FRESH directory install by a suppressed crawl supplies the
/// window's loss half (`saw_rescan`); a SURVIVOR re-arm never does, since a
/// survivor was already covered. Living in this struct is what gives the mark
/// its lifetime for free: the entry's removal at the settle edge
/// ([`Monitor::settle_bridges`]) is the mark's funeral, and the two terminal
/// removals ([`Monitor::unregister_root`], [`Monitor::invalidate_root`]) bury
/// it with the scope.
#[derive(Debug, Clone, Copy, Default)]
struct BridgeFlags {
  saw_rescan: bool,
  fresh_rearm: bool,
  bootstrap: bool,
}

/// Per-scope standing terminal coverage deficits: level-persistent darkness
/// whose one edge `Rescan` (emitted when the deficit opened) does not cover
/// changes landing while it stands. An entry exists only while non-empty (or
/// collapsed), and only ever for a descending scope.
///
/// The book is what lets the cookie-dispatch seam
/// ([`Monitor::resignal_coverage_deficits`]) put a fresh covering `Rescan`
/// ahead of every sync cookie written over the darkness, so a barrier can
/// never resolve delivered over a change the deficit hid.
#[derive(Debug, Default)]
struct DeficitBook {
  /// Slot holes: `(parent, name)`'s on-disk subtree is not covered — the
  /// kernel refused the install (the failed subtree was dropped), or an
  /// organic crawl dropped a deficit-carrying child there and re-anchored
  /// the erased loss pending the slot's rebuild or its removal record
  /// ([`Monitor::drop_subtree_for_crawl_rebuild`]).
  slots: BTreeMap<WatchId, BTreeSet<Segment>>,
  /// Exhausted-read interiors: this live watch's content could not be
  /// reconciled within the bounded retries; gap-created descendants under it
  /// may be unarmed.
  interiors: BTreeSet<WatchId>,
  /// The fine-grained book overflowed [`DEFICIT_CAP`]: the whole scope is
  /// suspect, re-signaled as one root `Rescan` plus one root re-arm kick.
  /// While set the fine sets stay empty (collapse absorbs new records).
  collapsed: bool,
}

impl DeficitBook {
  /// Whether the book carries nothing — neither fine entries nor the
  /// collapsed marker — and can be garbage-collected.
  fn is_clear(&self) -> bool {
    !self.collapsed && self.slots.is_empty() && self.interiors.is_empty()
  }

  /// Total fine-grained entries (slot holes plus interiors).
  fn fine_len(&self) -> usize {
    self.slots.values().map(BTreeSet::len).sum::<usize>() + self.interiors.len()
  }
}

/// Why a [`drop_subtree`](Monitor::drop_subtree) may erase the coverage
/// deficits anchored in the dropped subtree — the discharge reason, named at
/// every call site so the invariant is auditable in one place: **a recorded
/// coverage deficit is discharged only by a fresh covering `Rescan`, a
/// re-anchor, an explicit terminal teardown, or a proven-unsubscribed prune —
/// never by a structural `Removed`/`File`/move a filtered subscription would
/// not see.** A covering `Rescan` bypasses BOTH coverage and delivery filter
/// (it reaches every subscriber regardless of interest); a structural record is
/// interest- and filter-subject and can reach NONE, so it can never silently
/// stand in for the darkness the deficit tracked.
#[derive(Debug, Clone, Copy)]
enum DeficitDischarge {
  /// Stand a fresh covering `Rescan` (set both bridge bits so the window's
  /// [`settle_bridges`](Monitor::settle_bridges) flush emits the closing
  /// `Rescan`) for the dropped subtree's scope when the drop erases a real
  /// deficit. The default for a record- or move-driven drop — a slot emptied
  /// or replaced, a delete, an ignore, a move-out, a stale-destination replace
  /// — whose only structural signal a `Modified`-only (or removal-filtering)
  /// subscription would never observe.
  CoveringRescan,
  /// Re-anchor an erased deficit as a slot hole at the dropped child's
  /// SURVIVING parent — the crawl-rebuild non-survivor branch, the one drop
  /// with no coverage story of its own (see
  /// [`drop_subtree_for_crawl_rebuild`](Monitor::drop_subtree_for_crawl_rebuild)).
  /// The crawl's own re-install heals it through the
  /// [`install_child`](Monitor::install_child) interlock, or it stays booked
  /// for the dispatch re-signal until the vanish's `Removed` converges it.
  /// This discharges the ERASED DEFICIT only; retiring the coverage itself is
  /// covered separately by the crawl's own opening `Rescan`, which a
  /// deficit-free drop still owes.
  Reanchor,
  /// Terminal teardown of the scope (unregister, root invalidation, rebind):
  /// the caller's unconditional terminal/commit `Rescan` and whole-book wipe
  /// own coverage from here — the scope is gone, there is no barrier left to
  /// lie to.
  Teardown,
  /// A proven-unsubscribed prune
  /// ([`drop_watch_subtree`](Monitor::drop_watch_subtree)): the coverage is
  /// outside every committed subscription, so no subscriber exists to lie to.
  UnsubscribedPrune,
}

/// One unverified same-transport adoption edge — what
/// [`pending_adoptions`](Monitor::pending_adoptions) stands against the chain
/// parent that owes its re-proof.
///
/// **The obligation is to an IDENTITY, never to a coordinate.** A marker that
/// stored only the slot name would make every disposal resolve
/// [`child_watch`](Monitor::child_watch)`(parent, name)` — whichever child
/// occupies that slot at the moment of the release — and the dark window this
/// marker exists to catch is exactly the window in which that stops being the
/// adopted object. Before the first complete proof a `MovedFrom` can DETACH the
/// adopted watch — freeing the slot while the parent link, and so the
/// containment invariant, stay intact — and a replacement can grow into the
/// vacated name, with no marker update and no check of what was expected there;
/// a name-resolved disposal then retires that REPLACEMENT (or, on a slot still
/// empty, merely re-scans it) while the original unproven subtree survives, still
/// reconstructing its descendants' paths through an edge nothing ever confirmed,
/// and [`coverage_settled`](Monitor::coverage_settled) free to go true over it.
///
/// So the marker carries the adopted [`WatchId`] itself, and every
/// [`AdoptionDisposal`] acts on THAT watch rather than on the slot's current
/// occupant. The name is kept for the one question that really is about the
/// coordinate — which listing entry a proof must read — and the two are then
/// checked TOGETHER, which is what keeps a replacement from paying the
/// original's debt: the entry must carry the expected identity AND the adopted
/// watch must still hold the slot.
#[derive(Debug, Clone)]
struct AdoptionMarker {
  /// The slot name the old root was re-keyed under at the chain parent: the
  /// listing entry a proof reads, and the location a recorded death re-scans.
  /// A COORDINATE — never what a disposal resolves.
  name: Segment,
  /// The adopted watch: the scope's old root, re-keyed under the chain parent
  /// by the widen. The identity of the obligation, so a rename before the
  /// proof moves the debt with the object instead of leaving it at the slot.
  adopted: WatchId,
  /// The identity the widen NAMED the adopted object by
  /// ([`widen_root`](Monitor::widen_root)'s `old_identity`, which it refuses to
  /// splice without). The proof compares the listing entry against this stored
  /// value rather than against the adopted node's current `identity` field, so
  /// what is re-proven is the object the widen claimed to adopt and no later
  /// write to that field can turn an unprovable edge into a confirmed one.
  identity: Identity,
}

/// What becomes of the ADOPTED CHILD when a widen's adoption marker is
/// released — named at every release site so the invariant is auditable in one
/// place: **a marker is released only together with a disposal of the child it
/// adopted — a proof, a counted retirement, or the child's already-completed
/// destruction — never on its own.**
///
/// The marker is the only record that a widen's commit→arm window was never
/// verified, and releasing it is what lets the adoptions conjunct of
/// [`coverage_settled`](Monitor::coverage_settled) go true. A release that
/// leaves the unproven subtree standing hands a STRICT proof's leftovers to
/// the machinery every later reconciliation of that slot runs — which is
/// PERMISSIVE by design (pruning an incumbent on ignorance would un-cover a
/// live directory) and therefore RETAINS what it cannot positively displace.
/// The unproven subtree then keeps delivering at reconstructed-stale paths
/// with the barrier reading settled: the exact failure the marker exists to
/// prevent, reached through the marker's own release.
///
/// This is a rule about a class, not about one site. Three separate releases
/// have been written as bare removals whose covering story lived only in a
/// comment beside them, and a comment cannot be checked for being INERT on the
/// path it claims to cover — the retry-cap site's named cover (a located
/// `Rescan` plus an interior deficit) is suppressed in full on the held path
/// that reaches it. Naming the disposal as an ARGUMENT is what makes it
/// unskippable, and performing it inside
/// [`release_adoption_marker`](Monitor::release_adoption_marker) is what keeps
/// the name and the act from drifting: there is no way to spell the release
/// without choosing a variant here, and no variant whose cover is merely
/// asserted in prose. A `let _ =` on the result discards only EVIDENCE — that a
/// marker stood — never the disposal, which has already happened.
#[derive(Debug, Clone, Copy)]
enum AdoptionDisposal {
  /// The caller holds the proof that RESOLVES the edge and takes the verdict on
  /// the returned marker itself — the one disposal that leaves the act to its
  /// caller. Two sites own a proof, and they are the two halves of one:
  /// [`resolve_adoption`](Monitor::resolve_adoption) reads the confirming
  /// listing and answers a refutation or a recorded death immediately, and
  /// [`seal_staged_adoptions`](Monitor::seal_staged_adoptions) takes the
  /// CONFIRM once an ordering fence has put every record that could refute it
  /// ahead of the verdict.
  Verdict,
  /// No read can prove the edge. Either none is left — the bounded retries are
  /// spent ([`handle_incomplete_enumerate`](Monitor::handle_incomplete_enumerate))
  /// — or the adopted object has been seen to MOVE, which spends the proof a
  /// listing could still appear to give
  /// ([`on_move_self`](Monitor::on_move_self): its final occupancy and identity
  /// cannot distinguish an edge that never moved from one that left and came
  /// back). Either way, retire the adopted child INSIDE a counted covering
  /// `Rescan`:
  /// [`stand_counted_cover`](Monitor::stand_counted_cover) first, then a
  /// [`CoveringRescan`](DeficitDischarge::CoveringRescan) drop of the subtree.
  /// Root-anchored and counted so that it covers and releases on the HELD path
  /// too, where a located `Rescan` would name the vacated pre-move path and
  /// the interior deficit is not recorded at all.
  CountedRetirement,
  /// The adopted child is being destroyed by the very walk that is releasing
  /// this marker ([`drop_subtree`](Monitor::drop_subtree)): the marker keys on
  /// the dying node, so a child still UNDER it is already on the walk's stack.
  /// Erasing an unverified edge is erased COVERAGE all the same, which the walk
  /// reports as [`ErasedCover::Discharge`] and discharges under its own
  /// [`DeficitDischarge`] reason.
  ///
  /// "Still under it" is the whole content of that claim, and it is the
  /// CONTAINMENT INVARIANT rather than a hope: the one parent-rewrite site
  /// refuses to reparent an unproven adopted edge (see
  /// [`pending_adoptions`](Monitor::pending_adoptions)), so the adopted watch is a
  /// direct child of the marker's own node for as long as both live, and the walk
  /// that pops that node pushes the child in the same step. The release states it
  /// as a `debug_assert!` here, read through the CHILD's parent link — the dying
  /// node is already out of `nodes`, while the child still names it, so the check
  /// works mid-walk.
  ///
  /// That it is an invariant is what keeps this a single walk: a child free to be
  /// reparented out would have to be verified and then retired by a SECOND walk,
  /// destroying nodes outside the subtree the caller handed in.
  DiesWithTheWalk,
  /// The adopted child was already dropped, before this release
  /// ([`rebind_root`](Monitor::rebind_root) drops every child of the surviving
  /// root, and a depth-one widen keys its marker on that root). Checked rather
  /// than claimed: the release debug-asserts the adopted WATCH is gone — not
  /// merely that its old slot is empty, which a rename would satisfy while the
  /// child stood elsewhere — so a child that outlived the drop fails loudly
  /// instead of becoming a fourth silent release.
  ChildAlreadyDropped,
}

/// Declares a fieldless enum together with its `ALL` slice from ONE
/// written-out variant list, so the enum and `ALL` cannot drift apart: both
/// are expansions of the same input tokens rather than two hand-synced
/// lists, so a variant is either in both or in neither — never in one alone.
macro_rules! enum_with_all {
  (
    $(#[$enum_meta:meta])*
    enum $name:ident {
      $(
        $(#[$variant_meta:meta])*
        $variant:ident,
      )+
    }
  ) => {
    $(#[$enum_meta])*
    #[derive(Debug, Clone, Copy)]
    enum $name {
      $(
        $(#[$variant_meta])*
        $variant,
      )+
    }

    impl $name {
      /// Every variant, generated together with the enum above from the same
      /// written-out list (`enum_with_all!`): there is no second list a
      /// variant could be added to (or left out of) on its own.
      const ALL: &[Self] = &[
        $(Self::$variant,)+
      ];
    }
  };
}

enum_with_all! {
  /// Every per-node marker [`drop_subtree`](Monitor::drop_subtree)'s walk
  /// reclaims — the side-table entries a dying watch takes with it.
  ///
  /// The walk is the SINGLE destruction point all of them pass through, and each
  /// erasure is a coverage question with its own answer ([`ErasedCover`]).
  /// Enumerating the markers here, instead of open-coding one removal per marker
  /// inside the walk, is what keeps that answer from being forgotten:
  /// [`reclaim_node_marker`](Monitor::reclaim_node_marker)'s match is exhaustive,
  /// so a marker cannot join the walk without STATING what erasing it owes, and
  /// [`ALL`](Self::ALL) is what the walk iterates, so a stated answer cannot then
  /// go unasked.
  ///
  /// This is a rule about a class, not about one marker: a marker whose erasure
  /// silently discharged nothing has twice reached the walk by way of a
  /// booking-site argument that did not survive the node dying under it, and a
  /// per-marker rule cannot fail loudly for the marker nobody has added yet.
  enum NodeMarker {
    /// The node's outstanding [`Action::Enumerate`](crate::Action::Enumerate),
    /// with any coalesced re-arm obligation riding on it
    /// ([`latent_cold`](Monitor::latent_cold)).
    Enumerate,
    /// Every outstanding [`Action::Stat`](crate::Action::Stat) addressed to one
    /// of the node's slots, and the dedup index mirroring them.
    StatSlots,
    /// The node's detached-and-held move-source membership
    /// ([`held_sources`](Monitor::held_sources)) and its per-scope mirror.
    HeldSource,
    /// The debt a hold accrued from activity suppressed at its stale pre-move
    /// path ([`dirtied_holds`](Monitor::dirtied_holds)).
    DirtiedHold,
    /// A descent a read deferred to a slot's stat and booked against this node
    /// ([`owed_descents`](Monitor::owed_descents)).
    OwedDescent,
    /// The ACK-postdates-loss stamp of an outstanding reprove arm
    /// ([`reprove_stamps`](Monitor::reprove_stamps)).
    ReproveStamp,
    /// An unverified same-transport adoption edge awaiting this node's read
    /// ([`pending_adoptions`](Monitor::pending_adoptions)).
    Adoption,
    /// The coverage deficits anchored at this node (see [`DeficitBook`]).
    Deficits,
  }
}

/// What erasing one [`NodeMarker`] owes the scope — the whole vocabulary
/// [`drop_subtree`](Monitor::drop_subtree)'s walk understands.
///
/// A marker records coverage the monitor took responsibility for, so its
/// destruction is a loss unless something else already covers the same
/// interval. The answer belongs to the marker rather than to the consumer:
/// the walk destroys every variant wholesale, and a consumer that reasoned
/// about only the markers it knew of is exactly how an erased one goes
/// uncovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErasedCover {
  /// Nothing: the marker carries no coverage of its own, so erasing it is not
  /// a loss and a drop that erased only these stays silent.
  Nothing,
  /// The caller's [`DeficitDischarge`] reason — the covering `Rescan`'s two
  /// bridge bits, or the re-anchored slot deficit at the surviving parent.
  Discharge,
  /// A COUNTED covering re-read
  /// ([`stand_counted_cover`](Monitor::stand_counted_cover)), owed
  /// independently of the deficit condition `Discharge` rides: the object
  /// provably SURVIVES, so "erased nothing, so owes nothing" does not reach
  /// it and its dead handles keep carrying a live object's records.
  Counted,
}

/// What one walk of [`drop_subtree`](Monitor::drop_subtree) erased, folded
/// across its nodes and its markers.
#[derive(Debug, Clone, Copy, Default)]
struct ErasedCovers {
  /// Some marker owed the caller's discharge reason.
  discharge: bool,
  /// Some marker owed a counted covering re-read.
  counted: bool,
}

impl ErasedCovers {
  /// Folds one marker's answer in — the ONE place an [`ErasedCover`] is
  /// consumed, so no answer can be computed and then dropped.
  fn absorb(&mut self, cover: ErasedCover) {
    match cover {
      ErasedCover::Nothing => {}
      ErasedCover::Discharge => self.discharge = true,
      ErasedCover::Counted => self.counted = true,
    }
  }
}

/// The [`WatchNode::moved_at`] reading of a node whose own placement has never
/// changed.
///
/// The clock is advanced BEFORE a change is recorded against it
/// ([`Monitor::moved_placement`]), so the least reading any real move can carry
/// is 1 — which is what lets "never moved" be a reading rather than a second
/// field, and what makes it compare correctly against every stamp: `0` is
/// greater than no stamp, so a node that has not moved can never make one stale.
const NEVER_MOVED: u64 = 0;

/// One node in the parent-relative watch tree.
///
/// Paths are reconstructed by walking `parent` links to a root, so a node stores
/// only its own name and its parent — an intra-tree directory move is then a
/// single edge change rather than a subtree rewrite.
#[derive(Debug, Clone)]
struct WatchNode {
  parent: Option<WatchId>,
  name: Option<Segment>,
  scope: ScopeId,
  is_dir: bool,
  /// The arm attempt this handle is currently bound to — the most recent one
  /// issued for it. A [`Monitor::on_watch_result`] naming any other attempt
  /// answers for an arm some later one superseded and is discarded, so a stale
  /// outcome (above all a `Err` from a retired transport) can never invalidate
  /// the binding that replaced it. Written only by
  /// [`Monitor::queue_watch`](Monitor::queue_watch) and by the out-of-band
  /// re-arm funnel ([`Monitor::adopt_arm`](Monitor::adopt_arm)); a node is born
  /// with the attempt its first arm carries.
  attempt: ArmAttempt,
  /// The PLACEMENT clock reading ([`Monitor::placement_now`]) at which this
  /// node's outstanding round trip was issued — its pending arm, or its
  /// in-flight enumerate. [`NodeState`] makes those mutually exclusive, so one
  /// stamp serves both.
  ///
  /// The driver LOWERS an identity-relative coordinate to an absolute path
  /// before the I/O, and that path is a fact about where the node was, not a
  /// name for the node. Read back against
  /// [`placement_moved_since`](Monitor::placement_moved_since) it says whether
  /// the path the driver used still describes this node. Written wherever a
  /// round trip is ISSUED — [`Monitor::queue_watch`](Monitor::queue_watch),
  /// [`Monitor::adopt_arm`](Monitor::adopt_arm),
  /// [`Monitor::queue_enumerate`](Monitor::queue_enumerate) — and at birth, like
  /// `attempt`.
  placement: u64,
  /// The PLACEMENT clock reading at which THIS node's own placement last
  /// changed: its slot was vacated ([`Monitor::detach_child`]) or re-keyed by a
  /// rename ([`Monitor::reparent`]), or — for a root — the driver's root bytes
  /// were replaced under it ([`Monitor::rebind_root`]). Born [`NEVER_MOVED`],
  /// and written ONLY by [`Monitor::moved_placement`].
  ///
  /// A lowered path is `root_bytes ⊕ names along the parent chain`, so it stops
  /// describing its node exactly when one link OF THAT CHAIN changes. Recording
  /// the change on the node it happened to — rather than on the whole scope — is
  /// what keeps an unrelated rename from invalidating in-flight work elsewhere,
  /// at the cost of an ancestor walk when a result lands (see
  /// [`Monitor::placement_moved_since`]).
  ///
  /// A birth is not a placement change, so it must not read as one. Stamping a
  /// newborn with the clock's CURRENT value would make it postdate any older
  /// outstanding request — and a splice that puts a newborn on such a request's
  /// chain while preserving every absolute path
  /// ([`Reparent::Rerooted`](Reparent::Rerooted), the widen) would then reject a
  /// result nothing invalidated, once for every request in flight, whenever some
  /// unrelated scope happened to rename in between.
  moved_at: u64,
  /// The object identity this watch was installed for, if the driver supplied one.
  /// Compared against a fresh enumerate's entry identities during a re-arm to keep a
  /// surviving watch versus rebuild a same-name replacement (see [`Identity`]).
  identity: Option<Identity>,
  /// The coverage lifecycle: pending-arm, live-idle, or enumerating (see [`NodeState`]).
  state: NodeState,
  /// The set of watches whose `parent` is this node — the adjacency dual of `parent`.
  /// A detached-and-held move source stays here (its `parent` is unchanged) even though
  /// it has left `child_index`, so a subtree walk reaches it in O(children) without an
  /// O(N) scan of the whole node map.
  children: BTreeSet<WatchId>,
}

/// A pending [`RecordKind::MovedFrom`] awaiting its matching
/// [`RecordKind::MovedTo`].
///
/// It carries enough to validate a candidate pair before consuming it *and* to
/// resolve it when its source disappears. `scope` and `deadline` bound pairing in
/// space and time. The source is anchored by its slot `(from_parent, from)`
/// rather than an eager path: the location is reconstructed on use, so if the
/// source's own ancestor is reparented mid-window the resolved path follows it.
/// `from_parent` (the watch the `MovedFrom` arrived on) also gates liveness: a
/// teardown of that subtree discards this half (invariant b) rather than let it
/// later time out into a `Removed` for a path that no longer exists.
///
/// `held` is a watched-directory source's own subtree, detached from its old
/// `(parent, name)` slot but kept alive across the pairing window so a paired
/// `MovedTo` can [`reparent`](Monitor::reparent) it in O(1) — its descendants
/// follow their unchanged parent links, with no re-enumerate and no per-descendant
/// `Created`. Detaching frees the old path for a replacement to install its own
/// watch; an unpaired move tears the held subtree down when its window elapses.
/// `None` for a non-directory (unwatched) source.
#[derive(Debug, Clone)]
struct PendingMove {
  from_parent: WatchId,
  /// The source's watch-relative location under `from_parent` — one segment on a
  /// per-directory backend, possibly deeper on a kernel-recursive one.
  from: Location,
  scope: ScopeId,
  deadline: Instant,
  held: Option<WatchId>,
  /// The moved object's target class, kept so every move-derived delivery (the paired
  /// `Moved`, an unpaired half's `Removed`/`Created`) can honor the `ondir` modifier.
  /// A held source is definitionally a watched directory; otherwise this is whatever
  /// the source record reported.
  is_dir: Option<bool>,
  /// The facts the source record proved, carried so a resolution that outlives
  /// the record — a timeout's stranded `Removed`, an unanchored pair's
  /// `Created` — is still admitted on the move the half witnessed. Without it a
  /// `moved`-only subscriber would receive neither half of an unpairable
  /// rename nor anything covering it.
  evidence: Evidence,
  /// Whether subtree activity interleaved with this half's pairing window: a record or
  /// located overflow whose location mutual-prefixes the pending source landed while
  /// the half was parked. Such activity described a REPLACEMENT at the source, which
  /// the eventual resolution (a `Moved` reparenting the consumer's tree, or a
  /// `Removed`) contradicts — so a dirty half's resolution emits covering `Rescan`s
  /// at the source and, for a pair, the destination.
  ///
  /// Applies to held and unheld halves alike, and is ORTHOGONAL to
  /// [`dirtied_holds`](Monitor::dirtied_holds): that marker records content SUPPRESSED
  /// under a held source's detached subtree (paths through the hold reconstruct stale,
  /// so its records are fenced and recover with a destination rescan + re-arm at
  /// pairing). This flag records transitions at the half's SOURCE SLOT — activity that
  /// DELIVERED at the vacated path, which is outside the detached subtree and has no
  /// stale-path hazard. A held half whose slot was reoccupied owes the vacated path a
  /// source-side cover that no destination rescan provides, so a held half can carry
  /// both markers, each producing its own covers.
  dirty: bool,
}

impl PendingMove {
  /// Whether this half may still pair at `now` — the ONE definition of the
  /// pairing window, shared by the destination that consumes a half
  /// ([`Monitor::on_moved_to`]), the timeout that strands one
  /// ([`Monitor::handle_timeout`]), and the reparenting precondition
  /// ([`Monitor::reparenting_source`]). A second spelling of the same comparison
  /// is how a half becomes pairable to one of them and expired to another.
  fn in_window(&self, now: Instant) -> bool {
    !now.reached(self.deadline)
  }
}

/// The downward re-arm a read that deferred to a slot stat owes the slot's
/// INCUMBENT watch — the descent that read could not perform, because it could
/// not tell whether the incumbent's object was still the one at that name.
///
/// Owed to the WATCH, not to the slot: it is booked in
/// [`owed_descents`](Monitor::owed_descents) under the incumbent's
/// [`WatchId`], which a reparent preserves, rather than under the
/// `(parent, name)` the stat is addressed to, which a rename empties while the
/// object it named lives on.
///
/// Ordered by strength (`Rearm` < `Reprove`), and compared as an `Option` whose
/// `None` is weaker than either: a stat already outstanding for a slot is
/// re-encountered by later reads, so its obligation is UPGRADED with `max` and
/// can never be downgraded to the flavor of whichever read happened to queue it
/// first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum StatDescent {
  /// Re-arm the survivor downward, so a directory created under it during the
  /// deferral is armed rather than left blind.
  Rearm,
  /// As [`Rearm`](Self::Rearm), and the survivor's own binding must be
  /// RE-PROVEN by an acknowledged re-add first — the flavor of a reprove
  /// crawl, whose retained descendants may be identity-matched yet unbound.
  Reprove,
}

/// The slot one outstanding [`Action::Stat`](crate::Action::Stat) must settle:
/// a name under a watched parent whose listed kind was
/// [`FileKind::Unknown`](crate::FileKind::Unknown).
///
/// The request carries the slot, and the queue-time READINGS that decide how a
/// late answer must be routed and what its release owes. It carries no
/// OBLIGATION. The descent a deferring read owes lives in
/// [`owed_descents`](Monitor::owed_descents) keyed by the incumbent watch (see
/// [`StatDescent`]) — a request that carried it would tie
/// the obligation to this coordinate, and the object that owes it can leave the
/// coordinate before the answer lands. The COVER a retirement owes is likewise
/// not carried here — it is decided from what the answer actually did to the
/// slot ([`Monitor::settle_stat_slot`]), so an absent or unrecognized obligation
/// still ends in a cover rather than silence.
#[derive(Debug, Clone)]
struct StatSlot {
  parent: WatchId,
  name: Segment,
  scope: ScopeId,
  /// The PLACEMENT clock reading ([`Monitor::placement_now`]) this request was
  /// issued at. The slot key survives a rename of the parent — that is the whole
  /// point of keying by `(parent, name)` — but the PATH the driver lowered it to
  /// does not, so an answer whose parent chain moved since is describing the
  /// vacated path and must not settle the slot the parent now occupies.
  placement: u64,
  /// Whether the scope's registration window stood when this request was
  /// QUEUED. The stat is deliberately uncounted
  /// ([`Monitor::defer_stat_descent`]) and no conjunct of
  /// [`Monitor::coverage_settled`], so the scope's first settle edge can pass —
  /// burying the bootstrap mark — while a bootstrap-queued stat is still
  /// outstanding. An answer routed off the LIVE mark would then install cold and
  /// its post-arm read would announce the whole subtree as `Created`s: the exact
  /// registration inventory the suppression removes, resurrected in the
  /// answer-after-settle ordering. Deciding the window at queue time instead
  /// keeps the mark's lifetime exactly the window's — the stamp travels with the
  /// request, and is inert until an answer arrives, so nothing counted is added
  /// here.
  ///
  /// The stamp governs the install ROUTING — and, through it, one thing more,
  /// because that routing STANDS a cover: the detour's bridge half plus its
  /// counted re-arm are the window's closing `Rescan`, so a release that would
  /// otherwise hand this slot's darkness to a `Rescan` of its own withholds it
  /// ([`Monitor::ingest_stat_result`]). What a barrier may claim while the
  /// request stands is `stands_loss` below, which a registration-window request
  /// always carries but is not alone in carrying.
  bootstrap: bool,
  /// Whether this request stands its scope's SETTLEMENT LOSS
  /// ([`Monitor::stat_losses`]) for as long as it is owed — the answer to "what
  /// may a barrier claim in the meantime", where `bootstrap` answers "what does
  /// a late answer install".
  ///
  /// Two queue-time conditions raise it, and their union is deliberate:
  ///
  /// - the scope's REGISTRATION window stood (`bootstrap`), whose crawl arms
  ///   ground it announces nothing for; and
  /// - the slot held NO watch when the request was queued, in ANY window. The
  ///   listing that asked for the kind reconciled nothing for such a slot — it
  ///   books darkness ([`Monitor::record_slot_deficit`]) and waits — so the slot
  ///   may be a directory the scope has no watch on at all, and the read that
  ///   found it need not have stood any `Rescan` of its own (a pure grow, or a
  ///   record-driven cold read, stands none).
  ///
  /// Without it a fence opened between the queue and the answer certifies a
  /// window whose possible directory is watched by nothing, and writes beneath
  /// it are recorded by nothing. The standing coverage deficit does not close
  /// that: it re-signals at a sync cookie's DISPATCH, and an ordinary set-cover
  /// reply passes nowhere near it.
  ///
  /// It only ever RISES. The dedup in [`Monitor::queue_stat`] coalesces every
  /// later read of the same name onto one request, so the loss the answer
  /// discharges must be the strongest any of those reads carried — a slot whose
  /// incumbent died under an already-outstanding stat is re-listed into an EMPTY
  /// slot, and that read's darkness would otherwise be booked with nothing
  /// standing for it. It never falls: a later occupation heals the hole through
  /// [`Monitor::remove_slot_deficit`], which stands its own covering `Rescan`,
  /// and dropping the loss there would trade a discharge edge that cannot be
  /// forgotten for one that can.
  ///
  /// It is RELEASED at exactly two sites, because the row itself leaves
  /// [`Monitor::pending_stat`] at exactly two: the answer's arrival
  /// ([`Monitor::ingest_stat_result`]) and the parent's death
  /// ([`NodeMarker::StatSlots`]). A result for a request neither of them left
  /// behind releases nothing, having found no row to take.
  ///
  /// **Every release owes a REPLACEMENT**, and the rule is one rule at both:
  /// where the interval the request spanned went dark with nothing stood for it
  /// since ([`Monitor::stat_slot_dark`]), the loss is handed on rather than
  /// released into silence. The answer hands it to a covering `Rescan` at the
  /// slot wherever its own settlement healed no fine entry — the book holds
  /// none for it (one collapsed past [`DEFICIT_CAP`] records none, and a
  /// dispatch re-signal spends the ones it does record), or the reconcile
  /// reused an occupant another path had already put in the slot. The parent's
  /// death reports the darkness as an erased cover and lets the walk's
  /// [`DeficitDischarge`] place it, since a teardown that stands nothing is the
  /// right answer for a scope that is going away and the wrong one for a slot
  /// emptied by a record.
  stands_loss: bool,
  /// Whether an interval this request stands for went DARK — a read found the
  /// slot holding NO watch — with no cover stood for it since.
  ///
  /// The companion of `stands_loss` above, and separate from it because the two
  /// answer different questions. The loss answers "may a barrier claim this
  /// window", which a REGISTRATION-stamped request raises over ground the scope
  /// already watches; this answers "was there an unwatched interval for the
  /// release to hand off", which only an EMPTY slot creates. It implies
  /// `stands_loss` — every read that raises this raises that, and the test
  /// invariant checker pins the implication.
  ///
  /// It is CARRIED rather than re-derived at the answer, because the slot's
  /// occupancy then is not the same question. A directory can be installed
  /// under the outstanding request — a `Created`, a move-in, a later enumerate —
  /// and an answer reading the filled slot would take "something is there now"
  /// for "nothing was ever missing". What actually covers the interval before
  /// such a fill is the fill's own heal
  /// ([`Monitor::remove_slot_deficit`], which stands the covering `Rescan` when
  /// it removes a real entry); a fill that removes none covers nothing — the
  /// book held no entry for it to remove (one collapsed past [`DEFICIT_CAP`]
  /// holds none, and a dispatch re-signal spends the ones it signals), or the
  /// path that filled the slot consults no book at all
  /// ([`Monitor::reparent`]) — and this is what says so at the answer.
  ///
  /// Raised from the one emptiness reading that decides it
  /// ([`Monitor::queue_stat`]), on a created request and on one the dedup
  /// coalesced onto alike. Cleared only by a cover actually stood: a real
  /// removal in `remove_slot_deficit`, the single act that turns a slot's
  /// booked darkness into the window's closing `Rescan`. An occupation that
  /// stands no cover clears nothing and the answer still owes the transfer,
  /// which is the direction an occupation path nobody has written yet fails in.
  dark_uncovered: bool,
  /// Whether a cover has been stood for the vacancy the slot holds RIGHT NOW —
  /// the answer to "is this emptiness already accounted for", which the
  /// emptiness itself cannot give.
  ///
  /// A slot reading empty at the answer is reason to cover only while nothing
  /// has covered that emptiness yet. A `File`/`Gone` reconcile arriving from
  /// outside this request removes the slot's fine entry and stands the covering
  /// `Rescan` for exactly this vacancy — and leaves the slot EMPTY, since that
  /// is what those occupants mean. Read as "empty, therefore uncovered", the
  /// answer would then stand a SECOND cover over an interval already handed to
  /// the first: an epoch bump, a degraded cover state, and a consumer
  /// enumeration nothing asked for.
  ///
  /// Raised by an act that stands that cover and by nothing weaker. There are
  /// exactly two, because the settlement that EMPTIES a slot can emit from either
  /// of two places and a caller cannot tell from outside which of them did:
  ///
  /// - a real removal in [`Monitor::remove_slot_deficit`], at the one caller
  ///   whose settlement leaves the slot empty ([`Monitor::reconcile_slot`]'s
  ///   `File`/`Gone` arm). The other caller ([`Monitor::install_child`]) removes
  ///   the same entry to OCCUPY the slot, which ends a vacancy rather than
  ///   covering one, and raises nothing here; and
  /// - the teardown of the departing occupant itself
  ///   ([`Monitor::drop_departed_occupant`]), whose walk stands the scope's
  ///   covering `Rescan` when it erases a deficit anchored inside the dying
  ///   subtree. That cover is root-located, so it reaches this slot, and the walk
  ///   that stands it is the walk that empties the slot, so it cannot predate the
  ///   vacancy.
  ///
  /// Neither subsumes the other: they consume different books, and an occupation
  /// racing the request has already spent the slot's own fine entry, leaving the
  /// teardown as the whole of what the emptying stands.
  ///
  /// Deliberately NOT raised by every `Rescan` that happens to reach the slot. A
  /// root-located cover from anywhere in the scope — an overflow, a sibling's
  /// counted recovery, another subtree's bridge window, and the counted cover a
  /// teardown of this very subtree may owe for an object that survives elsewhere
  /// ([`Monitor::stand_counted_cover`]) — reaches this slot too, and that
  /// population is open-ended: there is no site set to record at, and most of it
  /// knows nothing about this slot. What makes the two above recordable is that
  /// each is part of the settlement of THIS slot, so each knows the vacancy it
  /// speaks for. Under-raising costs a redundant cover, which is legal;
  /// over-raising costs a missed one, which is not.
  ///
  /// Cleared by the act that opens a NEW vacancy — a removal from
  /// [`Monitor::child_index`] that really took an entry out
  /// ([`Monitor::vacate_child_slot`]) — because a cover stood for the previous
  /// vacancy says nothing about this one. That funnel is the only occupied-to-
  /// empty transition there is, which is what lets this be read as a fact about
  /// the CURRENT vacancy whenever the answer finds the slot empty. A refill needs
  /// no clear of its own: an occupied slot is not read here at all, and the drop
  /// that empties it again passes the same funnel.
  ///
  /// It is a SUPPRESSOR, never an obligation — it can only withhold a cover the
  /// live emptiness would otherwise stand, never stand one. So it carries no
  /// implication to `stands_loss` (a request standing no loss emits nothing
  /// either way) and no mirrored counter to pin; a missing clear costs a MISSED
  /// cover, which the cells hold rather than an invariant.
  vacancy_covered: bool,
}

/// Key for a half-resolved rename. A [`MoveCookie`] is unique only within one
/// backend instance, and disjoint roots may live on separate instances whose
/// cookies collide, so the cookie is namespaced by its [`ScopeId`]: a destination
/// may consume a source only under the identical composite key (invariant d). The
/// tuple derives `Ord` from both components, so it keys a `BTreeMap` — scope-major,
/// which lays one scope's halves out as a single contiguous range (what
/// [`Monitor::moves_settled`] tests, without a mirror counter to keep in step).
type PendingKey = (ScopeId, MoveCookie);

/// The least cookie any backend can mint, and so the lower bound of a scope's
/// contiguous range of [`PendingKey`]s.
const FIRST_COOKIE: MoveCookie = MoveCookie::new(NonZeroU64::MIN);

/// The low end of a scope-major [`WatchId`] range — the range start for
/// [`staged_adoptions`](Monitor::staged_adoptions)' per-scope lookups.
const FIRST_WATCH: WatchId = WatchId::new(NonZeroU64::MIN);

/// How many half-resolved renames ONE scope may park in
/// [`pending_moves`](Monitor::pending_moves) at once.
///
/// A parked half retires when its destination arrives, when its pairing window
/// elapses ([`Monitor::handle_timeout`]), or with the scope itself — so the store
/// holds only renames still inside one window, which real workloads keep orders of
/// magnitude below this. Without a bound, though, a scope that mints unique
/// unpairable cookies faster than the window retires them retains a `PendingMove`
/// and a detached watched subtree per cookie for as long as it keeps that up: an
/// adversarial stream buys unbounded retention, and every per-record pass over the
/// scope's halves degrades with it.
///
/// The bound is per-SCOPE, not global, so one scope's burst cannot starve the
/// halves of an unrelated root; the driver bounds how many scopes are live, so
/// bounded-scopes × this is bounded overall.
///
/// # Behaviour at the bound
///
/// It REFUSES, never evicts: a source arriving at a full scope is not parked, and
/// is therefore a source that can never pair — it takes the same unpairable path a
/// cookieless source takes ([`Monitor::on_moved_from`]), tearing its held subtree
/// down under a covering discharge and degrading to the `Removed` that path owes.
/// Evicting instead would forget a half whose destination is still coming and
/// silently drop the rename.
///
/// It is asked only of a source that would GROW the store. A cookie already parked
/// is a REPLACEMENT: it rewrites one key in place, so the high-water mark is
/// exactly where it was and there is nothing for the bound to defend. Refusing one
/// would be worse than admitting it, not safer — the store would keep the half the
/// replacement should have displaced, and pair that half's destination against a
/// source rename never had.
const PENDING_MOVE_CAP: usize = 64;

/// A delivery-dedup key: a change is suppressed only if an identical one is still
/// queued. Two changes are "identical" when they share a scope, location, kind
/// discriminant, and — for a [`ChangeKind::Moved`] — the same source location.
/// Carrying the source keeps two distinct renames to one destination from
/// collapsing into a single move; for every other kind the source slot is `None`.
type DedupKey = (ScopeId, Location, u8, Option<Location>);

/// What now occupies a child slot, as reported by a slot-changing record. `Dir`
/// is the only kind the core descends into (and thus watches per-directory);
/// `File` and `Gone` both mean the slot must hold no watch; `Unknown` is
/// unsettled and must be resolved before either can be decided. Consumed by
/// [`Monitor::reconcile_slot`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum SlotOccupant {
  /// A directory: watch it (per-directory backends descend into it).
  Dir,
  /// A non-directory file: never watched.
  File,
  /// The slot's object was removed: drop any watch it had.
  Gone,
  /// The occupant's kind could not be told from what the driver reported. It is
  /// NOT a non-directory: reading it as one would leave a real directory
  /// unwatched with no watch, no deficit and no `Rescan` — a subtree blind for
  /// as long as the process lives. The slot is booked as darkness and settled
  /// by an [`Action::Stat`](crate::Action::Stat) instead.
  Unknown,
}

/// How [`Monitor::rearm_watch_subtree`] (or an internal re-arm trigger) recorded a
/// re-arm obligation — the coverage-grow kickoff report a settle fence keys on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use = "a Coalesced kickoff's obligation is invisible to rearm_settled until its read completes; a settle fence must consume this"]
pub enum RearmKickoff {
  /// Nothing to re-arm: the watch is unknown/dead, or its scope is kernel-recursive
  /// (whole-subtree coverage never shrank).
  Refused,
  /// The obligation entered a state [`Monitor::rearm_settled`] counts — the scope
  /// reads unsettled until the re-arm work quiesces.
  Started,
  /// The obligation was folded into an in-flight **cold** read the settle counter
  /// deliberately does not count. It is not lost — the dirtied read's completion
  /// always escalates into a covering `Rescan` plus a counted re-arm retry — but a
  /// settle fence must treat this kickoff as lossy from birth (see
  /// [`Monitor::rearm_watch_subtree`]).
  Coalesced,
}

impl RearmKickoff {
  /// Whether this is [`Refused`](Self::Refused).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_refused(&self) -> bool {
    matches!(self, Self::Refused)
  }

  /// Whether this is [`Started`](Self::Started).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_started(&self) -> bool {
    matches!(self, Self::Started)
  }

  /// Whether this is [`Coalesced`](Self::Coalesced).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_coalesced(&self) -> bool {
    matches!(self, Self::Coalesced)
  }
}

/// What feeding one [`OsRecord`] to [`Monitor::on_os_record`] did to the watch
/// tree's SHAPE — the geometry a consumer that keeps its own per-scope bookkeeping
/// keyed by path must follow.
///
/// A consumer learns this from the call that performed it rather than by
/// re-deciding it from the same inputs. That is the whole point of the type: a
/// predicted reparent and a performed one are two implementations of one rule, and
/// two implementations drift. An outcome returned by the operation cannot — it is
/// the operation's own report. It also covers the case no read-only accessor could
/// see: a reparent the Monitor set out to perform and then *failed* leaves no trace
/// in the resulting tree, yet a consumer that predicted it would already have moved
/// its own anchor.
///
/// Deliberately NOT `#[must_use]`. `Nothing` is the outcome of essentially every
/// record and carries no obligation whatever, so a blanket must-use would put a
/// `let _ =` on nearly every feed — and a codebase trained to write `let _ =` on
/// this call is exactly how a real [`Reparented`](Self::Reparented) gets dropped.
/// The crate reserves `#[must_use]` for values that always carry an obligation
/// (see [`RearmKickoff`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordOutcome {
  /// The record moved no watched subtree between parents. Every record kind
  /// reports this except the one below — including a `MovedTo` that paired past
  /// its window, one whose source held no watched subtree, one with no cookie,
  /// and one whose reparent was *attempted and rejected* (a cyclic destination,
  /// or an endpoint the attempt's own teardown removed). A consumer re-anchors
  /// exactly when the Monitor reparented, and never when it did not.
  Nothing,
  /// A paired, in-window [`RecordKind::MovedTo`] over a held watched directory
  /// whose O(1) reparent SUCCEEDED, reporting the source slot as it stood
  /// immediately BEFORE that reparent.
  ///
  /// The slot is a `(from_parent, from)` pair, not an absolute path pinned when
  /// the source's `MovedFrom` arrived: `from` is reconstructed from the live tree
  /// at report time, so a source whose own ancestor was reparented mid-window is
  /// described by where it actually was, not where it started. Capturing it
  /// pre-reparent is what makes it the path the consumer's own bookkeeping is
  /// still keyed by; it is stable across the reparent that follows because a
  /// `from_parent` is never inside the subtree its child is moving.
  Reparented {
    /// The watch the source half's [`RecordKind::MovedFrom`] arrived on — the
    /// anchor `from` was reconstructed against, still watched at report time.
    from_parent: WatchId,
    /// The moved subtree's scope-relative location immediately before the
    /// reparent.
    from: Location,
  },
}

impl RecordOutcome {
  /// Whether this is [`Nothing`](Self::Nothing).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_nothing(&self) -> bool {
    matches!(self, Self::Nothing)
  }

  /// The pre-reparent source slot, or `None` for [`Nothing`](Self::Nothing).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn reparented(&self) -> Option<(WatchId, &Location)> {
    match self {
      Self::Nothing => None,
      Self::Reparented { from_parent, from } => Some((*from_parent, from)),
    }
  }
}

/// A scope's coverage-work epoch: an opaque count of the times that scope has
/// ACQUIRED work [`Monitor::coverage_settled`] counts.
///
/// Only [`Monitor::coverage_work_epoch`] mints one and the count itself is never
/// handed out, so the only way to name the epoch a scope reads NOW is to ask the
/// monitor that owns it. Deliberately no constructor and no conversion from a
/// raw counter: a holder of evidence stamped with an epoch can then compare that
/// stamp against a value it had to OBSERVE, and cannot manufacture one to
/// compare against instead.
///
/// One scope's epochs are ordered by acquisition, so a later one compares
/// greater. Two different scopes' epochs are unrelated counts, and comparing
/// them answers nothing.
///
/// Reading one off a monitor is the whole of the API:
///
/// ```
/// use core::num::NonZeroU64;
/// use tributary_proto::{Capabilities, Monitor, ScopeId};
///
/// let monitor = Monitor::new(Capabilities::new());
/// let scope = ScopeId::new(NonZeroU64::new(1).unwrap());
/// assert_eq!(
///   monitor.coverage_work_epoch(scope),
///   monitor.coverage_work_epoch(scope),
/// );
/// ```
///
/// Naming one any other way does not compile, which is what makes a holder's
/// currency check unskippable rather than merely expected:
///
/// ```compile_fail,E0423
/// use tributary_proto::monitor::CoverageWorkEpoch;
///
/// // No constructor, and the count is private: an epoch cannot be asserted,
/// // only observed.
/// let claimed = CoverageWorkEpoch(0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoverageWorkEpoch(u64);

/// The primitive-agnostic top half of the `tributaries` state machine.
///
/// `Monitor` owns everything the design says must be written once and shared
/// across every backend: the proto-minted handle registries, the
/// parent-relative watch tree (and thus path reconstruction), delivery dedup,
/// move normalization, overflow → [`ChangeKind::Rescan`], and emission. It is
/// concrete — it is *not* generic over a backend — so the recursion engine is
/// never fragmented per primitive. Backend-specific behavior enters only through
/// the [`Capabilities`] it is built with (above all
/// [`kernel_recursive`](Capabilities::kernel_recursive)).
///
/// # Driving the loop
///
/// The driver pushes inputs ([`register_root`](Self::register_root),
/// [`on_os_record`](Self::on_os_record), [`on_enumerate`](Self::on_enumerate),
/// [`on_watch_result`](Self::on_watch_result),
/// [`on_overflow`](Self::on_overflow),
/// [`handle_timeout`](Self::handle_timeout)) and drains outputs to a fixpoint
/// after each ([`poll_action`](Self::poll_action),
/// [`poll_event`](Self::poll_event)), arming a timer for
/// [`poll_timeout`](Self::poll_timeout). Draining after every input minimizes
/// latency, but it is a discipline, not a soundness precondition: a driver may
/// feed several inputs (a whole decoded kernel batch) before draining — the
/// queued changes coalesce only across adjacency that respects every
/// intervening transition, including subtree-wide adjacency for `Rescan`s. No
/// method performs I/O or reads a clock; time always arrives as a `now`
/// argument.
#[derive(Debug)]
pub struct Monitor {
  capabilities: Capabilities,
  move_window: Duration,

  watch_ids: Sequence,
  req_ids: Sequence,
  change_ids: Sequence,
  arm_attempts: Sequence,

  nodes: BTreeMap<WatchId, WatchNode>,
  /// `(parent, name) -> child watch`, kept in lockstep with `nodes`, so descent
  /// is idempotent (one watch per path) and a moved watched directory is
  /// detectable in O(log n).
  child_index: BTreeMap<(WatchId, Segment), WatchId>,
  roots: BTreeMap<ScopeId, WatchId>,
  /// Per-scope reconciliation generation. Bumped on every reconciliation trigger before
  /// that scope's `Rescan` is emitted; stamped on every emitted [`Change`]. Absent means
  /// [`Epoch::START`]. See [`Epoch`] for the no-silent-loss contract this underwrites.
  scope_epochs: BTreeMap<ScopeId, Epoch>,
  /// The DELIVERY interest each scope was registered with — what the consumer asked to
  /// receive. Distinct from the coverage mask sent to the backend: the core always
  /// subscribes to the structural kinds its watch tree needs (create/remove/move, on
  /// directories) and then narrows delivery here, in [`emit`](Self::emit) — otherwise a
  /// `Modified`-only registration would starve the tree of the very records that
  /// discover new directories, silently losing coverage.
  scope_interests: BTreeMap<ScopeId, Interest>,
  /// The capability profile each scope was registered with — which backend behavior
  /// (descend-per-directory vs kernel-recursive) governs that root's machinery. One
  /// Monitor can host mixed profiles (a driver selecting backends per root). Written on
  /// EVERY registration — the plain [`register_root`](Self::register_root) stores the
  /// constructor default — so a stale profile cannot leak across a scope's
  /// re-registration. Read through [`scope_descends`](Self::scope_descends).
  scope_profiles: BTreeMap<ScopeId, Capabilities>,
  /// Per-scope count of nodes in a re-arm-flavored state ([`NodeState::is_rearm`]) —
  /// the O(1) backing for [`rearm_settled`](Self::rearm_settled). Maintained at the
  /// three counter edges: every state transition (all funneled through
  /// [`set_state`](Self::set_state)), node birth ([`insert_node`](Self::insert_node)),
  /// and node removal (`drop_subtree`). An entry leaves the map when its count reaches
  /// zero, so a settled or torn-down scope holds no residue.
  rearm_pending: BTreeMap<ScopeId, usize>,
  /// Maps an outstanding enumerate request to the directory it reads. The node's
  /// [`NodeState::Enumerating`] carries the same `req` as the forward check, so a
  /// superseded result (whose node has moved on) is dropped rather than reconciled;
  /// the whole re-arm coalescing/retry state that used to live in four side-tables is
  /// now the node's [`NodeState`].
  pending_enumerate: BTreeMap<ReqId, WatchId>,
  /// Maps an outstanding [`Action::Stat`](crate::Action::Stat) to the slot
  /// whose kind it must settle. An entry exists only while the answer is owed.
  /// Deliberately NOT a conjunct of
  /// [`coverage_settled`](Self::coverage_settled): an unanswered stat must
  /// degrade to a re-signalled `Rescan`, not wedge every barrier of the scope.
  ///
  /// An UNWATCHED such slot BOOKS a coverage deficit at the read that asked for
  /// the kind — but the two lifetimes are NOT one, and nothing may read a
  /// standing request as proof that an entry still stands for its slot: a
  /// dispatch re-signal clears the entries it signals
  /// ([`resignal_deficits`](Self::resignal_deficits)) while the row stays owed,
  /// and a book collapsed past [`DEFICIT_CAP`] records none to begin with. What
  /// answers for the darkness across the whole of the request's life is the
  /// settlement loss below and the replacement its release owes
  /// ([`StatSlot::stands_loss`]).
  ///
  /// A request for a slot no watch covers — and every request a REGISTRATION
  /// window queued — additionally stands its scope's settlement loss for as long
  /// as it is owed ([`stat_losses`](Self::stat_losses)): the honest half of the
  /// exemption above, since the deficit re-signal that covers this darkness
  /// reaches a sync cookie's dispatch and not an ordinary set-cover reply.
  pending_stat: BTreeMap<ReqId, StatSlot>,
  /// The slots [`pending_stat`](Self::pending_stat) currently owes an answer
  /// for, mapped to the request that owes it, so asking twice for one is an
  /// O(log n) decision rather than a scan of every outstanding request. Mirrors
  /// that map's slots exactly (asserted by the test invariant checker).
  stat_slots: BTreeMap<(WatchId, Segment), ReqId>,
  /// Per-scope count of outstanding stats that stand the scope's SETTLEMENT
  /// LOSS ([`StatSlot::stands_loss`]) — the O(1) backing for
  /// [`stat_loss_outstanding`](Self::stat_loss_outstanding).
  ///
  /// Between the queue and the answer the scope has already left its counted
  /// re-arm state — queueing sets neither bridge bit and nothing counted — so a
  /// barrier built on [`coverage_settled`](Self::coverage_settled) can pass
  /// while the slot still holds no child watch, and a set-cover fence would
  /// certify a window whose possible directory is uncovered. This counter is
  /// what the consumer reads to refuse that certification.
  ///
  /// It is deliberately NOT a conjunct of `coverage_settled`. A blocking
  /// conjunct would let a driver that never answers wedge every barrier of the
  /// scope forever — the liveness hazard [`defer_stat_descent`] exists to
  /// avoid — whereas a loss signal degrades the verdict and leaves the settle
  /// floor under-claimed, which instructs the consumer to re-enumerate exactly
  /// as the coverage contract already asks.
  ///
  /// Maintained at the edges every such request passes, and there are only
  /// three because [`pending_stat`](Self::pending_stat) has only three: the
  /// [`queue_stat`](Self::queue_stat) that creates the row (or raises the loss
  /// of the row it coalesced onto), the answer's removal in
  /// [`ingest_stat_result`](Self::ingest_stat_result) (whatever the answer says,
  /// including a failure, an unresolvable kind, and one whose parent died under
  /// it), and the parent's own death ([`NodeMarker::StatSlots`]). An entry
  /// leaves the map at zero, so a scope holds no residue — and the whole map
  /// mirrors `pending_stat`'s loss-standing rows exactly (asserted by the test
  /// invariant checker).
  ///
  /// [`defer_stat_descent`]: Self::defer_stat_descent
  stat_losses: BTreeMap<ScopeId, usize>,
  /// The downward descent each watch is OWED by a read that deferred to its
  /// slot's stat ([`StatDescent`]), keyed by the watch itself.
  ///
  /// Keyed by identity, deliberately, and this is the whole point: a stat is
  /// addressed to a `(parent, name)` coordinate, and a rename empties that
  /// coordinate while the object that owes the descent lives on — detached,
  /// held, and about to be reparented with its subtree and its unproven
  /// bindings intact. An obligation keyed to the slot is settled against
  /// nothing by such an answer; one keyed to the watch rides the reparent and
  /// is discharged there ([`on_moved_to`](Self::on_moved_to)).
  ///
  /// An entry is UPGRADED, never downgraded
  /// ([`defer_stat_descent`](Self::defer_stat_descent)), and leaves the book
  /// exactly three ways: the stat's answer settles it against the incumbent it
  /// still finds ([`ingest_stat_result`](Self::ingest_stat_result)); a reparent
  /// discharges it against the identity it carried; or the owing watch is
  /// destroyed, which stands a counted cover
  /// ([`drop_subtree`](Self::drop_subtree)) rather than resolving toward
  /// silence. Bounded by the live node count, since the third exit is the one
  /// every death passes through.
  owed_descents: BTreeMap<WatchId, StatDescent>,
  /// Half-resolved renames awaiting their destination, keyed by `(scope, cookie)`.
  ///
  /// A parked half is a transition already consumed from the backend whose normalized
  /// change is still unwritten — which of `Moved`, `Removed` or nothing it becomes is
  /// unknown until the destination arrives or the window elapses. So membership here
  /// is also the moves conjunct of [`coverage_settled`](Self::coverage_settled)
  /// ([`moves_settled`](Self::moves_settled)): a barrier that certified over a parked
  /// half would let the change land behind a sync cookie the consumer has already
  /// treated as final.
  ///
  /// Four lifecycle invariants hold, each enforced at the site noted:
  /// (a) a half pairs only with a same-scope destination before its deadline
  /// (`on_moved_to`); (b) a half whose source is no longer watched never emits a
  /// stale `Removed` — every stored-half resolution routes through the liveness
  /// guard in `resolve_stored_half`, and a whole-scope `unregister_root` purges its
  /// halves outright (`purge_scope_pending_moves`); a narrow subtree drop instead
  /// leaves the half *pairable*, since its destination may still arrive at a
  /// surviving slot in the scope; (c) a cookie reused after its half timed out or
  /// went dead resolves fresh — the prior half was consumed, expired, or
  /// guard-discarded; (d) cross-scope identical cookies are isolated by the
  /// composite key (`on_moved_from` / `on_moved_to`).
  ///
  /// Each scope's population is bounded by [`PENDING_MOVE_CAP`]: a source that
  /// would take a scope past it is refused before it is parked
  /// ([`admits_pending_move`](Self::admits_pending_move)), which is what keeps a
  /// stream of unpairable renames from retaining halves — and their detached
  /// subtrees — without limit.
  pending_moves: BTreeMap<PendingKey, PendingMove>,
  /// Watched-directory move sources currently detached-and-held for their pairing window
  /// (the `held` of some [`PendingMove`]). A record arriving on such a source — or any
  /// node in its still-attached subtree — would deliver at the stale PRE-move path, so it
  /// is suppressed; the source is recorded in [`dirtied_holds`](Self::dirtied_holds) so
  /// the pairing reparent re-scans the destination to recover the change.
  held_sources: BTreeSet<WatchId>,
  /// Held sources (a subset of [`held_sources`](Self::held_sources)) that had a record
  /// suppressed during the hold, so the O(1) reparent alone would lose it: on pairing,
  /// such a source's destination gets a `Rescan` and a re-arm rather than a silent move.
  ///
  /// Membership is the whole answer. What the hold suppressed is content — a
  /// record, a delivery, a listing that could not be reconciled — and a re-read of
  /// the destination recovers all of it. A BINDING doubt never lands here: an
  /// acknowledgement that could not certify retires its binding at the seam
  /// ([`ingest_watch_result`](Self::ingest_watch_result)) instead of leaving one
  /// for the pairing to re-prove.
  dirtied_holds: BTreeSet<WatchId>,
  /// Per-scope bridge-window flags (see [`BridgeFlags`]), flushed into a
  /// closing `Rescan` at the scope's settle edge by
  /// [`settle_bridges`](Self::settle_bridges).
  bridge: BTreeMap<ScopeId, BridgeFlags>,
  /// Per-scope standing terminal deficits (see [`DeficitBook`]), consumed by
  /// [`resignal_coverage_deficits`](Self::resignal_coverage_deficits) and read
  /// by [`has_coverage_deficit`](Self::has_coverage_deficit).
  deficits: BTreeMap<ScopeId, DeficitBook>,
  /// Per-scope count of detached-and-held move sources — the O(1) backing for
  /// the holds conjunct of [`coverage_settled`](Self::coverage_settled).
  /// Mirrors [`held_sources`](Self::held_sources) membership exactly, at its
  /// three mutation sites.
  held_by_scope: BTreeMap<ScopeId, usize>,
  /// In-flight COLD reads carrying a coalesced re-arm obligation
  /// ([`RearmKickoff::Coalesced`]), keyed by the read's unique [`ReqId`] — the
  /// one latency [`rearm_settled`](Self::rearm_settled) deliberately does not
  /// count, gated instead by the latent conjunct of
  /// [`coverage_settled`](Self::coverage_settled). Removal mirrors
  /// [`pending_enumerate`](Self::pending_enumerate) removal exactly.
  latent_cold: BTreeMap<ReqId, ScopeId>,
  /// Unverified same-transport adoption edges: a widen re-keyed the scope's
  /// OLD root under a name at a freshly-minted chain parent whose kernel watch
  /// was not yet armed at the re-key, so a slot mutation in that window is
  /// recorded by nobody. Keyed by the chain parent, whose first complete read
  /// must positively re-confirm the edge; the [`AdoptionMarker`] value carries
  /// WHICH watch was adopted and the identity it was named by, so the debt is
  /// owed by an object rather than by a slot (see the type — this is what keeps
  /// a rename in the dark window from handing the proof to a replacement).
  /// Consumed by [`resolve_adoption`](Self::resolve_adoption) — immediately on a
  /// refutation or a recorded death, and one ordering fence later on a confirm
  /// ([`seal_staged_adoptions`](Self::seal_staged_adoptions), the only site that
  /// releases a marker as verified) — or by the retry cap when no read is left
  /// to reach it
  /// ([`handle_incomplete_enumerate`](Self::handle_incomplete_enumerate)), or by
  /// the adopted object's own [`RecordKind::MoveSelf`], which proves the
  /// window held a movement no listing can see afterwards
  /// ([`on_move_self`](Self::on_move_self)); an entry also
  /// dies with its keyed node (`drop_subtree`) and with a root rebind
  /// ([`rebind_root`](Self::rebind_root) — the depth-one widen keys the marker
  /// on the surviving root itself). Every removal funnels through
  /// [`release_adoption_marker`](Self::release_adoption_marker), so the settle
  /// counter below cannot drift and no release can go without disposing of the
  /// child it adopted ([`AdoptionDisposal`]).
  ///
  /// **CONTAINMENT INVARIANT.** For every entry `K → (name, adopted, identity)`:
  /// `adopted` is not a live node, or `nodes[adopted].parent == Some(K)`. An
  /// unproven adopted edge is IMMOVABLE.
  ///
  /// Three kinds of site can touch it, and no others. BIRTH constructs exactly
  /// this shape — the widen re-keys the adopted watch as a DIRECT child of the
  /// chain tail it then stands the marker at. Every DROP only moves an entry to
  /// the first disjunct, or removes the marker with its key. And `node.parent` is
  /// rewritten in exactly ONE place ([`reparent`](Self::reparent)), whose two
  /// callers are that widen splice and [`on_moved_to`](Self::on_moved_to)'s
  /// pairing arm — which REFUSES an unproven adopted watch
  /// ([`reparentable_adoption`](Self::reparentable_adoption)) and disposes of it
  /// where it stands, restoring the invariant by its first disjunct rather than
  /// compensating for a relocation.
  ///
  /// What it buys is LOCALITY: `drop_subtree(x)` mutates only `subtree(x)` plus
  /// scope-level bookkeeping, because the one disposal that resolves a node the
  /// caller did not name — retiring the adopted watch of a marker the walk erases
  /// — provably resolves a node INSIDE it. Every caller's continuation is written
  /// on that, and the alternative is threading a collateral fate through the
  /// hottest reconcile paths in the monitor.
  pending_adoptions: BTreeMap<WatchId, AdoptionMarker>,
  /// The adoption markers whose confirming listing has been ingested but whose
  /// CONFIRM has not been released yet, keyed scope-major by the marker's own
  /// chain parent, valued with the staging generation the listing was ingested
  /// at ([`adoption_staging_seq`](Self::adoption_staging_seq)).
  ///
  /// **Staging is not a release.** A staged marker still stands in
  /// [`pending_adoptions`](Self::pending_adoptions), still counts in
  /// [`adopting_by_scope`](Self::adopting_by_scope), and still refuses the one
  /// reparent site — everything the marker did before the listing, it goes on
  /// doing. What staging records is that the CONFIRMING direction of the proof
  /// has been read and now waits for its ordering fence
  /// ([`seal_staged_adoptions`](Self::seal_staged_adoptions)); the refuting
  /// directions never stage at all, because failing conservatively needs no
  /// fence.
  ///
  /// Why the wait. The confirm inspects the dark window's END state, and an
  /// end-state inspection certifies an interval only if every record of that
  /// interval which could refute it was ingested first. The listing's own
  /// trigger does not guarantee that: it completes on the blocking pool and is
  /// reported on the op channel, which the driver polls ahead of the source
  /// lane, so a `MoveSelf` that the kernel committed BEFORE the listing could
  /// still be unread when the listing's verdict runs. Waiting for a reader
  /// queue cut requested after the listing closes exactly that gap — the cut
  /// forwards everything the kernel held onto the source lane ahead of its own
  /// reply, so by the time the seal runs the refuting record has already spent
  /// this marker through [`on_move_self`](Self::on_move_self).
  ///
  /// Scope-major so the fence's two questions — does this scope owe a seal, and
  /// which of its markers does an answered cut reach — are one `O(log n)` range
  /// over a range of one or two entries.
  ///
  /// Mirrors nothing: it is a strict subset of `pending_adoptions`, maintained
  /// by [`stage_adoption`](Self::stage_adoption) and cleared by the single
  /// release funnel, so a marker cannot leave the map while an entry for it
  /// survives here (asserted by the test invariant checker).
  staged_adoptions: BTreeMap<(ScopeId, WatchId), u64>,
  /// Monotone staging counter — the order a marker's confirming listing was
  /// ingested in, against which a cut's reach is compared.
  ///
  /// Global rather than per-scope, and never reset: the comparison is only ever
  /// made between a scope's own markers and a cut requested for that scope, and
  /// one counter shared by every scope is as valid an order for each of them as
  /// a private one would be — with no per-scope entry to be born, reset, or
  /// reclaimed. A cut earns the right to seal markers staged at or before the
  /// value read when its request was committed to, so a marker staged AFTER
  /// that instant — whose listing the cut cannot have ordered — is left
  /// standing for a successor.
  adoption_staging_seq: u64,
  /// Per-scope count of unverified adoption edges — the O(1) backing for the
  /// adoptions conjunct of [`coverage_settled`](Self::coverage_settled). An
  /// unverified edge is coverage the barrier must not certify: until the
  /// tail's first complete read confirms it (or a mismatch/erasure stands its
  /// covering signal), a change under the adopted subtree may have mutated
  /// the UNWATCHED chain — recorded by nobody — so a sync cookie dispatched
  /// over the window could resolve delivered across an undelivered
  /// transition. Mirrors [`pending_adoptions`](Self::pending_adoptions)
  /// membership exactly (asserted by the test invariant checker).
  adopting_by_scope: BTreeMap<ScopeId, usize>,
  /// Per-scope monotone count of coverage-work ACQUISITIONS — the epoch
  /// [`coverage_work_epoch`](Self::coverage_work_epoch) reports. Bumped at the
  /// one funnel through which each of the stores behind
  /// [`coverage_settled`](Self::coverage_settled) gains an entry for the
  /// scope, and never on a release, so the value moves exactly when the
  /// barrier could have gone
  /// from settled back to unsettled. Absent means 0 (no coverage work ever
  /// acquired). Entries die with the scope, like every other per-scope
  /// generation: scope ids are never reused, so a fresh registration starting
  /// at 0 cannot collide with anything stamped by a dead one.
  coverage_work_epochs: BTreeMap<ScopeId, u64>,
  /// Per-scope loss generation on a
  /// [`lossy_watch_teardown`](Capabilities::lossy_watch_teardown) profile:
  /// bumped at every scope-level [`on_overflow`](Self::on_overflow), before
  /// the recovery's re-adds are issued. Absent means generation 0 (no loss
  /// yet). The generation is what makes a binding acknowledgement a PROOF:
  /// an ACK counts only if the arm it answers was issued under the CURRENT
  /// generation — an arm in flight across a loss may certify a binding that
  /// loss killed with its teardown swallowed, so its ACK re-issues instead
  /// (see [`reprove_stamps`](Self::reprove_stamps)). Entries die with the
  /// scope (unregister / root invalidation).
  loss_gens: BTreeMap<ScopeId, u64>,
  /// The PLACEMENT clock: a monotone reading stamped on every round trip when
  /// it is issued, and on every node whose own placement changes. It is the
  /// invalidation machinery for every coordinate the driver has LOWERED to an
  /// absolute path and still holds across an I/O — see
  /// [`placement_now`](Self::placement_now) and
  /// [`placement_moved_since`](Self::placement_moved_since).
  ///
  /// Deliberately ONE clock rather than one per scope: it is never compared
  /// across nodes, only against the readings recorded on a single node's own
  /// ancestor chain, so a shared ticker costs nothing and has no per-scope
  /// lifecycle to keep in step (a per-scope counter reclaimed at scope death
  /// would reset under any stamp that outlived it).
  placement_clock: u64,
  /// The loss generation each outstanding reprove arm was issued under —
  /// keyed by the arming node, mirroring `Arming { reprove: true }`
  /// membership exactly (asserted by the test invariant checker). A stamp
  /// older than the scope's current generation marks the arm's `Ok` ACK
  /// stale: the watch action is re-issued under the current generation and
  /// the node stays `Arming`. Bounded by the transport's per-ack-cycle loss
  /// dedup — each re-issue consumes one loss edge.
  reprove_stamps: BTreeMap<WatchId, u64>,

  actions: VecDeque<Action>,
  events: VecDeque<Change>,
}

impl Monitor {
  /// Builds a monitor for a backend with the given [`Capabilities`].
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn new(capabilities: Capabilities) -> Self {
    Self {
      capabilities,
      move_window: DEFAULT_MOVE_WINDOW,
      watch_ids: Sequence::new(),
      req_ids: Sequence::new(),
      change_ids: Sequence::new(),
      arm_attempts: Sequence::new(),
      nodes: BTreeMap::new(),
      child_index: BTreeMap::new(),
      roots: BTreeMap::new(),
      scope_epochs: BTreeMap::new(),
      scope_interests: BTreeMap::new(),
      scope_profiles: BTreeMap::new(),
      rearm_pending: BTreeMap::new(),
      pending_enumerate: BTreeMap::new(),
      pending_stat: BTreeMap::new(),
      stat_slots: BTreeMap::new(),
      stat_losses: BTreeMap::new(),
      owed_descents: BTreeMap::new(),
      pending_moves: BTreeMap::new(),
      held_sources: BTreeSet::new(),
      dirtied_holds: BTreeSet::new(),
      bridge: BTreeMap::new(),
      deficits: BTreeMap::new(),
      held_by_scope: BTreeMap::new(),
      latent_cold: BTreeMap::new(),
      pending_adoptions: BTreeMap::new(),
      staged_adoptions: BTreeMap::new(),
      adoption_staging_seq: 0,
      adopting_by_scope: BTreeMap::new(),
      coverage_work_epochs: BTreeMap::new(),
      loss_gens: BTreeMap::new(),
      placement_clock: 0,
      reprove_stamps: BTreeMap::new(),
      actions: VecDeque::new(),
      events: VecDeque::new(),
    }
  }

  /// This monitor's static capability profile.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn capabilities(&self) -> Capabilities {
    self.capabilities
  }

  /// The move-pairing window in effect.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn move_window(&self) -> Duration {
    self.move_window
  }

  /// Sets the move-pairing window.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn set_move_window(&mut self, window: Duration) -> &mut Self {
    self.move_window = window;
    self
  }

  /// Whether the core descends per-directory under the CONSTRUCTOR-DEFAULT
  /// profile (the backend is not kernel-recursive). A scope registered with its
  /// own profile ([`register_root_with_profile`](Self::register_root_with_profile))
  /// is governed by that profile instead, per scope.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn descends(&self) -> bool {
    !self.capabilities.kernel_recursive()
  }

  /// Whether `scope`'s registered profile descends per-directory, falling back to
  /// the constructor default for a scope with no stored profile (one that was
  /// never registered, or whose changes are resolving after invalidation).
  fn scope_descends(&self, scope: ScopeId) -> bool {
    !self
      .scope_profiles
      .get(&scope)
      .copied()
      .unwrap_or(self.capabilities)
      .kernel_recursive()
  }

  /// Whether a scope-level loss on `scope` must re-prove every retained
  /// kernel binding by an acknowledged re-add: the profile descends AND its
  /// watches' teardown records can be lost with the queue
  /// ([`lossy_watch_teardown`](Capabilities::lossy_watch_teardown)).
  fn scope_reproves_bindings(&self, scope: ScopeId) -> bool {
    let profile = self
      .scope_profiles
      .get(&scope)
      .copied()
      .unwrap_or(self.capabilities);
    !profile.kernel_recursive() && profile.lossy_watch_teardown()
  }

  /// The current loss generation of `scope` (0 before any loss).
  fn loss_gen(&self, scope: ScopeId) -> u64 {
    self.loss_gens.get(&scope).copied().unwrap_or(0)
  }

  /// Whether a funnel that KEEPS a retained node of `scope` must keep it
  /// reproof-flavored: the profile re-proves bindings AND a loss is on record.
  /// At generation 0 no queue loss ever occurred, and on a
  /// [`lossy_watch_teardown`](Capabilities::lossy_watch_teardown) backend a
  /// silent binding death REQUIRES one (a teardown record is only ever lost
  /// WITH the queue, and every queue loss surfaces as a scope-level overflow
  /// that bumps the generation) — so a plain re-arm is provably sufficient
  /// there, and every reprove arm carries generation ≥ 1.
  fn scope_needs_reproof(&self, scope: ScopeId) -> bool {
    self.scope_reproves_bindings(scope) && self.loss_gen(scope) > 0
  }

  /// One coverage-heal kick at `dir` — reinstall-flavored when the scope's
  /// retained bindings need re-proof ([`scope_needs_reproof`](Self::scope_needs_reproof)),
  /// the plain enumerate re-arm otherwise. Every deficit heal routes through
  /// this, so a heal can never silently downgrade a binding proof to a read:
  /// the darkness a deficit records may have absorbed the very loss that
  /// killed the anchor's retained subtree, and the healing crawl must then
  /// re-add what it keeps, not merely re-list it.
  ///
  /// [`inherit_rearm`](Self::inherit_rearm), never
  /// [`start_rearm`](Self::start_rearm): the re-signal CLEARS the entry it kicks
  /// for, so a kick a bare re-arm REFUSES — which is what it answers for an
  /// `Arming` anchor, the state a widen's freshly-spliced root sits in until its
  /// pre-arm outcome is replayed — would retire the recorded darkness with
  /// nothing counted standing in for it, and the scope would read settled and
  /// deficit-free over an interior no crawl ever revisited. The `Arming` arm
  /// marks the post-arm read instead, so the heal is counted in every state
  /// (`start_reinstall` already is).
  fn heal_kick(&mut self, scope: ScopeId, dir: WatchId) {
    if self.scope_needs_reproof(scope) {
      self.start_reinstall(dir);
    } else {
      let _ = self.inherit_rearm(dir);
    }
  }

  /// Advances `scope`'s loss generation — called at each scope-level loss on
  /// a binding-re-proving profile, BEFORE the recovery's re-adds are issued,
  /// so every arm already in flight becomes stale (its install may predate
  /// this loss) while the recovery's own arms stamp current.
  fn bump_loss_gen(&mut self, scope: ScopeId) {
    *self.loss_gens.entry(scope).or_insert(0) += 1;
  }

  /// The current reading of the placement clock — what a round trip is STAMPED
  /// with when it is issued ([`WatchNode::placement`], [`StatSlot::placement`]).
  ///
  /// # What the stamp is for
  ///
  /// Every round trip the Monitor asks a driver for — an arm, an enumerate, a
  /// stat — is issued as an identity-relative coordinate (`(parent, name)`, or a
  /// handle) that the driver LOWERS to an absolute path before the I/O. The
  /// coordinate survives a rename; the lowered path does not. A result is
  /// evidence about the node it names only if the tree still denotes the path
  /// the driver read, and the stamp read back through
  /// [`placement_moved_since`](Self::placement_moved_since) is what decides that.
  /// A result that fails the test proves nothing and is never accepted as clean.
  fn placement_now(&self) -> u64 {
    self.placement_clock
  }

  /// Records that `watch`'s own placement just changed, advancing the clock so
  /// every round trip already in flight against it — or against anything below
  /// it — can be told apart from one issued afterwards.
  ///
  /// # The three funnels, and why that set is complete
  ///
  /// The path a coordinate lowers to is `driver_root(scope) ⊕ location_of(w)`,
  /// where `location_of` walks the node's `(parent, name)` links to the root.
  /// A lowered path therefore stops describing its node exactly when one of
  /// three things happens, and each has one funnel:
  ///
  /// - the OBJECT leaves its slot while the tree still reconstructs the old path
  ///   — [`detach_child`](Self::detach_child), the one detach funnel every
  ///   watched-directory move source passes through. The reconstruction is
  ///   knowingly stale for the whole hold, so this is the edge at which every
  ///   coordinate under the source went bad, descendants included;
  /// - a LINK is re-keyed — [`reparent`](Self::reparent) under
  ///   [`Reparent::Moved`], which is what makes a coordinate issued DURING the
  ///   hold (a cascade into a held subtree lowers at the pre-move path) stale
  ///   once the destination is known. A widen splice re-keys under
  ///   [`Reparent::Rerooted`] and deliberately records nothing: the new chain
  ///   exactly compensates the new root, so every absolute path is preserved and
  ///   no lowered coordinate went stale;
  /// - the scope's ROOT is replaced — [`rebind_root`](Self::rebind_root), where
  ///   the driver's root bytes change under every node at once. The rebind
  ///   settles its own tree (children dropped, root arm adopted, root read
  ///   dropped), but an outstanding stat for a root slot outlives all of that
  ///   and would otherwise settle the new world with the old world's answer.
  ///
  /// Node BIRTH and node DEATH move no surviving node's path, so neither
  /// records anything: a newborn is born [`NEVER_MOVED`] (a birth reading taken
  /// off the clock would postdate every older request and invalidate the ones a
  /// path-preserving splice later routes through it), and a corpse's results are
  /// already dropped by the "does this node still name this request" checks.
  ///
  /// This is the ONE writer of [`WatchNode::moved_at`], which is what makes the
  /// funnel list above exhaustive rather than aspirational.
  fn moved_placement(&mut self, watch: WatchId) {
    self.placement_clock += 1;
    let now = self.placement_clock;
    if let Some(node) = self.nodes.get_mut(&watch) {
      node.moved_at = now;
    }
  }

  /// Whether the absolute path a coordinate anchored at `watch` was lowered to
  /// at clock reading `stamp` may since have stopped describing it: true iff any
  /// node on `watch`'s CURRENT ancestor chain (itself included) has moved since.
  ///
  /// # Why the chain, and not one counter per scope
  ///
  /// A per-scope generation would answer this in O(1), and it was the obvious
  /// shape — but it says "something in this scope moved", not "this path moved",
  /// so one rename would invalidate every round trip in flight anywhere in the
  /// scope. That is not a rounding error: during a crawl, dozens to hundreds of
  /// reads are outstanding at once, each would take a spurious `Rescan` and burn
  /// one of its [`REARM_MAX_RETRIES`] retries, and a third concurrent rename
  /// would escalate the whole crawl into interior deficits. Walking the chain
  /// instead is exact — a rename invalidates precisely the coordinates whose
  /// path it changed — and it keeps the cost where it belongs: recording a move
  /// stays O(1) (no subtree is ever walked), and the O(depth) walk is paid once
  /// per completed round trip, on the same order as the `location_of` this
  /// result is about to reconstruct anyway.
  ///
  /// A detached-and-held node keeps its `parent` link, so the walk still reaches
  /// the source that moved and the root above it.
  fn placement_moved_since(&self, watch: WatchId, stamp: u64) -> bool {
    let mut cursor = Some(watch);
    // Bounded exactly as [`location_of`](Self::location_of) is, and for the same
    // reason: this walks the very chain that reconstruction walks, so a tree the
    // reparent guards could not keep acyclic must not spin here either. Falling
    // out of the bound answers "not moved" — a re-issue loop over a corrupt tree
    // would be a worse failure than trusting one result in it, and the invariant
    // checker fails loudly on such a tree long before this could matter.
    for _ in 0..self.nodes.len() {
      let Some(id) = cursor else {
        return false;
      };
      let Some(node) = self.nodes.get(&id) else {
        return false;
      };
      if node.moved_at > stamp {
        return true;
      }
      cursor = node.parent;
    }
    debug_assert!(cursor.is_none(), "a placement walk reaches a root");
    false
  }

  /// Asks BOTH clauses of the lowered-path trust test for a round trip anchored
  /// at `watch` and stamped at `stamp` (see [`Lowering`]), and books whatever
  /// the answer obliges.
  ///
  /// Taking `&mut self` is the point: a coordinate that lowers inside a hold
  /// owes that hold's pairing a re-scan and a re-arm of the destination, and
  /// that debt is part of learning the answer rather than a second step a site
  /// can forget. Every completion that learns it was held has, by construction,
  /// recorded it — which is what makes "held activity defers its recovery to the
  /// pairing" an invariant instead of a convention repeated per round trip.
  fn fence_lowering(&mut self, watch: WatchId, stamp: u64) -> Lowering {
    let held = self.in_held_subtree(watch);
    if let Some(source) = held {
      self.book_hold(source);
    }
    Lowering {
      held,
      moved: self.placement_moved_since(watch, stamp),
    }
  }

  /// Records that this hold suppressed something at its vacated pre-move path, so
  /// its pairing owes the destination a `Rescan` and a re-arm rather than the
  /// silent O(1) carry-over.
  fn book_hold(&mut self, source: WatchId) {
    self.dirtied_holds.insert(source);
  }

  /// Whether a watch handle is currently registered (live or pending).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn is_watched(&self, id: WatchId) -> bool {
    self.nodes.contains_key(&id)
  }

  /// The disjoint root a watch belongs to, in O(walk) — present for any
  /// registered watch. This is the attribution the design keeps O(1) per record
  /// (every record carries its [`WatchId`]).
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn scope_of(&self, id: WatchId) -> Option<ScopeId> {
    self.nodes.get(&id).map(|node| node.scope)
  }

  /// Registers a new disjoint watched root for `scope`, minting its handle and
  /// queuing the [`Action::Watch`] that installs it.
  ///
  /// This is the bootstrap input — the layer above guarantees roots are
  /// disjoint. The returned [`WatchId`] is the handle the driver will see in the
  /// queued action and must report back through
  /// [`on_watch_result`](Self::on_watch_result).
  ///
  /// `mask` is the DELIVERY interest: which change kinds the consumer receives.
  /// The watch sent to the backend subscribes to a superset — the structural
  /// kinds (create/remove/move, on directories) the core's own watch tree needs —
  /// and emission narrows delivery back to `mask`. `Rescan` is never filtered.
  ///
  /// Answers `None` for exactly one reason — `scope` already has a registered
  /// root — decided before the first mutation. The whole refusal contract lives
  /// on [`register_root_with_profile`](Self::register_root_with_profile), which
  /// holds every line of the registration this delegates to.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn register_root(&mut self, scope: ScopeId, mask: Interest) -> Option<WatchId> {
    self.register_root_with_profile(scope, mask, self.capabilities)
  }

  /// Registers a new disjoint watched root governed by its OWN capability
  /// profile, overriding the constructor default for this scope only.
  ///
  /// This is how one Monitor hosts mixed backends: a driver selecting per root
  /// (a kernel-recursive fanotify mark on one filesystem, per-directory inotify
  /// on another) registers each root with the profile its backend satisfies.
  /// Everything else matches [`register_root`](Self::register_root).
  ///
  /// # Refusal
  ///
  /// Answers `None` for exactly ONE reason: `scope` already has a registered
  /// root. The refusal is decided strictly BEFORE the first mutation — no handle
  /// minted, no arm attempt consumed, no interest or profile stored, no counter
  /// bumped, no action queued — so a refused registration leaves the Monitor
  /// bit-identical and the caller free to unregister the live root and retry.
  ///
  /// It is a refusal rather than an overwrite because `roots.insert` would
  /// ORPHAN the incumbent root: a parentless node reachable by nothing, sharing
  /// every scope-keyed counter and pending move half with the surviving world,
  /// reconstructing its subtree's locations against the WRONG root — and, worst,
  /// able to un-register the LIVE root, since `drop_subtree` removes
  /// `roots[scope]` for any parentless node it walks. The scope's whole tree
  /// would then stand with no registered root and no signal at all. [`ScopeId`]
  /// is caller-minted, so a duplicate is reachable from this crate's public API
  /// rather than only from a Monitor bug.
  ///
  /// Liveness is judged by the registered ROOT alone, and deliberately not by
  /// the scope's stored interest or profile: those outlive a root teardown that
  /// was not an [`unregister_root`](Self::unregister_root) — an unmount-style
  /// `Ignored` drops the root and leaves them — so re-registering such a scope
  /// is the legitimate recovery path, not a duplicate. That recovery is not yet
  /// free of hazard: `invalidate_root` removes the dead incarnation's
  /// coverage-work epoch along with its root, so the replacement incarnation's
  /// [`coverage_work_epoch`](Self::coverage_work_epoch) restarts from zero, and
  /// a stamp an in-flight proof took against the retired incarnation can
  /// compare equal against the replacement's early epoch instead of signaling
  /// the death in between — tracked as #88, not fixed here.
  ///
  /// The answer is an [`Option`] and not a typed error because a single refusal
  /// reason carries no information the absence does not, and because it matches
  /// [`widen_root`](Self::widen_root)'s refuse-before-mutation idiom in this same
  /// module. **A second refusal reason is the tipping point to a `Result`** —
  /// recorded here so the next author does not have to rediscover it.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn register_root_with_profile(
    &mut self,
    scope: ScopeId,
    mask: Interest,
    caps: Capabilities,
  ) -> Option<WatchId> {
    // The whole guard, and it must stay exactly this probe: the scope's other
    // books survive a non-`unregister_root` teardown by design, so reading them
    // would refuse the legitimate re-registration a root death leaves behind.
    if self.roots.contains_key(&scope) {
      return None;
    }
    let id = WatchId::new(self.watch_ids.mint());
    let attempt = self.next_arm_attempt();
    let placement = self.placement_now();
    // The scope's books come FIRST: the birth below marks this scope's bridge
    // window, and every bridge setter gates on `scope_descends`, which reads the
    // profile stored here. Registering the profile after the birth would let a
    // KR root take the constructor default's answer and mint a bridge entry no
    // KR scope may hold.
    self.scope_interests.insert(scope, mask);
    self.scope_profiles.insert(scope, caps);
    // The root is born RE-ARM-FLAVORED, which is the whole suppression: its
    // post-arm read is a re-arm read, so the bootstrap crawl announces no
    // `Created` for ground that merely pre-existed the registration — the
    // contract says registration reports no inventory. Suppression is enabled at
    // THIS birth site and nowhere else: `widen_root`'s insert and
    // `install_child`'s stay cold, so a widen's convergence `Created`s and a
    // record-driven discovery are untouched.
    //
    // The crawl is consequently COUNTED (`insert_node` books it against
    // `rearm_pending`), which is the honest reading: a cover fence opened right
    // after the grant sees coverage still moving and resolves lossy, exactly as
    // it would inside any other re-arm window.
    self.insert_node(
      id,
      WatchNode {
        parent: None,
        name: None,
        scope,
        is_dir: true,
        attempt,
        placement,
        moved_at: NEVER_MOVED,
        identity: None,
        state: NodeState::Arming {
          rearm: true,
          reprove: false,
        },
        children: BTreeSet::new(),
      },
    );
    self.roots.insert(scope, id);
    // …and the window is MARKED, so the suppression cannot be a silent one. The
    // arm-before-readdir invariant is per-DIRECTORY, so an entry created in a
    // deep pre-existing directory between the grant and that directory's own arm
    // has no kernel record and is announced by no suppressed read. The mark is
    // what makes the crawl's first fresh descendant install stand the window's
    // loss half, so the whole gap closes under one `Rescan` at coverage settle.
    self.bridge_bootstrap(scope);
    self.queue_watch(
      id,
      crate::action::WatchTarget::Root(scope),
      Self::coverage_mask(mask),
    );
    Some(id)
  }

  /// Replaces the capability profile of an already-registered root — the narrow
  /// window a driver uses when a per-root backend is chosen only once its source
  /// has spawned (`Backend::Auto`: register provisionally, then adopt the
  /// probed backend's profile before the root's watch-result is fed).
  ///
  /// Sound only while the root is still bootstrapping: its node has no children
  /// and no record has been ingested, so `caps` governs only decisions still to
  /// come (the post-arm enumerate, every later descent gate). A no-op for an
  /// unregistered scope.
  ///
  /// The registration's bridge window is re-established under the adopted
  /// profile, in both directions. Every bridge setter gates on whether the
  /// profile DESCENDS, so a window minted under a provisional profile is
  /// bookkeeping the adopted one may not simply inherit:
  /// a root that turns out KERNEL-RECURSIVE holds no bridge window at all (its
  /// stream is its coverage; it queues no read for the mark to fire at), while
  /// one that turns out DESCENDING must gain the bootstrap mark its registration
  /// could not set — without it the root's suppressed post-arm crawl would run
  /// with no loss half, which is the silent under-delivery the mark exists to
  /// prevent.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn reprofile_root(&mut self, scope: ScopeId, caps: Capabilities) {
    if !self.roots.contains_key(&scope) {
      return;
    }
    self.scope_profiles.insert(scope, caps);
    if !self.scope_descends(scope) {
      self.bridge.remove(&scope);
      return;
    }
    self.bridge_bootstrap(scope);
    // The root's own birth flavour is unconditional (a provisional KR profile
    // still births re-arm-flavored), so the window's counted half is re-stated
    // here for the case the birth's own setter declined to record it. The exact
    // shape the two state funnels recognize as a suppressed fresh install.
    if matches!(
      self
        .roots
        .get(&scope)
        .and_then(|root| self.nodes.get(root))
        .map(|node| node.state),
      Some(NodeState::Arming {
        rearm: true,
        reprove: false
      })
    ) {
      self.bridge_fresh_rearm(scope);
    }
  }

  /// The mask actually installed on a watch: the consumer's requested interest augmented
  /// with the structural kinds the core cannot function without. Discovery and coverage
  /// maintenance need create/remove/move records — including for directory targets — no
  /// matter what the consumer asked to be DELIVERED; a `Modified`-only subscription
  /// forwarded verbatim would starve the tree of the records that find new directories.
  /// Delivery is narrowed back to the requested interest in [`emit`](Self::emit).
  fn coverage_mask(mask: Interest) -> Interest {
    mask.with_created().with_removed().with_moved().with_ondir()
  }

  /// The delivery interest `scope` was registered with. Falls back to everything for a
  /// scope with no stored interest (e.g. a change emitted while a move half of an
  /// unregistered scope resolves) — over-delivery is the safe direction.
  fn scope_interest(&self, scope: ScopeId) -> Interest {
    self
      .scope_interests
      .get(&scope)
      .copied()
      .unwrap_or_else(Interest::all)
  }

  /// The `ondir` delivery modifier: whether a change whose target is a directory
  /// (`is_dir == Some(true)`) may be delivered to `scope`. An unknown target class
  /// delivers — over-delivery, the direction the [`Interest`] contract already allows.
  fn ondir_allows(&self, scope: ScopeId, is_dir: Option<bool>) -> bool {
    is_dir != Some(true) || self.scope_interest(scope).ondir()
  }

  /// Unregisters a watched root and its whole subtree, queuing an
  /// [`Action::Unwatch`] for every live node removed.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn unregister_root(&mut self, scope: ScopeId) {
    if let Some(root) = self.roots.remove(&scope) {
      self.drop_subtree(root, DeficitDischarge::Teardown);
      // Whole-scope teardown: no destination in this scope can ever validly arrive,
      // so its pending move halves can never pair — purge them all (invariant b).
      // A *narrow* subtree drop does NOT purge (the `MovedTo` may still arrive at a
      // surviving destination in the scope); the `handle_timeout` liveness guard
      // suppresses a stale `Removed` for a half whose source parent was dropped.
      self.purge_scope_pending_moves(scope);
      self.scope_interests.remove(&scope);
      self.scope_profiles.remove(&scope);
      // Terminal machinery owns coverage from here: the bridge window and the
      // deficit book die with the scope (per-node drops already emptied the
      // book's fine entries; this also reclaims a collapsed marker), and so do
      // its loss and coverage-work generations (scope ids are never reused, so
      // neither can be confused with a later scope's).
      self.bridge.remove(&scope);
      self.deficits.remove(&scope);
      self.loss_gens.remove(&scope);
      self.coverage_work_epochs.remove(&scope);
    }
    self.settle_bridges();
  }

  /// Drops the watch subtree rooted at a **non-root** per-directory node `watch`,
  /// queuing an [`Action::Unwatch`] for every live node removed — the in-place prune
  /// that reclaims over-broad kernel coverage a descending backend armed under a
  /// wide root but that no surviving consumer still needs (shrink-in-place).
  ///
  /// This is the same **narrow subtree drop** the Monitor already performs when a
  /// watched directory is deleted or replaced (`drop_subtree`),
  /// exposed for the driver to trigger from an out-of-band coverage-reclaim request
  /// rather than from an observed filesystem transition: it keeps the node map, the
  /// child index, the adjacency sets, held-source state, and outstanding enumerate
  /// requests all in lockstep, and it deliberately leaves pending move halves
  /// **pairable** (a `MovedTo` may still arrive at a surviving destination in the
  /// scope — exactly as a delete-driven narrow drop does). It never emits a `Rescan`:
  /// the caller prunes only coverage no consumer is subscribed under, so nothing is
  /// owed a re-enumeration.
  ///
  /// A **no-op** (returning `false`) when `watch` is unknown or is a **scope root** —
  /// a root is torn down only by [`unregister_root`](Self::unregister_root), never by
  /// a subtree prune, so pruning can never collapse a scope. Returns `true` iff it
  /// dropped a live subtree.
  ///
  /// A [`kernel_recursive`](Capabilities::kernel_recursive) scope has no descended
  /// per-directory children — only its root node — so the driver never finds a
  /// non-root node to pass here, and shrink is naturally a no-op for it.
  pub fn drop_watch_subtree(&mut self, watch: WatchId) -> bool {
    let dropped = match self.nodes.get(&watch) {
      // A root (no parent) is never pruned in place; an unknown watch is already gone.
      Some(node) if node.parent.is_some() => {
        self.drop_subtree(watch, DeficitDischarge::UnsubscribedPrune);
        true
      }
      _ => false,
    };
    self.settle_bridges();
    dropped
  }

  /// Re-arms the live per-directory watch subtree rooted at `watch` — the in-place **grow**
  /// that restores kernel coverage of a subtree an earlier [`drop_watch_subtree`](Self::drop_watch_subtree)
  /// pruned but that a survivor now needs again (the bidirectional dual of that shrink prune,
  /// the set-cover reconcile).
  ///
  /// It reuses the exact overflow re-arm machinery (`start_rearm` →
  /// `rearm_enumerate`): a complete re-arm read installs a fresh
  /// watch for every present child directory currently lacking one — including one a prior
  /// prune removed — and cascades the re-arm into it recursively, so the subtree rebuilds all
  /// the way down. It emits **no** `Created` (a re-arm is coverage maintenance, not discovery)
  /// and, on a complete read, **no** `Rescan`; an unreadable read stands a `Rescan` and
  /// bounded-retries, exactly as an overflow re-arm does. The driver re-arms the deepest
  /// still-watched ANCESTOR of a now-retained prefix, so the recursive re-arm reaches and
  /// re-installs every previously-pruned directory between that ancestor and the leaf.
  ///
  /// A **no-op** (returning [`RearmKickoff::Refused`]) when `watch` is unknown/dead or its
  /// scope is [`kernel_recursive`](Capabilities::kernel_recursive): a whole-subtree mark has
  /// no per-directory children that could have been pruned, so there is nothing to re-arm
  /// (its coverage never shrank). Otherwise reports how the obligation was recorded:
  ///
  /// - [`Started`](RearmKickoff::Started) — the re-arm entered a state
  ///   [`rearm_settled`](Self::rearm_settled) counts (a fresh re-arm read, a dirtied
  ///   in-flight re-arm read, or a pending arm marked to continue re-arming), so the
  ///   scope reads unsettled until the work quiesces.
  /// - [`Coalesced`](RearmKickoff::Coalesced) — the obligation was folded into an
  ///   in-flight **cold** read the settle counter deliberately does not count (cold
  ///   discovery must never hold a fence). The obligation is not lost — the dirtied
  ///   read's completion always escalates (a covering `Rescan` plus a counted re-arm
  ///   retry) — but until that completion the scope can read settled while the
  ///   obligation is latent. **A settle fence built on
  ///   [`rearm_settled`](Self::rearm_settled) must therefore treat a `Coalesced`
  ///   kickoff as lossy from birth**: resolve it degraded, matching the covering
  ///   `Rescan` its completion is guaranteed to emit.
  pub fn rearm_watch_subtree(&mut self, watch: WatchId) -> RearmKickoff {
    let Some(scope) = self.scope_of(watch) else {
      return RearmKickoff::Refused;
    };
    if !self.scope_descends(scope) {
      return RearmKickoff::Refused;
    }
    // The grow-hijack conversion: a COLD-arming target (a discovery racing
    // this grow) is about to be converted re-arm-flavored, suppressing the
    // `Created`s its post-arm read would have announced — in a window that may
    // otherwise be clean. Stand the covering `Rescan` at the conversion site
    // so the window's closing `Rescan` (the conversion sets `fresh_rearm`)
    // has its loss half. Deliberately here and not in `inherit_rearm`:
    // install-then-convert is the normal crawl sequence, and crawl-internal
    // conversions already sit inside `saw_rescan` windows — emitting per
    // gap-directory would spam one `Rescan` each.
    if matches!(
      self.nodes.get(&watch).map(|node| node.state),
      Some(NodeState::Arming { rearm: false, .. })
    ) {
      self.emit_rescan(scope, self.location_of(watch));
    }
    let kick = self.inherit_rearm(watch);
    self.settle_bridges();
    kick
  }

  /// Rebinds `scope`'s root to a NEW transport in place — the descending
  /// half of a root replace. The root node survives with its `WatchId`,
  /// scope, and interest; everything else is old-world state that died with
  /// the retired stream and is dropped here:
  ///
  /// - Every descended child subtree is dropped (their kernel watches lived
  ///   on the old transport; the queued `Unwatch`s are dead-but-harmless on
  ///   the new one — watch ids are never reused, so a stale disarm can name
  ///   nothing live).
  /// - Pending move halves are purged whole-scope, exactly as
  ///   [`unregister_root`](Self::unregister_root) does: no old-world
  ///   destination can validly arrive on the new transport.
  /// - The root resets to a pending arm that CONTINUES a re-arm
  ///   (a counted obligation, so [`rearm_settled`](Self::rearm_settled)
  ///   holds `false` until the rebuild quiesces): the caller has already
  ///   armed the new root on the new transport and replays that outcome via
  ///   [`on_watch_result`](Self::on_watch_result), whose post-arm enumerate
  ///   rebuilds coverage re-arm-flavored — no `Created` spam, the caller's
  ///   covering `Rescan` already stands for the world change.
  ///
  /// Returns the surviving root `WatchId` together with the [`ArmAttempt`] its
  /// replayed outcome must be reported under, or `None` for an unknown scope or
  /// a [`kernel_recursive`](Capabilities::kernel_recursive) one (a KR swap
  /// replaces the stream whole; there is no per-directory book to rebind).
  pub fn rebind_root(&mut self, scope: ScopeId) -> Option<(WatchId, ArmAttempt)> {
    let root = *self.roots.get(&scope)?;
    if !self.scope_descends(scope) {
      return None;
    }
    // The driver's root BYTES change under every node of the scope at once, so
    // every coordinate lowered against the old world is addressed at a path this
    // world does not have. Ahead of everything below, so the root arm this
    // method adopts stamps the new world rather than the one it replaced. The
    // tree's own settlement (children dropped, root read dropped, root arm
    // superseded) leaves exactly one survivor this reaches instead: an
    // outstanding stat for a ROOT slot, whose answer would otherwise settle the
    // new root's slot with the old root's path.
    self.moved_placement(root);
    let children: std::vec::Vec<WatchId> = self
      .nodes
      .get(&root)
      .map(|node| node.children.iter().copied().collect())
      .unwrap_or_default();
    for child in children {
      self.drop_subtree(child, DeficitDischarge::Teardown);
    }
    self.purge_scope_pending_moves(scope);
    // The old world's standing deficits die with its transport: the commit's
    // covering `Rescan` plus the full re-arm rebuild re-attempt everything,
    // and a still-broken site re-records through its own failure edge. The
    // BRIDGE entry deliberately survives — the commit `Rescan` the caller
    // emits right after re-sets `saw_rescan` anyway, and the window's
    // `fresh_rearm` half is re-established by the rebuild: the root reset
    // below sets it when the root was not already re-arm-flavored, while a
    // root caught mid-reproof gets it from the rebuild's fresh installs or
    // its own `Installed` replay acknowledgement instead. The flush cannot
    // fire mid-rebind because the method ends with the root counted.
    self.deficits.remove(&scope);
    // An old-world root read that will never be reported must not leak its
    // request slot (`drop_subtree` does this for children; the root survives).
    if let Some(NodeState::Enumerating { req, .. }) = self.nodes.get(&root).map(|node| node.state) {
      self.pending_enumerate.remove(&req);
      self.latent_cold.remove(&req);
    }
    self.set_state(
      root,
      NodeState::Arming {
        rearm: true,
        reprove: false,
      },
    );
    // The reset arm is answered by the caller's NEW-transport replay — a
    // fresh proof by construction, not a reprove — so any stamp an in-flight
    // OLD-transport re-add left behind must not judge it.
    self.reprove_stamps.remove(&root);
    if let Some(node) = self.nodes.get_mut(&root) {
      node.identity = None;
    }
    // A depth-one widen keys its adoption marker on the ROOT itself, which this
    // rebind keeps — purge it, or a stale marker would fire on the rebound
    // root's next cold read. Chain-keyed markers died with the children above,
    // through the drop walk's own release.
    //
    // The ADOPTED CHILD is already gone here, and by construction rather than
    // by argument: whatever depth the widen had, the marker names a WATCH of
    // this scope other than the root (a widen adopts the old root under a
    // freshly minted one), every such node is a descendant of the root wherever
    // a later rename put it, and the loop above dropped every one of the root's
    // children whole — the adjacency set it walks holds detached-and-held
    // sources too. The disposal below asserts exactly that, of the adopted
    // watch itself rather than of its old slot, so a child that outlived the
    // drop — or merely moved out of the slot — is a loud failure rather than a
    // comment that stopped being true. The rebind's own commit `Rescan` (the
    // caller emits it) owns coverage for the erased world.
    // The evidence is discarded, never the disposal: this release destroys
    // nothing (the child is already gone) and `root` is the node it is keyed at,
    // which this method's whole contract is that it SURVIVES.
    let _ = self.release_adoption_marker(root, scope, AdoptionDisposal::ChildAlreadyDropped);
    self.settle_bridges();
    // The reset arm is the driver's already-executed new-transport arm: rebind
    // it to a fresh attempt and hand the token back, so the replayed outcome
    // names THIS arm. Every outcome still in flight from the retired transport
    // names an older one and is discarded — the fence that keeps a dead world's
    // synthesized failure from invalidating the live root it never touched.
    let attempt = self.adopt_arm(root);
    Some((root, attempt))
  }

  /// Mints a fresh [`WatchId`] with NO node behind it — the handle a driver
  /// pre-arms on a LIVE transport before a same-transport widen commit
  /// ([`widen_root`](Self::widen_root)). Records arriving for the id before the
  /// commit are dropped by the unknown-watch guard (coverage of the widened
  /// ground contractually begins at the commit; the post-commit cold read
  /// converges everything the drop skipped). Ids are never reused, so an
  /// abandoned reservation burns an integer and nothing else — there is no
  /// node to unwind, which is what keeps a failed pre-arm perfectly atomic.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn reserve_watch_id(&mut self) -> WatchId {
    WatchId::new(self.watch_ids.mint())
  }

  /// Commits a same-transport WIDEN of `scope`'s root: mints `reserved` (a
  /// [`reserve_watch_id`](Self::reserve_watch_id) handle the driver has ALREADY
  /// armed on the live transport) as the scope's new root ABOVE the current
  /// one and ADOPTS the old root node under it at the name `chain` gives (the
  /// old root's location relative to the new root, which must be EXACTLY ONE
  /// segment — see the depth cap below) — a single O(1) edge splice that touches
  /// no old-subtree node, disarms nothing, purges nothing, bumps no epoch, and
  /// emits no change. That is the zero-gap half of the descending widen: every
  /// old watch keeps recording on the unchanged transport, and every delivery
  /// reconstructs through the new root at its unchanged absolute path.
  ///
  /// What changes, exhaustively: the new root is inserted (queueing NOTHING —
  /// the caller replays its pre-arm outcome under the returned attempt via
  /// [`on_watch_result`](Self::on_watch_result),
  /// whose post-arm COLD enumerate discovers the newly covered ground as
  /// `Created`s), the old root's `parent`/`name` re-key under it, its
  /// node identity becomes `old_identity` (the replaced world's root identity,
  /// REQUIRED — children carry identities, and the new root's first read
  /// re-proves the edge against this one), and `roots` re-points. Everything
  /// else — the
  /// old subtree's states and children, pending enumerates, pending move halves,
  /// held sources, the deficit book, the bridge window, the scope's epoch,
  /// interest, and profile — is deliberately untouched: the old world did not
  /// end, so nothing of it may be discharged.
  ///
  /// Nothing observes the adopted slot across this splice — the new root's
  /// records are dropped by the unknown-watch guard until the commit and its
  /// first listing lands only after the replayed arm — so a slot mutation in
  /// that window is recorded by nobody; the adoption marker minted
  /// here makes the tail's first complete read re-confirm the adopted edge
  /// POSITIVELY — the listing must name the slot as a directory whose identity
  /// EQUALS `old_identity` — and escalate loudly on anything short of that
  /// (`resolve_adoption`) rather than trust a silently stale reconstruction. A
  /// confirming listing STAGES the marker rather than releasing it, so the
  /// certifying release is taken only behind a reader queue cut requested after
  /// that listing (`seal_staged_adoptions`) — which is what makes the reading a
  /// statement about the whole window instead of about its end, for the adopted
  /// OBJECT: the mount stack over its slot is sampled by the listing rather than
  /// witnessed, so a stack raised and dropped inside the window reads as no
  /// change at all.
  /// That re-proof is the whole payment for the dark window, which is why
  /// `old_identity` is a precondition rather than a hint: a widen that cannot
  /// name the object it is adopting has nothing to re-prove, and the only
  /// honest answer to an unprovable edge is to refuse the splice (the caller
  /// falls back to a replace that rebuilds the binding from scratch), never to
  /// commit it and let the tripwire confirm on ignorance.
  ///
  /// The same demand for a real proof caps `chain` at EXACTLY ONE segment: a
  /// longer chain is refused for the identical reason an unnameable adoption is.
  /// At depth one the marker's parent IS the new root — the node whose pre-armed
  /// outcome the caller replays — the adopted edge is the only edge the splice
  /// creates, and the one listing that resolves it inspects the very slot the
  /// dark window could have mutated. Every deeper shape breaks all three of
  /// those. The splice would mint INTERMEDIATE connectors as unidentified cold
  /// nodes, so each of their edges is an adoption no marker names and no read
  /// re-proves: a connector can move out of its slot and back inside the window
  /// with nobody recording it, movement further down the chain can go entirely
  /// unobserved, and a rename of an ANCESTOR of the old root produces no
  /// `MoveSelf` for the already-watched old root, so the invalidation that pays
  /// for a moved adoption never fires. The lone tail marker then confirms an
  /// edge whose ground it never looked at. There is no honest proof to build at
  /// depth two or deeper, so the splice is declined and the caller falls back to
  /// the stream replace — which rebuilds the whole binding through a fresh spawn
  /// barrier and needs no window proof at all.
  ///
  /// Returns the new root's id (`reserved`) together with the [`ArmAttempt`]
  /// its replayed pre-arm outcome must be reported under, or `None` for an
  /// unknown scope, a
  /// [`kernel_recursive`](Capabilities::kernel_recursive) one (a KR widen has
  /// no per-directory book — the stream swap owns it), an empty `chain`, a
  /// `chain` longer than one segment, a `reserved` id that already names a node,
  /// or a `None` `old_identity`. The last two are driver bugs, refused rather
  /// than corrupting the tree; the others are shapes this splice does not serve,
  /// and a caller that can reach them screens them itself so its own fallback
  /// stays a legitimate outcome rather than a bug report. Every `None` is
  /// decided strictly BEFORE the first mutation, so a refused widen leaves the
  /// Monitor bit-identical and the caller free to fall back to the stream
  /// replace; past that point the splice is infallible by construction and any
  /// broken invariant panics loudly rather than committing a partial tree.
  pub fn widen_root(
    &mut self,
    scope: ScopeId,
    reserved: WatchId,
    chain: std::vec::Vec<Segment>,
    old_identity: Option<Identity>,
  ) -> Option<(WatchId, ArmAttempt)> {
    let old_root = *self.roots.get(&scope)?;
    if !self.scope_descends(scope) {
      return None;
    }
    // An empty chain would make old and new the same node — not a widen.
    let (last, connectors) = chain.split_last()?;
    // Depth ONE only (see the doc): a deeper chain's intermediate connector
    // edges have no proof and no invalidation, so the splice is not offered at
    // that shape at all. Refused HERE — before the new root is minted, which is
    // the first mutation this method makes — so the Monitor is bit-identical and
    // the caller's stream-replace fallback starts from an untouched tree. This
    // sits with the other shape refusals rather than with the driver-bug asserts
    // below on purpose: a caller asking for a deep widen is asking for something
    // reasonable that this splice declines to do, not misusing the API.
    if !connectors.is_empty() {
      return None;
    }
    if self.nodes.contains_key(&reserved) {
      debug_assert!(false, "a reserved widen id is never a live node");
      return None;
    }
    // The adopted object must be NAMEABLE. A root's identity has exactly one
    // source — this parameter (a root is never discovered through a listing,
    // and every other write clears it), so an absent one is absent for the
    // adopted node's whole life: the tail's re-proof would then be comparing
    // against nothing and would confirm the edge on ignorance, certifying a
    // dark-window swap the marker exists to catch. Refuse instead, with the
    // tree untouched — and carry the identity out of the `Option` here, so the
    // marker below stores what the re-proof needs rather than a maybe.
    let adopted_identity = old_identity?;
    // The new root: a plain parentless directory node, cold-arming. Born
    // through the standard funnel (non-re-arm: no counter, no bridge bit) and
    // WITHOUT a queued watch action — the driver already holds its arm outcome.
    let attempt = self.next_arm_attempt();
    let placement = self.placement_now();
    self.insert_node(
      reserved,
      WatchNode {
        parent: None,
        name: None,
        scope,
        is_dir: true,
        attempt,
        placement,
        moved_at: NEVER_MOVED,
        identity: None,
        state: NodeState::Arming {
          rearm: false,
          reprove: false,
        },
        children: BTreeSet::new(),
      },
    );
    // The connecting chain, top-down, as ordinary cold discoveries: each queues
    // its arm through the normal control path (the live port is the attached
    // port — no transport special-casing), and each cold read announces the
    // genuinely new ground as `Created` (a re-arm flavor would suppress the
    // announcements with no covering `Rescan` standing — silent loss).
    // Top-down order also lets the driver derive each child's absolute path
    // from a parent already recorded in the same drain.
    //
    // VACUOUS as of the depth-one cap above: `connectors` is empty on every path
    // that reaches here, so this loop never runs and `tail` stays `reserved` —
    // the adopted edge hangs directly off the new root, which is exactly what
    // makes the marker provable. Kept rather than deleted so the cap stays the
    // single place that decides the supported depth: the splice mechanics for a
    // longer chain are still correct in themselves, and the reason a deep widen
    // is refused is the unprovable WINDOW, not a hole here.
    let mut tail = reserved;
    for seg in connectors {
      let _ = self.install_child(tail, scope, seg.clone(), true, None);
      // Infallible by construction: the parent was minted THIS call with an
      // empty slot, so `install_child` cannot have skipped. Every refusal this
      // method can report (`None`) happens strictly BEFORE the first mutation;
      // past that point a broken invariant must be a loud panic, never a
      // silently partial splice a release build would carry forward.
      tail = self
        .child_watch(tail, seg)
        .expect("a fresh chain slot always installs");
    }
    // adopt_child: re-key the old root under the tail. `reparent` is the
    // existing O(1) move splice; its stale-destination and inheritance branches
    // are vacuous here (the tail's slot is freshly minted and empty), and the
    // acyclic precondition holds trivially (the tail is not in the old
    // subtree). The old root's state and children ride along untouched.
    // Infallible by the same argument as the chain mints: both endpoints were
    // fetched or minted this call — loud beats partial.
    debug_assert!(self.can_reparent(old_root, tail));
    debug_assert!(!self.child_index.contains_key(&(tail, last.clone())));
    assert!(
      self.reparent(old_root, tail, last.clone(), Reparent::Rerooted),
      "both splice endpoints are live by construction"
    );
    if let Some(node) = self.nodes.get_mut(&old_root) {
      node.identity = Some(adopted_identity);
    }
    self.roots.insert(scope, reserved);
    // The dark-window tripwire: the tail's first complete read must
    // re-confirm the adopted edge (see the type doc and `resolve_adoption`).
    // The tail IS `reserved` under the depth-one cap, so the read that pays for
    // the window is the new root's own post-replay cold read.
    // It records WHICH watch was adopted and the identity naming it, not just
    // the slot: from this instant the tail is unarmed, so a rename can move
    // the object off `last` with nobody recording it, and a marker that named
    // only the slot would let the proof be paid by whoever turned up there.
    // The marker also holds [`coverage_settled`](Self::coverage_settled) down
    // from this instant, so a sync cookie cannot dispatch over the unverified
    // window — the tail's arm and read are deliberately cold and would
    // otherwise leave the barrier nothing to wait on.
    self.record_adoption_marker(tail, last.clone(), old_root, adopted_identity, scope);
    self.settle_bridges();
    Some((reserved, attempt))
  }

  /// Whether `scope` has no outstanding re-arm work: no node of the scope is
  /// pending an arm that continues a re-arm or holds an in-flight re-arm read.
  /// O(1).
  ///
  /// This is the coverage-reconcile settle predicate: a driver that triggered
  /// re-arm work for `scope` — a [`rearm_watch_subtree`](Self::rearm_watch_subtree)
  /// grow, an [`on_overflow`](Self::on_overflow) recovery — polls this after
  /// feeding results back to learn when that work has quiesced. LIVE-CHURN cold
  /// discovery never holds it down: a discovered directory's arm and enumerate
  /// run in non-re-arm states by construction, so consumer churn inside a settled
  /// scope cannot starve a fence built on this predicate. A REGISTRATION does
  /// hold it down, and deliberately: its crawl is re-arm-flavored (the inventory
  /// suppression), so it is counted from the grant until coverage settles, and a
  /// cover fence opened right after the grant reads lossy — the honest outcome,
  /// since it instructs exactly the crawl the contract already ordered. Every
  /// counted obligation is bounded — an unreadable re-arm read retries at most
  /// `REARM_MAX_RETRIES` times before its [`Rescan`](ChangeKind::Rescan) stands —
  /// so each terminal is armed-live or dropped-with-a-standing-`Rescan`, and a
  /// pending scope settles in bounded steps. A scope with no re-arm-flavored
  /// nodes — unknown, torn down, or simply idle — is trivially settled (`true`).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn rearm_settled(&self, scope: ScopeId) -> bool {
    !self.rearm_pending.contains_key(&scope)
  }

  /// Whether `scope` is settled for BARRIER purposes: whether the monitor
  /// still holds any transition of `scope` it has not put on the wire. There
  /// are six ways to hold one, and this is their conjunction — no counted
  /// re-arm work ([`rearm_settled`](Self::rearm_settled)); no
  /// detached-and-held move source (whose suppressed records' covering
  /// `Rescan` has not been emitted yet — it is owed only at the hold's pairing
  /// or timeout resolution); no in-flight cold read carrying a coalesced
  /// re-arm obligation (the one latency `rearm_settled` deliberately does not
  /// count; its completion escalates into a covering `Rescan` plus a counted
  /// retry); no UNVERIFIED same-transport adoption edge (a widen's connecting
  /// chain is deliberately cold — uncounted by the re-arm predicate — yet
  /// until the tail's first complete read verifies the adopted edge, a chain
  /// mutation from the commit's dark window may still be both unrecorded and
  /// unsignalled; the marker releases only at positive verification or
  /// together with the mismatch's covering `Rescan`/re-arm/deficit); no
  /// QUARANTINED binding — a node whose kernel watch is installed at a path
  /// the subtree has left, so changes under the path it now occupies are
  /// recorded by nobody until its re-add is acknowledged; and no half-resolved
  /// rename still parked for its pairing window — a `MovedFrom` the monitor
  /// has consumed and cannot normalize until its destination arrives or the
  /// window elapses, which for an ordinary file takes no hold and so is
  /// counted by nothing else.
  ///
  /// The first five are coverage the monitor cannot yet vouch for; the sixth
  /// is a change it has already taken off the backend and not yet delivered.
  /// One predicate carries both because they falsify the same claim: a fence
  /// built on the bare re-arm predicate would settle inside any of these
  /// windows and dispatch a sync cookie that neither a covering `Rescan` nor
  /// the transition itself precedes — and a consumer may finalize state on
  /// that cookie, so a change landing behind it arrives after the state it
  /// belongs to.
  ///
  /// A kernel-recursive scope reaches none of the first five states, so its
  /// barrier rests on the parked-rename conjunct alone; an unknown or
  /// torn-down scope is trivially settled.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn coverage_settled(&self, scope: ScopeId) -> bool {
    self.rearm_settled(scope)
      && self.holds_settled(scope)
      && self.latent_settled(scope)
      && self.adoptions_settled(scope)
      && self.moves_settled(scope)
  }

  /// Whether `scope` still owes an answer to a stat that stands its settlement
  /// loss — a listing entry of unknown kind whose slot may be a directory the
  /// scope has no watch on yet, or any entry its REGISTRATION window asked
  /// about.
  ///
  /// This is a LOSS signal for a settlement, and deliberately not a sixth
  /// conjunct of [`coverage_settled`](Self::coverage_settled). The two differ in
  /// exactly the way that matters here:
  ///
  /// - As a **conjunct**, a driver that never answers — the case the deferred
  ///   descent booking is written against, and the reason the stat is uncounted
  ///   at all — would hold every barrier of the scope down forever. No vehicle
  ///   that can be a barrier's sole cover may lack a proven bounded release, and
  ///   an unanswered stat has none.
  /// - As a **loss signal**, a fence settling while the stat stands reports a
  ///   degraded window and keeps its under-claimed settle floor, which instructs
  ///   the consumer to re-enumerate — the instruction the coverage contract
  ///   already asks for. That instruction is this signal's OWN, never a second
  ///   copy of one a standing coverage deficit is holding for the same slot:
  ///   the slot need carry no such entry at all (a registration-stamped request
  ///   raises this over ground the scope already watches), and
  ///   [`resignal_coverage_deficits`](Self::resignal_coverage_deficits) clears
  ///   the entries it signals while the request stays owed. The barrier still
  ///   resolves, on time.
  ///
  /// Between the queue and the answer the scope can be genuinely uncovered there
  /// and genuinely settled: where the slot held no watch, the read that listed
  /// it reconciled nothing for it (it books darkness and asks for a kind), and
  /// the scope leaves its counted re-arm state without waiting. A consumer that
  /// certifies coverage over that window would claim a cover the slot's possible
  /// directory is outside of, and writes beneath it would be recorded by
  /// nothing. Nor does the read that found the slot necessarily stand a `Rescan`
  /// of its own — a pure grow and a record-driven cold read both stand none — so
  /// this is the window's only loss.
  ///
  /// A REGISTRATION-window request raises the signal over a slot the scope may
  /// already watch, and for the window's own reason rather than the one above:
  /// that window's crawl arms ground it announces nothing for, so a fence
  /// certifying inside it claims a cover no delivered record backs.
  ///
  /// False for a scope with no such stat outstanding, for a kernel-recursive one
  /// (which descends into nothing and so stats no slot at all), and for an
  /// unknown or torn-down one. Reading it allocates nothing.
  #[cfg_attr(not(tarpaulin), inline)]
  #[must_use]
  pub fn stat_loss_outstanding(&self, scope: ScopeId) -> bool {
    self.stat_losses.contains_key(&scope)
  }

  /// Stands the covering [`Rescan`](ChangeKind::Rescan) a settlement about to
  /// report [`stat_loss_outstanding`](Self::stat_loss_outstanding) owes its
  /// consumer, and reports whether one was stood.
  ///
  /// The cover is the SCOPE's, not the slot's, and the loss's own shape is why.
  /// The request is still owed, so nobody knows whether the slot is a directory
  /// — which is exactly why the darkness could not be covered where it sits —
  /// and a REGISTRATION-window request stands the loss over a crawl that armed
  /// ground it announced nothing for anywhere under the root, which no one
  /// slot's `Rescan` names at all. A root-covering `Rescan` is the instruction
  /// the degraded verdict already carries — re-enumerate the scope — and the
  /// same one a collapsed deficit book stands
  /// ([`resignal_coverage_deficits`](Self::resignal_coverage_deficits)).
  ///
  /// Deliberately NO heal kick, which is the one place this parts company with
  /// that re-signal. A kick acquires counted coverage work: it re-opens the
  /// scope's barrier and retires the ordering proof the settling fence is
  /// holding, so a scope whose stat never comes back would stand a cover,
  /// re-open, settle, stand another, and never answer its caller at all. Nothing
  /// here is owed to the SITE — the slot's own answer, or its parent's death,
  /// ends the loss, and this call waits for neither.
  ///
  /// Nor does it CLEAR anything. The loss is level-persistent and stands until
  /// it is discharged, so every verdict minted over it stands its own cover
  /// rather than inheriting an earlier verdict's; a repeat while the previous
  /// `Rescan` is still queued coalesces into it — that one is undelivered, so it
  /// covers this verdict too — and still reports `true`.
  ///
  /// `false` for a scope standing no such loss, for a kernel-recursive one
  /// (which stats no slot and so never stands one), and for an unknown or
  /// torn-down scope, whose consumer this can no longer instruct.
  pub fn cover_stat_loss(&mut self, scope: ScopeId) -> bool {
    if !self.stat_loss_outstanding(scope) || !self.roots.contains_key(&scope) {
      return false;
    }
    self.emit_rescan(scope, Location::new());
    self.settle_bridges();
    true
  }

  /// `scope`'s coverage-work epoch: a monotone count of how many times the
  /// scope has ACQUIRED work that [`coverage_settled`](Self::coverage_settled)
  /// counts — a re-arm obligation, a detached-and-held move source, an
  /// in-flight cold read carrying a coalesced re-arm obligation, an unverified
  /// adoption edge, or a parked rename half. Releasing such work never moves
  /// it. An unknown or torn-down scope reads the never-acquired floor, and
  /// reading it allocates nothing.
  ///
  /// This exists so an ordering proof taken over a settled scope can be BOUND
  /// to the state that made it settled, instead of to an enumeration of the
  /// edges that could unsettle it. Each conjunct is "this store holds no entry
  /// for the scope", so the barrier can only go settled → unsettled by one of
  /// them GAINING an entry, which is exactly what bumps
  /// this counter. A holder that stamped the epoch while the scope was settled
  /// and finds the same value later therefore knows the barrier never re-opened
  /// in between — whatever the conjunct was, and however many conjuncts there
  /// come to be.
  ///
  /// Its converse is what makes it usable rather than merely safe: a settled
  /// scope acquiring no work leaves the epoch fixed, so a stamp taken over a
  /// quiescent scope stays valid and the holder converges instead of chasing a
  /// moving value.
  ///
  /// The epoch is returned as an opaque [`CoverageWorkEpoch`] rather than as its
  /// count, which is what makes the check above unskippable: a holder cannot
  /// build the value this returns out of the stamp it already carries, so
  /// establishing currency means reading the monitor.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn coverage_work_epoch(&self, scope: ScopeId) -> CoverageWorkEpoch {
    CoverageWorkEpoch(self.coverage_work_epochs.get(&scope).copied().unwrap_or(0))
  }

  /// Whether `scope` has a standing terminal coverage deficit: an arm-refused
  /// slot, an exhausted-read interior, or a collapsed whole-scope marker.
  /// Such darkness is level-persistent — its opening `Rescan` does not cover
  /// changes landing while it stands — so a sync cookie dispatched over it
  /// must first
  /// [`resignal_coverage_deficits`](Self::resignal_coverage_deficits).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn has_coverage_deficit(&self, scope: ScopeId) -> bool {
    self.deficits.contains_key(&scope)
  }

  /// Re-signals every standing terminal deficit of `scope`: emits one
  /// epoch-bumped covering `Rescan` per site at the site's CURRENT location
  /// (the scope root when the book collapsed), kicks one bounded re-arm at
  /// each site's healing anchor, and optimistically clears the re-signaled
  /// entries — a still-broken site re-records itself through its own failure
  /// edge before the kicked (counted) work can settle. Most such edges stand a
  /// fresh `Rescan` as they re-record; the unclassifiable EMPTY slot stands
  /// none, its window being covered by the settlement loss its outstanding stat
  /// carries instead
  /// ([`stat_loss_outstanding`](Self::stat_loss_outstanding)). A site currently
  /// inside a held (mid-move) subtree keeps its
  /// entry and dirties the hold instead, like every other held-subtree
  /// activity: a `Rescan` there would name the stale pre-move path.
  ///
  /// Returns whether anything was re-signaled. A no-op (`false`) for a scope
  /// with no deficit, an unknown scope, or a kernel-recursive one.
  pub fn resignal_coverage_deficits(&mut self, scope: ScopeId) -> bool {
    let signaled = self.resignal_deficits(scope);
    self.settle_bridges();
    signaled
  }

  /// Whether `scope` has no detached-and-held move source. O(1).
  fn holds_settled(&self, scope: ScopeId) -> bool {
    !self.held_by_scope.contains_key(&scope)
  }

  /// Whether `scope` has no unverified same-transport adoption edge. O(1).
  fn adoptions_settled(&self, scope: ScopeId) -> bool {
    !self.adopting_by_scope.contains_key(&scope)
  }

  /// Records the widen's unverified adoption edge at its chain parent — the one
  /// insert site, paired with
  /// [`release_adoption_marker`](Self::release_adoption_marker).
  ///
  /// `adopted` and `identity` are captured HERE, at the instant the marker is
  /// stood, because that is the last instant at which the slot and the object
  /// provably agree: from the commit onward the chain is unarmed and a rename
  /// can separate them behind the monitor's back (see [`AdoptionMarker`]).
  fn record_adoption_marker(
    &mut self,
    parent: WatchId,
    name: Segment,
    adopted: WatchId,
    identity: Identity,
    scope: ScopeId,
  ) {
    let evicted = self.pending_adoptions.insert(
      parent,
      AdoptionMarker {
        name,
        adopted,
        identity,
      },
    );
    debug_assert!(evicted.is_none(), "widen tails are freshly minted");
    *self.adopting_by_scope.entry(scope).or_insert(0) += 1;
    self.acquired_coverage_work(scope);
  }

  /// Retires the ADOPTED WATCH of a released marker: the subtree goes, inside
  /// whatever cover the release already stood. The one act every retirement
  /// disposal performs, so the name and the deed cannot drift apart between
  /// them.
  ///
  /// Resolved by [`WatchId`], never by slot: a child a `MovedFrom` detached
  /// before the proof is still exactly the one that dies, and a replacement
  /// that took its vacated slot keeps its own (properly discovered) coverage. A
  /// watch already destroyed leaves nothing to do — the edge cannot outlive its
  /// object.
  ///
  /// `parent` is the marker's own key, and is passed SOLELY to be asserted —
  /// after the drop, which is where the claim has content. The containment
  /// invariant ([`pending_adoptions`](Self::pending_adoptions)) makes `adopted` a
  /// direct child of it, so a retirement reaching an ANCESTOR of `parent` is the
  /// non-local destruction every caller's continuation is written against.
  fn retire_adopted(&mut self, adopted: WatchId, parent: WatchId) {
    if self.nodes.contains_key(&adopted) {
      self.drop_subtree(adopted, DeficitDischarge::CoveringRescan);
    }
    debug_assert!(
      self.nodes.contains_key(&parent),
      "adoption retirement is subtree-local"
    );
  }

  /// Removes the adoption marker keyed at `parent` (if any), keeping the
  /// per-scope settle counter in lockstep, and DISPOSES of the child it adopted
  /// per `disposal` — the ONE removal funnel, so no path can release the
  /// barrier conjunct without going through it, and no release can go without a
  /// disposal (see [`AdoptionDisposal`] for why that is structural rather than
  /// a convention).
  ///
  /// Returns the released [`AdoptionMarker`], or `None` when no marker stood.
  /// Only [`Verdict`](AdoptionDisposal::Verdict) hands back a marker its caller
  /// must still act on; every other disposal is PERFORMED here, and its marker
  /// says nothing more than that one was standing.
  ///
  /// No caller is told anything about `parent`'s fate, because there is nothing
  /// to tell: the containment invariant
  /// ([`pending_adoptions`](Self::pending_adoptions)) makes the adopted watch a
  /// direct CHILD of `parent`, so no disposal here can reach it.
  ///
  /// Every disposal resolves the marker's own
  /// [`adopted`](AdoptionMarker::adopted) watch. None of them re-derives it
  /// from `(parent, name)`: that lookup answers "who holds the slot NOW", and
  /// the marker exists precisely because the interval since it was stood is one
  /// in which the answer can have changed without the monitor recording it — a
  /// held detach frees the slot and a replacement may take it, both with the
  /// parent link (and so the invariant) intact.
  fn release_adoption_marker(
    &mut self,
    parent: WatchId,
    scope: ScopeId,
    disposal: AdoptionDisposal,
  ) -> Option<AdoptionMarker> {
    let marker = self.pending_adoptions.remove(&parent)?;
    // A staged marker is one still standing, so its staging entry leaves with
    // it here and at no other site — which is what makes the fence's latch
    // outlive nothing: the scope stops owing a seal the instant its last marker
    // goes, whichever of the seven exits took it.
    self.staged_adoptions.remove(&(scope, parent));
    match self.adopting_by_scope.get_mut(&scope) {
      Some(count) if *count > 1 => *count -= 1,
      Some(_) => {
        self.adopting_by_scope.remove(&scope);
      }
      None => debug_assert!(false, "the adoption counter mirrors the marker map"),
    }
    match disposal {
      // The caller's own read is the disposal; the marker below is its input.
      AdoptionDisposal::Verdict => {}
      AdoptionDisposal::CountedRetirement => {
        // The cover FIRST, then the coverage it covers ends — a `Rescan` that
        // postdates the disarm instructs nobody about the interval between.
        // Counted, so the barrier this release just took its conjunct off has
        // the cover's own re-arm to rest on rather than nothing.
        self.stand_counted_cover(scope);
        // A watch already destroyed is already the disposal: the edge this
        // marker stood for has no subtree left to keep addressing at a path
        // nothing proved, and the cover above still stands for the dark window
        // it opened.
        self.retire_adopted(marker.adopted, parent);
      }
      // The containment invariant, stated at the one site that rests on it: the
      // adopted child dies with this walk BECAUSE it is still under the node the
      // walk is destroying. Read through the CHILD's parent link, which is what
      // makes it checkable mid-walk — `parent` is already out of `nodes`, while a
      // child the walk has not reached yet still names it.
      AdoptionDisposal::DiesWithTheWalk => debug_assert!(
        self
          .nodes
          .get(&marker.adopted)
          .is_none_or(|node| node.parent == Some(parent)),
        "an unproven adopted edge is immovable, so it dies with its marker's walk"
      ),
      AdoptionDisposal::ChildAlreadyDropped => debug_assert!(
        !self.nodes.contains_key(&marker.adopted),
        "a ChildAlreadyDropped release must have nothing left to dispose of"
      ),
    }
    Some(marker)
  }

  /// Stages the marker keyed at `parent`: its confirming listing has been
  /// ingested, and its release now waits for the ordering fence — the ONE site
  /// that puts a marker into [`staged_adoptions`](Self::staged_adoptions),
  /// paired with the clear inside
  /// [`release_adoption_marker`](Self::release_adoption_marker).
  ///
  /// No coverage work is acquired and no epoch moves: the marker was already
  /// holding the adoptions conjunct of
  /// [`coverage_settled`](Self::coverage_settled) down and goes on holding it,
  /// so nothing about the barrier changed and a proof taken over the scope's
  /// coverage work is still speaking for the same window.
  ///
  /// Re-staging is refused rather than re-stamped. A second confirming listing
  /// says nothing the first did not — the marker's readings are one-way while
  /// it stands — and moving the stamp forward would push the marker past the
  /// reach of a cut already out for it, buying a needless round trip for a
  /// window that never re-opened.
  fn stage_adoption(&mut self, parent: WatchId, scope: ScopeId) {
    debug_assert!(
      self.pending_adoptions.contains_key(&parent),
      "staging names a standing marker"
    );
    if self.staged_adoptions.contains_key(&(scope, parent)) {
      return;
    }
    self.adoption_staging_seq += 1;
    self
      .staged_adoptions
      .insert((scope, parent), self.adoption_staging_seq);
  }

  /// The staging generation of `scope`'s newest staged marker, or `None` when
  /// the scope owes no seal. O(log n) plus the scope's own (one or two) staged
  /// entries; allocates nothing.
  ///
  /// This is what a fence asks for when it decides whether the ordering proof
  /// it holds already speaks for everything the scope owes.
  #[must_use]
  pub fn adoption_staging_high_water(&self, scope: ScopeId) -> Option<u64> {
    self
      .staged_adoptions
      .range((scope, FIRST_WATCH)..)
      .take_while(|((staged, _), _)| *staged == scope)
      .map(|(_, staged_at)| *staged_at)
      .max()
  }

  /// Whether `scope` has a staged marker a cut reaching `through` would seal.
  /// O(log n) plus the scope's own staged entries; allocates nothing.
  #[must_use]
  pub fn adoption_staged_through(&self, scope: ScopeId, through: u64) -> bool {
    self
      .staged_adoptions
      .range((scope, FIRST_WATCH)..)
      .take_while(|((staged, _), _)| *staged == scope)
      .any(|(_, staged_at)| *staged_at <= through)
  }

  /// Every scope that owes a seal, with the staging generation of its newest
  /// staged marker. Allocates only when some marker is staged.
  #[must_use]
  pub fn staged_adoption_scopes(&self) -> std::vec::Vec<(ScopeId, u64)> {
    let mut out: std::vec::Vec<(ScopeId, u64)> = std::vec::Vec::new();
    for ((scope, _), staged_at) in &self.staged_adoptions {
      match out.last_mut() {
        Some((last, high)) if last == scope => *high = (*high).max(*staged_at),
        _ => out.push((*scope, *staged_at)),
      }
    }
    out
  }

  /// Releases every marker of `scope` staged at or before `through` — the ONE
  /// site at which a widen's adoption edge is released as CONFIRMED, and the
  /// only consumer of the staging book.
  ///
  /// **The caller owes the ordering, and it is the whole content of the call.**
  /// `through` must be the reach of a reader-queue cut that was requested after
  /// the staged listings were ingested and whose answer has itself been
  /// ingested, with the scope's source lane drained to that answer. Given that,
  /// every record the kernel had committed by the listing is already fed —
  /// because one scope's records are FIFO from one kernel queue, and because a
  /// rename's records are committed before any listing of either of its parent
  /// directories that reflects it, which is exactly the listing a depth-one
  /// widen's proof reads. So an excursion the listing could have concealed has
  /// already spent its marker through the move-record path, and
  /// a marker that survives to here certifies the whole splice-to-listing
  /// interval rather than its end state.
  ///
  /// **The interval it certifies is the adopted OBJECT's, not the PATH's.**
  /// Every reading the proof rests on — the marker's survival, the listing's
  /// identity match, the occupancy check below — is about an inode, its parent
  /// link, and its filesystem, and so are the records that spend a marker. A
  /// mount stacked over the adopted slot and unmounted again before the listing
  /// touches none of them: the object neither moved nor lost its superblock, so
  /// no record is emitted for the ordering fence to carry, and by the listing
  /// the overlay is gone and the slot reads exactly as the widen left it. The
  /// proof then matches across an interval in which the path named a different
  /// tree. A stack STILL standing at the listing is caught — the enumerate's
  /// mount fence lowers it non-directory and the identity conjunct rejects it —
  /// so what stays uncovered is specifically a change that reverts inside the
  /// window, which a second mount-id reading would not see either: it reads
  /// clean at both ends.
  ///
  /// Nothing is re-read: the world is not stat-ed, listed, or asked for an
  /// identity again. The three readings the seal takes are the ones that only
  /// ever degrade while the marker stands, so taking them late is taking them
  /// safely and matching one cannot be an ABA:
  ///
  /// - the marker still stands — every spend, death, walk and rebind removes it
  ///   from the map this iterates, so a released marker is simply not here;
  /// - the adopted WATCH is alive — its death is one-way, and a recorded death
  ///   answers with the located `Rescan` the read-time verdict gives it;
  /// - the adopted watch still holds the slot — `detach_child` can vacate it and
  ///   nothing can restore it, since a fresh install mints a new id and the one
  ///   reparent site refuses an unproven adopted edge.
  ///
  /// A marker staged after `through` is left standing for its own cut: its
  /// listing was ingested after this cut was requested, so this cut orders
  /// nothing about it.
  pub fn seal_staged_adoptions(&mut self, scope: ScopeId, through: u64) {
    let due: std::vec::Vec<WatchId> = self
      .staged_adoptions
      .range((scope, FIRST_WATCH)..)
      .take_while(|((staged, _), _)| *staged == scope)
      .filter(|(_, staged_at)| **staged_at <= through)
      .map(|((_, parent), _)| *parent)
      .collect();
    for parent in due {
      let Some(marker) = self.pending_adoptions.get(&parent).cloned() else {
        debug_assert!(false, "a staged entry names a standing marker");
        self.staged_adoptions.remove(&(scope, parent));
        continue;
      };
      // The obligation is owed by the adopted WATCH, so that is what is looked
      // up — never whoever holds the slot now. A watch already destroyed is the
      // recorded-death case, whose vacated slot the consumer re-reads.
      if !self.nodes.contains_key(&marker.adopted) {
        let _ = self.release_adoption_marker(parent, scope, AdoptionDisposal::Verdict);
        self.emit_rescan(scope, self.location_of(parent).child(marker.name));
        continue;
      }
      if self.child_watch(parent, &marker.name) == Some(marker.adopted) {
        // Confirmed, and SILENTLY: no `Rescan`, no epoch bump, no re-arm. A
        // widen nothing interfered with pays the fence one round trip and
        // nothing else, so a barrier across it still resolves by delivery.
        let _ = self.release_adoption_marker(parent, scope, AdoptionDisposal::Verdict);
        continue;
      }
      // The slot parted from the object between the listing and this call, with
      // the marker still standing — so no listing ever proved the edge and the
      // adopted subtree would go on reconstructing paths through it. The cover
      // FIRST, then the coverage it covers ends, exactly as the read-time
      // stale-edge branch does it.
      let _ = self.release_adoption_marker(parent, scope, AdoptionDisposal::CountedRetirement);
    }
    self.settle_bridges();
  }

  /// Whether `scope` has no in-flight cold read carrying a coalesced re-arm
  /// obligation. O(latent) — the set is empty outside a loss racing a cold
  /// discovery.
  fn latent_settled(&self, scope: ScopeId) -> bool {
    !self.latent_cold.values().any(|s| *s == scope)
  }

  /// Records the in-flight cold read `req` of `scope` as carrying a coalesced
  /// re-arm obligation — the ONE insert funnel for
  /// [`latent_cold`](Self::latent_cold), paired with the removals that mirror
  /// `pending_enumerate`. Re-dirtying a read already tracked here gains the
  /// scope nothing, so only a genuine membership gain counts as acquired work.
  fn latent_cold_insert(&mut self, req: ReqId, scope: ScopeId) {
    if self.latent_cold.insert(req, scope).is_none() {
      self.acquired_coverage_work(scope);
    }
  }

  /// Whether `scope` has no half-resolved rename parked in
  /// [`pending_moves`](Self::pending_moves). O(log n): the store is keyed
  /// scope-major, so the scope's halves are one contiguous range and the
  /// predicate is just "is that range non-empty".
  ///
  /// Reading membership directly, rather than mirroring it in a per-scope
  /// counter, is what makes this conjunct safe to add. A half leaves the store
  /// four different ways — a destination consuming it (`on_moved_to`, pairing
  /// or past-window alike), its window expiring (`handle_timeout`), a same-key
  /// half displacing it (`park_pending_move`), and the whole-scope
  /// [`purge_scope_pending_moves`](Self::purge_scope_pending_moves) its three
  /// teardown callers share — and a mirror that missed any one of them would
  /// hold the barrier, and every fence resting on it, down forever.
  fn moves_settled(&self, scope: ScopeId) -> bool {
    self
      .pending_moves
      .range((scope, FIRST_COOKIE)..)
      .next()
      .is_none_or(|((half_scope, _), _)| *half_scope != scope)
  }

  /// Whether a source under `(scope, cookie)` may be parked — the admission rule
  /// of [`park_pending_move`](Self::park_pending_move), and the ONE spelling of
  /// [`PENDING_MOVE_CAP`]'s question.
  ///
  /// Asked of a source that would GROW the store, which is why a cookie already
  /// parked short-circuits to admitted: it displaces rather than adds, so no
  /// insert can take a scope past the cap.
  ///
  /// The count is DERIVED from membership, never mirrored in a per-scope counter,
  /// for the reason [`moves_settled`](Self::moves_settled) states: a half leaves
  /// the store four different ways, and a mirror that missed one would refuse a
  /// scope's renames forever on a phantom population. The store is keyed
  /// scope-major, so the scope's halves are one contiguous range and the count
  /// stops at the cap — O(cap), independent of how many halves the other scopes
  /// hold.
  fn admits_pending_move(&self, scope: ScopeId, cookie: MoveCookie) -> bool {
    self.pending_moves.contains_key(&(scope, cookie))
      || self
        .pending_moves
        .range((scope, FIRST_COOKIE)..)
        .take_while(|((half_scope, _), _)| *half_scope == scope)
        .take(PENDING_MOVE_CAP)
        .count()
        < PENDING_MOVE_CAP
  }

  /// Parks a half-resolved rename under `(scope, cookie)` — the ONE insert
  /// funnel for [`pending_moves`](Self::pending_moves) — returning the
  /// same-key half it displaced, for the caller to resolve.
  ///
  /// Only a genuine membership gain counts as acquired coverage work: a
  /// displacement leaves the range non-empty on both sides of the insert, so
  /// the scope was already unsettled and no proof can have been taken over it.
  ///
  /// Admission is the caller's precondition, not this call's: a refusal must
  /// degrade into the unpairable-source path, which the caller reaches BEFORE it
  /// has mutated anything on the source's behalf.
  fn park_pending_move(
    &mut self,
    scope: ScopeId,
    cookie: MoveCookie,
    pending: PendingMove,
  ) -> Option<PendingMove> {
    debug_assert!(self.admits_pending_move(scope, cookie));
    let displaced = self.pending_moves.insert((scope, cookie), pending);
    if displaced.is_none() {
      self.acquired_coverage_work(scope);
    }
    displaced
  }

  /// [`resignal_coverage_deficits`](Self::resignal_coverage_deficits) minus
  /// the public entry point's bridge flush.
  fn resignal_deficits(&mut self, scope: ScopeId) -> bool {
    let Some(&root) = self.roots.get(&scope) else {
      return false;
    };
    if !self.scope_descends(scope) {
      return false;
    }
    let Some(book) = self.deficits.get(&scope) else {
      return false;
    };
    if book.collapsed {
      // The whole scope is suspect: one root-covering `Rescan`, one full-tree
      // heal probe (bounded — a pending root's own arm outcome re-attempts
      // coverage anyway), binding-re-proving where the profile demands it.
      self.emit_rescan(scope, Location::new());
      self.heal_kick(scope, root);
      self.deficits.remove(&scope);
      return true;
    }
    // Snapshot the sites: each emission and kick below mutates the monitor
    // (and the entry removals mutate the book).
    let interiors: std::vec::Vec<WatchId> = book.interiors.iter().copied().collect();
    let slots: std::vec::Vec<(WatchId, Segment)> = book
      .slots
      .iter()
      .flat_map(|(parent, names)| names.iter().map(|name| (*parent, name.clone())))
      .collect();
    let mut signaled = false;
    for dir in interiors {
      if let Some(hold) = self.in_held_subtree(dir) {
        self.book_hold(hold);
        continue;
      }
      self.emit_rescan(scope, self.location_of(dir));
      self.heal_kick(scope, dir);
      if let Some(book) = self.deficits.get_mut(&scope) {
        book.interiors.remove(&dir);
      }
      signaled = true;
    }
    for (parent, name) in slots {
      if let Some(hold) = self.in_held_subtree(parent) {
        self.book_hold(hold);
        continue;
      }
      self.emit_rescan(scope, self.location_of(parent).child(name.clone()));
      self.heal_kick(scope, parent);
      if let Some(book) = self.deficits.get_mut(&scope)
        && let Some(names) = book.slots.get_mut(&parent)
      {
        names.remove(&name);
        if names.is_empty() {
          book.slots.remove(&parent);
        }
      }
      signaled = true;
    }
    self.gc_deficit_book(scope);
    signaled
  }

  /// Ingests one normalized event, reporting what it did to the watch tree's
  /// shape.
  ///
  /// The [`RecordOutcome`] exists so a consumer holding its own path-keyed
  /// bookkeeping never has to re-derive the Monitor's reparenting decision from
  /// the same record: it is told, by the call that made the decision. Everything
  /// but a successful held-directory reparent reports
  /// [`RecordOutcome::Nothing`]; ignoring the value is a supported way to drive
  /// the loop.
  ///
  /// The return value is a semver-relevant addition to this method — the crates
  /// in this workspace ship together and none is published, so it lands as an
  /// ordinary change rather than a deprecation.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn on_os_record(&mut self, rec: OsRecord, now: Instant) -> RecordOutcome {
    let outcome = self.ingest_record(rec, now);
    self.settle_bridges();
    outcome
  }

  /// [`on_os_record`](Self::on_os_record) minus the public entry point's
  /// bridge flush, which must run after ALL of a record's cascading —
  /// including the fenced early returns.
  fn ingest_record(&mut self, rec: OsRecord, now: Instant) -> RecordOutcome {
    let Some(scope) = self.scope_of(rec.watch()) else {
      return RecordOutcome::Nothing;
    };

    // Addressing-contract enforcement, never silent: a descending monitor ingests
    // only depth-one records (a deeper target has no per-directory watch to anchor
    // it), and a self-event kind carries no target at all. A violating record is a
    // driver bug; recover by rescanning-and-rearming the arrival watch — the
    // no-silent-loss escape — rather than mis-attributing the event. On a held
    // (mid-move) subtree that Rescan would land at the stale pre-move path, so the
    // recovery routes through the hold instead, like every other held activity.
    let depth = rec.depth();
    if (depth > 1 && self.scope_descends(scope)) || (depth > 0 && rec.kind().is_self_event()) {
      if let Some(source) = self.in_held_subtree(rec.watch()) {
        self.book_hold(source);
        self.mark_enumerate_dirty(rec.watch());
      } else {
        self.rescan_and_rearm(scope, rec.watch());
      }
      return RecordOutcome::Nothing;
    }

    // A record on a detached-and-held move source (or anything in its still-attached
    // subtree) would act on the stale PRE-move path — a scope-fence violation. Fence it:
    // suppress the record, mark the hold dirtied so the pairing reparent re-scans the
    // destination, and dirty any racing enumerate on the affected watch so a stale
    // snapshot re-arms rather than being trusted. The ONE exception is the held source's
    // OWN pairing `MovedTo` (its destination landing inside its own subtree is a cyclic
    // move) — it must reach `on_moved_to` to be reparented or rejected. Teardown and
    // self-events (`Ignored` / `MoveSelf` / `DeleteSelf`) are also let through, since they
    // must resolve the node rather than leave a stale watch.
    if let Some(source) = self.in_held_subtree(rec.watch()) {
      let fence = match rec.kind() {
        RecordKind::Created
        | RecordKind::Removed
        | RecordKind::Modified
        | RecordKind::Attrib
        | RecordKind::MovedFrom => true,
        // Let through only the held source's own pairing (matched by its pending key);
        // every other move-in landing in the held subtree is fenced.
        RecordKind::MovedTo => !rec.cookie().is_some_and(|cookie| {
          self
            .pending_moves
            .get(&(scope, cookie))
            .is_some_and(|pending| pending.held == Some(source))
        }),
        RecordKind::Ignored | RecordKind::MoveSelf | RecordKind::DeleteSelf => false,
      };
      if fence {
        self.book_hold(source);
        self.mark_enumerate_dirty(rec.watch());
        return RecordOutcome::Nothing;
      }
    }

    // Latent (not-yet-consumer-visible) transitions live in exactly TWO stores: the
    // event queue, whose dedup fences interleavings by the mutual-prefix touch relation
    // (`would_coalesce`), and `pending_moves`, whose parked halves queue NOTHING — so
    // interleaved subtree activity is invisible to the queue-based relation and must be
    // fenced here. (`held_sources` is the descending-profile fence over this same store;
    // every other container holds obligations or bookkeeping, not transitions: `actions`
    // carries watch/enumerate work, `NodeState::Enumerating` an outstanding read whose
    // result reconciles coverage, `scope_epochs`/`dirtied_holds` markers.) A surviving
    // record whose location mutual-prefixes a parked source — held or unheld — is an
    // ancestor-or-descendant transition inside that pairing window: it DELIVERS (its
    // path is its own current truth; the held fence's suppression above guards paths
    // through a DETACHED subtree, and a half's vacated source slot lies outside it),
    // and the half is marked dirty so its resolution emits covering `Rescan`s.
    //
    // Three transitions are NOT unseen and do not mark: a `MovedTo`'s OWN pairing half
    // (the window's resolution, not an interleaved fact); self-events (a root teardown
    // purges the scope's halves behind its unconditional `Rescan`, and a non-root
    // teardown silences anchored halves through the resolution liveness guard — the
    // tree tells those stories itself); and halves anchored inside the subtree a
    // parent-side cookieed `MovedFrom` is about to detach-and-hold — the tree CARRIES
    // that move, so the half's source reconstructs through the reparent and stays
    // current rather than contradicted.
    if !rec.kind().is_self_event() {
      let record_loc = self.record_location(&rec);
      let exclude = match rec.kind() {
        RecordKind::MovedTo => rec.cookie(),
        _ => None,
      };
      // Only a source the bound ADMITS carries its subtree; a refused one drops it
      // (`on_moved_from`), so the halves under it travel nowhere and are interleaved
      // facts to mark, exactly as under a cookieless source. Both sites read the same
      // store, and nothing between them inserts or removes a half, so they cannot
      // disagree about which it is.
      let carried = if rec.kind().is_moved_from()
        && rec
          .cookie()
          .is_some_and(|cookie| self.admits_pending_move(scope, cookie))
      {
        rec
          .name()
          .and_then(|name| self.child_watch(rec.watch(), name))
      } else {
        None
      };
      self.dirty_pending_sources_touching(scope, &record_loc, exclude, carried);
    }

    // A slot-changing record for a directory whose enumerate is still outstanding races
    // that read: dirty it, so its snapshot — which may list a since-removed child or miss
    // a just-created one — is re-read rather than trusted (the create-descend window).
    if matches!(
      rec.kind(),
      RecordKind::Created | RecordKind::Removed | RecordKind::MovedFrom | RecordKind::MovedTo
    ) {
      self.mark_enumerate_dirty(rec.watch());
    }

    // `on_moved_to` is the ONE handler whose work can move a watched subtree
    // between parents, so it is the only one with an outcome to report.
    match rec.kind() {
      RecordKind::MovedTo => self.on_moved_to(scope, &rec, now),
      RecordKind::Created => {
        self.on_created(scope, &rec);
        RecordOutcome::Nothing
      }
      RecordKind::Removed => {
        self.on_removed(scope, &rec);
        RecordOutcome::Nothing
      }
      // Content and metadata records both surface as `Modified` changes, which the
      // change-level filter cannot tell apart (it admits either flag), so the exact
      // gate lives here where the record's own facts are still known: an `Attrib`
      // record reaches a `modified`-only subscription only if it ALSO proved a content
      // change, and vice versa. The `ondir` target-class modifier applies too. Neither
      // kind affects coverage — suppressing delivery suppresses everything.
      RecordKind::Modified | RecordKind::Attrib => {
        if rec.evidence().admits(self.scope_interest(scope))
          && self.ondir_allows(scope, rec.is_dir())
        {
          self.emit_child(scope, &rec, ChangeKind::Modified);
        }
        RecordOutcome::Nothing
      }
      RecordKind::MovedFrom => {
        self.on_moved_from(scope, &rec, now);
        RecordOutcome::Nothing
      }
      RecordKind::MoveSelf => {
        self.on_move_self(scope, &rec);
        RecordOutcome::Nothing
      }
      RecordKind::DeleteSelf => {
        self.on_delete_self(scope, &rec);
        RecordOutcome::Nothing
      }
      RecordKind::Ignored => {
        self.on_ignored(scope, &rec);
        RecordOutcome::Nothing
      }
    }
  }

  /// Handles the result of an [`Action::Stat`].
  ///
  /// The core stats exactly one thing: a child slot a listing left
  /// [`FileKind::Unknown`]. A resolved answer settles the slot through the
  /// ordinary reconcile — a directory is armed and descended into, anything else
  /// drops whatever stale watch stood there — which also discharges any deficit
  /// the unknown booked. An answer that settles nothing (a failure, or a kind
  /// that is `Unknown` again) re-books that deficit and emits a covering
  /// [`Rescan`](ChangeKind::Rescan): the monitor never re-asks on its own, so
  /// the slot cannot spin the driver, and the darkness keeps re-signalling until
  /// an enumerate or a record settles it.
  ///
  /// A [`NotFound`](crate::IoClass::NotFound) failure is the benign race — the
  /// entry was gone before the stat ran — and settles the slot as empty.
  ///
  /// Settling a slot that spent any of the request's lifetime UNWATCHED ends
  /// that interval, and the settlement loss the request stood
  /// ([`stat_loss_outstanding`](Self::stat_loss_outstanding)) is released with
  /// the answer whatever it says — so where the settlement finds no recorded
  /// deficit to discharge (a book collapsed to its whole-scope marker records
  /// none, and [`resignal_coverage_deficits`](Self::resignal_coverage_deficits)
  /// spends the entries it signals), that loss is handed to a covering
  /// [`Rescan`](ChangeKind::Rescan) rather than released into silence.
  ///
  /// Whatever the answer, it also settles the INCUMBENT watch the read that
  /// deferred to this stat left standing: a kept incumbent receives the descent
  /// that read owed it, and a retired one earns a covering
  /// [`Rescan`](ChangeKind::Rescan) — plus, where the answer rebuilds the slot,
  /// coverage counted by [`coverage_settled`](Self::coverage_settled) so no
  /// barrier settles before the rebuild acknowledges.
  ///
  /// A result for an unknown or superseded request is dropped.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn on_stat_result(&mut self, req: ReqId, res: StatResult) {
    self.ingest_stat_result(req, res);
    self.settle_bridges();
  }

  /// [`on_stat_result`](Self::on_stat_result) minus the public entry point's
  /// bridge flush, which must run after ALL of a result's cascading.
  fn ingest_stat_result(&mut self, req: ReqId, res: StatResult) {
    let Some(slot) = self.pending_stat.remove(&req) else {
      return;
    };
    // Whether this request spans an interval the slot spent DARK — the question
    // the released loss owes its replacement for
    // ([`stat_slot_dark`](Self::stat_slot_dark)). Read off the row while it is
    // still whole, and through the SAME predicate the parent's death asks of a
    // row it reclaims unanswered: nothing between here and its use below moves a
    // watch into or out of the slot, and two releases that disagreed about which
    // windows were dark would be one release handing the darkness to nobody.
    let dark_interval = self.stat_slot_dark(&slot);
    let StatSlot {
      parent,
      name,
      scope,
      placement,
      bootstrap,
      stands_loss,
      ..
    } = slot;
    self.stat_slots.remove(&(parent, name.clone()));
    // The settlement loss is discharged by the ANSWER ARRIVING, not by what the
    // answer says, so it is released here — ahead of every early return and
    // every branch below. A failure, a kind that is `Unknown` again, an answer
    // the placement staled, and one whose parent died under it all reach a
    // terminal that re-books the darkness in the DEFICIT book (which the
    // dispatch re-signal covers) or dies with the node; none of them leaves a
    // stat outstanding, so none of them may leave the loss standing either.
    if stands_loss {
      self.stat_loss_dec(scope, 1);
    }
    // The slot's parent can have died while the stat ran; there is then no slot
    // left to settle, and its deficit died with the node.
    if !self.is_watched(parent) {
      return;
    }
    // The request is keyed by `(parent, name)`, which a rename carries intact —
    // but the driver probed a PATH, and a rename of the parent or of any ancestor
    // leaves that path describing a coordinate this slot no longer occupies.
    // Applying such an answer would settle the slot the parent holds NOW with
    // what was found where it used to be: a stale `NotFound` or `File` would
    // retire a destination watch, or clear a slot's deficit, over a directory
    // that is really there. A held parent is the same reconstruction failure one
    // clause over (see [`Lowering`]): its slot's path is the vacated pre-move one
    // for the whole pairing window, so the answer describes whatever occupies the
    // slot the subtree has LEFT. It is not evidence about this slot either — a
    // replacement's `File`, or a `NotFound` for a name only the vacated path
    // lacked, would retire an incumbent covering a directory that is really
    // there, and the destination's own recovery cannot rebuild it (an incomplete
    // destination read reconstructs no omitted name). It degrades instead: the
    // incumbent is KEPT with its coverage and its descent, and the pairing —
    // whose debt the fence booked — owns the destination's reconciliation.
    let lowering = self.fence_lowering(parent, placement);
    let stale = !lowering.is_evidence();
    // The watch this answer decides the fate of, captured BEFORE the settle: it
    // is the difference between the two settlements below that says whether
    // coverage ended here, and it cannot be read back afterwards.
    let incumbent = self.child_watch(parent, &name);
    // And the descent it is owed, taken BEFORE the reconcile can retire it: a
    // retirement's own cover ([`settle_stat_slot`](Self::settle_stat_slot))
    // discharges the obligation, so leaving the entry standing would make the
    // drop read it as an obligation that ESCAPED and stand a second, redundant
    // counted cover. An obligation left in the book past this point is one this
    // answer could not settle at all — its owner had already left the slot —
    // and that is exactly the case the reparent (or the drop) must honor.
    let descent = incumbent.and_then(|kept| self.owed_descents.remove(&kept));
    // Whether this answer left the interval the slot spent dark covered by
    // NOTHING. Asked of every arm, and asked as a VALUE the match produces, so
    // an arm added below does not compile until it has said which side of the
    // question it is on — the release above is unconditional precisely so no
    // answer shape can skip it, and its replacement is owed the same treatment.
    let owes_cover = match res {
      StatResult::Ok(entry) if !stale && !entry.kind().is_unknown() => {
        // Whether the settlement HEALED the slot's booked darkness — the one act
        // that turns a fine deficit entry into the covering `Rescan`. Taken as
        // the reconcile's own answer rather than read off the book beforehand:
        // what a pre-read could say is which entry stood, and the question is
        // which one this call REMOVED. The two part company wherever the
        // reconcile reuses what it finds — an identity match, or an identity
        // nobody could read, over a slot some other occupation path filled while
        // the request was outstanding — and there the entry stands, healed by
        // nobody, with the loss that covered its interval already released.
        let healed = self.reconcile_slot(
          parent,
          scope,
          &name,
          Self::entry_occupant(entry.kind()),
          false,
          entry.node(),
        );
        // The bootstrap crawl's unclassifiable-entry detour. A listing entry of
        // unknown kind is not reconciled by the read at all — it books darkness
        // and asks for a kind — so the directory it turns out to be is installed
        // HERE, by an ordinary cold `install_child`, and its own post-arm cold
        // read would announce the whole subtree as `Created`s. That is the
        // registration inventory the suppression removes, leaking straight back
        // on any `DT_UNKNOWN`-prone filesystem. Route the install through the
        // crawl's own suppression instead: `inherit_rearm` makes the answer's
        // post-arm read a re-arm read, and makes this sub-window counted so its
        // closing `Rescan` cannot precede the recovery.
        //
        // Gated on the EMPTY slot (`incumbent.is_none()`, captured before the
        // reconcile) — the same occupation check every other named site uses,
        // and the only shape whose install is born cold. Named install site #3.
        //
        // Off the queue-time STAMP, never the live mark (see
        // [`StatSlot::bootstrap`]). The loss half is stated for the one case the
        // heal cannot carry: `install_child`'s `remove_slot_deficit` already
        // stands both bridge bits when it removes a real entry, so an ordinary
        // empty-slot unknown is `Rescan`-covered without this — but a book
        // collapsed past `DEFICIT_CAP` records nothing to remove, and there this
        // is the window's only loss half.
        //
        // The install this answer performed into an EMPTY slot, if it performed
        // one, is read once: the detour's suppression routing needs the handle,
        // and the transfer below needs to know the detour stood the cover so it
        // does not stand a second one.
        let installed = incumbent
          .is_none()
          .then(|| self.child_watch(parent, &name))
          .flatten();
        if bootstrap && let Some(fresh) = installed {
          self.bridge_saw_rescan(scope);
          let _ = self.inherit_rearm(fresh);
        }
        // THE TRANSFER. This answer ENDED the slot's darkness — a directory is
        // armed and descended into, anything else drops whatever stale watch
        // stood there — and the release above ended the loss that was covering
        // the interval it spanned. Ordinarily the heal carries the handover:
        // `remove_slot_deficit` turns the slot's fine entry into both bridge
        // bits and the window closes with its `Rescan`. Where the settlement
        // turned no entry — the book had none, or the reconcile reused an
        // occupant it found rather than installing over one — that handover is
        // to NOTHING, and the interval, during which the slot may have been an
        // unwatched directory with writes beneath it recorded by no watch and
        // announced by no listing, would pass from a degraded fence to a
        // certified one at this line.
        //
        // Suppressed only by a cover this call OBSERVED being stood (`healed`,
        // and the detour's own half below). A standing deficit entry is not one:
        // the entry says the darkness was recorded, never that anything has
        // since covered it, and the re-signal that will eventually turn it fires
        // at a sync cookie's DISPATCH — nowhere near the ordinary set-cover
        // reply this release is racing.
        //
        // Only where the slot spent an interval DARK (`dark_interval`): a slot
        // a live watch covered for the whole of this request was never dark, so
        // there is nothing to hand off, and standing a cover anyway would
        // degrade every registration that meets a `DT_UNKNOWN` name over ground
        // it already watches. That question is deliberately NOT answered by the
        // slot's occupancy at this line — see `dark_interval` above.
        stands_loss && dark_interval && !healed && !(bootstrap && installed.is_some())
      }
      // The object vanished before the stat: the slot is empty, which the
      // ordinary `Gone` reconcile settles (dropping any stale watch and
      // discharging the deficit) — and, where that settlement discharged
      // nothing, the same transfer the resolving arm above owes, decided off
      // the same observed outcome.
      StatResult::Failed(class) if !stale && class.is_not_found() => {
        let healed = self.reconcile_slot(parent, scope, &name, SlotOccupant::Gone, false, None);
        stands_loss && dark_interval && !healed
      }
      // Unresolvable: the kind is still unknown, the stat itself failed, or the
      // answer describes a path the placement moved out from under it (`stale`).
      // This is the slot's own failure edge, so it re-books the darkness — a
      // dispatch re-signal clears entries optimistically, and a site that is still
      // broken is required to re-record through exactly this path — and stands a
      // fresh `Rescan` over the interval the darkness has already spanned.
      // Deliberately no re-stat: a slot that cannot be classified would otherwise
      // loop forever, and a re-stat chasing a moving placement would loop for as
      // long as the renames last. The degrade is covered-and-counted rather than
      // lossy — the incumbent (if any) is KEPT with its coverage and its descent,
      // and an EMPTY slot re-books the deficit every later sync re-signals, so
      // nothing is left dark and silent.
      _ => {
        if self.child_watch(parent, &name).is_none() {
          self.record_slot_deficit(scope, parent, name.clone());
        }
        true
      }
    };
    // The ONE cover site, past every arm: the degrade's standing `Rescan` and
    // the transfer a settling answer owes are a single emission, so neither can
    // be reached without the other having been decided and neither can fire
    // twice over one answer.
    //
    // Located, and so subject to the same address test every other located
    // recovery is. Under a hold this slot's reconstruction is the pre-move path,
    // so a `Rescan` here would send the consumer to the slot the subtree has
    // LEFT while the real destination kept no re-arm obligation at all —
    // uncovered until a later deficit re-signal. The fence above dirtied the
    // hold instead, which obliges the pairing to `Rescan` and re-arm the
    // destination; and the hold holds [`coverage_settled`](Self::coverage_settled)
    // itself down for as long as it stands — through the held source
    // ([`holds_settled`](Self::holds_settled)) and through the parked rename half
    // that detached it ([`moves_settled`](Self::moves_settled)) — so no fence can
    // certify the window this emission would have covered before that pairing
    // runs.
    if owes_cover && lowering.locatable() {
      self.emit_rescan(scope, self.child_location(parent, &name));
    }
    self.settle_stat_slot(
      scope,
      parent,
      &name,
      incumbent,
      descent,
      lowering.locatable(),
    );
  }

  /// Settles the coverage half of a resolved stat: what the answer did to the
  /// slot's INCUMBENT watch, which the deferring read deliberately left
  /// standing rather than deciding blind.
  ///
  /// Written as "what happened to the incumbent", never as an enumeration of the
  /// answers that owe something, so an answer no branch anticipated still lands
  /// in the covering case rather than in silence. Three outcomes:
  ///
  /// - **kept** (the successor IS the incumbent, or there was never a watch
  ///   here): no coverage ended, so nothing is covered. A kept incumbent
  ///   receives the descent the deferring read owed it and could not perform —
  ///   the whole reason [`owed_descents`](Self::owed_descents) exists. Without
  ///   it a crawl that skipped this name would leave the survivor's subtree
  ///   un-re-armed while its scope read settled, and a directory created under
  ///   it during the deferral would stay unwatched with nothing booked to say
  ///   so. `descent` is the caller's, taken against this same incumbent before
  ///   the answer could retire it; an obligation owed to a watch that had
  ///   already LEFT the slot is none of this settlement's business and is not
  ///   passed here.
  /// - **replaced** (a fresh watch stands where the incumbent did): the
  ///   retirement ends coverage of an object that was there, so it owes the
  ///   opening cover — and the rebuild is made COUNTED
  ///   ([`inherit_rearm`](Self::inherit_rearm)), which is what lets the cover be
  ///   suppressed inside an already-lossy window exactly as
  ///   [`rearm_enumerate`](Self::rearm_enumerate)'s rebuilt flavor is: the
  ///   window's closing `Rescan` cannot now precede the recovery. A fresh
  ///   install proves its own binding, so the reprove flavor does not reach it.
  /// - **retired with nothing in its place** (a `File`, or a vanish): no
  ///   successor exists, so no counted work will make this window close — the
  ///   suppression is unavailable rather than merely conservative, and the cover
  ///   is unconditional.
  ///
  /// The cover is located off the PARENT, which is still watched; the retired
  /// child's own node is gone by the time this runs.
  ///
  /// `deliver` is false when the parent's own reconstruction is the vacated
  /// pre-move path of an enclosing hold: the cover would then name a slot the
  /// subtree has left, so it is suppressed exactly as a held read's is and the
  /// pairing's destination `Rescan` carries it. The COUNTED rebuild below is
  /// coverage, not delivery, and runs regardless.
  fn settle_stat_slot(
    &mut self,
    scope: ScopeId,
    parent: WatchId,
    name: &Segment,
    incumbent: Option<WatchId>,
    descent: Option<StatDescent>,
    deliver: bool,
  ) {
    let successor = self.child_watch(parent, name);
    if successor == incumbent {
      if let (Some(kept), Some(descent)) = (incumbent, descent) {
        self.apply_descent(kept, descent);
      }
      return;
    }
    // Nothing was retired: the slot was uncovered and this answer occupied (or
    // left) it, which is the deficit book's own story — `install_child` heals a
    // booked hole and stands both bridge bits through `remove_slot_deficit`.
    if incumbent.is_none() {
      return;
    }
    let cover = self.child_location(parent, name);
    match successor {
      Some(fresh) => {
        if deliver && !self.bridge_is_lossy(scope) {
          self.emit_rescan(scope, cover);
        }
        let _ = self.inherit_rearm(fresh);
      }
      None => {
        if deliver {
          self.emit_rescan(scope, cover);
        }
      }
    }
  }

  /// Queues the [`Action::Stat`](crate::Action::Stat) that settles an
  /// unclassifiable slot, unless one is already outstanding for it — a slot
  /// re-listed as unknown on every retry of an unreadable directory must not
  /// stack a request per read.
  ///
  /// The request is born owing no DESCENT; a read that DEFERS one to it
  /// books that separately against the slot's incumbent
  /// ([`defer_stat_descent`](Self::defer_stat_descent)), which is also what lets
  /// a later read's stronger obligation reach a stat this dedup already
  /// coalesced onto. What it may be born STANDING is the settlement loss below,
  /// which degrades the scope's fences from the queue until the answer.
  ///
  /// This is also where the request's SETTLEMENT LOSS is stood
  /// ([`StatSlot::stands_loss`]), rather than at the reconcile that asked for the
  /// stat: the row is created here and nowhere else, so a caller cannot queue a
  /// stat over a slot it covers with nothing and forget to say so. The DARKNESS
  /// that loss stands over ([`StatSlot::dark_uncovered`]) comes off the same
  /// emptiness reading, so the two cannot disagree about what this read saw. The
  /// dedup below escapes neither — a coalesced read raises both against the
  /// request it lands on instead of returning silently.
  ///
  /// Never at a parent that is gone, for the same reason
  /// [`install_child`](Self::install_child) installs nothing there: the row's own
  /// reclamation is the parent's death ([`reclaim_node_marker`](Self::reclaim_node_marker)),
  /// which has already happened, so nothing would ever take it back — and its
  /// settlement loss would degrade every later fence of the scope forever. A
  /// tripwire on the containment invariant, like `install_child`'s: loud in
  /// tests, wedge-proof in release.
  fn queue_stat(&mut self, parent: WatchId, scope: ScopeId, name: Segment) {
    debug_assert!(
      self.nodes.contains_key(&parent),
      "a slot stat is only ever queued at a live parent"
    );
    if !self.nodes.contains_key(&parent) {
      return;
    }
    // An UNOCCUPIED slot is one the asking read covered with nothing: it
    // reconciled no watch there and booked the darkness, so until the answer
    // lands the slot may be a directory this scope does not watch. Read before
    // the dedup, because the emptiness is a fact about THIS read and the request
    // it lands on may be an older read's.
    let uncovered = self.child_watch(parent, &name).is_none();
    if let Some(&outstanding) = self.stat_slots.get(&(parent, name.clone())) {
      if uncovered {
        self.raise_stat_darkness(outstanding);
      }
      return;
    }
    let req = self.next_req_id();
    let bootstrap = self.in_bootstrap_window(scope);
    let stands_loss = bootstrap || uncovered;
    if stands_loss {
      // Standing from here until the answer (or the parent's death) discharges
      // it — see [`stat_losses`].
      //
      // [`stat_losses`]: Self::stat_losses
      self.stat_loss_inc(scope);
    }
    self.stat_slots.insert((parent, name.clone()), req);
    self.pending_stat.insert(
      req,
      StatSlot {
        parent,
        name: name.clone(),
        scope,
        placement: self.placement_now(),
        // Stamped at QUEUE time, deliberately — see [`StatSlot::bootstrap`].
        // The dedup above needs no upgrade rule for THIS half: inside the
        // registration window the only outstanding stat for a slot is one an
        // earlier in-window read queued, which already carries the stamp.
        bootstrap,
        stands_loss,
        // The emptiness this read saw, which the loss above does not record on
        // its own: a registration-stamped request raises the loss over a slot it
        // watched all along, and only THIS says whether any of it was dark.
        dark_uncovered: uncovered,
        // Born false whatever the slot holds, and for the same reason either
        // way: an EMPTY slot is one this read just booked darkness for and
        // nothing has covered since, and an OCCUPIED one holds no vacancy for
        // anything to have covered. Only a removal that stands the slot's cover
        // raises it — see [`StatSlot::vacancy_covered`].
        vacancy_covered: false,
      },
    );
    self.actions.push_back(Action::stat(
      req,
      crate::action::StatTarget::child(parent, name),
    ));
  }

  /// Books the descent obligation the calling read owed `(parent, name)`'s
  /// incumbent and could not perform, against that INCUMBENT — the identity a
  /// later rename carries out of the slot intact, never the slot the rename
  /// empties (see [`owed_descents`](Self::owed_descents)).
  ///
  /// It UPGRADES, never downgrades ([`StatDescent`] is ordered by strength): the
  /// stat for a slot is coalesced across every read that re-encounters the name,
  /// so the obligation the answer honors must be the strongest any of them
  /// carried — a reproof deferred onto a stat an earlier plain re-arm queued is
  /// still a reproof.
  ///
  /// Two no-ops, for the same reason: nothing would ever discharge the booking.
  /// A slot with no outstanding stat has no answer coming (the caller asked for
  /// one through the same reconcile, and a non-descending scope asks for none),
  /// and an EMPTY slot has no incumbent — the deferring read owed the name's
  /// coverage to nobody, and whatever the answer installs there proves its own
  /// binding by its install acknowledgement.
  ///
  /// The booking is deliberately UNCOUNTED, and an outstanding stat is
  /// deliberately no conjunct of [`coverage_settled`](Self::coverage_settled)
  /// ([`pending_stat`](Self::pending_stat)): a driver that never answers must
  /// degrade to a re-signalled `Rescan`, never wedge the scope's every barrier.
  /// Nothing rests on the answer ALONE — the incumbent keeps its watch and its
  /// coverage meanwhile, and the crawl that deferred stood its own `Rescan` — so
  /// an answer that never comes costs a degraded cover rather than a wedge.
  /// Where the deferring read left the slot covered by NOTHING — and for every
  /// REGISTRATION-window request — the degrade is made explicit rather than left
  /// to the deficit re-signal, which reaches a sync cookie's dispatch and not an
  /// ordinary set-cover reply: the standing request marks the scope's
  /// settlement lossy ([`stat_losses`](Self::stat_losses)) for exactly as long
  /// as it is owed.
  fn defer_stat_descent(&mut self, parent: WatchId, name: &Segment, descent: StatDescent) {
    if !self.stat_slots.contains_key(&(parent, name.clone())) {
      return;
    }
    let Some(incumbent) = self.child_watch(parent, name) else {
      return;
    };
    self
      .owed_descents
      .entry(incumbent)
      .and_modify(|owed| *owed = (*owed).max(descent))
      .or_insert(descent);
  }

  /// Performs a booked descent against the watch that owes it — the ONE
  /// definition of what each flavor means, shared by the answer that settles it
  /// in place ([`settle_stat_slot`](Self::settle_stat_slot)) and the reparent
  /// that discharges it after the slot it was deferred at emptied
  /// ([`on_moved_to`](Self::on_moved_to)). Two spellings could disagree about
  /// what a reproof is owed, which is the whole hazard here.
  fn apply_descent(&mut self, watch: WatchId, descent: StatDescent) {
    match descent {
      StatDescent::Reprove => self.start_reinstall(watch),
      StatDescent::Rearm => {
        let _ = self.inherit_rearm(watch);
      }
    }
  }

  /// Handles the result of an [`Action::Enumerate`].
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn on_enumerate(&mut self, req: ReqId, res: EnumerateResult) {
    self.ingest_enumerate(req, res);
    self.settle_bridges();
  }

  /// [`on_enumerate`](Self::on_enumerate) minus the public entry point's
  /// bridge flush, which must run after ALL of a result's cascading.
  fn ingest_enumerate(&mut self, req: ReqId, res: EnumerateResult) {
    // The read resolved (or was superseded): it can no longer carry a latent
    // coalesced obligation. Mirrors the `pending_enumerate` removal below.
    self.latent_cold.remove(&req);
    let Some(dir) = self.pending_enumerate.remove(&req) else {
      return;
    };
    // Accept the result only if `dir` still awaits THIS request. A node that was dropped
    // or whose read was superseded (re-armed, its slot rebuilt) has moved on — a stale
    // result must not reconcile against it. This is the gap the old `pending_enumerate`
    // + liveness pair could not close: the request identity now lives on the node.
    let (kind, attempts, dirty, scope, placement) = match self.nodes.get(&dir) {
      Some(WatchNode {
        state:
          NodeState::Enumerating {
            req: r,
            kind,
            attempts,
            dirty,
          },
        scope,
        placement,
        ..
      }) if *r == req => (*kind, *attempts, *dirty, *scope, *placement),
      _ => return,
    };
    // The request names this node, but the LISTING came from a path — and
    // [`fence_lowering`](Self::fence_lowering) is what says what that path is
    // worth. A read the clock invalidated is not a snapshot of this directory at
    // all (a rename of any ancestor re-points it at whatever now stands at the
    // vacated path), so it is handled like a read that FAILED: nothing of its
    // listing is reconciled, the coverage cascade and the bounded retry run, and
    // the retry re-reads wherever the node has landed. Reconciling its entries
    // instead would install a replacement's children under this node — the very
    // misattribution the fence exists to stop.
    //
    // A held (limbo) directory's read is the other clause. It fences DELIVERY —
    // it must not `Rescan` or `Created` at the stale pre-move path (the third
    // fence entry point, beside records and subtree overflow) — but it also
    // fences the listing's AUTHORITY: the names it reports are whatever occupies
    // the slot the subtree has left, so they may not be treated as this
    // directory's inventory. The read is still performed and its coverage still
    // taken, because the design deliberately reads under a hold so the subtree is
    // complete when it reparents; what it may no longer do is PRUNE. It therefore
    // routes through the never-prunes path with an ADDITIVE listing, and the
    // pairing reparent — whose debt the fence booked — owns the reconciliation
    // against the real destination.
    let lowering = self.fence_lowering(dir, placement);
    let held = lowering.held;
    // The read resolved: the node leaves `Enumerating`.
    self.set_state(dir, NodeState::Live);

    if res.forces_rescan() || dirty || !lowering.is_evidence() {
      // An incomplete read (`Partial` / `Failed`), a complete read a slot-changing
      // record raced (`dirty`) so its listing is a possibly-stale snapshot, or one the
      // placement moved under or a hold had already vacated (no longer evidence):
      // reconcile what may be reconciled, cascade the re-arm into every child,
      // bounded-retry to complete the watch set, and — unless the dir is held — emit a
      // `Rescan` for the unreadable content (a held dir's `Rescan` would point at the
      // stale path). The retry keeps a reprove flavor: the survivors' re-adds ride the
      // eventual complete read, so dropping the flavor here would silently downgrade
      // the binding proof to an enumerate.
      let reprove = matches!(kind, EnumKind::Rearm { reprove: true });
      let additive;
      let entries = if lowering.is_evidence() {
        res.entries()
      } else if lowering.moved {
        // Read at a path a rename re-pointed at somebody else's object: the
        // listing describes a directory this node is not, and none of it may
        // reach this node's slots. The retry re-reads wherever the node landed.
        &[][..]
      } else {
        // Held: the listing is the vacated path's, so it may only ADD coverage
        // for a name nothing here covers — the gap-created descendant the hold's
        // best-effort read exists to arm. It may not touch a covered slot: a
        // replacement's `File` at a name this subtree still watches would retire
        // a live directory over evidence about a path the object has left, and
        // the destination's own recovery cannot rebuild it (an incomplete
        // destination read reconstructs no omitted name).
        additive = self.additive_entries(dir, res.entries());
        &additive
      };
      self.handle_incomplete_enumerate(
        dir,
        scope,
        entries,
        attempts,
        lowering.locatable(),
        reprove,
      );
      return;
    }

    // A CLEAN completion fully reconciled this interior: a standing
    // exhausted-read deficit for it is healed (the P2 clear edge; the clear
    // stands the closing `Rescan` when it removes a real entry — see
    // `clear_interior_deficit`).
    self.clear_interior_deficit(scope, dir);

    // A pending same-transport adoption edge resolves on this — the parent's
    // first complete read (an incomplete or dirtied read returned above with
    // the marker intact, so the bounded retries keep re-checking, and the
    // retry's own completion is a re-arm the verdict is owed on just the same).
    // Strictly ABOVE the dispatch below: a refused edge is retired right here,
    // and the reconcile of that very name is the next thing to run — so it
    // meets an empty slot and installs, instead of finding the refused subtree
    // and reusing it.
    //
    // `dir` survives it by construction, not by check: the retirement resolves
    // the adopted WATCH, which the containment invariant keeps a direct CHILD of
    // `dir` (see `pending_adoptions`), and the dispatch below addresses `dir` at
    // every step.
    self.resolve_adoption(dir, scope, held.is_some(), &res);

    match kind {
      // A cold read on a held dir is coverage-only; route it as a re-arm (no
      // `Created`). A reprove flavor rides through (`Rearm { reprove }`): a
      // held dir's own binding is never a reinstall target, but its read's
      // survivors are ordinary in-slot children whose proof must not be lost.
      EnumKind::Rearm { reprove } if held.is_some() => {
        self.rearm_enumerate(dir, scope, &res, reprove)
      }
      EnumKind::Cold if held.is_some() => self.rearm_enumerate(dir, scope, &res, false),
      // A complete re-arm: prune vanished, arm new, cascade — without emitting `Created`.
      EnumKind::Rearm { reprove } => self.rearm_enumerate(dir, scope, &res, reprove),
      // A complete cold enumerate: discovery — emit `Created` and install per-directory.
      EnumKind::Cold => {
        for entry in res.entries() {
          // Delivery honors the `ondir` modifier (the kind gate is in `emit`); the
          // coverage install below runs regardless.
          if self.ondir_allows(scope, Some(entry.is_dir())) {
            let location = self.child_location(dir, entry.name());
            self.emit(
              scope,
              location,
              ChangeKind::Created,
              Evidence::of(RecordKind::Created),
            );
          }
          // A cold enumerate is discovery, not a replace, so an already-watched slot
          // is reused (`replaced = false`).
          let occupant = Self::entry_occupant(entry.kind());
          let _ = self.reconcile_slot(dir, scope, entry.name(), occupant, false, entry.node());
        }
      }
    }
  }

  /// The part of a listing that can only ADD coverage at `dir`: a name `dir` does
  /// not already watch reported as a directory, or one the read could not
  /// classify at all.
  ///
  /// This is all a HELD read may reconcile. Its listing came from the vacated
  /// pre-move path, so anything else is a DECISION ABOUT a slot rather than an
  /// addition to it: a positively-reported non-directory retires the name's
  /// incumbent and discharges its darkness, and a directory whose identity
  /// differs from the incumbent's rebuilds the slot — each spending evidence
  /// about a path the object has LEFT on coverage the destination's own recovery
  /// is not guaranteed to reconstruct (an incomplete destination read omits names
  /// and deliberately rebuilds none of them). What survives the filter cannot
  /// retire anything: an unclassifiable name settles no slot by construction (it
  /// books darkness and asks for a kind), and installing a watch where nothing
  /// stood is the one direction that cannot lose coverage — at worst it arms a
  /// replacement's child, which the pairing's own recovery discards.
  fn additive_entries(&self, dir: WatchId, entries: &[DirEntry]) -> std::vec::Vec<DirEntry> {
    entries
      .iter()
      .filter(|entry| {
        entry.kind().is_unknown()
          || (entry.is_dir() && self.child_watch(dir, entry.name()).is_none())
      })
      .cloned()
      .collect()
  }

  /// Handles a read of `dir` that cannot be trusted as a complete inventory — an
  /// incomplete one (`Partial` or `Failed`), or a complete one raced by a slot change
  /// or a placement change — in either the discovery or re-arm mode. It never prunes
  /// (the listing is not known to be exhaustive): it arms any newly-visible directory,
  /// cascades the re-arm into EVERY currently-known child directory (a partial listing
  /// may omit a still-present one whose subtree gained a gap-created descendant), emits
  /// a `Rescan` so the consumer refreshes the content the read could not report, and
  /// retries a bounded number of times before letting the `Rescan` stand — so a
  /// permanently-unreadable directory cannot spin the driver.
  ///
  /// `entries` is what the caller vouches for as having been read AT THIS NODE, which
  /// is why it is passed rather than taken off the result: a listing the placement
  /// clock invalidated was read somewhere else, and none of it may be reconciled here
  /// even though the result itself is `Ok`; a held directory's listing came from the
  /// vacated pre-move path, and only its additive part
  /// ([`additive_entries`](Self::additive_entries)) may be.
  fn handle_incomplete_enumerate(
    &mut self,
    dir: WatchId,
    scope: ScopeId,
    entries: &[DirEntry],
    attempts: u8,
    deliver: bool,
    reprove: bool,
  ) {
    // Reconcile every VISIBLE entry (a `Failed` read surfaces none): install or keep a
    // directory, and — for a name the listing now positively reports as a non-directory
    // — drop the stale watch so it can't keep attributing events or block a later real
    // directory there. Never prune OMITTED names (the listing is incomplete). No
    // `Created` — the `Rescan` below refreshes consumer content. A freshly-installed
    // child is picked up by the cascade that follows (it is now in the adjacency set).
    for entry in entries {
      let occupant = Self::entry_occupant(entry.kind());
      // The occupation check, taken BEFORE the reconcile that performs the
      // install — the fresh/survivor distinction the registration window's loss
      // half keys on. Named install site #2; the HELD route is the reason it is
      // here at all (a held read suppresses its own `Rescan` below, so an
      // in-window additive install there has no other cover), and it must be the
      // reconcile pass and never the cascade below, which re-arms survivors and
      // fresh installs alike.
      let fresh =
        matches!(occupant, SlotOccupant::Dir) && self.child_watch(dir, entry.name()).is_none();
      let _ = self.reconcile_slot(dir, scope, entry.name(), occupant, false, entry.node());
      if fresh {
        self.mark_bootstrap_loss(scope);
      }
    }
    // Cascade the re-arm into EVERY child of `dir` — those in a name-slot AND any
    // detached-and-held move source (mid-move, out of `child_index` but still in the
    // adjacency set at its pre-move parent). A Partial listing may omit a still-present
    // child, and a persistently-Failed read never re-reads at all, so a gap-created
    // descendant under any child would otherwise stay unwatched. On a REPROVE
    // read the in-slot cascade must be the re-add, not the plain re-arm: this
    // path may be the survivors' ONLY visit (an exhausted read never
    // completes, and its completion is what would have re-added them), and an
    // enumerate cascade would let a whole kept subtree reach `Live` on dead
    // bindings with no post-loss acknowledgement. A detached-and-held child
    // keeps the plain transfer — a held node is never a re-add target; its
    // pairing resolution owns the reproof. `inherit_rearm` / `start_rearm` /
    // `start_reinstall` all coalesce, so this cannot stack duplicate work
    // across the bounded retries.
    let children: std::vec::Vec<WatchId> = self
      .nodes
      .get(&dir)
      .map(|node| node.children.iter().copied().collect())
      .unwrap_or_default();
    for child in children {
      if reprove && self.is_slot_child(dir, child) {
        self.start_reinstall(child);
      } else {
        let _ = self.inherit_rearm(child);
      }
    }
    // A held dir's `Rescan` would point at its stale pre-move path, so it is suppressed
    // (the pairing reparent re-scans the real destination); coverage above still retries.
    if deliver {
      self.emit_rescan(scope, self.location_of(dir));
    }
    if attempts < REARM_MAX_RETRIES {
      // Retry as a re-arm read (`Created`-suppressed, reprove flavor kept); the
      // count carries on the node so a permanently-unreadable directory
      // escalates to the standing `Rescan` after a bounded number of tries
      // rather than spinning the driver.
      self.queue_enumerate(dir, EnumKind::Rearm { reprove }, attempts + 1);
      return;
    }
    // Retries exhausted with an adoption edge still unverified, and no read
    // left that could ever prove it. The marker cannot simply be kept — past
    // the bounded retries it would hold `coverage_settled` down with nothing
    // remaining to release it — so it is released together with the one
    // disposal that is not inert here: the adopted subtree is RETIRED inside a
    // counted covering `Rescan` anchored at the scope root.
    //
    // This site's own two signals are not that cover. On the HELD path — the
    // one a widen tail's incomplete reads actually take, since a hold costs a
    // listing its evidence status and routes every completion here — the
    // `Rescan` above is suppressed (it would name the vacated pre-move path)
    // AND the interior deficit below is skipped with it (the `if deliver`
    // gate), so both halves of "the standing `Rescan` plus the interior
    // deficit" are absent exactly where the release happens. What would remain
    // is the hold's pairing re-arm, which reconciles PERMISSIVELY: a name it
    // cannot classify is not diffed at all and defers to the slot's stat, whose
    // `Dir`-without-identity answer is no positive difference and so KEEPS the
    // incumbent. The edge no read ever confirmed would survive its own release,
    // its descendants delivering at reconstructed-stale paths with the barrier
    // settled — the same shape `resolve_adoption`'s stale-edge branch refuses,
    // reached by exhaustion instead of by refutation, so it takes the same
    // disposition.
    //
    // The scope ROOT is what the cover names because it is the only anchor that
    // works on both paths: it is locatable under a hold, and it is an ancestor
    // of the adopted object and of everything the retirement disarms. Its re-arm is
    // COUNTED, so the released barrier rests on the rebuild rather than on
    // nothing, and it is bounded — the marker is gone, so a re-exhaustion of
    // this very read stands no second cover.
    //
    // `dir` — the very directory whose exhausted read this is — survives it: the
    // containment invariant keeps the adopted watch a direct CHILD of `dir` (see
    // `pending_adoptions`), so the drop cannot climb to it, and the interior
    // deficit booked below stays a claim about a LIVE directory.
    let _ = self.release_adoption_marker(dir, scope, AdoptionDisposal::CountedRetirement);
    if deliver {
      // Retries exhausted — the node stays `Live` and the `Rescan` stands. It is
      // re-attempted the next time a reconciliation trigger for its scope re-arms it (a
      // fresh overflow, an ancestor's incomplete read cascading down, or a sync
      // cookie's deficit re-signal). A dedicated degraded state with its own backoff
      // timer, so a transiently-unreadable directory self-heals without waiting for
      // the next trigger, is a later refinement.
      //
      // The unreconciled interior is LEVEL-PERSISTENT darkness (gap-created
      // descendants under it were never armed), so record it past its standing
      // `Rescan`. The held case records nothing: the pairing re-arms the subtree
      // fresh or the timeout tears it down behind a delivered `Removed`, and a
      // post-pairing re-exhaustion is non-held and records then.
      self.record_interior_deficit(scope, dir);
    }
  }

  /// Queues an [`Action::Enumerate`] for `dir` and moves it to
  /// [`NodeState::Enumerating`] under the fresh request, recording `kind` (discovery vs
  /// re-arm) and the carried retry `attempts`.
  ///
  /// A node awaits at most ONE read — [`NodeState::Enumerating`] names exactly
  /// one request — so a read queued over an outstanding one SUPERSEDES it, and
  /// the superseded request must leave the reverse map with it or it is
  /// stranded there for the node's whole life (the drop walk reclaims only the
  /// request the node still names). Superseding is reached where a reconcile
  /// re-enters the very directory it is reconciling: a retirement inside
  /// [`handle_incomplete_enumerate`](Self::handle_incomplete_enumerate)'s pass
  /// can stand a counted cover, whose root re-arm reads the node this call is
  /// about to queue the bounded retry for. The retry wins, deliberately — it
  /// carries the retry budget, and the cover's re-arm would reset it and let a
  /// permanently unreadable directory spin.
  fn queue_enumerate(&mut self, dir: WatchId, kind: EnumKind, attempts: u8) {
    let Some(state) = self.nodes.get(&dir).map(|node| node.state) else {
      return;
    };
    if let NodeState::Enumerating { req: prior, .. } = state {
      self.pending_enumerate.remove(&prior);
      self.latent_cold.remove(&prior);
    }
    let req = self.next_req_id();
    self.pending_enumerate.insert(req, dir);
    // The read is addressed by handle but lowered to a path; stamp the placement
    // it is issued at, so a listing of the vacated path cannot reconcile this
    // directory's slots (see [`placement_now`](Self::placement_now)).
    let placement = self.placement_now();
    if let Some(node) = self.nodes.get_mut(&dir) {
      node.placement = placement;
    }
    self.set_state(
      dir,
      NodeState::Enumerating {
        req,
        kind,
        attempts,
        dirty: false,
      },
    );
    self.actions.push_back(Action::enumerate(req, dir));
  }

  /// Begins a rescan re-arm of `dir`, coalesced without losing the obligation. A live,
  /// idle directory ([`NodeState::Live`]) starts the read; a node with a read ALREADY
  /// outstanding does not stack a second request — but its in-flight snapshot predates
  /// this trigger, so it is DIRTIED: the result is then handled as untrusted (reconcile
  /// what is visible, then a re-arm retry) instead of being swallowed as a clean read
  /// whose listing may omit everything the trigger is about. A pending or dead node has
  /// nothing to read yet — a pending one's post-arm enumerate carries the obligation.
  /// A no-op on a non-descending scope (or a dead `dir`).
  ///
  /// Reports how the obligation was recorded — see [`RearmKickoff`]: dirtying an
  /// in-flight **cold** read is [`Coalesced`](RearmKickoff::Coalesced) (the obligation
  /// rides a read [`rearm_settled`](Self::rearm_settled) does not count until its
  /// completion escalates), while dirtying an in-flight re-arm read is
  /// [`Started`](RearmKickoff::Started) (that read is already counted).
  fn start_rearm(&mut self, dir: WatchId) -> RearmKickoff {
    let Some(scope) = self.scope_of(dir) else {
      return RearmKickoff::Refused;
    };
    if !self.scope_descends(scope) {
      return RearmKickoff::Refused;
    }
    match self.nodes.get(&dir).map(|node| node.state) {
      Some(NodeState::Live) => {
        self.queue_enumerate(dir, EnumKind::Rearm { reprove: false }, 0);
        RearmKickoff::Started
      }
      // Dirty the in-flight read AND reset its retry budget: the bounded ceiling is
      // per OBLIGATION, not per node lifetime. A fresh trigger coalescing onto a read
      // whose earlier incomplete completions already exhausted `attempts` must still
      // get its post-trigger retry — a record race, by contrast, needs no reset, since
      // the racing record's own slot reconciliation installs the coverage directly.
      Some(NodeState::Enumerating { req, kind, .. }) => {
        self.set_state(
          dir,
          NodeState::Enumerating {
            req,
            kind,
            attempts: 0,
            dirty: true,
          },
        );
        // A dirtied re-arm read is already a counted obligation; a dirtied COLD read
        // hides this trigger from the settle counter until its completion escalates —
        // so it is tracked latent, holding the scope's barrier fence
        // (`coverage_settled`) across the one window where `rearm_settled` reads
        // true while a re-walk obligation is in flight.
        match kind {
          EnumKind::Cold => {
            self.latent_cold_insert(req, scope);
            RearmKickoff::Coalesced
          }
          EnumKind::Rearm { .. } => RearmKickoff::Started,
        }
      }
      _ => RearmKickoff::Refused,
    }
  }

  /// Transfers a re-arm obligation onto `watch` — a watch that has just replaced a
  /// mid-re-arm one, or a surviving child cascaded during an incomplete parent read.
  /// Reports how the obligation was recorded ([`RearmKickoff`]); cascade-internal
  /// callers discard it (a cascade's own counted work keeps the scope unsettled
  /// through any coalesced sibling's completion).
  fn inherit_rearm(&mut self, watch: WatchId) -> RearmKickoff {
    match self.nodes.get(&watch).map(|node| node.state) {
      // Live (idle or enumerating): start_rearm reads now or dirties the in-flight read.
      Some(NodeState::Live) | Some(NodeState::Enumerating { .. }) => self.start_rearm(watch),
      // Still arming: its post-arm enumerate must continue the re-arm, so mark it —
      // a counted obligation (`Arming { rearm: true }`). A reprove flavor
      // already on the node rides along untouched (with its stamp).
      Some(NodeState::Arming { reprove, .. }) => {
        self.set_state(
          watch,
          NodeState::Arming {
            rearm: true,
            reprove,
          },
        );
        RearmKickoff::Started
      }
      // Dead — nothing to transfer.
      _ => RearmKickoff::Refused,
    }
  }

  /// Rebuilds `dir`'s direct children against a COMPLETE fresh enumerate during a
  /// rescan re-arm — all without emitting `Created` (the consumer re-scans content off
  /// the `Rescan`). This is the second half of the overflow dual obligation: re-walk to
  /// re-arm the proto's own watch set, so a subtree created during the overflow gap is
  /// not left unwatched. Incomplete reads route to
  /// [`handle_incomplete_enumerate`](Self::handle_incomplete_enumerate) instead.
  ///
  /// Overflow can hide a same-name delete+recreate, so this diffs the retained watch
  /// set against the fresh listing by object identity: a child whose identity is
  /// confirmed unchanged keeps its watch (re-armed downward to catch new grandchildren),
  /// while one whose name vanished, whose identity changed, or whose identity cannot be
  /// confirmed is dropped and its slot rebuilt. Absent any identity this degrades to
  /// rebuilding every affected child — the safe default.
  ///
  /// Retiring a watch ends coverage a record may already be queued against, so a crawl
  /// that retires ANY slot stands ONE opening `Rescan` at the crawled directory —
  /// coalesced across the whole listing, never per child. The obligation is stated
  /// so that SILENCE is the case that must be earned: every retirement owes the
  /// cover, and only a retirement whose successor this crawl PROVES it rebuilds
  /// (counted) may defer to the window's closing `Rescan` instead. A crawl that
  /// retires nothing emits nothing.
  ///
  /// A name the listing leaves unclassifiable retires nothing here: its incumbent
  /// keeps its watch and its coverage, and the decision passes to the slot's stat
  /// ([`settle_stat_slot`](Self::settle_stat_slot)). The descent this crawl owes
  /// that incumbent is booked against the INCUMBENT
  /// ([`owed_descents`](Self::owed_descents)), so a rename that empties the slot
  /// before the answer lands carries the obligation with the subtree instead of
  /// stranding it at a coordinate nothing occupies.
  ///
  /// A `reprove`-flavored read tightens the survivor rule: an identity match
  /// proves only that the NAME still holds the same object, never that OUR
  /// watch is still its live binding (an unmount+same-fs-remount matches every
  /// identity over a tree of dead watches), so each kept survivor is RE-ADDED
  /// ([`start_reinstall`](Self::start_reinstall)) rather than merely re-read.
  /// Fresh installs are unchanged either way — their install acknowledgement
  /// is their proof, and a fresh node has no retained descendants to flavor.
  fn rearm_enumerate(
    &mut self,
    dir: WatchId,
    scope: ScopeId,
    res: &EnumerateResult,
    reprove: bool,
  ) {
    // Index the fresh listing's directories by name → identity.
    let present: BTreeMap<Segment, Option<Identity>> = res
      .entries()
      .iter()
      .filter(|entry| entry.is_dir())
      .map(|entry| (entry.name().clone(), entry.node()))
      .collect();
    // Names the listing could not classify. They are absent from `present`, but that
    // absence is ignorance, not a vanish: pruning an incumbent watch on it would
    // silently un-cover a live directory, and leaving the name unwatched would blind a
    // new one. Both are settled out of band by the slot's stat.
    let unsettled: BTreeSet<Segment> = res
      .entries()
      .iter()
      .filter(|entry| entry.kind().is_unknown())
      .map(|entry| entry.name().clone())
      .collect();
    // Diff the retained watch set against it. An in-slot child whose object identity is
    // confirmed still present SURVIVES — its watch is kept and only re-armed downward to
    // catch new grandchildren. One whose name vanished, whose identity changed (a
    // same-name replacement), or whose identity cannot be confirmed is dropped. With no
    // identity available this degrades to the conservative rebuild-everything path.
    let existing: std::vec::Vec<WatchId> = self
      .nodes
      .get(&dir)
      .map(|node| node.children.iter().copied().collect())
      .unwrap_or_default();
    // The crawl's cover obligation, in the shape that makes SILENCE the case that
    // must be earned (see the emit below). `retired` is the bare fact that this
    // crawl ended coverage of SOMETHING; `rebuilt_every_retirement` starts true and
    // is cleared by any retirement whose counted successor the crawl cannot prove.
    // Stated the other way round — as a list of the retirement flavors that do owe
    // a cover — an entry kind nobody enumerated would set no flag and default to
    // silence, which is exactly how a coverage loss hides.
    let mut retired = false;
    let mut rebuilt_every_retirement = true;
    for child in existing {
      // A detached-and-held move source is not in its name-slot; leave it to be
      // reparented by its pending MovedTo rather than rebuilt.
      if !self.is_slot_child(dir, child) {
        continue;
      }
      let name = self.nodes.get(&child).and_then(|node| node.name.clone());
      // An unsettled name keeps its watch and its coverage until the stat answers;
      // the reconcile pass below asks for its kind.
      if name.as_ref().is_some_and(|name| unsettled.contains(name)) {
        continue;
      }
      let survives = name
        .as_ref()
        .and_then(|name| present.get(name).copied())
        .is_some_and(|fresh| self.identity_matches(child, fresh));
      if survives {
        if reprove {
          self.start_reinstall(child);
        } else {
          let _ = self.inherit_rearm(child);
        }
      } else {
        retired = true;
        // The ONE positive proof of a counted successor: the fresh listing still
        // shows this name as a DIRECTORY, so the install loop below rebuilds it and
        // `inherit_rearm`s the rebuild into `Arming { rearm: true }`. Anything else
        // — a name the listing omits, one it reports as a non-directory, one of a
        // kind this crawl has no branch for, or a nameless child no listing can be
        // matched against — leaves the flag cleared and so keeps the cover
        // unconditional. (`is_slot_child` above already proves the name is present;
        // the nameless fallback is the safe direction.)
        rebuilt_every_retirement &= name.as_ref().is_some_and(|name| present.contains_key(name));
        self.drop_subtree_for_crawl_rebuild(child);
      }
    }
    // Cover the coverage this crawl RETIRED. EVERY retirement owes it: the drop tears
    // down every `WatchId` in the dropped subtree while records naming them may already
    // sit queued on the backend — `ingest_record` discards those as an unrecognized
    // watch — and every structural signal that could stand in for them is interest- and
    // filter-subject (the vanish's `Removed`, which may itself be one of the discarded
    // records, and the rebuild's suppressed `Created`), so a `Modified`-only
    // subscription would be instructed to re-read nothing at all. The re-anchor above
    // carries only an ERASED deficit; a deficit-free subtree carries nothing.
    //
    // The ONE excuse for silence is a COUNTED SUCCESSOR inside an already-lossy window,
    // and it must be proven for every retirement this crawl made, not for some:
    //
    // - a retirement the crawl rebuilds is counted (every install is `inherit_rearm`ed
    //   into `Arming { rearm: true }`, so the window's `fresh_rearm` half is this
    //   crawl's own), which leaves only the loss half to supply. Every entry into this
    //   crawl but one arrives with it already set — an overflow recovery, a loss or
    //   incomplete-read re-arm, a rebind commit each stand their `Rescan` before the
    //   read they trigger — so the gap is exactly the PURE grow
    //   (`rearm_watch_subtree`), which stands none. A window already marked lossy
    //   closes with a root `Rescan` that postdates this retirement by construction, so
    //   a second one there adds no instruction.
    //
    // - a retirement the crawl does NOT prove it rebuilds arms no fresh coverage for
    //   the slot, so the window's `fresh_rearm` half is not its to supply. That makes
    //   the `bridge_is_lossy` shortcut unavailable rather than merely conservative — a
    //   site that does not also make the window counted must emit, because the
    //   conjunction it would defer to may never fire (see `bridge_is_lossy`). One such
    //   retirement in the crawl is enough to owe the whole crawl's cover.
    //
    // ONE opening `Rescan` per crawl, at the crawled directory, NOT one per child and
    // not one per flavor: an identity-less backend can confirm NO child, so a per-child
    // emit would storm one `Rescan` per entry of every re-armed listing. A crawl that
    // retires nothing owes nothing, so an ordinary prune-free grow stays silent.
    if retired && !(rebuilt_every_retirement && self.bridge_is_lossy(scope)) {
      self.emit_rescan(scope, self.location_of(dir));
    }
    // Install a fresh watch for every present directory now lacking one (a survivor keeps
    // its own; this covers vanished-then-new, replaced, and genuinely new names), marked
    // to continue the re-arm so its subtree rebuilds recursively.
    for entry in res.entries() {
      if !entry.is_dir() {
        continue;
      }
      if self.child_watch(dir, entry.name()).is_none() {
        let _ = self.install_child(dir, scope, entry.name().clone(), true, entry.node());
        if let Some(fresh) = self.child_watch(dir, entry.name()) {
          let _ = self.inherit_rearm(fresh);
        }
        // The occupation check above IS the fresh/survivor distinction, so the
        // registration window's loss half is stated right here — a survivor
        // re-armed by the branch above never reaches it. Named install site #1;
        // see `mark_bootstrap_loss`.
        self.mark_bootstrap_loss(scope);
      }
    }
    // Book every unclassifiable name as darkness and ask for its kind — and hand that
    // stat the descent this crawl OWED the name's incumbent and skipped above. The
    // skip is the only branch that leaves a retained subtree un-re-armed: without the
    // hand-off the crawl would settle with the survivor's descendants never revisited,
    // and a directory created under one during the gap would stay unwatched with
    // nothing booked to say so. The reprove flavor rides along, since a survivor the
    // stat confirms is a retained node whose binding this read cannot vouch for.
    for entry in res.entries() {
      if entry.kind().is_unknown() {
        let _ = self.reconcile_slot(
          dir,
          scope,
          entry.name(),
          SlotOccupant::Unknown,
          false,
          entry.node(),
        );
        self.defer_stat_descent(
          dir,
          entry.name(),
          if reprove {
            StatDescent::Reprove
          } else {
            StatDescent::Rearm
          },
        );
      }
    }
  }

  /// Resolves a pending same-transport adoption edge against `dir`'s first
  /// COMPLETE read: the adopted slot's only unwatched window is the widen's
  /// commit→arm gap, so this one verification closes the no-silent-loss hole
  /// that gap opens for the OBJECT the widen adopted — what the slot's path
  /// resolved to across the gap is a separate assumption, stated under
  /// **confirmed** below. Every complete read decides the marker; the outcomes:
  ///
  /// - **confirmed** — the ADOPTED WATCH still occupies the slot, the listing
  ///   names that slot as a directory, and the entry's identity POSITIVELY
  ///   equals the one the widen adopted it under
  ///   ([`AdoptionMarker::identity`]): the edge reads verified, and the marker
  ///   is STAGED rather than released. Strict, not permissive: this is a
  ///   re-proof, not a discovery, so ignorance confirms nothing — the same
  ///   polarity `rearm_enumerate` re-proves its survivors under, where an
  ///   identity-less backend can confirm NO child. The expected side is known by
  ///   construction ([`widen_root`](Self::widen_root) refuses an identityless
  ///   widen), so what this rejects is a LISTING that cannot name what it found
  ///   — and, through the occupancy conjunct, a listing that names a REPLACEMENT
  ///   perfectly well. An object that merely inherited the name discharges
  ///   nothing.
  ///
  ///   A SNAPSHOT of the window's END is admissible as a proof about the WHOLE
  ///   window only once every record of the window that could refute it has been
  ///   ingested — and *this listing's completion is not that moment*. Both
  ///   conjuncts are restored by an object that leaves the adopted slot and
  ///   returns before the read (the link is only rewritten by an observed move,
  ///   and the identity comes back with the object), so what refutes the
  ///   interval is the object's own [`RecordKind::MoveSelf`]
  ///   ([`on_move_self`](Self::on_move_self) spends the marker on it) — and that
  ///   record may still be sitting unread in the kernel's queue when this
  ///   listing lands, because the listing is taken off the reader entirely and
  ///   its completion is reported on a channel the driver polls ahead of the
  ///   source lane. The trigger structurally outruns the evidence.
  ///
  ///   So the confirming direction — and only it, since a refutation needs no
  ///   fence — waits: the marker stands STAGED
  ///   ([`staged_adoptions`](Self::staged_adoptions)) and its verdict is taken
  ///   by [`seal_staged_adoptions`](Self::seal_staged_adoptions) behind a reader
  ///   queue cut requested after this listing was ingested. Everything the
  ///   kernel held is then on the lane ahead of the cut's own reply, and one
  ///   scope's records are FIFO from one queue, so by the seal the refuting
  ///   record has already spent this marker. A marker that survives to the seal
  ///   therefore says the adopted OBJECT held the slot throughout, not merely
  ///   that it holds it now — with a `MoveSelf` lost to an overflow healed by
  ///   that overflow's scope-wide `Rescan` and counted re-arm, as every lost
  ///   record is. What it does not say is that the PATH named that object
  ///   throughout: a mount raised over the slot and dropped again inside the
  ///   window moves no inode and unmounts no filesystem, so it emits no record
  ///   to spend the marker and leaves the slot reading unchanged
  ///   ([`seal_staged_adoptions`](Self::seal_staged_adoptions)).
  /// - **stale edge** — the adopted watch is alive but the proof fails: the
  ///   name vanished from the complete listing, or the listing cannot
  ///   positively match it (a different object, or no identity at all), or the
  ///   watch is no longer in that slot at all (a `MovedFrom` detached it, or a
  ///   replacement took the vacated name). Its true path is then unknowable to
  ///   the proof (the moved-root problem — its descendants would keep delivering
  ///   at reconstructed paths nothing confirmed), so escalate the scope root —
  ///   one epoch-bumped covering
  ///   `Rescan` plus a counted re-arm — and, INSIDE that cover, DROP the
  ///   adopted subtree. Loud, D1-equivalent, never silent. It runs through
  ///   [`stand_counted_cover`](Self::stand_counted_cover) rather than the bare
  ///   rescan-and-rearm because THIS read is what released the adoption
  ///   conjunct that was holding
  ///   [`coverage_settled`](Self::coverage_settled) down: a re-arm the root's
  ///   own state can refuse — a widen's spliced root is `Arming` until its
  ///   pre-arm outcome is replayed, and a chain tail can complete its first
  ///   read before that — would leave the released barrier resting on nothing
  ///   while the stale edge still stands. Retiring the edge is likewise this
  ///   branch's own work and not the re-arm's to inherit: every later
  ///   reconciliation of that slot is PERMISSIVE where this proof is strict, so
  ///   an edge handed on would be retained rather than replaced (see the drop
  ///   below).
  /// - **recorded death** — the adopted WATCH is gone (its own self-events tore
  ///   it down mid-window) with no parent watch armed to mint the parent-side
  ///   `Removed`: stand a located `Rescan` at the vacated slot so the
  ///   consumer's re-read converges the ghost. Nothing unproven survives — the
  ///   edge cannot outlive its object — so no retirement is owed. A re-occupied
  ///   slot additionally installs through the caller's ordinary reconcile.
  ///
  /// The reading is taken on every complete read, whatever flavor queued it —
  /// a re-arm crawl is coverage machinery, never a substitute proof. It
  /// re-proves only what its listing CLASSIFIES: a name reported `Unknown`
  /// retires nothing (pruning on ignorance would un-cover a live directory)
  /// and defers to the slot's stat, which answers through the permissive
  /// reconcile and so KEEPS an incumbent it cannot positively displace — as
  /// does a stat that fails, and as does one no driver ever answers. An edge
  /// handed to that machinery is therefore retained rather than replaced,
  /// while the marker this read spent has already released the barrier
  /// conjunct that was holding [`coverage_settled`](Self::coverage_settled)
  /// down. So the decision is made HERE, and made BEFORE the crawl runs: the
  /// crawl then reconciles that name against an EMPTIED slot and installs into
  /// it, rather than meeting the subtree this read just refused to confirm.
  ///
  /// A HELD completion takes no verdict — and that arm is a standing guard, not
  /// a live path. A hold already costs the listing its evidence status
  /// (`Lowering::is_evidence`), so such a read never reaches here at all: it
  /// routes to the incomplete handler, which KEEPS the marker and re-reads, and
  /// only the bounded retries' exhaustion releases it. The guard states what
  /// the verdict would be if a held listing were ever admitted, and why it is
  /// none: that listing came from the path the subtree has LEFT, so it
  /// describes whatever now stands there and could confirm or refute the
  /// adopted edge only by accident.
  ///
  /// It is written as a DISPOSAL rather than a bare return
  /// ([`CountedRetirement`](AdoptionDisposal::CountedRetirement), the same one
  /// the exhaustion site takes) because a guard whose failure mode is a silent
  /// release is not a guard. Neither of the covers a hold does carry can be
  /// borrowed here: the hold's own barrier conjunct
  /// ([`holds_settled`](Self::holds_settled)) is released by the pairing
  /// without ever looking at this edge, and the destination `Rescan` and re-arm
  /// that reading under a hold books against that pairing
  /// ([`fence_lowering`](Self::fence_lowering)) reconcile PERMISSIVELY — they
  /// retain an incumbent they cannot classify, which is precisely the unproven
  /// edge. Only a counted cover that also EMPTIES the slot answers a released
  /// marker no read ever proved.
  ///
  /// Only the confirm waits. The refuting outcomes release the marker at this
  /// completion, unfenced and unchanged, because an ordering proof buys nothing
  /// for a conservative answer: a late record that would have refuted an edge
  /// this read already refused costs work, never correctness, whereas the
  /// confirm is the one direction whose match must mean the interval was clean.
  ///
  /// `dir` — the directory whose read this is, and the caller's next several
  /// steps' only subject — is untouched by every outcome: the one destructive
  /// outcome retires the adopted WATCH, which the containment invariant keeps a
  /// direct CHILD of `dir` (see [`pending_adoptions`](Self::pending_adoptions)).
  fn resolve_adoption(&mut self, dir: WatchId, scope: ScopeId, held: bool, res: &EnumerateResult) {
    if held {
      let _ = self.release_adoption_marker(dir, scope, AdoptionDisposal::CountedRetirement);
      return;
    }
    let Some(marker) = self.pending_adoptions.get(&dir).cloned() else {
      return;
    };
    // The proof is owed by the ADOPTED WATCH, so that is what is looked up —
    // never "whoever holds the slot now". A watch already destroyed is the
    // recorded-death case below; a live one is proven or retired, wherever a
    // rename has since put it.
    if !self.nodes.contains_key(&marker.adopted) {
      let _ = self.release_adoption_marker(dir, scope, AdoptionDisposal::Verdict);
      self.emit_rescan(scope, self.location_of(dir).child(marker.name));
      return;
    }
    let entry = res
      .entries()
      .iter()
      .find(|entry| *entry.name() == marker.name);
    // Three conjuncts, and a replacement fails the first of them: the adopted
    // watch must STILL hold the slot the listing is about, the entry must be a
    // directory, and its identity must be the one the widen named. Confirming
    // on the slot's current occupant would let an object that merely inherited
    // the name discharge another object's debt — which is the whole shape of a
    // dark-window substitution.
    let confirmed = self.child_watch(dir, &marker.name) == Some(marker.adopted)
      && entry.is_some_and(|entry| entry.is_dir() && entry.node() == Some(marker.identity));
    if confirmed {
      // STAGED, not released: the confirming direction is the one that needs an
      // ordering fence behind it, and the marker keeps standing — holding the
      // barrier, refusing the reparent, spendable by the very record that would
      // refute it — until [`seal_staged_adoptions`](Self::seal_staged_adoptions)
      // takes the verdict behind an answered cut.
      //
      // A read meeting a marker already staged reaches here too, and leaves the
      // stamp where it is (see [`stage_adoption`](Self::stage_adoption)). Only
      // the FIRST confirming listing is ever the confirm — the cut requested
      // behind it is the one that orders its window — so a later listing can
      // refute (above), and can add nothing.
      self.stage_adoption(dir, scope);
      return;
    }
    let _ = self.release_adoption_marker(dir, scope, AdoptionDisposal::Verdict);
    // The cover FIRST, then the coverage it covers ends — a `Rescan` that
    // postdates the disarm instructs nobody about the interval between.
    self.stand_counted_cover(scope);
    // The retirement is not optional and not deferrable. Leaving the unproven
    // edge standing for a later reconciliation to replace asks a PERMISSIVE
    // decision to finish a STRICT one, and it does not: a name the re-arm
    // crawl cannot classify is deliberately not diffed at all (pruning an
    // incumbent on ignorance would un-cover a live directory), so it
    // defers to the slot's stat — whose `Dir` answer without an identity is
    // no positive difference and therefore KEEPS the incumbent, exactly as
    // a stat that fails or never arrives keeps it. The edge this branch
    // just refused to confirm would then survive its own escalation, its
    // descendants still delivering at reconstructed-stale paths with the
    // barrier settled. A retired subtree has no such ambiguity: every one of
    // those paths installs fresh.
    //
    // And it retires the ADOPTED WATCH, not the slot's current occupant. When
    // the two have parted — a rename in the window, with something else grown
    // into the name — retiring the occupant would disarm an object with a
    // perfectly good coverage story while leaving the unproven one alive
    // under its new path, which is the failure inverted rather than fixed.
    //
    // `CoveringRescan` for the erased darkness, like every other drop whose
    // object may well still exist: the structural signals are interest- and
    // filter-subject, so the window's closing `Rescan` is what covers the
    // dark interval. No located `Rescan` of its own — the root one stood
    // just above already re-instructs this slot, and the same read's
    // ordinary reconcile is the next thing to touch it.
    //
    // And it is SUBTREE-LOCAL: the adopted watch is a direct child of `dir`
    // by the containment invariant, so this drop leaves `dir` — the directory
    // the caller goes on reconciling this very listing into — standing.
    self.retire_adopted(marker.adopted, dir);
  }

  /// Handles the result of an [`Action::Watch`].
  ///
  /// On success the node becomes live and — when the core descends and the node
  /// is a directory — an [`Action::Enumerate`] is queued. The ordering "watch
  /// armed strictly before readdir" is a state-machine invariant, so the
  /// enumerate is only ever queued *after* this success. The
  /// [`WatchAck`](crate::WatchAck) says HOW the arm bound: for a binding
  /// re-proof (a loss-triggered re-add on a
  /// [`lossy_watch_teardown`](Capabilities::lossy_watch_teardown) profile) an
  /// [`Installed`](crate::WatchAck::Installed) proves the old binding was dead
  /// or rebound — a dark window the settle edge's closing `Rescan` must cover —
  /// while an [`Aliased`](crate::WatchAck::Aliased) proves it was live all
  /// along; for a first-time install the distinction carries nothing. A
  /// reprove `Ok` counts only when the arm was issued under the scope's
  /// CURRENT loss generation: a stale acknowledgement may certify a binding a
  /// later loss killed with its teardown swallowed, so the watch action is
  /// re-issued and the node stays pending.
  ///
  /// Every non-success result is treated as coverage loss: the node and its
  /// subtree are dropped and a [`ChangeKind::Rescan`] is emitted for the affected
  /// location, so a caller never believes a subtree is watched when the kernel
  /// refused the watch. This covers all [`WatchError`] variants uniformly — a
  /// watch-limit refusal, a permission denial, a vanished target, or any other
  /// I/O failure — none may leave a node registered-but-not-live and silent.
  ///
  /// `attempt` is the [`ArmAttempt`] the answered arm carried — read off its
  /// [`WatchCommand`](crate::WatchCommand), or returned by the out-of-band
  /// re-arm that replaced it ([`rebind_root`](Self::rebind_root),
  /// [`widen_root`](Self::widen_root)). A result for any OTHER attempt answers
  /// an arm some later one superseded and is DISCARDED: a `WatchId` outlives
  /// its bindings, so without the fence a late `Err` from a retired transport
  /// would tear down the live rebound root that arm never touched. Because the
  /// token is minted per arm and captured at issue time, a driver gets the
  /// fence by echoing what it was handed — there is nothing left for it to
  /// reinvent.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn on_watch_result(
    &mut self,
    id: WatchId,
    attempt: ArmAttempt,
    res: Result<crate::WatchAck, WatchError>,
  ) {
    self.ingest_watch_result(id, attempt, res);
    self.settle_bridges();
  }

  /// [`on_watch_result`](Self::on_watch_result) minus the public entry
  /// point's bridge flush — a failed arm's drop can be the settle edge.
  fn ingest_watch_result(
    &mut self,
    id: WatchId,
    attempt: ArmAttempt,
    res: Result<crate::WatchAck, WatchError>,
  ) {
    let Some(node) = self.nodes.get(&id) else {
      return;
    };
    // The supersession fence, ahead of every effect: an outcome that does not
    // name the arm this handle is currently bound to is old-world — its target
    // binding was replaced by the arm that superseded it, and applying either
    // verdict would judge a binding the attempt never observed.
    if node.attempt != attempt {
      return;
    }
    let scope = node.scope;
    let is_dir = node.is_dir;
    let placement = node.placement;
    let state = node.state;
    // The LOWERED-PATH fence, which the supersession fence above cannot subsume:
    // supersession catches a rename of THIS node's own slot (the Monitor can
    // compute where the arm should have gone, and re-issues it there), while a
    // rename of an ANCESTOR leaves this node's `(parent, name)` — and so its
    // attempt — untouched even though the path the driver opened is now
    // somebody else's. The hold is the second clause the clock can never see: a
    // detached-and-held move source reconstructs at its pre-move path for the
    // whole pairing window BY DESIGN, so a coordinate lowered anywhere in its
    // subtree was born addressed at a slot the object has already left, with no
    // later move for the clock to catch. [`Lowering::is_evidence`] asks both
    // clauses, once, here.
    let lowering = self.fence_lowering(id, placement);
    // CERTIFY OR RETIRE — the whole rule this seam applies to a success, and the
    // reason there is no third state between "proven" and "gone".
    //
    // An `Ok` reports that a kernel binding was installed at the path the driver
    // LOWERED; `is_evidence` says whether that path is this node's. When it is
    // not, the acknowledgement certifies nothing — it is proof about whatever
    // occupies a slot this node has left. A binding nothing may certify may not
    // be KEPT either: every record it produces would be attributed to the node's
    // current path, as a false change there or as a retirement of coverage the
    // real object carries, and no later `Rescan` retracts a delivered change. So
    // the binding is RETIRED, and the retirement pays the cover and the counted
    // replacement it owes
    // ([`retire_unprovable_binding`](Self::retire_unprovable_binding)).
    //
    // Retiring the BINDING is not refusing to ARM. Arming inside a held subtree
    // is the design's own best-effort coverage — it is what keeps a gap-created
    // descendant of a mid-move source watched — so the arm is still issued and
    // still answered here; what this declines is to call the answer proof.
    //
    // A non-`Arming` node is left alone: its arm already resolved, so this is a
    // duplicate or late outcome that established nothing to retire.
    if res.is_ok() && !lowering.is_evidence() && matches!(state, NodeState::Arming { .. }) {
      self.retire_unprovable_binding(id, scope, &lowering);
      return;
    }
    if lowering.moved {
      // A FAILURE is the case where discarding the verdict IS the whole
      // recovery: a refused arm created no binding, so nothing is left behind
      // it — and the `Err` may not stand either, since it would retire a node
      // whose object is alive and armable at its new location. The obligation is
      // re-issued at wherever the node sits now
      // ([`readdress_outstanding_arm`](Self::readdress_outstanding_arm), the
      // same funnel a re-slotted arm uses, so a reprove arm keeps its loss
      // stamp).
      //
      // Re-issuing rather than retiring is what keeps the node LIVE-bound: an
      // `Arming` node with no arm outstanding is counted work nothing would ever
      // release, and no re-arm cascade re-issues an arm (they only flavor one).
      // It terminates because each re-issue is stamped with the current reading,
      // and only a further move ON ITS OWN CHAIN can invalidate it again.
      self.readdress_outstanding_arm(id);
      return;
    }

    match res {
      Ok(ack) => {
        // Only a pending (Arming) watch transitions to live. A duplicate or late `Ok` on
        // an already-armed node is ignored, not replayed: resetting it to `Live` would
        // clobber an outstanding `Enumerating` read and orphan its request.
        let NodeState::Arming { rearm, reprove } = state else {
          return;
        };
        if reprove {
          // A re-established binding is the positive proof of a dark window:
          // between the loss and this install nothing recorded the subtree,
          // so the settle edge owes the closing `Rescan` (the bit deliberately
          // NOT set at entry for a reprove arm). Set even when the stamp below
          // is stale — the window this ACK witnessed was real regardless, and
          // the settle edge always postdates the final counted ACK.
          if ack.is_installed() {
            self.bridge_fresh_rearm(scope);
          }
          // The ACK-postdates-loss stamp: an arm issued before the scope's
          // latest loss may certify a binding that loss killed with its
          // teardown swallowed. Such an `Ok` is not proof — re-issue the
          // watch under the current generation and stay pending. Bounded by
          // the transport's per-ack-cycle loss dedup: each re-issue consumes
          // one loss edge.
          if self.reprove_stamps.get(&id).copied() != Some(self.loss_gen(scope)) {
            self.queue_reinstall(id, scope);
            return;
          }
          self.reprove_stamps.remove(&id);
        }
        // Every `Ok` that certifies a binding lowered at the node's own path,
        // by construction: an unprovable one was retired above and returned, so
        // there is no third state here to reason about. Stated rather than
        // assumed — the whole class this seam exists for is an acknowledgement
        // taken as proof of a path it never described.
        debug_assert!(
          lowering.is_evidence(),
          "a certifying acknowledgement lowered at the node's own path"
        );
        self.set_state(id, NodeState::Live);
        if is_dir && self.scope_descends(scope) {
          // Continue a rescan re-arm into this freshly-armed directory if it was
          // installed as part of one. A HELD node needs no clause of its own: an
          // acknowledgement taken under a hold never certifies (it is retired
          // above), so no node reaches here inside one, and the cold read this
          // queues therefore cannot be a held-origin read whose flavor a later
          // pairing would strand.
          if reprove {
            // A re-proved binding's read carries the flavor on: its kept
            // survivors are re-added in turn, so the proof reaches the leaves.
            self.queue_enumerate(id, EnumKind::Rearm { reprove: true }, 0);
          } else if rearm {
            let _ = self.start_rearm(id);
          } else {
            self.queue_enumerate(id, EnumKind::Cold, 0);
          }
        }
      }
      // A failed install must not leave a silent blind spot: reconstruct the location
      // while the node still exists, emit a `Rescan`, then drop it. But a node that is
      // held (a pending source or descendant detached mid-move) has a STALE pre-move
      // location, so it may not be Rescanned there — the fence already dirtied the
      // enclosing hold, and the pairing reparent re-scans the destination. Drop the
      // failed node either way.
      Err(_) => {
        if !lowering.locatable() {
          self.drop_subtree(id, DeficitDischarge::CoveringRescan);
        } else if self.is_root_watch(id) {
          // A refused ROOT install is a root invalidation like any other: Rescan, then
          // drop the tree AND purge the scope's pending halves.
          self.emit_rescan(scope, self.location_of(id));
          self.invalidate_root(scope, id);
        } else {
          self.emit_rescan(scope, self.location_of(id));
          // The refused slot is a LEVEL-PERSISTENT hole: the `Rescan` above
          // covers only changes up to now, while the on-disk directory stays
          // dark until something re-occupies or re-arms the slot. Record it
          // (both links are `Some` — the node is a non-root) so every sync
          // cookie dispatched over the darkness re-signals it first.
          if let Some((parent, name)) = self
            .nodes
            .get(&id)
            .and_then(|node| node.parent.zip(node.name.clone()))
          {
            self.record_slot_deficit(scope, parent, name);
          }
          self.drop_subtree(id, DeficitDischarge::CoveringRescan);
        }
      }
    }
  }

  /// Retires the binding an unprovable acknowledgement reported, and rebuilds
  /// the coverage that retirement ends — the entire discharge of the
  /// certify-or-retire rule ([`ingest_watch_result`](Self::ingest_watch_result)).
  ///
  /// # Why the binding dies rather than waits
  ///
  /// The alternative is to keep the node live and suppress everything riding its
  /// binding until a later acknowledgement re-proves it. That needs a marker with
  /// its own lifetime, a bounded release for every path that marker can survive
  /// on, and a barrier conjunct so no sync certifies over the suppressed window —
  /// three things that must agree, at every site that can move, drop or re-arm the
  /// node. Death needs none of them: the queued [`Action::Unwatch`] ends the
  /// kernel binding, records already in flight against the handle are discarded by
  /// [`ingest_record`](Self::ingest_record)'s opening `scope_of` (an unknown
  /// watch), and there is no interval between the unprovable `Ok` and the
  /// retirement for a barrier to observe — they are the same call.
  ///
  /// # What it costs, and what it deliberately does not
  ///
  /// The teardown reaches only the individually doubtful FRONTIER binding — a node
  /// whose own arm was in flight when the path moved under it, typically a leaf
  /// with no children yet. The subtree a rename CARRIES is untouched: the O(1)
  /// reparent re-keys one link, and nothing here walks it.
  fn retire_unprovable_binding(&mut self, id: WatchId, scope: ScopeId, lowering: &Lowering) {
    // A ROOT has no slot to rebuild and no parent to cover at — its lowered path
    // IS the scope's ground — so an acknowledgement that does not describe it is
    // a root invalidation like a refused root install: `Rescan` first, so the
    // loss is never silent, then drop the tree and the scope's pending halves.
    let Some((parent, name, is_dir, identity)) = self.nodes.get(&id).and_then(|node| {
      node
        .parent
        .zip(node.name.clone())
        .map(|(parent, name)| (parent, name, node.is_dir, node.identity))
    }) else {
      self.emit_rescan(scope, self.location_of(id));
      self.invalidate_root(scope, id);
      return;
    };
    self.drop_subtree(id, DeficitDischarge::CoveringRescan);
    // Under a hold there is no location this call may address: the tree
    // reconstructs the vacated PRE-move path for the whole pairing window, so a
    // `Rescan` emitted here would send the consumer to re-read a slot the object
    // has left, and a replacement armed here would lower to that same slot and be
    // retired again on its own acknowledgement. Defer the REBUILD, not the ISSUE:
    // [`fence_lowering`](Self::fence_lowering) has already dirtied the enclosing
    // hold, and the pairing's cover plus counted crawl re-install the emptied slot
    // through the destination — or the move window expires and the whole held
    // subtree is torn down behind its `Removed`.
    if !lowering.locatable() {
      return;
    }
    // Ending coverage of an object that provably still exists owes BOTH halves.
    // The retiree's own identity carries forward: the object occupying the slot
    // is the same one whose arm went unprovable — only the acknowledgement was
    // untrustworthy, never the object's sameness.
    self.cover_and_rebuild_slot(scope, parent, name, is_dir, identity);
  }

  /// Covers and rebuilds the slot a dying binding leaves behind — the one
  /// composition every "the object provably survives, its binding does not" site
  /// owes, kept in a single place so a second copy cannot drift from it.
  ///
  /// The cover is UNCONDITIONAL. Every structural signal that could stand in for
  /// it is interest- and filter-subject — a `Modified`-only subscription receives
  /// no instruction at all — and the replacement's own read is a re-arm, so its
  /// content is `Created`-suppressed. Only a `Rescan` bypasses both.
  ///
  /// The replacement is always re-arm-flavored whatever the retiree's state was:
  /// this window is lossy by construction (the `Rescan` above), so the coverage
  /// being rebuilt is carried-over content rather than a discovery, and a cold
  /// install would announce every pre-existing entry as `Created` while leaving
  /// the window's counted half unsupplied — `coverage_settled` would then read
  /// true with the slot still unread. Entering `Arming { rearm: true }` is what
  /// marks the bridge window and holds the barrier until the rebuilt read lands.
  ///
  /// `identity` is the caller's claim about the slot's NEW occupant rather than
  /// the retiree's history: a caller that knows the object is unchanged carries
  /// it forward, and one that cannot passes `None`, so a later survivor-diff
  /// degrades honestly to a rebuild instead of asserting a sameness nothing
  /// proved.
  fn cover_and_rebuild_slot(
    &mut self,
    scope: ScopeId,
    parent: WatchId,
    name: Segment,
    is_dir: bool,
    identity: Option<Identity>,
  ) {
    self.emit_rescan(scope, self.child_location(parent, &name));
    // A kernel-recursive scope keeps no per-directory slot to rebuild: its single
    // root binding already covers the ground the `Rescan` above re-instructed.
    if !self.scope_descends(scope) {
      return;
    }
    if self.child_watch(parent, &name).is_none() {
      let _ = self.install_child(parent, scope, name.clone(), is_dir, identity);
      if let Some(fresh) = self.child_watch(parent, &name) {
        let _ = self.inherit_rearm(fresh);
      }
    }
  }

  /// Turns a notification-queue overflow into a [`ChangeKind::Rescan`] covering
  /// exactly the affected scope AND reconciles the proto's own watch set for it, so
  /// nothing is silently lost and no post-overflow subtree is left unwatched.
  ///
  /// On a [`lossy_watch_teardown`](Capabilities::lossy_watch_teardown)
  /// descending profile, a scope-level loss ([`Scope::Root`] and the
  /// [`Scope::All`] arm) additionally RE-PROVES every retained kernel binding:
  /// the dropped window may have carried per-watch teardown records (an
  /// unmount's whole tree of them), so an identity-matched survivor may be
  /// kernel-dead and only an acknowledged re-add — issued under the loss
  /// generation this input bumps — may keep it. The re-adds ride the states
  /// [`rearm_settled`](Self::rearm_settled) already counts, so
  /// [`coverage_settled`](Self::coverage_settled) (and every barrier built on
  /// it) cannot settle before every binding acknowledgement lands. Located
  /// ([`Scope::Subtree`]) overflows carry no kernel-loss evidence and never
  /// re-prove.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn on_overflow(&mut self, scope: Scope, _now: Instant) {
    match scope {
      Scope::All => {
        let roots: std::vec::Vec<(ScopeId, WatchId)> =
          self.roots.iter().map(|(s, w)| (*s, *w)).collect();
        for (scope_id, root) in roots {
          // A whole-scope loss is a transition anywhere under the root, so every
          // unheld pending half's window was interleaved (the root location prefixes
          // every source).
          self.dirty_pending_sources_touching(scope_id, &Location::new(), None, None);
          self.scope_loss_recovery(scope_id, root);
        }
        // The root re-arm may build temporary destination coverage for a held source's
        // move; the pairing reparent would drop it and re-arm nothing if the temp re-arm
        // already completed. Dirty every held source so pairing re-scans/re-arms it.
        self.dirty_held_sources(None);
      }
      Scope::Root(scope_id) => {
        // Only a registered scope has a watch set to reconcile; an overflow
        // reported for an unregistered or already-torn-down scope is dropped
        // rather than emitting a Rescan for a scope the Monitor no longer covers
        // (the `Subtree` arm below guards symmetrically via `scope_of`).
        if let Some(&root) = self.roots.get(&scope_id) {
          self.dirty_pending_sources_touching(scope_id, &Location::new(), None, None);
          self.scope_loss_recovery(scope_id, root);
          self.dirty_held_sources(Some(scope_id));
        }
      }
      Scope::Subtree(sub) => {
        // A subtree overflow on a held source (or a node in its subtree) would `Rescan`
        // and re-arm at the stale PRE-move path, just like a record would. Fence it the
        // same way: mark the enclosing hold dirtied and dirty the watch's outstanding
        // enumerate, then leave the pairing reparent to `Rescan`/re-arm the real
        // destination. Only a non-held subtree rescans-and-rearms in place.
        let watch = sub.watch();
        if let Some(source) = self.in_held_subtree(watch) {
          self.book_hold(source);
          self.mark_enumerate_dirty(watch);
        } else if let Some(scope_id) = self.scope_of(watch) {
          // The Rescan lands at the located directory (the watch's own location plus
          // the descent). The re-arm starts from the nearest watch: the descent has no
          // watch of its own — it is deep only on a kernel-recursive backend, whose
          // re-arm is a no-op anyway — and a descending backend's re-arm cascade
          // covers the descent from the watch. A located loss is also an interleaved
          // transition for any pending half it mutual-prefixes.
          let at = self.location_of(watch).join(sub.descent());
          self.dirty_pending_sources_touching(scope_id, &at, None, None);
          self.emit_rescan(scope_id, at);
          let _ = self.start_rearm(watch);
        }
      }
    }
    self.settle_bridges();
  }

  /// Marks every held move source in `scope` (or all held sources, when `None`) dirtied,
  /// so its pairing reparent re-scans and re-arms the destination. A root/all overflow
  /// re-arms roots and can build temporary destination coverage for an in-flight move;
  /// without this, a reparent that drops the temp watch after its re-arm already completed
  /// would leave the moved-in source with no re-arm obligation and silently lose coverage.
  fn dirty_held_sources(&mut self, scope: Option<ScopeId>) {
    let held: std::vec::Vec<WatchId> = self
      .held_sources
      .iter()
      .copied()
      .filter(|&source| match scope {
        None => true,
        Some(scope) => self.scope_of(source) == Some(scope),
      })
      .collect();
    for source in held {
      self.book_hold(source);
    }
  }

  /// Marks dirty every pending move half of `scope` — held or unheld — whose
  /// reconstructed source location mutual-prefixes `loc`: the pending-store half of the
  /// latent-transition fence (see the inventory note in
  /// [`on_os_record`](Self::on_os_record)). The source is reconstructed on use
  /// ([`pending_from`](Self::pending_from)), so a mid-window reparent of the source's
  /// ancestor is followed rather than indexed stale. Halves whose `from_parent` is no
  /// longer watched are skipped: their location cannot be reconstructed, and the
  /// resolution liveness guard silences them entirely, so a dirty flag could never
  /// surface. `exclude` names a half the caller is about to resolve (a pairing
  /// `MovedTo`'s own cookie); `carried` names a watch whose subtree the caller's own
  /// machinery is detaching-and-holding — halves anchored at or under it follow that
  /// move through the tree and are not marked.
  ///
  /// This runs once per ingested record, so it walks the scope's contiguous key
  /// range rather than every scope's halves under a filter: the work is bounded by
  /// [`PENDING_MOVE_CAP`], not by what unrelated roots happen to have in flight.
  fn dirty_pending_sources_touching(
    &mut self,
    scope: ScopeId,
    loc: &Location,
    exclude: Option<MoveCookie>,
    carried: Option<WatchId>,
  ) {
    let keys: std::vec::Vec<PendingKey> = self
      .pending_moves
      .range((scope, FIRST_COOKIE)..)
      .take_while(|((half_scope, _), _)| *half_scope == scope)
      .filter(|((_, cookie), pending)| {
        Some(*cookie) != exclude
          && !pending.dirty
          && self.is_watched(pending.from_parent)
          && !carried.is_some_and(|held| {
            pending.from_parent == held || self.is_descendant(pending.from_parent, held)
          })
          && Self::locations_touch(&self.pending_from(pending), loc)
      })
      .map(|(key, _)| *key)
      .collect();
    for key in keys {
      if let Some(pending) = self.pending_moves.get_mut(&key) {
        pending.dirty = true;
      }
    }
  }

  /// Emits the covering `Rescan`s a DIRTY paired half owes at resolution: the
  /// interleaved facts described a replacement at the source, and the just-emitted
  /// `Moved`'s application at the consumer contradicts them — both the vacated source
  /// and the populated destination need the re-read instruction. The source side
  /// routes through the same liveness rule as every stored-half resolution (a dead
  /// `from_parent` cannot reconstruct a live source path); the destination is where
  /// the pairing record just arrived, live by construction.
  fn rescan_dirty_pair(&mut self, scope: ScopeId, pending: &PendingMove, to: &Location) {
    if !pending.dirty {
      return;
    }
    if let Some(from) = self.live_pending_from(pending) {
      self.emit_rescan(scope, from);
    }
    self.emit_rescan(scope, to.clone());
  }

  /// Re-anchors every pending half of `scope` whose reconstructed source lies
  /// STRICTLY within a just-resolved pair's source subtree (`from`), rewriting its
  /// stored suffix so it reconstructs under the destination (`to`) — the
  /// anchor-relative analogue of the tree carrying a held subtree's halves through
  /// [`reparent`](Self::reparent). The two mechanisms cannot double-apply: this runs
  /// after the reparent, and a tree-carried half already reconstructs under `to`, so
  /// its source no longer starts with `from` and it does not match here. It matches
  /// exactly the halves whose ANCHOR did not move — a kernel-recursive deep suffix
  /// under the root watch, or a per-directory half anchored at an unmoved parent.
  ///
  /// The strict/exact boundary is an object-identity line. A path names different
  /// objects over time, and every resolution site removes the resolving half from
  /// the store before this walk runs — so a half still parked with source EXACTLY
  /// equal to `from` postdates the resolving `MovedFrom` and names the SUCCESSOR
  /// object that reoccupied the vacated path. Its departure happened at `from`, not
  /// at the departed object's destination: it keeps its suffix (resolving `Moved`/
  /// `Removed` from `from`) and is only marked. Strict descendants, by contrast,
  /// are contents of the moved subtree itself and genuinely travel to `to`.
  ///
  /// Every matched half also becomes dirty: the ancestor move is a transition its
  /// window absorbed — a half parked after the resolving `MovedFrom` was marked by no
  /// record, and even a marked one now owes its covers at resolution. Heldness does
  /// not change this — the touch is to the half's SOURCE slot, so the source-side
  /// cover must come from its own flag; a held half's hold marker would cover only
  /// the destination (see [`PendingMove::dirty`]). A rewritten half whose anchor is
  /// not a prefix of `to` cannot re-express its suffix against that anchor (a
  /// cross-directory per-directory replacement); it keeps the stale suffix and the
  /// flag alone covers — its resolution rescans the source it emits at, and the
  /// resolved pair's own dirty covers handle the relocated side.
  ///
  /// This runs once per resolved pairing `MovedTo`, so it walks the scope's
  /// contiguous key range rather than every scope's halves under a filter: the
  /// work is bounded by [`PENDING_MOVE_CAP`], not by what unrelated roots happen
  /// to have in flight.
  fn reanchor_pending_sources(&mut self, scope: ScopeId, from: &Location, to: &Location) {
    let matched: std::vec::Vec<(PendingKey, Option<Location>)> = self
      .pending_moves
      .range((scope, FIRST_COOKIE)..)
      .take_while(|((half_scope, _), _)| *half_scope == scope)
      .filter(|(_, pending)| self.is_watched(pending.from_parent))
      .filter_map(|(key, pending)| {
        let source = self.pending_from(pending);
        if !source.starts_with(from) {
          return None;
        }
        let rewritten = if source == *from {
          // The successor at the vacated path: mark, never relocate.
          None
        } else {
          let anchor = self.location_of(pending.from_parent);
          to.starts_with(&anchor).then(|| {
            Location::from_segments(
              to.segments()[anchor.len()..]
                .iter()
                .chain(&source.segments()[from.len()..])
                .cloned(),
            )
          })
        };
        Some((*key, rewritten))
      })
      .collect();
    for (key, rewritten) in matched {
      if let Some(pending) = self.pending_moves.get_mut(&key) {
        if let Some(from) = rewritten {
          pending.from = from;
        }
        pending.dirty = true;
      }
    }
  }

  /// Emits an overflow [`ChangeKind::Rescan`] for a scope AND re-enumerates `dir` in
  /// re-arm mode ([`rearm_enumerate`](Self::rearm_enumerate)) so directories created
  /// during the overflow gap are re-armed and vanished ones pruned — both halves of
  /// the dual obligation. A no-op re-arm on a non-descending backend or a dead `dir`.
  fn rescan_and_rearm(&mut self, scope: ScopeId, dir: WatchId) {
    self.emit_rescan(scope, self.location_of(dir));
    let _ = self.start_rearm(dir);
  }

  /// One scope-level loss recovery: the covering root `Rescan` plus the watch-set
  /// reconcile — as a binding-re-proving reinstall on a
  /// [`lossy_watch_teardown`](Capabilities::lossy_watch_teardown) profile (the
  /// loss generation is bumped FIRST, so every arm already in flight is stale
  /// and the recovery's own re-adds stamp current), as the plain enumerate
  /// re-arm otherwise. The `Rescan` is minted before the reinstall either way:
  /// lag entry relies on the mint being synchronous with the loss input.
  fn scope_loss_recovery(&mut self, scope: ScopeId, root: WatchId) {
    if !self.scope_reproves_bindings(scope) {
      self.rescan_and_rearm(scope, root);
      return;
    }
    self.bump_loss_gen(scope);
    self.emit_rescan(scope, self.location_of(root));
    self.start_reinstall(root);
  }

  /// Requires `watch`'s kernel binding to be re-proven by an acknowledged
  /// re-add — the only sound instrument for "is OUR watch the live binding of
  /// what the path names" on a backend whose teardown records are losable.
  /// The node enters `Arming { rearm: true, reprove: true }` (counted, so the
  /// scope reads unsettled until the acknowledgement chain completes) and the
  /// re-add is issued stamped with the current loss generation:
  ///
  /// - **Live** — issue the re-add; the post-ACK read continues the reproof
  ///   downward.
  /// - **Enumerating** (re-arm or cold) — the read's snapshot cannot vouch for
  ///   the binding it rode on, so supersede it: the orphaned request is
  ///   dropped by the existing name-the-request rule (and a latent coalesced
  ///   obligation is reclaimed — the reproof is a counted successor), and the
  ///   re-add is issued.
  /// - **Arming** — coalesce: one watch action per node is outstanding by
  ///   construction, and the in-flight arm predates the loss, so it is left
  ///   stamped stale (a missing stamp, or one from an earlier generation) —
  ///   its `Ok` ACK re-issues under the current generation instead of
  ///   counting. The node is marked reprove so the stamp rule applies.
  ///
  /// One trigger reaches here: a recorded LOSS on a binding-re-proving profile.
  /// An arm whose lowering was not the node's own is no longer re-proved at all
  /// — it certifies nothing, so the binding it reports is retired
  /// ([`ingest_watch_result`](Self::ingest_watch_result)) rather than kept and
  /// re-addressed.
  ///
  /// Dead nodes have nothing to re-prove. A held move SOURCE is never targeted:
  /// the loss entry point re-adds only the root (never held), the crawl re-adds
  /// only in-slot survivors, the pairing re-adds its source only after the hold
  /// has ended and the re-key has landed, and a detached source has no
  /// outstanding arm for a late outcome to answer — its arm
  /// was retired at the detach ([`retire_arm`](Self::retire_arm)) and nothing
  /// re-issues one at a slot it no longer occupies. A DESCENDANT of a held
  /// source may be targeted, and soundly: it keeps its own `(parent, name)`, so
  /// the re-add is addressed through a live in-subtree parent handle rather
  /// than any absolute path the move invalidated — which is exactly the
  /// best-effort arming under a hold the design already performs.
  fn start_reinstall(&mut self, watch: WatchId) {
    let Some(scope) = self.scope_of(watch) else {
      return;
    };
    match self.nodes.get(&watch).map(|node| node.state) {
      Some(NodeState::Live) => {
        self.set_state(
          watch,
          NodeState::Arming {
            rearm: true,
            reprove: true,
          },
        );
        self.queue_reinstall(watch, scope);
      }
      Some(NodeState::Enumerating { req, .. }) => {
        self.pending_enumerate.remove(&req);
        self.latent_cold.remove(&req);
        self.set_state(
          watch,
          NodeState::Arming {
            rearm: true,
            reprove: true,
          },
        );
        self.queue_reinstall(watch, scope);
      }
      Some(NodeState::Arming { .. }) => {
        // The in-flight arm becomes the reproof vehicle: one watch action per
        // node is outstanding, so nothing new is issued. A plain arm was
        // issued before this trigger's generation bump — stamp it one behind
        // (provably stale), so its ACK re-issues under the current generation
        // instead of counting. An existing reprove stamp is kept: it already
        // records that arm's true issue generation.
        self.set_state(
          watch,
          NodeState::Arming {
            rearm: true,
            reprove: true,
          },
        );
        // The one-behind stamp is what makes the in-flight arm's `Ok` re-issue
        // under the current generation instead of counting, so wherever a LOSS
        // raised the doubt it must be genuinely behind — and it is: the
        // scope-loss entry bumps the generation before any loss-driven funnel
        // runs, and it is the only trigger left: an arm whose lowering was not
        // the node's own is retired rather than re-proved, so no caller reaches
        // here at generation 0. The saturating subtraction is what makes that
        // reading total rather than a panic if one ever does.
        let stale = self.loss_gen(scope).saturating_sub(1);
        self.reprove_stamps.entry(watch).or_insert(stale);
      }
      None => {}
    }
  }

  /// Issues the re-add [`Action::Watch`] for a reprove-arming node — through
  /// [`queue_slot_arm`](Self::queue_slot_arm), so the re-add is addressed to
  /// wherever the node sits NOW — and stamps it with the scope's current loss
  /// generation.
  fn queue_reinstall(&mut self, watch: WatchId, scope: ScopeId) {
    if !self.queue_slot_arm(watch, scope) {
      return;
    }
    self.reprove_stamps.insert(watch, self.loss_gen(scope));
  }

  /// Issues the [`Action::Watch`] arming `watch` at the slot it occupies NOW —
  /// the root's own re-add as
  /// [`WatchTarget::RearmRoot`](crate::action::WatchTarget::RearmRoot) (never
  /// the stream-spawning root bootstrap), a child's through its current
  /// `(parent, name)` addressing. Reports whether an arm was issued (`false`
  /// only for a dead handle).
  ///
  /// A `Child` target is a COORDINATE handed across the driver round trip, and
  /// a rename that re-slots the node between the issue and the install leaves
  /// it aimed at a name the object has left. The handle in the same command is
  /// the identity that survives that rename, so the pairing of "issue off the
  /// current slot" with "re-issue at every re-slot"
  /// ([`readdress_outstanding_arm`](Self::readdress_outstanding_arm)) and
  /// "never dispatch a superseded arm" ([`poll_action`](Self::poll_action)) is
  /// what keeps *the outstanding arm names where the node is* an invariant
  /// rather than a fact that was true when it was queued.
  fn queue_slot_arm(&mut self, watch: WatchId, scope: ScopeId) -> bool {
    let Some(node) = self.nodes.get(&watch) else {
      return false;
    };
    let target = match node.parent.zip(node.name.clone()) {
      Some((parent, name)) => crate::action::WatchTarget::child(parent, name),
      None => crate::action::WatchTarget::RearmRoot(scope),
    };
    let mask = Self::coverage_mask(self.scope_interest(scope));
    self.queue_watch(watch, target, mask);
    true
  }

  /// Re-addresses the arm outstanding for a node whose SLOT just changed, so
  /// the install lands where the node now is.
  ///
  /// A pending arm is addressed to a `(parent, name)` coordinate that a rename
  /// can empty while the node it named lives on — detached, reparented, and
  /// still awaiting the very acknowledgement that would return it to `Live`.
  /// Neither half of the existing machinery closes that on its own: the queued
  /// action cannot be rewritten once the driver holds it, and
  /// [`start_reinstall`](Self::start_reinstall) deliberately issues nothing for
  /// a node already `Arming` (one arm per node is outstanding by construction),
  /// so the stale addressing would simply stand. Issuing a fresh arm here
  /// supersedes the old attempt — a still-in-flight outcome for it is then
  /// discarded by [`ingest_watch_result`](Self::ingest_watch_result), and a
  /// still-queued one by [`poll_action`](Self::poll_action) — and the node
  /// stays counted until an acknowledgement for the FINAL slot lands.
  ///
  /// A reprove arm re-issues through [`queue_reinstall`](Self::queue_reinstall)
  /// so its loss-generation stamp travels with it; without the re-stamp the
  /// fresh arm would answer under whatever the superseded one carried.
  ///
  /// A node whose state is no longer `Arming` has no outstanding arm to
  /// re-address — its arm already resolved — and correctly takes nothing from
  /// this.
  fn readdress_outstanding_arm(&mut self, watch: WatchId) {
    let Some(node) = self.nodes.get(&watch) else {
      return;
    };
    let NodeState::Arming { reprove, .. } = node.state else {
      return;
    };
    let scope = node.scope;
    if reprove {
      self.queue_reinstall(watch, scope);
    } else {
      self.queue_slot_arm(watch, scope);
    }
  }

  /// Retires the arm outstanding for `watch` WITHOUT issuing a replacement —
  /// the supersession half of a slot change that leaves the node with no slot
  /// to be addressed at ([`detach_child`](Self::detach_child)).
  ///
  /// A detached source occupies no `(parent, name)`, so there is no coordinate
  /// an arm could name: installing at the one it just vacated would bind this
  /// handle to whatever replacement took the path. The node stays `Arming` and
  /// uncertified for the hold's duration, which is exactly right — it is either
  /// reparented, and re-addressed there, or torn down with its half.
  fn retire_arm(&mut self, watch: WatchId) {
    let _ = self.adopt_arm(watch);
  }

  /// Advances time, resolving move halves whose pairing window has elapsed: an
  /// unpaired source becomes a [`ChangeKind::Removed`] (a watched-directory
  /// source's subtree was already dropped when it moved away, in `on_moved_from`).
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn handle_timeout(&mut self, now: Instant) {
    let expired: std::vec::Vec<PendingKey> = self
      .pending_moves
      .iter()
      .filter(|(_, pending)| !pending.in_window(now))
      .map(|(key, _)| *key)
      .collect();

    for key in expired {
      if let Some(pending) = self.pending_moves.remove(&key) {
        self.resolve_stored_half(pending);
      }
    }
    self.settle_bridges();
  }

  /// Dequeues the next [`Action`] for the driver to execute, if any.
  ///
  /// A queued [`Action::Watch`] whose [`ArmAttempt`] its handle no longer names
  /// is DISCARDED rather than handed out: a later arm superseded it before it
  /// was ever dispatched, so its `(parent, name)` addressing describes a slot
  /// the node has since left. This is the dispatch-side half of the
  /// supersession fence [`on_watch_result`](Self::on_watch_result) applies on
  /// the reply side — and it must be a fence at the point of USE rather than a
  /// removal at the point of supersession, because a queued action cannot be
  /// found by handle without a scan of the queue. Executing one anyway is not
  /// merely wasted work: on a backend that keys its raw handle by [`WatchId`]
  /// it binds this watch to whatever object took the vacated path, and every
  /// record that object produces is then attributed to a subtree that lives
  /// somewhere else. Nothing is lost by discarding — an arm is superseded only
  /// where a replacement is queued in its place, where the driver has already
  /// executed it out of band ([`rebind_root`](Self::rebind_root)), or where the
  /// node has been detached mid-move and so has no slot left to arm at all.
  ///
  /// An arm handed out here is also RE-STAMPED with the placement clock: this —
  /// not the enqueue — is the seam the driver lowers its coordinate at, so this
  /// is the reading against which its acknowledgement is judged.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn poll_action(&mut self) -> Option<Action> {
    while let Some(action) = self.actions.pop_front() {
      if !self.is_superseded_arm(&action) {
        self.stamp_dispatch(&action);
        return Some(action);
      }
    }
    None
  }

  /// Re-stamps the placement of the arm `action` carries, at the moment it is
  /// HANDED OUT.
  ///
  /// The stamp exists to answer "does the absolute path the driver lowered this
  /// coordinate to still describe the node" ([`placement_now`](Self::placement_now)),
  /// so it is only sound if it postdates nothing the lowering saw and predates
  /// nothing it did not. A driver cannot lower an action it has not been given,
  /// and it derives the path from the tree AS OF the poll — so the dispatch is
  /// the earliest reading that is still a fact about the lowering, and the
  /// enqueue is strictly too early.
  ///
  /// The difference is a whole batch wide, and it is not academic. A backend
  /// feeds one kernel batch record by record and drains the resulting actions
  /// only once the batch is spent: a record can discover a descendant and queue
  /// its arm, a later record of the SAME batch rename that descendant's
  /// ancestor, and the drain then correctly open the descendant at its new
  /// destination. Judged against the enqueue reading the acknowledgement reads
  /// stale and the binding is RETIRED — a FALSE staleness, since the arm was
  /// lowered at the right path all along — and a retirement is not free: a live
  /// kernel binding is torn down and its subtree re-crawled, so every record the
  /// gap swallows is carried only by whatever the rebuild's own read sees.
  ///
  /// This does not launder an arm queued before a DETACH into a clean one. That
  /// hazard is the `held` clause's, not the clock's: a detached-and-held source
  /// reconstructs at its pre-move path for the whole pairing window BY DESIGN, so
  /// the path a coordinate under it lowers to is knowingly stale no matter when
  /// the reading is taken, and [`Lowering`] answers both clauses separately for
  /// exactly this reason. The clock's question is narrower — "did the derived
  /// path change after it was derived" — and the derivation happens here.
  ///
  /// Only the dispatched action is stamped. One already handed to the driver
  /// keeps the reading it was given, since its lowering is already in the past;
  /// and a superseded arm is discarded above without stamping, so it cannot
  /// advance the reading its replacement will answer under.
  fn stamp_dispatch(&mut self, action: &Action) {
    let Some(id) = action.as_watch().map(|cmd| cmd.id()) else {
      return;
    };
    let now = self.placement_now();
    if let Some(node) = self.nodes.get_mut(&id) {
      node.placement = now;
    }
  }

  /// Whether `action` installs a watch under an [`ArmAttempt`] some later arm
  /// for the same handle has already superseded. An action for a handle with no
  /// node is NOT superseded: its trailing [`Action::Unwatch`] is what reclaims
  /// it, and the driver's contract already makes that pair a no-op.
  fn is_superseded_arm(&self, action: &Action) -> bool {
    action.as_watch().is_some_and(|cmd| {
      self
        .nodes
        .get(&cmd.id())
        .is_some_and(|node| node.attempt != cmd.attempt())
    })
  }

  /// Dequeues the next normalized [`Change`] for the consumer, if any.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn poll_event(&mut self) -> Option<Change> {
    self.events.pop_front()
  }

  /// The earliest instant at which [`handle_timeout`](Self::handle_timeout) has
  /// work to do (the soonest pending-move deadline), or `None` if no timer is
  /// armed.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn poll_timeout(&self) -> Option<Instant> {
    self
      .pending_moves
      .values()
      .map(|pending| pending.deadline)
      .min()
  }

  fn on_created(&mut self, scope: ScopeId, rec: &OsRecord) {
    // Delivery respects the `ondir` target-class modifier (the kind gate is in `emit`);
    // coverage reconciliation below runs regardless — the record may exist only because
    // of the coverage-augmented subscription.
    if self.ondir_allows(scope, rec.is_dir()) {
      self.emit_child(scope, rec, ChangeKind::Created);
    }
    if let Some(name) = rec.name() {
      // A create is discovery, not a replace: an occupied slot is a duplicate
      // (an enumerate racing the live `Created`), so reuse it (`replaced = false`).
      let _ = self.reconcile_slot(
        rec.watch(),
        scope,
        name,
        Self::record_occupant(rec),
        false,
        rec.node(),
      );
    }
  }

  fn on_removed(&mut self, scope: ScopeId, rec: &OsRecord) {
    if self.ondir_allows(scope, rec.is_dir()) {
      self.emit_child(scope, rec, ChangeKind::Removed);
    }
    if let Some(name) = rec.name() {
      // The slot's object is gone: drop any watch that covered it, so a later
      // create at the same name is not mistaken for a duplicate of the old object.
      let _ = self.reconcile_slot(
        rec.watch(),
        scope,
        name,
        SlotOccupant::Gone,
        false,
        rec.node(),
      );
    }
  }

  fn on_moved_from(&mut self, scope: ScopeId, rec: &OsRecord, now: Instant) {
    let from_parent = rec.watch();
    // Only a depth-one source can name a per-directory child watch; a deeper
    // (kernel-recursive) source has no child watches to detach.
    let src = rec
      .name()
      .and_then(|name| self.child_watch(rec.watch(), name));
    // The bound is asked HERE, in the pattern's guard, because everything the
    // cookied arm does before it parks — the detach, the hold, the born-dirty
    // mark — is bookkeeping owed to a half that is about to exist. Testing
    // capacity after any of it would leave a refused record half-applied, with
    // a detached source no parked half will ever resolve.
    match (rec.cookie(), rec.target()) {
      (Some(cookie), Some(target)) if self.admits_pending_move(scope, cookie) => {
        // Detach a watched-directory source from its old `(parent, name)` slot the
        // moment it moves away, but KEEP its subtree: a paired `MovedTo` reparents it
        // in O(1) (descendants follow for free), and until then detaching has already
        // freed the old path for a replacement to install its own watch. An unpaired
        // half tears the held subtree down when it resolves (`resolve_stored_half`).
        if let Some(src) = src {
          self.detach_child(src);
          // Fence the held subtree from delivery: a record on it during the window would
          // reconstruct through the stale pre-move path (see `in_held_subtree`). The hold
          // also gates the scope's barrier fence (`coverage_settled`): a record suppressed
          // under it owes its covering `Rescan` only at resolution, so no sync cookie may
          // dispatch before then.
          if self.held_sources.insert(src) {
            self.held_by_scope_inc(scope);
          }
          // A hold born while the scope's binding reproof is unsettled leaves
          // the recovery's reach (the crawl re-adds only in-slot survivors),
          // and an in-slot subtree is unproven only while an ancestor's
          // reproof is still counted — so this detach is exactly where an
          // unproven retained subtree can escape the crawl. Born-dirty the
          // hold: its pairing then re-adds the reparented source instead of
          // trusting the O(1) carry-over, so a kernel-dead subtree cannot
          // reach `Live` with no post-loss acknowledgement. Re-dirtying an
          // already-flavored or already-proven source costs its pairing one
          // bounded re-add; a settled scope pays nothing.
          if self.scope_needs_reproof(scope) && !self.rearm_settled(scope) {
            self.book_hold(src);
          }
        }
        let pending = PendingMove {
          from_parent,
          from: target.clone(),
          scope,
          deadline: now + self.move_window,
          held: src,
          // A held source is a watched directory by construction; trust the tree over
          // the record's (possibly absent) flag.
          is_dir: if src.is_some() {
            Some(true)
          } else {
            rec.is_dir()
          },
          evidence: rec.evidence(),
          dirty: false,
        };
        // Invariant (d): the cookie is namespaced by scope, so only a *same-scope*
        // reused/colliding cookie collides on this composite key. The displaced
        // half can no longer be paired, so it resolves on its own rather than
        // being silently overwritten.
        if let Some(displaced) = self.park_pending_move(scope, cookie, pending) {
          self.resolve_stored_half(displaced);
        }
      }
      // A source that can never pair: no cookie (or a degenerate nameless record),
      // or one the scope's bound refused — declining to remember a half is what
      // makes it unpairable, so the two are the same fact and share this one
      // teardown. Tear the subtree down now and emit the `Removed`. `from_parent`
      // is `rec.watch()`, live by construction (`scope_of` succeeded), so no
      // liveness guard is needed.
      unpairable => {
        let is_dir = if src.is_some() {
          Some(true)
        } else {
          rec.is_dir()
        };
        if let Some(src) = src {
          // Where the two part company is what the teardown OWES. A cookied, NAMED
          // source reaches this arm only because the guard above refused it — that
          // guard is the arm's sole discriminator, so the shape re-reads the refusal
          // without re-deciding it — and a refusal is the one case here in which the
          // object provably survives: the cookie is a rename still in flight, so the
          // directory exists and its destination is still coming. A cookieless or
          // nameless source carries no such evidence; for it, "moved away" is
          // terminal knowledge, indistinguishable from the removal whose teardown
          // the erasure argument was written for.
          if matches!(unpairable, (Some(_), Some(_))) {
            self.stand_counted_cover(scope);
          }
          // The object left the slot — that is what this record reports and what
          // the `Removed` below degrades it to — so the vacancy the teardown
          // opens is handed to whatever cover the teardown itself stood.
          self.drop_departed_occupant(src);
        }
        let from = self.record_location(rec);
        self.resolve_lost_source(scope, from, is_dir, rec.evidence());
      }
    }
  }

  /// The pre-reparent source slot of a parked half that takes
  /// [`on_moved_to`](Self::on_moved_to)'s held-directory reparenting arm — the ONE
  /// definition of that arm's precondition.
  ///
  /// `Some((from_parent, from))` exactly when the half is still in its pairing
  /// window, the destination record names a direct child slot to reparent onto, the
  /// half holds a watched subtree to reparent, and the half's own `from_parent` is
  /// still watched. (Pairing itself — a same-scope cookie hit in `pending_moves` —
  /// is the caller's lookup: it is what produced the `pending` argument.)
  ///
  /// `on_moved_to` consults this once, pre-reparent, and consults nothing else:
  /// the arm re-anchors the halves parked under `from` against this value, and a
  /// reparent that then SUCCEEDS reports this same value as the record's
  /// [`RecordOutcome::Reparented`]. Deciding it twice — once to act, once to
  /// report — is precisely the skew this indirection exists to make impossible.
  ///
  /// The last conjunct is belt-and-braces rather than a discriminating one on the
  /// success path: a teardown of `from_parent` walks its `children`, which still
  /// contains a detached-and-held source, so a dead `from_parent` implies a dead
  /// `held` and a reparent that cannot succeed anyway. It is stated because it is
  /// what makes `from` a location at all — a half whose anchor died reconstructs
  /// nothing, which is the same reason [`emit_pair`](Self::emit_pair) degrades its
  /// delivery to a `Created`.
  fn reparenting_source(
    &self,
    pending: &PendingMove,
    name: Option<&Segment>,
    now: Instant,
  ) -> Option<(WatchId, Location)> {
    if !pending.in_window(now) || name.is_none() || pending.held.is_none() {
      return None;
    }
    self
      .live_pending_from(pending)
      .map(|from| (pending.from_parent, from))
  }

  fn on_moved_to(&mut self, scope: ScopeId, rec: &OsRecord, now: Instant) -> RecordOutcome {
    let mut outcome = RecordOutcome::Nothing;
    let to = self.record_location(rec);
    match rec
      .cookie()
      .and_then(|cookie| self.pending_moves.remove(&(scope, cookie)))
    {
      // Invariants (a)+(d): the composite key restricts the lookup to a same-scope
      // half, so a cross-scope cookie collision never matches here (it resolves as
      // a fresh `Created` via the `None` arm). A matched half pairs only before its
      // window elapses; past it the source already stranded (a late destination).
      Some(pending) if pending.in_window(now) => {
        // ONE class per resolution, consumed by BOTH delivery and reconciliation:
        // the arriving record is the NEWEST observation of the object, so its positive
        // flag wins; the pending half's class only fills an OMITTED flag. The reverse
        // precedence would let a stale half (a lingering file source whose parent was
        // narrowly torn down, paired by a reused cookie) demote a real directory
        // destination to an unwatched file slot — silent coverage loss.
        let class = rec.is_dir().or(pending.is_dir);
        // ONE fact set per resolution too: the pairing is the two halves' single
        // event, so whatever either half proved admits the change it becomes.
        let paired = pending.evidence.union(rec.evidence());
        // The source path this pairing relocates, captured while the half is intact:
        // other halves parked under it must re-anchor once the `Moved` is emitted.
        // `from_parent` is the source's (old) parent — never inside the moved subtree —
        // so this reconstruction is stable across the reparent below. An unanchored
        // half emits `Created`, not `Moved` (see `emit_pair`): nothing relocates, so
        // there is nothing to re-anchor under.
        let resolved_from = self.live_pending_from(&pending);
        // The same capture for the held-directory arm, taken through the arm's own
        // single-definition precondition so the value that steers the re-anchor and
        // the value this record reports are one evaluation, not two agreeing ones.
        let reparenting = self.reparenting_source(&pending, rec.name(), now);
        match (rec.name(), pending.held) {
          // Held directory: attempt the O(1) reparent and emit the pairing only once
          // it succeeds — a `Moved` must never precede a rejected/aborted reparent.
          (Some(name), Some(src)) => {
            // The hold ends now, however it resolves. Whether records were suppressed
            // during it decides if the O(1) reparent alone suffices or the destination
            // must also be re-scanned. (A failed reparent drops `src`, whose teardown
            // also clears these sets, so removing here first is just the paired case.)
            if self.held_sources.remove(&src) {
              self.held_by_scope_dec(scope);
            }
            let dirtied = self.dirtied_holds.remove(&src);
            // Asked BEFORE the re-key: an adopted watch whose edge no read has
            // proven yet does not move. The only `reparent` that relocates an
            // existing edge, so this is the whole enforcement of the containment
            // invariant (see `pending_adoptions`).
            if self.can_reparent(src, rec.watch())
              && self.reparentable_adoption(src)
              && self.reparent(src, rec.watch(), name.clone(), Reparent::Moved)
            {
              self.emit_pair(scope, to.clone(), &pending, class, paired);
              if let Some((_, from)) = reparenting.as_ref() {
                self.reanchor_pending_sources(scope, from, &to);
              }
              // The reparent LANDED, and this is the only branch in which one does:
              // report the slot the tree just left. It is the SAME value the
              // re-anchor above ran on — captured before the re-key, so it names
              // where the subtree was (the key a consumer's own bookkeeping still
              // holds), not where it now is.
              outcome = match reparenting {
                Some((from_parent, from)) => RecordOutcome::Reparented { from_parent, from },
                None => RecordOutcome::Nothing,
              };
              // A source-slot touch during the hold (a delivered replacement at the
              // vacated path) covers through the half's own flag — source AND
              // destination — independent of the under-hold suppression below.
              self.rescan_dirty_pair(scope, &pending, &to);
              if dirtied {
                // Records under the moved subtree were suppressed at the stale path:
                // re-scan the destination and re-arm the subtree to recover them.
                // A re-READ suffices for all of it — what a hold suppresses is
                // content, and the retired name a retirement left empty is one the
                // crawl re-installs like any other.
                //
                // A scope-level loss during the hold also DIRTIES it (the
                // recovery deliberately skips a held subtree), and THAT one a
                // re-read cannot answer: on a binding-re-proving scope with a
                // loss on record the re-arm must be the re-add, because the
                // reparented source is in-slot at the destination now and its
                // acknowledged re-add — resolved through the live path — is what
                // re-proves the subtree the recovery could not reach (a plain
                // read would keep every identity-matched descendant on
                // possibly-dead bindings).
                self.emit_rescan(scope, to);
                if self.scope_needs_reproof(scope) {
                  self.start_reinstall(src);
                } else {
                  let _ = self.inherit_rearm(src);
                }
              }
              // A descent booked against this subtree before it moved: the stat
              // it was deferred at is addressed to the slot the source has now
              // LEFT, so that answer finds no incumbent and settles the
              // obligation against nothing. It travelled on the identity
              // instead, which the reparent preserved — discharge it here,
              // after the re-key, so the re-add it may issue resolves through
              // the destination path rather than the stale pre-move one. Not
              // implied by the dirtied branch above: a hold is born dirty only
              // where the scope's reproof was still UNSETTLED, and the deferral
              // is deliberately uncounted, so the common case is a settled
              // scope whose hold carries no marker at all.
              if let Some(descent) = self.owed_descents.remove(&src) {
                self.apply_descent(src, descent);
              }
            } else {
              // Not reparentable: a dead or cyclic held source, a reparent that
              // aborted because the held source sat inside the (now torn-down)
              // destination, or an UNPROVEN ADOPTED EDGE, which is immovable
              // (`reparentable_adoption`). Tear down any surviving held subtree;
              // reconcile the destination as a fresh move-in if its parent survived,
              // else escalate with a `Rescan` — never a `Moved` into a path we no
              // longer cover.
              //
              // The third reason needs nothing written for it, because this route
              // already IS the disposition an unprovable adoption is owed: the drop
              // below is subtree-local (the invariant makes the source a direct
              // child of the marker's node), the pair is still emitted, the
              // destination is re-scanned at its REAL location, and its rebuild is
              // COUNTED. The marker is left standing on purpose — with its adopted
              // watch now dead it resolves through machinery that already exists.
              if self.is_watched(src) {
                self.drop_subtree(src, DeficitDischarge::CoveringRescan);
              }
              if self.is_watched(rec.watch()) {
                self.emit_pair(scope, to.clone(), &pending, class, paired);
                // The arm's own capture again — the reparent failing changes where the
                // pair relocates halves FROM not at all. The `outcome` stays `Nothing`:
                // the tree did not carry the subtree, so a consumer must NOT re-anchor
                // as if it had. That sliver is why the record reports what it did
                // rather than exposing what it decided.
                if let Some((_, from)) = reparenting.as_ref() {
                  self.reanchor_pending_sources(scope, from, &to);
                }
                // A source-slot touch during the hold still owes its source-side
                // cover here (the destination side coalesces with the unconditional
                // rescan below).
                self.rescan_dirty_pair(scope, &pending, &to);
                // The O(1) carry-over failed, so the moved subtree's interval is
                // uncovered BY CONSTRUCTION — whatever happened between the source
                // dying (a failed install, a raced teardown) and the fresh destination
                // watch arming was seen by no one. Re-scan the destination
                // unconditionally; this also outlives the dirtied_holds marker, which
                // a source-teardown clears while the half is still pairable.
                self.emit_rescan(scope, to);
                // Reconcile with the class the pair PROVES — a record with an omitted
                // flag must not demote the moved directory to an unwatched file slot.
                let _ = self.reconcile_slot(
                  rec.watch(),
                  scope,
                  name,
                  Self::class_occupant(class),
                  true,
                  rec.node(),
                );
                // That rebuild is over CARRIED-OVER content, not a discovery, and the
                // `Rescan` above is this window's opening loss edge — so the fresh
                // destination watch must be COUNTED behind it. A cold install would
                // leave the window nothing to wait on: the bridge conjunction would
                // never complete, and `coverage_settled` would read true while the
                // destination subtree was still unread.
                if let Some(fresh) = self.child_watch(rec.watch(), name) {
                  let _ = self.inherit_rearm(fresh);
                }
              } else {
                // The destination parent died with the held subtree (it sat inside it),
                // so the precomputed `to` reconstructed through the detached source and
                // is a STALE pre-move path. Escalate at the scope root — the one
                // location still known live — never at a path we no longer cover. The
                // root Rescan is a scope-wide transition like a whole-scope loss:
                // every parked half (either store) resolves AFTER it and must cover,
                // or its stale facts would land post-rescan uninstructed.
                self.dirty_pending_sources_touching(scope, &Location::new(), None, None);
                self.dirty_held_sources(Some(scope));
                // The record in hand proves the moved object is alive somewhere in the
                // scope, and this arm just ended the whole subtree's coverage without
                // rebuilding any of it — so the root escalation owes the SAME counted
                // crawl a nameless destination's teardown owes, not a bare edge
                // `Rescan` the barrier can certify over on the very next poll. (A
                // kernel-recursive scope never reaches here: the arm needs a held
                // source, which only a per-directory child watch can be.)
                self.stand_counted_cover(scope);
              }
            }
          }
          // Non-directory (or unwatched) source: emit the pairing and reconcile the slot.
          (Some(name), None) => {
            self.emit_pair(scope, to.clone(), &pending, class, paired);
            if let Some(from) = resolved_from.as_ref() {
              self.reanchor_pending_sources(scope, from, &to);
            }
            self.rescan_dirty_pair(scope, &pending, &to);
            let _ = self.reconcile_slot(
              rec.watch(),
              scope,
              name,
              Self::class_occupant(class),
              true,
              rec.node(),
            );
          }
          (None, held) => {
            if let Some(src) = held {
              // The destination record in hand proves the object is alive inside the
              // scope, and a nameless one leaves the tree no slot to re-cover it at —
              // so unlike every sibling arm this drop ends the subtree's coverage for
              // good, with only the interest- and filter-subject `Moved` to say so.
              // The erasure argument is about a vanished subtree and does not reach
              // this one.
              self.stand_counted_cover(scope);
              self.drop_subtree(src, DeficitDischarge::CoveringRescan);
            }
            self.emit_pair(scope, to.clone(), &pending, class, paired);
            if let Some(from) = resolved_from.as_ref() {
              self.reanchor_pending_sources(scope, from, &to);
            }
            self.rescan_dirty_pair(scope, &pending, &to);
          }
        }
      }
      Some(pending) => {
        // Late destination (past the window): the source stranded. Resolve it (drops
        // the held subtree, emits a guarded `Removed`). Then treat the arrival as a
        // fresh object — but only if the destination parent survived that teardown (a
        // cyclic/descendant late destination sits inside the held source, so dropping
        // it removes `rec.watch()`); otherwise escalate with a `Rescan`.
        //
        // The arriving object IS the stranded source, but the record is the NEWER
        // observation: its positive flag wins, and the pending half's class (proven
        // `Some(true)` for a held watched directory) fills an OMITTED flag — so
        // unknown-class over-delivery only remains where the class is genuinely
        // unknown on both sides, and a stale half cannot override a live signal.
        let class = rec.is_dir().or(pending.is_dir);
        // Whether resolving the half ENDS the coverage of a watched subtree this very
        // record proves is still alive. The strand's own teardown may not go silent
        // here the way a timed-out or displaced half's may: those resolve on the
        // absence of a destination, so nothing left can describe the object, whereas
        // this arm holds the destination record. Every signal the resolution does
        // emit — the stranded `Removed`, the arrival's `Created` — is interest- and
        // filter-subject and reaches a `Modified`-only subscription with nothing,
        // while a later record in the same batch naming one of the dropped
        // descendant handles is discarded by the unknown-watch guard (and cannot even
        // dirty the hold, whose node is already gone). Only a `Rescan` reaches that
        // subscription.
        let carried = pending.held.is_some_and(|src| self.is_watched(src));
        self.resolve_stored_half(pending);
        if self.is_watched(rec.watch()) {
          // Delivery honors `ondir`; the slot reconciliation below is coverage and
          // runs regardless.
          if self.ondir_allows(scope, class) {
            self.emit(scope, to.clone(), ChangeKind::Created, rec.evidence());
          }
          if let Some(name) = rec.name() {
            if carried {
              // The opening loss edge for the interval between the teardown above and
              // the destination watch arming below — the failed-carry-over arm's
              // `Rescan`, owed for the same reason past the window as within it.
              self.emit_rescan(scope, to.clone());
            }
            let _ = self.reconcile_slot(
              rec.watch(),
              scope,
              name,
              Self::class_occupant(class),
              true,
              rec.node(),
            );
            // And the rebuild is COUNTED behind that edge: it re-covers CARRIED-OVER
            // content, not a discovery, so a cold install would leave the window
            // nothing to wait on — the bridge conjunction would never complete, and
            // `coverage_settled` would read true while the destination subtree was
            // still unread. Counted without the edge `Rescan` is no better: the read
            // flips re-arm-flavored, its `Created`s are suppressed, and with
            // `saw_rescan` unset no closing `Rescan` is ever minted.
            if carried && let Some(fresh) = self.child_watch(rec.watch(), name) {
              let _ = self.inherit_rearm(fresh);
            }
          } else if carried {
            // A nameless destination leaves the tree no slot to re-cover the subtree
            // at, so the recovery anchors at the root — the in-window nameless twin's
            // argument, applied past the window.
            self.stand_counted_cover(scope);
          }
        } else {
          // Resolving the stranded source dropped the destination parent (a cyclic late
          // destination sits inside the held subtree), so the precomputed `to` is a
          // stale pre-move path — escalate at the scope root instead, marking both
          // parked stores as for any scope-wide transition (see the in-window twin).
          self.dirty_pending_sources_touching(scope, &Location::new(), None, None);
          self.dirty_held_sources(Some(scope));
          // Counted, for the in-window twin's reason: the record proves the object
          // survives, and this arm rebuilt none of the coverage it just ended.
          self.stand_counted_cover(scope);
        }
      }
      None => {
        if self.ondir_allows(scope, rec.is_dir()) {
          self.emit(scope, to, ChangeKind::Created, rec.evidence());
        }
        if let Some(name) = rec.name() {
          let _ = self.reconcile_slot(
            rec.watch(),
            scope,
            name,
            Self::record_occupant(rec),
            true,
            rec.node(),
          );
        }
      }
    }
    outcome
  }

  /// Resolves a *stored* pending half (one taken from `pending_moves` — at timeout,
  /// on cookie-collision displacement, or as a past-window late destination) into a
  /// [`ChangeKind::Removed`] — but only if its source is still watched.
  ///
  /// A narrow subtree drop deliberately leaves a half pairable (its destination may
  /// still arrive), so a half whose `from_parent` was since torn down can linger.
  /// Such a half is dead — its source path no longer exists — and must NOT emit a
  /// stale `Removed`, however it later leaves the map. This single liveness guard
  /// covers every stored-half resolution site (invariants b/c).
  ///
  /// A held source subtree — kept only to enable an O(1) reparent — never paired, so
  /// it is torn down here (a no-op if a `from_parent` teardown already reclaimed it
  /// through the parent-link walk).
  fn resolve_stored_half(&mut self, pending: PendingMove) {
    if let Some(src) = pending.held {
      self.drop_subtree(src, DeficitDischarge::CoveringRescan);
    }
    if let Some(from) = self.live_pending_from(&pending) {
      self.resolve_lost_source(
        pending.scope,
        from.clone(),
        pending.is_dir,
        pending.evidence,
      );
      // A dirty half's window saw interleaved subtree activity whose facts the
      // stranded-source `Removed` above contradicts: cover the source with a re-read
      // instruction, under the same liveness guard (a dead `from_parent` has no live
      // source path to rescan — and nothing to contradict).
      if pending.dirty {
        self.emit_rescan(pending.scope, from.clone());
      }
      // The `Removed` just delivered is itself a subtree transition: a half parked
      // UNDER this source (one that arrived after this half's own `MovedFrom` marked
      // the store, so no record ever touched it) would otherwise resolve against a
      // tree the consumer has already dropped. Mark, don't rewrite — a removal
      // relocates nothing.
      self.dirty_pending_sources_touching(pending.scope, &from, None, None);
    }
  }

  /// The current source location of a pending half, reconstructed from its slot
  /// `(from_parent, from)` so it tracks any reparent of the source's ancestor.
  fn pending_from(&self, pending: &PendingMove) -> Location {
    self.location_of(pending.from_parent).join(&pending.from)
  }

  /// [`pending_from`](Self::pending_from) under the anchor-liveness guard — the ONE
  /// definition of "this half still has a source path at all".
  ///
  /// A narrow subtree drop leaves a half pairable after its `from_parent` died
  /// (invariants b/c), and such a half reconstructs nothing: `location_of` a dead
  /// watch is not the path the source occupied. Every site that must not speak of a
  /// dead source — the stranded-half `Removed` and its covering `Rescan`, the pair's
  /// `Moved`-versus-`Created` degrade, a dirty pair's source-side cover, and the
  /// reparenting slot this record reports — asks here rather than re-spelling the
  /// guard, so none of them can disagree about whether a source exists.
  fn live_pending_from(&self, pending: &PendingMove) -> Option<Location> {
    self
      .is_watched(pending.from_parent)
      .then(|| self.pending_from(pending))
  }

  /// Emits the outcome of a paired `MovedTo`: a `Moved` when the source is still
  /// anchored, otherwise a fresh `Created`. Liveness is checked *now*, not snapshotted
  /// earlier — a reparent can have dropped `from_parent` (its destination slot may be
  /// the source's own parent), and a `Moved` reconstructed off a dropped parent would
  /// carry a wrong from-path. Delivery-only (coverage runs at the call sites); the
  /// `ondir` modifier gates the whole emission by `class` — the caller's single
  /// per-resolution class, the same value its reconciliation consumes.
  fn emit_pair(
    &mut self,
    scope: ScopeId,
    to: Location,
    pending: &PendingMove,
    class: Option<bool>,
    evidence: Evidence,
  ) {
    if !self.ondir_allows(scope, class) {
      return;
    }
    if let Some(from) = self.live_pending_from(pending) {
      self.emit(scope, to, ChangeKind::Moved(from), evidence);
    } else {
      // A rename whose source anchor died reports as a `Created`; the pair's own
      // evidence rides along so a `moved`-only subscription still learns of it.
      self.emit(scope, to, ChangeKind::Created, evidence);
    }
  }

  /// Detaches a child watch from its `(parent, name)` slot without tearing down its
  /// subtree. The node stays in `nodes` (still attributing records, at its pre-move
  /// path) so a paired [`MovedTo`](Self::on_moved_to) can [`reparent`](Self::reparent)
  /// it; freeing the slot lets a replacement at the old path install its own watch.
  ///
  /// The object has left the path the tree still reconstructs for it, so this is
  /// also where every coordinate lowered under this subtree — the node's own and
  /// its descendants' alike — stops describing what it names. That is settled in
  /// two complementary ways, and both are needed:
  ///
  /// - the node's own placement change is recorded
  ///   ([`moved_placement`](Self::moved_placement)), which is the completion-side
  ///   net: a result for any round trip already dispatched under this subtree no
  ///   longer counts as clean. It reaches descendants — which no supersession
  ///   can, since their own slots did not change — without walking the subtree,
  ///   because the walk happens on the far side, once, per completed request;
  /// - a pending ARM is retired ([`retire_arm`](Self::retire_arm)), which the
  ///   clock cannot stand in for: retiring is DISPATCH-side prevention. The
  ///   arm's `(parent, name)` addressing now names the vacated path, so an arm
  ///   still queued would install a binding on whatever replacement stands
  ///   there, and rejecting its acknowledgement afterwards does not un-bind it.
  fn detach_child(&mut self, child: WatchId) {
    if let Some(node) = self.nodes.get(&child)
      && let (Some(parent), Some(name)) = (node.parent, node.name.clone())
    {
      self.vacate_child_slot(parent, name);
    }
    self.moved_placement(child);
    if matches!(
      self.nodes.get(&child).map(|node| node.state),
      Some(NodeState::Arming { .. })
    ) {
      self.retire_arm(child);
    }
  }

  /// Reparents a held subtree onto a new `(parent, name)` edge in O(1): re-keys the
  /// node and its child-index entry. Descendants follow their unchanged parent links,
  /// so their paths reconstruct through the new location with no re-enumerate and no
  /// per-descendant `Created`. Any stale watch already occupying the destination is a
  /// different, now-replaced object and is torn down first — and its in-flight re-arm
  /// obligation (if any) transfers to the reparented subtree, so a raced overflow
  /// re-arm is not lost.
  ///
  /// Returns whether the re-key happened. It does NOT if dropping the stale
  /// destination also removed `child` — the case where the held source sat
  /// inside the destination slot — leaving nothing to re-key; the caller escalates.
  /// The caller is responsible for the acyclic precondition ([`can_reparent`]).
  ///
  /// `flavor` is the caller's answer to "did any absolute path change?", and it
  /// is asked rather than inferred because the two callers genuinely differ (see
  /// [`Reparent`]).
  ///
  /// [`can_reparent`]: Self::can_reparent
  fn reparent(
    &mut self,
    child: WatchId,
    new_parent: WatchId,
    new_name: Segment,
    flavor: Reparent,
  ) -> bool {
    let mut inherit_rearm = false;
    if let Some(stale) = self.child_watch(new_parent, &new_name)
      && stale != child
    {
      // The replaced destination may carry a re-arm obligation (a pending arm that will
      // re-arm, or an outstanding re-arm read). Either way it must pass to the reparented
      // subtree, not vanish with the drop.
      inherit_rearm = self.has_rearm_obligation(stale);
      self.drop_subtree(stale, DeficitDischarge::CoveringRescan);
    }
    // Dropping the stale destination can have removed `child` itself (the held source
    // sat inside that slot). Only re-key when both endpoints survive.
    if !self.is_watched(child) || !self.is_watched(new_parent) {
      return false;
    }
    // Move `child` between adjacency sets to track its new parent link.
    let old_parent = self.nodes.get(&child).and_then(|node| node.parent);
    if let Some(old) = old_parent
      && let Some(old_node) = self.nodes.get_mut(&old)
    {
      old_node.children.remove(&child);
    }
    if let Some(node) = self.nodes.get_mut(&child) {
      node.parent = Some(new_parent);
      node.name = Some(new_name.clone());
    }
    if let Some(parent_node) = self.nodes.get_mut(&new_parent) {
      parent_node.children.insert(child);
    }
    self.child_index.insert((new_parent, new_name), child);
    // Ahead of every round trip this re-key goes on to issue, so each is stamped
    // against the placement it is actually addressed at: a `Moved` re-key means
    // every coordinate lowered under this subtree before now — including one
    // issued DURING the hold, which lowered at the pre-move path by design —
    // describes a location the subtree has left.
    if matches!(flavor, Reparent::Moved) {
      self.moved_placement(child);
    }
    if inherit_rearm {
      let _ = self.inherit_rearm(child);
    }
    // The node now answers to a different `(parent, name)`, so an arm still
    // outstanding for it is addressed to the slot it just left — re-address it
    // here, at the one funnel every re-key passes through.
    self.readdress_outstanding_arm(child);
    true
  }

  /// The KEY of the marker whose still-unproven adopted watch is `watch` — the
  /// chain parent that owes its re-proof — or `None` when `watch` owes no
  /// adoption proof.
  ///
  /// Asked through `watch`'s OWN parent link, which the containment invariant
  /// ([`pending_adoptions`](Self::pending_adoptions)) makes exact rather than
  /// merely likely: an unproven adopted watch is a direct child of the marker
  /// that names it, so the single candidate is the marker keyed at that parent,
  /// and one `O(log n)` pair of lookups decides it. That is what pays for having
  /// no reverse index — a second map to keep in lockstep with the first would be
  /// one more thing that could drift out of it.
  ///
  /// Both places the answer matters read it here, so "is this watch an unproven
  /// adopted edge" has one definition: the reparent refusal
  /// ([`reparentable_adoption`](Self::reparentable_adoption)) and the invalidation
  /// a moved adopted watch's own [`RecordKind::MoveSelf`] triggers
  /// ([`on_move_self`](Self::on_move_self)).
  fn unproven_adoption_of(&self, watch: WatchId) -> Option<WatchId> {
    let parent = self.nodes.get(&watch)?.parent?;
    match self.pending_adoptions.get(&parent) {
      Some(marker) if marker.adopted == watch => Some(parent),
      _ => None,
    }
  }

  /// Whether `src` may be reparented AT ALL: whether it is anything other than
  /// the still-unproven adopted watch of the marker standing at its own parent.
  ///
  /// The enforcement half of the containment invariant
  /// ([`pending_adoptions`](Self::pending_adoptions)), and the whole of it: this
  /// is asked at the only [`reparent`](Self::reparent) call that relocates an
  /// existing edge, so refusing here refuses everywhere.
  ///
  /// Permitting the move is what costs. Two ordinary paired renames can put the
  /// adopted watch ABOVE the node that owes its proof, from which point retiring
  /// the edge destroys the very directory whose in-flight enumerate asked for the
  /// retirement, and every continuation holding coordinates under it emits,
  /// installs or books against a node that is gone. One `O(log n)` lookup per
  /// paired DIRECTORY move is cheaper than a collateral fate threaded through
  /// `reconcile_slot` and both enumerate loops.
  ///
  /// And a refusal is not a loss: the caller's not-reparentable route already IS
  /// the disposition an unprovable adopted edge is owed, taken at the rename
  /// instead of at the proof.
  ///
  /// Refusing the move is only half of what the proof needs, and the half that
  /// can only speak for a move the monitor OBSERVED. Its other half is
  /// [`on_move_self`](Self::on_move_self): an adopted watch that moved with no
  /// parent-side record to refuse spends its proof instead.
  fn reparentable_adoption(&self, src: WatchId) -> bool {
    self.unproven_adoption_of(src).is_none()
  }

  /// Whether `child`'s subtree may be reparented under `new_parent`: both must be
  /// live and the move must be acyclic — `new_parent` may be neither `child` itself
  /// nor any node within `child`'s subtree, or path reconstruction would loop.
  fn can_reparent(&self, child: WatchId, new_parent: WatchId) -> bool {
    self.is_watched(child)
      && self.is_watched(new_parent)
      && new_parent != child
      && !self.is_descendant(new_parent, child)
  }

  /// Whether `maybe_descendant` lies within `ancestor`'s subtree, walking parent
  /// links to a root. Bounded by the node count so a malformed tree cannot loop.
  fn is_descendant(&self, maybe_descendant: WatchId, ancestor: WatchId) -> bool {
    let mut cursor = Some(maybe_descendant);
    for _ in 0..=self.nodes.len() {
      match cursor {
        Some(id) if id == ancestor => return true,
        Some(id) => cursor = self.nodes.get(&id).and_then(|node| node.parent),
        None => break,
      }
    }
    false
  }

  /// Resolves a source half that found no destination: the object left this
  /// location, so emit a [`ChangeKind::Removed`]. A watched-directory source had
  /// its now-stale watch subtree dropped already at `on_moved_from` (eager-drop),
  /// so there is nothing more to tear down here.
  fn resolve_lost_source(
    &mut self,
    scope: ScopeId,
    from: Location,
    is_dir: Option<bool>,
    evidence: Evidence,
  ) {
    if !self.ondir_allows(scope, is_dir) {
      return;
    }
    // The `Removed` is the DEGRADE of a rename the monitor could not pair, not a
    // removal anyone observed. Its evidence still names the move, so the
    // subscriber who asked about renames — and would otherwise receive neither
    // half of one, nor a `Rescan` — is admitted on the fact that actually
    // happened.
    self.emit(scope, from, ChangeKind::Removed, evidence);
  }

  /// The single point of truth for "the watch at `(parent, name)` matches the
  /// slot's current occupant". EVERY record that can change a slot's occupant —
  /// [`Created`](Self::on_created), every [`MovedTo`](Self::on_moved_to),
  /// [`Removed`](Self::on_removed), and each [`enumerate`](Self::on_enumerate)
  /// entry — routes through here, so directory coverage cannot be lost by a missed
  /// per-record path (this centralization replaces the per-handler coverage
  /// decisions that let stale-slot bugs recur).
  ///
  /// `replaced` distinguishes the two ways a directory comes to occupy a slot:
  /// - **move-in** (`true`): the arrival is a definitively-new object, so any watch
  ///   already in the slot is a different, now-stale object and is dropped before
  ///   re-arming (a file may even replace a watched directory).
  /// - **discovery** (`false`): a create/enumerate of an already-watched slot is a
  ///   duplicate race (a true replace arrives as `Removed` then `Created`, which
  ///   frees the slot first), so the existing watch is reused — [`install_child`]
  ///   is idempotent.
  ///
  /// A `File`/`Gone` occupant always drops any stale watch, and only
  /// [`SlotOccupant::Dir`] is watched. An occupant the driver could not classify
  /// ([`SlotOccupant::Unknown`]) settles NEITHER: an
  /// [`Action::Stat`](crate::Action::Stat) is asked for the kind, and — where
  /// nothing already covers the slot — it is booked as a standing deficit, so the
  /// darkness re-signals at every dispatch instead of passing for a proven
  /// non-directory, AND the request stands the scope's settlement loss
  /// ([`StatSlot::stands_loss`]) so no fence certifies the window in between.
  /// Any incumbent watch stays live meanwhile: it may be covering
  /// the very directory the listing failed to name. A no-op when the core does not
  /// descend (kernel-recursive: no per-directory watches to manage).
  ///
  /// Reports whether this reconcile HEALED the slot's booked darkness — whether
  /// [`remove_slot_deficit`](Self::remove_slot_deficit) removed a real fine entry
  /// for `(parent, name)`, the single act that stands the BOOKED darkness's
  /// covering `Rescan`. Two occupants can stand it (a `Dir` that installs, a
  /// `File`/`Gone` that empties), and a caller cannot tell which from the
  /// occupant it passed in: a `Dir` reconcile that REUSES the incumbent — an
  /// identity match, or an identity nobody could read — installs nothing and
  /// heals nothing, and a book collapsed past [`DEFICIT_CAP`] holds no entry for
  /// any of them to remove.
  /// Most callers own no such obligation and ignore the answer; the one that does
  /// is [`ingest_stat_result`](Self::ingest_stat_result), whose released
  /// settlement loss owes this slot a cover wherever this reconcile stood none.
  ///
  /// [`install_child`]: Self::install_child
  fn reconcile_slot(
    &mut self,
    parent: WatchId,
    scope: ScopeId,
    name: &Segment,
    occupant: SlotOccupant,
    replaced: bool,
    identity: Option<Identity>,
  ) -> bool {
    if !self.scope_descends(scope) {
      return false;
    }
    match occupant {
      SlotOccupant::Dir => {
        // Replace the incumbent watch when the caller says so (a definitively-new
        // move-in), OR when identity reveals a same-name replacement (the slot holds a
        // watch of a known-different object). An unknown identity on either side never
        // forces a replace — discovery of an already-watched slot stays a reuse.
        let existing = self.child_watch(parent, name);
        let replace =
          replaced || existing.is_some_and(|stale| self.identity_differs(stale, identity));
        // Replacing a mid-re-arm watch must not lose its re-arm obligation: capture it
        // before the drop and pass it to the fresh watch, so a subtree being re-armed
        // during an overflow stays covered when a move-in replaces its slot.
        let mut inherit = false;
        if replace && let Some(stale) = existing {
          inherit = self.has_rearm_obligation(stale);
          self.drop_subtree(stale, DeficitDischarge::CoveringRescan);
        }
        let healed = self.install_child(parent, scope, name.clone(), true, identity);
        if inherit && let Some(fresh) = self.child_watch(parent, name) {
          let _ = self.inherit_rearm(fresh);
        }
        healed
      }
      SlotOccupant::Unknown => {
        // Neither branch above may run on ignorance: watching would arm on every
        // unclassifiable file, and dropping (or never installing) would leave a real
        // directory blind for the process's lifetime with no watch, no deficit and no
        // `Rescan` to say so.
        //
        // The slot is DARK only where nothing already covers it. An incumbent watch is
        // live coverage whatever the listing failed to name, so booking a deficit over
        // it would signal darkness that does not exist — and the heal interlock could
        // not clear it, since re-occupying an occupied slot is a no-op. Either way the
        // stat is asked: it decides whether to install, to keep, or to drop.
        //
        // The hole booked here is the one deficit site with no `Rescan` behind
        // it — this read need never have stood one — so its window's cover is
        // the settlement loss `queue_stat` stands over the same emptiness. That
        // half deliberately lives in the funnel: it is owed by any queue at an
        // uncovered slot, including one this call only coalesces onto.
        if self.child_watch(parent, name).is_none() {
          self.record_slot_deficit(scope, parent, name.clone());
        }
        self.queue_stat(parent, scope, name.clone());
        false
      }
      SlotOccupant::File | SlotOccupant::Gone => {
        if let Some(stale) = self.child_watch(parent, name) {
          self.drop_departed_occupant(stale);
        }
        // The slot's object is gone (or a never-watched file). A recorded
        // arm-refused hole there is NOT converged by the emptying: the
        // `Removed`/`File` record that drove it is interest- and
        // filter-subject — a `Modified`-only (or removal-filtering)
        // subscription never sees it — so it cannot stand in for the change
        // the hole's darkness hid. `remove_slot_deficit` stands the covering
        // `Rescan` (both bridge bits → the settle's closing `Rescan`, which
        // bypasses interest and filter) when it removes a real entry.
        let covered = self.remove_slot_deficit(scope, parent, name);
        // This is the one settlement whose cover is stood over a slot that stays
        // EMPTY — `File` and `Gone` both mean no watch may stand here — so it is
        // the one that can leave an outstanding stat looking at an emptiness
        // somebody else has already accounted for. Say so, off the removal's own
        // answer rather than off the occupant passed in: a collapsed book holds
        // no entry for any occupant to turn, and stands nothing.
        // `install_child`'s removal is the same act to the opposite end — it
        // OCCUPIES the slot — so it says nothing here.
        //
        // The removal is HALF of what this settlement can stand. The teardown
        // above is the other half, and it raises the same flag off its own answer
        // rather than through this one: a slot whose fine entry an occupation
        // already spent leaves the removal nothing to turn while the teardown may
        // still have erased plenty (see [`StatSlot::vacancy_covered`]).
        if covered {
          self.cover_stat_vacancy(parent, name);
        }
        covered
      }
    }
  }

  /// The [`ArmAttempt`] `id` is currently arming under — the most recent one
  /// issued for it — or `None` for a handle with no node.
  ///
  /// This is BOOKKEEPING, not the reply path. An outcome must be reported under
  /// the attempt CAPTURED when the arm was dispatched (off its
  /// [`WatchCommand`](crate::WatchCommand), or returned by
  /// [`rebind_root`](Self::rebind_root) / [`widen_root`](Self::widen_root));
  /// reading the current attempt at reply time would answer for whichever arm is
  /// current and reintroduce exactly the misattribution the token prevents.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn arm_attempt(&self, id: WatchId) -> Option<ArmAttempt> {
    self.nodes.get(&id).map(|node| node.attempt)
  }

  /// The object identity a watch was installed for, if the driver supplied one.
  ///
  /// The driver reads this back when arming the watch's kernel watch: the open
  /// resolves by path (or an anchor chain), and the object it lands on must match
  /// this identity before the watch is installed — otherwise a rename between the
  /// enumerate that discovered the object and the arm would install the watch on a
  /// DIFFERENT object while the Monitor keeps the old identity (misattribution).
  pub fn node_identity(&self, watch: WatchId) -> Option<Identity> {
    self.nodes.get(&watch).and_then(|node| node.identity)
  }

  /// Whether `watch`'s installed identity and `other` are both known and unequal — the
  /// positive signal of a same-name replacement. Unknown on either side is NOT "differs":
  /// identity is optional, and absent it the core reconciles conservatively (reuse on
  /// discovery, rebuild on a re-arm) rather than guessing.
  fn identity_differs(&self, watch: WatchId, other: Option<Identity>) -> bool {
    match (self.nodes.get(&watch).and_then(|node| node.identity), other) {
      (Some(installed), Some(fresh)) => installed != fresh,
      _ => false,
    }
  }

  /// Whether `watch`'s installed identity and `other` are both known and EQUAL — a
  /// positive confirmation that the object at a name survived a re-arm unchanged, so its
  /// watch can be kept rather than rebuilt. Unknown on either side is NOT a match (the
  /// re-arm then rebuilds conservatively).
  fn identity_matches(&self, watch: WatchId, other: Option<Identity>) -> bool {
    match (self.nodes.get(&watch).and_then(|node| node.identity), other) {
      (Some(installed), Some(fresh)) => installed == fresh,
      _ => false,
    }
  }

  /// Maps a record's reported directory-ness to a [`SlotOccupant`]. Only a known
  /// directory (`is_dir() == Some(true)`) is a `Dir`; `Some(false)` and `None` are
  /// both `File` (the descending-backend `is_dir` contract — see [`reconcile_slot`]).
  ///
  /// A record's flag is deliberately NOT routed through
  /// [`SlotOccupant::Unknown`]: `is_dir` is absent on the vast majority of records
  /// from backends that never report it, so treating absence as unsettled would
  /// stat every file the tree ever sees. A listing's
  /// [`FileKind`](crate::FileKind) is a different claim — it is the driver's
  /// answer to "what IS this", and `Unknown` there means it tried and could not
  /// tell.
  ///
  /// [`reconcile_slot`]: Self::reconcile_slot
  fn record_occupant(rec: &OsRecord) -> SlotOccupant {
    Self::class_occupant(rec.is_dir())
  }

  /// Maps a listed entry's [`FileKind`](crate::FileKind) to a [`SlotOccupant`]:
  /// a directory is watched, an unclassifiable kind is unsettled, and every
  /// other kind is a proven non-directory.
  fn entry_occupant(kind: FileKind) -> SlotOccupant {
    match kind {
      FileKind::Dir => SlotOccupant::Dir,
      FileKind::Unknown => SlotOccupant::Unknown,
      FileKind::File | FileKind::Symlink | FileKind::Other => SlotOccupant::File,
    }
  }

  /// Maps a target class to a [`SlotOccupant`] — the [`record_occupant`] rule applied
  /// to a class recovered from a pending move half rather than read off one record. A
  /// move destination must reconcile with the class the pair PROVES (a held source is a
  /// watched directory), or a late record with an omitted flag would leave the moved
  /// directory silently unwatched.
  ///
  /// [`record_occupant`]: Self::record_occupant
  fn class_occupant(is_dir: Option<bool>) -> SlotOccupant {
    if is_dir == Some(true) {
      SlotOccupant::Dir
    } else {
      SlotOccupant::File
    }
  }

  fn on_move_self(&mut self, scope: ScopeId, rec: &OsRecord) {
    if self.is_root_watch(rec.watch()) {
      // A moved root's new path is unknowable from inotify alone: emit a `Rescan` and then
      // INVALIDATE the stale root tree. Its watch now follows the moved-away object, so a
      // later record on any of these `WatchId`s would reconstruct relative to the old root
      // path and deliver a false event; dropping the subtree makes `scope_of` reject them.
      // Re-establishing coverage for the scope is the layer-above's job (a fresh root
      // register), exactly as for any lost watch.
      self.emit_rescan(scope, Location::new());
      self.invalidate_root(scope, rec.watch());
      return;
    }
    // A non-root that owes a widen's adoption proof is the ONE exception, because
    // this record is the only thing left that can refute that proof. The proof is a
    // SNAPSHOT of the chain parent's first complete listing — the adopted watch
    // still holds the slot, the entry is a directory, its identity is the one the
    // widen named — and an object that leaves the slot and returns before the read
    // restores every conjunct of it. Occupancy and identity describe the END of the
    // dark window; neither says the edge was continuous ACROSS it, and the window is
    // one nothing else records — a rename out of the adopted slot and back raises no
    // parent-side half for `reparentable_adoption` to refuse, because the parent that
    // would have raised one either had no watch yet (a minted connector arms strictly
    // after the splice) or had its pre-commit records dropped by the unknown-watch
    // guard (a depth-one widen keys the marker on the reserved root itself). The
    // `(parent, name)` link is therefore never rewritten — nothing observed a move —
    // and still names the very watch the listing then finds: the proof would confirm
    // on an ABA.
    //
    // What that confirmation would certify is not nothing. The adopted subtree's own
    // watches kept recording throughout, and every one of those deliveries
    // reconstructed its path through an edge that did not exist while the object was
    // away — no `Rescan` covering the interval, and the barrier free to settle over
    // it the instant the snapshot confirmed.
    //
    // So the object's own record spends the proof: the same `CountedRetirement`
    // every unprovable adopted edge takes, the cover FIRST and the coverage it ends
    // after, root-anchored because a subtree that has just moved leaves no located
    // path this call may address. And it spends it in time, which is the fence's
    // whole contribution: a confirming listing only STAGES its marker, and the
    // cut requested after that listing puts every record the kernel held ahead of
    // the seal — so an excursion the listing could have concealed reaches this
    // spend while the marker still stands, instead of arriving after a verdict
    // had already been taken and finding nothing to spend. Subtree-LOCAL, as at every other disposal — the
    // containment invariant makes the adopted watch a direct CHILD of the marker it
    // owes, so the chain parent survives to reconcile its own listing, which now
    // meets an emptied slot and installs into it. And the adoptions conjunct is
    // released onto that cover's counted re-arm rather than onto nothing, which is
    // what keeps a spent proof from wedging the scope.
    if let Some(parent) = self.unproven_adoption_of(rec.watch()) {
      let _ = self.release_adoption_marker(parent, scope, AdoptionDisposal::CountedRetirement);
    }
    // A NON-root MoveSelf is otherwise deliberately a no-op. In-queue kernel order
    // (the same contract the cookie window depends on — see `RecordKind::MoveSelf`)
    // means the parent-side records have already run: the node is either
    // detached-and-held (its stale path is fenced; dropping it here would break the
    // pending reparent) or already reparented (its path is CURRENT; dropping it would
    // destroy the coverage the O(1) carry-over just preserved). A parent-side record
    // lost to an overflow is healed by the overflow Rescan + re-arm, which prunes the
    // vacated slot.
    //
    // Neither reason survives the exception above, which is what lets the exception
    // be taken without qualifying either of them: the pending reparent a HELD adopted
    // watch waits on is one the invariant refuses outright, so retiring it breaks
    // nothing that was going to happen, and an already-reparented adopted watch does
    // not exist — that refusal dropped it, so the lookup answers `None` and this is
    // all that is left to do.
  }

  /// Invalidates a scope's root after an OS-driven teardown (a moved, deleted, ignored,
  /// or install-refused root): drops the whole tree AND purges the scope's pending move
  /// halves. The composite pending key carries no root generation, so a half from the
  /// dead generation would otherwise stay pairable — a same-cookie destination in a
  /// re-registered generation of the `ScopeId` could consume it, and its stale class
  /// could reconcile a real directory as a file, silently losing coverage. The caller
  /// emits the unfiltered `Rescan` first (invariant: root invalidation never silent).
  fn invalidate_root(&mut self, scope: ScopeId, root: WatchId) {
    self.drop_subtree(root, DeficitDischarge::Teardown);
    self.purge_scope_pending_moves(scope);
    // As for `unregister_root`: the caller's unconditional `Rescan` plus the
    // teardown own coverage now — no bridge window, deficit book, loss
    // generation, or coverage-work generation survives.
    self.bridge.remove(&scope);
    self.deficits.remove(&scope);
    self.loss_gens.remove(&scope);
    self.coverage_work_epochs.remove(&scope);
  }

  fn on_delete_self(&mut self, scope: ScopeId, rec: &OsRecord) {
    // A root's own deletion ends ALL coverage for the scope. The `Removed` itself is
    // delivered per the registered interest (a root is a directory by construction,
    // so `ondir` applies) — but the coverage loss must never be silent: an
    // unconditional `Rescan` (never filtered, epoch-bumping) follows, exactly as for
    // a moved root, so even a consumer subscribed to none of the change kinds learns
    // its view of the scope just ended. A non-root's consumer-facing `Removed` is the
    // parent-side record's job — its live parent watch still covers it.
    if self.is_root_watch(rec.watch()) {
      if self.ondir_allows(scope, Some(true)) {
        let location = self.location_of(rec.watch());
        self.emit(scope, location, ChangeKind::Removed, rec.evidence());
      }
      self.emit_rescan(scope, Location::new());
      self.invalidate_root(scope, rec.watch());
      return;
    }
    // The watched object itself is gone: tear the watch down NOW rather than waiting
    // for the trailing `Ignored`. A stale entry in the window between the two would
    // make a replacement `Created` at the same slot reuse it (discovery-reuse), and
    // the eventual `Ignored` teardown would then leave the replacement unwatched.
    //
    // The parent-side `Removed` this pairs with is interest- and filter-subject
    // (a `Modified`-only subscription never sees it), so a deficit dying with
    // the deleted subtree carries a covering `Rescan` rather than clearing
    // silently — and the vacancy it leaves is handed to that same `Rescan`, so a
    // stat still outstanding for the slot does not stand a second one. The
    // record is the object's OWN deletion, which is the proof this route needs;
    // the parent-side `Removed` reaches the same emptiness through
    // [`reconcile_slot`](Self::reconcile_slot) and finds the watch already gone,
    // so whichever of the two the driver delivers first owns the cover.
    self.drop_departed_occupant(rec.watch());
  }

  fn on_ignored(&mut self, scope: ScopeId, rec: &OsRecord) {
    let watch = rec.watch();
    // A root's kernel-side teardown with no preceding record (an unmount, an external
    // watch removal) ends the scope's coverage with NO parent watch left to report it:
    // signal with the unconditional `Rescan` before invalidating, as for a deleted or
    // moved root.
    if self.is_root_watch(watch) {
      self.emit_rescan(scope, Location::new());
      self.invalidate_root(scope, watch);
      return;
    }
    // A LIVE non-root ignore is not a deletion. A deleted directory reaches this
    // handler never: its `DeleteSelf` is subscribed and the kernel orders it before
    // the trailing `IN_IGNORED`, and the parent-side `Removed` reconciles the slot —
    // either tears the node down first, so the trailing record names an unregistered
    // watch and dies at `ingest_record`'s opening `scope_of`. What survives to here
    // is a teardown of an object no other record speaks for, and whose slot is
    // occupied still: an `IN_IGNORED` whose self-record the queue dropped, or the
    // unmount of the filesystem the scope ITSELF sits on — the kernel destroys every
    // watch on that superblock and orders the descendants' teardowns against the
    // root's not at all, so a descendant's may be ingested first. (A submount BELOW
    // the root raises nothing here: the enumerate lowering fences descent at the
    // scope's mount frame, so no binding is ever installed across one.) Ending that
    // coverage owes the same two halves a retired binding owes — an unconditional
    // located cover and a counted replacement — rather than the silence a parent-side
    // `Removed` used to be credited with.
    //
    // Under a hold there is no location this call may address: the tree reconstructs
    // the vacated PRE-move path, so a `Rescan` here would send the consumer to re-read
    // a slot the object has left. Defer the REBUILD, not the ISSUE — dirty the hold and
    // let the pairing (or the move window's timeout teardown) carry it, as every other
    // held activity does. When the ignored watch IS the held source, the drop's own
    // `DirtiedHold` reclaim answers `Counted` and stands the root-anchored counted
    // cover: a mid-rename subtree's destination is unknowable, so the root is the
    // only location that cannot be wrong.
    if let Some(source) = self.in_held_subtree(watch) {
      self.book_hold(source);
      self.drop_subtree(watch, DeficitDischarge::CoveringRescan);
      return;
    }
    // Captured before the walk erases the links it reads.
    let slot = self.nodes.get(&watch).and_then(|node| {
      node
        .parent
        .zip(node.name.clone())
        .map(|(parent, name)| (parent, name, node.is_dir))
    });
    self.drop_subtree(watch, DeficitDischarge::CoveringRescan);
    let Some((parent, name, is_dir)) = slot else {
      // A non-root carries both links by construction; without them no slot can be
      // addressed, so the cover falls back to the scope's root.
      self.stand_counted_cover(scope);
      return;
    };
    // Identity is deliberately NOT the retiree's. Nothing here proves the slot still
    // holds the object the dead binding named — an unmount replaces it outright, and
    // an overflow-orphaned teardown leaves what happened unknown — so `None` degrades
    // a later survivor-diff to a rebuild instead of certifying a sameness the record
    // never established.
    self.cover_and_rebuild_slot(scope, parent, name, is_dir, None);
  }

  fn emit_child(&mut self, scope: ScopeId, rec: &OsRecord, kind: ChangeKind) {
    let location = self.record_location(rec);
    self.emit(scope, location, kind, rec.evidence());
  }

  /// The scope's current reconciliation generation ([`Epoch::START`] if never bumped).
  fn epoch_of(&self, scope: ScopeId) -> Epoch {
    self
      .scope_epochs
      .get(&scope)
      .copied()
      .unwrap_or(Epoch::START)
  }

  /// Advances a scope's reconciliation generation and returns the new value. Called on
  /// every non-coalesced reconciliation trigger (through
  /// [`emit_rescan`](Self::emit_rescan)), so the `Rescan` — and every change emitted
  /// after it — carries a generation that strictly dominates whatever the consumer
  /// acted on before the trigger.
  fn bump_epoch(&mut self, scope: ScopeId) -> Epoch {
    let next = self.epoch_of(scope).next();
    self.scope_epochs.insert(scope, next);
    next
  }

  fn emit_rescan(&mut self, scope: ScopeId, location: Location) {
    // The bridge window learns of the loss FIRST, before the coalesce check:
    // a trigger whose `Rescan` folds into a still-queued twin is still a loss
    // in this window (the twin is undelivered, so the window's closing
    // `Rescan` must still postdate it).
    self.bridge_saw_rescan(scope);
    // A `Rescan` IS the reconciliation trigger: bump the generation FIRST so the Rescan,
    // and every later change for this scope, strictly dominates what the consumer holds.
    // But the coalesce is decided BEFORE the bump: a trigger whose Rescan would coalesce
    // into a still-queued identical one adds no new instruction — the queued
    // (undelivered) Rescan's single generation stands for the whole contiguous loss run
    // — and skipping the bump keeps the public epoch contract exact: no delivered change
    // ever carries a generation that no delivered Rescan announced. The decision is a
    // pure read of the event queue, so `emit` re-running it below cannot disagree.
    if self.would_coalesce(scope, &location, &ChangeKind::Rescan) {
      return;
    }
    self.bump_epoch(scope);
    // A `Rescan` bypasses the filter on its own kind, so it needs no evidence
    // to be admitted.
    self.emit(scope, location, ChangeKind::Rescan, Evidence::new());
  }

  fn emit(&mut self, scope: ScopeId, location: Location, kind: ChangeKind, evidence: Evidence) {
    // The delivery filter: narrow to the kinds the consumer registered for. The backend
    // was subscribed to a coverage superset (see `coverage_mask`), so unrequested kinds
    // are expected here and dropped — EXCEPT `Rescan`, the no-silent-loss escape, which
    // is always delivered. `Attrib` records conflate into `Modified` at the change
    // level, so either flag admits it (the exact per-record gate is at the source).
    let interest = self.scope_interest(scope);
    let wanted = match &kind {
      ChangeKind::Rescan => true,
      ChangeKind::Created => interest.created(),
      ChangeKind::Removed => interest.removed(),
      ChangeKind::Moved(_) => interest.moved(),
      ChangeKind::Modified => interest.modified() || interest.attrib(),
    };
    // A change reports ONE kind, but the event behind it may have proven several
    // facts — a mask carrying create AND attrib, a rename half that degrades to a
    // removal. Narrowing on the reported kind alone drops the change entirely for a
    // subscriber who asked about one of the OTHER proven facts, with no `Rescan`
    // covering the silence. So `evidence` admits too: whatever the change is called,
    // it reaches everyone who subscribed to something it proved. Widening only ever
    // turns drop into deliver, and over-delivery is the direction the `Interest`
    // contract already allows.
    if !wanted && !evidence.admits(interest) {
      return;
    }
    if self.would_coalesce(scope, &location, &kind) {
      return;
    }
    let id = self.next_change_id();
    let change = Change::new(id, scope, location, kind, self.epoch_of(scope));
    self.events.push_back(change);
  }

  /// Whether a change of `kind` at `location` would coalesce into the most-recent
  /// still-queued change touching it — the ONE dedup decision, applied by
  /// [`emit`](Self::emit) and consulted by [`emit_rescan`](Self::emit_rescan) before
  /// the epoch bump. A pure read of the event queue and the pending-move store:
  /// consecutive calls with both unchanged return the same answer.
  ///
  /// A parked move half queues NOTHING, so an in-window ancestor transition is
  /// invisible to the queue scan alone — a change touching a pending source is
  /// therefore never coalescible (the pending-store side of the latent-transition
  /// fence; suppression-reducing only, like every widening of the relation).
  ///
  /// Coalesce only an ADJACENT duplicate: suppress iff the most-recent still-queued
  /// change TOUCHING any location this change touches is identical. A change touches its
  /// destination; a `Moved(from)` ALSO touches its source — and this holds on BOTH sides
  /// of the comparison.
  ///
  /// Locations touch by HIERARCHY, not equality: two locations touch iff either is a
  /// prefix of the other ([`locations_touch`](Self::locations_touch)). Every change's
  /// meaning depends on its whole ancestor path — an ancestor transition can remove or
  /// replace the subtree that gives the location its object — and a `Rescan`'s coverage
  /// is its whole subtree, so relatedness runs in BOTH directions and the touch relation
  /// is mutual-prefix; there is no third direction. Concretely:
  /// rescan→create(child)→rescan keeps both rescans (the second may cover a loss ordered
  /// after that create); rescan(/a/b)→removed(/a)→created(/a)→rescan(/a/b) keeps both
  /// rescans (the ancestor swap invalidated the first re-read);
  /// create(/a/b)→removed(/a)→created(/a)→create(/a/b) keeps both creates (suppressing
  /// the second would silently lose /a/b under the recreated parent);
  /// create→remove→create at one location keeps all three; and
  /// move(/a→/b)→create(/a)→move(/a→/b) keeps both moves. Only hierarchy-UNRELATED
  /// (sibling-subtree) interleavings coalesce across, which is sound: a sibling
  /// transition cannot affect this location's object, and a suppressed duplicate of a
  /// state fact leaves the consumer at the same final state.
  ///
  /// Truly-adjacent identical Rescans still coalesce: nothing the earlier Rescan covers
  /// separates them, both losses precede the survivor's delivery-time re-read, the
  /// coalesced trigger never bumps the generation (see `emit_rescan`), and `dedup_key`
  /// ignores the epoch precisely so one delivered instruction can stand for the run.
  ///
  /// Widening the touch relation only ever turns suppress into deliver: an identical
  /// queued candidate shares the exact location (mutual-prefix includes equality), so a
  /// wider relation merely inserts additional NON-identical stoppers ahead of it in the
  /// scan — and extra Rescans or re-delivered state facts are always legal, silence is
  /// not. A queue-wide key set — or a one-sided, destination-only scan — would drop a
  /// real transition and mis-converge the consumer.
  fn would_coalesce(&self, scope: ScopeId, location: &Location, kind: &ChangeKind) -> bool {
    let key: DedupKey = (
      scope,
      location.clone(),
      Self::kind_tag(kind),
      kind.moved_from().cloned(),
    );
    let mut touched: std::vec::Vec<&Location> = std::vec::Vec::with_capacity(2);
    touched.push(&key.1);
    if let Some(source) = key.3.as_ref() {
      touched.push(source);
    }
    // Runs once per emitted change, so it walks the scope's contiguous key range
    // rather than every scope's halves under a filter: bounded by
    // `PENDING_MOVE_CAP`, not by what unrelated roots happen to have parked.
    let pending_blocks = self
      .pending_moves
      .range((scope, FIRST_COOKIE)..)
      .take_while(|((half_scope, _), _)| *half_scope == scope)
      .any(|(_, pending)| {
        self.is_watched(pending.from_parent) && {
          let source = self.pending_from(pending);
          touched
            .iter()
            .any(|&loc| Self::locations_touch(&source, loc))
        }
      });
    if pending_blocks {
      return false;
    }
    self
      .events
      .iter()
      .rev()
      .find(|queued| {
        queued.scope() == scope && {
          let queued_source = queued.kind().moved_from();
          touched.iter().any(|&loc| {
            Self::locations_touch(queued.location(), loc)
              || queued_source.is_some_and(|src| Self::locations_touch(src, loc))
          })
        }
      })
      .is_some_and(|queued| Self::dedup_key(queued) == key)
  }

  /// Hierarchical relatedness for the dedup's touch relation: either location lies
  /// within the other's subtree (prefix-inclusive, so equal locations touch).
  fn locations_touch(a: &Location, b: &Location) -> bool {
    a.starts_with(b) || b.starts_with(a)
  }

  /// Inserts a freshly-minted node — the single funnel every node birth passes
  /// through, so one born directly into a re-arm-flavored state is counted for
  /// [`rearm_settled`](Self::rearm_settled) exactly like a transition into one.
  fn insert_node(&mut self, id: WatchId, node: WatchNode) {
    if node.state.is_rearm() {
      self.rearm_pending_inc(node.scope);
    }
    // A node BORN into `Arming { rearm: true }` is the same suppressed fresh
    // install as a transition into it (see `set_state`). No node is ever born
    // reproving — a reproof targets an already-tracked binding.
    debug_assert!(
      !matches!(node.state, NodeState::Arming { reprove: true, .. }),
      "a freshly-minted node has no prior binding to re-prove"
    );
    if matches!(
      node.state,
      NodeState::Arming {
        rearm: true,
        reprove: false
      }
    ) {
      self.bridge_fresh_rearm(node.scope);
    }
    self.nodes.insert(id, node);
  }

  /// Mints and arms the watch for `(parent, name)`, reporting whether doing so
  /// HEALED the slot's booked darkness — whether `remove_slot_deficit` removed a
  /// real fine entry here, which is the single act that stands the slot's
  /// covering `Rescan`.
  ///
  /// The answer is the OUTCOME, not a prediction of it, which is what a caller
  /// deciding whether it still owes that slot a cover needs: an install this call
  /// did not perform (the slot was already occupied) and one that found no entry
  /// to remove (a book collapsed past [`DEFICIT_CAP`]) both stand nothing, and
  /// only running the install says which happened.
  fn install_child(
    &mut self,
    parent: WatchId,
    scope: ScopeId,
    name: Segment,
    is_dir: bool,
    identity: Option<Identity>,
  ) -> bool {
    // No child under a parent that is not there — a TRIPWIRE, not the mechanism.
    // Every install runs inside some directory's reconcile, and what keeps that
    // directory alive is the containment invariant (see
    // [`pending_adoptions`](Self::pending_adoptions)).
    //
    // Loud in tests, silent in release, because the two failure modes are not
    // comparable. An orphan would be born with a parent link nothing resolves —
    // in no adjacency set, so no drop reaches it, rearm-counted the moment the
    // caller continues the re-arm, and its `Watch` naming a parent the consumer
    // rejects, so NO result can ever release the count: the scope's
    // [`coverage_settled`](Self::coverage_settled) false for the rest of the
    // process. A wedge is the one unacceptable outcome, so a future change that
    // broke locality must not reach it.
    debug_assert!(
      self.nodes.contains_key(&parent),
      "a child is only ever installed under a live parent"
    );
    if !self.nodes.contains_key(&parent) {
      return false;
    }
    // Descent is idempotent: a cold enumerate racing a live `Created` (or
    // duplicate create records) must not mint a second watch for one path, or
    // every record under it would be delivered twice. Reuse any pending-or-live
    // child watch already covering `(parent, name)`.
    if self.child_index.contains_key(&(parent, name.clone())) {
      return false;
    }
    // The slot-heal clear edge (the P2↔P1 interlock): occupying a recorded
    // arm-refused hole heals it, and the hole's dark interval is covered only
    // by the window's closing `Rescan` — so `remove_slot_deficit` stands both
    // bridge bits itself when it removes a real entry, order-robustly (an
    // organic pure grow reaching the hole has no `Rescan` of its own). This is
    // the ONE funnel every fresh INSTALL passes through: `reconcile_slot`'s
    // `Dir` arm, `rearm_enumerate`'s direct installs, the incomplete-read
    // reconciles, `cover_and_rebuild_slot` and the widen's chain build all route
    // here. (A record-driven cold re-install lands here too and stands the bits;
    // its `Removed`+`Created` records already converged an all-interest consumer,
    // so the resulting closing `Rescan` is redundant-but-legal for it and honest
    // for a filtered one.)
    //
    // It is NOT every OCCUPATION, and nothing may read it as one: a paired
    // `MovedTo` re-keys a held subtree straight onto its destination slot
    // ([`reparent`](Self::reparent)), consulting no deficit and healing no hole.
    // So a filled slot is never evidence that some site stood that slot's cover.
    // What an outstanding stat's darkness rests on is carried on the request
    // instead ([`StatSlot::dark_uncovered`]), and only a real heal here
    // discharges it.
    let healed = self.remove_slot_deficit(scope, parent, &name);
    let id = WatchId::new(self.watch_ids.mint());
    let attempt = self.next_arm_attempt();
    let placement = self.placement_now();
    self.insert_node(
      id,
      WatchNode {
        parent: Some(parent),
        name: Some(name.clone()),
        scope,
        is_dir,
        attempt,
        placement,
        moved_at: NEVER_MOVED,
        identity,
        state: NodeState::Arming {
          rearm: false,
          reprove: false,
        },
        children: BTreeSet::new(),
      },
    );
    if let Some(parent_node) = self.nodes.get_mut(&parent) {
      parent_node.children.insert(id);
    }
    self.child_index.insert((parent, name.clone()), id);
    // A descendant watch subscribes with the same coverage augmentation as its root:
    // the scope's requested kinds plus the structural set the tree needs. Delivery is
    // narrowed to the requested interest at emission, not here.
    let mask = Self::coverage_mask(self.scope_interest(scope));
    self.queue_watch(id, crate::action::WatchTarget::child(parent, name), mask);
    healed
  }

  /// Drops the subtree occupying a slot the driving record proves the object has
  /// LEFT — a parent-side removal, the object's own delete, an unpairable
  /// move-out — and hands the vacancy the drop opens to the walk's own covering
  /// `Rescan` wherever the walk stood one
  /// ([`cover_stat_vacancy`](Self::cover_stat_vacancy)).
  ///
  /// The second act that can stand a cover for a slot's current vacancy, beside the
  /// fine-entry removal in [`remove_slot_deficit`](Self::remove_slot_deficit),
  /// and the one no caller could report for itself: what the walk erased — and so
  /// whether the discharge emitted anything — is known only inside it. The two
  /// part company at exactly one place, which is why both are needed: an
  /// occupation racing the request spends the slot's fine entry, so the removal
  /// turns nothing, while the occupant's own subtree may have booked plenty for
  /// the walk to erase.
  ///
  /// Three things make the cover this hands over a cover for THIS vacancy:
  ///
  /// - it is located at the scope ROOT ([`drop_subtree`](Self::drop_subtree)), so
  ///   it reaches every slot of the scope, this one included;
  /// - the drop that stands it is the same walk that EMPTIES the slot, so the
  ///   cover cannot predate the vacancy it is credited to; and
  /// - the record that drove the drop proves the object is gone from the slot, so
  ///   the vacancy carries no darkness continuing PAST the cover — which is what
  ///   separates this from the drops that merely disarm a binding
  ///   (an arm refusal, a retired adoption). Those leave an object that may still
  ///   be there, unwatched: their darkness outlives whatever they emitted, and
  ///   they book it ([`record_slot_deficit`](Self::record_slot_deficit)) or
  ///   rebuild the slot instead of coming here.
  ///
  /// The slot is captured BEFORE the walk erases the links that name it, and only
  /// where the index still points at this very node: a node already detached from
  /// its slot (a held move source, whose name a replacement may since have taken)
  /// empties nothing here and so speaks for no vacancy.
  fn drop_departed_occupant(&mut self, occupant: WatchId) {
    let vacated = self
      .nodes
      .get(&occupant)
      .and_then(|node| node.parent.zip(node.name.clone()))
      .filter(|(parent, name)| self.child_index.get(&(*parent, name.clone())) == Some(&occupant));
    let stood = self.drop_subtree(occupant, DeficitDischarge::CoveringRescan);
    if stood && let Some((parent, name)) = vacated {
      self.cover_stat_vacancy(parent, &name);
    }
  }

  /// Drops the watch subtree rooted at `root`, queuing an
  /// [`Action::Unwatch`] per removed node, and DISCHARGES any coverage
  /// deficits the dropped nodes anchored per `discharge` (see
  /// [`DeficitDischarge`]): a record- or move-driven drop stands a covering
  /// `Rescan` — the structural record that drove it is interest- and
  /// filter-subject and may reach no subscriber; a crawl rebuild re-anchors;
  /// a terminal teardown or a proven-unsubscribed prune discharges silently
  /// (no barrier left to lie to). The covering `Rescan` and the re-anchor
  /// fire ONLY when the walk erased a real entry, so a deficit-free drop
  /// stays silent (the A2 overreach guard).
  ///
  /// # What the deficit-free-drop guard does NOT cover, and why that is the ruling
  ///
  /// One sequence slips between the guard and every act that would otherwise
  /// stand for it. A slot's incumbent is dropped here having erased no
  /// deficit, so this stays silent; the scope's [`DeficitBook`] is COLLAPSED
  /// past [`DEFICIT_CAP`], so nothing fine is booked in its place; no read
  /// lists the name while the slot is empty, so nothing observes the
  /// emptiness; and the slot is then re-occupied cold — by
  /// [`install_child`](Self::install_child), which finds no deficit to remove,
  /// or by [`reparent`](Self::reparent), which consults none. The interval the
  /// slot stood dark is therefore stood for by nothing slot-shaped.
  ///
  /// **Under a collapsed book that interval is covered by the scope-level
  /// marker and the dispatch re-signal alone**, and that is where the
  /// collapsed-book regime's cover for it ends. The trade is the collapse's
  /// whole purpose: past the cap the scope keeps ONE whole-scope marker plus
  /// one root re-arm kick instead of one `Rescan` per hole
  /// ([`resignal_coverage_deficits`](Self::resignal_coverage_deficits)), and
  /// raising darkness here to close the gap would override this guard for
  /// EVERY deficit-free drop — not only the ones that go on to be silently
  /// re-occupied — which is precisely the per-hole bookkeeping the collapse
  /// exists to stop paying.
  ///
  /// So this is a documented boundary rather than an unfound hole: a reader
  /// arriving at the guard meets what it undertakes and what it does not.
  /// Nothing here is load-bearing for an UNcollapsed book, where the slot's
  /// own fine entry is what the drop erases or leaves standing.
  ///
  /// Some markers are discharged separately and on their own condition: they
  /// are not deficit anchors, so a subtree that booked no deficit still owes
  /// them, and their objects provably survive (see
  /// [`stand_counted_cover`](Self::stand_counted_cover)).
  ///
  /// Which is which is not decided here. EVERY per-node marker the walk
  /// reclaims goes through [`reclaim_node_marker`](Self::reclaim_node_marker),
  /// whose exhaustive match makes stating the cover a condition of being
  /// reclaimed at all — see [`NodeMarker`] for why that is structural rather
  /// than a convention.
  ///
  /// One of those covers is a claim about this walk itself: an erased adoption
  /// marker discharges on the ground that the child it adopted is dying here too
  /// ([`DiesWithTheWalk`](AdoptionDisposal::DiesWithTheWalk)). That is the
  /// containment invariant rather than an assumption, and it is what makes this
  /// ONE walk: this destroys `subtree(root)` and nothing else, which is what every
  /// caller's continuation is written on.
  ///
  /// Reports whether the DISCHARGE stood the scope's covering `Rescan` — the
  /// OUTCOME of the match below, never the reason passed in: a walk that erased
  /// nothing stands nothing (A2), a re-anchor BOOKS the loss rather than covering
  /// it, and a teardown or an unsubscribed prune covers nothing by construction.
  /// Where one IS stood it is the window's closing `Rescan`, located at the scope
  /// ROOT and so reaching every slot of the scope — which is what lets
  /// [`drop_departed_occupant`](Self::drop_departed_occupant) hand the vacancy
  /// this walk opens to it. Most callers own no such obligation and ignore the
  /// answer.
  ///
  /// The counted debt's [`stand_counted_cover`] is a root `Rescan` too and is
  /// deliberately NOT reported: it answers for an object that survives somewhere
  /// unnameable rather than for anything this walk did to a slot, and a walk can
  /// owe it having emptied nothing at all.
  ///
  /// [`stand_counted_cover`]: Self::stand_counted_cover
  fn drop_subtree(&mut self, root: WatchId, discharge: DeficitDischarge) -> bool {
    // The dropped subtree's scope, and — for a re-anchor — the dropped
    // child's surviving-parent slot: both captured BEFORE the walk erases
    // them. Every node in a subtree shares the root's scope (scopes are
    // disjoint roots), so the root's scope is where any erased deficit lived.
    let root_scope = self.nodes.get(&root).map(|node| node.scope);
    let reanchor = matches!(discharge, DeficitDischarge::Reanchor)
      .then(|| {
        self.nodes.get(&root).and_then(|node| {
          node
            .parent
            .zip(node.name.clone())
            .map(|(parent, name)| (node.scope, parent, name))
        })
      })
      .flatten();
    // What the walk erased, folded across nodes and markers. Every marker
    // removal goes through the one funnel that produces this
    // ([`reclaim_node_marker`](Self::reclaim_node_marker)), so no marker can be
    // reclaimed without its answer reaching the discharge below.
    let mut erased = ErasedCovers::default();
    let mut stack = std::vec::Vec::new();
    stack.push(root);
    while let Some(id) = stack.pop() {
      let Some(node) = self.nodes.remove(&id) else {
        continue;
      };
      // Removal is the third counter edge beside transition and birth: a node dropped
      // mid-re-arm takes its pending count with it, so a torn-down cascade settles
      // rather than holding `rearm_settled` down forever.
      if node.state.is_rearm() {
        self.rearm_pending_dec(node.scope);
      }
      // Descend via the adjacency set — O(subtree), not an O(N) scan of every node for
      // each popped one. A held (detached) source under `id` is in `children` too, so a
      // torn-down parent reclaims its held child here.
      stack.extend(node.children.iter().copied());
      // Keep the child index in lockstep with the node map: a removed child must leave
      // both, or a later descent would skip re-arming it (stale index) and a path could
      // resolve through a dropped node.
      if node.parent.is_none() {
        self.roots.remove(&node.scope);
      } else {
        if let Some(parent) = node.parent
          && let Some(parent_node) = self.nodes.get_mut(&parent)
        {
          // Detach from the parent's adjacency set (a no-op if the parent is itself
          // mid-drop and already gone).
          parent_node.children.remove(&id);
        }
        // Clear the slot only if it still points to THIS node: a detached-and-held move
        // source keeps its old `(parent, name)`, and a replacement may have taken that
        // slot since — dropping the stale source must not orphan it.
        if let (Some(parent), Some(name)) = (node.parent, node.name.clone())
          && self.child_index.get(&(parent, name.clone())) == Some(&id)
        {
          self.vacate_child_slot(parent, name);
        }
      }
      // Reclaim every per-node marker through the one funnel, and fold each
      // answer in. Iterating `NodeMarker::ALL` rather than open-coding the
      // removals is the point: a marker added to the funnel is asked about
      // here for free, and one added ONLY here would not compile.
      for &marker in NodeMarker::ALL {
        erased.absorb(self.reclaim_node_marker(marker, id, &node));
      }
      self.actions.push_back(Action::Unwatch(id));
    }
    // NOTE: a narrow subtree drop deliberately does NOT purge pending move halves.
    // A half whose source parent was dropped may still pair: its `MovedTo` can
    // arrive at a still-watched destination in the same scope. Keeping it pairable
    // preserves the move; the `handle_timeout` liveness guard (`is_watched(
    // from_parent)`) suppresses the stale `Removed` if no destination ever comes.
    // Whole-scope teardown purges instead — see `unregister_root` /
    // `purge_scope_pending_moves`.
    //
    // Discharge the erased darkness per the named reason. A drop that erased
    // nothing owes nothing, so a clean prune/regrow of deficit-free coverage
    // stays silent (A2).
    //
    // What the discharge actually STOOD is folded up as it goes, so the answer
    // is the outcome rather than a re-reading of the reason: only two of the
    // four discharges can emit anything at all, and either of them can be the
    // silent one.
    let mut stood = false;
    if erased.discharge {
      match discharge {
        // A structural record a filtered subscription would not see cannot
        // stand in for the darkness the deficit tracked: set both bridge bits
        // so the window's closing `Rescan` (which bypasses interest AND
        // filter) covers the whole dark interval for every subscriber.
        DeficitDischarge::CoveringRescan => {
          if let Some(scope) = root_scope {
            self.bridge_saw_rescan(scope);
            self.bridge_fresh_rearm(scope);
            // Both bits on a descending scope ARE the closing `Rescan`:
            // [`settle_bridges`](Self::settle_bridges) emits it at the window's
            // first settle edge, and until that edge `rearm_settled` — and so
            // `coverage_settled` — reads false, so no fence can pass the window
            // the emission covers. A kernel-recursive scope takes neither bit
            // and stands nothing here.
            stood = self.scope_descends(scope);
          }
        }
        // Re-anchor the loss at the surviving parent slot; the crawl's own
        // re-install heals it through `install_child`, or it stays booked for
        // the dispatch re-signal until the vanish's `Removed` converges it.
        DeficitDischarge::Reanchor => {
          if let Some((scope, parent, name)) = reanchor {
            self.record_slot_deficit(scope, parent, name);
          }
        }
        // The scope is gone (its terminal/commit `Rescan` and whole-book wipe
        // own coverage), or the coverage is outside every committed
        // subscription: either way no barrier remains to lie to.
        DeficitDischarge::Teardown | DeficitDischarge::UnsubscribedPrune => {}
      }
    }
    // The counted debts are discharged INDEPENDENTLY of the deficit condition
    // above: none of them is a deficit anchor, so a subtree that booked no
    // deficit still owes them, and none of them is a vanish either — their
    // objects are provably still there. So the covering re-read must be
    // counted (see `stand_counted_cover`). `Teardown` and `UnsubscribedPrune`
    // keep their own ownership arguments: no barrier remains to lie to.
    if erased.counted
      && matches!(
        discharge,
        DeficitDischarge::CoveringRescan | DeficitDischarge::Reanchor
      )
      && let Some(scope) = root_scope
    {
      // Deliberately NOT folded into `stood`. This cover is stood on a claim
      // about an OBJECT — it provably survives at a location this call cannot
      // name — and a walk can owe it having vacated no slot at all (a held source
      // detached long ago, a descent owed to a watch that had already left).
      // Reading a root `Rescan` stood for somebody's whereabouts as the
      // settlement of THIS slot's emptiness is the inference the answer is not
      // entitled to make; the discharge above is, because erased deficits and the
      // slot's own fine entry are the same darkness in the same book.
      self.stand_counted_cover(scope);
    }
    stood
  }

  /// Reclaims one [`NodeMarker`] for the dying node `id`, reporting what
  /// erasing it owes — the ONE removal funnel for every per-node marker
  /// [`drop_subtree`](Self::drop_subtree)'s walk destroys.
  ///
  /// `node` is the entry already taken out of the map, so this reads the dying
  /// node's own state rather than a lookup that would find nothing.
  fn reclaim_node_marker(
    &mut self,
    marker: NodeMarker,
    id: WatchId,
    node: &WatchNode,
  ) -> ErasedCover {
    match marker {
      // A dropped directory's read may never be reported by the driver, so
      // `on_enumerate` would never remove it — leaving the reverse map to grow
      // without bound under repeated drop-while-enumerating. Nothing is owed:
      // the coalesced obligation such a read can carry (`latent_cold`) is to
      // re-arm the very subtree this walk is destroying, and the loss that
      // dirtied it stood its own `Rescan` when it landed.
      NodeMarker::Enumerate => {
        if let NodeState::Enumerating { req, .. } = node.state {
          self.pending_enumerate.remove(&req);
          self.latent_cold.remove(&req);
        }
        ErasedCover::Nothing
      }
      // A dropped directory's outstanding slot stats can never be settled
      // against it — the slots died with it — so their requests are reclaimed
      // exactly as an outstanding enumerate is. What the reclamation OWES is
      // where the two part company: this one RELEASES the scope's settlement
      // loss, and a release owes a replacement.
      NodeMarker::StatSlots => {
        // The darkness the released rows were standing for, folded up BEFORE
        // they go — the release-side twin of the transfer the answer owes.
        //
        // The loss is the whole of what a fence had to go on while the slot may
        // have been an unwatched directory, so ending it hands that interval to
        // whatever is stood in its place. The `Deficits` marker below is not
        // reliably that: this parent may have booked no fine entry for the slot
        // (a book collapsed past [`DEFICIT_CAP`] records none), and a dispatch
        // re-signal may already have spent the entry it did book — either way
        // that marker erases nothing and the walk would stand nothing at all.
        //
        // Asked through the same predicate the answer asks
        // ([`stat_slot_dark`](Self::stat_slot_dark)), and asked HERE because
        // this is where the row can still be read. The slot's occupancy is still
        // the pre-walk truth at this line: this node's children are on the
        // walk's stack and vacate their slots only as they are popped, which is
        // after every marker of THIS node is reclaimed.
        //
        // Gated on the row STANDING the loss, exactly as the answer's transfer
        // is: a request that degraded no fence ends no obligation, and an
        // incumbent that left the slot under it is the departing drop's business
        // rather than this row's.
        let dark = self
          .pending_stat
          .values()
          .filter(|slot| slot.parent == id && slot.stands_loss)
          .any(|slot| self.stat_slot_dark(slot));
        // A settlement loss dies with the request it was standing for: the slot
        // is gone, so no answer can ever arrive to release it, and leaving it
        // standing would degrade every later fence of the scope forever. Counted
        // from the reclaimed rows rather than assumed, since only some of them
        // stand one; each one's scope is its parent's (the invariant checker
        // pins it).
        let mut standing = 0usize;
        self.pending_stat.retain(|_, slot| {
          if slot.parent != id {
            return true;
          }
          standing += usize::from(slot.stands_loss);
          false
        });
        self.stat_loss_dec(node.scope, standing);
        self.stat_slots.retain(|(parent, _), _| *parent != id);
        // Reported as an ERASURE, never placed here: the walk's own
        // [`DeficitDischarge`] decides what an erased cover is worth, and it is
        // the only side that knows. A record- or move-driven drop turns this
        // into the window's closing `Rescan`; a crawl rebuild re-anchors it as a
        // slot hole at the surviving parent, at the same coarser coordinate the
        // erased deficits themselves land on; a terminal teardown and a
        // proven-unsubscribed prune stand nothing, and standing something there
        // would be meaningless — the scope is going away, or the coverage is
        // outside every committed subscription, so no barrier is left to hand it
        // to.
        match dark {
          true => ErasedCover::Discharge,
          false => ErasedCover::Nothing,
        }
      }
      // A dropped watch is no longer a held move source. The hold itself owes
      // nothing: what a hold can accrue is the suppressed-activity debt below,
      // and a hold that suppressed nothing hid nothing.
      NodeMarker::HeldSource => {
        if self.held_sources.remove(&id) {
          self.held_by_scope_dec(node.scope);
        }
        ErasedCover::Nothing
      }
      // A dirtied-hold marker is the ONLY record that activity under a held
      // subtree was suppressed at its stale pre-move path, and it is owed a
      // covering re-read at the hold's resolution. This walk is the single
      // destruction point EVERY variant of that hold passes through —
      // including an ANCESTOR teardown that reclaims a detached-and-held
      // source through the parent link, after which `pending.held` names a
      // dead node and no resolution site could still see the marker — so the
      // debt must be carried here rather than at any consumer. A hold exists
      // because the object was proven to be MOVING, so the cover is COUNTED.
      NodeMarker::DirtiedHold => {
        if self.dirtied_holds.remove(&id) {
          ErasedCover::Counted
        } else {
          ErasedCover::Nothing
        }
      }
      // The same argument for a descent still booked against a node this walk
      // is about to destroy. Reaching here at all means the obligation ESCAPED
      // its stat: an answer settles the descent against the incumbent it finds
      // and takes the entry with it, so anything left is owed to a watch that
      // had already left its slot — a detached move source whose reparent
      // never came. Its subtree dies with its coverage never re-proven and its
      // handles still carrying the object's records, which is the one thing an
      // obligation that cannot be transferred must not do silently.
      NodeMarker::OwedDescent => match self.owed_descents.remove(&id) {
        Some(_) => ErasedCover::Counted,
        None => ErasedCover::Nothing,
      },
      // A dropped reprove arm's outstanding stamp dies with the node. It
      // records WHEN an arm was issued, not coverage: the arm it stamps dies
      // in the same breath, and the counted obligation that arm carried is
      // released through the re-arm counter edge above.
      NodeMarker::ReproveStamp => {
        self.reprove_stamps.remove(&id);
        ErasedCover::Nothing
      }
      // An adoption edge awaiting this node's read dies with it — and an
      // UNVERIFIED adoption is erased COVERAGE, exactly like an erased
      // deficit: the adopted subtree's watches are being disarmed while its
      // edge was never positively confirmed, so the disappearance may be
      // wholly unrecorded (the dark window's mutation had no armed parent to
      // record it, and the drop's driving signal — a cold listing's slot
      // reconcile — delivers no re-read instruction of its own).
      //
      // No separate disposal of the adopted watch is owed: the containment
      // invariant makes it a direct child of THIS node, so the walk that popped
      // this node has already pushed it — which
      // [`DiesWithTheWalk`](AdoptionDisposal::DiesWithTheWalk) asserts.
      NodeMarker::Adoption => {
        match self.release_adoption_marker(id, node.scope, AdoptionDisposal::DiesWithTheWalk) {
          Some(_) => ErasedCover::Discharge,
          None => ErasedCover::Nothing,
        }
      }
      // Its deficit anchors die with it; report a real erasure so the one
      // caller with no coverage story of its own can carry the loss (see
      // `drop_node_deficits` / `drop_subtree_for_crawl_rebuild`).
      NodeMarker::Deficits => match self.drop_node_deficits(node.scope, id) {
        true => ErasedCover::Discharge,
        false => ErasedCover::Nothing,
      },
    }
  }

  /// [`drop_subtree`](Self::drop_subtree) for `rearm_enumerate`'s
  /// non-survivor branch — the one drop with NO coverage story of its own:
  /// nothing is delivered for it, and the crawl rebuilds the slot
  /// `Created`-suppressed, so a real deficit erased with the subtree would
  /// vanish without a trace. If the darkness had healed on disk before the
  /// crawl, the rebuild then reads clean inside a possibly PURE grow window
  /// — no `saw_rescan`, so no closing `Rescan` — and the next sync would
  /// observe a settled, deficit-free scope and resolve a false `Delivered`
  /// over whatever the dark interval hid.
  ///
  /// Carry the loss instead: re-anchor it as a slot hole at the SURVIVING
  /// parent. The crawl's own re-install of that slot heals it through the
  /// [`install_child`](Self::install_child) interlock (both bridge bits →
  /// the window's closing `Rescan` covers the whole dark interval), and a
  /// slot the crawl does not rebuild (the name vanished) stays booked for
  /// the dispatch re-signal until the in-flight `Removed` converges it.
  ///
  /// The carry is only HALF the coverage story, and only the half that is
  /// conditional on a recorded deficit. Retiring the subtree also invalidates
  /// every `WatchId` in it while records naming them may already be queued on
  /// the backend — [`ingest_record`](Self::ingest_record) discards those as an
  /// unrecognized watch — and that is owed whether or not a deficit was
  /// erased. The crawl therefore stands its own opening `Rescan` on top of this
  /// carry for EVERY retirement (see [`rearm_enumerate`](Self::rearm_enumerate)),
  /// including one whose name the listing no longer shows as a directory: the
  /// vanish's own `Removed` is interest- and filter-subject and may itself be
  /// among the records this retirement just orphaned, so it cannot stand in.
  /// Every other `drop_subtree` context (record-delivered churn,
  /// held-subtree resolution, umbrella prune, teardown, root invalidation)
  /// keeps the bare call: those erasures are converged, covered at the hold's
  /// resolution, out of contract, or terminal.
  fn drop_subtree_for_crawl_rebuild(&mut self, child: WatchId) {
    self.drop_subtree(child, DeficitDischarge::Reanchor);
  }

  /// Drops every pending move half belonging to `scope`. Called only where the
  /// scope's whole world ends — consumer teardown ([`unregister_root`](Self::unregister_root)),
  /// OS-driven root loss ([`invalidate_root`](Self::invalidate_root)), and a transport
  /// swap's rebuild ([`rebind_root`](Self::rebind_root)) — so no destination the halves
  /// could pair with can ever validly arrive (invariant b). Each caller emits or owns a
  /// covering `Rescan` for the whole scope, which is what lets the halves go
  /// undelivered: this releases the moves conjunct of
  /// [`coverage_settled`](Self::coverage_settled) wholesale, and the barrier may only
  /// re-open on coverage no longer under discussion.
  fn purge_scope_pending_moves(&mut self, scope: ScopeId) {
    self
      .pending_moves
      .retain(|(half_scope, _), _| *half_scope != scope);
  }

  fn record_location(&self, rec: &OsRecord) -> Location {
    match rec.target() {
      Some(target) => self.location_of(rec.watch()).join(target),
      None => self.location_of(rec.watch()),
    }
  }

  fn child_location(&self, parent: WatchId, name: &Segment) -> Location {
    self.location_of(parent).child(name.clone())
  }

  /// The watch covering `(parent, name)`, pending or live, if any.
  fn child_watch(&self, parent: WatchId, name: &Segment) -> Option<WatchId> {
    self.child_index.get(&(parent, name.clone())).copied()
  }

  /// The held move-source ancestor of `watch` (possibly `watch` itself), if any: the
  /// detached source whose subtree `watch` currently sits in. A record on such a watch
  /// would reconstruct through the source's stale pre-move parent link, so its delivery
  /// must be suppressed for the pairing window. Bounded by the node count.
  fn in_held_subtree(&self, watch: WatchId) -> Option<WatchId> {
    let mut cursor = Some(watch);
    for _ in 0..=self.nodes.len() {
      match cursor {
        Some(id) if self.held_sources.contains(&id) => return Some(id),
        Some(id) => cursor = self.nodes.get(&id).and_then(|node| node.parent),
        None => break,
      }
    }
    None
  }

  /// Whether `child` currently occupies its name-slot under `parent` (i.e. `child_index`
  /// points to it). False for a detached-and-held move source, which stays in the
  /// parent's adjacency set but leaves `child_index` for the pairing window.
  fn is_slot_child(&self, parent: WatchId, child: WatchId) -> bool {
    self
      .nodes
      .get(&child)
      .and_then(|node| node.name.clone())
      .is_some_and(|name| self.child_index.get(&(parent, name)) == Some(&child))
  }

  /// Whether a watch carries an unfulfilled rescan re-arm obligation — a pending arm
  /// that will re-arm (`Arming { rearm: true }`) or an outstanding re-arm read
  /// (`Enumerating { kind: Rearm }`) — so it can be transferred to a replacement watch.
  fn has_rearm_obligation(&self, id: WatchId) -> bool {
    self
      .nodes
      .get(&id)
      .is_some_and(|node| node.state.is_rearm())
  }

  /// Sets a node's [`NodeState`], if it is still registered — the single funnel
  /// every state transition passes through, so the per-scope counter behind
  /// [`rearm_settled`](Self::rearm_settled) is maintained in O(1) at the
  /// transition edges (a node entering or leaving a re-arm-flavored state).
  fn set_state(&mut self, id: WatchId, state: NodeState) {
    let Some(node) = self.nodes.get_mut(&id) else {
      return;
    };
    let was = node.state.is_rearm();
    let is = state.is_rearm();
    let entered_fresh = matches!(
      state,
      NodeState::Arming {
        rearm: true,
        reprove: false
      }
    ) && !matches!(node.state, NodeState::Arming { rearm: true, .. });
    let scope = node.scope;
    node.state = state;
    // A node ENTERING `Arming { rearm: true }` is a `Created`-suppressed
    // fresh install (or a cold→re-arm conversion whose discovery is now
    // suppressed): the bridge window armed coverage whose content only a
    // closing `Rescan` can instruct the consumer to re-read. A REPROVE entry
    // deliberately sets nothing here — whether a dark window existed is
    // unknown until its acknowledgement, which sets the bit iff the binding
    // was re-established (`Installed`); marking at entry would cost one
    // closing `Rescan` per ordinary overflow recovery whose bindings were all
    // live.
    if entered_fresh {
      self.bridge_fresh_rearm(scope);
    }
    if was == is {
      return;
    }
    if is {
      self.rearm_pending_inc(scope);
    } else {
      self.rearm_pending_dec(scope);
    }
  }

  /// Advances `scope`'s coverage-work epoch — called from EVERY funnel through
  /// which one of [`coverage_settled`](Self::coverage_settled)'s stores gains
  /// an entry for the scope, and from nowhere else. Anything that adds a
  /// further conjunct owes its acquisition funnel a call here, or a proof
  /// stamped with this epoch would survive the very window the new conjunct
  /// exists to hold open.
  fn acquired_coverage_work(&mut self, scope: ScopeId) {
    *self.coverage_work_epochs.entry(scope).or_insert(0) += 1;
  }

  /// Counts one node of `scope` entering a re-arm-flavored state.
  fn rearm_pending_inc(&mut self, scope: ScopeId) {
    *self.rearm_pending.entry(scope).or_insert(0) += 1;
    self.acquired_coverage_work(scope);
  }

  /// Counts one node of `scope` leaving a re-arm-flavored state (or being removed
  /// in one), dropping the entry at zero so a settled scope holds no residue.
  fn rearm_pending_dec(&mut self, scope: ScopeId) {
    if let Some(count) = self.rearm_pending.get_mut(&scope) {
      *count -= 1;
      if *count == 0 {
        self.rearm_pending.remove(&scope);
      }
    }
  }

  /// Counts one loss-standing stat of `scope` queued.
  ///
  /// Deliberately NOT [`acquired_coverage_work`](Self::acquired_coverage_work):
  /// the stat is uncounted, so it acquires no coverage work, and bumping the
  /// epoch here would retire every ordering proof a settled window is holding
  /// for a request that adds nothing for a proof to order.
  fn stat_loss_inc(&mut self, scope: ScopeId) {
    *self.stat_losses.entry(scope).or_insert(0) += 1;
  }

  /// Releases `by` of `scope`'s loss-standing stats, dropping the entry at zero
  /// so a scope with none holds no residue. A zero release is a no-op, which is
  /// what lets the teardown edge call it unconditionally with whatever it
  /// reclaimed.
  fn stat_loss_dec(&mut self, scope: ScopeId, by: usize) {
    if by == 0 {
      return;
    }
    if let Some(count) = self.stat_losses.get_mut(&scope) {
      *count -= by;
      if *count == 0 {
        self.stat_losses.remove(&scope);
      }
    }
  }

  /// Whether `slot`'s request spans an interval the slot spent DARK — holding no
  /// watch, so a directory standing there was covered by nothing.
  ///
  /// THE question a released settlement loss owes its replacement for, and it
  /// lives in ONE place because both releases must answer it the same way: the
  /// answer's arrival ([`ingest_stat_result`](Self::ingest_stat_result)) and the
  /// parent's death ([`NodeMarker::StatSlots`]) end the same obligation over the
  /// same interval, and a window one of them called dark while the other called
  /// it covered is a release that hands the darkness to nobody.
  ///
  /// It takes two terms because no single reading carries it.
  ///
  /// The LIVE term says the slot holds no watch at this instant, which is reason
  /// enough to cover. What it does NOT say is that a slot reading OCCUPIED was
  /// never dark: a `Created`, a move-in, or a later enumerate can have filled
  /// the slot under the outstanding request, and the fill covers the interval
  /// before it only where it HEALED a booked hole — a book collapsed past
  /// [`DEFICIT_CAP`] leaves it nothing to heal and it stands nothing at all.
  /// Read as proof of an unbroken cover, the fill would erase exactly the
  /// history the loss was standing for.
  ///
  /// So that history is CARRIED on the request instead
  /// ([`StatSlot::dark_uncovered`]): raised by the read that found the slot
  /// empty, cleared only by a cover actually stood. The live term stays for the
  /// darkness no read ever observed — an incumbent dropped under the request
  /// with nothing re-listing the name — where the carried fact has nothing to
  /// say and the slot is plainly dark now.
  ///
  /// …and that live term is asked of the CURRENT VACANCY, not of emptiness as
  /// such ([`StatSlot::vacancy_covered`]). An emptiness a `File`/`Gone`
  /// reconcile has already handed to a covering `Rescan` stays empty afterwards
  /// — that is what those occupants mean — so "empty here" would resurrect a
  /// cover that already stood and charge the scope a second epoch and a second
  /// enumeration for it. What is asked instead is whether THIS vacancy is still
  /// uncovered: raised by the drop that opens one, cleared by the removal that
  /// covers one, and neither by the slot merely reading empty.
  ///
  /// Darkness ALONE, deliberately: whether the request also STANDS the scope's
  /// settlement loss ([`StatSlot::stands_loss`]) is the caller's separate
  /// conjunct at both releases. A request standing none degraded no fence, so it
  /// ended no obligation and owes no replacement — the departure it may have
  /// witnessed belongs to whatever performed it.
  fn stat_slot_dark(&self, slot: &StatSlot) -> bool {
    slot.dark_uncovered
      || (self.child_watch(slot.parent, &slot.name).is_none() && !slot.vacancy_covered)
  }

  /// Raises everything an EMPTY-slot read owes against an ALREADY-OUTSTANDING
  /// request — the dedup half of [`queue_stat`](Self::queue_stat)'s emptiness
  /// rule, and BOTH of the halves that rule stands.
  ///
  /// A stat is coalesced across every read that re-encounters the name, so what
  /// the answer discharges must be the strongest any of them carried. A slot
  /// occupied when the first read asked can be emptied under the standing
  /// request (its incumbent removed, or replaced by a non-directory), and the
  /// next read to list the name unclassifiable then books darkness over a slot
  /// this scope covers with nothing. Returning silently there would leave that
  /// read's hole with no loss standing at all.
  ///
  /// The DARKNESS ([`StatSlot::dark_uncovered`]) is raised AHEAD of the loss's
  /// own idempotence, because the two are not raised by the same populations: a
  /// registration-stamped request already stands the loss over a slot it watched
  /// all along, and short-circuiting on that would let the emptiness this read is
  /// reporting reach the answer as though the slot had never been dark. The loss
  /// half stays idempotent below, so the common case — a re-list of a slot whose
  /// request already stands both — adds nothing and the counter keeps mirroring
  /// the map.
  fn raise_stat_darkness(&mut self, req: ReqId) {
    let Some(slot) = self.pending_stat.get_mut(&req) else {
      return;
    };
    slot.dark_uncovered = true;
    if slot.stands_loss {
      return;
    }
    slot.stands_loss = true;
    let scope = slot.scope;
    self.stat_loss_inc(scope);
  }

  /// Tells any stat outstanding for `(parent, name)` that the vacancy the slot
  /// holds has just been handed a cover
  /// ([`StatSlot::vacancy_covered`]) — so its answer, which will find the slot
  /// still empty, does not stand a second one over the same interval.
  ///
  /// Called from the settlement whose cover is stood over a slot that stays
  /// empty, by each of the two acts within it that can stand one — the departing
  /// occupant's teardown ([`drop_departed_occupant`](Self::drop_departed_occupant))
  /// and the fine entry's removal
  /// ([`remove_slot_deficit`](Self::remove_slot_deficit)) — and bound in both
  /// cases to that act's OWN answer: a walk that erased nothing and a collapsed
  /// book that held nothing each stand nothing, and a stat still looking at an
  /// uncovered emptiness must not be told otherwise. Raising is idempotent, so a
  /// settlement in which both acts fire says the same thing twice.
  fn cover_stat_vacancy(&mut self, parent: WatchId, name: &Segment) {
    if let Some(&req) = self.stat_slots.get(&(parent, name.clone()))
      && let Some(slot) = self.pending_stat.get_mut(&req)
    {
      slot.vacancy_covered = true;
    }
  }

  /// Empties the slot `(parent, name)` in [`child_index`](Self::child_index),
  /// and tells any stat outstanding for it that the vacancy it is now looking at
  /// is a NEW one ([`StatSlot::vacancy_covered`]): whatever covered the last one
  /// covered an interval that ended when something occupied this slot.
  ///
  /// The ONE funnel every occupied-to-empty transition passes through — the
  /// detach of a move source ([`detach_child`](Self::detach_child)) and the drop
  /// walk's slot clear ([`drop_subtree`](Self::drop_subtree)) are the only two
  /// removals there are — which is what makes the flag readable as a fact about
  /// the CURRENT vacancy. A removal added outside it would leave a stale cover
  /// standing over a fresh darkness, which costs a MISSED cover; there is no
  /// counter to catch that, so the funnel is the guarantee.
  ///
  /// Clears on the removal's own answer: a call that took nothing out opened no
  /// vacancy — the slot already held none, or held a replacement this removal is
  /// not entitled to orphan — and discharges nothing.
  fn vacate_child_slot(&mut self, parent: WatchId, name: Segment) {
    if self.child_index.remove(&(parent, name.clone())).is_none() {
      return;
    }
    if let Some(&req) = self.stat_slots.get(&(parent, name))
      && let Some(slot) = self.pending_stat.get_mut(&req)
    {
      slot.vacancy_covered = false;
    }
  }

  /// Counts one detached-and-held move source of `scope` — called iff the
  /// `held_sources` insert actually inserted, so the count mirrors membership.
  fn held_by_scope_inc(&mut self, scope: ScopeId) {
    *self.held_by_scope.entry(scope).or_insert(0) += 1;
    self.acquired_coverage_work(scope);
  }

  /// Counts one held move source of `scope` released — called iff the
  /// `held_sources` remove actually removed, dropping the entry at zero.
  fn held_by_scope_dec(&mut self, scope: ScopeId) {
    if let Some(count) = self.held_by_scope.get_mut(&scope) {
      *count -= 1;
      if *count == 0 {
        self.held_by_scope.remove(&scope);
      }
    }
  }

  /// Flushes every bridge window whose scope has settled — the tail of every
  /// public mutating entry point, AFTER all synchronous cascading, so the
  /// transient mid-call zero-crossings of the re-arm counter (a linear-chain
  /// rebuild zeroes it at every level) are never observed. Cross-method
  /// transient zeros cannot occur: a window's frontier is always counted —
  /// each completing input re-raises the counter within its own call (an arm
  /// success queues its read; a read completion installs-and-inherits), and
  /// an un-arrived arm result holds `Arming { rearm: true }`.
  ///
  /// At each settle edge: a scope whose root is gone drops its entry
  /// (teardown machinery owns coverage from there); a scope with BOTH bits
  /// set emits the closing `Rescan` at the scope root (see [`BridgeFlags`]
  /// for why the conjunction); either way the entry is removed — the window
  /// is over, and a lossy window that armed nothing fresh must not leak its
  /// `saw_rescan` into a later unrelated grow (a standing hole's loss fact
  /// survives in the [`DeficitBook`] and re-enters through the heal edges).
  /// The emit itself re-sets `saw_rescan`; removing the entry AFTER it leaves
  /// the next window a clean slate.
  fn settle_bridges(&mut self) {
    if self.bridge.is_empty() {
      return;
    }
    let flagged: std::vec::Vec<ScopeId> = self.bridge.keys().copied().collect();
    for scope in flagged {
      if !self.rearm_settled(scope) {
        continue;
      }
      if self.roots.contains_key(&scope) {
        let flags = self.bridge.get(&scope).copied().unwrap_or_default();
        if flags.saw_rescan && flags.fresh_rearm {
          self.emit_rescan(scope, Location::new());
        }
      }
      self.bridge.remove(&scope);
    }
  }

  /// Marks `scope`'s bridge window lossy — a `Rescan` passed. Set FIRST in
  /// [`emit_rescan`](Self::emit_rescan) (a coalesced trigger is still a loss
  /// in this window); a no-op for a kernel-recursive scope.
  fn bridge_saw_rescan(&mut self, scope: ScopeId) {
    if self.scope_descends(scope) {
      self.bridge.entry(scope).or_default().saw_rescan = true;
    }
  }

  /// Whether `scope`'s bridge window is ALREADY marked lossy — a `Rescan` has
  /// passed since the window's last settle edge. Read by a site that would
  /// otherwise stand its own opening `Rescan` purely to supply the window's
  /// loss half: the window's closing `Rescan` postdates everything inside it,
  /// so once the bit is set a second opening `Rescan` instructs the consumer
  /// to do nothing it is not already going to do. Never a substitute for the
  /// loss half itself — a site that does not also make the window COUNTED must
  /// emit, since the conjunction would otherwise never fire.
  fn bridge_is_lossy(&self, scope: ScopeId) -> bool {
    self
      .bridge
      .get(&scope)
      .is_some_and(|flags| flags.saw_rescan)
  }

  /// Marks `scope`'s bridge window as having armed suppressed coverage — a
  /// node entered `Arming { rearm: true }`. Fed by the two state funnels
  /// ([`set_state`](Self::set_state) / [`insert_node`](Self::insert_node));
  /// the descending gate is a belt (the state is unreachable elsewhere).
  fn bridge_fresh_rearm(&mut self, scope: ScopeId) {
    if self.scope_descends(scope) {
      self.bridge.entry(scope).or_default().fresh_rearm = true;
    }
  }

  /// Seeds `scope`'s BOOTSTRAP mark — the registration window is open. Called
  /// from the registration birth site only (and re-stated by
  /// [`reprofile_root`](Self::reprofile_root) when a provisional profile is
  /// replaced by a descending one). The mark's funeral is the bridge entry's own
  /// removal: the scope's first settle edge, or either terminal teardown.
  fn bridge_bootstrap(&mut self, scope: ScopeId) {
    if self.scope_descends(scope) {
      self.bridge.entry(scope).or_default().bootstrap = true;
    }
  }

  /// Whether `scope`'s registration window is still open.
  fn in_bootstrap_window(&self, scope: ScopeId) -> bool {
    self.bridge.get(&scope).is_some_and(|flags| flags.bootstrap)
  }

  /// The registration window's LOSS half: a FRESH directory install by a
  /// suppressed crawl, while the bootstrap mark stands, marks the window lossy.
  ///
  /// A suppressed crawl announces no `Created`, so ground it arms for the first
  /// time may hold an entry created between the grant and that directory's own
  /// arm — recorded by no kernel watch (the arm-before-readdir invariant is
  /// per-directory, not per-scope) and announced by no listing. Standing the
  /// loss half here is what makes the window's closing `Rescan` fire, which is
  /// the one instruction that covers the whole gap.
  ///
  /// A SURVIVOR re-arm deliberately never calls this: a survivor was already
  /// covered, so only newly-armed ground can hold an unreported pre-arm
  /// creation. The distinction is exactly [`install_child`]'s occupation check,
  /// which is why this is called at the named install sites and never inside the
  /// generic funnels ([`insert_node`](Self::insert_node),
  /// [`set_state`](Self::set_state), [`inherit_rearm`](Self::inherit_rearm)):
  /// those cannot tell a suppressed-crawl install from a record-driven cold one,
  /// and a funnel-level rule would fire on a kernel `Created` racing the
  /// bootstrap — a spurious closing `Rescan` on an otherwise-empty root.
  ///
  /// The mark's standing is a STEADY-STATE claim about which sites fire, not an
  /// in-window invariant. A second suppressed crawl is reachable while the mark
  /// stands (an overflow recovery, a grow-hijack, an incomplete-read retry, a
  /// held read, an in-window regrow), and the rule fires there too. Every such
  /// interleaving is benign: `saw_rescan` is monotone within a window
  /// ([`emit_rescan`](Self::emit_rescan) sets it before the coalesce check) so a
  /// fire at an already-covered site is a no-op, and the remainder are covers in
  /// the safe direction. A per-site "not in-window" guard would break the HELD
  /// case, which is a site with no cover of its own.
  ///
  /// [`install_child`]: Self::install_child
  fn mark_bootstrap_loss(&mut self, scope: ScopeId) {
    if self.in_bootstrap_window(scope) {
      self.bridge_saw_rescan(scope);
    }
  }

  /// Counted covering recovery for a teardown that drops a subtree whose object
  /// provably SURVIVES at an unknown in-scope location — a teardown that cannot
  /// borrow [`drop_subtree`](Self::drop_subtree)'s erasure argument.
  ///
  /// That argument ("erased nothing, so owes nothing") is about a subtree whose
  /// object VANISHED: once it is gone no later record can describe it, so the
  /// dead handles carry nothing to lose and a fully-proven subtree may go
  /// silently. It does not reach a teardown the monitor performs while HOLDING a
  /// record that proves the object survives inside the scope. There the dead
  /// handles keep carrying the live object's records until the `Unwatch` lands,
  /// and [`ingest_record`](Self::ingest_record) discards those as an unrecognized
  /// watch — while every signal such a teardown does emit (`Removed`, `Created`,
  /// `Moved`) is interest- and filter-subject, so a `Modified`-only subscription
  /// receives no instruction at all. The window's closing `Rescan` bypasses both,
  /// which is precisely what that subscription needs.
  ///
  /// The recovery is COUNTED, and that is the whole point. Standing the two bridge
  /// bits alone would leave the window with nothing to wait on — [`settle_bridges`]
  /// gates on [`rearm_settled`](Self::rearm_settled) — so the window would flush
  /// inside this very call: the closing `Rescan` would PRECEDE the recovery instead
  /// of closing it, and [`coverage_settled`](Self::coverage_settled) could read true
  /// while the surviving subtree was still blind.
  ///
  /// The re-arm is anchored at the scope ROOT because every caller reaches here
  /// holding exactly the same gap: the object's current home is not a location this
  /// call can name. A refused source's contents live at a destination the refusal
  /// deliberately forgot and can never pair; a nameless destination gives the tree
  /// no slot to re-cover at; a late or cyclic arrival whose destination parent died
  /// with the held subtree reconstructs only a stale pre-move path; and a stale
  /// adoption edge means the adopted subtree's true path is unknowable. The only
  /// node guaranteed to be an ancestor — if the object is in scope at all — is the
  /// root. An object OUTSIDE the scope leaves the root crawl nothing fresh to arm,
  /// `fresh_rearm` never sets, and the bridge conjunction suppresses the closing
  /// `Rescan` on its own: honest rather than faked.
  ///
  /// [`inherit_rearm`](Self::inherit_rearm), never
  /// [`start_rearm`](Self::start_rearm): a root that is still `Arming` (a widen
  /// leaves a live tree processing records under one) REFUSES a bare re-arm, which
  /// would reproduce the exact uncounted opening `Rescan` this exists to prevent.
  /// The `Arming` arm marks the post-arm read instead, so the obligation is counted
  /// and bridge-marked either way.
  ///
  /// No loss-generation bump, no binding re-proof, no marking of parked halves: a
  /// refusal carries no kernel-loss evidence — the record stream is intact and every
  /// retained binding is as alive as before — and bumping the generation mid-ingest
  /// would re-stale in-flight reprove arms and shift
  /// [`scope_needs_reproof`](Self::scope_needs_reproof) for every later record of the
  /// same batch.
  ///
  /// [`settle_bridges`]: Self::settle_bridges
  fn stand_counted_cover(&mut self, scope: ScopeId) {
    if !self.scope_descends(scope) {
      return;
    }
    let Some(&root) = self.roots.get(&scope) else {
      return;
    };
    self.emit_rescan(scope, self.location_of(root));
    let _ = self.inherit_rearm(root);
  }

  /// Records a slot hole `(parent, name)` in `scope`'s deficit book (see
  /// [`DeficitBook::slots`]). A `Rescan` covers only changes up to itself while
  /// the slot stays dark on disk, so this carries the level-persistent fact past
  /// whatever the edge stood.
  ///
  /// The entry is a standing COORDINATE, never a claim that a `Rescan` already
  /// stands for it — its four callers do not agree about that, and one of them
  /// stands none:
  ///
  /// - an **arm-refused install** ([`ingest_watch_result`]) emits the hole's
  ///   `Rescan` immediately before booking;
  /// - an **unresolvable stat answer** ([`ingest_stat_result`]) emits it
  ///   immediately after — or, under a hold whose slot reconstructs to the
  ///   vacated pre-move path, leaves it to the pairing its fence dirtied;
  /// - a **re-anchored deficit**
  ///   ([`drop_subtree_for_crawl_rebuild`](Self::drop_subtree_for_crawl_rebuild))
  ///   carries the `Rescan` that stood when the erased entry was originally
  ///   recorded;
  /// - an **empty-slot `Unknown` reconcile** ([`reconcile_slot`]) stands NO
  ///   `Rescan` — the read that reached it may have stood none of its own (a
  ///   pure grow, or a record-driven cold read). Its window is covered instead
  ///   by the settlement loss [`queue_stat`](Self::queue_stat) stands for the
  ///   request that decides the slot ([`stat_losses`](Self::stat_losses)), for
  ///   exactly as long as the answer is owed — and the answer that ends it hands
  ///   that loss to a covering `Rescan` of its own wherever the settlement finds
  ///   no entry to heal (see [`ingest_stat_result`]). Which is NOT only where
  ///   this call recorded none: the entry it does record is spent by any
  ///   dispatch re-signal ([`resignal_deficits`](Self::resignal_deficits)) that
  ///   reaches the slot first, and the loss outlives it.
  ///
  /// Never beneath a parent that is gone. A hole is a COORDINATE, and the
  /// re-signal reconstructs it from the parent's own location: with the parent
  /// dead that reconstruction truncates to whatever prefix survives, so the entry
  /// would degrade every later fence of the scope and then re-instruct a path the
  /// hole was never about. A dead parent's own darkness is discharged by the drop
  /// that killed it, under that drop's [`DeficitDischarge`].
  ///
  /// A tripwire on the containment invariant, like
  /// [`install_child`](Self::install_child)'s: every caller books against a
  /// coordinate it holds live, and the one act that could have invalidated one
  /// mid-continuation is refused at its source.
  ///
  /// [`ingest_watch_result`]: Self::ingest_watch_result
  /// [`ingest_stat_result`]: Self::ingest_stat_result
  /// [`reconcile_slot`]: Self::reconcile_slot
  fn record_slot_deficit(&mut self, scope: ScopeId, parent: WatchId, name: Segment) {
    if !self.scope_descends(scope) {
      return;
    }
    debug_assert!(
      self.nodes.contains_key(&parent),
      "a slot hole is only ever booked beneath a live parent"
    );
    if !self.nodes.contains_key(&parent) {
      return;
    }
    let book = self.deficits.entry(scope).or_default();
    if book.collapsed {
      return;
    }
    book.slots.entry(parent).or_default().insert(name);
    Self::enforce_deficit_cap(book);
  }

  /// Records an exhausted-read interior hole for `dir` in `scope`'s book
  /// (see [`DeficitBook::interiors`]).
  ///
  /// Never for a `dir` that is gone, on the same grounds as
  /// [`record_slot_deficit`](Self::record_slot_deficit): the claim is about the
  /// unreconciled interior of a LIVE directory, re-signalled at that directory's
  /// location, and a dead one has neither. Same tripwire, same reason.
  fn record_interior_deficit(&mut self, scope: ScopeId, dir: WatchId) {
    if !self.scope_descends(scope) {
      return;
    }
    debug_assert!(
      self.nodes.contains_key(&dir),
      "an interior hole is only ever booked for a live directory"
    );
    if !self.nodes.contains_key(&dir) {
      return;
    }
    let book = self.deficits.entry(scope).or_default();
    if book.collapsed {
      return;
    }
    book.interiors.insert(dir);
    Self::enforce_deficit_cap(book);
  }

  /// Collapses a book past [`DEFICIT_CAP`] to the whole-scope marker, keeping
  /// memory and re-signal work bounded under mass failure.
  fn enforce_deficit_cap(book: &mut DeficitBook) {
    if book.fine_len() > DEFICIT_CAP {
      book.slots.clear();
      book.interiors.clear();
      book.collapsed = true;
    }
  }

  /// Whether `scope`'s book carries a FINE entry for the slot `(parent, name)` —
  /// the darkness whose removal stands the covering `Rescan`
  /// ([`remove_slot_deficit`](Self::remove_slot_deficit)).
  ///
  /// A COLLAPSED book answers `false`: the collapse records the scope's darkness
  /// at ROOT granularity and keeps no entry for any settlement to heal, so this
  /// is a strictly narrower question than
  /// [`has_coverage_deficit`](Self::has_coverage_deficit).
  ///
  /// An OBSERVATION, deliberately available to white-box cells and to nothing
  /// else. A standing entry says the darkness was recorded, never that anything
  /// has covered it, so no site may decide what it owes the slot by reading one:
  /// what discharges an obligation is a cover observed being STOOD
  /// (`remove_slot_deficit`'s own answer, which the settlement paths return),
  /// and the two part company at every occupation that heals nothing.
  #[cfg(test)]
  fn slot_deficit_booked(&self, scope: ScopeId, parent: WatchId, name: &Segment) -> bool {
    self
      .deficits
      .get(&scope)
      .and_then(|book| book.slots.get(&parent))
      .is_some_and(|names| names.contains(name))
  }

  /// Removes a recorded slot hole, reporting whether one was recorded. When it
  /// removes a REAL entry it stands the covering `Rescan` (both bridge bits →
  /// the window's closing `Rescan`): the hole's darkness ends here — an
  /// [`install_child`](Self::install_child) occupation heals it, or a
  /// `Removed`/`File` occupant empties it — and every driver of that end is
  /// either `Created`-suppressed (a re-arm install) or interest- and
  /// filter-subject (a structural record a `Modified`-only subscription never
  /// sees), so ONLY a covering `Rescan` (which bypasses interest AND filter)
  /// can honestly discharge it. A no-op removal (no such entry) sets nothing,
  /// so a clean occupation of a deficit-free slot stays silent (A2).
  ///
  /// A real removal is also the DISCHARGE for any outstanding stat's claim on
  /// the same slot ([`StatSlot::dark_uncovered`]): the cover stood here is the
  /// one that claim was waiting for, so the answer must not stand a second.
  /// Bound to the same `removed` flag as the bridge bits, which is what keeps
  /// the two from drifting — an occupation that healed NOTHING (a book collapsed
  /// past [`DEFICIT_CAP`] holds no entry to heal) stands no cover here and
  /// discharges no claim, leaving the answer owing the transfer.
  ///
  /// The claim's other half — whether the cover this stood was stood over a slot
  /// left EMPTY ([`StatSlot::vacancy_covered`]) — is decided by the CALLER, which
  /// is the only side that knows: the same removal empties the slot from
  /// [`reconcile_slot`](Self::reconcile_slot)'s `File`/`Gone` arm and occupies it
  /// from [`install_child`](Self::install_child). And this is not the only act
  /// that can raise that half — the emptying's own teardown
  /// ([`drop_departed_occupant`](Self::drop_departed_occupant)) stands a cover
  /// this book knows nothing about, which is why the half is a suppressor with no
  /// mirrored obligation rather than a mirror of `removed`.
  fn remove_slot_deficit(&mut self, scope: ScopeId, parent: WatchId, name: &Segment) -> bool {
    let Some(book) = self.deficits.get_mut(&scope) else {
      return false;
    };
    let Some(names) = book.slots.get_mut(&parent) else {
      return false;
    };
    let removed = names.remove(name);
    if names.is_empty() {
      book.slots.remove(&parent);
    }
    self.gc_deficit_book(scope);
    if removed {
      self.bridge_saw_rescan(scope);
      self.bridge_fresh_rearm(scope);
      // The same act, told to the request that is waiting to hear it: this slot's
      // darkness has been handed to a cover, so the answer owes no second one.
      if let Some(&req) = self.stat_slots.get(&(parent, name.clone()))
        && let Some(slot) = self.pending_stat.get_mut(&req)
      {
        slot.dark_uncovered = false;
      }
    }
    removed
  }

  /// The interior-heal clear edge: a CLEAN completion for `dir` reconciled the
  /// interior a standing deficit said was dark. When it removes a REAL entry
  /// it stands the covering `Rescan` (both bridge bits → the window's closing
  /// `Rescan`, the P2↔P1 interlock): a standing interior deficit is only ever
  /// cleared by a re-arm read (the resignal heal-kick, or a cascade — a Live
  /// interior never re-enters a fresh COLD read while its deficit stands),
  /// whose content is `Created`-suppressed, so only a covering `Rescan` (which
  /// bypasses interest AND filter) instructs a `Modified`-only subscription to
  /// re-read the now-reconciled interior — even when the healing window was
  /// otherwise clean (an organic pure grow reaching the hole). A no-op removal
  /// sets nothing, so a clean read of a deficit-free interior stays silent (A2).
  fn clear_interior_deficit(&mut self, scope: ScopeId, dir: WatchId) {
    let Some(book) = self.deficits.get_mut(&scope) else {
      return;
    };
    let removed = book.interiors.remove(&dir);
    self.gc_deficit_book(scope);
    if removed {
      self.bridge_saw_rescan(scope);
      self.bridge_fresh_rearm(scope);
    }
  }

  /// Drops the fine entries anchored at a dying node — `drop_subtree`'s
  /// hook — reporting whether any were actually recorded, so the caller can
  /// discharge the erasure per its named [`DeficitDischarge`]: a record- or
  /// move-driven drop stands a covering `Rescan` (the structural record is
  /// filter-subject and may reach no subscriber); a crawl rebuild re-anchors
  /// at the surviving parent; a teardown or unsubscribed prune discharges
  /// silently. The hook itself sets no bits — the reason lives at the
  /// `drop_subtree` call site, where the context is known.
  fn drop_node_deficits(&mut self, scope: ScopeId, id: WatchId) -> bool {
    let Some(book) = self.deficits.get_mut(&scope) else {
      return false;
    };
    let interior = book.interiors.remove(&id);
    let slots = book.slots.remove(&id).is_some();
    self.gc_deficit_book(scope);
    interior || slots
  }

  /// Removes an emptied, uncollapsed book — the entry-present-only-while-
  /// non-empty invariant.
  fn gc_deficit_book(&mut self, scope: ScopeId) {
    if self.deficits.get(&scope).is_some_and(DeficitBook::is_clear) {
      self.deficits.remove(&scope);
    }
  }

  /// Marks `watch`'s outstanding enumerate as dirtied by a racing slot-changing record,
  /// so its listing is treated as a stale snapshot when it returns. A no-op unless
  /// `watch` is currently [`NodeState::Enumerating`].
  fn mark_enumerate_dirty(&mut self, watch: WatchId) {
    if let Some(node) = self.nodes.get_mut(&watch)
      && let NodeState::Enumerating { dirty, .. } = &mut node.state
    {
      *dirty = true;
    }
  }

  /// The `(name, identity)` of every in-slot child watch of `dir` — the
  /// directory listing a faithful read of a filesystem matching the tree
  /// would return. For the property storms, whose enumerate results must
  /// track the tree through moves for identity-matched survivors to arise.
  #[cfg(test)]
  fn slot_children(&self, dir: WatchId) -> std::vec::Vec<(Segment, Option<Identity>)> {
    let Some(node) = self.nodes.get(&dir) else {
      return std::vec::Vec::new();
    };
    node
      .children
      .iter()
      .filter(|child| self.is_slot_child(dir, **child))
      .filter_map(|child| {
        let child = self.nodes.get(child)?;
        Some((child.name.clone()?, child.identity))
      })
      .collect()
  }

  /// Answers `id`'s CURRENT arm attempt — what a driver that captured the token
  /// off the `Action::Watch` it is replying to would echo. The default for every
  /// test not ABOUT supersession, which drives
  /// [`on_watch_result`](Self::on_watch_result) directly with the two attempts it
  /// must tell apart. An unknown handle answers under an arbitrary attempt, so
  /// the unknown-node guard is still the thing under test.
  #[cfg(test)]
  fn ack_watch(&mut self, id: WatchId, res: Result<crate::WatchAck, WatchError>) {
    let attempt = self
      .arm_attempt(id)
      .unwrap_or_else(|| ArmAttempt::new(NonZeroU64::MIN));
    self.on_watch_result(id, attempt, res);
  }

  /// Whether `dir` has a rescan re-arm read outstanding — the successor to the old
  /// `rearm_dirs` membership, for white-box tests.
  #[cfg(test)]
  fn is_rearm_enumerating(&self, dir: WatchId) -> bool {
    matches!(
      self.nodes.get(&dir).map(|node| node.state),
      Some(NodeState::Enumerating {
        kind: EnumKind::Rearm { .. },
        ..
      })
    )
  }

  /// Asserts the Monitor's core structural invariants. Run after every input in the
  /// property tests to turn silent corruption into an immediate counterexample.
  #[cfg(test)]
  fn assert_invariants(&self) {
    let n = self.nodes.len();
    // `child_index` agrees with the node it points at, and that node sits in its
    // parent's adjacency set (name-slot ⊆ adjacency).
    for ((parent, name), child) in &self.child_index {
      let node = self
        .nodes
        .get(child)
        .expect("child_index points at a live node");
      assert_eq!(
        node.parent,
        Some(*parent),
        "child_index parent matches node.parent"
      );
      assert_eq!(
        node.name.as_ref(),
        Some(name),
        "child_index name matches node.name"
      );
      assert!(
        self
          .nodes
          .get(parent)
          .is_some_and(|p| p.children.contains(child)),
        "a child_index child is in its parent's adjacency set"
      );
    }
    for (id, node) in &self.nodes {
      // Adjacency is the exact dual of the parent link.
      for child in &node.children {
        assert_eq!(
          self.nodes.get(child).and_then(|c| c.parent),
          Some(*id),
          "an adjacency child's parent is this node"
        );
      }
      if let Some(parent) = node.parent {
        assert!(
          self
            .nodes
            .get(&parent)
            .is_some_and(|p| p.children.contains(id)),
          "a node is in its parent's adjacency set"
        );
      }
      // Every outstanding enumerate request maps back through `pending_enumerate`.
      if let NodeState::Enumerating { req, .. } = node.state {
        assert_eq!(
          self.pending_enumerate.get(&req),
          Some(id),
          "an Enumerating node's request is registered to it"
        );
      }
      // Acyclicity: the parent walk reaches a root within the node count.
      let mut cursor = node.parent;
      for _ in 0..=n {
        match cursor {
          Some(cur) => cursor = self.nodes.get(&cur).and_then(|c| c.parent),
          None => break,
        }
      }
      assert!(
        cursor.is_none(),
        "the parent walk terminates (the tree is acyclic)"
      );
    }
    // Reverse of the enumerate check: every pending request maps to a live node that
    // still names it, so a dropped/superseded read leaks no bookkeeping.
    for (req, dir) in &self.pending_enumerate {
      assert!(
        matches!(
          self.nodes.get(dir).map(|node| node.state),
          Some(NodeState::Enumerating { req: r, .. }) if r == *req
        ),
        "a pending_enumerate request maps to a live node that names it"
      );
    }
    // Root uniqueness, the structural half of the duplicate-registration guard:
    // a parentless node IS its scope's registered root. Both mint sites
    // (`register_root_with_profile`, `widen_root`) re-point `roots` in the same
    // call, and no path ever clears a `parent` afterwards — a detached move
    // source keeps its `(parent, name)` — so this holds by construction, and
    // that is exactly what makes `drop_subtree`'s unconditional
    // `roots.remove(&node.scope)` on the parentless branch provably safe rather
    // than accidentally safe. A second parentless node in one scope cannot also
    // equal `roots[scope]`, so this one comparison carries both clauses: every
    // parentless node is the registered root, and no scope has two of them.
    for (id, node) in &self.nodes {
      if node.parent.is_none() {
        assert_eq!(
          self.roots.get(&node.scope),
          Some(id),
          "a parentless node is its scope's one registered root"
        );
      }
    }
    // Every registered root has a stored delivery interest and capability profile.
    for scope in self.roots.keys() {
      assert!(
        self.scope_interests.contains_key(scope),
        "a registered root's scope has a delivery interest"
      );
      assert!(
        self.scope_profiles.contains_key(scope),
        "a registered root's scope has a capability profile"
      );
    }
    // A held source is a live node; a dirtied hold is a held source.
    for held in &self.held_sources {
      assert!(
        self.nodes.contains_key(held),
        "a held source is a live node"
      );
    }
    for dirtied in &self.dirtied_holds {
      assert!(
        self.held_sources.contains(dirtied),
        "a dirtied hold is a held source"
      );
    }
    // The incremental per-scope re-arm-pending counter equals a from-scratch
    // recount of re-arm-flavored nodes — and holds no zero-count entries, since
    // the recount cannot produce one.
    let mut recount: BTreeMap<ScopeId, usize> = BTreeMap::new();
    for node in self.nodes.values() {
      if node.state.is_rearm() {
        *recount.entry(node.scope).or_insert(0) += 1;
      }
    }
    assert_eq!(
      self.rearm_pending, recount,
      "the re-arm-pending counter matches a from-scratch recount"
    );
    // The per-scope held-source counter equals a from-scratch recount of
    // `held_sources` grouped by scope (its exact mirror, no zero entries).
    let mut held_recount: BTreeMap<ScopeId, usize> = BTreeMap::new();
    for held in &self.held_sources {
      let scope = self
        .scope_of(*held)
        .expect("a held source is a live node (checked above)");
      *held_recount.entry(scope).or_insert(0) += 1;
    }
    assert_eq!(
      self.held_by_scope, held_recount,
      "the held-by-scope counter matches a from-scratch recount"
    );
    // A bridge entry exists only for a registered, descending scope, and only
    // while at least one bit is set (the flush removes it at every settle
    // edge; a root-less scope is trivially settled, so none can linger).
    for (scope, flags) in &self.bridge {
      assert!(
        flags.saw_rescan || flags.fresh_rearm || flags.bootstrap,
        "a bridge entry carries at least one set bit"
      );
      assert!(
        self.roots.contains_key(scope),
        "a bridge entry's scope has a registered root"
      );
      assert!(
        self.scope_descends(*scope),
        "a bridge entry's scope descends"
      );
    }
    // A deficit book exists only for a registered, descending scope; it is
    // non-empty or collapsed (never both: collapse absorbs the fine entries);
    // its fine count respects the cap; and every anchor is a live node of the
    // book's scope (`drop_subtree` reclaims a dying node's entries).
    for (scope, book) in &self.deficits {
      assert!(
        self.roots.contains_key(scope),
        "a deficit book's scope has a registered root"
      );
      assert!(
        self.scope_descends(*scope),
        "a deficit book's scope descends"
      );
      assert!(
        !book.is_clear(),
        "a deficit book is present only while non-empty (or collapsed)"
      );
      if book.collapsed {
        assert!(
          book.slots.is_empty() && book.interiors.is_empty(),
          "a collapsed book holds no fine entries"
        );
      }
      assert!(
        book.fine_len() <= DEFICIT_CAP,
        "the fine-grained book respects DEFICIT_CAP"
      );
      for (parent, names) in &book.slots {
        assert!(!names.is_empty(), "no empty slot-hole set is retained");
        let node = self
          .nodes
          .get(parent)
          .expect("a slot hole's parent anchor is a live node");
        assert_eq!(
          node.scope, *scope,
          "a slot hole's parent anchor belongs to the book's scope"
        );
      }
      for dir in &book.interiors {
        let node = self
          .nodes
          .get(dir)
          .expect("an interior hole's anchor is a live node");
        assert_eq!(
          node.scope, *scope,
          "an interior hole's anchor belongs to the book's scope"
        );
      }
    }
    // Every same-transport adoption marker keys a LIVE directory node of a
    // DESCENDING scope (`drop_subtree`, `rebind_root`, and the read-resolution
    // paths reclaim it with its parent). One scope MAY carry several markers
    // at once — back-to-back widens splice a fresh tail above the previous one
    // before its first read resolves — but never two on one parent (widen
    // tails are freshly minted; the map keying enforces it structurally).
    //
    // And the CONTAINMENT invariant (see [`Monitor::pending_adoptions`]): the
    // adopted watch is dead, or still a direct child of the marker's own key. It
    // is what makes every `drop_subtree` local to the subtree its caller named,
    // enforced by refusing to reparent an unproven adopted edge — so it is
    // checked here, over the whole map, after every input the storms drive.
    let mut adopting: BTreeMap<ScopeId, usize> = BTreeMap::new();
    for (parent, marker) in &self.pending_adoptions {
      let node = self
        .nodes
        .get(parent)
        .expect("an adoption marker keys a live node");
      assert!(node.is_dir, "an adoption marker keys a directory");
      assert!(
        self.scope_descends(node.scope),
        "an adoption marker's scope descends"
      );
      assert!(
        self
          .nodes
          .get(&marker.adopted)
          .is_none_or(|adopted| adopted.parent == Some(*parent)),
        "a live adopted watch is still a direct child of the marker it owes"
      );
      *adopting.entry(node.scope).or_insert(0) += 1;
    }
    assert_eq!(
      adopting, self.adopting_by_scope,
      "the adoption settle counter mirrors the marker map exactly"
    );
    // Staging is a SUBSET of the standing markers, keyed under the marker's own
    // scope — the property the seal's latch rests on, because a staged entry
    // that outlived its marker would keep a scope owing a seal nothing can
    // answer. The single release funnel is what maintains it.
    for (scope, parent) in self.staged_adoptions.keys() {
      let marker_scope = self
        .pending_adoptions
        .get(parent)
        .and_then(|_| self.nodes.get(parent))
        .map(|node| node.scope);
      assert_eq!(
        marker_scope,
        Some(*scope),
        "a staged adoption names a standing marker of its own scope"
      );
    }
    // The reprove-stamp map mirrors `Arming { reprove: true }` membership
    // exactly: every outstanding reproof is stamped, no stamp outlives its
    // arm, and a reproof is always re-arm-flavored.
    let mut reproving: BTreeSet<WatchId> = BTreeSet::new();
    for (id, node) in &self.nodes {
      if let NodeState::Arming { rearm, reprove } = node.state {
        assert!(rearm || !reprove, "a reprove arm is always re-arm-flavored");
        if reprove {
          reproving.insert(*id);
        }
      }
    }
    assert_eq!(
      self.reprove_stamps.keys().copied().collect::<BTreeSet<_>>(),
      reproving,
      "the reprove-stamp map mirrors reprove-arming membership exactly"
    );
    for (id, stamp) in &self.reprove_stamps {
      let scope = self.scope_of(*id).expect("a stamped arm is a live node");
      assert!(
        *stamp <= self.loss_gen(scope),
        "no stamp postdates its scope's loss generation"
      );
    }
    // No placement reading may postdate the clock: every one is taken FROM it
    // and the clock only advances, so a greater reading would mean a stamp
    // survived a rewind — and a stamp that postdates a move reads as fresh
    // exactly where it must not.
    for node in self.nodes.values() {
      assert!(
        node.placement <= self.placement_clock && node.moved_at <= self.placement_clock,
        "no node's placement readings postdate the placement clock"
      );
    }
    for slot in self.pending_stat.values() {
      assert!(
        slot.placement <= self.placement_clock,
        "no stat's placement reading postdates the placement clock"
      );
    }
    // The stat dedup index mirrors the outstanding requests' slots exactly, and
    // every such slot names a live parent — a dead parent's stats are reclaimed
    // with its node.
    assert_eq!(
      self
        .pending_stat
        .values()
        .map(|slot| (slot.parent, slot.name.clone()))
        .collect::<BTreeSet<_>>(),
      self.stat_slots.keys().cloned().collect::<BTreeSet<_>>(),
      "the stat dedup index mirrors the outstanding stat slots exactly"
    );
    // And each index entry names the very request that owes that slot — the
    // lookup a deferral rides on, so a stale mapping would silently book an
    // obligation against a slot whose answer is not coming.
    for (slot, req) in &self.stat_slots {
      let pending = self
        .pending_stat
        .get(req)
        .expect("the stat dedup index names an outstanding request");
      assert_eq!(
        (pending.parent, pending.name.clone()),
        *slot,
        "the stat dedup index maps a slot to the request holding it"
      );
    }
    for slot in self.pending_stat.values() {
      let node = self
        .nodes
        .get(&slot.parent)
        .expect("an outstanding stat names a live parent");
      assert_eq!(
        node.scope, slot.scope,
        "an outstanding stat belongs to its parent's scope"
      );
    }
    // The settlement-loss counter mirrors the loss-standing outstanding stats
    // exactly. A counter that over-read would degrade every later fence of the
    // scope for the rest of its life; one that under-read would certify the very
    // window this signal exists to refuse — so it is pinned to the map rather
    // than trusted to its three edges.
    let mut standing: BTreeMap<ScopeId, usize> = BTreeMap::new();
    for slot in self.pending_stat.values().filter(|slot| slot.stands_loss) {
      *standing.entry(slot.scope).or_insert(0) += 1;
    }
    assert_eq!(
      standing, self.stat_losses,
      "the stat settlement-loss counter mirrors the loss-standing requests exactly"
    );
    // …and the REGISTRATION half of the predicate is never lost inside the
    // union: a stamped request stands the loss whatever its slot held. Pinned
    // separately because the mirror above is satisfied by ANY consistent pair of
    // maps, including one where the stamp had quietly stopped raising it.
    for slot in self.pending_stat.values() {
      assert!(
        !slot.bootstrap || slot.stands_loss,
        "a registration-stamped stat always stands its scope's settlement loss"
      );
      // …and so does a request carrying an uncovered dark interval, which is the
      // union's other member: the transfer that hands that interval a cover is
      // the RELEASED LOSS's replacement, so a request owing one without standing
      // a loss would be emitting a cover for a window no fence was ever degraded
      // over.
      assert!(
        !slot.dark_uncovered || slot.stands_loss,
        "a stat carrying uncovered darkness always stands its scope's settlement loss"
      );
    }
    // Every booked descent names a LIVE watch — the drop walk is the funnel
    // that discharges one whose owner dies, so a key with no node would be an
    // obligation nothing can ever perform and nothing ever covered.
    for owed in self.owed_descents.keys() {
      assert!(
        self.nodes.contains_key(owed),
        "a booked descent is owed to a live watch"
      );
    }
    // Every latent cold read is an outstanding request whose node still names
    // it, reads COLD, was dirtied by the coalesced trigger, and belongs to the
    // recorded scope — the exact mirror of the insert edge.
    for (req, scope) in &self.latent_cold {
      let dir = self
        .pending_enumerate
        .get(req)
        .expect("a latent cold read is an outstanding enumerate");
      let node = self
        .nodes
        .get(dir)
        .expect("a pending enumerate maps to a live node (checked above)");
      assert_eq!(
        node.scope, *scope,
        "a latent cold read belongs to the scope it was recorded under"
      );
      assert!(
        matches!(
          node.state,
          NodeState::Enumerating {
            req: r,
            kind: EnumKind::Cold,
            dirty: true,
            ..
          } if r == *req
        ),
        "a latent cold read's node holds the dirtied cold read"
      );
    }
  }

  /// Where `id` sits relative to the root of its own scope — `Some` only when
  /// the parent walk PROVES it, and `None` otherwise.
  ///
  /// The scope root itself is `Some(Location::new())`: the empty location, which
  /// is [`Location`]'s own convention for "the watched root". A watch one level
  /// down is `Some` of a one-segment location, and so on; the segments are
  /// root-first and already canonical for their volume (see [`Segment`]).
  ///
  /// This is the derivation the layer above should use instead of keeping its own
  /// map of where each watch sits. The monitor addresses coverage by [`WatchId`]
  /// plus parent links, and a rename repairs those links in O(1) at the splice —
  /// so a location read back through here is correct after a move by
  /// construction, with nothing to re-anchor by hand.
  ///
  /// # `None` does not mean "at the root"
  ///
  /// `None` means the walk from `id` did not terminate at the [`WatchId`]
  /// registered as its scope's root, so this monitor cannot say where `id` is.
  /// Concretely: `id` names no live node; its scope has no registered root; a
  /// parent link points at a node that is gone (an ancestor was removed out from
  /// under it); a non-root node carries no name; or the walk exceeded the live
  /// node count, which a chain can only do by cycling.
  ///
  /// The root answers `Some(Location::new())` — an EMPTY location, not `None`. A
  /// caller that treats `None` as "empty, therefore the root" turns "unknown"
  /// into "the root path", and every path it then derives lands at the top of the
  /// watched tree instead of where the watch actually is. That is the specific
  /// wrong answer this accessor exists to make unrepresentable, and it is why
  /// this is not a wrapper over the internal lenient walk: that walk stops early
  /// on a missing node or an exhausted bound and returns whatever prefix it had
  /// collected, which composes into a plausible path near the root. A
  /// short-but-plausible location is worse than no location, because a caller
  /// joining it onto a root path cannot tell the two apart.
  ///
  /// # Do not cache the result
  ///
  /// Re-derive per use. A location is a fact about the tree at the instant it is
  /// read, and the tree moves: a rename relocates a whole subtree by rewriting
  /// one parent link, and every location under it changes with no notification to
  /// a holder of an earlier answer. A stored copy is a mirror of the tree that
  /// something must now repair on every move — which is exactly the hand-repaired
  /// mirror that deriving from here is meant to delete. Nothing in the type
  /// prevents caching, so the discipline lives here.
  ///
  /// The one legitimate keep is a location captured deliberately as a HISTORICAL
  /// fact — where something was when an event was observed. Such a value must not
  /// be read back later as where the watch is now.
  ///
  /// # Stability
  ///
  /// The `None` contract above is the semver-relevant part of this signature: a
  /// later relaxation that answered with a short location where this answers
  /// `None` would still compile at every call site, and would put back the exact
  /// wrong answer the `Option` was introduced to exclude. Widening it is a
  /// breaking change even though the type does not change.
  ///
  /// ```
  /// use core::num::NonZeroU64;
  /// use tributary_proto::{Capabilities, Interest, Location, Monitor, ScopeId};
  ///
  /// let mut monitor = Monitor::new(Capabilities::new());
  /// let scope = ScopeId::new(NonZeroU64::new(1).unwrap());
  /// let root = monitor.register_root(scope, Interest::all()).expect("a fresh scope");
  ///
  /// // The scope root IS a location: the empty one.
  /// assert_eq!(monitor.location_of_checked(root), Some(Location::new()));
  ///
  /// // A handle with no node is not placeable — and that is a different answer
  /// // from the root's, which is the whole point of the `Option`.
  /// let unplaced = monitor.reserve_watch_id();
  /// assert_eq!(monitor.location_of_checked(unplaced), None);
  /// ```
  pub fn location_of_checked(&self, id: WatchId) -> Option<Location> {
    let root = *self.roots.get(&self.nodes.get(&id)?.scope)?;
    let mut segments = std::vec::Vec::new();
    let mut cursor = id;
    // A simple path in a tree of `n` nodes visits at most `n` of them, so a walk
    // still running after `n` steps is revisiting one: a cycle, which answers
    // `None` rather than the prefix collected so far.
    for _ in 0..self.nodes.len() {
      if cursor == root {
        segments.reverse();
        return Some(Location::from_segments(segments));
      }
      let node = self.nodes.get(&cursor)?;
      // A non-root node names its slot in its parent; one that does not cannot be
      // placed, and skipping it would silently shorten the answer by a level.
      segments.push(node.name.clone()?);
      cursor = node.parent?;
    }
    None
  }

  /// The lenient walk: reconstructs as much of `id`'s location as the tree can
  /// still supply, and TRUNCATES silently when it cannot supply all of it (a
  /// missing node, an exhausted bound). Its callers reconstruct locations for
  /// changes they are emitting under a `WatchId` a live record just arrived on,
  /// or under an anchor they have already liveness-guarded
  /// ([`live_pending_from`](Self::live_pending_from)), so the truncating branches
  /// are unreachable for them. Anything outside those guarantees — above all a
  /// location handed across the public boundary to be joined onto a root path —
  /// wants [`location_of_checked`](Self::location_of_checked), which reports the
  /// same conditions as `None` instead of as a short location.
  fn location_of(&self, id: WatchId) -> Location {
    let mut segments = std::vec::Vec::new();
    let mut cursor = Some(id);
    // Bounded by the node count: reparent guards keep the tree acyclic, but a walk
    // that never reaches a root would otherwise loop — a path cannot exceed the
    // number of live nodes.
    for _ in 0..self.nodes.len() {
      let Some(current) = cursor else {
        break;
      };
      let Some(node) = self.nodes.get(&current) else {
        break;
      };
      if let Some(name) = &node.name {
        segments.push(name.clone());
      }
      cursor = node.parent;
    }
    segments.reverse();
    Location::from_segments(segments)
  }

  fn is_root_watch(&self, id: WatchId) -> bool {
    self
      .nodes
      .get(&id)
      .map(|node| node.parent.is_none())
      .unwrap_or(false)
  }

  /// Mints the token for one arm attempt. Attempts, like every proto handle,
  /// are never reused — a reused one could not tell a superseded outcome from
  /// the current arm's.
  fn next_arm_attempt(&mut self) -> ArmAttempt {
    ArmAttempt::new(self.arm_attempts.mint())
  }

  /// Issues the [`Action::Watch`] arming `id`, under a FRESH attempt token
  /// recorded on the node. The single funnel every queued arm passes through,
  /// which is what makes "the node names the one attempt whose outcome counts"
  /// an invariant rather than a convention: an arm issued here supersedes every
  /// earlier one for the handle at the instant it is queued, so a result still
  /// in flight for one of those is discarded by
  /// [`ingest_watch_result`](Self::ingest_watch_result) instead of being
  /// applied to the binding that replaced it.
  fn queue_watch(&mut self, id: WatchId, target: crate::action::WatchTarget, mask: Interest) {
    let attempt = self.next_arm_attempt();
    let placement = self.placement_now();
    if let Some(node) = self.nodes.get_mut(&id) {
      node.attempt = attempt;
      // The arm's addressing is a coordinate the driver lowers, and the reading
      // that judges its acknowledgement is taken where the lowering happens —
      // at the dispatch ([`stamp_dispatch`](Self::stamp_dispatch)). This is the
      // conservative FLOOR for the interval before that: an arm never handed
      // out was never lowered, so nothing about it may read fresher than the
      // node's own last round trip, and answering "moved" for one costs a
      // re-address rather than a false certification.
      node.placement = placement;
    }
    self
      .actions
      .push_back(Action::watch(id, attempt, target, mask));
  }

  /// Rebinds an EXISTING node to a fresh attempt with NO action queued,
  /// returning the token — the one supersession that issues nothing.
  ///
  /// Two callers, one shape: a rebind's new-transport root, whose arm the
  /// driver already executed out of band and whose replayed outcome must carry
  /// this token, and [`retire_arm`](Self::retire_arm), where the node has no
  /// slot left for an arm to name at all. Either way the arms that came before
  /// are superseded from this instant. (A widen's pre-armed root is born with
  /// its attempt instead, having had no node to rebind.)
  fn adopt_arm(&mut self, id: WatchId) -> ArmAttempt {
    let attempt = self.next_arm_attempt();
    let placement = self.placement_now();
    if let Some(node) = self.nodes.get_mut(&id) {
      node.attempt = attempt;
      // An out-of-band arm was executed by the driver against the placement in
      // effect NOW, so its replayed outcome is stamped current — the rebind that
      // reaches here has already recorded the root swap it is committing, and
      // this arm is the one issued after it.
      node.placement = placement;
    }
    attempt
  }

  fn next_change_id(&mut self) -> ChangeId {
    ChangeId::new(self.change_ids.mint())
  }

  fn next_req_id(&mut self) -> ReqId {
    ReqId::new(self.req_ids.mint())
  }

  fn dedup_key(change: &Change) -> DedupKey {
    let from = match change.kind() {
      ChangeKind::Moved(from) => Some(from.clone()),
      _ => None,
    };
    (
      change.scope(),
      change.location().clone(),
      Self::kind_tag(change.kind()),
      from,
    )
  }

  const fn kind_tag(kind: &ChangeKind) -> u8 {
    match kind {
      ChangeKind::Created => 0,
      ChangeKind::Modified => 1,
      ChangeKind::Removed => 2,
      ChangeKind::Moved(_) => 3,
      ChangeKind::Rescan => 4,
    }
  }
}

#[cfg(test)]
mod tests;
