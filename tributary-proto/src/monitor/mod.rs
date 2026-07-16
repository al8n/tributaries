//! The primitive-agnostic top half: the `Monitor` state machine.

use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::{
  action::Action,
  capabilities::Capabilities,
  change::{Change, ChangeKind},
  error::WatchError,
  id::{ChangeId, Epoch, Identity, MoveCookie, ReqId, ScopeId, Sequence, WatchId},
  interest::Interest,
  path::{Location, Segment},
  record::{EnumerateResult, OsRecord, RecordKind},
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnumKind {
  /// Discovery of a freshly-armed directory — each entry is a new `Created`.
  Cold,
  /// A rescan re-arm — reconcile the watch set without emitting `Created`.
  Rearm,
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
  Arming { rearm: bool },
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
      Self::Arming { rearm: true }
        | Self::Enumerating {
          kind: EnumKind::Rearm,
          ..
        }
    )
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
#[derive(Debug, Clone, Copy, Default)]
struct BridgeFlags {
  saw_rescan: bool,
  fresh_rearm: bool,
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

/// Key for a half-resolved rename. A [`MoveCookie`] is unique only within one
/// backend instance, and disjoint roots may live on separate instances whose
/// cookies collide, so the cookie is namespaced by its [`ScopeId`]: a destination
/// may consume a source only under the identical composite key (invariant d). The
/// tuple derives `Ord` from both components, so it keys a `BTreeMap`.
type PendingKey = (ScopeId, MoveCookie);

/// A delivery-dedup key: a change is suppressed only if an identical one is still
/// queued. Two changes are "identical" when they share a scope, location, kind
/// discriminant, and — for a [`ChangeKind::Moved`] — the same source location.
/// Carrying the source keeps two distinct renames to one destination from
/// collapsing into a single move; for every other kind the source slot is `None`.
type DedupKey = (ScopeId, Location, u8, Option<Location>);

/// What now occupies a child slot, as reported by a slot-changing record. `Dir`
/// is the only kind the core descends into (and thus watches per-directory);
/// `File` and `Gone` both mean the slot must hold no watch. Consumed by
/// [`Monitor::reconcile_slot`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum SlotOccupant {
  /// A directory: watch it (per-directory backends descend into it).
  Dir,
  /// A non-directory file: never watched.
  File,
  /// The slot's object was removed: drop any watch it had.
  Gone,
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
  /// Half-resolved renames awaiting their destination, keyed by `(scope, cookie)`.
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
      nodes: BTreeMap::new(),
      child_index: BTreeMap::new(),
      roots: BTreeMap::new(),
      scope_epochs: BTreeMap::new(),
      scope_interests: BTreeMap::new(),
      scope_profiles: BTreeMap::new(),
      rearm_pending: BTreeMap::new(),
      pending_enumerate: BTreeMap::new(),
      pending_moves: BTreeMap::new(),
      held_sources: BTreeSet::new(),
      dirtied_holds: BTreeSet::new(),
      bridge: BTreeMap::new(),
      deficits: BTreeMap::new(),
      held_by_scope: BTreeMap::new(),
      latent_cold: BTreeMap::new(),
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
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn register_root(&mut self, scope: ScopeId, mask: Interest) -> WatchId {
    self.register_root_with_profile(scope, mask, self.capabilities)
  }

  /// Registers a new disjoint watched root governed by its OWN capability
  /// profile, overriding the constructor default for this scope only.
  ///
  /// This is how one Monitor hosts mixed backends: a driver selecting per root
  /// (a kernel-recursive fanotify mark on one filesystem, per-directory inotify
  /// on another) registers each root with the profile its backend satisfies.
  /// Everything else matches [`register_root`](Self::register_root).
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn register_root_with_profile(
    &mut self,
    scope: ScopeId,
    mask: Interest,
    caps: Capabilities,
  ) -> WatchId {
    let id = WatchId::new(self.watch_ids.mint());
    self.insert_node(
      id,
      WatchNode {
        parent: None,
        name: None,
        scope,
        is_dir: true,
        identity: None,
        state: NodeState::Arming { rearm: false },
        children: BTreeSet::new(),
      },
    );
    self.roots.insert(scope, id);
    self.scope_interests.insert(scope, mask);
    self.scope_profiles.insert(scope, caps);
    self.actions.push_back(Action::watch(
      id,
      crate::action::WatchTarget::Root(scope),
      Self::coverage_mask(mask),
    ));
    id
  }

  /// Replaces the capability profile of an already-registered root — the narrow
  /// window a driver uses when a per-root backend is chosen only once its source
  /// has spawned (`Backend::Auto`: register provisionally, then adopt the
  /// probed backend's profile before the root's watch-result is fed).
  ///
  /// Sound only while the root is still bootstrapping: its node has no children
  /// and no record has been ingested, so `caps` governs only decisions still to
  /// come (the post-arm cold enumerate, every later descent gate). A no-op for
  /// an unregistered scope.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn reprofile_root(&mut self, scope: ScopeId, caps: Capabilities) {
    if self.roots.contains_key(&scope) {
      self.scope_profiles.insert(scope, caps);
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
      self.drop_subtree(root);
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
      // book's fine entries; this also reclaims a collapsed marker).
      self.bridge.remove(&scope);
      self.deficits.remove(&scope);
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
        self.drop_subtree(watch);
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
      Some(NodeState::Arming { rearm: false })
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
  /// Returns the surviving root `WatchId`, or `None` for an unknown scope or
  /// a [`kernel_recursive`](Capabilities::kernel_recursive) one (a KR swap
  /// replaces the stream whole; there is no per-directory book to rebind).
  pub fn rebind_root(&mut self, scope: ScopeId) -> Option<WatchId> {
    let root = *self.roots.get(&scope)?;
    if !self.scope_descends(scope) {
      return None;
    }
    let children: std::vec::Vec<WatchId> = self
      .nodes
      .get(&root)
      .map(|node| node.children.iter().copied().collect())
      .unwrap_or_default();
    for child in children {
      self.drop_subtree(child);
    }
    self.purge_scope_pending_moves(scope);
    // The old world's standing deficits die with its transport: the commit's
    // covering `Rescan` plus the full re-arm rebuild re-attempt everything,
    // and a still-broken site re-records through its own failure edge. The
    // BRIDGE entry deliberately survives — the commit `Rescan` the caller
    // emits right after re-sets `saw_rescan` anyway, and the root reset below
    // sets `fresh_rearm`; the flush cannot fire mid-rebind because the method
    // ends with the root counted.
    self.deficits.remove(&scope);
    // An old-world root read that will never be reported must not leak its
    // request slot (`drop_subtree` does this for children; the root survives).
    if let Some(NodeState::Enumerating { req, .. }) = self.nodes.get(&root).map(|node| node.state) {
      self.pending_enumerate.remove(&req);
      self.latent_cold.remove(&req);
    }
    self.set_state(root, NodeState::Arming { rearm: true });
    if let Some(node) = self.nodes.get_mut(&root) {
      node.identity = None;
    }
    self.settle_bridges();
    Some(root)
  }

  /// Whether `scope` has no outstanding re-arm work: no node of the scope is
  /// pending an arm that continues a re-arm or holds an in-flight re-arm read.
  /// O(1).
  ///
  /// This is the coverage-reconcile settle predicate: a driver that triggered
  /// re-arm work for `scope` — a [`rearm_watch_subtree`](Self::rearm_watch_subtree)
  /// grow, an [`on_overflow`](Self::on_overflow) recovery — polls this after
  /// feeding results back to learn when that work has quiesced. Cold discovery
  /// never holds it down: a fresh root's or a live-churn directory's initial arm
  /// and enumerate run in non-re-arm states by construction, so consumer churn
  /// inside a settled scope cannot starve a fence built on this predicate. Every
  /// counted obligation is bounded — an unreadable re-arm read retries at most
  /// `REARM_MAX_RETRIES` times before its [`Rescan`](ChangeKind::Rescan) stands —
  /// so each terminal is armed-live or dropped-with-a-standing-`Rescan`, and a
  /// pending scope settles in bounded steps. A scope with no re-arm-flavored
  /// nodes — unknown, torn down, or simply idle — is trivially settled (`true`).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn rearm_settled(&self, scope: ScopeId) -> bool {
    !self.rearm_pending.contains_key(&scope)
  }

  /// Whether `scope` is settled for BARRIER purposes: no counted re-arm work
  /// ([`rearm_settled`](Self::rearm_settled)), no detached-and-held move
  /// source (whose suppressed records' covering `Rescan` has not been emitted
  /// yet — it is owed only at the hold's pairing or timeout resolution), and
  /// no in-flight cold read carrying a coalesced re-arm obligation (the one
  /// latency `rearm_settled` deliberately does not count; its completion
  /// escalates into a covering `Rescan` plus a counted retry). A fence built
  /// on the bare re-arm predicate would settle inside either window and
  /// dispatch a sync cookie no covering `Rescan` precedes. Trivially `true`
  /// for a kernel-recursive scope (none of the three states is reachable) and
  /// for an unknown or torn-down one.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn coverage_settled(&self, scope: ScopeId) -> bool {
    self.rearm_settled(scope) && self.holds_settled(scope) && self.latent_settled(scope)
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
  /// edge, with a fresh edge `Rescan`, before the kicked (counted) work can
  /// settle. A site currently inside a held (mid-move) subtree keeps its
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

  /// Whether `scope` has no in-flight cold read carrying a coalesced re-arm
  /// obligation. O(latent) — the set is empty outside a loss racing a cold
  /// discovery.
  fn latent_settled(&self, scope: ScopeId) -> bool {
    !self.latent_cold.values().any(|s| *s == scope)
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
      // heal probe (bounded — `start_rearm` refuses a pending or dead root,
      // whose own arm outcome re-attempts coverage anyway).
      self.emit_rescan(scope, Location::new());
      let _ = self.start_rearm(root);
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
        self.dirtied_holds.insert(hold);
        continue;
      }
      self.emit_rescan(scope, self.location_of(dir));
      let _ = self.start_rearm(dir);
      if let Some(book) = self.deficits.get_mut(&scope) {
        book.interiors.remove(&dir);
      }
      signaled = true;
    }
    for (parent, name) in slots {
      if let Some(hold) = self.in_held_subtree(parent) {
        self.dirtied_holds.insert(hold);
        continue;
      }
      self.emit_rescan(scope, self.location_of(parent).child(name.clone()));
      let _ = self.start_rearm(parent);
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

  /// Ingests one normalized event.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn on_os_record(&mut self, rec: OsRecord, now: Instant) {
    self.ingest_record(rec, now);
    self.settle_bridges();
  }

  /// [`on_os_record`](Self::on_os_record) minus the public entry point's
  /// bridge flush, which must run after ALL of a record's cascading —
  /// including the fenced early returns.
  fn ingest_record(&mut self, rec: OsRecord, now: Instant) {
    let Some(scope) = self.scope_of(rec.watch()) else {
      return;
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
        self.dirtied_holds.insert(source);
        self.mark_enumerate_dirty(rec.watch());
      } else {
        self.rescan_and_rearm(scope, rec.watch());
      }
      return;
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
        self.dirtied_holds.insert(source);
        self.mark_enumerate_dirty(rec.watch());
        return;
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
      let carried = if rec.kind().is_moved_from() && rec.cookie().is_some() {
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

    match rec.kind() {
      RecordKind::Created => self.on_created(scope, &rec),
      RecordKind::Removed => self.on_removed(scope, &rec),
      // Content and metadata records both surface as `Modified` changes, so the exact
      // per-kind gate lives here where the record kind is still known; the `ondir`
      // target-class modifier applies too. Neither kind affects coverage — suppressing
      // delivery suppresses everything.
      RecordKind::Modified => {
        if self.scope_interest(scope).modified() && self.ondir_allows(scope, rec.is_dir()) {
          self.emit_child(scope, &rec, ChangeKind::Modified);
        }
      }
      RecordKind::Attrib => {
        if self.scope_interest(scope).attrib() && self.ondir_allows(scope, rec.is_dir()) {
          self.emit_child(scope, &rec, ChangeKind::Modified);
        }
      }
      RecordKind::MovedFrom => self.on_moved_from(scope, &rec, now),
      RecordKind::MovedTo => self.on_moved_to(scope, &rec, now),
      RecordKind::MoveSelf => self.on_move_self(scope, &rec),
      RecordKind::DeleteSelf => self.on_delete_self(scope, &rec),
      RecordKind::Ignored => self.on_ignored(&rec),
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
    let (kind, attempts, dirty, scope) = match self.nodes.get(&dir) {
      Some(WatchNode {
        state:
          NodeState::Enumerating {
            req: r,
            kind,
            attempts,
            dirty,
          },
        scope,
        ..
      }) if *r == req => (*kind, *attempts, *dirty, *scope),
      _ => return,
    };
    // The read resolved: the node leaves `Enumerating`.
    self.set_state(dir, NodeState::Live);

    // A held (limbo) directory's read must not DELIVER at the stale pre-move path (the
    // third fence entry point, beside records and subtree overflow), but it must still
    // reconcile COVERAGE so the subtree is complete when it reparents. Dirty the hold,
    // then treat the read as coverage-only: no `Created` (a cold read is routed as a
    // re-arm) and no stale `Rescan` (an incomplete read reconciles + retries silently).
    // The pairing reparent emits the real destination `Rescan`.
    let held = self.in_held_subtree(dir);
    if let Some(source) = held {
      self.dirtied_holds.insert(source);
    }

    if res.forces_rescan() || dirty {
      // An incomplete read (`Partial` / `Failed`), OR a complete read a slot-changing
      // record raced (`dirty`) so its listing is a possibly-stale snapshot: reconcile what
      // is visible, cascade the re-arm into every child, bounded-retry to complete the
      // watch set, and — unless the dir is held — emit a `Rescan` for the unreadable
      // content (a held dir's `Rescan` would point at the stale path).
      self.handle_incomplete_enumerate(dir, scope, &res, attempts, held.is_none());
      return;
    }

    // A CLEAN completion fully reconciled this interior: a standing
    // exhausted-read deficit for it is healed (the P2 clear edge; bridge bits
    // iff the healing read was re-arm-flavored — see `clear_interior_deficit`).
    self.clear_interior_deficit(scope, dir, kind == EnumKind::Rearm);

    match kind {
      // A cold read on a held dir is coverage-only; route it as a re-arm (no `Created`).
      EnumKind::Rearm | EnumKind::Cold if held.is_some() => self.rearm_enumerate(dir, scope, &res),
      // A complete re-arm: prune vanished, arm new, cascade — without emitting `Created`.
      EnumKind::Rearm => self.rearm_enumerate(dir, scope, &res),
      // A complete cold enumerate: discovery — emit `Created` and install per-directory.
      EnumKind::Cold => {
        for entry in res.entries() {
          // Delivery honors the `ondir` modifier (the kind gate is in `emit`); the
          // coverage install below runs regardless.
          if self.ondir_allows(scope, Some(entry.is_dir())) {
            let location = self.child_location(dir, entry.name());
            self.emit(scope, location, ChangeKind::Created);
          }
          // Only a known directory is descended into (an `Unknown`-kind entry is a
          // non-directory, never watched). A cold enumerate is discovery, not a replace,
          // so an already-watched slot is reused (`replaced = false`).
          let occupant = if entry.is_dir() {
            SlotOccupant::Dir
          } else {
            SlotOccupant::File
          };
          self.reconcile_slot(dir, scope, entry.name(), occupant, false, entry.node());
        }
      }
    }
  }

  /// Handles an incomplete enumerate (`Partial` or `Failed`) of `dir`, in either the
  /// discovery or re-arm mode. It never prunes (the listing is incomplete): it arms any
  /// newly-visible directory, cascades the re-arm into EVERY currently-known child
  /// directory (a partial listing may omit a still-present one whose subtree gained a
  /// gap-created descendant), emits a `Rescan` so the consumer refreshes the content
  /// the read could not report, and retries a bounded number of times before letting
  /// the `Rescan` stand — so a permanently-unreadable directory cannot spin the driver.
  fn handle_incomplete_enumerate(
    &mut self,
    dir: WatchId,
    scope: ScopeId,
    res: &EnumerateResult,
    attempts: u8,
    deliver: bool,
  ) {
    // Reconcile every VISIBLE entry (a `Failed` read surfaces none): install or keep a
    // directory, and — for a name the listing now positively reports as a non-directory
    // — drop the stale watch so it can't keep attributing events or block a later real
    // directory there. Never prune OMITTED names (the listing is incomplete). No
    // `Created` — the `Rescan` below refreshes consumer content. A freshly-installed
    // child is picked up by the cascade that follows (it is now in the adjacency set).
    for entry in res.entries() {
      let occupant = if entry.is_dir() {
        SlotOccupant::Dir
      } else {
        SlotOccupant::File
      };
      self.reconcile_slot(dir, scope, entry.name(), occupant, false, entry.node());
    }
    // Cascade the re-arm into EVERY child of `dir` — those in a name-slot AND any
    // detached-and-held move source (mid-move, out of `child_index` but still in the
    // adjacency set at its pre-move parent). A Partial listing may omit a still-present
    // child, and a persistently-Failed read never re-reads at all, so a gap-created
    // descendant under any child would otherwise stay unwatched. `inherit_rearm` /
    // `start_rearm` coalesce, so this cannot stack duplicate work across the bounded
    // retries.
    let children: std::vec::Vec<WatchId> = self
      .nodes
      .get(&dir)
      .map(|node| node.children.iter().copied().collect())
      .unwrap_or_default();
    for child in children {
      let _ = self.inherit_rearm(child);
    }
    // A held dir's `Rescan` would point at its stale pre-move path, so it is suppressed
    // (the pairing reparent re-scans the real destination); coverage above still retries.
    if deliver {
      self.emit_rescan(scope, self.location_of(dir));
    }
    if attempts < REARM_MAX_RETRIES {
      // Retry as a re-arm read (`Created`-suppressed); the count carries on the node so a
      // permanently-unreadable directory escalates to the standing `Rescan` after a
      // bounded number of tries rather than spinning the driver.
      self.queue_enumerate(dir, EnumKind::Rearm, attempts + 1);
    } else if deliver {
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
  fn queue_enumerate(&mut self, dir: WatchId, kind: EnumKind, attempts: u8) {
    let req = self.next_req_id();
    self.pending_enumerate.insert(req, dir);
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
        self.queue_enumerate(dir, EnumKind::Rearm, 0);
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
            self.latent_cold.insert(req, scope);
            RearmKickoff::Coalesced
          }
          EnumKind::Rearm => RearmKickoff::Started,
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
      // a counted obligation (`Arming { rearm: true }`).
      Some(NodeState::Arming { .. }) => {
        self.set_state(watch, NodeState::Arming { rearm: true });
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
  fn rearm_enumerate(&mut self, dir: WatchId, scope: ScopeId, res: &EnumerateResult) {
    // Index the fresh listing's directories by name → identity.
    let present: BTreeMap<Segment, Option<Identity>> = res
      .entries()
      .iter()
      .filter(|entry| entry.is_dir())
      .map(|entry| (entry.name().clone(), entry.node()))
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
    for child in existing {
      // A detached-and-held move source is not in its name-slot; leave it to be
      // reparented by its pending MovedTo rather than rebuilt.
      if !self.is_slot_child(dir, child) {
        continue;
      }
      let name = self.nodes.get(&child).and_then(|node| node.name.clone());
      let survives = name
        .as_ref()
        .and_then(|name| present.get(name).copied())
        .is_some_and(|fresh| self.identity_matches(child, fresh));
      if survives {
        let _ = self.inherit_rearm(child);
      } else {
        self.drop_subtree_for_crawl_rebuild(child);
      }
    }
    // Install a fresh watch for every present directory now lacking one (a survivor keeps
    // its own; this covers vanished-then-new, replaced, and genuinely new names), marked
    // to continue the re-arm so its subtree rebuilds recursively.
    for entry in res.entries() {
      if !entry.is_dir() {
        continue;
      }
      if self.child_watch(dir, entry.name()).is_none() {
        self.install_child(dir, scope, entry.name().clone(), true, entry.node());
        if let Some(fresh) = self.child_watch(dir, entry.name()) {
          let _ = self.inherit_rearm(fresh);
        }
      }
    }
  }

  /// Handles the result of an [`Action::Watch`].
  ///
  /// On success the node becomes live and — when the core descends and the node
  /// is a directory — an [`Action::Enumerate`] is queued. The ordering "watch
  /// armed strictly before readdir" is a state-machine invariant, so the
  /// enumerate is only ever queued *after* this success.
  ///
  /// Every non-success result is treated as coverage loss: the node and its
  /// subtree are dropped and a [`ChangeKind::Rescan`] is emitted for the affected
  /// location, so a caller never believes a subtree is watched when the kernel
  /// refused the watch. This covers all [`WatchError`] variants uniformly — a
  /// watch-limit refusal, a permission denial, a vanished target, or any other
  /// I/O failure — none may leave a node registered-but-not-live and silent.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn on_watch_result(&mut self, id: WatchId, res: Result<(), WatchError>) {
    self.ingest_watch_result(id, res);
    self.settle_bridges();
  }

  /// [`on_watch_result`](Self::on_watch_result) minus the public entry
  /// point's bridge flush — a failed arm's drop can be the settle edge.
  fn ingest_watch_result(&mut self, id: WatchId, res: Result<(), WatchError>) {
    let Some(node) = self.nodes.get_mut(&id) else {
      return;
    };
    let scope = node.scope;
    let is_dir = node.is_dir;

    match res {
      Ok(()) => {
        // Only a pending (Arming) watch transitions to live. A duplicate or late `Ok` on
        // an already-armed node is ignored, not replayed: resetting it to `Live` would
        // clobber an outstanding `Enumerating` read and orphan its request.
        let NodeState::Arming { rearm } = node.state else {
          return;
        };
        self.set_state(id, NodeState::Live);
        if is_dir && self.scope_descends(scope) {
          // Continue a rescan re-arm into this freshly-armed directory if it was installed
          // as part of one — OR if it arms while in a held subtree: a held-origin read must
          // stay coverage-only (Created-suppressed) even if the move pairs and clears the
          // hold before the result returns, so tag it as a re-arm now (the intent persists
          // on `Enumerating.kind`). A cold discovery would else emit false `Created` for
          // pre-existing destination children after the move.
          if rearm || self.in_held_subtree(id).is_some() {
            let _ = self.start_rearm(id);
          } else {
            self.queue_enumerate(id, EnumKind::Cold, 0);
          }
        }
      }
      // A failed install must not leave a silent blind spot: reconstruct the location
      // while the node still exists, emit a `Rescan`, then drop it. But a node that is
      // held (a pending source or descendant detached mid-move) has a STALE pre-move
      // location — fence it like every other held-subtree activity: dirty the enclosing
      // hold (so the pairing reparent re-scans the destination) instead of Rescanning the
      // old path, then drop the failed node.
      Err(_) => {
        if let Some(source) = self.in_held_subtree(id) {
          self.dirtied_holds.insert(source);
          self.drop_subtree(id);
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
          self.drop_subtree(id);
        }
      }
    }
  }

  /// Turns a notification-queue overflow into a [`ChangeKind::Rescan`] covering
  /// exactly the affected scope AND reconciles the proto's own watch set for it, so
  /// nothing is silently lost and no post-overflow subtree is left unwatched.
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
          self.rescan_and_rearm(scope_id, root);
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
          self.rescan_and_rearm(scope_id, root);
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
          self.dirtied_holds.insert(source);
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
    self.dirtied_holds.extend(held);
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
  fn dirty_pending_sources_touching(
    &mut self,
    scope: ScopeId,
    loc: &Location,
    exclude: Option<MoveCookie>,
    carried: Option<WatchId>,
  ) {
    let keys: std::vec::Vec<PendingKey> = self
      .pending_moves
      .iter()
      .filter(|((half_scope, cookie), pending)| {
        *half_scope == scope
          && Some(*cookie) != exclude
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
    if self.is_watched(pending.from_parent) {
      let from = self.pending_from(pending);
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
  fn reanchor_pending_sources(&mut self, scope: ScopeId, from: &Location, to: &Location) {
    let matched: std::vec::Vec<(PendingKey, Option<Location>)> = self
      .pending_moves
      .iter()
      .filter(|((half_scope, _), pending)| {
        *half_scope == scope && self.is_watched(pending.from_parent)
      })
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

  /// Advances time, resolving move halves whose pairing window has elapsed: an
  /// unpaired source becomes a [`ChangeKind::Removed`] (a watched-directory
  /// source's subtree was already dropped when it moved away, in `on_moved_from`).
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn handle_timeout(&mut self, now: Instant) {
    let expired: std::vec::Vec<PendingKey> = self
      .pending_moves
      .iter()
      .filter(|(_, pending)| now.reached(pending.deadline))
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
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn poll_action(&mut self) -> Option<Action> {
    self.actions.pop_front()
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
      let location = self.record_location(rec);
      self.emit(scope, location, ChangeKind::Created);
    }
    if let Some(name) = rec.name() {
      // A create is discovery, not a replace: an occupied slot is a duplicate
      // (an enumerate racing the live `Created`), so reuse it (`replaced = false`).
      self.reconcile_slot(
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
      let location = self.record_location(rec);
      self.emit(scope, location, ChangeKind::Removed);
    }
    if let Some(name) = rec.name() {
      // The slot's object is gone: drop any watch that covered it, so a later
      // create at the same name is not mistaken for a duplicate of the old object.
      self.reconcile_slot(
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
    match (rec.cookie(), rec.target()) {
      (Some(cookie), Some(target)) => {
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
          dirty: false,
        };
        // Invariant (d): the cookie is namespaced by scope, so only a *same-scope*
        // reused/colliding cookie collides on this composite key. The displaced
        // half can no longer be paired, so it resolves on its own rather than
        // being silently overwritten.
        if let Some(displaced) = self.pending_moves.insert((scope, cookie), pending) {
          self.resolve_stored_half(displaced);
        }
      }
      // A no-cookie (or degenerate nameless) source can never pair: tear its subtree
      // down now and emit the `Removed`. `from_parent` is `rec.watch()`, live by
      // construction (`scope_of` succeeded), so no liveness guard is needed.
      _ => {
        let is_dir = if src.is_some() {
          Some(true)
        } else {
          rec.is_dir()
        };
        if let Some(src) = src {
          self.drop_subtree(src);
        }
        let from = self.record_location(rec);
        self.resolve_lost_source(scope, from, is_dir);
      }
    }
  }

  fn on_moved_to(&mut self, scope: ScopeId, rec: &OsRecord, now: Instant) {
    let to = self.record_location(rec);
    match rec
      .cookie()
      .and_then(|cookie| self.pending_moves.remove(&(scope, cookie)))
    {
      // Invariants (a)+(d): the composite key restricts the lookup to a same-scope
      // half, so a cross-scope cookie collision never matches here (it resolves as
      // a fresh `Created` via the `None` arm). A matched half pairs only before its
      // window elapses; past it the source already stranded (a late destination).
      Some(pending) if !now.reached(pending.deadline) => {
        // ONE class per resolution, consumed by BOTH delivery and reconciliation:
        // the arriving record is the NEWEST observation of the object, so its positive
        // flag wins; the pending half's class only fills an OMITTED flag. The reverse
        // precedence would let a stale half (a lingering file source whose parent was
        // narrowly torn down, paired by a reused cookie) demote a real directory
        // destination to an unwatched file slot — silent coverage loss.
        let class = rec.is_dir().or(pending.is_dir);
        // The source path this pairing relocates, captured while the half is intact:
        // other halves parked under it must re-anchor once the `Moved` is emitted.
        // `from_parent` is the source's (old) parent — never inside the moved subtree —
        // so this reconstruction is stable across the reparent below. An unanchored
        // half emits `Created`, not `Moved` (see `emit_pair`): nothing relocates, so
        // there is nothing to re-anchor under.
        let resolved_from = self
          .is_watched(pending.from_parent)
          .then(|| self.pending_from(&pending));
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
            if self.can_reparent(src, rec.watch()) && self.reparent(src, rec.watch(), name.clone())
            {
              self.emit_pair(scope, to.clone(), &pending, class);
              if let Some(from) = resolved_from.as_ref() {
                self.reanchor_pending_sources(scope, from, &to);
              }
              // A source-slot touch during the hold (a delivered replacement at the
              // vacated path) covers through the half's own flag — source AND
              // destination — independent of the under-hold suppression below.
              self.rescan_dirty_pair(scope, &pending, &to);
              if dirtied {
                // Records under the moved subtree were suppressed at the stale path:
                // re-scan the destination and re-arm the subtree to recover them.
                self.emit_rescan(scope, to);
                let _ = self.inherit_rearm(src);
              }
            } else {
              // Not reparentable: a dead or cyclic held source, or a reparent that
              // aborted because the held source sat inside the (now torn-down)
              // destination. Tear down any surviving held subtree; reconcile the
              // destination as a fresh move-in if its parent survived, else escalate
              // with a `Rescan` — never a `Moved` into a path we no longer cover.
              if self.is_watched(src) {
                self.drop_subtree(src);
              }
              if self.is_watched(rec.watch()) {
                self.emit_pair(scope, to.clone(), &pending, class);
                if let Some(from) = resolved_from.as_ref() {
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
                self.reconcile_slot(
                  rec.watch(),
                  scope,
                  name,
                  Self::class_occupant(class),
                  true,
                  rec.node(),
                );
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
                self.emit_rescan(scope, Location::new());
              }
            }
          }
          // Non-directory (or unwatched) source: emit the pairing and reconcile the slot.
          (Some(name), None) => {
            self.emit_pair(scope, to.clone(), &pending, class);
            if let Some(from) = resolved_from.as_ref() {
              self.reanchor_pending_sources(scope, from, &to);
            }
            self.rescan_dirty_pair(scope, &pending, &to);
            self.reconcile_slot(
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
              self.drop_subtree(src);
            }
            self.emit_pair(scope, to.clone(), &pending, class);
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
        self.resolve_stored_half(pending);
        if self.is_watched(rec.watch()) {
          // Delivery honors `ondir`; the slot reconciliation below is coverage and
          // runs regardless.
          if self.ondir_allows(scope, class) {
            self.emit(scope, to, ChangeKind::Created);
          }
          if let Some(name) = rec.name() {
            self.reconcile_slot(
              rec.watch(),
              scope,
              name,
              Self::class_occupant(class),
              true,
              rec.node(),
            );
          }
        } else {
          // Resolving the stranded source dropped the destination parent (a cyclic late
          // destination sits inside the held subtree), so the precomputed `to` is a
          // stale pre-move path — escalate at the scope root instead, marking both
          // parked stores as for any scope-wide transition (see the in-window twin).
          self.dirty_pending_sources_touching(scope, &Location::new(), None, None);
          self.dirty_held_sources(Some(scope));
          self.emit_rescan(scope, Location::new());
        }
      }
      None => {
        if self.ondir_allows(scope, rec.is_dir()) {
          self.emit(scope, to, ChangeKind::Created);
        }
        if let Some(name) = rec.name() {
          self.reconcile_slot(
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
      self.drop_subtree(src);
    }
    if self.is_watched(pending.from_parent) {
      let from = self.pending_from(&pending);
      self.resolve_lost_source(pending.scope, from.clone(), pending.is_dir);
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
  ) {
    if !self.ondir_allows(scope, class) {
      return;
    }
    if self.is_watched(pending.from_parent) {
      let from = self.pending_from(pending);
      self.emit(scope, to, ChangeKind::Moved(from));
    } else {
      self.emit(scope, to, ChangeKind::Created);
    }
  }

  /// Detaches a child watch from its `(parent, name)` slot without tearing down its
  /// subtree. The node stays in `nodes` (still attributing records, at its pre-move
  /// path) so a paired [`MovedTo`](Self::on_moved_to) can [`reparent`](Self::reparent)
  /// it; freeing the slot lets a replacement at the old path install its own watch.
  fn detach_child(&mut self, child: WatchId) {
    if let Some(node) = self.nodes.get(&child)
      && let (Some(parent), Some(name)) = (node.parent, node.name.clone())
    {
      self.child_index.remove(&(parent, name));
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
  /// [`can_reparent`]: Self::can_reparent
  fn reparent(&mut self, child: WatchId, new_parent: WatchId, new_name: Segment) -> bool {
    let mut inherit_rearm = false;
    if let Some(stale) = self.child_watch(new_parent, &new_name)
      && stale != child
    {
      // The replaced destination may carry a re-arm obligation (a pending arm that will
      // re-arm, or an outstanding re-arm read). Either way it must pass to the reparented
      // subtree, not vanish with the drop.
      inherit_rearm = self.has_rearm_obligation(stale);
      self.drop_subtree(stale);
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
    if inherit_rearm {
      let _ = self.inherit_rearm(child);
    }
    true
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
  fn resolve_lost_source(&mut self, scope: ScopeId, from: Location, is_dir: Option<bool>) {
    if !self.ondir_allows(scope, is_dir) {
      return;
    }
    self.emit(scope, from, ChangeKind::Removed);
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
  /// A `File`/`Gone` occupant always drops any stale watch. Only [`SlotOccupant::Dir`]
  /// is watched: a descending backend must report directory-ness for a directory
  /// appearance (inotify does, via `IN_ISDIR`), so an unknown kind maps to `File`
  /// and is not watched (Rescanning every unknown would fire on every file). A
  /// no-op when the core does not descend (kernel-recursive: no per-directory
  /// watches to manage).
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
  ) {
    if !self.scope_descends(scope) {
      return;
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
          self.drop_subtree(stale);
        }
        self.install_child(parent, scope, name.clone(), true, identity);
        if inherit && let Some(fresh) = self.child_watch(parent, name) {
          let _ = self.inherit_rearm(fresh);
        }
      }
      SlotOccupant::File | SlotOccupant::Gone => {
        if let Some(stale) = self.child_watch(parent, name) {
          self.drop_subtree(stale);
        }
        // The slot's object is gone (or a never-watched file): a recorded
        // arm-refused hole there is moot. No bridge bits — a record-driven
        // emptying was DELIVERED (the consumer converges on the removal), and
        // an enumerate-driven one happens inside a window whose own `Rescan`s
        // carry the bits.
        let _ = self.remove_slot_deficit(scope, parent, name);
      }
    }
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
  /// [`reconcile_slot`]: Self::reconcile_slot
  fn record_occupant(rec: &OsRecord) -> SlotOccupant {
    Self::class_occupant(rec.is_dir())
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
    }
    // A NON-root MoveSelf is deliberately a no-op. In-queue kernel order (the same
    // contract the cookie window depends on — see `RecordKind::MoveSelf`) means the
    // parent-side records have already run: the node is either detached-and-held (its
    // stale path is fenced; dropping it here would break the pending reparent) or
    // already reparented (its path is CURRENT; dropping it would destroy the coverage
    // the O(1) carry-over just preserved). A parent-side record lost to an overflow is
    // healed by the overflow Rescan + re-arm, which prunes the vacated slot.
  }

  /// Invalidates a scope's root after an OS-driven teardown (a moved, deleted, ignored,
  /// or install-refused root): drops the whole tree AND purges the scope's pending move
  /// halves. The composite pending key carries no root generation, so a half from the
  /// dead generation would otherwise stay pairable — a same-cookie destination in a
  /// re-registered generation of the `ScopeId` could consume it, and its stale class
  /// could reconcile a real directory as a file, silently losing coverage. The caller
  /// emits the unfiltered `Rescan` first (invariant: root invalidation never silent).
  fn invalidate_root(&mut self, scope: ScopeId, root: WatchId) {
    self.drop_subtree(root);
    self.purge_scope_pending_moves(scope);
    // As for `unregister_root`: the caller's unconditional `Rescan` plus the
    // teardown own coverage now — no bridge window or deficit book survives.
    self.bridge.remove(&scope);
    self.deficits.remove(&scope);
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
        self.emit(scope, location, ChangeKind::Removed);
      }
      self.emit_rescan(scope, Location::new());
      self.invalidate_root(scope, rec.watch());
      return;
    }
    // The watched object itself is gone: tear the watch down NOW rather than waiting
    // for the trailing `Ignored`. A stale entry in the window between the two would
    // make a replacement `Created` at the same slot reuse it (discovery-reuse), and
    // the eventual `Ignored` teardown would then leave the replacement unwatched.
    self.drop_subtree(rec.watch());
  }

  fn on_ignored(&mut self, rec: &OsRecord) {
    // A root's kernel-side teardown with no preceding record (an unmount, an external
    // watch removal) ends the scope's coverage with NO parent watch left to report it:
    // signal with the unconditional `Rescan` before invalidating, as for a deleted or
    // moved root. A non-root's removal is its live parent watch's job to report.
    if self.is_root_watch(rec.watch())
      && let Some(scope) = self.scope_of(rec.watch())
    {
      self.emit_rescan(scope, Location::new());
      self.invalidate_root(scope, rec.watch());
      return;
    }
    self.drop_subtree(rec.watch());
  }

  fn emit_child(&mut self, scope: ScopeId, rec: &OsRecord, kind: ChangeKind) {
    let location = self.record_location(rec);
    self.emit(scope, location, kind);
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
    self.emit(scope, location, ChangeKind::Rescan);
  }

  fn emit(&mut self, scope: ScopeId, location: Location, kind: ChangeKind) {
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
    if !wanted {
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
    let pending_blocks = self.pending_moves.iter().any(|((half_scope, _), pending)| {
      *half_scope == scope && self.is_watched(pending.from_parent) && {
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
    // install as a transition into it (see `set_state`).
    if matches!(node.state, NodeState::Arming { rearm: true }) {
      self.bridge_fresh_rearm(node.scope);
    }
    self.nodes.insert(id, node);
  }

  fn install_child(
    &mut self,
    parent: WatchId,
    scope: ScopeId,
    name: Segment,
    is_dir: bool,
    identity: Option<Identity>,
  ) {
    // Descent is idempotent: a cold enumerate racing a live `Created` (or
    // duplicate create records) must not mint a second watch for one path, or
    // every record under it would be delivered twice. Reuse any pending-or-live
    // child watch already covering `(parent, name)`.
    if self.child_index.contains_key(&(parent, name.clone())) {
      return;
    }
    // The slot-heal clear edge (the P2↔P1 interlock): occupying a recorded
    // arm-refused hole heals it, and the hole's dark interval is covered only
    // by the window's closing `Rescan` — so the heal sets BOTH bridge bits
    // itself, order-robustly (an organic pure grow reaching the hole has no
    // `Rescan` of its own). This is the ONE funnel every slot occupation
    // passes through: `reconcile_slot`'s `Dir` arm, `rearm_enumerate`'s
    // direct installs, and the incomplete-read reconciles all route here. (A
    // record-driven cold re-install lands here too and sets the bits; its
    // `Removed`+`Created` records already converged the consumer, so the
    // resulting closing `Rescan` is redundant-but-legal, and rare.)
    if self.remove_slot_deficit(scope, parent, &name) {
      self.bridge_saw_rescan(scope);
      self.bridge_fresh_rearm(scope);
    }
    let id = WatchId::new(self.watch_ids.mint());
    self.insert_node(
      id,
      WatchNode {
        parent: Some(parent),
        name: Some(name.clone()),
        scope,
        is_dir,
        identity,
        state: NodeState::Arming { rearm: false },
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
    self.actions.push_back(Action::watch(
      id,
      crate::action::WatchTarget::child(parent, name),
      mask,
    ));
  }

  /// Drops the watch subtree rooted at `root`, queuing an
  /// [`Action::Unwatch`] per removed node. Returns whether the walk erased
  /// any recorded deficit entry — consumed only by
  /// [`drop_subtree_for_crawl_rebuild`](Self::drop_subtree_for_crawl_rebuild);
  /// every other caller's coverage story already accounts for the dropped
  /// anchors (see [`drop_node_deficits`](Self::drop_node_deficits)).
  fn drop_subtree(&mut self, root: WatchId) -> bool {
    let mut erased = false;
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
        if let (Some(parent), Some(name)) = (node.parent, node.name)
          && self.child_index.get(&(parent, name.clone())) == Some(&id)
        {
          self.child_index.remove(&(parent, name));
        }
      }
      // Clear an outstanding enumerate request: a dropped directory's read may never be
      // reported by the driver, so `on_enumerate` would never remove it — leaving the
      // reverse map to grow without bound under repeated drop-while-enumerating.
      if let NodeState::Enumerating { req, .. } = node.state {
        self.pending_enumerate.remove(&req);
        self.latent_cold.remove(&req);
      }
      // A dropped watch is no longer a held move source.
      if self.held_sources.remove(&id) {
        self.held_by_scope_dec(node.scope);
      }
      self.dirtied_holds.remove(&id);
      // Its deficit anchors die with it; report a real erasure so the one
      // caller with no coverage story of its own can carry the loss (see
      // `drop_node_deficits` / `drop_subtree_for_crawl_rebuild`).
      erased |= self.drop_node_deficits(node.scope, id);
      self.actions.push_back(Action::Unwatch(id));
    }
    // NOTE: a narrow subtree drop deliberately does NOT purge pending move halves.
    // A half whose source parent was dropped may still pair: its `MovedTo` can
    // arrive at a still-watched destination in the same scope. Keeping it pairable
    // preserves the move; the `handle_timeout` liveness guard (`is_watched(
    // from_parent)`) suppresses the stale `Removed` if no destination ever comes.
    // Whole-scope teardown purges instead — see `unregister_root` /
    // `purge_scope_pending_moves`.
    erased
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
  /// the dispatch re-signal until the in-flight `Removed` converges it. A
  /// drop that erased nothing carries nothing, so a clean rebuild of
  /// deficit-free coverage stays silent and pure prune/regrow flows are
  /// unaffected. Every other `drop_subtree` context (record-delivered
  /// churn, held-subtree resolution, umbrella prune, teardown, root
  /// invalidation) keeps the bare call: those erasures are converged,
  /// covered at the hold's resolution, out of contract, or terminal.
  fn drop_subtree_for_crawl_rebuild(&mut self, child: WatchId) {
    let anchor = self.nodes.get(&child).and_then(|node| {
      node
        .parent
        .zip(node.name.clone())
        .map(|(parent, name)| (node.scope, parent, name))
    });
    if self.drop_subtree(child)
      && let Some((scope, parent, name)) = anchor
    {
      self.record_slot_deficit(scope, parent, name);
    }
  }

  /// Drops every pending move half belonging to `scope`. Called only on whole-scope
  /// teardown ([`unregister_root`](Self::unregister_root)), where no destination in
  /// the scope can ever validly arrive, so no half can pair (invariant b).
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
    let entered_fresh = matches!(state, NodeState::Arming { rearm: true })
      && !matches!(node.state, NodeState::Arming { rearm: true });
    let scope = node.scope;
    node.state = state;
    // A node ENTERING `Arming { rearm: true }` is a `Created`-suppressed
    // fresh install (or a cold→re-arm conversion whose discovery is now
    // suppressed): the bridge window armed coverage whose content only a
    // closing `Rescan` can instruct the consumer to re-read.
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

  /// Counts one node of `scope` entering a re-arm-flavored state.
  fn rearm_pending_inc(&mut self, scope: ScopeId) {
    *self.rearm_pending.entry(scope).or_insert(0) += 1;
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

  /// Counts one detached-and-held move source of `scope` — called iff the
  /// `held_sources` insert actually inserted, so the count mirrors membership.
  fn held_by_scope_inc(&mut self, scope: ScopeId) {
    *self.held_by_scope.entry(scope).or_insert(0) += 1;
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

  /// Marks `scope`'s bridge window as having armed suppressed coverage — a
  /// node entered `Arming { rearm: true }`. Fed by the two state funnels
  /// ([`set_state`](Self::set_state) / [`insert_node`](Self::insert_node));
  /// the descending gate is a belt (the state is unreachable elsewhere).
  fn bridge_fresh_rearm(&mut self, scope: ScopeId) {
    if self.scope_descends(scope) {
      self.bridge.entry(scope).or_default().fresh_rearm = true;
    }
  }

  /// Records a slot hole `(parent, name)` in `scope`'s deficit book (see
  /// [`DeficitBook::slots`]): an arm-refused install, or an organically
  /// erased deficit re-anchored by
  /// [`drop_subtree_for_crawl_rebuild`](Self::drop_subtree_for_crawl_rebuild).
  /// The hole's edge `Rescan` already stands (emitted at the arm failure,
  /// or when the re-anchored deficit was originally recorded); this carries
  /// the level-persistent fact past it.
  fn record_slot_deficit(&mut self, scope: ScopeId, parent: WatchId, name: Segment) {
    if !self.scope_descends(scope) {
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
  fn record_interior_deficit(&mut self, scope: ScopeId, dir: WatchId) {
    if !self.scope_descends(scope) {
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

  /// Removes a recorded slot hole, reporting whether one was recorded. No
  /// bridge bits: the record-driven clears (a delivered `Removed`/`File`
  /// occupant) converged the consumer on their own.
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
    removed
  }

  /// The interior-heal clear edge: a CLEAN completion for `dir` reconciled
  /// the interior a standing deficit said was dark. When the healing read was
  /// re-arm-flavored its content was `Created`-suppressed, so the heal sets
  /// BOTH bridge bits — the P2↔P1 interlock that guarantees the window closes
  /// with a covering `Rescan` even when it was otherwise clean (an organic
  /// pure grow reaching the hole). A clean COLD completion announced its
  /// content and sets nothing.
  fn clear_interior_deficit(&mut self, scope: ScopeId, dir: WatchId, rearm: bool) {
    let Some(book) = self.deficits.get_mut(&scope) else {
      return;
    };
    let removed = book.interiors.remove(&dir);
    self.gc_deficit_book(scope);
    if removed && rearm {
      self.bridge_saw_rescan(scope);
      self.bridge_fresh_rearm(scope);
    }
  }

  /// Drops the fine entries anchored at a dying node — `drop_subtree`'s
  /// hook — reporting whether any were actually recorded. No bridge bits
  /// here: a record-delivered drop converged, a held-subtree drop is covered
  /// at the hold's resolution, an umbrella prune is unsubscribed by
  /// contract, and a teardown ends in a terminal `Rescan`. A crawl rebuild
  /// has no such story — its re-installs re-set the bits only for a deficit
  /// anchored at a SURVIVING parent, never for one whose anchor dies with
  /// the subtree — so
  /// [`drop_subtree_for_crawl_rebuild`](Self::drop_subtree_for_crawl_rebuild)
  /// re-anchors a reported erasure at the surviving parent instead.
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

  /// Whether `dir` has a rescan re-arm read outstanding — the successor to the old
  /// `rearm_dirs` membership, for white-box tests.
  #[cfg(test)]
  fn is_rearm_enumerating(&self, dir: WatchId) -> bool {
    matches!(
      self.nodes.get(&dir).map(|node| node.state),
      Some(NodeState::Enumerating {
        kind: EnumKind::Rearm,
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
        flags.saw_rescan || flags.fresh_rearm,
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
