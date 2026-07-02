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
  Enumerating {
    req: ReqId,
    kind: EnumKind,
    attempts: u8,
  },
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
/// space and time. The source is anchored by its slot `(from_parent, from_name)`
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
  from_name: Segment,
  scope: ScopeId,
  deadline: Instant,
  held: Option<WatchId>,
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
/// [`poll_timeout`](Self::poll_timeout). No method performs I/O or reads a clock;
/// time always arrives as a `now` argument.
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

  actions: VecDeque<Action>,
  events: VecDeque<Change>,
  pending_keys: BTreeSet<DedupKey>,
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
      pending_enumerate: BTreeMap::new(),
      pending_moves: BTreeMap::new(),
      actions: VecDeque::new(),
      events: VecDeque::new(),
      pending_keys: BTreeSet::new(),
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

  /// Whether the core descends per-directory (the backend is not
  /// kernel-recursive).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn descends(&self) -> bool {
    !self.capabilities.kernel_recursive()
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
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn register_root(&mut self, scope: ScopeId, mask: Interest) -> WatchId {
    let id = WatchId::new(self.watch_ids.mint());
    self.nodes.insert(
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
    self.actions.push_back(Action::watch(
      id,
      crate::action::WatchTarget::Root(scope),
      mask,
    ));
    id
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
    }
  }

  /// Ingests one normalized event.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn on_os_record(&mut self, rec: OsRecord, now: Instant) {
    let Some(scope) = self.scope_of(rec.watch()) else {
      return;
    };

    match rec.kind() {
      RecordKind::Created => self.on_created(scope, &rec),
      RecordKind::Removed => self.on_removed(scope, &rec),
      RecordKind::Modified => self.emit_child(scope, &rec, ChangeKind::Modified),
      RecordKind::Attrib => self.emit_child(scope, &rec, ChangeKind::Modified),
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
    let Some(dir) = self.pending_enumerate.remove(&req) else {
      return;
    };
    // Accept the result only if `dir` still awaits THIS request. A node that was dropped
    // or whose read was superseded (re-armed, its slot rebuilt) has moved on — a stale
    // result must not reconcile against it. This is the gap the old `pending_enumerate`
    // + liveness pair could not close: the request identity now lives on the node.
    let (kind, attempts, scope) = match self.nodes.get(&dir) {
      Some(WatchNode {
        state:
          NodeState::Enumerating {
            req: r,
            kind,
            attempts,
          },
        scope,
        ..
      }) if *r == req => (*kind, *attempts, *scope),
      _ => return,
    };
    // The read resolved: the node leaves `Enumerating`.
    self.set_state(dir, NodeState::Live);

    if res.forces_rescan() {
      // An incomplete read (`Partial` or `Failed`), in EITHER mode: reconcile what is
      // visible, cascade the re-arm into every child, emit a `Rescan` for the content
      // the read could not report, and bounded-retry to complete the watch set.
      self.handle_incomplete_enumerate(dir, scope, &res, attempts);
      return;
    }

    match kind {
      // A complete re-arm: prune vanished, arm new, cascade — without emitting `Created`.
      EnumKind::Rearm => self.rearm_enumerate(dir, scope, &res),
      // A complete cold enumerate: discovery — emit `Created` and install per-directory.
      EnumKind::Cold => {
        for entry in res.entries() {
          let location = self.child_location(dir, entry.name());
          self.emit(scope, location, ChangeKind::Created);
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
      self.inherit_rearm(child);
    }
    self.emit_rescan(scope, self.location_of(dir));
    if attempts < REARM_MAX_RETRIES {
      // Retry as a re-arm read (`Created`-suppressed); the count carries on the node so a
      // permanently-unreadable directory escalates to the standing `Rescan` after a
      // bounded number of tries rather than spinning the driver.
      self.queue_enumerate(dir, EnumKind::Rearm, attempts + 1);
    }
    // else: retries exhausted — the node stays `Live` and the `Rescan` stands. (S3 turns
    // this into a recovering `Degraded` state re-attempted on the next reconcile trigger.)
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
      },
    );
    self.actions.push_back(Action::enumerate(req, dir));
  }

  /// Begins a rescan re-arm of `dir`, coalesced. Only a live, idle directory
  /// ([`NodeState::Live`]) starts a read: a node already enumerating absorbs the trigger
  /// (one read at a time, so repeated overflows and cascades cannot stack requests), and
  /// a pending or dead one has nothing to read yet — a pending one's post-arm enumerate
  /// carries the obligation instead. A no-op on a non-descending backend.
  fn start_rearm(&mut self, dir: WatchId) {
    if self.descends()
      && matches!(
        self.nodes.get(&dir).map(|node| node.state),
        Some(NodeState::Live)
      )
    {
      self.queue_enumerate(dir, EnumKind::Rearm, 0);
    }
  }

  /// Transfers a re-arm obligation onto `watch` — a watch that has just replaced a
  /// mid-re-arm one, or a surviving child cascaded during an incomplete parent read.
  fn inherit_rearm(&mut self, watch: WatchId) {
    match self.nodes.get(&watch).map(|node| node.state) {
      // Live and idle: begin the re-arm now.
      Some(NodeState::Live) => self.start_rearm(watch),
      // Still arming: its post-arm enumerate must continue the re-arm, so mark it.
      Some(NodeState::Arming { .. }) => self.set_state(watch, NodeState::Arming { rearm: true }),
      // Already enumerating (obligation in flight) or dead — nothing to transfer.
      _ => {}
    }
  }

  /// Rebuilds `dir`'s direct children against a COMPLETE fresh enumerate during a
  /// rescan re-arm — all without emitting `Created` (the consumer re-scans content off
  /// the `Rescan`). This is the second half of the overflow dual obligation: re-walk to
  /// re-arm the proto's own watch set, so a subtree created during the overflow gap is
  /// not left unwatched. Incomplete reads route to
  /// [`handle_incomplete_enumerate`](Self::handle_incomplete_enumerate) instead.
  ///
  /// Overflow can hide a same-name delete+recreate, and the primitive-agnostic Monitor
  /// carries no identity (`dev_ino`) to tell a replacement from the original — so it
  /// conservatively drops EVERY existing child watch (pruning vanished names and
  /// replacing present ones alike) and installs a fresh watch for each present
  /// directory, marked to continue the re-arm so its subtree rebuilds recursively.
  /// Detecting a same-name replacement *without* this rebuild needs the wd-reuse /
  /// inode identity the inotify sub-machine supplies (§6); until then, rebuilding the
  /// affected children on overflow is the safe choice.
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
        self.inherit_rearm(child);
      } else {
        self.drop_subtree(child);
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
          self.inherit_rearm(fresh);
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
    let Some(node) = self.nodes.get_mut(&id) else {
      return;
    };
    let scope = node.scope;
    let is_dir = node.is_dir;

    match res {
      Ok(()) => {
        let rearm = matches!(node.state, NodeState::Arming { rearm: true });
        node.state = NodeState::Live;
        if is_dir && self.descends() {
          // Continue a rescan re-arm into this freshly-armed directory if it was
          // installed as part of one; otherwise a normal discovery enumerate.
          if rearm {
            self.start_rearm(id);
          } else {
            self.queue_enumerate(id, EnumKind::Cold, 0);
          }
        }
      }
      // Reconstruct the location while the node still exists, then drop it: a
      // failed install — for any reason — must not leave a silent blind spot.
      Err(_) => {
        self.emit_rescan(scope, self.location_of(id));
        self.drop_subtree(id);
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
          self.rescan_and_rearm(scope_id, root);
        }
      }
      Scope::Root(scope_id) => {
        // Only a registered scope has a watch set to reconcile; an overflow
        // reported for an unregistered or already-torn-down scope is dropped
        // rather than emitting a Rescan for a scope the Monitor no longer covers
        // (the `Subtree` arm below guards symmetrically via `scope_of`).
        if let Some(&root) = self.roots.get(&scope_id) {
          self.rescan_and_rearm(scope_id, root);
        }
      }
      Scope::Subtree(watch) => {
        if let Some(scope_id) = self.scope_of(watch) {
          self.rescan_and_rearm(scope_id, watch);
        }
      }
    }
  }

  /// Emits an overflow [`ChangeKind::Rescan`] for a scope AND re-enumerates `dir` in
  /// re-arm mode ([`rearm_enumerate`](Self::rearm_enumerate)) so directories created
  /// during the overflow gap are re-armed and vanished ones pruned — both halves of
  /// the dual obligation. A no-op re-arm on a non-descending backend or a dead `dir`.
  fn rescan_and_rearm(&mut self, scope: ScopeId, dir: WatchId) {
    self.emit_rescan(scope, self.location_of(dir));
    self.start_rearm(dir);
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
  }

  /// Dequeues the next [`Action`] for the driver to execute, if any.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn poll_action(&mut self) -> Option<Action> {
    self.actions.pop_front()
  }

  /// Dequeues the next normalized [`Change`] for the consumer, if any.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn poll_event(&mut self) -> Option<Change> {
    let change = self.events.pop_front()?;
    self.pending_keys.remove(&Self::dedup_key(&change));
    Some(change)
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
    // TODO(§6): set the create-descend dirty flag — records hitting the new dir
    // before its enumerate is processed must escalate to a subtree Rescan. The
    // dirty-window tracking lands with the inotify sub-machine.
    let location = self.record_location(rec);
    self.emit(scope, location, ChangeKind::Created);
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
    let location = self.record_location(rec);
    self.emit(scope, location, ChangeKind::Removed);
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
    let src = rec
      .name()
      .and_then(|name| self.child_watch(rec.watch(), name));
    match (rec.cookie(), rec.name()) {
      (Some(cookie), Some(name)) => {
        // Detach a watched-directory source from its old `(parent, name)` slot the
        // moment it moves away, but KEEP its subtree: a paired `MovedTo` reparents it
        // in O(1) (descendants follow for free), and until then detaching has already
        // freed the old path for a replacement to install its own watch. An unpaired
        // half tears the held subtree down when it resolves (`resolve_stored_half`).
        if let Some(src) = src {
          self.detach_child(src);
        }
        let pending = PendingMove {
          from_parent,
          from_name: name.clone(),
          scope,
          deadline: now + self.move_window,
          held: src,
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
        if let Some(src) = src {
          self.drop_subtree(src);
        }
        let from = self.record_location(rec);
        self.resolve_lost_source(scope, from);
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
        match (rec.name(), pending.held) {
          // Held directory: attempt the O(1) reparent and emit the pairing only once
          // it succeeds — a `Moved` must never precede a rejected/aborted reparent.
          (Some(name), Some(src)) => {
            if self.can_reparent(src, rec.watch()) && self.reparent(src, rec.watch(), name.clone())
            {
              self.emit_pair(scope, to, &pending);
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
                self.emit_pair(scope, to, &pending);
                self.reconcile_slot(
                  rec.watch(),
                  scope,
                  name,
                  Self::record_occupant(rec),
                  true,
                  rec.node(),
                );
              } else {
                self.emit_rescan(scope, to);
              }
            }
          }
          // Non-directory (or unwatched) source: emit the pairing and reconcile the slot.
          (Some(name), None) => {
            self.emit_pair(scope, to, &pending);
            self.reconcile_slot(
              rec.watch(),
              scope,
              name,
              Self::record_occupant(rec),
              true,
              rec.node(),
            );
          }
          (None, held) => {
            if let Some(src) = held {
              self.drop_subtree(src);
            }
            self.emit_pair(scope, to, &pending);
          }
        }
      }
      Some(pending) => {
        // Late destination (past the window): the source stranded. Resolve it (drops
        // the held subtree, emits a guarded `Removed`). Then treat the arrival as a
        // fresh object — but only if the destination parent survived that teardown (a
        // cyclic/descendant late destination sits inside the held source, so dropping
        // it removes `rec.watch()`); otherwise escalate with a `Rescan`.
        self.resolve_stored_half(pending);
        if self.is_watched(rec.watch()) {
          self.emit(scope, to, ChangeKind::Created);
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
        } else {
          self.emit_rescan(scope, to);
        }
      }
      None => {
        self.emit(scope, to, ChangeKind::Created);
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
      self.resolve_lost_source(pending.scope, from);
    }
  }

  /// The current source location of a pending half, reconstructed from its slot
  /// `(from_parent, from_name)` so it tracks any reparent of the source's ancestor.
  fn pending_from(&self, pending: &PendingMove) -> Location {
    self.child_location(pending.from_parent, &pending.from_name)
  }

  /// Emits the outcome of a paired `MovedTo`: a `Moved` when the source is still
  /// anchored, otherwise a fresh `Created`. Liveness is checked *now*, not snapshotted
  /// earlier — a reparent can have dropped `from_parent` (its destination slot may be
  /// the source's own parent), and a `Moved` reconstructed off a dropped parent would
  /// carry a wrong from-path.
  fn emit_pair(&mut self, scope: ScopeId, to: Location, pending: &PendingMove) {
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
  /// destination also removed `child` — the adversarial case where the held source sat
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
      self.inherit_rearm(child);
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
  fn resolve_lost_source(&mut self, scope: ScopeId, from: Location) {
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
    if !self.descends() {
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
          self.inherit_rearm(fresh);
        }
      }
      SlotOccupant::File | SlotOccupant::Gone => {
        if let Some(stale) = self.child_watch(parent, name) {
          self.drop_subtree(stale);
        }
      }
    }
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
    if rec.is_dir() == Some(true) {
      SlotOccupant::Dir
    } else {
      SlotOccupant::File
    }
  }

  fn on_move_self(&mut self, scope: ScopeId, rec: &OsRecord) {
    if self.is_root_watch(rec.watch()) {
      // The new path of a moved root is unknowable from inotify alone.
      self.emit_rescan(scope, Location::new());
    }
  }

  fn on_delete_self(&mut self, scope: ScopeId, rec: &OsRecord) {
    if self.is_root_watch(rec.watch()) {
      let location = self.location_of(rec.watch());
      self.emit(scope, location, ChangeKind::Removed);
    }
  }

  fn on_ignored(&mut self, rec: &OsRecord) {
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
  /// every reconciliation trigger (through [`emit_rescan`](Self::emit_rescan)), so the
  /// `Rescan` — and every change emitted after it — carries a generation that strictly
  /// dominates whatever the consumer acted on before the trigger.
  fn bump_epoch(&mut self, scope: ScopeId) -> Epoch {
    let next = self.epoch_of(scope).next();
    self.scope_epochs.insert(scope, next);
    next
  }

  fn emit_rescan(&mut self, scope: ScopeId, location: Location) {
    // A `Rescan` IS the reconciliation trigger: bump the generation FIRST so the Rescan,
    // and every later change for this scope, strictly dominates what the consumer holds.
    self.bump_epoch(scope);
    self.emit(scope, location, ChangeKind::Rescan);
  }

  fn emit(&mut self, scope: ScopeId, location: Location, kind: ChangeKind) {
    let id = self.next_change_id();
    let change = Change::new(id, scope, location, kind, self.epoch_of(scope));
    let key = Self::dedup_key(&change);
    if self.pending_keys.insert(key) {
      self.events.push_back(change);
    }
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
    let id = WatchId::new(self.watch_ids.mint());
    self.nodes.insert(
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
    self.actions.push_back(Action::watch(
      id,
      crate::action::WatchTarget::child(parent, name),
      Interest::all(),
    ));
  }

  fn drop_subtree(&mut self, root: WatchId) {
    let mut stack = std::vec::Vec::new();
    stack.push(root);
    while let Some(id) = stack.pop() {
      let Some(node) = self.nodes.remove(&id) else {
        continue;
      };
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
      self.actions.push_back(Action::Unwatch(id));
    }
    // NOTE: a narrow subtree drop deliberately does NOT purge pending move halves.
    // A half whose source parent was dropped may still pair: its `MovedTo` can
    // arrive at a still-watched destination in the same scope. Keeping it pairable
    // preserves the move; the `handle_timeout` liveness guard (`is_watched(
    // from_parent)`) suppresses the stale `Removed` if no destination ever comes.
    // Whole-scope teardown purges instead — see `unregister_root` /
    // `purge_scope_pending_moves`.
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
    match rec.name() {
      Some(name) => self.child_location(rec.watch(), name),
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
    matches!(
      self.nodes.get(&id).map(|node| node.state),
      Some(
        NodeState::Arming { rearm: true }
          | NodeState::Enumerating {
            kind: EnumKind::Rearm,
            ..
          }
      )
    )
  }

  /// Sets a node's [`NodeState`], if it is still registered.
  fn set_state(&mut self, id: WatchId, state: NodeState) {
    if let Some(node) = self.nodes.get_mut(&id) {
      node.state = state;
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
