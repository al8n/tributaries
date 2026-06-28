//! The primitive-agnostic top half: the `Monitor` state machine.

use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::{
  action::Action,
  capabilities::Capabilities,
  change::{Change, ChangeKind},
  error::WatchError,
  id::{ChangeId, MoveCookie, ReqId, ScopeId, Sequence, WatchId},
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
  live: bool,
}

/// A pending [`RecordKind::MovedFrom`] awaiting its matching
/// [`RecordKind::MovedTo`].
///
/// It carries enough to validate a candidate pair before consuming it *and* to
/// purge it when its source disappears. `scope` and `deadline` bound pairing in
/// space and time. `from_parent` (the watch the `MovedFrom` arrived on) anchors
/// the half in the watch tree: a teardown of that subtree must discard this half
/// (invariant b) rather than let it later time out into a `Removed` for a path
/// that no longer exists.
///
/// A watched-directory source is *eager-dropped* the moment it moves away (see
/// [`Monitor::on_moved_from`]), so the half holds no reference to it; coverage at
/// a rename's destination is re-armed from the `MovedTo` record, exactly like a
/// fresh directory creation.
#[derive(Debug, Clone)]
struct PendingMove {
  from: Location,
  scope: ScopeId,
  deadline: Instant,
  from_parent: WatchId,
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
        live: false,
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
    let Some(&WatchNode { scope, live, .. }) = self.nodes.get(&dir) else {
      return;
    };
    if !live {
      return;
    }

    if res.forces_rescan() {
      self.emit_rescan(scope, self.location_of(dir));
      return;
    }

    for entry in res.entries() {
      let location = self.child_location(dir, entry.name());
      self.emit(scope, location, ChangeKind::Created);
      // The enumerate `is_dir` contract mirrors the record `is_dir` contract: only
      // a known directory is descended into (an `Unknown`-kind entry is treated as a
      // non-directory, never watched). A cold enumerate is discovery, not a replace,
      // so an already-watched slot is reused (`replaced = false`).
      let occupant = if entry.is_dir() {
        SlotOccupant::Dir
      } else {
        SlotOccupant::File
      };
      self.reconcile_slot(dir, scope, entry.name(), occupant, false);
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
        node.live = true;
        if is_dir && self.descends() {
          let req = self.next_req_id();
          self.pending_enumerate.insert(req, id);
          self.actions.push_back(Action::enumerate(req, id));
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
  /// exactly the affected scope, so nothing is silently lost.
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn on_overflow(&mut self, scope: Scope, _now: Instant) {
    match scope {
      Scope::All => {
        let roots: std::vec::Vec<(ScopeId, WatchId)> =
          self.roots.iter().map(|(s, w)| (*s, *w)).collect();
        for (scope_id, root) in roots {
          self.emit_rescan(scope_id, self.location_of(root));
        }
      }
      Scope::Root(scope_id) => {
        let location = self
          .roots
          .get(&scope_id)
          .map(|root| self.location_of(*root))
          .unwrap_or_default();
        self.emit_rescan(scope_id, location);
      }
      Scope::Subtree(watch) => {
        if let Some(scope_id) = self.scope_of(watch) {
          self.emit_rescan(scope_id, self.location_of(watch));
        }
      }
    }
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
      self.reconcile_slot(rec.watch(), scope, name, Self::record_occupant(rec), false);
    }
  }

  fn on_removed(&mut self, scope: ScopeId, rec: &OsRecord) {
    let location = self.record_location(rec);
    self.emit(scope, location, ChangeKind::Removed);
    if let Some(name) = rec.name() {
      // The slot's object is gone: drop any watch that covered it, so a later
      // create at the same name is not mistaken for a duplicate of the old object.
      self.reconcile_slot(rec.watch(), scope, name, SlotOccupant::Gone, false);
    }
  }

  fn on_moved_from(&mut self, scope: ScopeId, rec: &OsRecord, now: Instant) {
    let from = self.record_location(rec);
    let from_parent = rec.watch();
    let from_watch = rec
      .name()
      .and_then(|name| self.child_watch(rec.watch(), name));
    // Eager-drop a watched-directory source the moment it moves away: free its
    // `(parent, name)` slot and subtree NOW, before recording the half. This lets a
    // replacement arriving at the same path during the pending window install its
    // own watch (the slot is no longer occupied by a stale entry), and stops the
    // dead watch from delivering records for a path the object has left. Coverage
    // at a rename's destination is re-armed later from the `MovedTo` record, so the
    // half need not reference the dropped source. Dropping before the insert also
    // means this drop's `purge_pending_moves` runs while the new half is not yet
    // present, so it cannot purge the half we record.
    if let Some(src) = from_watch {
      self.drop_subtree(src);
    }
    match rec.cookie() {
      Some(cookie) => {
        let pending = PendingMove {
          from,
          scope,
          deadline: now + self.move_window,
          from_parent,
        };
        // Invariant (d): the cookie is namespaced by scope, so only a *same-scope*
        // reused/colliding cookie collides on this composite key. The displaced
        // half can no longer be paired, so it resolves on its own rather than
        // being silently overwritten.
        if let Some(displaced) = self.pending_moves.insert((scope, cookie), pending) {
          self.resolve_stored_half(displaced);
        }
      }
      // A no-cookie source is resolved immediately; its `from_parent` is `rec.watch()`,
      // which is live by construction (`scope_of` succeeded), so no guard is needed.
      None => self.resolve_lost_source(scope, from),
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
        // A validated rename: emit the move (coverage re-armed below).
        self.emit(scope, to, ChangeKind::Moved(pending.from));
      }
      Some(pending) => {
        // Late destination (past the window): the source stranded. Resolve it into a
        // `Removed` (guarded — a dead source emits nothing), and treat the arrival as
        // a fresh object moved into the slot.
        self.resolve_stored_half(pending);
        self.emit(scope, to, ChangeKind::Created);
      }
      None => {
        self.emit(scope, to, ChangeKind::Created);
      }
    }
    // A `MovedTo` brings a definitively-NEW object to the slot (`replaced = true`),
    // so any stale watch there is dropped before re-arming. Runs for every arm, so
    // coverage at the destination is reconciled however the move resolved.
    if let Some(name) = rec.name() {
      self.reconcile_slot(rec.watch(), scope, name, Self::record_occupant(rec), true);
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
  fn resolve_stored_half(&mut self, pending: PendingMove) {
    if self.is_watched(pending.from_parent) {
      self.resolve_lost_source(pending.scope, pending.from);
    }
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
  ) {
    if !self.descends() {
      return;
    }
    match occupant {
      SlotOccupant::Dir => {
        if replaced && let Some(stale) = self.child_watch(parent, name) {
          self.drop_subtree(stale);
        }
        self.install_child(parent, scope, name.clone(), true);
      }
      SlotOccupant::File | SlotOccupant::Gone => {
        if let Some(stale) = self.child_watch(parent, name) {
          self.drop_subtree(stale);
        }
      }
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

  fn emit_rescan(&mut self, scope: ScopeId, location: Location) {
    self.emit(scope, location, ChangeKind::Rescan);
  }

  fn emit(&mut self, scope: ScopeId, location: Location, kind: ChangeKind) {
    let id = self.next_change_id();
    let change = Change::new(id, scope, location, kind);
    let key = Self::dedup_key(&change);
    if self.pending_keys.insert(key) {
      self.events.push_back(change);
    }
  }

  fn install_child(&mut self, parent: WatchId, scope: ScopeId, name: Segment, is_dir: bool) {
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
        live: false,
      },
    );
    self.child_index.insert((parent, name.clone()), id);
    self.actions.push_back(Action::watch(
      id,
      crate::action::WatchTarget::child(parent, name),
      Interest::all(),
    ));
  }

  fn drop_subtree(&mut self, root: WatchId) {
    let mut removed = BTreeSet::new();
    let mut stack = std::vec::Vec::new();
    stack.push(root);
    while let Some(id) = stack.pop() {
      let children: std::vec::Vec<WatchId> = self
        .nodes
        .iter()
        .filter(|(_, node)| node.parent == Some(id))
        .map(|(child, _)| *child)
        .collect();
      stack.extend(children);

      if let Some(node) = self.nodes.remove(&id) {
        // Keep the child index in lockstep with the node map: a removed child must
        // leave both, or a later descent would skip re-arming it (stale index) and
        // a path could resolve through a dropped node.
        if node.parent.is_none() {
          self.roots.remove(&node.scope);
        } else if let (Some(parent), Some(name)) = (node.parent, node.name) {
          self.child_index.remove(&(parent, name));
        }
        removed.insert(id);
        self.actions.push_back(Action::Unwatch(id));
      }
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

  fn location_of(&self, id: WatchId) -> Location {
    let mut segments = std::vec::Vec::new();
    let mut cursor = Some(id);
    while let Some(current) = cursor {
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
