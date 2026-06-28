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
/// [`RecordKind::MovedTo`], with the deadline past which it is resolved alone.
#[derive(Debug, Clone)]
struct PendingMove {
  from: Location,
  scope: ScopeId,
  deadline: Instant,
}

/// A delivery-dedup key: a change is suppressed if an identical one is still
/// queued. Two changes are "identical" when they share a scope, location, and
/// kind discriminant — enough to make a cold-start `Created` idempotent against a
/// concurrent live `Created` for the same path.
type DedupKey = (ScopeId, Location, u8);

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
  roots: BTreeMap<ScopeId, WatchId>,
  pending_enumerate: BTreeMap<ReqId, WatchId>,
  pending_moves: BTreeMap<MoveCookie, PendingMove>,

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
      RecordKind::Removed => self.emit_child(scope, &rec, ChangeKind::Removed),
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
      if entry.is_dir() && self.descends() {
        self.install_child(dir, scope, entry.name().clone(), true);
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
  /// On [`WatchError::NoSpace`] the scope is degraded: rather than silently
  /// blinding the subtree, a [`ChangeKind::Rescan`] is emitted for the scope so
  /// the consumer re-enumerates. On [`WatchError::NotFound`] /
  /// [`WatchError::Gone`] the node is dropped (the target vanished before the
  /// watch took).
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
      Err(WatchError::NoSpace) => {
        self.emit_rescan(scope, self.location_of(id));
      }
      Err(WatchError::NotFound | WatchError::Gone) => {
        self.drop_subtree(id);
      }
      Err(WatchError::Permission | WatchError::Io) => {}
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
  /// unpaired source becomes a [`ChangeKind::Removed`].
  #[cfg_attr(not(tarpaulin), inline)]
  pub fn handle_timeout(&mut self, now: Instant) {
    let expired: std::vec::Vec<MoveCookie> = self
      .pending_moves
      .iter()
      .filter(|(_, pending)| now.reached(pending.deadline))
      .map(|(cookie, _)| *cookie)
      .collect();

    for cookie in expired {
      if let Some(pending) = self.pending_moves.remove(&cookie) {
        self.emit(pending.scope, pending.from, ChangeKind::Removed);
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
    self.emit_child(scope, rec, ChangeKind::Created);
    // TODO(§6): set the create-descend dirty flag — records hitting the new dir
    // before its enumerate is processed must escalate to a subtree Rescan. The
    // dirty-window tracking lands with the inotify sub-machine.
    let is_dir = rec.is_dir().unwrap_or(false);
    if is_dir
      && self.descends()
      && let Some(name) = rec.name()
    {
      self.install_child(rec.watch(), scope, name.clone(), true);
    }
  }

  fn on_moved_from(&mut self, scope: ScopeId, rec: &OsRecord, now: Instant) {
    let from = self.record_location(rec);
    match rec.cookie() {
      Some(cookie) => {
        self.pending_moves.insert(
          cookie,
          PendingMove {
            from,
            scope,
            deadline: now + self.move_window,
          },
        );
      }
      None => {
        self.emit(scope, from, ChangeKind::Removed);
      }
    }
  }

  fn on_moved_to(&mut self, scope: ScopeId, rec: &OsRecord, now: Instant) {
    let to = self.record_location(rec);
    let paired = rec
      .cookie()
      .and_then(|cookie| self.pending_moves.remove(&cookie));
    match paired {
      Some(pending) => {
        // TODO(§6): when the moved object is a watched directory, reparent its
        // subtree edge in place (O(1)) instead of relying on re-arming. The
        // parent-relative tree makes this a single edge change; it lands with
        // the inotify sub-machine.
        self.emit(scope, to, ChangeKind::Moved(pending.from));
      }
      None => {
        let _ = now;
        self.emit(scope, to, ChangeKind::Created);
        let is_dir = rec.is_dir().unwrap_or(false);
        if is_dir
          && self.descends()
          && let Some(name) = rec.name()
        {
          self.install_child(rec.watch(), scope, name.clone(), true);
        }
      }
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
      let children: std::vec::Vec<WatchId> = self
        .nodes
        .iter()
        .filter(|(_, node)| node.parent == Some(id))
        .map(|(child, _)| *child)
        .collect();
      stack.extend(children);

      if let Some(node) = self.nodes.remove(&id) {
        if node.parent.is_none() {
          self.roots.remove(&node.scope);
        }
        self.actions.push_back(Action::Unwatch(id));
      }
    }
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
    (
      change.scope(),
      change.location().clone(),
      Self::kind_tag(change.kind()),
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
