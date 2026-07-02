//! The sans-I/O driver core: every decision between a raw OS batch and the
//! Monitor lives here, with all I/O returned as typed [`Effect`]s.
//!
//! `DriverCore` is the proto's Sans-I/O pattern applied one level up. It owns
//! the [`Monitor`] plus the driver state the Monitor cannot hold — path
//! lowering, flag grounding, rename classification, probe parking, overflow
//! clamping, identity minting, and the consumer-lag protocol — and it never
//! spawns, stats, sends, or reads a clock. The async driver task executes the
//! effects it emits and feeds the results (and the time) back in, so every
//! protocol is unit-testable with a hand clock and zero tasks.
//!
//! FSEvents flags are hints, never a log: one event's flag word can carry
//! several operations OR'd together with ordering unrecoverable, so no record
//! verb is minted from an ambiguous word — truth is established by a
//! [`Probe`](Effect::Probe) and anything un-groundable escalates to a located
//! rescan. Loss is never silent.

use std::{
  collections::{BTreeMap, VecDeque},
  num::NonZeroU64,
  path::{Path, PathBuf},
  time::Duration,
};

use tributary_proto::{
  Capabilities, Change, FileKind, Identity, Instant, Interest, Location, Monitor, MoveCookie,
  OsRecord, RecordKind, Scope, ScopeId, Segment, SubtreeScope, WatchError, WatchId,
};

use crate::os::{FsEventFlags, RawOsEvent, SourceError};

#[cfg(test)]
mod tests;

/// Correlates a [`Effect::Probe`] request with its
/// [`on_probe_result`](DriverCore::on_probe_result).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ProbeId(u64);

/// What an executed probe (an `lstat` of one path) found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeOutcome {
  /// The path does not exist.
  Missing,
  /// The path exists.
  Present {
    /// The object's kind.
    kind: FileKind,
    /// The object's inode number, if one could be read.
    file_id: Option<NonZeroU64>,
    /// The device the object lives on; identity is minted only on the
    /// root's own device.
    dev: u64,
  },
  /// The probe failed (permission, I/O); existence is unknowable.
  Failed,
}

/// What the blocking spawn of a native source learned about its root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RootMeta {
  /// The canonicalized root — the byte-exact prefix event paths arrive under.
  pub(crate) root: PathBuf,
  /// The device the root lives on.
  pub(crate) root_dev: u64,
}

/// One I/O obligation the driver task must execute for the core.
#[derive(Debug)]
pub(crate) enum Effect {
  /// Start the native source watching `root` for `scope`.
  SpawnStream {
    /// The scope the stream will feed.
    scope: ScopeId,
    /// The root path as the consumer supplied it.
    root: PathBuf,
  },
  /// Quiesce and destroy `scope`'s native source.
  TeardownStream {
    /// The scope whose stream is torn down.
    scope: ScopeId,
  },
  /// `lstat` one path and feed the outcome back under `probe`.
  Probe {
    /// The correlation id the result must echo.
    probe: ProbeId,
    /// The absolute path to stat.
    path: PathBuf,
  },
  /// Deliver one change to the consumer, reporting the delivery outcome back
  /// through [`on_delivery`](DriverCore::on_delivery).
  Emit {
    /// The scope the change belongs to.
    scope: ScopeId,
    /// The change to deliver.
    change: Change,
  },
}

/// The outcome of one attempted [`Effect::Emit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Delivery {
  /// The consumer channel accepted the change.
  Accepted,
  /// The consumer channel was full; the change was not delivered.
  Refused,
}

/// A planned Monitor input, compiled from one raw event.
#[derive(Debug)]
enum Planned {
  /// Feed a normalized record.
  Rec(OsRecord),
  /// Feed an overflow for a scope slice.
  Over(Scope),
}

/// One raw event's compilation: its planned inputs, possibly gated on a probe.
#[derive(Debug)]
struct Item {
  planned: Vec<Planned>,
  probe: Option<ProbeId>,
}

/// A batch whose items are being resolved; fed to the Monitor only once every
/// probe has answered, so per-root input order is preserved.
#[derive(Debug)]
struct PendingBatch {
  items: Vec<Item>,
  awaiting: usize,
}

/// Per-root batch parking: while a batch has probes in flight, later batches
/// queue behind it rather than overtaking it.
#[derive(Debug, Default)]
struct Park {
  active: Option<PendingBatch>,
  queued: VecDeque<Vec<RawOsEvent>>,
}

/// Why a probe was issued, and how to plan its resolution.
#[derive(Debug)]
enum ProbePurpose {
  /// A multi-verb flag word needed existence to ground a single record.
  Ambiguous {
    item: usize,
    flags: FsEventFlags,
    target: Option<Location>,
    path: PathBuf,
  },
  /// An unpaired rename half needed existence to pick its direction.
  Rename {
    item: usize,
    file_id: Option<NonZeroU64>,
    target: Option<Location>,
    path: PathBuf,
  },
  /// A `RootChanged` needed the root's existence to pick the death signal.
  RootAlive { item: usize },
}

#[derive(Debug)]
struct ProbeCtx {
  scope: ScopeId,
  purpose: ProbePurpose,
}

/// How long a refused parked delivery waits before it is offered again. The
/// retry rides the core's own timer: an immediate re-offer would spin the
/// executing loop without yielding (the channel cannot drain meanwhile), so a
/// lagged consumer is polled at this bounded interval instead.
const DELIVERY_RETRY: Duration = Duration::from_millis(25);

/// The consumer-lag state of one scope. Events are only ever dropped while a
/// strictly-greater-epoch `Rescan` is parked and undelivered, so the
/// consumer's post-`Rescan` re-enumeration provably covers them.
#[derive(Debug)]
enum LagState {
  /// Deliveries flow.
  Normal,
  /// The consumer channel refused a change: a dominating `Rescan` is parked
  /// (or being minted, while `parked` is `None`) and everything else for the
  /// scope is dropped as dominated.
  Lagged {
    parked: Option<Change>,
    attempt: Attempt,
  },
}

/// The delivery lifecycle of a parked `Rescan`.
#[derive(Debug, Clone, Copy)]
enum Attempt {
  /// Ready to be offered by [`DriverCore::poll_effect`].
  Idle,
  /// Offered and awaiting its [`DriverCore::on_delivery`] outcome; carries
  /// the offered change's epoch so an acceptance of a since-replaced
  /// `Rescan` retries the newer one rather than ending the lag.
  InFlight(tributary_proto::Epoch),
  /// Refused; re-offered once the retry deadline passes.
  Spent {
    /// When the next offer becomes due.
    retry_at: Instant,
  },
}

/// One watched root's driver-side state.
#[derive(Debug)]
struct ScopeState {
  watch: WatchId,
  requested: PathBuf,
  /// Canonicalized root bytes — known once the stream spawned.
  root: Option<PathBuf>,
  root_dev: Option<u64>,
  /// Foreign-device prefixes discovered under the root (mounts, firmlinks);
  /// tiny in practice, so a linear scan beats indexing.
  mounts: Vec<PathBuf>,
  lag: LagState,
  park: Park,
  /// The journal id counter wrapped; any minted resume token is invalid.
  resume_poisoned: bool,
}

/// Where a path fell relative to its scope root.
enum Lowered {
  /// The root itself.
  Root,
  /// A descendant, as a root-relative location.
  Target(Location),
  /// Not under the root (above it, unrelated, or unrepresentable) — the
  /// caller escalates, never drops.
  Outside,
}

/// The sans-I/O driver core. See the module docs for the shape.
#[derive(Debug)]
pub(crate) struct DriverCore {
  monitor: Monitor,
  scopes: BTreeMap<ScopeId, ScopeState>,
  watch_scopes: BTreeMap<WatchId, ScopeId>,
  probes: BTreeMap<ProbeId, ProbeCtx>,
  effects: VecDeque<Effect>,
  scope_seq: u64,
  probe_seq: u64,
}

impl DriverCore {
  /// Builds a core whose Monitor pairs renames within `move_window`.
  pub(crate) fn new(move_window: Duration) -> Self {
    let mut monitor = Monitor::new(
      Capabilities::new()
        .with_supports_push()
        .with_native_move()
        .with_kernel_recursive(),
    );
    monitor.set_move_window(move_window);
    Self {
      monitor,
      scopes: BTreeMap::new(),
      watch_scopes: BTreeMap::new(),
      probes: BTreeMap::new(),
      effects: VecDeque::new(),
      scope_seq: 0,
      probe_seq: 0,
    }
  }

  /// Registers a new watched root, returning its scope handle. Queues the
  /// [`Effect::SpawnStream`] that starts the native source.
  pub(crate) fn on_watch(&mut self, root: PathBuf, interest: Interest) -> ScopeId {
    self.scope_seq += 1;
    let scope = ScopeId::new(NonZeroU64::new(self.scope_seq).expect("sequence starts at one"));
    let watch = self.monitor.register_root(scope, interest);
    self.scopes.insert(
      scope,
      ScopeState {
        watch,
        requested: root,
        root: None,
        root_dev: None,
        mounts: Vec::new(),
        lag: LagState::Normal,
        park: Park::default(),
        resume_poisoned: false,
      },
    );
    self.watch_scopes.insert(watch, scope);
    self.drain_monitor();
    scope
  }

  /// Unregisters a watched root; its teardown effect follows.
  pub(crate) fn on_unwatch(&mut self, scope: ScopeId) {
    if self.scopes.contains_key(&scope) {
      self.monitor.unregister_root(scope);
      self.drain_monitor();
    }
  }

  /// Feeds the blocking spawn's outcome for `scope`'s stream.
  pub(crate) fn on_stream_spawned(&mut self, scope: ScopeId, res: Result<RootMeta, SourceError>) {
    let Some(state) = self.scopes.get_mut(&scope) else {
      return;
    };
    let watch = state.watch;
    match res {
      Ok(meta) => {
        state.root = Some(meta.root);
        state.root_dev = Some(meta.root_dev);
        self.monitor.on_watch_result(watch, Ok(()));
      }
      Err(err) => {
        self.monitor.on_watch_result(watch, Err(watch_error(&err)));
      }
    }
    self.drain_monitor();
  }

  /// Feeds one decoded callback batch for `scope`.
  pub(crate) fn on_batch(&mut self, scope: ScopeId, events: Vec<RawOsEvent>, now: Instant) {
    let Some(mut state) = self.scopes.remove(&scope) else {
      return;
    };
    if state.park.active.is_some() {
      state.park.queued.push_back(events);
      self.scopes.insert(scope, state);
      return;
    }
    let batch = self.compile(&mut state, scope, events);
    let fed = Self::feed_if_ready(&mut self.monitor, &mut state, batch, now);
    self.scopes.insert(scope, state);
    if fed {
      self.pump_queued(scope, now);
    }
    self.drain_monitor();
  }

  /// Feeds one probe's outcome; a completed batch (and any batches queued
  /// behind it) is then fed to the Monitor in order.
  pub(crate) fn on_probe_result(&mut self, probe: ProbeId, outcome: ProbeOutcome, now: Instant) {
    let Some(ctx) = self.probes.remove(&probe) else {
      return;
    };
    let Some(mut state) = self.scopes.remove(&ctx.scope) else {
      return;
    };
    let scope = ctx.scope;
    let item = Self::resolve(&mut state, ctx.purpose, outcome);
    let mut fed = false;
    if let Some(batch) = state.park.active.as_mut() {
      let (idx, planned) = item;
      if let Some(slot) = batch.items.get_mut(idx) {
        slot.planned = planned;
        slot.probe = None;
        batch.awaiting = batch.awaiting.saturating_sub(1);
      }
      if batch.awaiting == 0 {
        let batch = state.park.active.take().expect("just observed Some");
        Self::apply(&mut self.monitor, batch, now);
        fed = true;
      }
    }
    self.scopes.insert(scope, state);
    if fed {
      self.pump_queued(scope, now);
    }
    self.drain_monitor();
  }

  /// Feeds a transport-level loss signal for `scope` (a dropped batch, the
  /// handle's overflow latch): parked work is dominated and dropped, and the
  /// Monitor turns the loss into an epoch-bumped `Rescan`.
  pub(crate) fn on_root_overflow(&mut self, scope: ScopeId, now: Instant) {
    let Some(state) = self.scopes.get_mut(&scope) else {
      return;
    };
    state.park.active = None;
    state.park.queued.clear();
    self.probes.retain(|_, ctx| ctx.scope != scope);
    self.monitor.on_overflow(Scope::Root(scope), now);
    self.drain_monitor();
  }

  /// Feeds a dead-stream signal: the scope's coverage ended with no parent
  /// watch left to report it.
  pub(crate) fn on_source_fatal(&mut self, scope: ScopeId, now: Instant) {
    let Some(state) = self.scopes.get(&scope) else {
      return;
    };
    let watch = state.watch;
    self
      .monitor
      .on_os_record(OsRecord::new(watch, RecordKind::Ignored), now);
    self.drain_monitor();
  }

  /// Feeds the outcome of one attempted [`Effect::Emit`].
  pub(crate) fn on_delivery(&mut self, scope: ScopeId, delivery: Delivery, now: Instant) {
    let Some(state) = self.scopes.get_mut(&scope) else {
      return;
    };
    match (delivery, &mut state.lag) {
      (Delivery::Accepted, LagState::Lagged { parked, attempt }) => {
        let delivered_current = match (parked.as_ref(), &attempt) {
          (Some(change), Attempt::InFlight(epoch)) => change.epoch() == *epoch,
          _ => false,
        };
        if delivered_current {
          state.lag = LagState::Normal;
        } else {
          // A since-replaced Rescan was accepted: the newer one still owes
          // delivery, so it becomes offerable immediately.
          *attempt = Attempt::Idle;
        }
      }
      (Delivery::Accepted, LagState::Normal) => {}
      (Delivery::Refused, LagState::Normal) => {
        state.lag = LagState::Lagged {
          parked: None,
          attempt: Attempt::Idle,
        };
        self.monitor.on_overflow(Scope::Root(scope), now);
        self.drain_monitor();
      }
      (Delivery::Refused, LagState::Lagged { attempt, .. }) => {
        // Never re-offer synchronously — the refusing channel cannot have
        // drained yet; the retry rides the core's timer.
        *attempt = Attempt::Spent {
          retry_at: now + DELIVERY_RETRY,
        };
      }
    }
  }

  /// Advances time: resolves rename halves whose pairing window elapsed and
  /// re-arms refused parked deliveries whose retry deadline passed.
  pub(crate) fn on_timeout(&mut self, now: Instant) {
    self.monitor.handle_timeout(now);
    for state in self.scopes.values_mut() {
      if let LagState::Lagged { attempt, .. } = &mut state.lag
        && let Attempt::Spent { retry_at } = attempt
        && now.reached(*retry_at)
      {
        *attempt = Attempt::Idle;
      }
    }
    self.drain_monitor();
  }

  /// Dequeues the next I/O obligation, if any. A scope lagging with a parked
  /// `Rescan` offers that delivery here once per attempt; a refusal re-arms
  /// through the retry timer, never synchronously.
  pub(crate) fn poll_effect(&mut self) -> Option<Effect> {
    if let Some(effect) = self.effects.pop_front() {
      return Some(effect);
    }
    for (scope, state) in self.scopes.iter_mut() {
      if let LagState::Lagged {
        parked: Some(change),
        attempt: attempt @ Attempt::Idle,
      } = &mut state.lag
      {
        *attempt = Attempt::InFlight(change.epoch());
        return Some(Effect::Emit {
          scope: *scope,
          change: change.clone(),
        });
      }
    }
    None
  }

  /// The earliest instant [`on_timeout`](Self::on_timeout) has work to do:
  /// the Monitor's pairing deadline or a parked delivery's retry, whichever
  /// comes first.
  pub(crate) fn poll_timeout(&self) -> Option<Instant> {
    let retry = self
      .scopes
      .values()
      .filter_map(|state| match &state.lag {
        LagState::Lagged {
          attempt: Attempt::Spent { retry_at },
          ..
        } => Some(*retry_at),
        _ => None,
      })
      .min();
    match (self.monitor.poll_timeout(), retry) {
      (Some(monitor), Some(retry)) => Some(if monitor.reached(retry) {
        retry
      } else {
        monitor
      }),
      (monitor, retry) => monitor.or(retry),
    }
  }

  /// Whether `scope`'s journal ids wrapped, invalidating any resume token.
  #[cfg(test)]
  pub(crate) fn resume_poisoned(&self, scope: ScopeId) -> bool {
    self
      .scopes
      .get(&scope)
      .is_some_and(|state| state.resume_poisoned)
  }

  /// Applies a fully-resolved batch to the Monitor in item order.
  fn feed_if_ready(
    monitor: &mut Monitor,
    state: &mut ScopeState,
    batch: PendingBatch,
    now: Instant,
  ) -> bool {
    if batch.awaiting == 0 {
      Self::apply(monitor, batch, now);
      true
    } else {
      state.park.active = Some(batch);
      false
    }
  }

  fn apply(monitor: &mut Monitor, batch: PendingBatch, now: Instant) {
    for item in batch.items {
      for planned in item.planned {
        match planned {
          Planned::Rec(rec) => monitor.on_os_record(rec, now),
          Planned::Over(scope) => monitor.on_overflow(scope, now),
        }
      }
    }
  }

  /// Compiles and feeds queued batches until one parks or the queue drains.
  fn pump_queued(&mut self, scope: ScopeId, now: Instant) {
    loop {
      let Some(mut state) = self.scopes.remove(&scope) else {
        return;
      };
      let Some(events) = state.park.queued.pop_front() else {
        self.scopes.insert(scope, state);
        return;
      };
      let batch = self.compile(&mut state, scope, events);
      let fed = Self::feed_if_ready(&mut self.monitor, &mut state, batch, now);
      self.scopes.insert(scope, state);
      if !fed {
        return;
      }
    }
  }

  /// Compiles one raw batch into planned Monitor inputs, minting probes for
  /// everything a flag word alone cannot ground.
  fn compile(
    &mut self,
    state: &mut ScopeState,
    scope: ScopeId,
    events: Vec<RawOsEvent>,
  ) -> PendingBatch {
    // Same-batch rename pairing: exactly two renamed events sharing a fileID
    // are one within-tree rename; the journal orders source before
    // destination, so the lower event id is the source half.
    let mut rename_groups: BTreeMap<NonZeroU64, Vec<usize>> = BTreeMap::new();
    for (idx, ev) in events.iter().enumerate() {
      // Only a plain rename half may pre-pair; any control flag routes the
      // event through the full grounding table instead.
      let special = ev.flags.root_changed()
        || ev.flags.lost_sync()
        || ev.flags.must_scan_subdirs()
        || ev.flags.event_ids_wrapped()
        || ev.flags.history_done()
        || ev.flags.mount()
        || ev.flags.unmount();
      if ev.flags.item_renamed()
        && !special
        && let Some(fid) = ev.file_id
      {
        rename_groups.entry(fid).or_default().push(idx);
      }
    }
    let mut paired: BTreeMap<usize, Planned> = BTreeMap::new();
    for (fid, group) in &rename_groups {
      if let [a, b] = group.as_slice()
        && events[*a].path != events[*b].path
      {
        let (from_idx, to_idx) = if events[*a].event_id <= events[*b].event_id {
          (*a, *b)
        } else {
          (*b, *a)
        };
        let cookie = MoveCookie::new(*fid);
        let (from_slot, to_slot) = (from_idx.min(to_idx), from_idx.max(to_idx));
        if let (Some(from), Some(to)) = (
          self.plan_move_half(
            state,
            RecordKind::MovedFrom,
            &events[from_idx],
            Some(cookie),
          ),
          self.plan_move_half(state, RecordKind::MovedTo, &events[to_idx], Some(cookie)),
        ) {
          // The source half must reach the Monitor before its destination:
          // roles follow the event ids, feed positions take the earlier slot.
          paired.insert(from_slot, from);
          paired.insert(to_slot, to);
        }
      }
    }

    let mut items = Vec::with_capacity(events.len());
    let mut awaiting = 0usize;
    for (idx, ev) in events.iter().enumerate() {
      if let Some(planned) = paired.remove(&idx) {
        items.push(Item {
          planned: vec![planned],
          probe: None,
        });
        continue;
      }
      match self.plan_event(state, scope, idx, ev) {
        ItemPlan::Immediate(planned) => items.push(Item {
          planned,
          probe: None,
        }),
        ItemPlan::Await { probe, path } => {
          awaiting += 1;
          self.effects.push_back(Effect::Probe { probe, path });
          items.push(Item {
            planned: Vec::new(),
            probe: Some(probe),
          });
        }
      }
    }
    PendingBatch { items, awaiting }
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
  ) -> ItemPlan {
    let flags = ev.flags;
    if flags.history_done() {
      return ItemPlan::Immediate(Vec::new());
    }
    if flags.root_changed() {
      let probe = self.mint_probe(scope, ProbePurpose::RootAlive { item: idx });
      let path = state
        .root
        .clone()
        .unwrap_or_else(|| state.requested.clone());
      return ItemPlan::Await { probe, path };
    }
    if flags.event_ids_wrapped() {
      state.resume_poisoned = true;
      return ItemPlan::Immediate(vec![Planned::Over(Scope::Root(scope))]);
    }
    if flags.lost_sync() {
      return ItemPlan::Immediate(vec![Planned::Over(Scope::Root(scope))]);
    }
    if flags.must_scan_subdirs() {
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

    if flags.item_renamed() {
      let probe = self.mint_probe(
        scope,
        ProbePurpose::Rename {
          item: idx,
          file_id: ev.file_id,
          target,
          path: ev.path.clone(),
        },
      );
      return ItemPlan::Await {
        probe,
        path: ev.path.clone(),
      };
    }

    let created = flags.item_created();
    let removed = flags.item_removed();
    let modified = flags.item_modified();
    let attrib = flags.item_inode_meta_mod()
      || flags.item_change_owner()
      || flags.item_xattr_mod()
      || flags.item_finder_info_mod();
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
        if ev.flags.mount() {
          if !state.mounts.iter().any(|m| m == &ev.path) {
            state.mounts.push(ev.path.clone());
          }
        } else {
          state.mounts.retain(|m| m != &ev.path);
        }
        vec![Planned::Over(located(state.watch, Some(location)))]
      }
      Lowered::Outside => vec![Planned::Over(Scope::Root(scope))],
    }
  }

  /// Plans one half of a same-batch rename pair. `None` when the path cannot
  /// be lowered — the caller then leaves both halves to the singleton path.
  fn plan_move_half(
    &mut self,
    state: &mut ScopeState,
    kind: RecordKind,
    ev: &RawOsEvent,
    cookie: Option<MoveCookie>,
  ) -> Option<Planned> {
    let target = match lower(state, &ev.path) {
      Lowered::Target(location) => Some(location),
      // A rename half naming the root or an outside path is not a pairable
      // child move; fall back to the singleton probe path.
      Lowered::Root | Lowered::Outside => return None,
    };
    let mut rec = record_from_event(
      state,
      kind,
      target,
      dir_hint(ev.flags),
      ev.file_id,
      &ev.path,
    );
    if let Some(cookie) = cookie {
      rec = rec.with_cookie(cookie);
    }
    Some(Planned::Rec(rec))
  }

  /// Resolves one probe's plan. Returns the item index and its planned inputs.
  fn resolve(
    state: &mut ScopeState,
    purpose: ProbePurpose,
    outcome: ProbeOutcome,
  ) -> (usize, Vec<Planned>) {
    match purpose {
      ProbePurpose::RootAlive { item } => {
        let kind = match outcome {
          ProbeOutcome::Missing => RecordKind::DeleteSelf,
          // Present elsewhere or unknowable both end the scope's coverage:
          // the registered path no longer names the watched object.
          ProbeOutcome::Present { .. } | ProbeOutcome::Failed => RecordKind::MoveSelf,
        };
        (item, vec![Planned::Rec(OsRecord::new(state.watch, kind))])
      }
      ProbePurpose::Ambiguous {
        item,
        flags,
        target,
        path,
      } => {
        let planned = match outcome {
          ProbeOutcome::Missing => {
            let rec = record_with(state, RecordKind::Removed, target, dir_hint(flags), None);
            vec![Planned::Rec(rec)]
          }
          ProbeOutcome::Present { kind, file_id, dev } => {
            learn_device(state, &path, dev);
            let verb = if flags.item_created() {
              RecordKind::Created
            } else if flags.item_modified() {
              RecordKind::Modified
            } else {
              RecordKind::Attrib
            };
            let node = mint(state, &path, file_id, Some(dev));
            let rec = record_with(state, verb, target, Some(kind.is_dir()), node);
            vec![Planned::Rec(rec)]
          }
          ProbeOutcome::Failed => vec![Planned::Over(located(state.watch, target))],
        };
        (item, planned)
      }
      ProbePurpose::Rename {
        item,
        file_id,
        target,
        path,
      } => {
        let planned = match outcome {
          // Gone: the source half of a move out of (or within) the tree. The
          // fileID cookie lets a destination half pair inside the Monitor's
          // window; without one the Monitor degrades it to a removal now.
          ProbeOutcome::Missing => {
            let mut rec = record_with(state, RecordKind::MovedFrom, target, None, None);
            if let Some(fid) = file_id {
              rec = rec.with_cookie(MoveCookie::new(fid));
            }
            vec![Planned::Rec(rec)]
          }
          // Exists: the destination half. An appeared DIRECTORY delivers no
          // events for the children it arrived with, so the record is paired
          // with a located rescan — unless the Monitor pairs it with a held
          // source, where the extra rescan is merely redundant, never wrong.
          ProbeOutcome::Present {
            kind,
            file_id: probed,
            dev,
          } => {
            learn_device(state, &path, dev);
            let cookie = file_id.or(probed);
            let node = mint(state, &path, probed, Some(dev));
            let mut rec = record_with(
              state,
              RecordKind::MovedTo,
              target.clone(),
              Some(kind.is_dir()),
              node,
            );
            if let Some(fid) = cookie {
              rec = rec.with_cookie(MoveCookie::new(fid));
            }
            let mut planned = vec![Planned::Rec(rec)];
            if kind.is_dir() {
              planned.push(Planned::Over(located(state.watch, target)));
            }
            planned
          }
          ProbeOutcome::Failed => vec![Planned::Over(located(state.watch, target))],
        };
        (item, planned)
      }
    }
  }

  fn mint_probe(&mut self, scope: ScopeId, purpose: ProbePurpose) -> ProbeId {
    self.probe_seq += 1;
    let probe = ProbeId(self.probe_seq);
    self.probes.insert(probe, ProbeCtx { scope, purpose });
    probe
  }

  /// Clamps an overflow path to the scope: strictly-under-root rescans the
  /// located subtree; the root, an ancestor ("/" on drops), or anything
  /// unrepresentable rescans the whole root.
  fn clamp(state: &ScopeState, scope: ScopeId, path: &Path) -> Scope {
    match lower(state, path) {
      Lowered::Target(location) => {
        Scope::Subtree(SubtreeScope::new(state.watch).with_descent(location))
      }
      Lowered::Root | Lowered::Outside => Scope::Root(scope),
    }
  }

  /// Drains the Monitor to a fixpoint: actions become effects, changes route
  /// through the per-scope lag protocol. Events drain first — a root-death
  /// `Rescan` must route while its scope's lag state still exists.
  fn drain_monitor(&mut self) {
    while let Some(change) = self.monitor.poll_event() {
      self.route_event(change);
    }
    while let Some(action) = self.monitor.poll_action() {
      match action {
        tributary_proto::Action::Watch(cmd) => {
          if let Some(scope) = cmd.target().root() {
            let root = self
              .scopes
              .get(&scope)
              .map(|state| state.requested.clone())
              .unwrap_or_default();
            self.effects.push_back(Effect::SpawnStream { scope, root });
          } else {
            debug_assert!(false, "a kernel-recursive monitor never descends");
          }
        }
        tributary_proto::Action::Unwatch(watch) => {
          if let Some(scope) = self.watch_scopes.remove(&watch) {
            self.scopes.remove(&scope);
            self.probes.retain(|_, ctx| ctx.scope != scope);
            self.effects.push_back(Effect::TeardownStream { scope });
          }
        }
        other => {
          debug_assert!(
            false,
            "a kernel-recursive monitor requests no reads: {other:?}"
          );
        }
      }
    }
  }

  fn route_event(&mut self, change: Change) {
    let scope = change.scope();
    let Some(state) = self.scopes.get_mut(&scope) else {
      // A change for a scope torn down in the same drain still delivers —
      // over-delivery is the safe direction.
      self.effects.push_back(Effect::Emit { scope, change });
      return;
    };
    match &mut state.lag {
      LagState::Normal => self.effects.push_back(Effect::Emit { scope, change }),
      LagState::Lagged { parked, .. } => {
        if change.kind().is_rescan() {
          // The newest dominating Rescan wins; everything else the scope
          // produces while lagged is covered by it and dropped.
          *parked = Some(change);
        }
      }
    }
  }
}

/// The plan for one compiled event.
enum ItemPlan {
  Immediate(Vec<Planned>),
  Await { probe: ProbeId, path: PathBuf },
}

/// Builds a record with identity minted from the event-side fileID.
fn record_from_event(
  state: &ScopeState,
  kind: RecordKind,
  target: Option<Location>,
  is_dir: Option<bool>,
  file_id: Option<NonZeroU64>,
  path: &Path,
) -> OsRecord {
  let node = mint(state, path, file_id, None);
  record_with(state, kind, target, is_dir, node)
}

/// Builds a record addressing `target` under the scope's root watch.
fn record_with(
  state: &ScopeState,
  kind: RecordKind,
  target: Option<Location>,
  is_dir: Option<bool>,
  node: Option<Identity>,
) -> OsRecord {
  let mut rec = OsRecord::new(state.watch, kind);
  if let Some(target) = target {
    rec = rec.with_target(target);
  }
  if let Some(is_dir) = is_dir {
    rec = rec.with_is_dir(is_dir);
  }
  if let Some(node) = node {
    rec = rec.with_node(node);
  }
  rec
}

/// A located subtree overflow at `target` under `watch` (the watch itself
/// when `target` is `None`).
fn located(watch: WatchId, target: Option<Location>) -> Scope {
  let sub = SubtreeScope::new(watch);
  Scope::Subtree(match target {
    Some(location) => sub.with_descent(location),
    None => sub,
  })
}

/// The directory-ness hint a flag word carries, if any.
fn dir_hint(flags: FsEventFlags) -> Option<bool> {
  if flags.item_is_dir() {
    Some(true)
  } else if flags.item_is_file() || flags.item_is_symlink() {
    Some(false)
  } else {
    None
  }
}

/// Mints the record identity for an object at `path`.
///
/// One function serves the event path (no device known — trusted iff no
/// foreign-mount prefix covers the path) and the probe path (`dev` known —
/// authoritative). Two minting schemes would make the Monitor's identity
/// comparisons fire on the same object forever.
fn mint(
  state: &ScopeState,
  path: &Path,
  file_id: Option<NonZeroU64>,
  dev: Option<u64>,
) -> Option<Identity> {
  let fid = file_id?;
  match (dev, state.root_dev) {
    (Some(dev), Some(root_dev)) if dev != root_dev => return None,
    _ => {}
  }
  if state.mounts.iter().any(|m| path.starts_with(m)) {
    return None;
  }
  Some(Identity::new(fid))
}

/// Records a probed foreign-device path as a mount prefix, so later
/// event-side identities under it degrade to `None` instead of colliding.
fn learn_device(state: &mut ScopeState, path: &Path, dev: u64) {
  if let Some(root_dev) = state.root_dev
    && dev != root_dev
    && !state.mounts.iter().any(|m| path.starts_with(m))
  {
    state.mounts.push(path.to_path_buf());
  }
}

/// Lowers an absolute event path to its place under the scope root.
fn lower(state: &ScopeState, path: &Path) -> Lowered {
  let Some(root) = state.root.as_deref() else {
    return Lowered::Outside;
  };
  let root_bytes = path_bytes(root);
  let bytes = path_bytes(path);
  let Some(rest) = bytes.strip_prefix(root_bytes) else {
    return Lowered::Outside;
  };
  let rest = match rest {
    [] => return Lowered::Root,
    [b'/', tail @ ..] => tail,
    // The prefix matched mid-component (root "/a/b" vs path "/a/bc").
    _ => return Lowered::Outside,
  };
  let mut segments = Vec::new();
  for part in rest.split(|&b| b == b'/') {
    if part.is_empty() {
      continue;
    }
    // macOS filenames are valid Unicode by filesystem contract; anything
    // else is unaddressable and escalates at the caller.
    let Ok(part) = std::str::from_utf8(part) else {
      return Lowered::Outside;
    };
    segments.push(Segment::new(part));
  }
  if segments.is_empty() {
    Lowered::Root
  } else {
    Lowered::Target(Location::from_segments(segments))
  }
}

fn path_bytes(path: &Path) -> &[u8] {
  #[cfg(unix)]
  {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes()
  }
  #[cfg(not(unix))]
  {
    path.as_os_str().to_str().map_or(&[][..], str::as_bytes)
  }
}

/// Maps a spawn failure to the Monitor's watch-error vocabulary.
fn watch_error(err: &SourceError) -> WatchError {
  match err {
    SourceError::RootUnavailable { source, .. } => match source.kind() {
      std::io::ErrorKind::NotFound => WatchError::NotFound,
      std::io::ErrorKind::PermissionDenied => WatchError::Permission,
      _ => WatchError::Io,
    },
    _ => WatchError::Io,
  }
}
