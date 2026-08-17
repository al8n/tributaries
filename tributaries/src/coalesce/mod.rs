//! The opt-in settle/debounce coalescer — a pure, sans-I/O state machine (design §6).
//!
//! A [`Coalescer`] buffers post-attribution [`Event`]s keyed by `(Subscription, key)`
//! and collapses a burst of changes to one key into a single emission, so a consumer
//! that only cares about the *settled* state of a file is not woken once per
//! intermediate write. It is generic over the key component `C` and the caller value
//! `V`, exactly like the [`Event`] it buffers. It is **pure**: it reads no clock
//! and knows no runtime — every time-dependent entry point takes an explicit
//! `now: Instant`, so it is exhaustively testable with a manual clock and zero real
//! time. All timer I/O lives in the driver (design global constraints): the driver
//! feeds it `now`, asks it for the [next deadline](Coalescer::next_deadline) to sleep
//! until, and [drains](Coalescer::drain_ready) the entries that have come due.
//!
//! # Per-subscription policy (design §6)
//!
//! The coalescer owns each subscription's effective debounce policy (it already keys
//! everything by [`Subscription`]): the watcher-global `default` plus a per-subscription
//! override map the driver [registers](Coalescer::set_policy) at watch commit. An
//! absent entry inherits the default; an [`Off`](Debounce::Off) override rides the
//! ready queue undelayed and uncollapsed (pass-through in admission order — it drains
//! on the same tick it was admitted); a [`Custom`](Debounce::Custom) override runs the
//! collapse table under its own windows, its `max_buffered` additionally capping that
//! subscription's own fresh entries. A policy is registered before any of its
//! subscription's events are admitted and never changes over the subscription's life,
//! so a pass-through subscription can never hold buffered entries to order against.
//!
//! # The collapse table (design §6)
//!
//! Within a settle window, per `(subscription, path)`, the buffered kind and an
//! incoming change collapse to the net lifecycle effect:
//!
//! | buffered → incoming | result |
//! |---|---|
//! | Created → Created  | Created (still a new file) |
//! | Created → Modified | Created (new file, latest content) |
//! | Created → Removed  | **annihilate** (a transient file — emit nothing) |
//! | Modified → Created | Modified (net change at a live path) |
//! | Modified → Modified | Modified (coalesce to one) |
//! | Modified → Removed | Removed |
//! | Removed → Created  | Modified (churn at a path — a re-creation) |
//! | Removed → Modified | Modified (net change at a re-appeared path) |
//! | Removed → Removed  | Removed |
//!
//! The five rows the design names anchor the table; the other four are the same
//! net-lifecycle fold ("did the path end new / changed / gone?"), never a silent
//! drop — the *only* intentional annihilation is the tabled create-then-remove
//! transient. The emitted event carries the **newest** observation's umbrella epoch
//! stamp (epochs are monotone within a burst — a [`Rescan`](EventKind::Rescan) flushes
//! the buffer, so no coalescing pair ever straddles a re-point), so a coalesced pair
//! never emits a dominated stamp.
//!
//! # Invariants that override coalescing (design §6)
//!
//! - **[`Moved`](EventKind::Moved) is atomic** — a rename is never split and never
//!   coalesced with either endpoint's other events: it emits whole and undelayed.
//!   Because it emits immediately (its newest-epoch stamp), it first flushes the
//!   **whole** subscription's buffered entries (all older-epoch, like a `Rescan`), not
//!   just its two endpoint paths — otherwise the immediate `Moved` would jump ahead of
//!   an older buffered entry for the same subscription and the delivered epochs would
//!   go backwards, violating the monotone per-subscription epoch contract (design §8).
//! - **[`Rescan`](EventKind::Rescan) flushes and bypasses** — a coverage-loss signal
//!   immediately flushes *every* buffered entry for its subscription (their content is
//!   now suspect) and emits the `Rescan` undelayed. Its umbrella epoch stamp (assigned
//!   upstream, design §8) is **preserved unchanged** — it must keep dominating the
//!   subscription's prior stream.
//! - **Bounded hold** — an entry's total hold is capped at
//!   [`max_hold`](crate::DebounceConfig::max_hold), so a continuously-touched path
//!   still emits its coalesced state instead of settling forever.
//!
//! # Per-subscription emission order (design §8)
//!
//! Buffered entries live in a [`BTreeMap`] keyed by `(subscription, path)`, but a
//! subscription's due/flushed entries are **not** emitted in that path order — they are
//! emitted in **admission-sequence** order, a monotone `u64` the coalescer stamps on each
//! buffered entry at admit time (and re-takes on every collapse, so a surviving entry's
//! sequence tracks the newest observation it folded in — the same observation whose epoch
//! it carries). Within a subscription that sequence order equals epoch order (the umbrella
//! epoch is monotone per subscription), so a consumer that uses the epoch high-water for
//! idempotency/dominance never sees a subscription's epochs go backwards and silently drop
//! the older change. Two paths whose lexical order opposes their epoch order — `/a` at
//! epoch 2, `/z` at epoch 1 — would emit `/a` (epoch 2) before `/z` (epoch 1) under the
//! BTreeMap path key; by admission sequence they emit `/z` (epoch 1) then `/a` (epoch 2).
//! Across *different* subscriptions the relative order is unconstrained — each has an
//! independent epoch space — so the drains key on `(subscription, sequence)`, leaving each
//! subscription's run contiguous and in epoch order.

use std::{
  collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
  time::Instant,
  vec::Vec,
};

use crate::{
  event::{Event, EventKind},
  options::{Debounce, DebounceConfig},
  subscription::Subscription,
  subsume::Salvage,
};

// Buffered entries INSPECTED by a deadline query (`next_deadline` / `drain_ready`) — the
// quantity the deadline index exists to keep proportional to what is DUE rather than to what
// is buffered. Both queries sit on the owner's hot path: one runs after every raw source
// record, the other before every `select!`, so a full-buffer scan turns a settling burst into
// a per-tick CPU multiplier — debounce amplifying the storm it exists to damp.
//
// Thread-local so libtest's parallel cells cannot perturb one another's count (each test body
// owns its thread).
#[cfg(test)]
thread_local! {
  pub(crate) static DEADLINE_VISITS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// Records that a deadline query inspected `n` buffered entries.
#[cfg(test)]
fn note_deadline_visits(n: usize) {
  DEADLINE_VISITS.with(|visits| visits.set(visits.get() + n));
}

#[cfg(not(test))]
#[inline(always)]
#[allow(clippy::inline_always)]
fn note_deadline_visits(_n: usize) {}

#[cfg(test)]
mod tests;

/// The buffer key: one coalescing slot per caller subscription and key.
///
/// Ordered (`Subscription` and `Vec<C>` are both `Ord`) so the backing [`BTreeMap`]
/// iterates deterministically — the design forbids `HashMap`-iteration nondeterminism
/// in the drain order (§10).
type Key<C> = (Subscription, Vec<C>);

/// One buffered, still-coalescing entry: the current collapsed event, the two deadlines
/// that decide when it emits, and its admission sequence for the drain order.
#[derive(Debug, Clone)]
struct Buffered<C, V> {
  /// When the burst began — the anchor for the [`max_hold`](DebounceConfig::max_hold)
  /// ceiling, preserved across every collapse so a continuously-touched key cannot
  /// reset its own hold cap.
  first_seen: Instant,
  /// When this entry is due: `min(last_seen + quiet_window, first_seen + max_hold)`.
  /// Each new change pushes `last_seen + quiet_window` out (the settle), but the
  /// `first_seen + max_hold` cap bounds the total hold.
  emit_at: Instant,
  /// This entry's monotone **admission sequence**, drawn from the coalescer's admission
  /// counter on first insert and re-taken on every collapse so it always reflects the
  /// *newest* folded observation — the same observation whose epoch this entry carries.
  /// A multi-entry drain orders each subscription's entries by this sequence, not by their
  /// BTreeMap path key, so a subscription's buffered epochs never emit out of order
  /// (design §8; see the [module docs](self#per-subscription-emission-order-design-8)).
  seq: u64,
  /// The current collapsed event, stamped with the newest observation's umbrella epoch.
  event: Event<C, V>,
}

/// The action the [collapse table](self#the-collapse-table-design-6) dictates for a
/// buffered kind meeting an incoming one.
enum Collapse {
  /// Keep the buffered event (its kind already represents the net effect); only its
  /// epoch advances to the newest observation. Rows whose result kind equals the
  /// *buffered* kind: `Created→{Created,Modified}`, `Modified→{Created,Modified}`.
  KeepBuffered,
  /// Replace the buffered event with the incoming one (its kind is the net effect and
  /// it already carries the newest epoch). Rows whose result kind equals the
  /// *incoming* kind: `Modified→Removed`, `Removed→{Modified,Removed}`.
  ReplaceWithIncoming,
  /// Mint a synthetic [`Modified`](EventKind::Modified) — the one row whose result kind
  /// is carried by *neither* event: `Removed→Created` (churn / re-creation).
  BecomeModified,
  /// Drop the entry entirely and emit nothing — the sole intentional annihilation:
  /// `Created→Removed` (a file that lived and died inside the window).
  Annihilate,
}

/// The opt-in settle/debounce coalescer (design §6): a pure state machine collapsing
/// bursts of changes per `(subscription, path)`, driven by an external clock.
///
/// Constructed with the watcher-global default policy; the driver instantiates one only
/// when somebody opted in — eagerly for a global [`DebounceConfig`], lazily on the first
/// [`Debounce::Custom`] override (absent both, events pass through untouched and no
/// coalescer exists). See the [module docs](self) for the per-subscription policy
/// resolution, the collapse table, and the overriding invariants.
#[derive(Debug)]
pub(crate) struct Coalescer<C, V> {
  /// The watcher-global settle policy every subscription inherits absent an override —
  /// [`None`] when the coalescer exists only via per-subscription
  /// [`Custom`](Debounce::Custom) overrides (inheriting nothing = pass-through).
  default: Option<DebounceConfig>,
  /// The per-subscription policy overrides ([`set_policy`](Self::set_policy)):
  /// `Some(config)` = [`Custom`](Debounce::Custom), `None` = [`Off`](Debounce::Off);
  /// an ABSENT subscription inherits [`default`](Self::default). Never iterated (all
  /// point lookups), so `HashMap` nondeterminism cannot leak into any drain order
  /// (design §10).
  policies: HashMap<Subscription, Option<DebounceConfig>>,
  /// Each subscription's count of FRESH buffered entries — the state behind the
  /// per-subscription `max_buffered` cap ([`DebounceConfig::max_buffered`]). Maintained
  /// by every path that inserts into or removes from [`buffer`](Self::buffer)
  /// (an entry is dropped at zero, so absence = 0); an incorrect counter is the bug
  /// class here, so every decrement funnels through the debug-asserted
  /// [`dec_per_sub`](Self::dec_per_sub) or a whole-subscription reconciliation.
  per_sub_len: HashMap<Subscription, usize>,
  /// The coalescing slots, one per `(subscription, key)`. A [`BTreeMap`] so iteration is
  /// deterministic (design §10 forbids `HashMap`-iteration nondeterminism); the *emission*
  /// order within a subscription is by admission sequence (`Buffered::seq`), not this path
  /// key — see the [module docs](self#per-subscription-emission-order-design-8).
  buffer: BTreeMap<Key<C>, Buffered<C, V>>,
  /// The **deadline index**: `(emit_at, key)` for every buffered entry, ordered by deadline.
  /// Kept in exact lockstep with [`buffer`](Self::buffer) — every insert, every collapse that
  /// moves a deadline, and every removal maintains it — so
  /// [`next_deadline`](Self::next_deadline) reads the earliest deadline as the set's first
  /// element and [`drain_ready`](Self::drain_ready) walks only the prefix that is actually due.
  ///
  /// Without it both queries scanned the whole buffer: the driver calls `drain_ready` after
  /// **every** raw source record (even one that fanned out to nothing) and `next_deadline`
  /// before **every** `select!`, so `T` ticks against `M` settling paths cost `Θ(T × M)` entry
  /// inspections before any routing work — and raising `max_buffered` to absorb a bigger
  /// workload turned a memory-headroom knob into a latency multiplier.
  deadlines: BTreeSet<(Instant, Key<C>)>,
  /// Events that must emit *immediately*, in FIFO order: [`Moved`](EventKind::Moved)
  /// whole, a [`Rescan`](EventKind::Rescan), and the buffered entries a `Moved`/`Rescan`
  /// flushed. Each is tagged with the `now` it became ready (its effective `emit_at`),
  /// so [`next_deadline`](Self::next_deadline) reports it and [`drain_ready`](Self::drain_ready)
  /// releases it. FIFO preserves "flushed entries before the signal that flushed them"
  /// and "a `Rescan` jumps the queue ahead of a still-buffering burst".
  ready: VecDeque<(Instant, Event<C, V>)>,
  /// The monotone **admission counter**: bumped once per buffered admission and stamped
  /// onto the entry (`Buffered::seq`), so a multi-entry drain emits each subscription's
  /// entries in admission order — which equals per-subscription epoch order, since the
  /// umbrella epoch is monotone per subscription (design §8) — rather than in BTreeMap
  /// path-key order, under which two paths whose lexical order opposes their epoch order
  /// emit epochs backwards and a high-water consumer silently drops the older change. A
  /// `u64` cannot wrap in practice: at a billion buffered admissions per second it would
  /// take roughly 585 years.
  next_seq: u64,
}

impl<C, V> Coalescer<C, V>
where
  C: Ord + Clone,
  V: Clone,
{
  /// Creates a coalescer with the given watcher-global default policy — [`None`] when
  /// it exists only to serve per-subscription [`Custom`](Debounce::Custom) overrides
  /// (an inheriting subscription then passes through untouched).
  pub(crate) fn new(default: Option<DebounceConfig>) -> Self {
    Self {
      default,
      policies: HashMap::new(),
      per_sub_len: HashMap::new(),
      buffer: BTreeMap::new(),
      deadlines: BTreeSet::new(),
      ready: VecDeque::new(),
      next_seq: 0,
    }
  }

  /// Registers `sub`'s debounce posture (design §6): [`Inherit`](Debounce::Inherit)
  /// removes the override (absence IS the inherit resolution), [`Off`](Debounce::Off)
  /// records raw pass-through, [`Custom`](Debounce::Custom) records the subscription's
  /// own settle policy. Called by the driver at watch commit, adjacent to the filter
  /// registration, before any of the subscription's events are admitted.
  pub(crate) fn set_policy(&mut self, sub: Subscription, policy: Debounce) {
    match policy {
      Debounce::Inherit => {
        self.policies.remove(&sub);
      }
      Debounce::Off => {
        self.policies.insert(sub, None);
      }
      Debounce::Custom(config) => {
        self.policies.insert(sub, Some(config));
      }
    }
  }

  /// Retires `sub` entirely: its buffered and ready entries
  /// ([`drop_subscription`](Self::drop_subscription), which also zeroes its fresh-entry
  /// counter) AND its registered policy. For the paths where the subscription itself
  /// ends — a caller unwatch/orphan release or a terminal root retirement. The
  /// still-live paths (a widen/restore re-point, an overflow park) call
  /// [`drop_subscription`](Self::drop_subscription) instead, keeping the policy: the
  /// subscription keeps delivering and must keep its posture.
  pub(crate) fn forget_subscription<H>(&mut self, sub: Subscription) -> Salvage<C, V, H> {
    let salvage = self.drop_subscription(sub);
    // The policy is a `Copy` configuration this crate owns, not caller state — nothing to place.
    self.policies.remove(&sub);
    salvage
  }

  /// The effective settle policy for `sub`: its registered override — `Some(config)` =
  /// [`Custom`](Debounce::Custom), `None` = [`Off`](Debounce::Off) — or, absent one,
  /// the watcher-global [`default`](Self::default). A resolved `None` means raw
  /// pass-through.
  fn effective_policy(&self, sub: Subscription) -> Option<DebounceConfig> {
    match self.policies.get(&sub) {
      Some(policy) => *policy,
      None => self.default,
    }
  }

  /// The coalescer-wide structural bound on buffered entries: the watcher-global
  /// default's `max_buffered`, or [`DebounceConfig::DEFAULT_MAX_BUFFERED`] when the
  /// coalescer exists only via per-subscription overrides (no global config to read a
  /// cap from). Per-subscription `Custom` caps apply *within* this bound, never widen it.
  fn structural_cap(&self) -> usize {
    self
      .default
      .map_or(DebounceConfig::DEFAULT_MAX_BUFFERED, |config| {
        config.max_buffered()
      })
  }

  /// Whether `sub` has a registered policy override — the driver-level tests' probe for
  /// the forget-vs-drop cleanup split.
  #[cfg(test)]
  pub(crate) fn has_policy(&self, sub: Subscription) -> bool {
    self.policies.contains_key(&sub)
  }

  /// Returns the next monotone admission sequence, advancing the counter. It is stamped
  /// onto each buffered entry (`Buffered::seq`) so a multi-entry drain emits a
  /// subscription's entries in admission order (= per-subscription epoch order). The `u64`
  /// cannot wrap in practice (one tick per buffered admission — see the field docs).
  fn bump_seq(&mut self) -> u64 {
    let seq = self.next_seq;
    self.next_seq += 1;
    seq
  }

  /// Admits one attributed event at logical time `now` under its subscription's
  /// [effective policy](self#per-subscription-policy-design-6): a raw
  /// pass-through subscription's event rides the ready queue undelayed; otherwise a
  /// known lifecycle change ([`Created`](EventKind::Created) / [`Modified`](EventKind::Modified) /
  /// [`Removed`](EventKind::Removed)) buffers and collapses per the
  /// [table](self#the-collapse-table-design-6), and —
  /// for a [`Moved`](EventKind::Moved), a [`Rescan`](EventKind::Rescan), or any unknown/future
  /// non-lifecycle kind (`EventKind` is `#[non_exhaustive]`) — the overriding invariant applies
  /// (flush + emit whole / flush + bypass) regardless of policy, never folding it into the
  /// lifecycle collapse table.
  ///
  /// No event is ever silently dropped: every admitted event is either buffered for
  /// later emission, folded into a buffered entry that will emit, made immediately
  /// ready, or — for exactly the create-then-remove transient — intentionally
  /// annihilated. `now` must be nondecreasing across calls (the driver's monotonic
  /// clock guarantees it).
  ///
  /// Returns `Some(subscription)` when this admission OVERFLOWED a buffered-entry cap
  /// ([`DebounceConfig::max_buffered`]) — the coalescer-wide
  /// [structural bound](Self::structural_cap) or the admitting subscription's own
  /// per-subscription cap: the event was NOT buffered, and the
  /// caller owes that subscription the same dominating parked
  /// [`Rescan`](EventKind::Rescan) it mints for a full event channel
  /// (`park_rescan` — which also purges the subscription's buffered entries, zeroing its
  /// fresh-entry counter), so the dropped event and everything purged are accounted,
  /// never silent. `None` on every ordinary admission.
  #[must_use = "an overflowed subscription is owed a dominating parked Rescan"]
  pub(crate) fn admit(&mut self, ev: Event<C, V>, now: Instant) -> Option<Subscription> {
    if ev.is_rescan() {
      // Rescan: flush every buffered entry for this subscription (their content is now
      // suspect) and emit the Rescan undelayed, its upstream epoch stamp preserved.
      self.flush_subscription(ev.subscription(), now);
      self.ready.push_back((now, ev));
      None
    } else if ev.move_from().is_some() {
      // Moved is atomic: it emits whole and *undelayed* — never split, never coalesced.
      // Because it emits immediately (newest epoch), it must first flush the WHOLE
      // subscription's buffered entries (all older-epoch, since admission is monotone),
      // exactly as a Rescan does — flushing only its two endpoint paths would let the
      // immediate Moved jump ahead of an older buffered entry for another path of the
      // same subscription, so the delivered epochs would go backwards and violate the
      // monotone per-subscription epoch contract (design §6/§8). Detected through
      // `move_from` — the `Moved` kind's in-kind source key — the same second endpoint
      // the router fans out on.
      self.flush_subscription(ev.subscription(), now);
      self.ready.push_back((now, ev));
      None
    } else if matches!(
      ev.kind(),
      EventKind::Created | EventKind::Modified | EventKind::Removed
    ) {
      // A known lifecycle change (Created / Modified / Removed), dispatched on the
      // subscription's effective policy.
      match self.effective_policy(ev.subscription()) {
        // Raw pass-through — an `Off` override, or inheriting a disabled global default
        // (possible once a sibling's `Custom` override instantiated the coalescer): ride
        // the ready queue undelayed and uncollapsed. The FIFO queue drains on the same
        // push tick the event was admitted on, so pass-through adds zero latency and
        // preserves per-subscription admission order (a pass-through subscription never
        // holds buffered entries to order against — its policy is fixed before its first
        // event, see the module docs).
        None => {
          self.ready.push_back((now, ev));
          None
        }
        // A settling policy — the global default inherited, or the subscription's own
        // `Custom` windows: buffer it, collapsing onto any entry already held for its
        // (subscription, path) — or shed the subscription when a fresh entry would
        // overflow a cap.
        Some(config) => self.coalesce(ev, now, config),
      }
    } else {
      // An unknown/future non-lifecycle kind: the umbrella's own `EventKind` is
      // #[non_exhaustive], and the collapse table only knows the three lifecycle kinds (its
      // default arm would relabel or drop one). Do NOT buffer it — flush the subscription's
      // buffer and emit it immediately, exactly like a Moved/Rescan, so it is delivered
      // in-order (older buffered entries flushed ahead of it, the monotone per-subscription
      // epoch preserved) and never collapsed under an allowed version-skew (// no silent loss).
      self.flush_subscription(ev.subscription(), now);
      self.ready.push_back((now, ev));
      None
    }
  }

  /// The earliest instant at which some entry is due — the timer target the driver
  /// sleeps until (design §6). [`None`] when nothing is pending.
  ///
  /// The minimum of the deadline index's first entry and the head of the ready queue
  /// (FIFO, and `now` is nondecreasing, so its front is the earliest-ready). A ready
  /// deadline is in the (recent) past, so the driver's sleep returns at once and it
  /// drains — that is how a `Rescan`/`Moved` bypasses the still-buffering bursts.
  ///
  /// One index probe, not a buffer scan: this runs before every owner `select!`.
  pub(crate) fn next_deadline(&self) -> Option<Instant> {
    self.debug_check_index();
    let buffered = self.deadlines.first().map(|(at, _)| *at);
    note_deadline_visits(usize::from(buffered.is_some()));
    let ready = self.ready.front().map(|(at, _)| *at);
    match (buffered, ready) {
      (Some(a), Some(b)) => Some(a.min(b)),
      (a, b) => a.or(b),
    }
  }

  /// Appends every entry due at `now` to `out` — the ready queue first (immediate
  /// emissions, in FIFO order), then every buffered entry whose deadline has passed,
  /// ordered within each subscription by admission sequence (= epoch order).
  ///
  /// After this the coalescer holds only entries still settling; their deadlines are
  /// reported by [`next_deadline`](Self::next_deadline). `now` must be nondecreasing.
  pub(crate) fn drain_ready(&mut self, now: Instant, out: &mut Vec<Event<C, V>>) {
    // Immediate emissions first: everything the ready queue holds is due (each was
    // enqueued with `emit_at <= its own now <= now`), and FIFO order keeps a Rescan
    // after the entries it flushed and ahead of the buffered bursts.
    while let Some((at, _)) = self.ready.front() {
      if *at <= now {
        let (_, event) = self.ready.pop_front().expect("front just observed");
        out.push(event);
      } else {
        break;
      }
    }
    // Then the buffered entries that have come due — emitted in (subscription, admission-
    // sequence) order, NOT BTreeMap path-key order: within a subscription that is epoch
    // order (admission is monotone), so a high-water consumer never sees a subscription's
    // epochs go backwards. Across subscriptions the order is free (independent epoch
    // spaces); keying on the subscription first keeps each one's run contiguous.
    //
    // The due set comes off the DEADLINE INDEX's ordered prefix, so a tick with nothing due
    // inspects one entry rather than the whole buffer. The boundary probe (the first not-yet-due
    // deadline) is what makes the walk stop; everything after it is strictly later.
    let mut due: Vec<(Subscription, u64, Key<C>)> = Vec::new();
    let mut visited = 0;
    for (at, key) in &self.deadlines {
      visited += 1;
      if *at > now {
        break;
      }
      let seq = self
        .buffer
        .get(key)
        .expect("the index names a buffered entry")
        .seq;
      due.push((key.0, seq, key.clone()));
    }
    note_deadline_visits(visited);
    due.sort_by_key(|(sub, seq, _)| (*sub, *seq));
    for (_, _, key) in due {
      let entry = self.buffer.remove(&key).expect("key just collected");
      self.deadlines.remove(&(entry.emit_at, key.clone()));
      self.dec_per_sub(key.0);
      out.push(entry.event);
    }
    self.debug_check_index();
  }

  /// Appends *every* pending event to `out` regardless of deadline — the ready queue
  /// (FIFO) then every buffered entry, ordered within each subscription by admission
  /// sequence (= epoch order) — leaving the coalescer empty.
  ///
  /// For stream close: once the source is drained no further change can arrive to
  /// settle a buffered burst, so the driver force-emits the coalesced tail rather than
  /// silently dropping it (no-silent-loss).
  ///
  /// The EVENTS leave through `out` — they are delivered, not destroyed — but the two indexes
  /// keyed on them do not: a buffer key and a deadline key are each a deep copy of the caller's own
  /// components, and this runs on the driver's terminal path, ahead of the bounded
  /// [`join_close`](crate::source::Source::join_close) and the acknowledgement carrying its
  /// verdict. So both copies come back in the [`Salvage`] every caller-owned removal in this crate
  /// leaves by, rather than dying inside a `clear()` and an iterator's discarded key.
  pub(crate) fn flush_all<H>(&mut self, out: &mut Vec<Event<C, V>>) -> Salvage<C, V, H> {
    let mut salvage = Salvage::new();
    out.extend(self.ready.drain(..).map(|(_, event)| event));
    // The deadline index's own copies. `clear()` destroys every one of them where it stands, so the
    // set is TAKEN and walked instead — the same `take`-not-`remove` reasoning
    // [`drop_subscription`](Self::drop_subscription) applies per entry, done wholesale.
    for (_, (_, path)) in core::mem::take(&mut self.deadlines) {
      salvage.keep_key(path);
    }
    // The buffered tail in (subscription, admission-sequence) order — the same
    // per-subscription epoch order `drain_ready` keeps, so a teardown flush cannot deliver
    // a subscription's epochs out of order (design §8). Consuming the map by value hands each
    // MAP-OWNED key over with its entry, and it is placed here rather than discarded by the
    // destructuring: the event carries its own copy of that key, so dropping this one silently is
    // exactly the removal shape no `#[must_use]` can see.
    let mut tail: Vec<(Subscription, u64, Event<C, V>)> = Vec::with_capacity(self.buffer.len());
    for ((sub, path), buffered) in core::mem::take(&mut self.buffer) {
      salvage.keep_key(path);
      tail.push((sub, buffered.seq, buffered.event));
    }
    tail.sort_by_key(|(sub, seq, _)| (*sub, *seq));
    out.extend(tail.into_iter().map(|(_, _, event)| event));
    // The whole buffer is gone, so every fresh-entry count reconciles to zero.
    self.per_sub_len.clear();
    salvage
  }

  /// Buffers a lifecycle event under its subscription's effective `config`, collapsing
  /// it onto any entry already held for its `(subscription, key)` per the
  /// [table](self#the-collapse-table-design-6).
  fn coalesce(
    &mut self,
    ev: Event<C, V>,
    now: Instant,
    config: DebounceConfig,
  ) -> Option<Subscription> {
    let key = (ev.subscription(), ev.key().to_vec());
    // The effective settle windows, read up front so recomputing the deadline does not
    // re-borrow `self` while the buffered entry is held mutably.
    let (quiet, max_hold) = (config.quiet_window(), config.max_hold());
    // The admission sequence for THIS observation, taken before the buffer borrow. A fresh
    // entry keeps it; a collapse re-takes it (below) so the surviving entry's drain
    // position reflects its newest folded epoch — the epoch it also adopts here. An
    // annihilating collapse leaves it unused: a harmless gap in the monotone sequence.
    let seq = self.bump_seq();
    let Some(buffered) = self.buffer.get_mut(&key) else {
      // First change to this path in the window: a FRESH entry — the only way the
      // buffer grows, so this is where both memory bounds live. At a cap, shed the
      // subscription instead of growing: the event is dropped UNBUFFERED and the caller
      // parks the dominating Rescan that accounts for it (and purges the subscription's
      // entries, freeing space and zeroing its counter). Collapses below never grow the
      // map and stay exempt from both caps.
      let sub = ev.subscription();
      // The coalescer-WIDE structural bound (the watcher-global cap) is checked first:
      // for an inheriting subscription the per-sub check below reads the same cap over
      // a subset count, so this one always fires first — the per-sub cap only ever
      // narrows a `Custom` subscription within the structural bound.
      if self.buffer.len() >= self.structural_cap() {
        return Some(sub);
      }
      // The PER-SUBSCRIPTION cap: the effective policy's `max_buffered` bounds this
      // subscription's own fresh entries, so one noisy long-window subscription sheds
      // itself instead of starving the shared buffer until the structural bound sheds
      // whoever admits next.
      if self.per_sub_len.get(&sub).copied().unwrap_or(0) >= config.max_buffered() {
        return Some(sub);
      }
      let entry = Buffered {
        first_seen: now,
        emit_at: Self::deadline(now, now, quiet, max_hold),
        seq,
        event: ev,
      };
      self.deadlines.insert((entry.emit_at, key.clone()));
      self.buffer.insert(key, entry);
      *self.per_sub_len.entry(sub).or_insert(0) += 1;
      return None;
    };
    let first_seen = buffered.first_seen;
    // The index entry currently filed under this deadline; every arm below either moves it to
    // the recomputed deadline or removes it, so the index never keeps a stale one.
    let was_due_at = buffered.emit_at;

    match Self::collapse(buffered.event.kind(), ev.kind()) {
      Collapse::KeepBuffered => {
        // The buffered kind already represents the net effect; only advance its stamp
        // to the newest observation (monotone, so this never downgrades the epoch), and
        // take that observation's admission sequence so the entry's drain position tracks
        // its newest epoch.
        buffered.event.set_epoch(ev.epoch());
        buffered.emit_at = Self::deadline(first_seen, now, quiet, max_hold);
        buffered.seq = seq;
      }
      Collapse::ReplaceWithIncoming => {
        // The incoming event is the net effect and already carries the newest epoch;
        // the burst's original first_seen is kept so the hold cap is not reset.
        buffered.event = ev;
        buffered.emit_at = Self::deadline(first_seen, now, quiet, max_hold);
        buffered.seq = seq;
      }
      Collapse::BecomeModified => {
        // Removed-then-Created churn: the net is a Modified carried by neither event —
        // mint one at the shared key/location with the newest epoch, carrying the owning
        // subscription's baked value forward (both collapsed events share it — same
        // subscription — so the coalesced result stays attributable).
        let mut synthetic = Event::synthetic(
          ev.subscription(),
          ev.key().to_vec(),
          ev.location().clone(),
          EventKind::Modified,
          ev.epoch(),
        );
        synthetic.set_value(ev.value().cloned());
        buffered.event = synthetic;
        buffered.emit_at = Self::deadline(first_seen, now, quiet, max_hold);
        buffered.seq = seq;
      }
      Collapse::Annihilate => {
        // Created-then-Removed transient: the file lived and died inside the window;
        // emit nothing. (The sequence taken above is simply left unused.) The removed
        // entry frees its fresh-entry slot.
        self.buffer.remove(&key);
        self.deadlines.remove(&(was_due_at, key.clone()));
        self.dec_per_sub(key.0);
        return None;
      }
    }
    // A surviving collapse pushed the settle out: re-file the index entry under its new
    // deadline. Reading the new value back from the buffer keeps the index and the entry from
    // ever disagreeing about which deadline is filed.
    let now_due_at = self.buffer.get(&key).expect("the entry survived").emit_at;
    if now_due_at != was_due_at {
      self.deadlines.remove(&(was_due_at, key.clone()));
      self.deadlines.insert((now_due_at, key));
    }
    None
  }

  /// The deadline index holds exactly one entry per buffered entry. Drift is the bug class
  /// this representation introduces — an index entry left behind after a removal would resurrect
  /// a deleted key on the next drain, and a missing one would strand a settling entry past its
  /// deadline — so every mutation path is checked from the two hot queries.
  fn debug_check_index(&self) {
    debug_assert_eq!(
      self.deadlines.len(),
      self.buffer.len(),
      "the deadline index drifted from the buffer"
    );
  }

  /// Decrements `sub`'s fresh-entry count by one, dropping the map entry at zero
  /// (absence = 0, so the map stays bounded by subscriptions that actually hold
  /// buffered entries). Every single-entry buffer removal funnels through here; the
  /// whole-subscription paths ([`flush_subscription`](Self::flush_subscription) /
  /// [`drop_subscription`](Self::drop_subscription) / [`flush_all`](Self::flush_all))
  /// reconcile the counter wholesale instead. The debug asserts are the tripwire for
  /// the counter-drift bug class: a decrement with no recorded count means some insert
  /// or removal path missed its accounting.
  fn dec_per_sub(&mut self, sub: Subscription) {
    use std::collections::hash_map::Entry;
    match self.per_sub_len.entry(sub) {
      Entry::Occupied(mut occupied) => {
        let count = occupied.get_mut();
        debug_assert!(*count > 0, "a zero fresh-entry count was left in the map");
        *count = count.saturating_sub(1);
        if *count == 0 {
          occupied.remove();
        }
      }
      Entry::Vacant(_) => {
        debug_assert!(
          false,
          "a buffered entry was removed for a subscription with no fresh-entry count"
        );
      }
    }
  }

  /// The action the collapse table dictates for `buffered` meeting `incoming`.
  ///
  /// Both are lifecycle kinds ([`Created`](EventKind::Created) /
  /// [`Modified`](EventKind::Modified) / [`Removed`](EventKind::Removed)) — a buffered
  /// entry is only ever one of those, and [`admit`](Self::admit) dispatches `Moved`, `Rescan`,
  /// and any unknown/future non-lifecycle kind aside (flush-and-emit) before reaching here, so
  /// `incoming` is a lifecycle kind too. The default arm covers the four rows whose result
  /// equals the buffered kind (`Created`/`Modified` then `Created`/`Modified`); a non-lifecycle
  /// kind cannot reach it, but would fall there harmlessly.
  fn collapse(buffered: &EventKind<C>, incoming: &EventKind<C>) -> Collapse {
    use EventKind::{Created, Modified, Removed};
    match (buffered, incoming) {
      (Created, Removed) => Collapse::Annihilate,
      (Removed, Created) => Collapse::BecomeModified,
      (Modified | Removed, Removed) | (Removed, Modified) => Collapse::ReplaceWithIncoming,
      _ => Collapse::KeepBuffered,
    }
  }

  /// The emit deadline: settle to `now + quiet_window`, but never past the hold cap
  /// `first_seen + max_hold` (design §6, bounded hold). Saturating, so an
  /// astronomically large window can never overflow the clock arithmetic.
  fn deadline(
    first_seen: Instant,
    now: Instant,
    quiet_window: core::time::Duration,
    max_hold: core::time::Duration,
  ) -> Instant {
    let settle = now.checked_add(quiet_window).unwrap_or_else(far_future);
    let cap = first_seen.checked_add(max_hold).unwrap_or_else(far_future);
    settle.min(cap)
  }

  /// Flushes every buffered entry for `sub` into the ready queue at `now`, in
  /// admission-sequence (= epoch) order — a `Rescan`/`Moved`'s "content is now suspect,
  /// emit what we held" (design §6). Ordering by sequence rather than by path key keeps the
  /// flushed entries climbing in epoch as the FIFO ready queue replays them ahead of the
  /// signal that flushed them, so the subscription's delivered epochs never go backwards
  /// (design §8).
  pub(crate) fn flush_subscription(&mut self, sub: Subscription, now: Instant) {
    let mut entries = self.subscription_entries(sub);
    entries.sort_by_key(|(seq, _)| *seq);
    let flushed = entries.len();
    for (_, key) in entries {
      let entry = self.buffer.remove(&key).expect("key just collected");
      self.deadlines.remove(&(entry.emit_at, key));
      self.ready.push_back((now, entry.event));
    }
    // Every buffered entry of `sub` moved to the ready queue: its fresh-entry count
    // reconciles to zero (flushed-ready entries are no longer capped — they are already
    // owed emission).
    let counted = self.per_sub_len.remove(&sub).unwrap_or(0);
    debug_assert!(
      counted == flushed,
      "fresh-entry count drifted from the buffer: counted {counted}, flushed {flushed}"
    );
  }

  /// Drops every buffered and ready entry for `sub` — zeroing its fresh-entry counter,
  /// but **keeping its registered policy** — the parked-overflow-`Rescan` analog
  /// of [`admit`](Self::admit)'s flush-on-`Rescan` (design backpressure doc).
  ///
  /// When the owner sheds `sub` to a **parked** dominating `Rescan` (the event channel was
  /// full, so the `Rescan` could not be delivered inline), that `Rescan` will dominate
  /// everything `sub` still holds here. Emitting those deltas would put a stale-epoch event
  /// *after* the `Rescan` once it is finally delivered, so they are discarded — the
  /// re-enumeration the `Rescan` triggers covers them. Mirrors the fs layer's
  /// `purge_scope_emits`. (In the driver's call path the ready queue has already been
  /// drained, so in practice only the buffer holds suspect deltas; the ready scan keeps the
  /// operation self-contained regardless of call site.)
  ///
  /// The policy survives because every caller of this method sheds a subscription that is
  /// **still live** — an overflow park, a widen/restore re-point — and its later events
  /// must keep their registered posture. A subscription that is genuinely ending takes
  /// [`forget_subscription`](Self::forget_subscription) instead.
  ///
  /// Everything discarded is CALLER-owned — a buffered delivery owns the key it was located at and
  /// the value baked onto it, and both index keys are deep copies of the caller's components — so
  /// none of it is destroyed here. It travels back in a `#[must_use]` [`Salvage`], the
  /// one door every caller-owned removal in this crate leaves by, because every caller of this
  /// method is reachable on the driver's terminal path: destroying a caller `C` or `V` here would
  /// put its destructor in front of the teardown's bounded quiescence wait and the acknowledgement
  /// carrying its verdict.
  pub(crate) fn drop_subscription<H>(&mut self, sub: Subscription) -> Salvage<C, V, H> {
    let mut salvage = Salvage::new();
    let entries = self.subscription_entries(sub);
    let dropped = entries.len();
    for (_, key) in entries {
      // `remove_entry` rather than `remove`: a map removal hands back its VALUE and destroys the
      // key it was filed under, and this map's key owns a deep copy of the caller's components. It
      // is the one shape neither `#[must_use]` nor a private-map wrapper can catch — the removal
      // does return something, and the site does use it, while the key dies unmentioned inside the
      // call. THREE copies exist here and each leaves by the same door: the map's own, the deadline
      // index's, and the scan's.
      let Some((owned, entry)) = self.buffer.remove_entry(&key) else {
        // Nothing buffered under this key, so only the scan's own copy is in hand.
        salvage.keep_key(key.1);
        continue;
      };
      salvage.keep_key(owned.1);
      salvage.keep_event(entry.event);
      // `take` rather than `remove`, for the same reason one line up: the deadline index owns a
      // copy of the key, and `remove` would destroy it where it stands. The query tuple owns the
      // scan's, which outlives the lookup and is placed after it.
      let query = (entry.emit_at, key);
      if let Some(indexed) = self.deadlines.take(&query) {
        salvage.keep_key(indexed.1.1);
      }
      salvage.keep_key(query.1.1);
    }
    // Every buffered entry of `sub` is gone: its fresh-entry count reconciles to zero —
    // the counter zeroing behind the shed path's "purge frees the cap" guarantee.
    let counted = self.per_sub_len.remove(&sub).unwrap_or(0);
    debug_assert!(
      counted == dropped,
      "fresh-entry count drifted from the buffer: counted {counted}, dropped {dropped}"
    );
    let mut kept = VecDeque::with_capacity(self.ready.len());
    for (at, event) in std::mem::take(&mut self.ready) {
      if event.subscription() == sub {
        salvage.keep_event(event);
      } else {
        kept.push_back((at, event));
      }
    }
    self.ready = kept;
    salvage
  }

  /// The buffered `(admission-sequence, key)` pairs belonging to `sub`, in BTreeMap key
  /// order — the shared prefix scan behind both
  /// [`flush_subscription`](Self::flush_subscription) (which re-sorts by sequence to
  /// preserve epoch order) and [`drop_subscription`](Self::drop_subscription) (which
  /// ignores order, only removing). `(sub, Vec::new())` is the least key in `sub`'s range,
  /// and the take-while stops at the first key of the next subscription.
  fn subscription_entries(&self, sub: Subscription) -> Vec<(u64, Key<C>)> {
    self
      .buffer
      .range((sub, Vec::new())..)
      .take_while(|((s, _), _)| *s == sub)
      .map(|(k, b)| (b.seq, k.clone()))
      .collect()
  }
}

/// A far-future instant used only as the saturating ceiling when
/// `now + window` would overflow the platform clock — unreachable in practice
/// (a `Duration` that large is a configuration mistake, not a wish).
fn far_future() -> Instant {
  // `Instant` has no `MAX`; the largest reachable value is "now plus a very long
  // time". A century is finite on every supported platform's clock and dwarfs any
  // sane settle/hold window, so a deadline pinned here effectively never fires.
  Instant::now() + std::time::Duration::from_secs(100 * 365 * 24 * 60 * 60)
}
