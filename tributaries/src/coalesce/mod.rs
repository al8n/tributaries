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

use std::{
  collections::{BTreeMap, VecDeque},
  time::Instant,
  vec::Vec,
};

use tributary_fs::EventKind;

use crate::{event::Event, options::DebounceConfig, subscription::Subscription};

#[cfg(test)]
mod tests;

/// The buffer key: one coalescing slot per caller subscription and key.
///
/// Ordered (`Subscription` and `Vec<C>` are both `Ord`) so the backing [`BTreeMap`]
/// iterates deterministically — the design forbids `HashMap`-iteration nondeterminism
/// in the drain order (§10).
type Key<C> = (Subscription, Vec<C>);

/// One buffered, still-coalescing entry: the current collapsed event plus the two
/// deadlines that decide when it emits.
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
/// Constructed with a [`DebounceConfig`]; the driver instantiates one only when the
/// caller opted in (absent a config, events pass through untouched and no coalescer
/// exists). See the [module docs](self) for the collapse table and the overriding
/// invariants.
#[derive(Debug)]
pub(crate) struct Coalescer<C, V> {
  cfg: DebounceConfig,
  /// The coalescing slots, one per `(subscription, key)`. A [`BTreeMap`] for a
  /// deterministic drain order.
  buffer: BTreeMap<Key<C>, Buffered<C, V>>,
  /// Events that must emit *immediately*, in FIFO order: [`Moved`](EventKind::Moved)
  /// whole, a [`Rescan`](EventKind::Rescan), and the buffered entries a `Moved`/`Rescan`
  /// flushed. Each is tagged with the `now` it became ready (its effective `emit_at`),
  /// so [`next_deadline`](Self::next_deadline) reports it and [`drain_ready`](Self::drain_ready)
  /// releases it. FIFO preserves "flushed entries before the signal that flushed them"
  /// and "a `Rescan` jumps the queue ahead of a still-buffering burst".
  ready: VecDeque<(Instant, Event<C, V>)>,
}

impl<C, V> Coalescer<C, V>
where
  C: Ord + Clone,
{
  /// Creates a coalescer with the given settle policy.
  pub(crate) fn new(cfg: DebounceConfig) -> Self {
    Self {
      cfg,
      buffer: BTreeMap::new(),
      ready: VecDeque::new(),
    }
  }

  /// Admits one attributed event at logical time `now`: buffers and collapses it per
  /// the [table](self#the-collapse-table-design-6), or — for a
  /// [`Moved`](EventKind::Moved) or [`Rescan`](EventKind::Rescan) — applies the
  /// overriding invariant (flush + emit whole / flush + bypass).
  ///
  /// No event is ever silently dropped: every admitted event is either buffered for
  /// later emission, folded into a buffered entry that will emit, made immediately
  /// ready, or — for exactly the create-then-remove transient — intentionally
  /// annihilated. `now` must be nondecreasing across calls (the driver's monotonic
  /// clock guarantees it).
  pub(crate) fn admit(&mut self, ev: Event<C, V>, now: Instant) {
    if ev.is_rescan() {
      // Rescan: flush every buffered entry for this subscription (their content is now
      // suspect) and emit the Rescan undelayed, its upstream epoch stamp preserved.
      self.flush_subscription(ev.subscription(), now);
      self.ready.push_back((now, ev));
    } else if ev.move_from().is_some() {
      // Moved is atomic: it emits whole and *undelayed* — never split, never coalesced.
      // Because it emits immediately (newest epoch), it must first flush the WHOLE
      // subscription's buffered entries (all older-epoch, since admission is monotone),
      // exactly as a Rescan does — flushing only its two endpoint paths would let the
      // immediate Moved jump ahead of an older buffered entry for another path of the
      // same subscription, so the delivered epochs would go backwards and violate the
      // monotone per-subscription epoch contract (design §6/§8). Detected through the
      // wrapper-level `move_from` (uniform for fs-backed and synthetic moves), not an
      // `EventKind` match, so it needs no fs `MovedEvent` to recognize.
      self.flush_subscription(ev.subscription(), now);
      self.ready.push_back((now, ev));
    } else {
      // A lifecycle change (Created / Modified / Removed): buffer it, collapsing onto
      // any entry already held for its (subscription, path).
      self.coalesce(ev, now);
    }
  }

  /// The earliest instant at which some entry is due — the timer target the driver
  /// sleeps until (design §6). [`None`] when nothing is pending.
  ///
  /// The minimum of every buffered entry's `emit_at` and the head of the ready queue
  /// (FIFO, and `now` is nondecreasing, so its front is the earliest-ready). A ready
  /// deadline is in the (recent) past, so the driver's sleep returns at once and it
  /// drains — that is how a `Rescan`/`Moved` bypasses the still-buffering bursts.
  pub(crate) fn next_deadline(&self) -> Option<Instant> {
    let buffered = self.buffer.values().map(|b| b.emit_at).min();
    let ready = self.ready.front().map(|(at, _)| *at);
    match (buffered, ready) {
      (Some(a), Some(b)) => Some(a.min(b)),
      (a, b) => a.or(b),
    }
  }

  /// Appends every entry due at `now` to `out` — the ready queue first (immediate
  /// emissions, in FIFO order), then every buffered entry whose deadline has passed
  /// (in deterministic key order).
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
    // Then the buffered entries that have come due, in key order (deterministic).
    let due: Vec<Key<C>> = self
      .buffer
      .iter()
      .filter(|(_, b)| b.emit_at <= now)
      .map(|(k, _)| k.clone())
      .collect();
    for key in due {
      let entry = self.buffer.remove(&key).expect("key just collected");
      out.push(entry.event);
    }
  }

  /// Appends *every* pending event to `out` regardless of deadline — the ready queue
  /// (FIFO) then every buffered entry (key order) — leaving the coalescer empty.
  ///
  /// For stream close: once the source is drained no further change can arrive to
  /// settle a buffered burst, so the driver force-emits the coalesced tail rather than
  /// silently dropping it (no-silent-loss).
  pub(crate) fn flush_all(&mut self, out: &mut Vec<Event<C, V>>) {
    out.extend(self.ready.drain(..).map(|(_, event)| event));
    out.extend(
      std::mem::take(&mut self.buffer)
        .into_values()
        .map(|b| b.event),
    );
  }

  /// Buffers a lifecycle event, collapsing it onto any entry already held for its
  /// `(subscription, key)` per the [table](self#the-collapse-table-design-6).
  fn coalesce(&mut self, ev: Event<C, V>, now: Instant) {
    let key = (ev.subscription(), ev.key().to_vec());
    // Read the settle windows up front so recomputing the deadline does not re-borrow
    // `self` while the buffered entry is held mutably.
    let (quiet, max_hold) = (self.cfg.quiet_window(), self.cfg.max_hold());
    let Some(buffered) = self.buffer.get_mut(&key) else {
      // First change to this path in the window: open a fresh entry.
      let entry = Buffered {
        first_seen: now,
        emit_at: Self::deadline(now, now, quiet, max_hold),
        event: ev,
      };
      self.buffer.insert(key, entry);
      return;
    };
    let first_seen = buffered.first_seen;

    match Self::collapse(buffered.event.kind(), ev.kind()) {
      Collapse::KeepBuffered => {
        // The buffered kind already represents the net effect; only advance its stamp
        // to the newest observation (monotone, so this never downgrades the epoch).
        buffered.event.set_epoch(ev.epoch());
        buffered.emit_at = Self::deadline(first_seen, now, quiet, max_hold);
      }
      Collapse::ReplaceWithIncoming => {
        // The incoming event is the net effect and already carries the newest epoch;
        // the burst's original first_seen is kept so the hold cap is not reset.
        buffered.event = ev;
        buffered.emit_at = Self::deadline(first_seen, now, quiet, max_hold);
      }
      Collapse::BecomeModified => {
        // Removed-then-Created churn: the net is a Modified carried by neither event —
        // mint one at the shared key/location with the newest epoch.
        buffered.event = Event::synthetic(
          ev.subscription(),
          ev.key().to_vec(),
          ev.location().clone(),
          EventKind::Modified,
          ev.epoch(),
        );
        buffered.emit_at = Self::deadline(first_seen, now, quiet, max_hold);
      }
      Collapse::Annihilate => {
        // Created-then-Removed transient: the file lived and died inside the window;
        // emit nothing.
        self.buffer.remove(&key);
      }
    }
  }

  /// The action the collapse table dictates for `buffered` meeting `incoming`.
  ///
  /// Both are lifecycle kinds ([`Created`](EventKind::Created) /
  /// [`Modified`](EventKind::Modified) / [`Removed`](EventKind::Removed)) — a buffered
  /// entry is only ever one of those, and [`admit`](Self::admit) dispatches
  /// `Moved`/`Rescan` aside before reaching here. The default arm covers the four rows
  /// whose result equals the buffered kind (`Created`/`Modified` then
  /// `Created`/`Modified`); any non-lifecycle kind, which cannot occur, safely falls
  /// there too.
  fn collapse(buffered: &EventKind, incoming: &EventKind) -> Collapse {
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
  /// deterministic key order — a `Rescan`'s "content is now suspect, emit what we held"
  /// (design §6).
  fn flush_subscription(&mut self, sub: Subscription, now: Instant) {
    for key in self.subscription_keys(sub) {
      let entry = self.buffer.remove(&key).expect("key just collected");
      self.ready.push_back((now, entry.event));
    }
  }

  /// Drops every buffered and ready entry for `sub` — the parked-overflow-`Rescan` analog
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
  pub(crate) fn drop_subscription(&mut self, sub: Subscription) {
    for key in self.subscription_keys(sub) {
      self.buffer.remove(&key);
    }
    self.ready.retain(|(_, event)| event.subscription() != sub);
  }

  /// The buffered keys belonging to `sub`, in deterministic key order — the shared prefix
  /// scan behind both [`flush_subscription`](Self::flush_subscription) and
  /// [`drop_subscription`](Self::drop_subscription). `(sub, Vec::new())` is the least key
  /// in `sub`'s range, and the take-while stops at the first key of the next subscription.
  fn subscription_keys(&self, sub: Subscription) -> Vec<Key<C>> {
    self
      .buffer
      .range((sub, Vec::new())..)
      .take_while(|((s, _), _)| *s == sub)
      .map(|(k, _)| k.clone())
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
