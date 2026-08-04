//! The umbrella's per-subscription monotone-epoch ledger — the one piece of genuine
//! ordering logic this crate owns (design §8).
//!
//! # Why the raw fs epoch is not enough
//!
//! `tributary-fs` stamps every event with an [`Epoch`] that is **per-`ScopeId` and
//! restarts at [`Epoch::START`] on every new kernel arm**. A single caller
//! [`Subscription`] is delivered from *different* fs roots over its lifetime: a widen
//! (design §4) re-points it onto a freshly-armed wider root whose epoch sequence
//! restarts at 0. So the raw fs epoch is **not** a valid dominance order across a
//! re-point — a synthetic widen-`Rescan` minted above the pre-widening high-water
//! would dominate the new root's genuine post-widen events (which restart at 0), and
//! a conforming consumer would drop them. Silent loss.
//!
//! # The rebasing model
//!
//! The ledger owns, per [`Subscription`], an `epoch_base` (starting [`Epoch::START`])
//! and a `high_water` (the greatest stamp delivered). Every delivered event is
//! stamped in the subscription's **own** monotone space, never the raw fs epoch:
//!
//! - A delivered event from the subscription's current root with raw fs epoch `e` is
//!   stamped `epoch_base + e`, **clamped up to the subscription's high-water**
//!   ([`stamp`](EpochLedger::stamp)). The raw fs epoch is a per-scope reconciliation
//!   *generation* — constant across ordinary events, advanced only on a `Rescan`/overflow
//!   — so `e` does **not** climb per event; the high-water clamp (not any monotonicity of
//!   `e`) is what keeps a delivery from sorting below a dominating `Rescan` that already
//!   advanced high-water (an overflow shed).
//! - On a widen re-point ([`repoint`](EpochLedger::repoint)): let `hw` be the
//!   subscription's current high-water; the synthetic `Rescan` is emitted at
//!   `hw.next()` and `epoch_base` is set to `hw.next()` for the new root. The new
//!   root's events (raw fs epoch 0, 1, …) then stamp `hw.next() + 0, +1, …` — they
//!   **tie-or-exceed** the `Rescan` (not dominated), while the entire pre-widening
//!   stream (`≤ hw`) is dominated by it. Each subscription rebases independently from
//!   its own high-water.
//!
//! [`stamp_and_fan_out`](EpochLedger::stamp_and_fan_out) ties this to the pure
//! [`fan_out`](crate::route::fan_out) router: it fans one raw event out to its
//! covering subscribers (unchanged) and stamps each delivery in that subscriber's
//! space. It is generic over how a delivery is built, so the routing + rebasing
//! decision is testable without constructing the fs event type (whose constructor is
//! private to `tributary-fs`).

use std::collections::HashMap;

use tributary_proto::Epoch;

use crate::{
  route::{RoutableEvent, fan_out},
  subscription::Subscription,
};

#[cfg(test)]
mod tests;

/// The umbrella's per-subscription monotone-epoch state (design §8): the `epoch_base`
/// and `high_water` every delivered event is stamped against, rebased on each widen.
///
/// Pure — no I/O, no clock, no runtime. The driver holds one of these and drives it
/// from `next()` (via [`stamp_and_fan_out`](Self::stamp_and_fan_out)) and from the
/// widen re-point (via [`repoint`](Self::repoint)).
#[derive(Debug, Default)]
pub(crate) struct EpochLedger {
  /// Per-subscription `epoch_base` (design §8): the umbrella-relative floor its
  /// current root's raw fs epochs are added to. Starts [`Epoch::START`] (the
  /// absent-entry default) and is bumped to `hw.next()` on every widen re-point.
  base: HashMap<Subscription, Epoch>,
  /// Per-subscription high-water — the greatest stamp delivered so far, so a
  /// synthetic widen `Rescan` (design §8) can be minted strictly above it.
  high_water: HashMap<Subscription, Epoch>,
}

impl EpochLedger {
  /// Creates an empty ledger (every subscription starts at [`Epoch::START`]).
  pub(crate) fn new() -> Self {
    Self::default()
  }

  /// The umbrella-relative stamp for `sub`'s next delivery from its **current** root
  /// with raw fs epoch `raw`: `epoch_base + raw`, **clamped up to `sub`'s current
  /// high-water** so a delivery can never sort below a dominating `Rescan` that already
  /// advanced high-water (design §8). Advances `sub`'s high-water to cover the stamp and
  /// returns it.
  ///
  /// The clamp is load-bearing because the raw fs epoch is a **per-scope reconciliation
  /// generation, not a per-event counter**: `tributary-fs` stamps every ordinary change
  /// with the scope's *current* generation and only advances it on a `Rescan`/overflow
  /// (see `tributary_proto`'s monitor), so successive ordinary events routinely carry the
  /// **same** `raw`. After an overflow [`shed_rescan`](Self::shed_rescan) mints a
  /// dominating `Rescan` at `high_water.next()`, a later same-generation event would
  /// otherwise stamp its old `epoch_base + raw` — *below* that `Rescan` — and a
  /// dominance-applying consumer would silently drop it. Clamping to `high_water` lifts it
  /// to tie the shed `Rescan` (a tie is not dominated), closing the loss. When `raw` does
  /// climb — a fresh generation, or the post-[`repoint`](Self::repoint) new root counting
  /// up from 0 — the clamp is a no-op: `epoch_base + raw` already meets or exceeds
  /// high-water.
  ///
  /// The `u64` add is saturating; the ceiling is unreachable (it would take ~1.8·10¹⁹
  /// events on one subscription's current root to reach it).
  pub(crate) fn stamp(&mut self, sub: Subscription, raw: Epoch) -> Epoch {
    let base = self.base.get(&sub).copied().unwrap_or(Epoch::START);
    let natural = base.as_u64().saturating_add(raw.as_u64());
    let hw = self.high_water.get(&sub).copied().unwrap_or(Epoch::START);
    let stamp = Epoch::new(natural.max(hw.as_u64()));
    self.bump(sub, stamp);
    stamp
  }

  /// Like [`stamp`](Self::stamp) but for a **source-emitted `Rescan`**, which must
  /// *strictly* dominate every prior delivery (it is the no-silent-loss coverage-loss
  /// signal): returns `max(epoch_base + raw, high_water.next())` — one past the current
  /// high-water even when an ordinary post-shed delivery already reached it — and advances
  /// high-water to it.
  ///
  /// The distinction from [`stamp`](Self::stamp) is load-bearing after the high-water clamp: an
  /// ordinary post-shed same-generation event is clamped *up to* `high_water` (a tie with
  /// the shed `Rescan`, which is not dominated). A source `Rescan` stamped by the ordinary
  /// clamp would then only *tie* that already-delivered event rather than dominate it, so a
  /// high-water consumer could ignore the lower layer's coverage-loss signal. Minting at
  /// `high_water.next()` restores strict dominance — the same guarantee the umbrella's own
  /// synthetic Rescans already get from [`repoint`](Self::repoint) / [`shed_rescan`](Self::shed_rescan).
  pub(crate) fn stamp_rescan(&mut self, sub: Subscription, raw: Epoch) -> Epoch {
    let base = self.base.get(&sub).copied().unwrap_or(Epoch::START);
    let natural = base.as_u64().saturating_add(raw.as_u64());
    let hw = self.high_water.get(&sub).copied().unwrap_or(Epoch::START);
    let stamp = Epoch::new(natural.max(hw.next().as_u64()));
    self.bump(sub, stamp);
    stamp
  }

  /// Rebases `sub` onto a widened root (design §8) and returns the stamp for its
  /// synthetic dominating `Rescan`.
  ///
  /// The `Rescan` is emitted at `sub`'s current-high-water `.next()`, and `sub`'s
  /// `epoch_base` is set to that same value for its new root. So the new root's
  /// events (raw fs epoch 0, 1, …) will [`stamp`](Self::stamp) to `hw.next() + 0,
  /// +1, …` — they tie-or-exceed the `Rescan` (not dominated), while the whole
  /// pre-widening stream (`≤ hw`) is dominated by it. Advances `sub`'s high-water to
  /// cover the `Rescan` and returns its stamp.
  pub(crate) fn repoint(&mut self, sub: Subscription) -> Epoch {
    let hw = self.high_water.get(&sub).copied().unwrap_or(Epoch::START);
    let rescan = hw.next();
    self.base.insert(sub, rescan);
    self.bump(sub, rescan);
    rescan
  }

  /// Mints a strictly-dominating [`Rescan`](crate::EventKind::Rescan) epoch for
  /// `sub` **without rebasing its root** — the overflow shed (design backpressure doc).
  ///
  /// Returns `sub`'s current-high-water `.next()` and advances high-water to it, but —
  /// unlike [`repoint`](Self::repoint) — **leaves `epoch_base` unchanged**. A shed stays
  /// on the **same live root** (there was no re-arm), so its `epoch_base` still names that
  /// root's floor; [`repoint`](Self::repoint) rebases only because a widen re-arms onto a
  /// fresh root whose raw fs epochs restart at 0.
  ///
  /// Post-shed dominance is upheld by [`stamp`](Self::stamp)'s high-water clamp — **not**
  /// by any assumption that raw fs epochs climb. Because the raw epoch is a per-scope
  /// reconciliation *generation* (constant across ordinary events — see
  /// [`stamp`](Self::stamp)), a later same-generation delivery would stamp its old
  /// `epoch_base + raw` *below* this `Rescan`; the clamp lifts it to tie the `Rescan`
  /// instead, so it is never dominated. Leaving `epoch_base` unchanged (rather than
  /// inflating it) keeps the base meaningful for a subsequent genuine generation bump,
  /// whose `epoch_base + raw'` — clamped — still ties-or-exceeds this shed floor.
  ///
  /// The pre-shed stream (all `≤ hw`) is strictly dominated by the returned `Rescan`, and
  /// repeated sheds are idempotent (monotone `high_water.next()`; N sheds collapse to one
  /// dominating `Rescan` at the driver's per-subscription dirty-set).
  pub(crate) fn shed_rescan(&mut self, sub: Subscription) -> Epoch {
    let hw = self.high_water.get(&sub).copied().unwrap_or(Epoch::START);
    let rescan = hw.next();
    self.bump(sub, rescan);
    rescan
  }

  /// Fans one raw event out to its covering, filter-admitting subscribers (design
  /// §5/§7) and stamps each delivery in that subscriber's own monotone epoch space
  /// (design §8).
  ///
  /// Coverage and filter admission are decided by the unchanged pure
  /// [`fan_out`](crate::route::fan_out): `event` reaches exactly the subscribers in
  /// `subscribers` whose key (resolved by `canonical_of`) covers it **and** whose
  /// filter (`admits`) admits the minted delivery, plus — for a `Rescan` — every
  /// subscriber whose subtree *intersects* the rescan's, bypassing content admission.
  /// Fan-out rebases each delivery's location into its subscriber's own coordinate off
  /// the **event's own** captured root depth, so the anchor never has to be threaded
  /// through here. `raw` is the event's
  /// raw fs epoch; each admitted subscriber's delivery is stamped `epoch_base + raw` via
  /// [`stamp`](Self::stamp), advancing that subscriber's high-water. Stamping runs
  /// *after* admission, so a filtered-out delivery never perturbs a subscription's
  /// epoch space.
  ///
  /// The closures keep this shared between production and the pure test without
  /// touching the [`RoutableEvent`] seam: `admits` is the fan-out filter gate,
  /// `sub_of` recovers the [`Subscription`] a [`fan_out`](crate::route::fan_out)
  /// delivery belongs to, and `stamp_into` binds the computed stamp onto that
  /// delivery. Production's `Delivered` is [`crate::Event`] (`admits` consults the
  /// subscription's [`Filter`](crate::Filter), `sub_of` = its `subscription()`,
  /// `stamp_into` sets its epoch); the test's is the raw [`Subscription`] (`admits`
  /// applies a fake predicate, `stamp_into` pairs it with the stamp), so routing +
  /// filtering + rebasing is exercised without the private fs event constructor.
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn stamp_and_fan_out<'a, C, E, D>(
    &mut self,
    event: &E,
    raw: Epoch,
    subscribers: &[Subscription],
    canonical_of: impl Fn(Subscription) -> Option<&'a [C]>,
    admits: impl Fn(Subscription, &E::Delivered) -> bool,
    sub_of: impl Fn(&E::Delivered) -> Subscription,
    stamp_into: impl Fn(E::Delivered, Epoch) -> D,
  ) -> Vec<D>
  where
    C: PartialEq + 'a,
    E: RoutableEvent<C>,
  {
    let is_rescan = event.is_rescan();
    fan_out(event, subscribers, canonical_of, admits)
      .into_iter()
      .map(|delivered| {
        let sub = sub_of(&delivered);
        // A source-emitted `Rescan` must STRICTLY dominate every prior delivery for the
        // subscription ([`stamp_rescan`] = `high_water.next()`); an ordinary delivery takes
        // the high-water clamp ([`stamp`]). Without the split a source `Rescan` at the
        // same generation as a post-shed event would only tie it, losing the coverage-loss
        // signal.
        let stamp = if is_rescan {
          self.stamp_rescan(sub, raw)
        } else {
          self.stamp(sub, raw)
        };
        stamp_into(delivered, stamp)
      })
      .collect()
  }

  /// Forgets all per-subscription epoch state for `sub` — its `epoch_base` and
  /// `high_water` — reclaiming both map slots.
  ///
  /// The driver calls this on **every** successful unwatch (both a plain drop and the
  /// last-subscriber root-emptied case), so a `watch → stamp/repoint → unwatch` churn
  /// cannot grow the ledger without bound. Subscription ids are minted monotonically
  /// and never reused (the subsumer's counter), so a re-added subscription starts
  /// fresh at [`Epoch::START`] via the absent-entry default — there is no stale state
  /// to alias.
  pub(crate) fn remove(&mut self, sub: Subscription) {
    self.base.remove(&sub);
    self.high_water.remove(&sub);
  }

  /// Advances `sub`'s high-water to cover `stamp` (a stamp is always ≥ the current
  /// high-water within a root and a `Rescan` is minted strictly above it, so this is
  /// monotone; `max` guards it regardless).
  fn bump(&mut self, sub: Subscription, stamp: Epoch) {
    self
      .high_water
      .entry(sub)
      .and_modify(|current| *current = (*current).max(stamp))
      .or_insert(stamp);
  }

  /// The number of subscriptions still holding `(base, high_water)` state — the leak
  /// [`remove`](Self::remove) must keep bounded across a watch/unwatch churn. Both maps
  /// stay in lockstep (every stamp/repoint touches both, every `remove` clears both),
  /// asserted by the driver's churn test.
  #[cfg(all(test, feature = "tokio"))]
  pub(crate) fn tracked_len(&self) -> (usize, usize) {
    (self.base.len(), self.high_water.len())
  }
}
