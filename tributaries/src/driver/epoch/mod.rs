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
//!   stamped `epoch_base + e` ([`stamp`](EpochLedger::stamp)). Within one root `e` is
//!   monotone, so the stamp is monotone.
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

use std::{collections::HashMap, path::Path};

use tributary_fs::Epoch;

use crate::{
  route::{RoutableEvent, fan_out},
  subscription::Subscription,
  subsume::RootEntry,
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
  /// with raw fs epoch `raw`: `epoch_base + raw`, in `sub`'s own monotone space
  /// (design §8). Advances `sub`'s high-water to cover the stamp and returns it.
  ///
  /// Within one root `raw` is monotone, so the stamp is monotone. The `u64` add is
  /// saturating; the ceiling is unreachable (it would take ~1.8·10¹⁹ events on one
  /// subscription's current root to reach it).
  pub(crate) fn stamp(&mut self, sub: Subscription, raw: Epoch) -> Epoch {
    let base = self.base.get(&sub).copied().unwrap_or(Epoch::START);
    let stamp = Epoch::new(base.as_u64().saturating_add(raw.as_u64()));
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

  /// Fans one raw event out to its covering subscribers (design §5) and stamps each
  /// delivery in that subscriber's own monotone epoch space (design §8).
  ///
  /// Coverage is decided by the unchanged pure [`fan_out`](crate::route::fan_out):
  /// `event` reaches exactly the subscribers of `entry` whose canonical path
  /// (resolved by `canonical_of`) covers it, plus — for a `Rescan` — *every*
  /// subscriber of the root. `raw` is the event's raw fs epoch; each covered
  /// subscriber's delivery is stamped `epoch_base + raw` via [`stamp`](Self::stamp),
  /// advancing that subscriber's high-water.
  ///
  /// The two closures keep this shared between production and the pure test without
  /// touching the [`RoutableEvent`] seam: `sub_of` recovers the [`Subscription`] a
  /// [`fan_out`](crate::route::fan_out) delivery belongs to, and `stamp_into` binds
  /// the computed stamp onto that delivery. Production's `Delivered` is
  /// [`crate::Event`] (`sub_of` = its `subscription()`, `stamp_into` sets its epoch);
  /// the test's is the raw [`Subscription`] (`stamp_into` pairs it with the stamp),
  /// so routing + rebasing is exercised without the private fs event constructor.
  pub(crate) fn stamp_and_fan_out<'a, E, D>(
    &mut self,
    event: &E,
    raw: Epoch,
    entry: &RootEntry,
    canonical_of: impl Fn(Subscription) -> Option<&'a Path>,
    sub_of: impl Fn(&E::Delivered) -> Subscription,
    stamp_into: impl Fn(E::Delivered, Epoch) -> D,
  ) -> Vec<D>
  where
    E: RoutableEvent,
  {
    fan_out(event, entry, canonical_of)
      .into_iter()
      .map(|delivered| {
        let stamp = self.stamp(sub_of(&delivered), raw);
        stamp_into(delivered, stamp)
      })
      .collect()
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
}
