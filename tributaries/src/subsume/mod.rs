//! The sans-I/O overlap-subsumption engine, generic over the key component `C`, the
//! caller value `V`, and the armed-root handle `H`.
//!
//! This is the control plane of the umbrella crate: a pure state machine that folds
//! possibly-**overlapping** caller subscriptions into the pairwise-disjoint roots the
//! source (`tributary-fs` for 0.1.0) requires. It performs **no** I/O,
//! reads no clock, and knows nothing of any runtime — it is exhaustively
//! property-testable over keys and an abstract handle alone.
//!
//! # Coordinate system
//!
//! Everything operates in one key space: a watched location is a `Vec<C>` of
//! components, and coverage / ancestor / exact are [`iradix`] ops on `&[C]`, so `[a,
//! b]` is an ancestor of `[a, b, c]` but not of `[a, bc]`. The fs source keys on a
//! path's `OsString` components (`C = OsString`); a caller with a richer key
//! instantiates `C` at its own component type.
//!
//! # Immutable watch-set + the concurrent read plane
//!
//! The authoritative watch-set is an **immutable** [`sync::Radix`](iradix::sync::Radix)
//! keyed by `Vec<C>` and valued by [`RootRecord`]. Each control mutation opens a
//! [`Txn`](iradix::sync::Radix::txn), applies its edits, [`commit`](iradix::sync::Txn::commit)s
//! into the next tree, and **publishes** that tree into a shared `arc_swap` slot so
//! every [`WatchView`](crate::WatchView) reader sees the last committed watch-set
//! wait-free (design §5). The publish is unconditional and follows the commit, so a
//! watch-set change is visible immediately after it commits and never before.
//!
//! # Plan / commit split
//!
//! A `watch` cannot mutate committed state up front: the real root handle does not
//! exist until *after* the source is armed, and if that arming fails no state may have
//! changed. So [`Subsumer::plan_watch`] is a pure read returning a [`WatchOutcome`]
//! describing the operations the driver must perform, and [`Subsumer::commit_watch`]
//! applies the state transition once the real handle is known. `unwatch` needs no such
//! split — the handle already exists — so [`Subsumer::plan_unwatch`] mutates
//! immediately and reports whether the root emptied.

use core::{hash::Hash, num::NonZeroU64};
use std::{collections::HashMap, sync::Arc, vec::Vec};

use arc_swap::ArcSwap;
use iradix::sync::Radix;
use tributary_proto::ScopeId;

use crate::{
  interest::Interest,
  subscription::{InstanceId, Subscription},
  view::WatchView,
};

#[cfg(test)]
mod tests;

/// The last committed watch-set, published as **one** immutable snapshot so a
/// [`WatchView`] reader never sees the root plane and the coverage plane torn apart.
///
/// Two immutable [`sync::Radix`](Radix)es, kept in lockstep and swapped together:
///
/// - `roots` — `root key -> record`: the armed-root plane. Answers root membership
///   ([`WatchView::contains`]) and the live-root count ([`WatchView::len`]).
/// - `covers` — `subscription key -> `[`CoverEntry`]: the **live-subscription coverage +
///   attribution** plane, keyed on every live subscription's own key (a [`CoverEntry`] folds
///   every subscription sharing one key, each with its own caller value). Answers
///   [`WatchView::is_watched`] (membership) **and** the **attribution value**
///   ([`WatchView::covering`] / [`resolve`](WatchView::resolve) read the value of the longest
///   live subscription covering the key here — never the armed root's).
///
/// Why the value plane lives on `covers`, not `roots`: an armed root can outlive the
/// subscription whose key equalled its own — a `Widen` then `unwatch` of the widening watch, or
/// a `Covered` watch then `unwatch` of the root's own watch — leaving the armed root **broader
/// than any live subscription** (the narrower covered/re-pointed subscriptions remain). Deriving
/// `is_watched` from `roots` would over-report (call a key watched that `fan_out` delivers to no
/// subscriber), and reading the **attribution value** from `roots` would return the *departed*
/// root-owner's value for a key a narrower surviving subscription now owns. Both are answered
/// from `covers` instead: `is_watched` is true iff some **live subscription's own key** is an
/// ancestor-or-equal of the queried key (exactly the set `fan_out` delivers to), and attribution
/// returns the value of the **longest** such live subscription (design §5). The armed root
/// staying broad is harmless (a re-installed subscription is `Covered` under it, no re-arm —
/// **self-healing**).
///
/// # Over-broad is self-healing; shrink is the budget reclaim (set-cover)
///
/// Because over-broadness is correctness-neutral, the umbrella never *needs* to re-narrow an armed
/// root — but a broad kernel watch still **pins source budget** (inotify watch descriptors under the
/// wide root). So when a drop leaves a root over-broad, [`plan_unwatch`](Subsumer::plan_unwatch)
/// reports the wide handle plus the survivors' **retained cover** (an antichain), and the driver
/// forwards it to [`Source::set_cover`](crate::Source::set_cover) — a synchronous fire-and-forget request to
/// reclaim the excess coverage **in place**. The golden rationale: **shrink-in-place at the source
/// beats release-and-rearm at the umbrella because the survivors' coverage never moves** — no root is
/// released and re-armed, so there is no gap to close with a `Rescan` and no re-crawl. Shrink is a
/// pure optimization layered on top of the self-healing invariant, never a correctness dependency.
///
/// Not [`Debug`]: the underlying [`sync::Radix`](Radix) is not, and no reader needs it.
pub(crate) struct Published<C, V, H> {
  /// The armed-root plane: `root key -> record` (membership + live-root count).
  pub(crate) roots: Radix<C, RootRecord<C, H>>,
  /// The live-subscription coverage + attribution plane: `subscription key -> `[`CoverEntry`]
  /// of every live subscription registered at that key (each carrying its caller value).
  /// Present iff some live subscription covers the key — the truthful `is_watched` set — and its
  /// longest covering entry's value is the attribution [`covering`](WatchView::covering) returns.
  pub(crate) covers: Radix<C, CoverEntry<V>>,
}

/// One key's live-subscription coverage-plane entry: every live subscription registered at
/// **exactly** this key, each paired with the caller value it carries, in registration order.
/// The entry is present in [`Published::covers`] iff it holds at least one subscription (the key
/// is removed when its last subscription drops), so its presence answers
/// [`WatchView::is_watched`] and its [`value`](Self::value) answers attribution.
///
/// A single stored value would not do: several subscriptions can share one key with **different**
/// values (`watch("/a", A)` then `watch("/a", B)`), and one departing must restore the surviving
/// one's value — so the whole set is kept and removal is by [`Subscription`], not a bare
/// refcount. [`value`](Self::value) returns the **most-recent** (highest-id) live subscription's
/// value, a deterministic tie-break that under monotonic ids is the last-installed surviving
/// owner.
#[derive(Clone)]
pub(crate) struct CoverEntry<V> {
  /// `(subscription, value)` for every live subscription at this exact key, in registration
  /// order. Never empty while the entry is present (the key is removed on the last drop).
  subs: Vec<(Subscription, V)>,
}

impl<V> CoverEntry<V> {
  /// An empty entry (no covering subscription yet).
  fn new() -> Self {
    Self { subs: Vec::new() }
  }

  /// Records one more live subscription `sub` at this key, carrying `value`.
  fn push(&mut self, sub: Subscription, value: V) {
    self.subs.push((sub, value));
  }

  /// Drops `sub` from this key (a no-op if absent), leaving every other subscription sharing it
  /// — so attribution falls back to a surviving owner rather than to nothing.
  /// Drops every subscription in `departing` in ONE pass — the batch-retirement
  /// primitive: a cohort retire clones this entry once and retains
  /// through it once, instead of clone-per-subscriber.
  fn remove_all(&mut self, departing: &std::collections::HashSet<Subscription>) {
    self.subs.retain(|(sub, _)| !departing.contains(sub));
  }

  fn remove(&mut self, sub: Subscription) {
    self.subs.retain(|(s, _)| *s != sub);
  }

  /// Whether no live subscription remains at this key (the caller then removes the key).
  fn is_empty(&self) -> bool {
    self.subs.is_empty()
  }

  /// The attribution value: the **most-recent** (highest-id) live subscription's value — the
  /// deterministic tie-break when several live subscriptions share this exact key. Never panics:
  /// a present entry always holds at least one subscription.
  pub(crate) fn value(&self) -> &V {
    &self
      .subs
      .iter()
      .max_by_key(|(sub, _)| *sub)
      .expect("a present cover entry holds at least one live subscription")
      .1
  }

  /// This **exact** subscription's own caller value, if `sub` is one of the live subscriptions at
  /// this key. This is the per-event attribution source (design §3), distinct from
  /// [`value`](Self::value) (the longest/most-recent owner the wait-free view query returns): a
  /// delivered event is attributed to the *specific* subscription it was routed to, whose own
  /// value the driver bakes onto it. `None` if `sub` is not (or no longer) at this key.
  pub(crate) fn value_of(&self, sub: Subscription) -> Option<&V> {
    self
      .subs
      .iter()
      .find(|(s, _)| *s == sub)
      .map(|(_, value)| value)
  }
}

/// The shared, wait-free-readable publication of the authoritative watch-set: an
/// `arc_swap` slot holding the last committed immutable [`Published`] snapshot. The
/// [`Subsumer`] publishes into it after every commit; each [`WatchView`] clone reads
/// the same slot.
pub(crate) type Shared<C, V, H> = Arc<ArcSwap<Published<C, V, H>>>;

/// One live root's registry record — the value stored in the subsumption radix.
///
/// It carries the root's `key` (its radix key, recovered when a dead/uncovered root's
/// subscribers must be named a dominating loss `Rescan`), the armed `handle`, and every caller
/// [`Subscription`] this root serves, in registration order.
///
/// It carries **no** caller value and **no** interest. Attribution
/// ([`covering`](crate::WatchView::covering)) reads the owning value from the live-subscription
/// [`covers`](Published::covers) plane, not from the armed root — an armed root can outlive the
/// subscription whose value equalled it (design §5). And every umbrella root is armed
/// [`Interest::all`] (design §4), so the kernel watch never narrows what it collects; each
/// subscription's own interest is a fan-out gate held in its [`SubRecord`].
///
/// It also records the [`retained_cover`](Self::retained_cover) — the source's **actual coverage**
/// for this root (set-cover) — so [`plan_watch`](Subsumer::plan_watch) can tell whether a later
/// `Covered` newcomer falls OUTSIDE that (possibly-narrowed) coverage and so needs an awaited
/// [`Source::grow`](crate::Source::grow) to reclaim real coverage before the watch can commit.
#[derive(Debug, Clone)]
pub(crate) struct RootRecord<C, H> {
  /// The root's key (== its radix key).
  pub(crate) key: Vec<C>,
  /// The armed root handle.
  pub(crate) handle: H,
  /// Every caller subscription this root serves, in registration order.
  pub(crate) subscribers: Vec<Subscription>,
  /// The source's ACTUAL coverage for this root (set-cover): `None` = **full** coverage (a
  /// fresh/widened root never narrowed, or one grown back to its own key — the cancel-equivalent),
  /// `Some(cover)` = narrowed to the prefix-free antichain `cover`. Kept EXACT — it names the source's
  /// true current coverage, not an optimistic projection — because it is updated in lockstep with the
  /// source's applied coverage via [`set_retained_cover`](Subsumer::set_retained_cover): NARROWED on a
  /// [`Source::set_cover`](crate::Source::set_cover) PRUNE issue (fire-and-forget, so recorded
  /// pessimistically at issue — narrow-on-issue), and BROADENED on a
  /// [`Source::grow`](crate::Source::grow) **`Ok`** (awaited and applied before that `Ok`, so
  /// broadening at that instant matches live coverage — broaden-on-`Ok`; a failed grow broadens
  /// nothing, since the watch aborts uncommitted — R1). Read by
  /// [`plan_watch`](Subsumer::plan_watch): a `Covered` newcomer under NONE of a `Some` cover's
  /// prefixes lies in a pruned region the source no longer backs, so its commit regains no real
  /// coverage until an awaited grow lands ([`WatchOutcome::Covered::outside_cover`]).
  pub(crate) retained_cover: Option<Vec<Vec<C>>>,
}

impl<C, H> RootRecord<C, H> {
  /// Whether `key` falls OUTSIDE this root's actual coverage (set-cover) — the
  /// [`outside_cover`](WatchOutcome::Covered::outside_cover) accessor
  /// [`plan_watch`](Subsumer::plan_watch) folds into a `Covered` outcome: `true` iff the root was
  /// **narrowed** ([`retained_cover`](Self::retained_cover) is `Some`) and `key` lies under NONE of
  /// its retained prefixes (the source pruned that region), so a newcomer there needs an awaited
  /// grow. `false` under a full-coverage (`None`) root or for a `key` at-or-under some retained
  /// prefix — the source already backs it.
  fn covered_outside(&self, key: &[C]) -> bool
  where
    C: PartialEq,
  {
    self.retained_cover.as_ref().is_some_and(|cover| {
      !cover
        .iter()
        .any(|prefix| key.starts_with(prefix.as_slice()))
    })
  }
}

/// The plan [`Subsumer::plan_watch`] produces: which operations the driver must
/// perform for one `watch`, before the state transition is committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WatchOutcome<C, H> {
  /// The subtree is already watched by an existing root at or above the key. No new
  /// kernel watch: `commit_watch` just adds `sub` to that root's subscribers.
  Covered {
    /// The existing root handle covering the new subscription.
    fs_root: H,
    /// The new subscription.
    sub: Subscription,
    /// Whether the newcomer's key falls OUTSIDE the covering root's actual coverage (set-cover):
    /// `true` iff the root was **narrowed** ([`retained_cover`](RootRecord::retained_cover) is
    /// `Some`) and the newcomer's key lies under NONE of its retained prefixes — the source pruned
    /// that region, so a `Covered` commit (which arms nothing) would regain no real kernel coverage
    /// on its own. The driver then AWAITS a [`Source::grow`](crate::Source::grow) to a fresh cover
    /// that includes the newcomer BEFORE committing (grow-before-commit, R1): on `Ok` coverage is
    /// live before the watch returns (no bridging `Rescan` needed); on `Err` the watch fails with
    /// nothing committed and the record unbroadened. `false` when the root is at full coverage
    /// (`None`) or the newcomer is already inside the retained cover — the source already backs it.
    outside_cover: bool,
  },
  /// The key is a strict ancestor of one or more existing roots, which it subsumes.
  /// The driver must **release the subsumed roots (`unwatch`) first, then arm** the
  /// wider watch — the lower source rejects a root overlapping a live one, so the
  /// wider root cannot be armed while a subsumed one is live. The brief coverage gap
  /// between the two is closed by the dominating `Rescan` each re-pointed subscriber
  /// receives. `commit_watch` re-points `repointed` (and adds the new `sub`) onto the
  /// wider root.
  Widen {
    /// The key of the new, wider root (equal to the new subscription's own key).
    new_root_key: Vec<C>,
    /// The subscribers of every subsumed root, to re-point onto the wider root, in
    /// deterministic (root key, then registration) order.
    repointed: Vec<Subscription>,
    /// The subsumed root handles the driver must release, in root-key order.
    unwatch: Vec<H>,
    /// The new subscription.
    sub: Subscription,
  },
  /// The key neither is covered by nor covers any existing root. The driver arms a
  /// fresh watch; `commit_watch` records the new root once its handle is known.
  Disjoint {
    /// The key of the fresh root (equal to the subscription's key).
    root_key: Vec<C>,
    /// The new subscription.
    sub: Subscription,
  },
}

/// The result of [`Subsumer::plan_unwatch`].
///
/// Not [`Copy`]: the [`Dropped`](Self::Dropped) shrink cover carries an owned antichain of
/// keys (the set-cover design).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnwatchOutcome<C, H> {
  /// The subscription was removed; its root still serves other subscribers.
  ///
  /// `shrink` reports whether the drop left the source coverage RECLAIMABLE — the wide root broader
  /// than the survivors need — which the source may PRUNE in place (the set-cover design v3, the
  /// shrink-in-place seam). It is `Some((wide_root, retained_cover))` in either of two cases (see
  /// [`detect_shrink`](Subsumer::detect_shrink)): the root was at **full** coverage and the
  /// subscription that pinned it at its own key departed (the original over-broad case), OR the root
  /// was **already narrowed** and this (non-root) departure lets the cover shrink further still — a
  /// survivor under the recorded cover left, so its subtree can now be pruned too (F2). Either way
  /// `retained_cover` is the minimal prefix-free **antichain** of the surviving subscribers' keys —
  /// the narrowest set they all still sit under — so pruning to it drops no live coverage, with no
  /// gap and no re-crawl. `None` when nothing is reclaimable: a survivor still pins the root at its
  /// own key, or the already-narrowed cover is unchanged by this departure.
  ///
  /// Over-broadness is **correctness-neutral and self-healing** (a re-installed key is `Covered`
  /// under the still-armed wide root — design §5), so `shrink` is a pure budget-reclaim optimization
  /// the driver forwards to the source; the source may apply it, defer it, or ignore it.
  Dropped {
    /// `Some((wide_root, retained_cover))` iff the source coverage is reclaimable — the wide root
    /// handle plus the minimal prefix-free antichain of the surviving subscribers' keys under it.
    /// `None` otherwise.
    shrink: Option<(H, Vec<Vec<C>>)>,
  },
  /// The subscription was its root's last: the driver must release the kernel watch
  /// on `fs_root` (the engine has already dropped the root's state).
  RootEmptied {
    /// The now-empty root handle to release.
    fs_root: H,
  },
}

/// One subscription's side-table record: the root it currently rides, its own key,
/// and its own [`Interest`] (the §4 side table; the `Filter` half lives in the
/// driver's swappable map). Because every root is armed [`Interest::all`], a
/// subscription's `interest` is purely a fan-out gate (design §4/§5), not something
/// that ever narrows the kernel watch.
#[derive(Debug, Clone)]
struct SubRecord<C, H> {
  root: H,
  key: Vec<C>,
  interest: Interest,
}

/// A not-yet-committed `watch`'s reservation: its key, its caller value, and its
/// interest, stashed under the freshly-minted subscription id until the paired
/// `commit_watch` / `abort_watch` consumes it.
#[derive(Debug, Clone)]
struct PendingWatch<C, V> {
  key: Vec<C>,
  value: V,
  interest: Interest,
}

/// The sans-I/O overlap-subsumption engine, generic over the key component `C`, the
/// caller value `V`, and the armed-root handle `H`.
///
/// `H` is testable with a trivial handle type (e.g. `u32`); the fs driver instantiates
/// it at the fs binding's `RootHandle`. Maintains the authoritative immutable
/// [`sync::Radix`](Radix) (`key -> record`, the subsumption / ancestor plane), a
/// handle → key reverse index (the O(1) per-root lookup), a side table from each live
/// subscription to the root it rides, and the shared publication slot every
/// [`WatchView`] reads.
pub(crate) struct Subsumer<C, V, H> {
  /// The authoritative watch-set: `key -> record`. The disjointness / ancestor plane.
  index: Radix<C, RootRecord<C, H>>,
  /// The authoritative **live-subscription coverage + attribution** plane: `subscription key ->
  /// `[`CoverEntry`]. Every live subscription's own key is present, its [`CoverEntry`] holding
  /// that subscription's caller value (folding every subscription sharing the key), so a
  /// `get_ancestor` here answers both "is some live subscription an ancestor-or-equal of this
  /// key" (the truthful `is_watched` set) and "what value owns it" (the longest covering
  /// subscription's — the attribution [`covering`](WatchView::covering) returns), published in
  /// [`Published::covers`]. Maintained in lockstep with `subs`: a subscription is added on every
  /// `commit_watch` and removed on every `plan_unwatch` / `force_remove_root`.
  covers: Radix<C, CoverEntry<V>>,
  /// Root handle → its radix key. The O(1) reverse lookup for [`entry`](Self::entry).
  by_handle: HashMap<H, Vec<C>>,
  /// Live subscription → the root it rides, its own key, and its interest.
  subs: HashMap<Subscription, SubRecord<C, H>>,
  /// Not-yet-committed plans, keyed by the id each `plan_watch` freshly minted. A plan
  /// stashes under its own new id, and the paired `commit_watch` / `abort_watch`
  /// consumes exactly that id — so plans never collide and may interleave freely; the
  /// only requirement is that every plan is eventually committed OR aborted, which
  /// [`abort_watch`](Self::abort_watch) makes enforceable.
  pending: HashMap<Subscription, PendingWatch<C, V>>,
  /// This owner's per-watcher [`InstanceId`] brand, minted once at construction and stamped
  /// onto every [`Subscription`] this engine mints — so a handle from a different watcher (whose
  /// `next_sub` counter also starts at 1) can never be mistaken for one of ours (design §3).
  instance: InstanceId,
  /// The next subscription id to mint. Monotonic and never reused, so a re-pointed or
  /// dropped-and-re-added subscription never aliases a live one.
  next_sub: NonZeroU64,
  /// The shared publication slot: the last committed watch-set, republished after
  /// every commit so every [`WatchView`] reader is wait-free and eventually
  /// consistent (design §5).
  shared: Shared<C, V, H>,
}

// The radix and the shared slot are not `Debug`; the side tables are the
// authoritative per-root / per-subscription state and stand in for them.
impl<C, V, H> core::fmt::Debug for Subsumer<C, V, H>
where
  C: core::fmt::Debug,
  V: core::fmt::Debug,
  H: core::fmt::Debug,
{
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("Subsumer")
      .field("by_handle", &self.by_handle)
      .field("subs", &self.subs)
      .field("pending", &self.pending)
      .finish_non_exhaustive()
  }
}

impl<C, V, H> Default for Subsumer<C, V, H>
where
  C: Ord + Clone,
  V: Clone,
  H: Copy + Eq + Hash,
{
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

// Bound-free operations — no `C`/`V`/`H` bounds, so the owner's `Drop` guard can call them while
// assuming only the `Source` bound the `Owner` struct carries (a `Drop` impl may not add bounds
// its type definition lacks).
impl<C, V, H> Subsumer<C, V, H> {
  /// Publishes an **empty** read-plane snapshot into the shared slot, so every [`WatchView`]
  /// reader reports "nothing watched" — `is_watched`/`covering`/`resolve` all empty and
  /// `contains`/`len` zero. The driver empties the plane at owner teardown — on the normal path
  /// after draining owed Rescans, and unconditionally from the owner's `Drop` guard, so a panic in
  /// any caller callback still empties it: the authoritative watch-set is about to drop with the
  /// owner task and its source, so a retained view must stop advertising coverage whose owner and
  /// source no longer exist (design §5). Like [`publish`](Self::publish) it is a single synchronous
  /// `arc_swap` store of a fresh empty snapshot — idempotent, and running no caller `C`/`V`/`H`
  /// method (the two trees are empty), so it needs no bounds and cannot itself panic, which makes it
  /// safe to call while unwinding.
  pub(crate) fn publish_empty(&self) {
    self.shared.store(Arc::new(Published {
      roots: Radix::new(),
      covers: Radix::new(),
    }));
  }
}

impl<C, V, H> Subsumer<C, V, H>
where
  C: Ord + Clone,
  V: Clone,
  H: Copy + Eq + Hash,
{
  /// Creates an empty engine, seeding the shared publication slot with an empty
  /// watch-set.
  pub(crate) fn new() -> Self {
    let index = Radix::new();
    let covers = Radix::new();
    let shared = Arc::new(ArcSwap::from_pointee(Published {
      roots: index.clone(),
      covers: covers.clone(),
    }));
    Self {
      index,
      covers,
      by_handle: HashMap::new(),
      subs: HashMap::new(),
      pending: HashMap::new(),
      instance: InstanceId::mint(),
      next_sub: NonZeroU64::MIN,
      shared,
    }
  }

  /// This owner's per-watcher [`InstanceId`] brand. The driver checks a handed-back
  /// [`Subscription`]'s brand against this before an `unwatch` touches any state, so a handle
  /// minted by a different watcher — even one whose `ScopeId` collides with a live local one —
  /// is rejected rather than retiring an unrelated subscription (design §3).
  pub(crate) fn instance(&self) -> InstanceId {
    self.instance
  }

  /// A cheap `Clone` read handle over the shared watch-set publication (design §5):
  /// every method is `&self`, wait-free, and reads the last committed watch-set.
  pub(crate) fn view(&self) -> WatchView<C, V, H> {
    WatchView::new(self.shared.clone())
  }

  /// Publishes the current authoritative watch-set into the shared slot — the
  /// **commit → publish** step run after every committed mutation (design §5). Both
  /// planes (the armed-root `index` and the live-subscription `covers`) are swapped
  /// together as one [`Published`] snapshot, so a reader never sees them torn apart;
  /// each tree is an O(1) structural-sharing clone.
  fn publish(&self) {
    self.shared.store(Arc::new(Published {
      roots: self.index.clone(),
      covers: self.covers.clone(),
    }));
  }

  /// Records one more live subscription `sub` at `key` in the coverage plane, carrying its caller
  /// `value` for attribution (creating the [`CoverEntry`] if `key` was absent). Called on every
  /// committed `watch` regardless of outcome — `Disjoint`, `Widen`, and `Covered` all add a live
  /// subscription whose own key must answer `is_watched` truthfully **and** resolve to its own
  /// value.
  fn cover_add(&mut self, sub: Subscription, key: &[C], value: V) {
    let mut txn = self.covers.txn();
    let mut entry = txn.get(key).cloned().unwrap_or_else(CoverEntry::new);
    entry.push(sub, value);
    txn.insert(key, entry);
    self.covers = txn.commit();
  }

  /// Drops the live subscription `sub` at `key` from the coverage plane, removing the key once
  /// its last subscription is gone. Called on every `unwatch` and for every subscriber of a
  /// force-removed dead root, so `covers` tracks exactly the set of keys — and owning values —
  /// some live subscription still covers.
  fn cover_remove(&mut self, sub: Subscription, key: &[C]) {
    let mut txn = self.covers.txn();
    if let Some(mut entry) = txn.get(key).cloned() {
      entry.remove(sub);
      if entry.is_empty() {
        txn.remove(key);
      } else {
        txn.insert(key, entry);
      }
    }
    self.covers = txn.commit();
  }

  /// Plans a `watch` of `key` carrying `value` with `interest`, returning the
  /// operations the driver must perform. Reads only; the state transition is applied
  /// by the paired [`commit_watch`](Self::commit_watch).
  ///
  /// The new subscription's id is minted from the engine's own monotonic counter, so
  /// overlapping subscriptions never collide even when they subsume onto one root.
  pub(crate) fn plan_watch(
    &mut self,
    key: &[C],
    value: V,
    interest: Interest,
  ) -> WatchOutcome<C, H> {
    let sub = self.mint_subscription();
    self.pending.insert(
      sub,
      PendingWatch {
        key: key.to_vec(),
        value,
        interest,
      },
    );

    // Case 1 — Covered: an existing root at or above `key` already watches this
    // subtree. Disjointness guarantees at most one such ancestor, and its presence
    // rules out any strict descendant. The covering root is armed `Interest::all`
    // (design §4), so it carries every kind this newcomer could ask for.
    if let Some(record) = self.index.get_ancestor(key) {
      // Covered-OUTSIDE (set-cover ): the covering root's source coverage was narrowed (`retained_cover`
      // is `Some`) to prefixes NONE of which is an ancestor-or-equal of this newcomer's key. The
      // source pruned that region, so `commit_watch` — which arms nothing — would leave the newcomer
      // advertised-yet-uncovered until the driver's awaited grow lands (applied before the watch
      // returns). A full-coverage root (`None`) or a newcomer already under a retained prefix is
      // `false`.
      let outside_cover = record.covered_outside(key);
      return WatchOutcome::Covered {
        fs_root: record.handle,
        sub,
        outside_cover,
      };
    }

    // Case 2 — Widen: `key` is a strict ancestor of one or more existing roots, which
    // it now subsumes. Collect them in key order (iradix yields strict descendants
    // ascending), gathering their handles to release and their subscribers to
    // re-point. No interest union is computed — every root is armed `Interest::all`.
    let mut unwatch = Vec::new();
    let mut repointed = Vec::new();
    for record in self.index.descendants(key) {
      repointed.extend_from_slice(&record.subscribers);
      unwatch.push(record.handle);
    }
    if !unwatch.is_empty() {
      return WatchOutcome::Widen {
        new_root_key: key.to_vec(),
        repointed,
        unwatch,
        sub,
      };
    }

    // Case 3 — Disjoint: neither covered nor covering.
    WatchOutcome::Disjoint {
      root_key: key.to_vec(),
      sub,
    }
  }

  /// Commits the state transition for `outcome`, binding the real `fs_root` the driver
  /// obtained by arming the watch and keying the root at `fs_root_key` — the
  /// **authoritative key the source reports** for the armed handle, which closes the
  /// canonicalization TOCTOU (design §4). For a fresh (`Disjoint`) or widened
  /// (`Widen`) root the newcomer's key *equals* the root key, so its side-table key is
  /// simply `fs_root_key`.
  ///
  /// For [`WatchOutcome::Covered`] no arm happened (the covering root was armed — and
  /// its key validated — when first created), so `fs_root_key` is ignored and the
  /// newcomer's own key is used unchanged. Each committed mutation republishes the
  /// watch-set (design §5).
  pub(crate) fn commit_watch(
    &mut self,
    outcome: &WatchOutcome<C, H>,
    fs_root: H,
    fs_root_key: &[C],
  ) {
    match outcome {
      WatchOutcome::Covered { sub, .. } => {
        let PendingWatch {
          key,
          value,
          interest,
        } = self.take_pending(*sub);
        let root_key = self
          .by_handle
          .get(&fs_root)
          .expect("covered root is live")
          .clone();
        let mut txn = self.index.txn();
        let mut record = txn.get(&root_key).expect("covered root record").clone();
        record.subscribers.push(*sub);
        txn.insert(root_key.as_slice(), record);
        self.index = txn.commit();
        // The covered subscription's own (narrower) key joins the coverage plane carrying its
        // OWN value — so `is_watched` stays truthful for it AND attribution resolves it to its
        // own value, never the covering root's (whose own watch may later depart, leaving the
        // armed root broader than any live subscription — design §5).
        self.cover_add(*sub, &key, value);
        self.subs.insert(
          *sub,
          SubRecord {
            root: fs_root,
            key,
            interest,
          },
        );
        self.publish();
      }
      WatchOutcome::Disjoint { sub, .. } => {
        let PendingWatch {
          value, interest, ..
        } = self.take_pending(*sub);
        let root_key = fs_root_key.to_vec();
        let record = RootRecord {
          key: root_key.clone(),
          handle: fs_root,
          subscribers: std::vec![*sub],
          // A freshly-armed root covers its whole key (`Interest::all`) — full coverage, never
          // narrowed (set-cover ).
          retained_cover: None,
        };
        let mut txn = self.index.txn();
        txn.insert(root_key.as_slice(), record);
        self.index = txn.commit();
        self.by_handle.insert(fs_root, root_key.clone());
        // The disjoint root's own subscription joins the coverage plane carrying its value, so
        // attribution resolves the root and its descendants to it (the value plane lives on
        // `covers`, not the armed root — design §5).
        self.cover_add(*sub, &root_key, value);
        self.subs.insert(
          *sub,
          SubRecord {
            root: fs_root,
            key: root_key,
            interest,
          },
        );
        self.publish();
      }
      WatchOutcome::Widen {
        repointed,
        unwatch,
        sub,
        ..
      } => {
        let PendingWatch {
          value, interest, ..
        } = self.take_pending(*sub);
        let root_key = fs_root_key.to_vec();

        let mut subscribers = repointed.clone();
        subscribers.push(*sub);
        let record = RootRecord {
          key: root_key.clone(),
          handle: fs_root,
          subscribers,
          // The wider root is freshly armed `Interest::all` over its whole key — full coverage,
          // never narrowed (any pending set_cover for the released subsumed handles is moot);
          // set-cover .
          retained_cover: None,
        };

        // Drop the subsumed roots' index keys and install the wider root atomically:
        // remove every strict descendant of the wider key (exactly the subsumed set,
        // which the driver's `fs_path_preserves_plan` guard verified), then insert.
        let mut txn = self.index.txn();
        txn.remove_descendants(root_key.as_slice());
        txn.insert(root_key.as_slice(), record);
        self.index = txn.commit();

        for old in unwatch {
          self.by_handle.remove(old);
        }
        self.by_handle.insert(fs_root, root_key.clone());
        for &moved in repointed {
          self
            .subs
            .get_mut(&moved)
            .expect("re-pointed subscription is live")
            .root = fs_root;
        }
        // Only the new (widening) subscription's key joins the coverage plane, carrying its
        // value; each re-pointed subscription's own key + value is invariant under the widen (it
        // rides a new root, but its key is unchanged), so it is already counted in `covers`.
        self.cover_add(*sub, &root_key, value);
        self.subs.insert(
          *sub,
          SubRecord {
            root: fs_root,
            key: root_key,
            interest,
          },
        );
        self.publish();
      }
    }
  }

  /// Abandons the plan `outcome` without committing it, discarding the pending
  /// reservation `plan_watch` stashed. Call this on every path where arming failed, so
  /// the not-yet-committed subscription's pending entry cannot leak. Idempotent per
  /// plan (consuming an already-committed or already-aborted id is a no-op). No
  /// watch-set change committed, so nothing is republished.
  pub(crate) fn abort_watch(&mut self, outcome: &WatchOutcome<C, H>) {
    let sub = match outcome {
      WatchOutcome::Covered { sub, .. }
      | WatchOutcome::Widen { sub, .. }
      | WatchOutcome::Disjoint { sub, .. } => *sub,
    };
    self.pending.remove(&sub);
  }

  /// Removes `sub`, reporting whether its root emptied (returns `None` for an unknown
  /// subscription). Mutates immediately and republishes — no commit step is needed.
  ///
  /// On the non-emptied ([`Dropped`](UnwatchOutcome::Dropped)) path it also reports
  /// whether the armed root is now **over-broad** and the source may shrink its coverage
  /// in place (the set-cover design) — see [`detect_shrink`](Self::detect_shrink).
  pub(crate) fn plan_unwatch(&mut self, sub: Subscription) -> Option<UnwatchOutcome<C, H>> {
    let record = self.subs.remove(&sub)?;
    let root_key = self
      .by_handle
      .get(&record.root)
      .expect("live subscription's root is live")
      .clone();

    let mut txn = self.index.txn();
    let mut root = txn.get(&root_key).expect("live root record").clone();
    root.subscribers.retain(|&s| s != sub);
    let emptied = root.subscribers.is_empty();
    // The surviving subscribers, captured before `root` is moved back into the index — the
    // over-broadness detection reads their keys (each still live in `self.subs`).
    let survivors = root.subscribers.clone();
    if emptied {
      txn.remove(root_key.as_slice());
    } else {
      txn.insert(root_key.as_slice(), root);
    }
    self.index = txn.commit();

    // Drop this subscription from the coverage plane (the root may live on for its other,
    // narrower subscribers, and the key stays covered iff another live sub shares it).
    self.cover_remove(sub, &record.key);

    let outcome = if emptied {
      self.by_handle.remove(&record.root);
      UnwatchOutcome::RootEmptied {
        fs_root: record.root,
      }
    } else {
      // The root lives on for its narrower subscribers; report whether the departure left the source
      // coverage reclaimable — either newly over-broad (full coverage, the root-key sub departed) or
      // an already-narrowed cover that can shrink further (a non-root sub departed — F2).
      let shrink = self.detect_shrink(&root_key, record.root, &survivors);
      UnwatchOutcome::Dropped { shrink }
    };
    self.publish();
    Some(outcome)
  }

  /// Whether the drop that left `survivors` behind on the armed root at `root_key` (handle
  /// `root_handle`) made the source coverage RECLAIMABLE, and if so the RETAINED COVER the source may
  /// prune down to (the set-cover design v3). Generalized over the root's **recorded** coverage
  /// ([`retained_cover`](RootRecord::retained_cover)) so BOTH reclaim cases are caught:
  ///
  /// - **full coverage (`None`)** — over-broad iff no surviving subscriber's key still equals the
  ///   root's own key. Only the departure of the sub that pinned the root at its own (widest) key can
  ///   newly open a gap between the armed root and its live subscribers; a survivor still at the root
  ///   key keeps that key legitimately watched. (This is the original set-cover over-broad case.)
  /// - **already narrowed (`Some(cover)`)** — reclaimable iff the survivors' antichain is STRICTLY
  ///   narrower than `cover`, i.e. a non-root subscriber under the cover departed and its subtree can
  ///   now be pruned too (F2, the previously-missed non-root re-prune). Every live
  ///   subscriber sits under `cover` (the umbrella's invariant: the record always names a cover of the
  ///   current membership), so the survivor antichain's coverage is a subset of `cover`'s; being
  ///   unequal therefore means strictly smaller (the minimal antichain of a coverage region is
  ///   unique). Equal → the departure reclaimed nothing (a duplicate, or a sub deeper than a
  ///   still-needed cover prefix).
  ///
  /// The retained cover is the minimal prefix-free [`antichain`] of the survivors' keys — the
  /// narrowest set of prefixes under which every live subscriber still sits, so pruning to it drops no
  /// live coverage. Always non-empty on a `Some` (a non-emptied root has at least one survivor).
  fn detect_shrink(
    &self,
    root_key: &[C],
    root_handle: H,
    survivors: &[Subscription],
  ) -> Option<(H, Vec<Vec<C>>)> {
    let survivor_keys: Vec<Vec<C>> = survivors
      .iter()
      .map(|s| {
        self
          .subs
          .get(s)
          .map(|record| record.key.clone())
          .expect("a surviving subscriber is live in the side table")
      })
      .collect();
    // The cover last ISSUED to the source for this root — read from the just-committed record (the
    // root is not emptied on this path, so it is present).
    let recorded = self
      .index
      .get(root_key)
      .and_then(|record| record.retained_cover.clone());
    match recorded {
      // Full coverage: a survivor still at the root key keeps the wide coverage legitimately watched
      // — not over-broad.
      None => {
        if survivor_keys.iter().any(|key| key.as_slice() == root_key) {
          return None;
        }
        Some((root_handle, antichain(survivor_keys)))
      }
      // Already narrowed: re-prune iff the survivors' antichain is strictly narrower than the recorded
      // cover (F2).
      Some(cover) => {
        let survivor_antichain = antichain(survivor_keys);
        (survivor_antichain != cover).then_some((root_handle, survivor_antichain))
      }
    }
  }

  /// The retained cover naming every live subscriber of the root `handle` — plus the
  /// `newcomer` key when one is supplied — recomputed from the root's **current** membership; or
  /// `None` when one of those keys still equals the root's own key (legitimately pinning the whole
  /// coverage). `Some` is the minimal prefix-free [`antichain`] of the collected keys (the narrowest
  /// set under which they all still sit); a handle naming no live root is `None` (nothing to cover).
  ///
  /// The driver reads this on a **Covered-outside** watch to compute the fresh cover it GROWS the
  /// source up to (set-cover, grow-BEFORE-commit): the newcomer arms nothing AND is **not yet
  /// committed** when the grow is issued — the umbrella only broadens state after the awaited grow
  /// returns `Ok` — so its key is passed **explicitly** as `newcomer` rather than read from the
  /// committed membership. On the grow's `Ok` the driver commits and records the same cover via
  /// [`set_retained_cover`](Self::set_retained_cover), so the record broadens EXACTLY to the
  /// source's live coverage. `None` means a key (a survivor's, or the newcomer's own) pins the root
  /// at its own key, so the driver grows back to the **cancel-equivalent** (the root's own key —
  /// full coverage) and records `None`. Unlike [`detect_shrink`](Self::detect_shrink) (which decides
  /// reclaim from a *departing* key on an unwatch), this is a pure membership query.
  pub(crate) fn retained_cover_for(
    &self,
    handle: H,
    newcomer: Option<&[C]>,
  ) -> Option<Vec<Vec<C>>> {
    let root_key = self.by_handle.get(&handle)?;
    let record = self.index.get(root_key)?;
    let mut subscriber_keys: Vec<Vec<C>> = record
      .subscribers
      .iter()
      .map(|s| {
        self
          .subs
          .get(s)
          .map(|sub_record| sub_record.key.clone())
          .expect("a live root's subscriber is live in the side table")
      })
      .collect();
    if let Some(extra) = newcomer {
      subscriber_keys.push(extra.to_vec());
    }
    // A key still at the root key keeps the whole coverage legitimately watched — not
    // over-broad; the driver grows back to the cancel-equivalent (full coverage) instead.
    if subscriber_keys
      .iter()
      .any(|key| key.as_slice() == root_key.as_slice())
    {
      return None;
    }
    Some(antichain(subscriber_keys))
  }

  /// Records the source's ACTUAL coverage for the root `handle` (set-cover ) — the bookkeeping
  /// [`plan_watch`](Self::plan_watch) reads to decide a `Covered` newcomer's
  /// [`outside_cover`](WatchOutcome::Covered::outside_cover). `Some(cover)` records a narrowing to the
  /// antichain `cover`; `None` records **full** coverage — a fresh/widened root (never narrowed) or a
  /// root grown back to its own key (the cancel-equivalent).
  ///
  /// The driver calls this at every coverage-reconcile site with exactly the cover the source now
  /// holds, so the record stays EXACT: NARROWED on a [`Source::set_cover`](crate::Source::set_cover)
  /// PRUNE issue (the over-broad-unwatch shrink and the non-root re-prune — narrow-on-issue, safe
  /// pessimism for a fire-and-forget prune) and BROADENED on a [`Source::grow`](crate::Source::grow)
  /// **`Ok`** (the Covered-outside grow and its cancel-equivalent — broaden-on-`Ok`, when the awaited
  /// grow has already applied, so the record never runs ahead of live coverage; a failed grow
  /// broadens NOTHING — the watch is aborted instead, ratified R1). A no-op for an
  /// unknown handle (nothing to record). Republishes so the read plane's `roots` snapshot stays in
  /// lockstep with the index (no [`WatchView`] reader consults `retained_cover`, but the two planes
  /// are always swapped together — design §5).
  pub(crate) fn set_retained_cover(&mut self, handle: H, cover: Option<Vec<Vec<C>>>) {
    let Some(root_key) = self.by_handle.get(&handle).cloned() else {
      return;
    };
    let mut txn = self.index.txn();
    let Some(mut record) = txn.get(&root_key).cloned() else {
      return;
    };
    record.retained_cover = cover;
    txn.insert(root_key.as_slice(), record);
    self.index = txn.commit();
    self.publish();
  }

  /// The retained cover last recorded for the root `handle` (see
  /// [`set_retained_cover`](Self::set_retained_cover)): `Some(cover)` when the source coverage was
  /// narrowed to the antichain `cover`, `None` for full coverage or an unknown handle. The by-handle
  /// introspection counterpart of [`RootRecord::covered_outside`] (the field
  /// [`plan_watch`](Self::plan_watch) reads through the record it already holds), used to assert the
  /// bookkeeping in unit tests.
  #[cfg(test)]
  pub(crate) fn retained_cover_of(&self, handle: H) -> Option<Vec<Vec<C>>> {
    let root_key = self.by_handle.get(&handle)?;
    self.index.get(root_key)?.retained_cover.clone()
  }

  /// The live record for `fs_root`, if any.
  pub(crate) fn entry(&self, fs_root: H) -> Option<&RootRecord<C, H>> {
    let key = self.by_handle.get(&fs_root)?;
    self.index.get(key)
  }

  /// Force-drops the root `handle` and every subscriber riding it, returning those
  /// subscribers so the driver can reclaim their per-subscription state (filter, epoch
  /// ledger) — the **dead-root retirement** (design §4, invariant I4). A watched root
  /// died (the source tore its handle down and emitted a terminal `Rescan`, already fanned
  /// out to every subscriber), so the dead root is torn out of index / reverse-index /
  /// side-table and no later event routes to its dead handle. Republishes.
  pub(crate) fn force_remove_root(&mut self, handle: H) -> Vec<Subscription> {
    let Some(root_key) = self.by_handle.remove(&handle) else {
      return Vec::new();
    };
    let mut txn = self.index.txn();
    let record = txn
      .remove(root_key.as_slice())
      .expect("force-removed root record");
    self.index = txn.commit();
    // Free the dead root's subscribers from the side table AND the coverage plane, so a
    // retired root's keys stop answering `is_watched` true (they cover nothing now).
    // BATCHED per cover key: the per-subscriber `cover_remove` cloned the
    // whole same-key cohort entry once per departing member — O(cohort squared) deep
    // value clones plus a txn commit each. Grouping the departures by key makes the
    // conversion genuinely linear: one entry clone, one retain pass, and one commit
    // for the whole root.
    let mut departing_by_key: std::collections::BTreeMap<
      Vec<C>,
      std::collections::HashSet<Subscription>,
    > = std::collections::BTreeMap::new();
    for &sub in &record.subscribers {
      if let Some(sub_record) = self.subs.remove(&sub) {
        departing_by_key
          .entry(sub_record.key)
          .or_default()
          .insert(sub);
      }
    }
    let mut txn = self.covers.txn();
    for (key, departing) in departing_by_key {
      if let Some(mut entry) = txn.get(&key).cloned() {
        entry.remove_all(&departing);
        if entry.is_empty() {
          txn.remove(&key);
        } else {
          txn.insert(key.as_slice(), entry);
        }
      }
    }
    self.covers = txn.commit();
    self.publish();
    record.subscribers
  }

  /// Rebinds the live root `old` onto a fresh handle `new`, keeping its key, record, and
  /// subscribers — the **re-arm restore** the driver runs when a failed widen must put its
  /// disarmed subsumed roots back (design driver-golden doc, invariant I3). A disarm then
  /// re-arm at the *same* key yields a new source handle, so the record's handle, the
  /// reverse index, and every subscriber's ridden-root pointer must move to it; no key
  /// changes, so the coverage plane is untouched. A no-op if `old` is not a live root.
  ///
  /// `new` is **generation-unique** by the [`Source::Handle`](crate::Source::Handle) contract, so
  /// it is absent from `by_handle` before this runs: the `by_handle.insert(new, ..)` below can
  /// never clobber another live root's reverse-map entry. The driver `debug_assert`s this at the arm
  /// choke point (an exhaustive owner-level observed-handle tripwire for a contract-violating
  /// source), so no in-band alias recovery is needed here.
  pub(crate) fn rebind_root(&mut self, old: H, new: H) {
    let Some(root_key) = self.by_handle.get(&old).cloned() else {
      return;
    };
    let mut txn = self.index.txn();
    let Some(mut record) = txn.get(&root_key).cloned() else {
      return;
    };
    record.handle = new;
    let subscribers = record.subscribers.clone();
    txn.insert(root_key.as_slice(), record);
    self.index = txn.commit();
    self.by_handle.remove(&old);
    self.by_handle.insert(new, root_key);
    for sub in subscribers {
      if let Some(side) = self.subs.get_mut(&sub) {
        side.root = new;
      }
    }
    self.publish();
  }

  /// The key a live subscription was registered at, if any (its entry in the §4 side
  /// table).
  pub(crate) fn subscription_key(&self, sub: Subscription) -> Option<&[C]> {
    self.subs.get(&sub).map(|record| record.key.as_slice())
  }

  /// The [`Interest`] a live subscription was registered with, if any — the fan-out
  /// gate (design §4/§5) applied to every non-`Rescan` delivery. Every root is armed
  /// [`Interest::all`], so this narrows *delivery*, never the kernel watch.
  pub(crate) fn subscription_interest(&self, sub: Subscription) -> Option<Interest> {
    self.subs.get(&sub).map(|record| record.interest)
  }

  /// The caller value the live subscription `sub` was registered with, read from the
  /// live-subscription coverage plane (design §3/§5) — the per-event attribution the driver
  /// bakes onto every delivery so it survives teardown (once the owner quiesces and the
  /// [`WatchView`] is emptied, `resolve` can no longer attribute a still-queued event). `None`
  /// for an unknown or already-retired subscription.
  ///
  /// Unlike [`covering`](crate::WatchView::covering) — the *longest* live subscription covering a
  /// key, the view's live query — this is the value of the **exact** `sub` the delivery was
  /// routed to: the specific owner of a per-subscription `Rescan`, and the covering subscription a
  /// delta fanned out to. It reads the [`CoverEntry`] at `sub`'s own key (kept in lockstep with
  /// the side table), so it is `Some` for the whole lifetime the driver needs to bake or capture.
  pub(crate) fn subscription_value(&self, sub: Subscription) -> Option<&V> {
    let key = self.subs.get(&sub)?.key.as_slice();
    self.covers.get(key)?.value_of(sub)
  }

  /// Whether committing a fresh/widened root at `fs_root_key` would keep the same
  /// subsumption the plan assumed — used by the driver to guard the canonicalization
  /// TOCTOU (design §4) after the source reports its authoritative key.
  ///
  /// Safe when the key is not covered by an existing root, and the set of committed
  /// roots it strictly contains equals `planned_unwatch`. A divergence that changes
  /// subsumption (now covered, or overlapping a different set) makes the driver disarm
  /// and abort rather than commit a mis-keyed or overlapping entry.
  pub(crate) fn fs_path_preserves_plan(&self, fs_root_key: &[C], planned_unwatch: &[H]) -> bool {
    if self.index.get_ancestor(fs_root_key).is_some() {
      return false;
    }
    let now: std::collections::HashSet<H> = self
      .index
      .descendants(fs_root_key)
      .map(|record| record.handle)
      .collect();
    let planned: std::collections::HashSet<H> = planned_unwatch.iter().copied().collect();
    now == planned
  }

  /// The number of not-yet-committed plans still holding a pending reservation — the
  /// leak the plan→commit-or-abort contract must keep at zero between watches.
  #[cfg(all(test, feature = "tokio"))]
  pub(crate) fn pending_len(&self) -> usize {
    self.pending.len()
  }

  /// Every live root as `(key, handle)`, in deterministic key order. Iterates the
  /// [`iradix`] index (values in key order), never a [`HashMap`], so the order is
  /// reproducible.
  #[cfg(test)]
  pub(crate) fn roots(&self) -> impl Iterator<Item = (&[C], H)> {
    self
      .index
      .values()
      .map(|record| (record.key.as_slice(), record.handle))
  }

  /// Mints the next subscription id from the engine's monotonic counter, branded with this
  /// owner's [`InstanceId`] so the handle names a subscription of this watcher alone.
  fn mint_subscription(&mut self) -> Subscription {
    let next = self.next_sub;
    self.next_sub = self
      .next_sub
      .checked_add(1)
      .expect("subscription id space (u64) exhausted");
    Subscription::new(self.instance, ScopeId::new(next))
  }

  /// Consumes the reservation `plan_watch` stashed under `sub`'s freshly-minted id. A
  /// commit consumes exactly its own plan's id, so this is present unless the plan was
  /// already aborted (arm failure) — in which case `commit_watch` must not run for it.
  fn take_pending(&mut self, sub: Subscription) -> PendingWatch<C, V> {
    self
      .pending
      .remove(&sub)
      .expect("commit_watch consumes its own plan's pending entry (not yet aborted)")
  }
}

/// The minimal prefix-free **antichain** of `keys`: the fewest keys such that every input
/// key is an ancestor-or-equal of exactly one of them — the RETAINED COVER a shrink reclaims
/// coverage down to (the set-cover design).
///
/// Dedups equal keys, then keeps a key iff no OTHER key is a strict ancestor (proper prefix)
/// of it, dropping every key that descends from another and leaving the maximal-coverage
/// prefixes. So a survivor set `{[a,b], [a,b,c], [a,c]}` reduces to `{[a,b], [a,c]}` — `[a,b,c]`
/// is already covered by `[a,b]`. Siblings with no ancestor among the set (`{[a,b,c], [a,b,d]}`)
/// are all kept: neither covers the other, so both subtrees must be retained.
fn antichain<C: Ord + Clone>(mut keys: Vec<Vec<C>>) -> Vec<Vec<C>> {
  keys.sort();
  keys.dedup();
  keys
    .iter()
    .filter(|key| {
      // Drop `key` iff some strictly-shorter OTHER key is a proper prefix (ancestor) of it.
      !keys
        .iter()
        .any(|other| other.len() < key.len() && key.starts_with(other.as_slice()))
    })
    .cloned()
    .collect()
}
