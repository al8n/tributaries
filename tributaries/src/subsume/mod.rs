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
  event::Event,
  filter::Filter,
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
/// **exactly** this key, each paired with the caller value it carries. The entry is present
/// in [`Published::covers`] iff it holds at least one subscription (the key is removed when
/// its last subscription drops), so its presence answers [`WatchView::is_watched`] and its
/// [`value`](Self::value) answers attribution.
///
/// A single stored value would not do: several subscriptions can share one key with **different**
/// values (`watch("/a", A)` then `watch("/a", B)`), and one departing must restore the surviving
/// one's value — so the whole set is kept and removal is by [`Subscription`], not a bare
/// refcount. [`value`](Self::value) returns the **most-recent** (highest-id) live subscription's
/// value, a deterministic tie-break that under monotonic ids is the last-installed surviving
/// owner.
///
/// # Why a persistent trie and not a `Vec`
///
/// This entry lives inside an immutable radix value that is **cloned on every mutation** of the
/// coverage plane and republished on every commit. A `Vec<(Subscription, V)>` makes that clone
/// deep: registering `N` subscriptions at one key copies `N(N-1)/2` caller values, and `V` is
/// caller-controlled and may be arbitrarily expensive. Worse, exact lookup and "most recent" were
/// both linear scans, and exact lookup runs once **per delivery** — so one event on an `N`-member
/// cohort cost `Θ(N²)` subscription comparisons on top of the `N` deliveries it owes.
///
/// Keying the cohort in its own [`Radix`] — by the subscription's `u64` id, whose big-endian byte
/// decomposition orders lexicographically exactly as it does numerically — makes every one of
/// those `O(log N)` or `O(1)`:
///
/// - cloning the entry is a structural-sharing root clone: `O(1)`, and it clones **no** `V`;
/// - add and remove are single trie mutations;
/// - [`value_of`](Self::value_of) is a point lookup, not a cohort scan;
/// - [`value`](Self::value) is the trie's greatest key — the highest live id — read without
///   visiting the rest of the cohort.
pub(crate) struct CoverEntry<V> {
  /// Every live subscription at this exact key, keyed by its `u64` id and valued by that
  /// subscription's caller value. Never empty while the entry is present (the key is removed
  /// on the last drop). Id order is registration order (ids are minted monotonically), so the
  /// trie's greatest key is the most recently installed live owner.
  subs: Radix<u8, V>,
}

// Cohort members visited by an attribution lookup (`CoverEntry::value` / `value_of`) — the
// quantity this representation exists to hold constant. Attribution runs once per DELIVERED
// EVENT, so a lookup that visits a cohort member per comparison makes one raw event to an
// N-member cohort quadratic. A complexity regression reads this counter across a doubling
// cohort and binds the per-lookup visit count to the lookup, not to the cohort.
//
// Thread-local so libtest's parallel cells cannot perturb one another's count (each test body
// owns its thread).
#[cfg(test)]
thread_local! {
  pub(crate) static COHORT_VISITS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// Records that an attribution lookup visited `n` cohort members.
#[cfg(test)]
fn note_cohort_visits(n: usize) {
  COHORT_VISITS.with(|visits| visits.set(visits.get() + n));
}

#[cfg(not(test))]
#[inline(always)]
#[allow(clippy::inline_always)]
fn note_cohort_visits(_n: usize) {}

// Hand-written rather than derived: the derive would demand `V: Clone`, but a `Radix` clone is
// an `O(1)` structural-sharing root clone that touches no value at all. That is the whole point
// of the representation — the coverage plane is cloned on every commit.
impl<V> Clone for CoverEntry<V> {
  fn clone(&self) -> Self {
    Self {
      subs: self.subs.clone(),
    }
  }
}

impl<V> CoverEntry<V> {
  /// An empty entry (no covering subscription yet).
  fn new() -> Self {
    Self { subs: Radix::new() }
  }

  /// Whether no live subscription remains at this key (the caller then removes the key).
  fn is_empty(&self) -> bool {
    self.subs.is_empty()
  }

  /// The attribution value: the **most-recent** (highest-id) live subscription's value — the
  /// deterministic tie-break when several live subscriptions share this exact key. Read as the
  /// cohort trie's greatest key, so it costs one descent rather than a scan. Never panics:
  /// a present entry always holds at least one subscription.
  pub(crate) fn value(&self) -> &V {
    // ONE member: the trie's greatest key is reached by descent, not by comparing the cohort.
    note_cohort_visits(1);
    self
      .subs
      .values_rev()
      .next()
      .expect("a present cover entry holds at least one live subscription")
  }

  /// This **exact** subscription's own caller value, if `sub` is one of the live subscriptions at
  /// this key. This is the per-event attribution source (design §3), distinct from
  /// [`value`](Self::value) (the longest/most-recent owner the wait-free view query returns): a
  /// delivered event is attributed to the *specific* subscription it was routed to, whose own
  /// value the driver bakes onto it. `None` if `sub` is not (or no longer) at this key.
  ///
  /// A point lookup: the driver calls it once per delivered event, so a cohort scan here is a
  /// per-event factor of the cohort size.
  pub(crate) fn value_of(&self, sub: Subscription) -> Option<&V> {
    // AT MOST ONE member: a point lookup reaches its own entry or none, whatever the cohort
    // size — the property the complexity regression binds.
    let found = self.subs.get(&sub.id().as_u64());
    note_cohort_visits(usize::from(found.is_some()));
    found
  }
}

impl<V: Clone> CoverEntry<V> {
  /// Records one more live subscription `sub` at this key, carrying `value`, and hands back any
  /// value that stood under the same id (never one in practice — ids are minted monotonically and
  /// never reused — but a displaced caller value is a caller destructor either way, so it leaves
  /// by the same door every other one does).
  fn push(&mut self, sub: Subscription, value: V) -> Option<V> {
    let mut txn = self.subs.txn();
    let displaced = txn.insert(&sub.id().as_u64(), value);
    self.subs = txn.commit();
    displaced
  }

  /// Removes `sub` from this key (a no-op if absent), leaving every other subscription sharing it
  /// — so attribution falls back to a surviving owner rather than to nothing — and hands its
  /// caller value back rather than destroying it here (see [`Salvage`]).
  fn remove(&mut self, sub: Subscription) -> Option<V> {
    let mut txn = self.subs.txn();
    let removed = txn.remove(&sub.id().as_u64());
    self.subs = txn.commit();
    removed
  }

  /// Removes every subscription in `departing` under ONE transaction — the batch-retirement
  /// primitive a cohort retire uses, so a whole root's departure is one commit rather than one
  /// per departing member — handing every removed caller value back (see [`Salvage`]).
  fn remove_all(
    &mut self,
    departing: &std::collections::HashSet<Subscription>,
    removed: &mut Vec<V>,
  ) {
    let mut txn = self.subs.txn();
    for sub in departing {
      removed.extend(txn.remove(&sub.id().as_u64()));
    }
    self.subs = txn.commit();
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
/// subscribers must be named a dominating loss `Rescan`) and the armed `handle`.
///
/// It carries **no subscriber list**. The routing cohort is mutable — every `Covered` watch
/// appends to it — while this record is an *immutable* radix value that must be cloned to be
/// changed. Holding the growing `Vec` here made each admission copy the whole cohort, so
/// registering `N` subscriptions under one root copied `N(N-1)/2` subscription ids before a
/// single event was routed. The cohort lives in the engine's own
/// [`root_subs`](Subsumer::root_subs) map instead, where an append is `O(1)` and the published
/// snapshot receives this lean record; nothing on the read plane ever needed the list.
///
/// It carries **no** caller value and **no** interest either. Attribution
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
///
/// Carries no key. Every variant's root key is *by construction* the new subscription's own
/// canonicalized key, which the driver already owns for the whole reconcile and hands to
/// `commit_watch` directly — so a key field here would be a duplicate the driver has no reader
/// for, and one more owned `Vec<C>` whose destructor is the CALLER's code, destroyed by an
/// abandoned reconcile's frame exit rather than placed through [`Salvage`]. Hence the key
/// component `C` does not appear at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WatchOutcome<H> {
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

/// Caller-owned state a mutator **removed from the engine and deliberately did not destroy**,
/// handed back for its owner to release deliberately.
///
/// # Why a mutator hands its removals back instead of dropping them
///
/// `C` and `V` are caller types, so every one of these releases runs a caller destructor, and a
/// caller destructor is as fallible as a caller [`Filter`](crate::Filter) predicate — the contract
/// cannot require panic-freedom of either. WHERE that destructor runs is therefore a placement
/// decision, and inside a mutator is the one place it can never be placed well: the unwind leaves
/// through the mutator's call site, in front of whatever that call site still owed. On the driver's
/// terminal path what it owes is the source's teardown seam, every pending cookie's reap, the
/// bounded quiescence wait and the acknowledgement that carries its verdict — none of which can be
/// re-attempted once an unwind has gone past them, and the last two of which nothing downstream of
/// the run loop is even able to perform.
///
/// So every mutator that would destroy caller-owned state returns it in one of these instead. The
/// type is `#[must_use]`, which is what keeps that from being a convention: a call site cannot
/// ignore the return, and the one disposal route it can reach decides — by the driver's teardown
/// latch — whether the release happens at once or is held to the end of the teardown.
///
/// # What lands here, and what needs no place here
///
/// Both authoritative trees are persistent, so a removal from either frees nothing on its own: the
/// pre-mutation version is still owned by the publication standing in the shared slot, and the
/// nodes the mutation unlinked die with THAT. Capturing the DISPLACED PUBLICATION therefore defers
/// every radix-borne `C` and `V` of that mutation at once — which is why most mutators salvage
/// nothing else, and why capturing it is not optional bookkeeping but the bulk of the guarantee.
///
/// What escapes that net is what never lived in a tree, or what a removal hands back as an owned
/// value: a not-yet-committed [`PendingWatch`] reservation, a [`RootRecord`] or [`SubRecord`] a
/// `remove` returned, a cover value, a reverse-index key.
///
/// # Not only this engine's removals
///
/// The bundle is named for its first producer but scoped by the CATEGORY it holds: a value whose
/// destructor is the caller's own code. The driver's own per-subscription planes hold exactly that
/// — a parked re-enumeration's key and baked value, an undelivered [`Event`], a subscription's
/// admission [`Filter`] — and their removals travel and are released the same way, through the same
/// one route, rather than through a second bundle that would be one more thing to keep ordered
/// against the teardown's bounded wait. Which is why those planes' element types are NOT held here:
/// a `ParkedRescan` is a driver concept and belongs to the driver, so it is decomposed at the
/// boundary into the caller-owned halves this bundle already carries (a key, a value) and the
/// bookkeeping that is not caller-owned at all (an epoch) is simply not handed over.
///
/// # The one window this cannot cover
///
/// A bundle is a LOCAL until its producer returns it. So caller code the producer itself runs
/// **mid-removal** — `C::cmp` on a radix descent, `C::clone`, `H::hash`, and `C::drop` — unwinds
/// past the bundle and takes everything already placed in it with it, exactly as if those values
/// had been destroyed at the site.
///
/// `C::drop` is in that list for a reason that is measured, not theoretical, and it is the one
/// place the "capturing the displaced publication defers every radix-borne `C`" argument above does
/// NOT reach. That argument is about the tree's SHARED nodes: the pre-mutation version still owns
/// them, so unlinking frees nothing. A copy-on-write transaction also builds nodes of its OWN —
/// split labels, merged labels from a collapse — and those are unshared, so when the txn's edit
/// discards one its label's components are destroyed inside the radix, in the middle of the
/// mutator, with the bundle still a local. A caller key removed by
/// [`force_remove_root`](Subsumer::force_remove_root) or
/// [`cover_remove`](Subsumer::cover_remove) whose node the removal collapses reaches a caller
/// destructor exactly there.
///
/// Nothing in this type closes that. Making the bundle an owner field instead of a local moves the
/// same window (the owner is borrowed by the producer); catching around every mutator puts a
/// containment boundary on the hot path to buy a window only caller code can open; and the
/// intermediate labels are the radix's, reachable through no API this crate has. What narrows it is
/// ORDERING inside each producer — retain first, then run caller code (see `force_remove_root`,
/// whose grouping borrows already-retained keys rather than owning one) — and that is as far as
/// ordering goes: a producer that must compare before it can know what to remove still has a first
/// comparison. It is a stated limit rather than an unexamined one; the containment at the end of
/// the driver's teardown keeps the blast radius of the panic itself to one unwind either way.
#[must_use = "these are caller-owned values whose destructors are the caller's own code — release \
              them deliberately, never by discarding a removal's return"]
pub(crate) struct Salvage<C, V, H> {
  /// Publications displaced out of the shared slot by a republish. Each is the last owner of
  /// every node its successor unlinked.
  publications: Vec<Arc<Published<C, V, H>>>,
  /// Root records an index removal handed back.
  roots: Vec<RootRecord<C, H>>,
  /// Live-subscription records a side-table removal handed back.
  subs: Vec<SubRecord<C, H>>,
  /// Not-yet-committed reservations an aborted plan handed back.
  pending: Vec<PendingWatch<C, V>>,
  /// Caller values a coverage-plane removal handed back, and caller values the driver salvaged
  /// from a request it is abandoning.
  values: Vec<V>,
  /// Keys a reverse-index removal handed back, request keys the driver salvaged, superseded
  /// reservation keys, the retained-cover prefixes a coverage re-record replaced, and the driver's
  /// parked re-enumeration keys — including the tail a widen truncated off one.
  keys: Vec<Vec<C>>,
  /// Deliveries that were minted but never handed to the consumer: an offer a full or closed
  /// channel refused, and the buffered deltas a subscription's retirement discards. Each owns the
  /// key it was located at and the value baked onto it.
  events: Vec<Event<C, V>>,
  /// Admission gates a retiring subscription's driver-side entry handed back. The gate's caller
  /// half only: the driver's per-subscription quarantine verdict rides with the subscription, not
  /// with the caller's predicate, and is not caller-owned.
  filters: Vec<Filter<C>>,
}

// Hand-written rather than derived: a derive would demand `C: Default` / `V: Default` /
// `H: Default`, and an empty bundle needs none of them — every field starts as an empty `Vec`.
// Staying bound-free is what lets the driver's destructor, which carries only `S: LocalSource<C>`,
// take the bundle out of the owner on its way past.
impl<C, V, H> Default for Salvage<C, V, H> {
  fn default() -> Self {
    Self {
      publications: Vec::new(),
      roots: Vec::new(),
      subs: Vec::new(),
      pending: Vec::new(),
      values: Vec::new(),
      keys: Vec::new(),
      events: Vec::new(),
      filters: Vec::new(),
    }
  }
}

impl<C, V, H> Salvage<C, V, H> {
  /// An empty bundle — what a mutator that removed nothing caller-owned hands back.
  pub(crate) fn new() -> Self {
    Self::default()
  }

  /// Takes everything `other` holds into this bundle, so several mutators' removals travel — and
  /// are released — as one.
  pub(crate) fn absorb(&mut self, mut other: Self) {
    self.publications.append(&mut other.publications);
    self.roots.append(&mut other.roots);
    self.subs.append(&mut other.subs);
    self.pending.append(&mut other.pending);
    self.values.append(&mut other.values);
    self.keys.append(&mut other.keys);
    self.events.append(&mut other.events);
    self.filters.append(&mut other.filters);
  }

  /// Retains a publication displaced out of the shared slot — including the one
  /// [`swap_in_empty`](Subsumer::swap_in_empty) hands back to a teardown.
  pub(crate) fn keep_publication(&mut self, publication: Arc<Published<C, V, H>>) {
    self.publications.push(publication);
  }

  /// Retains a caller value the driver salvaged from a request it is abandoning.
  pub(crate) fn keep_value(&mut self, value: V) {
    self.values.push(value);
  }

  /// Retains a key the driver salvaged from a request it is abandoning.
  pub(crate) fn keep_key(&mut self, key: Vec<C>) {
    self.keys.push(key);
  }

  /// Retains a delivery that was minted but never reached the consumer — a refused offer, or a
  /// buffered delta a retirement discards.
  pub(crate) fn keep_event(&mut self, event: Event<C, V>) {
    self.events.push(event);
  }

  /// Retains the caller half of an admission gate a retiring subscription handed back.
  pub(crate) fn keep_filter(&mut self, filter: Filter<C>) {
    self.filters.push(filter);
  }

  /// Whether this bundle holds nothing at all — the reading a cell takes to pin that a LIVE path
  /// deferred nothing. Never consulted to decide anything: the bundle is storage, not state.
  #[cfg(all(test, feature = "tokio"))]
  pub(crate) fn is_empty(&self) -> bool {
    self.publications.is_empty()
      && self.roots.is_empty()
      && self.subs.is_empty()
      && self.pending.is_empty()
      && self.values.is_empty()
      && self.keys.is_empty()
      && self.events.is_empty()
      && self.filters.is_empty()
  }

  /// How many admission gates this bundle holds — the reading a cell takes to BOUND what a
  /// teardown retains, where emptiness is the wrong question and a count is the right one. Never
  /// consulted to decide anything: the bundle is storage, not state.
  #[cfg(all(test, feature = "tokio"))]
  pub(crate) fn filters_len(&self) -> usize {
    self.filters.len()
  }

  /// Releases everything at the call site — the disposal a cell takes when it drives the engine
  /// directly and no teardown is in play.
  #[cfg(test)]
  pub(crate) fn release(self) {
    drop(self);
  }

  /// Retains a root record an index removal handed back.
  fn keep_root(&mut self, record: RootRecord<C, H>) {
    self.roots.push(record);
  }

  /// Retains a live-subscription record a side-table removal handed back.
  fn keep_sub(&mut self, record: SubRecord<C, H>) {
    self.subs.push(record);
  }

  /// Retains a not-yet-committed reservation an aborted plan handed back.
  fn keep_pending(&mut self, reservation: PendingWatch<C, V>) {
    self.pending.push(reservation);
  }
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
  /// Root handle → every caller subscription that root serves, in registration order — the
  /// **mutable routing cohort**, deliberately owner-local rather than a field of the immutable
  /// [`RootRecord`]. Fan-out iterates it; admission appends to it. Kept in lockstep with
  /// `by_handle`: an entry is created with its root, moved by [`rebind_root`](Self::rebind_root),
  /// and dropped when the root is emptied or force-removed.
  root_subs: HashMap<H, Vec<Subscription>>,
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
      .field("root_subs", &self.root_subs)
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
  /// Installs an **empty** read-plane snapshot in the shared slot — so every [`WatchView`] reader
  /// reports "nothing watched": `is_watched`/`covering`/`resolve` all empty and `contains`/`len`
  /// zero — and hands back the publication it DISPLACED rather than releasing it here. The driver
  /// empties the plane at owner teardown — on the normal path after draining owed Rescans, and
  /// unconditionally from the owner's `Drop` guard, so a panic in any caller callback still empties
  /// it: the authoritative watch-set is about to drop with the owner task and its source, so a
  /// retained view must stop advertising coverage whose owner and source no longer exist
  /// (design §5). Like [`publish`](Self::publish) the install itself is a single synchronous
  /// `arc_swap` swap of a fresh empty snapshot — idempotent, and running no caller `C`/`V`/`H`
  /// method (the two trees it installs are empty), so it needs no bounds and cannot itself panic,
  /// which makes it safe to call while unwinding.
  ///
  /// # Why the displaced snapshot comes back instead of being dropped
  ///
  /// Emptying the plane is TWO operations, and only the first is infallible. Installing the empty
  /// snapshot runs no caller code. **Releasing the one it replaces runs caller destructors**: that
  /// snapshot owns radix nodes holding caller `C` keys and `V` values, and it can be their LAST
  /// owner — a mutation that removed a value from the authoritative trees leaves it alive in the
  /// published snapshot alone until the next publish, so a caller callback that unwound out of a
  /// mutator between its commit and its [`publish`](Self::publish) strands exactly that. A `store`
  /// fuses the two, and the caller destructor then unwinds out of the *install's* call site.
  ///
  /// That is why this hands the snapshot back: the release is the caller's to place and to contain,
  /// while the install — the part the read-plane guarantee actually rests on — has already
  /// happened and cannot be undone by an unwinding `Drop`.
  #[must_use = "the displaced publication owns caller `C`/`V` values, so releasing it runs caller \
                destructors — place that release deliberately, inside an unwind boundary"]
  pub(crate) fn swap_in_empty(&self) -> Arc<Published<C, V, H>> {
    self.shared.swap(Arc::new(Published {
      roots: Radix::new(),
      covers: Radix::new(),
    }))
  }

  /// Re-installs a publication the caller previously took out of the slot, discarding whatever
  /// stands there now.
  ///
  /// Staging only, and there is no product caller: every mutator publishes FORWARD, so nothing but
  /// a panic can leave the slot holding a snapshot the authoritative trees have already moved past
  /// — and a panic sited precisely inside a mutator's commit-to-publish window needs a caller `C`
  /// whose `Clone` unwinds or a caller handle whose `Hash` does, both of which land mid-mutator by
  /// a call count that is the mutator's own business. A cell that wants the STATE (the published
  /// snapshot as the last owner of a departed `V`) rather than that call count assembles it here:
  /// take the snapshot out with [`swap_in_empty`](Self::swap_in_empty), mutate, put it back.
  #[cfg(all(test, feature = "tokio"))]
  pub(crate) fn test_reinstall_publication(&self, snapshot: Arc<Published<C, V, H>>) {
    self.shared.store(snapshot);
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
      root_subs: HashMap::new(),
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
  ///
  /// A SWAP rather than a store, and the displaced snapshot comes back rather than dying here, for
  /// the reason [`swap_in_empty`](Self::swap_in_empty) spells out at length: that snapshot holds
  /// the pre-mutation version of both trees, so it — not the commit above it — is the last owner of
  /// every node this mutation unlinked, and releasing it runs those caller `C`/`V` destructors. A
  /// store would run them inside the mutator, which is the one placement from which the unwind is
  /// guaranteed to leave through the caller's frame ahead of whatever that caller still owed. See
  /// [`Salvage`].
  #[must_use = "the displaced publication is the last owner of every node this mutation unlinked"]
  fn publish(&self) -> Arc<Published<C, V, H>> {
    self.shared.swap(Arc::new(Published {
      roots: self.index.clone(),
      covers: self.covers.clone(),
    }))
  }

  /// Records one more live subscription `sub` at `key` in the coverage plane, carrying its caller
  /// `value` for attribution (creating the [`CoverEntry`] if `key` was absent). Called on every
  /// committed `watch` regardless of outcome — `Disjoint`, `Widen`, and `Covered` all add a live
  /// subscription whose own key must answer `is_watched` truthfully **and** resolve to its own
  /// value.
  fn cover_add(&mut self, sub: Subscription, key: &[C], value: V, salvage: &mut Salvage<C, V, H>) {
    let mut txn = self.covers.txn();
    let mut entry = txn.get(key).cloned().unwrap_or_else(CoverEntry::new);
    salvage.values.extend(entry.push(sub, value));
    txn.insert(key, entry);
    self.covers = txn.commit();
  }

  /// Drops the live subscription `sub` at `key` from the coverage plane, removing the key once
  /// its last subscription is gone. Called on every `unwatch` and for every subscriber of a
  /// force-removed dead root, so `covers` tracks exactly the set of keys — and owning values —
  /// some live subscription still covers. The removed caller value goes into `salvage` rather than
  /// being destroyed here (see [`Salvage`]).
  fn cover_remove(&mut self, sub: Subscription, key: &[C], salvage: &mut Salvage<C, V, H>) {
    let mut txn = self.covers.txn();
    if let Some(mut entry) = txn.get(key).cloned() {
      salvage.values.extend(entry.remove(sub));
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
  pub(crate) fn plan_watch(&mut self, key: &[C], value: V, interest: Interest) -> WatchOutcome<H> {
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
      // Covered-OUTSIDE (the set-cover reconcile): the covering root's source coverage was narrowed (`retained_cover`
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
      if let Some(cohort) = self.root_subs.get(&record.handle) {
        repointed.extend_from_slice(cohort);
      }
      unwatch.push(record.handle);
    }
    if !unwatch.is_empty() {
      return WatchOutcome::Widen {
        repointed,
        unwatch,
        sub,
      };
    }

    // Case 3 — Disjoint: neither covered nor covering.
    WatchOutcome::Disjoint { sub }
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
  ///
  /// Returns the caller-owned state the commit displaced — above all the publication its republish
  /// swapped out, which is the last owner of every node this commit unlinked (see [`Salvage`]).
  pub(crate) fn commit_watch(
    &mut self,
    outcome: &WatchOutcome<H>,
    fs_root: H,
    fs_root_key: &[C],
  ) -> Salvage<C, V, H> {
    let mut salvage = Salvage::new();
    match outcome {
      WatchOutcome::Covered { sub, .. } => {
        let PendingWatch {
          key,
          value,
          interest,
        } = self.take_pending(*sub);
        // The routing cohort is owner-local, so admitting a covered subscription is a push —
        // the immutable root record is untouched and the radix is not re-committed at all.
        self
          .root_subs
          .get_mut(&fs_root)
          .expect("covered root is live")
          .push(*sub);
        // The covered subscription's own (narrower) key joins the coverage plane carrying its
        // OWN value — so `is_watched` stays truthful for it AND attribution resolves it to its
        // own value, never the covering root's (whose own watch may later depart, leaving the
        // armed root broader than any live subscription — design §5).
        self.cover_add(*sub, &key, value, &mut salvage);
        if let Some(displaced) = self.subs.insert(
          *sub,
          SubRecord {
            root: fs_root,
            key,
            interest,
          },
        ) {
          salvage.keep_sub(displaced);
        }
        salvage.keep_publication(self.publish());
      }
      WatchOutcome::Disjoint { sub, .. } => {
        // The reservation's own key is SUPERSEDED here by `fs_root_key` — the authoritative key the
        // source reported for the armed handle — so it is not stored. It is still the caller's
        // `Vec<C>`, and destroying it here would run caller destructors inside a half-applied
        // mutation; it leaves by the same door every other removal does.
        let PendingWatch {
          key: superseded,
          value,
          interest,
        } = self.take_pending(*sub);
        salvage.keep_key(superseded);
        let root_key = fs_root_key.to_vec();
        let record = RootRecord {
          key: root_key.clone(),
          handle: fs_root,
          // A freshly-armed root covers its whole key (`Interest::all`) — full coverage, never
          // narrowed (a set-cover prune).
          retained_cover: None,
        };
        let mut txn = self.index.txn();
        if let Some(displaced) = txn.insert(root_key.as_slice(), record) {
          salvage.keep_root(displaced);
        }
        self.index = txn.commit();
        if let Some(displaced) = self.by_handle.insert(fs_root, root_key.clone()) {
          salvage.keep_key(displaced);
        }
        self.root_subs.insert(fs_root, std::vec![*sub]);
        // The disjoint root's own subscription joins the coverage plane carrying its value, so
        // attribution resolves the root and its descendants to it (the value plane lives on
        // `covers`, not the armed root — design §5).
        self.cover_add(*sub, &root_key, value, &mut salvage);
        if let Some(displaced) = self.subs.insert(
          *sub,
          SubRecord {
            root: fs_root,
            key: root_key,
            interest,
          },
        ) {
          salvage.keep_sub(displaced);
        }
        salvage.keep_publication(self.publish());
      }
      WatchOutcome::Widen {
        repointed,
        unwatch,
        sub,
        ..
      } => {
        // Superseded by `fs_root_key`, exactly as on the `Disjoint` arm above, and placed rather
        // than destroyed for the same reason.
        let PendingWatch {
          key: superseded,
          value,
          interest,
        } = self.take_pending(*sub);
        salvage.keep_key(superseded);
        let root_key = fs_root_key.to_vec();

        let mut subscribers = repointed.clone();
        subscribers.push(*sub);
        let record = RootRecord {
          key: root_key.clone(),
          handle: fs_root,
          // The wider root is freshly armed `Interest::all` over its whole key — full coverage,
          // never narrowed (any pending set_cover for the released subsumed handles is moot);
          // set-cover .
          retained_cover: None,
        };

        // Drop the subsumed roots' index keys and install the wider root atomically:
        // remove every strict descendant of the wider key (exactly the subsumed set,
        // which the driver's `fs_path_preserves_plan` guard verified), then insert.
        let mut txn = self.index.txn();
        // The subsumed roots' records go with their keys. `remove_descendants` clones no removed
        // value, so those records are freed only when the last version holding them dies — the
        // publication salvaged below.
        txn.remove_descendants(root_key.as_slice());
        if let Some(displaced) = txn.insert(root_key.as_slice(), record) {
          salvage.keep_root(displaced);
        }
        self.index = txn.commit();

        for old in unwatch {
          salvage.keys.extend(self.by_handle.remove(old));
          self.root_subs.remove(old);
        }
        if let Some(displaced) = self.by_handle.insert(fs_root, root_key.clone()) {
          salvage.keep_key(displaced);
        }
        self.root_subs.insert(fs_root, subscribers);
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
        self.cover_add(*sub, &root_key, value, &mut salvage);
        if let Some(displaced) = self.subs.insert(
          *sub,
          SubRecord {
            root: fs_root,
            key: root_key,
            interest,
          },
        ) {
          salvage.keep_sub(displaced);
        }
        salvage.keep_publication(self.publish());
      }
    }
    salvage
  }

  /// Abandons the plan `outcome` without committing it, **handing back** the pending reservation
  /// `plan_watch` stashed. Call this on every path where arming failed, so the not-yet-committed
  /// subscription's pending entry cannot leak. Idempotent per plan (consuming an already-committed
  /// or already-aborted id yields an empty bundle). No watch-set change committed, so nothing is
  /// republished.
  ///
  /// The reservation holds the caller's key AND the caller's value, so destroying it here would run
  /// two caller destructors inside the funnel — invisibly, since the old signature returned nothing
  /// and the removal read as bookkeeping. Every one of this method's call sites is an abandoned
  /// reconcile, and several of them are TERMINAL: they hold a consumed [`CloseReply`] that the run
  /// tail still has to answer with the source's quiescence verdict, which an unwind out of here
  /// would downgrade to a dropped sender. So it hands the reservation back (see [`Salvage`]).
  pub(crate) fn abort_watch(&mut self, outcome: &WatchOutcome<H>) -> Salvage<C, V, H> {
    let sub = match outcome {
      WatchOutcome::Covered { sub, .. }
      | WatchOutcome::Widen { sub, .. }
      | WatchOutcome::Disjoint { sub, .. } => *sub,
    };
    let mut salvage = Salvage::new();
    if let Some(reservation) = self.pending.remove(&sub) {
      salvage.keep_pending(reservation);
    }
    salvage
  }

  /// Removes `sub`, reporting whether its root emptied (returns `None` for an unknown
  /// subscription). Mutates immediately and republishes — no commit step is needed.
  ///
  /// On the non-emptied ([`Dropped`](UnwatchOutcome::Dropped)) path it also reports
  /// whether the armed root is now **over-broad** and the source may shrink its coverage
  /// in place (the set-cover design) — see [`detect_shrink`](Self::detect_shrink).
  ///
  /// The caller-owned state the departure removed — the subscription record, its cover value, the
  /// reverse-index key, the displaced publication — travels back in the [`Salvage`] rather than
  /// being destroyed here. The bundle is returned even on the unknown-subscription path, where it
  /// is empty, so the disposal is uniform.
  pub(crate) fn plan_unwatch(
    &mut self,
    sub: Subscription,
  ) -> (Option<UnwatchOutcome<C, H>>, Salvage<C, V, H>) {
    let mut salvage = Salvage::new();
    let Some(record) = self.subs.remove(&sub) else {
      return (None, salvage);
    };
    let root_key = self
      .by_handle
      .get(&record.root)
      .expect("live subscription's root is live")
      .clone();

    // The routing cohort is owner-local: a departure is a retain over it, never a clone of the
    // immutable root record.
    let cohort = self
      .root_subs
      .get_mut(&record.root)
      .expect("live subscription's root has a cohort");
    cohort.retain(|&s| s != sub);
    let emptied = cohort.is_empty();
    // The surviving subscribers — the over-broadness detection reads their keys (each still
    // live in `self.subs`).
    let survivors = cohort.clone();
    if emptied {
      let mut txn = self.index.txn();
      if let Some(removed) = txn.remove(root_key.as_slice()) {
        salvage.keep_root(removed);
      }
      self.index = txn.commit();
    }

    // Drop this subscription from the coverage plane (the root may live on for its other,
    // narrower subscribers, and the key stays covered iff another live sub shares it).
    self.cover_remove(sub, &record.key, &mut salvage);

    let outcome = if emptied {
      salvage.keys.extend(self.by_handle.remove(&record.root));
      self.root_subs.remove(&record.root);
      UnwatchOutcome::RootEmptied {
        fs_root: record.root,
      }
    } else {
      // The root lives on for its narrower subscribers; report whether the departure left the source
      // coverage reclaimable — either newly over-broad (full coverage, the root-key sub departed) or
      // an already-narrowed cover that can shrink further (a non-root sub departed — F2).
      let shrink = self.detect_shrink(&root_key, record.root, &survivors, &mut salvage);
      UnwatchOutcome::Dropped { shrink }
    };
    salvage.keep_publication(self.publish());
    // The departing subscription's own record — its key is the caller's — leaves by the same door.
    salvage.keep_sub(record);
    salvage.keep_key(root_key);
    (Some(outcome), salvage)
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
    salvage: &mut Salvage<C, V, H>,
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
    // root is not emptied on this path, so it is present). BORROWED, not cloned: this is a pure
    // comparison, and a deep clone here would be one more copy of the caller's components for this
    // frame to dispose of.
    let recorded = self
      .index
      .get(root_key)
      .and_then(|record| record.retained_cover.as_ref());
    match recorded {
      // Full coverage: a survivor still at the root key keeps the wide coverage legitimately watched
      // — not over-broad.
      None => {
        if survivor_keys.iter().any(|key| key.as_slice() == root_key) {
          // Nothing to reclaim, and the survivors' cloned keys are still caller components.
          salvage.keys.extend(survivor_keys);
          return None;
        }
        Some((root_handle, antichain(survivor_keys, salvage)))
      }
      // Already narrowed: re-prune iff the survivors' antichain is strictly narrower than the
      // recorded cover — unequal AND contained by it. A survivor OUTSIDE the recorded cover
      // means the record is DEGRADED (a live-root source `Rescan` rewound the claim to the
      // empty cover): the survivors' keys are not proof of coverage there, and re-pruning
      // would RECORD a cover the source never re-proved — the fire-and-forget `set_cover`
      // retains-and-releases, it never establishes — so a later newcomer under it would
      // classify Covered-INSIDE and commit over the unproven region. Skip the reclaim and
      // keep the degraded record: it broadens only through an awaited successful grow.
      Some(cover) => {
        let survivor_antichain = antichain(survivor_keys, salvage);
        let contained = survivor_antichain
          .iter()
          .all(|key| cover.iter().any(|c| key.starts_with(c.as_slice())));
        if contained && survivor_antichain != *cover {
          return Some((root_handle, survivor_antichain));
        }
        // No reclaim: the antichain is not issued to anyone, so its keys go back the same way the
        // pruned ones already did.
        salvage.keys.extend(survivor_antichain);
        None
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
    salvage: &mut Salvage<C, V, H>,
  ) -> Option<Vec<Vec<C>>> {
    let root_key = self.by_handle.get(&handle)?;
    self.index.get(root_key)?;
    let mut subscriber_keys: Vec<Vec<C>> = self
      .root_subs
      .get(&handle)
      .map_or(&[][..], Vec::as_slice)
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
      // Nothing to reclaim, and the cloned subscriber keys are still caller components.
      salvage.keys.extend(subscriber_keys);
      return None;
    }
    Some(antichain(subscriber_keys, salvage))
  }

  /// [`retained_cover_for`](Self::retained_cover_for) with its [`Salvage`] released at the call
  /// site, for the same reason [`test_plan_unwatch`](Self::test_plan_unwatch) exists.
  #[cfg(test)]
  pub(crate) fn test_retained_cover_for(
    &self,
    handle: H,
    newcomer: Option<&[C]>,
  ) -> Option<Vec<Vec<C>>> {
    let mut salvage = Salvage::new();
    let cover = self.retained_cover_for(handle, newcomer, &mut salvage);
    salvage.release();
    cover
  }

  /// Records the source's ACTUAL coverage for the root `handle` (the set-cover record) — the bookkeeping
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
  pub(crate) fn set_retained_cover(
    &mut self,
    handle: H,
    cover: Option<Vec<Vec<C>>>,
  ) -> Salvage<C, V, H> {
    let mut salvage = Salvage::new();
    let Some(root_key) = self.by_handle.get(&handle).cloned() else {
      return salvage;
    };
    let mut txn = self.index.txn();
    let Some(mut record) = txn.get(&root_key).cloned() else {
      // The reverse-index key was cloned out to look the record up, so even the nothing-to-do exit
      // owns a caller `Vec<C>` — placed here rather than destroyed by this frame, exactly as on the
      // path below.
      salvage.keep_key(root_key);
      return salvage;
    };
    // The record this replaces carries the previous cover — caller `C` components — so it leaves
    // by the same door every other removal does (see [`Salvage`]). TWO copies exist: the displaced
    // record `insert` hands back below, and this clone's own, which a plain assignment would
    // destroy right here. Both are placed.
    salvage.keys.extend(
      core::mem::replace(&mut record.retained_cover, cover)
        .into_iter()
        .flatten(),
    );
    if let Some(displaced) = txn.insert(root_key.as_slice(), record) {
      salvage.keep_root(displaced);
    }
    self.index = txn.commit();
    salvage.keep_publication(self.publish());
    salvage.keep_key(root_key);
    salvage
  }

  /// Degrades a NARROWED retained-cover record (`Some(cover)`) for the root `handle` to the
  /// EMPTY cover — the claim that nothing below the root is source-covered — so every later
  /// newcomer under it classifies Covered-OUTSIDE and re-proves coverage through
  /// [`grow`](crate::LocalSource::grow) before its commit broadens the record again. The
  /// response to a live-root source `Rescan`: the loss signal means the recorded claim may
  /// span a hole, and trusting it would commit newcomers with no kernel backing. A
  /// never-narrowed record (`None` — full coverage, healed by the source's own re-arm
  /// machinery), an already-empty record, and an unknown handle are untouched.
  pub(crate) fn degrade_retained_cover(&mut self, handle: H) -> Salvage<C, V, H> {
    let mut salvage = Salvage::new();
    let Some(root_key) = self.by_handle.get(&handle).cloned() else {
      return salvage;
    };
    let Some(record) = self.index.get(&root_key) else {
      salvage.keep_key(root_key);
      return salvage;
    };
    // The ORDINARY no-op — a never-narrowed or already-empty record — and it owns the cloned
    // reverse-index key just as much as the mutating path does.
    if record.retained_cover.as_ref().is_none_or(Vec::is_empty) {
      salvage.keep_key(root_key);
      return salvage;
    }
    let mut record = record.clone();
    // The clone's own copy of the previous cover, overwritten here — placed rather than destroyed
    // inside the mutator, exactly as in `set_retained_cover`.
    salvage.keys.extend(
      record
        .retained_cover
        .replace(Vec::new())
        .into_iter()
        .flatten(),
    );
    let mut txn = self.index.txn();
    if let Some(displaced) = txn.insert(root_key.as_slice(), record) {
      salvage.keep_root(displaced);
    }
    self.index = txn.commit();
    salvage.keep_publication(self.publish());
    salvage.keep_key(root_key);
    salvage
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

  /// The live root `fs_root`'s key together with its **routing cohort** — the subscriber list
  /// fan-out iterates, held owner-local rather than inside the immutable record (see
  /// [`RootRecord`]). `None` for a handle naming no live root.
  pub(crate) fn root_view(&self, fs_root: H) -> Option<(&[C], &[Subscription])> {
    let key = self.by_handle.get(&fs_root)?;
    let record = self.index.get(key)?;
    let cohort = self.root_subs.get(&fs_root).map_or(&[][..], Vec::as_slice);
    Some((record.key.as_slice(), cohort))
  }

  /// The routing cohort of the live root `fs_root` — empty for a handle naming no live root.
  #[cfg(test)]
  pub(crate) fn subscribers(&self, fs_root: H) -> &[Subscription] {
    self.root_subs.get(&fs_root).map_or(&[][..], Vec::as_slice)
  }

  /// Force-drops the root `handle` and every subscriber riding it, returning those
  /// subscribers so the driver can reclaim their per-subscription state (filter, epoch
  /// ledger) — the **dead-root retirement** (design §4, invariant I4). A watched root
  /// died (the source tore its handle down and emitted a terminal `Rescan`, already fanned
  /// out to every subscriber), so the dead root is torn out of index / reverse-index /
  /// side-table and no later event routes to its dead handle. Republishes.
  pub(crate) fn force_remove_root(&mut self, handle: H) -> (Vec<Subscription>, Salvage<C, V, H>) {
    let mut salvage = Salvage::new();
    let Some(root_key) = self.by_handle.remove(&handle) else {
      return (Vec::new(), salvage);
    };
    let mut txn = self.index.txn();
    salvage.keep_root(
      txn
        .remove(root_key.as_slice())
        .expect("force-removed root record"),
    );
    self.index = txn.commit();
    let subscribers = self.root_subs.remove(&handle).unwrap_or_default();
    // Free the dead root's subscribers from the side table AND the coverage plane, so a
    // retired root's keys stop answering `is_watched` true (they cover nothing now).
    //
    // EVERY removed side-table record is retained FIRST, before any grouping. Several
    // subscriptions may share one key, and a grouping keyed by an OWNED `Vec<C>` destroys every
    // duplicate the moment its entry is found occupied — caller destructors running inside the
    // mutator, which is the one placement the bundle exists to keep them out of, and which no
    // `#[must_use]` on the return can see. The grouping below therefore borrows the retained keys
    // and owns none of them.
    let retained_from = salvage.subs.len();
    let mut departing_subs = Vec::with_capacity(subscribers.len());
    for &sub in &subscribers {
      if let Some(sub_record) = self.subs.remove(&sub) {
        salvage.keep_sub(sub_record);
        departing_subs.push(sub);
      }
    }
    // BATCHED per cover key: the per-subscriber `cover_remove` cloned the
    // whole same-key cohort entry once per departing member — O(cohort squared) deep
    // value clones plus a txn commit each. Grouping the departures by key makes the
    // conversion genuinely linear: one entry clone, one retain pass, and one commit
    // for the whole root.
    let mut departing_by_key: std::collections::BTreeMap<
      &[C],
      std::collections::HashSet<Subscription>,
    > = std::collections::BTreeMap::new();
    for (&sub, record) in departing_subs.iter().zip(&salvage.subs[retained_from..]) {
      departing_by_key
        .entry(record.key.as_slice())
        .or_default()
        .insert(sub);
    }
    let mut txn = self.covers.txn();
    for (key, departing) in departing_by_key {
      if let Some(mut entry) = txn.get(key).cloned() {
        entry.remove_all(&departing, &mut salvage.values);
        if entry.is_empty() {
          txn.remove(key);
        } else {
          txn.insert(key, entry);
        }
      }
    }
    self.covers = txn.commit();
    salvage.keep_publication(self.publish());
    salvage.keep_key(root_key);
    (subscribers, salvage)
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
  pub(crate) fn rebind_root(&mut self, old: H, new: H) -> Salvage<C, V, H> {
    let mut salvage = Salvage::new();
    let Some(root_key) = self.by_handle.get(&old).cloned() else {
      return salvage;
    };
    let mut txn = self.index.txn();
    let Some(mut record) = txn.get(&root_key).cloned() else {
      salvage.keep_key(root_key);
      return salvage;
    };
    record.handle = new;
    if let Some(displaced) = txn.insert(root_key.as_slice(), record) {
      salvage.keep_root(displaced);
    }
    self.index = txn.commit();
    salvage.keys.extend(self.by_handle.remove(&old));
    if let Some(displaced) = self.by_handle.insert(new, root_key) {
      salvage.keep_key(displaced);
    }
    let subscribers = self.root_subs.remove(&old).unwrap_or_default();
    for &sub in &subscribers {
      if let Some(side) = self.subs.get_mut(&sub) {
        side.root = new;
      }
    }
    self.root_subs.insert(new, subscribers);
    salvage.keep_publication(self.publish());
    salvage
  }

  /// [`plan_unwatch`](Self::plan_unwatch) with its [`Salvage`] released at the call site — the
  /// disposal a cell that drives the engine directly wants, there being no teardown to hold it for.
  #[cfg(test)]
  pub(crate) fn test_plan_unwatch(&mut self, sub: Subscription) -> Option<UnwatchOutcome<C, H>> {
    let (outcome, salvage) = self.plan_unwatch(sub);
    salvage.release();
    outcome
  }

  /// [`force_remove_root`](Self::force_remove_root) with its [`Salvage`] released at the call site,
  /// for the same reason [`test_plan_unwatch`](Self::test_plan_unwatch) exists.
  #[cfg(test)]
  pub(crate) fn test_force_remove_root(&mut self, handle: H) -> Vec<Subscription> {
    let (subscribers, salvage) = self.force_remove_root(handle);
    salvage.release();
    subscribers
  }

  /// The key a live subscription was registered at, if any (its entry in the §4 side
  /// table).
  pub(crate) fn subscription_key(&self, sub: Subscription) -> Option<&[C]> {
    self.subs.get(&sub).map(|record| record.key.as_slice())
  }

  /// The ROOT a live subscription rides — the handle its events (and its sync
  /// cookie) belong to. One subscription never spans roots, so this is total
  /// for a live sub and `None` once it is gone.
  pub(crate) fn subscription_root(&self, sub: Subscription) -> Option<H>
  where
    H: Copy,
  {
    self.subs.get(&sub).map(|record| record.root)
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
fn antichain<C: Ord, V, H>(mut keys: Vec<Vec<C>>, salvage: &mut Salvage<C, V, H>) -> Vec<Vec<C>> {
  keys.sort();
  // Both prunings — the duplicates and the covered descendants — hand the key back rather than
  // destroying it: `keys` is built by CLONING live subscribers' keys, so each one is caller
  // components, and this runs inside `plan_unwatch`, which the teardown tail's queued grant cleanup
  // reaches with everything that teardown owes still ahead of it.
  let mut deduped: Vec<Vec<C>> = Vec::with_capacity(keys.len());
  for key in keys {
    if deduped.last().is_some_and(|last| *last == key) {
      salvage.keep_key(key);
    } else {
      deduped.push(key);
    }
  }
  // Drop `key` iff some strictly-shorter OTHER key is a proper prefix (ancestor) of it.
  let covered: Vec<bool> = deduped
    .iter()
    .map(|key| {
      deduped
        .iter()
        .any(|other| other.len() < key.len() && key.starts_with(other.as_slice()))
    })
    .collect();
  let mut kept = Vec::with_capacity(deduped.len());
  for (key, covered) in deduped.into_iter().zip(covered) {
    if covered {
      salvage.keep_key(key);
    } else {
      kept.push(key);
    }
  }
  kept
}
