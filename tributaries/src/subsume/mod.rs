//! The sans-I/O overlap-subsumption engine, generic over the key component `C`, the
//! caller value `V`, and the armed-root handle `H`.
//!
//! This is the control plane of the umbrella crate: a pure state machine that folds
//! possibly-**overlapping** caller subscriptions into the pairwise-disjoint roots the
//! source ([`tributary-fs`](tributary_fs) for 0.1.0) requires. It performs **no** I/O,
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
use tributary_proto::{Interest, ScopeId};

use crate::{subscription::Subscription, view::WatchView};

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
/// self-healing; re-narrowing the arm is deferred to M2).
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
#[derive(Debug, Clone)]
pub(crate) struct RootRecord<C, H> {
  /// The root's key (== its radix key).
  pub(crate) key: Vec<C>,
  /// The armed root handle.
  pub(crate) handle: H,
  /// Every caller subscription this root serves, in registration order.
  pub(crate) subscribers: Vec<Subscription>,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnwatchOutcome<H> {
  /// The subscription was removed; its root still serves other subscribers.
  Dropped,
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
/// `H` is testable with a trivial handle type (e.g. `u32`); the driver instantiates
/// it at `H = tributary_fs::RootHandle`. Maintains the authoritative immutable
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
      next_sub: NonZeroU64::MIN,
      shared,
    }
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

  /// Publishes an **empty** read-plane snapshot into the shared slot, so every [`WatchView`]
  /// reader reports "nothing watched" — `is_watched`/`covering`/`resolve` all empty and
  /// `contains`/`len` zero. The driver calls this once at owner teardown: the authoritative
  /// watch-set is about to drop with the owner task and its source, so a retained view must stop
  /// advertising coverage whose owner and source no longer exist (design §5). Like
  /// [`publish`](Self::publish) it is a single synchronous `arc_swap` store, so wait-free readers
  /// never block.
  pub(crate) fn publish_empty(&self) {
    self.shared.store(Arc::new(Published {
      roots: Radix::new(),
      covers: Radix::new(),
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
      return WatchOutcome::Covered {
        fs_root: record.handle,
        sub,
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
  pub(crate) fn plan_unwatch(&mut self, sub: Subscription) -> Option<UnwatchOutcome<H>> {
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
      UnwatchOutcome::Dropped
    };
    self.publish();
    Some(outcome)
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
    for &sub in &record.subscribers {
      // Free the dead root's subscribers from the side table AND the coverage plane, so a
      // retired root's keys stop answering `is_watched` true (they cover nothing now).
      if let Some(sub_record) = self.subs.remove(&sub) {
        self.cover_remove(sub, &sub_record.key);
      }
    }
    self.publish();
    record.subscribers
  }

  /// Rebinds the live root `old` onto a fresh handle `new`, keeping its key, record, and
  /// subscribers — the **re-arm restore** the driver runs when a failed widen must put its
  /// disarmed subsumed roots back (design driver-golden doc, invariant I3). A disarm then
  /// re-arm at the *same* key yields a new source handle, so the record's handle, the
  /// reverse index, and every subscriber's ridden-root pointer must move to it; no key
  /// changes, so the coverage plane is untouched. A no-op if `old` is not a live root.
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

  /// Mints the next subscription id from the engine's monotonic counter.
  fn mint_subscription(&mut self) -> Subscription {
    let next = self.next_sub;
    self.next_sub = self
      .next_sub
      .checked_add(1)
      .expect("subscription id space (u64) exhausted");
    Subscription::new(ScopeId::new(next))
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
