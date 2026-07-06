//! The sans-I/O overlap-subsumption engine.
//!
//! This is the control plane of the umbrella crate: a pure state machine that
//! folds possibly-**overlapping** caller subscriptions into the pairwise-disjoint
//! roots [`tributary-fs`](tributary_fs) requires. It performs **no** I/O, reads no
//! clock, and knows nothing of any runtime — it is exhaustively property-testable
//! over paths and an abstract root-id alone.
//!
//! # Coordinate system
//!
//! Everything operates in one canonical-path space: the form `tributary-fs` itself
//! reports (its own canonicalized root paths and reconstructed event paths). The
//! engine never re-implements canonicalization; it keys off what fs already
//! canonicalized. The subsumption index is an [`iradix`] radix keyed by a canonical
//! path's **components** (via iradix's built-in [`Path`] key, which stores one
//! `OsString` per component), so `/a/b` is an ancestor of `/a/b/c` but not `/a/bc`.
//!
//! # Plan / commit split
//!
//! A `watch` cannot mutate committed state up front: the real fs root handle does
//! not exist until *after* the kernel watch is armed, and if that arming fails no
//! state may have changed. So [`Subsumer::plan_watch`] is a pure read that returns
//! a [`WatchOutcome`] describing the fs operations the driver must perform, and
//! [`Subsumer::commit_watch`] applies the state transition once the real handle is
//! known. `unwatch` needs no such split — the handle already exists — so
//! [`Subsumer::plan_unwatch`] mutates immediately and reports whether the root
//! emptied (so the driver can release the kernel watch).
//!
//! [`Path`]: std::path::Path

use core::num::NonZeroU64;
use std::{
  collections::HashMap,
  ffi::OsString,
  hash::Hash,
  path::{Path, PathBuf},
  vec::Vec,
};

use tributary_proto::{Interest, ScopeId};

use crate::subscription::Subscription;

#[cfg(test)]
mod tests;

/// One live root's registry record.
///
/// The design sketch's `fs_root` is the [`entries`](Subsumer) map key — every
/// accessor hands the entry back alongside that handle — so the record stores no
/// redundant copy and needs no root-id type parameter. It carries the root's
/// canonical `path`, needed to check coverage (that every subscriber's path descends
/// from this root) and to key the subsumption index.
///
/// It stores **no** interest: every umbrella root is armed [`Interest::all`]
/// (design §4), so the kernel watch never narrows what it collects and there is no
/// per-root union to track. Each subscription's own interest is a fan-out gate held
/// in its [`SubRecord`], not a property of the shared root.
#[derive(Debug, Clone)]
pub(crate) struct RootEntry {
  /// The root's canonical path (the subsumption-index key for this entry).
  pub(crate) path: PathBuf,
  /// Every caller subscription this root serves, in registration order.
  pub(crate) subscribers: Vec<Subscription>,
}

/// The plan [`Subsumer::plan_watch`] produces: which fs operations the driver must
/// perform for one `watch`, before the state transition is committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WatchOutcome<R> {
  /// The subtree is already watched by an existing root at or above `path`. No new
  /// kernel watch: `commit_watch` just adds `sub` to that root's subscribers.
  Covered {
    /// The existing root handle covering the new subscription.
    fs_root: R,
    /// The new subscription.
    sub: Subscription,
  },
  /// `path` is a strict ancestor of one or more existing roots, which it subsumes.
  /// The driver must **release the subsumed roots (`unwatch`) first, then arm** the
  /// wider watch at `new_root_path` (always [`Interest::all`], design §4) — the lower
  /// watcher rejects a root overlapping a live one (`Overlaps`), so the wider root
  /// cannot be armed while a subsumed one is live. The brief coverage gap between the
  /// two is closed by the dominating `Rescan` each re-pointed subscriber receives.
  /// `commit_watch` re-points `repointed` (and adds the new `sub`) onto the wider
  /// root. No interest union is carried — every root is armed `Interest::all`, so a
  /// widen never has to widen a narrower root's mask.
  Widen {
    /// The canonical path of the new, wider root (equal to the new subscription's
    /// own canonical path).
    new_root_path: PathBuf,
    /// The subscribers of every subsumed root, to re-point onto the wider root, in
    /// deterministic (root key, then registration) order.
    repointed: Vec<Subscription>,
    /// The subsumed fs root handles the driver must release, in root-key order.
    unwatch: Vec<R>,
    /// The new subscription.
    sub: Subscription,
  },
  /// `path` neither is covered by nor covers any existing root. The driver arms a
  /// fresh watch (always [`Interest::all`], design §4); `commit_watch` records the
  /// new root once its handle is known.
  Disjoint {
    /// The canonical path of the fresh root (equal to the subscription's path).
    root_path: PathBuf,
    /// The new subscription.
    sub: Subscription,
  },
}

/// The result of [`Subsumer::plan_unwatch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnwatchOutcome<R> {
  /// The subscription was removed; its root still serves other subscribers.
  Dropped,
  /// The subscription was its root's last: the driver must release the kernel
  /// watch on `fs_root` (the engine has already dropped the root's state).
  RootEmptied {
    /// The now-empty root handle to release.
    fs_root: R,
  },
}

/// One subscription's side-table record: the root it currently rides, its own
/// canonical path, and its own [`Interest`] (the §4 `Subscription ->
/// (canonical_path, fs_root, Interest, …)` table; the `Filter` half lives in the
/// driver's swappable map). Because every root is armed [`Interest::all`], a
/// subscription's `interest` is purely a fan-out gate (design §4/§5), not something
/// that ever narrows the kernel watch.
#[derive(Debug, Clone)]
struct SubRecord<R> {
  root: R,
  path: PathBuf,
  interest: Interest,
}

/// The sans-I/O overlap-subsumption engine.
///
/// Generic over the opaque fs root id `R` so it is testable with a trivial handle
/// type (e.g. `u32`); the driver instantiates it at `R = tributary_fs::RootHandle`.
/// Maintains three coupled structures: an [`iradix`] index mapping each canonical
/// root path to its handle (the subsumption / ancestor-query plane), a map from
/// handle to its [`RootEntry`] (the O(1) per-root record), and a side table from
/// each live subscription to the root it rides.
pub(crate) struct Subsumer<R> {
  /// Canonical-path-components → fs root handle. The disjointness / ancestor plane.
  index: iradix::unsync::Radix<OsString, R>,
  /// fs root handle → its live record. O(1); the authoritative per-root state.
  entries: HashMap<R, RootEntry>,
  /// Live subscription → the root it rides, its own canonical path, and its interest.
  subs: HashMap<Subscription, SubRecord<R>>,
  /// The canonical path **and interest** of not-yet-committed subscriptions, keyed by
  /// the id each `plan_watch` freshly minted. A plan stashes under its own new id, and
  /// the paired `commit_watch` / `abort_watch` consumes exactly that id — so plans
  /// never collide and may interleave freely; the only requirement is that every
  /// plan is eventually committed (arm succeeded) OR aborted (arm failed), which
  /// [`Subsumer::abort_watch`] makes enforceable rather than a bare convention.
  pending: HashMap<Subscription, (PathBuf, Interest)>,
  /// The next subscription id to mint. Monotonic and never reused, so a re-pointed
  /// or dropped-and-re-added subscription never aliases a live one.
  next_sub: NonZeroU64,
}

// `iradix::unsync::Radix` is not `Debug`; the entries map is the authoritative
// state, so it stands in for the index (which merely mirrors its paths).
impl<R: core::fmt::Debug> core::fmt::Debug for Subsumer<R> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("Subsumer")
      .field("entries", &self.entries)
      .field("subs", &self.subs)
      .field("pending", &self.pending)
      .finish()
  }
}

impl<R> Default for Subsumer<R>
where
  R: Copy + Eq + Hash,
{
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

impl<R> Subsumer<R>
where
  R: Copy + Eq + Hash,
{
  /// Creates an empty engine.
  pub(crate) fn new() -> Self {
    Self {
      index: iradix::unsync::Radix::new(),
      entries: HashMap::new(),
      subs: HashMap::new(),
      pending: HashMap::new(),
      next_sub: NonZeroU64::MIN,
    }
  }

  /// Plans a `watch` of `canonical` (already in the fs canonical-path space) with
  /// `interest`, returning the fs operations the driver must perform. Reads only;
  /// the state transition is applied by the paired [`commit_watch`](Self::commit_watch).
  ///
  /// The new subscription's id is minted from the engine's own monotonic counter,
  /// so overlapping subscriptions never collide even when they subsume onto one
  /// kernel watch.
  pub(crate) fn plan_watch(&mut self, canonical: &Path, interest: Interest) -> WatchOutcome<R> {
    let sub = self.mint_subscription();
    self
      .pending
      .insert(sub, (canonical.to_path_buf(), interest));

    // Case 1 — Covered: an existing root at or above `canonical` already watches
    // this subtree. Disjointness guarantees at most one such ancestor, and its
    // presence rules out any strict descendant, so this short-circuits cleanly. The
    // covering root is already armed `Interest::all` (design §4), so it carries every
    // kind this newcomer could ask for — the newcomer's interest is applied only as a
    // fan-out gate, never as a demand on the shared watch.
    if let Some(&fs_root) = self.index.get_ancestor(canonical) {
      return WatchOutcome::Covered { fs_root, sub };
    }

    // Case 2 — Widen: `canonical` is a strict ancestor of one or more existing
    // roots, which it now subsumes. Collect them in canonical-path order (iradix
    // yields strict descendants ascending), gathering their handles to release and
    // their subscribers to re-point. No interest union is computed — every root is
    // armed `Interest::all`, so the wider root already carries every subsumed
    // subscription's kinds (design §4).
    let mut unwatch = Vec::new();
    let mut repointed = Vec::new();
    for &subsumed in self.index.descendants(canonical) {
      let entry = &self.entries[&subsumed];
      repointed.extend_from_slice(&entry.subscribers);
      unwatch.push(subsumed);
    }
    if !unwatch.is_empty() {
      return WatchOutcome::Widen {
        new_root_path: canonical.to_path_buf(),
        repointed,
        unwatch,
        sub,
      };
    }

    // Case 3 — Disjoint: neither covered nor covering.
    WatchOutcome::Disjoint {
      root_path: canonical.to_path_buf(),
      sub,
    }
  }

  /// Commits the state transition for `outcome`, binding the real `fs_root` the
  /// driver obtained by arming the watch and keying the root at `fs_root_path` — the
  /// **authoritative canonical path fs reports** for the armed handle
  /// (`Watcher::root_path`), which closes the canonicalization TOCTOU (design §4): a
  /// component that swapped between the umbrella's provisional canonicalization and
  /// fs's would otherwise leave events prefixed by fs's path while the subsumer
  /// recorded the umbrella's. The newcomer's own coverage path is re-keyed into the
  /// same coordinate — for a fresh (`Disjoint`) or widened (`Widen`) root the
  /// newcomer's canonical path *equals* the root path, so its side-table path is
  /// simply `fs_root_path`.
  ///
  /// For [`WatchOutcome::Covered`] no arm happened (the covering root was armed —
  /// and its fs path validated — when it was first created), so `fs_root_path` is
  /// ignored and the newcomer's provisional canonical path is used unchanged; it is
  /// already an ancestor-or-equal descendant of the covering root's fs-canonical key.
  ///
  /// The driver must only pass an `fs_root_path` whose subsumption relative to the
  /// existing roots matches the plan (same case: fresh-disjoint stays disjoint, or a
  /// widen subsumes exactly the planned roots); a divergence is caught by the driver
  /// before committing (it re-queries and aborts), so this method never has to
  /// re-plan.
  pub(crate) fn commit_watch(
    &mut self,
    outcome: &WatchOutcome<R>,
    fs_root: R,
    fs_root_path: &Path,
  ) {
    match outcome {
      WatchOutcome::Covered { sub, .. } => {
        let (path, interest) = self.take_pending(*sub);
        self
          .entries
          .get_mut(&fs_root)
          .expect("covered root exists")
          .subscribers
          .push(*sub);
        self.subs.insert(
          *sub,
          SubRecord {
            root: fs_root,
            path,
            interest,
          },
        );
      }
      WatchOutcome::Disjoint { sub, .. } => {
        let (_planned, interest) = self.take_pending(*sub);
        let root_path = fs_root_path.to_path_buf();
        self.index.insert(root_path.as_path(), fs_root);
        self.entries.insert(
          fs_root,
          RootEntry {
            path: root_path.clone(),
            subscribers: std::vec![*sub],
          },
        );
        self.subs.insert(
          *sub,
          SubRecord {
            root: fs_root,
            path: root_path,
            interest,
          },
        );
      }
      WatchOutcome::Widen {
        repointed,
        unwatch,
        sub,
        ..
      } => {
        let (_planned, interest) = self.take_pending(*sub);
        let root_path = fs_root_path.to_path_buf();

        // Drop the subsumed roots' index keys and entries. Their subscribers stay
        // live — only their owning root changes.
        self.index.remove_descendants(root_path.as_path());
        for old in unwatch {
          self.entries.remove(old);
        }

        // Install the wider root, adopting every re-pointed subscriber plus the
        // newcomer (deterministic order: subsumed subscribers first, then `sub`).
        let mut subscribers = repointed.clone();
        subscribers.push(*sub);
        self.index.insert(root_path.as_path(), fs_root);
        self.entries.insert(
          fs_root,
          RootEntry {
            path: root_path.clone(),
            subscribers,
          },
        );

        for &moved in repointed {
          self
            .subs
            .get_mut(&moved)
            .expect("re-pointed subscription is live")
            .root = fs_root;
        }
        self.subs.insert(
          *sub,
          SubRecord {
            root: fs_root,
            path: root_path,
            interest,
          },
        );
      }
    }
  }

  /// Abandons the plan `outcome` without committing it, discarding the pending
  /// reservation `plan_watch` stashed. Call this on every path where arming the
  /// real kernel watch failed, so the not-yet-committed subscription's pending
  /// entry cannot leak: `plan_watch` mutated nothing committed, and no `fs_root`
  /// was ever obtained, so dropping the reservation fully unwinds the plan.
  ///
  /// Idempotent per plan: consuming an already-committed (or already-aborted)
  /// outcome's id is a no-op, so a double-abort or an abort-after-commit is safe.
  pub(crate) fn abort_watch(&mut self, outcome: &WatchOutcome<R>) {
    let sub = match outcome {
      WatchOutcome::Covered { sub, .. }
      | WatchOutcome::Widen { sub, .. }
      | WatchOutcome::Disjoint { sub, .. } => *sub,
    };
    self.pending.remove(&sub);
  }

  /// Removes `sub`, reporting whether its root emptied (returns `None` for an
  /// unknown subscription). Mutates immediately — no commit step is needed.
  pub(crate) fn plan_unwatch(&mut self, sub: Subscription) -> Option<UnwatchOutcome<R>> {
    let record = self.subs.remove(&sub)?;
    let entry = self
      .entries
      .get_mut(&record.root)
      .expect("live subscription's root exists");
    entry.subscribers.retain(|&s| s != sub);

    if entry.subscribers.is_empty() {
      let emptied = self.entries.remove(&record.root).expect("just retained it");
      self.index.remove(emptied.path.as_path());
      Some(UnwatchOutcome::RootEmptied {
        fs_root: record.root,
      })
    } else {
      Some(UnwatchOutcome::Dropped)
    }
  }

  /// The live record for `fs_root`, if any.
  pub(crate) fn entry(&self, fs_root: R) -> Option<&RootEntry> {
    self.entries.get(&fs_root)
  }

  /// Re-keys a live root from a dead handle `old` to a freshly-armed `new`, keeping its
  /// path, subscribers, and index key — used on the **widen rollback** (design §4/§8).
  ///
  /// When a widen disarms the subsumed roots and then fails to bring up the wider root,
  /// the driver re-arms each subsumed root to restore the pre-widen state. A fresh arm
  /// yields a *new* handle (fs never reuses one), and events from it will carry that new
  /// handle in [`root`](tributary_fs::Event::root), so the subsumer must re-point the
  /// root's entry and every subscriber onto it or fan-out would fail to resolve them.
  /// The root's canonical path and subscriber set are unchanged (the rollback restores,
  /// it does not re-plan); [`iradix::unsync::Radix::insert`] overwrites the same key.
  pub(crate) fn rekey_root(&mut self, old: R, new: R) {
    let entry = self.entries.remove(&old).expect("re-keyed root is live");
    self.index.insert(entry.path.as_path(), new);
    for &sub in &entry.subscribers {
      self
        .subs
        .get_mut(&sub)
        .expect("re-keyed root's subscriber is live")
        .root = new;
    }
    self.entries.insert(new, entry);
  }

  /// Force-drops the root `handle` and every subscriber riding it, returning those
  /// subscribers so the driver can reclaim their per-subscription state (filter, epoch
  /// ledger). The **degenerate** widen path (design §4/§8): a rollback re-arm of a
  /// subsumed root itself failed, so that root cannot be restored and its subscribers
  /// are terminally uncovered — the driver has signalled each a loss `Rescan`, and this
  /// tears the dead root out of the index/entries/side-table so no later event routes to
  /// its (never-armed) handle and the invariants (no root with a dead handle, no dangling
  /// side-table record) still hold.
  pub(crate) fn force_remove_root(&mut self, handle: R) -> Vec<Subscription> {
    let Some(entry) = self.entries.remove(&handle) else {
      return Vec::new();
    };
    self.index.remove(entry.path.as_path());
    for &sub in &entry.subscribers {
      self.subs.remove(&sub);
    }
    entry.subscribers
  }

  /// The canonical path a live subscription was registered at, if any (its entry
  /// in the §4 side table).
  pub(crate) fn subscription_path(&self, sub: Subscription) -> Option<&Path> {
    self.subs.get(&sub).map(|record| record.path.as_path())
  }

  /// The [`Interest`] a live subscription was registered with, if any — the fan-out
  /// gate (design §4/§5) applied to every non-`Rescan` delivery. Every root is armed
  /// [`Interest::all`], so this narrows *delivery*, never the kernel watch.
  pub(crate) fn subscription_interest(&self, sub: Subscription) -> Option<Interest> {
    self.subs.get(&sub).map(|record| record.interest)
  }

  /// Whether committing a fresh/widened root at `fs_root_path` would keep the same
  /// subsumption the plan assumed against `planned_path` — used by the driver to
  /// guard the canonicalization TOCTOU (design §4) after `Watcher::root_path` reports
  /// fs's authoritative canonical path.
  ///
  /// A commit is safe when fs's path is identical to the planned one (the common
  /// case), or when the divergent fs path is *still* disjoint from every committed
  /// root and subsumes exactly the roots the plan drained. Concretely: it must not be
  /// covered by an existing root, and the set of committed roots it strictly contains
  /// must equal `planned_unwatch`. If it diverges in a way that changes subsumption
  /// (now covered by, or overlapping a different set of, existing roots), the driver
  /// disarms and aborts rather than committing a mis-keyed or overlapping entry.
  pub(crate) fn fs_path_preserves_plan(&self, fs_root_path: &Path, planned_unwatch: &[R]) -> bool {
    // Covered by an existing root now? Then it should never have armed a fresh/wider
    // root — the plan is invalidated.
    if self.index.get_ancestor(fs_root_path).is_some() {
      return false;
    }
    // The roots this fs path strictly contains must be exactly the ones the plan drained
    // (order-insensitive), or a different overlap has appeared.
    let now: std::collections::HashSet<R> = self.index.descendants(fs_root_path).copied().collect();
    let planned: std::collections::HashSet<R> = planned_unwatch.iter().copied().collect();
    now == planned
  }

  /// The number of not-yet-committed plans still holding a pending reservation —
  /// the leak the plan→commit-or-abort contract must keep at zero between watches.
  /// Consumed by the driver's arm-failure test, which needs a runtime.
  #[cfg(all(test, feature = "tokio"))]
  pub(crate) fn pending_len(&self) -> usize {
    self.pending.len()
  }

  /// Every live root as `(canonical path, handle)`, in deterministic canonical-path
  /// order. Iterates the [`iradix`] index (which yields values in key order), never
  /// the [`HashMap`], so the order is reproducible. The disjointness / coverage
  /// invariants are checked against this; it has no non-test consumer yet, so it is
  /// gated to keep a plain library build free of dead code.
  #[cfg(test)]
  pub(crate) fn roots(&self) -> impl Iterator<Item = (&Path, R)> {
    self.index.values().map(move |&handle| {
      let entry = &self.entries[&handle];
      (entry.path.as_path(), handle)
    })
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

  /// Consumes the canonical path and interest `plan_watch` stashed under `sub`'s
  /// freshly-minted id. A commit consumes exactly its own plan's id, so this is
  /// present unless the plan was already aborted (arm failure) — in which case
  /// `commit_watch` must not run for it.
  fn take_pending(&mut self, sub: Subscription) -> (PathBuf, Interest) {
    self
      .pending
      .remove(&sub)
      .expect("commit_watch consumes its own plan's pending entry (not yet aborted)")
  }
}
