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
/// Extends the design sketch (`fs_root` + `subscribers`) with the root's canonical
/// `path` and the `interest` currently armed on it: `path` is needed to check
/// coverage (that every subscriber's path descends from this root) and to key the
/// subsumption index; `interest` is the union the kernel watch currently carries,
/// so a later widening can union it with the newcomer's without narrowing coverage
/// a subsumed subscription relied on.
#[derive(Debug, Clone)]
pub(crate) struct RootEntry<R> {
  /// The disjoint fs root handle backing this entry's kernel watch.
  pub(crate) fs_root: R,
  /// The root's canonical path (the subsumption-index key for this entry).
  pub(crate) path: PathBuf,
  /// The union interest currently armed on the kernel watch.
  pub(crate) interest: Interest,
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
  /// The driver must arm a wider watch at `new_root_path` (with `union_interest`)
  /// **before** releasing the subsumed roots (`unwatch`), so coverage never gaps;
  /// `commit_watch` re-points `repointed` (and adds the new `sub`) onto it.
  Widen {
    /// The canonical path of the new, wider root (equal to the new subscription's
    /// own canonical path).
    new_root_path: PathBuf,
    /// The union of every subsumed root's interest and the newcomer's.
    union_interest: Interest,
    /// The subscribers of every subsumed root, to re-point onto the wider root, in
    /// deterministic (root key, then registration) order.
    repointed: Vec<Subscription>,
    /// The subsumed fs root handles the driver must release, in root-key order.
    unwatch: Vec<R>,
    /// The new subscription.
    sub: Subscription,
  },
  /// `path` neither is covered by nor covers any existing root. The driver arms a
  /// fresh watch; `commit_watch` records the new root once its handle is known.
  Disjoint {
    /// The canonical path of the fresh root (equal to the subscription's path).
    root_path: PathBuf,
    /// The interest to arm on the fresh watch.
    interest: Interest,
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

/// One subscription's side-table record: the root it currently rides and its own
/// canonical path (the §4 `Subscription -> (canonical_path, fs_root, …)` table,
/// trimmed to what S1 needs; `Filter` arrives with routing in a later milestone).
#[derive(Debug, Clone)]
struct SubRecord<R> {
  root: R,
  path: PathBuf,
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
  entries: HashMap<R, RootEntry<R>>,
  /// Live subscription → the root it rides and its own canonical path.
  subs: HashMap<Subscription, SubRecord<R>>,
  /// Canonical path stashed by `plan_watch` for the not-yet-committed subscription,
  /// consumed by the paired `commit_watch` (the driver contract is plan→commit on
  /// the same engine, one at a time).
  pending: HashMap<Subscription, PathBuf>,
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
    self.pending.insert(sub, canonical.to_path_buf());

    // Case 1 — Covered: an existing root at or above `canonical` already watches
    // this subtree. Disjointness guarantees at most one such ancestor, and its
    // presence rules out any strict descendant, so this short-circuits cleanly.
    if let Some(&fs_root) = self.index.get_ancestor(canonical) {
      return WatchOutcome::Covered { fs_root, sub };
    }

    // Case 2 — Widen: `canonical` is a strict ancestor of one or more existing
    // roots, which it now subsumes. Collect them in canonical-path order (iradix
    // yields strict descendants ascending), gathering their handles to release and
    // their subscribers to re-point, and union every subsumed interest with the new
    // one so coverage a subsumed subscription relied on is never narrowed.
    let mut unwatch = Vec::new();
    let mut repointed = Vec::new();
    let mut union_interest = interest;
    for &subsumed in self.index.descendants(canonical) {
      let entry = &self.entries[&subsumed];
      union_interest = union(union_interest, entry.interest);
      repointed.extend_from_slice(&entry.subscribers);
      unwatch.push(subsumed);
    }
    if !unwatch.is_empty() {
      return WatchOutcome::Widen {
        new_root_path: canonical.to_path_buf(),
        union_interest,
        repointed,
        unwatch,
        sub,
      };
    }

    // Case 3 — Disjoint: neither covered nor covering.
    WatchOutcome::Disjoint {
      root_path: canonical.to_path_buf(),
      interest,
      sub,
    }
  }

  /// Commits the state transition for `outcome`, binding the real `fs_root` the
  /// driver obtained by arming the watch (for [`WatchOutcome::Covered`] this is the
  /// existing covering root carried in the outcome).
  pub(crate) fn commit_watch(&mut self, outcome: &WatchOutcome<R>, fs_root: R) {
    match outcome {
      WatchOutcome::Covered { sub, .. } => {
        let path = self.take_pending(*sub);
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
          },
        );
      }
      WatchOutcome::Disjoint {
        root_path,
        interest,
        sub,
      } => {
        let path = self.take_pending(*sub);
        self.index.insert(root_path.as_path(), fs_root);
        self.entries.insert(
          fs_root,
          RootEntry {
            fs_root,
            path: root_path.clone(),
            interest: *interest,
            subscribers: std::vec![*sub],
          },
        );
        self.subs.insert(
          *sub,
          SubRecord {
            root: fs_root,
            path,
          },
        );
      }
      WatchOutcome::Widen {
        new_root_path,
        union_interest,
        repointed,
        unwatch,
        sub,
      } => {
        let path = self.take_pending(*sub);

        // Drop the subsumed roots' index keys and entries. Their subscribers stay
        // live — only their owning root changes.
        self.index.remove_descendants(new_root_path.as_path());
        for old in unwatch {
          self.entries.remove(old);
        }

        // Install the wider root, adopting every re-pointed subscriber plus the
        // newcomer (deterministic order: subsumed subscribers first, then `sub`).
        let mut subscribers = repointed.clone();
        subscribers.push(*sub);
        self.index.insert(new_root_path.as_path(), fs_root);
        self.entries.insert(
          fs_root,
          RootEntry {
            fs_root,
            path: new_root_path.clone(),
            interest: *union_interest,
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
            path,
          },
        );
      }
    }
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
  pub(crate) fn entry(&self, fs_root: R) -> Option<&RootEntry<R>> {
    self.entries.get(&fs_root)
  }

  /// The canonical path a live subscription was registered at, if any (its entry
  /// in the §4 side table).
  pub(crate) fn subscription_path(&self, sub: Subscription) -> Option<&Path> {
    self.subs.get(&sub).map(|record| record.path.as_path())
  }

  /// Every live root as `(canonical path, handle)`, in deterministic canonical-path
  /// order (for invariants and tests). Iterates the [`iradix`] index (which yields
  /// values in key order), never the [`HashMap`], so the order is reproducible.
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

  /// Consumes the canonical path `plan_watch` stashed for `sub`.
  fn take_pending(&mut self, sub: Subscription) -> PathBuf {
    self
      .pending
      .remove(&sub)
      .expect("commit_watch follows plan_watch for this subscription")
  }
}

/// The field-wise union of two interests (each kind is wanted if either wants it).
fn union(a: Interest, b: Interest) -> Interest {
  Interest::new()
    .maybe_created(a.created() || b.created())
    .maybe_removed(a.removed() || b.removed())
    .maybe_modified(a.modified() || b.modified())
    .maybe_moved(a.moved() || b.moved())
    .maybe_attrib(a.attrib() || b.attrib())
    .maybe_ondir(a.ondir() || b.ondir())
}
