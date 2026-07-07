//! The concurrent read plane — a wait-free membership / attribution handle over the
//! last committed watch-set (design §5).
//!
//! A [`WatchView`] is a cheap `Clone + Send + Sync` handle over the shared `arc_swap`
//! slot the subsumption engine republishes after every commit. Every method is `&self`
//! and wait-free: it `load`s a consistent immutable snapshot and answers
//! from it, with **no lock and no round-trip to the driver**. This is the "is this
//! already watched?" / "which watch owns this?" path any outside thread reads.
//!
//! # Eventually consistent
//!
//! A view reflects the **last committed** watch-set. A just-issued `watch` that has
//! not committed yet reads as not-present, and a caller re-checks after its
//! `watch().await` returns (design §5/§9). This is exactly right for a dedup query:
//! consistency for the *control* decision (subsume vs. arm) is the driver's
//! authoritative copy; the view is for *queries*.

use core::ops::Deref;

use crate::subsume::Shared;

#[cfg(test)]
mod tests;

/// An owned snapshot of a caller value `V`, returned by attribution
/// ([`WatchView::covering`] / [`resolve`](WatchView::resolve)).
///
/// The watch-set snapshot a query loads is a temporary immutable tree, so the owning
/// value cannot be handed back by reference; it is cloned out into this owned wrapper.
/// A `Snapshot` [`Deref`]s to the value, so it reads like a `&V`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot<V> {
  value: V,
}

impl<V> Snapshot<V> {
  #[inline]
  const fn new(value: V) -> Self {
    Self { value }
  }

  /// Borrows the owned value.
  #[inline]
  pub const fn get(&self) -> &V {
    &self.value
  }

  /// Consumes the snapshot, yielding the owned value.
  #[inline]
  pub fn into_inner(self) -> V {
    self.value
  }
}

impl<V> Deref for Snapshot<V> {
  type Target = V;

  #[inline]
  fn deref(&self) -> &V {
    &self.value
  }
}

/// A cheap `Clone + Send + Sync` wait-free read handle over the last committed
/// watch-set (design §5).
///
/// The two semantically-relevant type parameters are the key component `C` and the
/// caller value `V`; `H` is the armed-root handle carried in the shared root record
/// (an implementation detail — the fs handle for the local-fs source). Every method is
/// `&self`, reads a loaded immutable snapshot, and is **eventually consistent**: it
/// reflects the last committed watch-set, so a just-issued `watch` that has not
/// committed yet reads as not-present (design §5).
///
/// A `Clone` shares the same published slot: once the driver republishes a committed
/// change, it is visible to every clone at once.
pub struct WatchView<C, V, H> {
  shared: Shared<C, V, H>,
}

impl<C, V, H> WatchView<C, V, H> {
  /// Builds a view over the shared publication slot the subsumer republishes into.
  #[inline]
  pub(crate) fn new(shared: Shared<C, V, H>) -> Self {
    Self { shared }
  }
}

// The shared `ArcSwap<Radix>` slot is not `Debug`; the handle carries no
// summarizable side state of its own, so this is a bound-free opaque view.
impl<C, V, H> core::fmt::Debug for WatchView<C, V, H> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("WatchView").finish_non_exhaustive()
  }
}

impl<C, V, H> WatchView<C, V, H>
where
  C: Ord + Clone,
{
  /// Whether `key` is watched: covered by an exact watch **or** any ancestor watch
  /// (`contains || get_ancestor.is_some()`) — the membership dedup check (design §5).
  #[inline]
  #[must_use]
  pub fn is_watched(&self, key: &[C]) -> bool {
    let snapshot = self.shared.load();
    snapshot.contains(key) || snapshot.get_ancestor(key).is_some()
  }

  /// Whether `key` is watched by an **exact** root (not merely covered by an
  /// ancestor).
  #[inline]
  #[must_use]
  pub fn contains(&self, key: &[C]) -> bool {
    self.shared.load().contains(key)
  }

  /// The caller value of the root that **covers** `key` — the deepest watch at or
  /// above it (`get_ancestor`), the owning attribution value (design §5). `None` when
  /// `key` is not watched.
  #[inline]
  #[must_use]
  pub fn covering(&self, key: &[C]) -> Option<Snapshot<V>>
  where
    V: Clone,
  {
    self
      .shared
      .load()
      .get_ancestor(key)
      .map(|record| Snapshot::new(record.value.clone()))
  }

  /// Attribution alias for [`covering`](Self::covering): the caller value owning
  /// `key`, for resolving an observed key back to its watch (design §5).
  #[inline]
  #[must_use]
  pub fn resolve(&self, key: &[C]) -> Option<Snapshot<V>>
  where
    V: Clone,
  {
    self.covering(key)
  }
}

impl<C, V, H> WatchView<C, V, H> {
  /// The number of live roots in the last committed watch-set.
  #[inline]
  #[must_use]
  pub fn len(&self) -> usize {
    self.shared.load().len()
  }

  /// Whether the last committed watch-set holds no roots.
  #[inline]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.shared.load().is_empty()
  }
}

impl<C, V, H> Clone for WatchView<C, V, H> {
  /// Shares the same published slot — a committed change the driver republishes is
  /// observed by every clone (the point of the shared read plane).
  #[inline]
  fn clone(&self) -> Self {
    Self {
      shared: self.shared.clone(),
    }
  }
}
