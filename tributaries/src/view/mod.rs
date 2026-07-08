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
  /// Whether `key` is watched — the membership dedup check (design §5).
  ///
  /// True iff some **live subscription's own key** is an ancestor-or-equal of `key`.
  /// This is live-subscription coverage, **not** armed-root coverage: an armed root can
  /// outlive the subscription whose key equalled its own (a widen then unwatch of the
  /// widening watch, or a covered watch then unwatch of the root's own watch), leaving the
  /// root broader than any live subscription. Answering from the armed root would then
  /// over-report — call a key watched that fan-out delivers to no subscriber — and a dedup
  /// caller (the indexer) would skip installing it and silently miss its changes. Keying on
  /// live subscriptions makes `is_watched` exactly the set fan-out delivers to, so a dedup
  /// caller that skips a `true` key never loses events; and re-installing a `false` key is
  /// covered under the still-armed broad root (no re-arm — self-healing).
  #[inline]
  #[must_use]
  pub fn is_watched(&self, key: &[C]) -> bool {
    self.shared.load().covers.get_ancestor(key).is_some()
  }

  /// Whether `key` is watched by an **exact armed root** (not merely covered by an
  /// ancestor) — a root-plane query, distinct from [`is_watched`](Self::is_watched)'s
  /// live-subscription coverage.
  #[inline]
  #[must_use]
  pub fn contains(&self, key: &[C]) -> bool {
    self.shared.load().roots.contains(key)
  }

  /// The caller value **owning** `key` — the attribution value (design §5). `None` when `key`
  /// is not watched.
  ///
  /// Attribution follows the **live-subscription** coverage plane, same as
  /// [`is_watched`](Self::is_watched): the value returned is that of the **longest** live
  /// subscription whose own key is an ancestor-or-equal of `key`. A covered subscription owns its
  /// **own** value even though it shares a broader root, so a covered key resolves to the covered
  /// subscription's value, not the covering root's; and a key an armed-but-broadened root no
  /// longer truly covers resolves to nothing rather than to a departed watch's value. When
  /// several live subscriptions share the exact longest key, the most-recent (highest-id) wins —
  /// a deterministic tie-break.
  #[inline]
  #[must_use]
  pub fn covering(&self, key: &[C]) -> Option<Snapshot<V>>
  where
    V: Clone,
  {
    // Attribution reads the live-subscription coverage plane, not the armed-root plane: the
    // longest live subscription covering `key`, tie-broken most-recent within a shared key. An
    // armed root can outlive the subscription whose value equalled it, so reading the root's
    // value would return a departed watch's value for a key a narrower live sub now owns.
    self
      .shared
      .load()
      .covers
      .get_ancestor(key)
      .map(|entry| Snapshot::new(entry.value().clone()))
  }

  /// Attribution alias for [`covering`](Self::covering): the caller value **currently** owning
  /// `key`, for resolving an observed key back to its live watch (design §5) — the *live* "is key
  /// `k` watched, and by whom" query.
  ///
  /// This reflects the **current** watch-set, so it is the right call for pre-watch dedup and
  /// membership. To attribute a **delivered event**, prefer its baked
  /// [`Event::value`](crate::Event::value): that value is captured at emit time and stays valid
  /// even after teardown empties this view (when `resolve` would answer `None` for a still-queued
  /// event — design §3).
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
  /// The number of live **armed roots** in the last committed watch-set.
  #[inline]
  #[must_use]
  pub fn len(&self) -> usize {
    self.shared.load().roots.len()
  }

  /// Whether the last committed watch-set holds no armed roots.
  #[inline]
  #[must_use]
  pub fn is_empty(&self) -> bool {
    self.shared.load().roots.is_empty()
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
