//! The caller-facing subscription handle and its per-watcher instance brand.

use core::{
  num::NonZeroU64,
  sync::atomic::{AtomicU64, Ordering},
};

use tributary_proto::ScopeId;

/// A process-global identity minted once per [`Tributaries`](crate::Tributaries) owner and
/// stamped onto every [`Subscription`] that owner hands out.
///
/// It is the brand that makes a [`Subscription`] a capability for exactly **one** watcher. Each
/// watcher mints its [`ScopeId`]s independently from 1, so two watchers' handles routinely carry
/// colliding scope ids; the instance brand is what keeps a handle minted by one watcher from
/// being mistaken for — or used to `unwatch` — an unrelated subscription of another whose scope
/// id happens to match. (The lower `tributary-fs` layer brands its `RootHandle` by watcher
/// instance for exactly this reason.)
///
/// There is no public constructor: an `InstanceId` is only ever minted internally, so a caller
/// can neither fabricate one nor forge a [`Subscription`] carrying a foreign brand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstanceId(NonZeroU64);

impl InstanceId {
  /// The raw brand — the component a sync cookie's name carries so two watcher
  /// instances in one process never mint colliding markers.
  pub(crate) const fn get(&self) -> u64 {
    self.0.get()
  }

  /// Mints the next process-global instance id — called once per owner at construction.
  ///
  /// A monotonic `fetch_add` over a process-global [`AtomicU64`]: the fetched previous value plus
  /// one is the id, non-zero unless the counter has wrapped the entire `u64` space (unreachable
  /// — it would take 2⁶⁴ watcher constructions in one process), which the [`expect`] catches.
  ///
  /// [`expect`]: Option::expect
  pub(crate) fn mint() -> Self {
    static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(0);
    let raw = NEXT_INSTANCE
      .fetch_add(1, Ordering::Relaxed)
      .wrapping_add(1);
    Self(NonZeroU64::new(raw).expect("process-global instance id counter wrapped the u64 space"))
  }

  /// The fixed instance brand the sans-I/O unit tests synthesize subscriptions under (rather than
  /// minting them through a live owner).
  #[cfg(test)]
  pub(crate) const TEST: Self = Self(NonZeroU64::MIN);
}

impl core::fmt::Display for InstanceId {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    core::fmt::Display::fmt(&self.0, f)
  }
}

/// A caller-facing handle to one watch subscription.
///
/// Returned by `watch` and consumed by `unwatch`; every delivered event is retagged with the
/// `Subscription` it belongs to. It pairs the owning watcher's [`InstanceId`] brand with the
/// [`ScopeId`] the stack mints — the disjoint-root token, reinterpreted at this layer as *one
/// caller subscription* (a subscription need not map one-to-one onto a kernel watch: many
/// overlapping subscriptions can share one subsumed root).
///
/// # A handle is a per-watcher capability, not a bare integer
///
/// The [`InstanceId`] brand makes a `Subscription` valid only for the watcher that minted it:
/// [`unwatch`](crate::Tributaries::unwatch) rejects a handle branded by a *different* watcher even
/// when its [`ScopeId`] collides with a live local subscription's. There is no public constructor,
/// so a caller can neither forge a handle nor mint one carrying a foreign brand — the only
/// `Subscription`s that exist are the ones a watcher handed out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Subscription {
  instance: InstanceId,
  scope: ScopeId,
}

impl Subscription {
  /// Pairs an owner [`InstanceId`] with a [`ScopeId`] into a branded `Subscription`.
  ///
  /// Crate-private: only an owner (through its subsumer) mints subscriptions, each branded with
  /// that owner's instance. There is deliberately no public constructor, so a handle can neither
  /// be forged nor minted with a foreign brand.
  #[inline]
  pub(crate) const fn new(instance: InstanceId, scope: ScopeId) -> Self {
    Self { instance, scope }
  }

  /// Synthesizes a subscription under the fixed test instance brand — for the sans-I/O unit tests
  /// that construct subscriptions directly rather than minting them through a live owner.
  #[cfg(test)]
  pub(crate) const fn for_test(scope: ScopeId) -> Self {
    Self::new(InstanceId::TEST, scope)
  }

  /// The owning watcher's [`InstanceId`] brand — the identity `unwatch` checks so a handle from
  /// one watcher can never retire another's subscription.
  #[inline]
  pub const fn instance(&self) -> InstanceId {
    self.instance
  }

  /// The underlying [`ScopeId`].
  #[inline]
  pub const fn id(&self) -> ScopeId {
    self.scope
  }
}

impl core::fmt::Display for Subscription {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    core::fmt::Display::fmt(&self.scope, f)
  }
}
