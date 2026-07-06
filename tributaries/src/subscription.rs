//! The caller-facing subscription handle.

use tributary_proto::ScopeId;

/// A caller-facing handle to one watch subscription.
///
/// Returned by `watch` and consumed by `unwatch`; every delivered event is
/// retagged with the `Subscription` it belongs to. It is a thin newtype over a
/// [`ScopeId`] — the disjoint-root token the stack mints — reinterpreted at this
/// layer as *one caller subscription*, since a subscription need not map one-to-one
/// onto a kernel watch (many overlapping subscriptions can share one subsumed root).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Subscription(ScopeId);

impl Subscription {
  /// Wraps a [`ScopeId`] as a `Subscription`.
  #[inline]
  pub const fn new(id: ScopeId) -> Self {
    Self(id)
  }

  /// The underlying [`ScopeId`].
  #[inline]
  pub const fn id(&self) -> ScopeId {
    self.0
  }
}

impl core::fmt::Display for Subscription {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    core::fmt::Display::fmt(&self.0, f)
  }
}
