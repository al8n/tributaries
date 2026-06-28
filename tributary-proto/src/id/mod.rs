//! Opaque, proto-minted handles and the disjoint-root / move-pairing tokens.
//!
//! The core never traffics in raw OS handles (an inotify `wd`, an FSEvents
//! stream id). Instead the [`Monitor`](crate::Monitor) mints monotonic
//! [`NonZeroU64`] handles — [`WatchId`], [`ReqId`], [`ChangeId`] — and the
//! driver owns the table mapping each [`WatchId`] to its raw handle. This single
//! abstraction fixes three independently-found problems at once: the
//! inotify-ism in the vocabulary, inode aliasing (one `wd` backing several
//! anchors), and `wd`-reuse / ABA misattribution.
//!
//! [`ScopeId`] (a disjoint watched root) is *not* proto-minted — it is supplied
//! by the layer above (`watershed`, which subsumes overlapping scopes into
//! disjoint roots). [`MoveCookie`] is the backend-agnostic pairing token for a
//! rename (an inotify cookie, an FSEvents file id).

use core::num::NonZeroU64;

macro_rules! proto_id {
  ($(#[$meta:meta])* $name:ident) => {
    $(#[$meta])*
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct $name(NonZeroU64);

    impl $name {
      #[doc = concat!("Wraps a raw non-zero value as a [`", stringify!($name), "`].")]
      ///
      /// Handles are normally minted by the [`Monitor`](crate::Monitor); this
      /// constructor exists for the driver's lookup tables and for tests.
      #[cfg_attr(not(tarpaulin), inline(always))]
      pub const fn new(value: NonZeroU64) -> Self {
        Self(value)
      }

      #[doc = concat!("The non-zero handle backing this [`", stringify!($name), "`].")]
      #[cfg_attr(not(tarpaulin), inline(always))]
      pub const fn get(&self) -> NonZeroU64 {
        self.0
      }

      #[doc = concat!("The raw [`u64`] value of this [`", stringify!($name), "`].")]
      #[cfg_attr(not(tarpaulin), inline(always))]
      pub const fn as_u64(&self) -> u64 {
        self.0.get()
      }
    }

    impl core::fmt::Display for $name {
      #[cfg_attr(not(tarpaulin), inline(always))]
      fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, f)
      }
    }
  };
}

proto_id! {
  /// An opaque, proto-minted, monotonic handle for one established watch.
  ///
  /// Replaces the raw inotify `wd` (or any backend's native watch handle) inside
  /// the core. Every [`OsRecord`](crate::OsRecord) carries the `WatchId` it came
  /// from, so attribution to a disjoint root is O(1).
  WatchId
}

proto_id! {
  /// An opaque, proto-minted handle correlating an
  /// [`Action::Enumerate`](crate::Action::Enumerate) or
  /// [`Action::Stat`](crate::Action::Stat) request with its later result.
  ReqId
}

proto_id! {
  /// The dedup / identity key stamped on every emitted [`Change`](crate::Change).
  ///
  /// The core dedups deliveries by this key; it is also the seam for the M2
  /// at-least-once delivery story.
  ChangeId
}

proto_id! {
  /// Identifies one disjoint watched root (one subtree the consumer asked for).
  ///
  /// Supplied by the layer above (which guarantees roots are disjoint), not
  /// minted by the core. Every [`Change`](crate::Change) is born tagged with the
  /// `ScopeId` it belongs to.
  ScopeId
}

proto_id! {
  /// A backend-agnostic token pairing the two halves of a rename.
  ///
  /// An inotify `IN_MOVED_FROM` / `IN_MOVED_TO` cookie, or an FSEvents file id
  /// reported on both `ItemRenamed` records. The two halves carry the same
  /// `MoveCookie`; the core pairs them within a timeout window to synthesize a
  /// [`ChangeKind::Moved`](crate::ChangeKind::Moved).
  MoveCookie
}

/// A monotonic minter of [`NonZeroU64`] handle values, starting at 1.
///
/// Handles are never reused: reuse would reintroduce the ABA misattribution the
/// proto-minted handles exist to prevent. Exhausting the [`u64`] space (more
/// than 1.8 * 10^19 mints) is unreachable in any real process; it panics rather
/// than wrap so a wrapped handle can never be misattributed.
#[derive(Debug, Clone)]
pub(crate) struct Sequence {
  next: NonZeroU64,
}

impl Sequence {
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub(crate) const fn new() -> Self {
    Self {
      next: NonZeroU64::MIN,
    }
  }

  #[cfg_attr(not(tarpaulin), inline)]
  pub(crate) fn mint(&mut self) -> NonZeroU64 {
    let value = self.next;
    self.next = self
      .next
      .checked_add(1)
      .expect("proto handle space (u64) exhausted");
    value
  }
}

impl Default for Sequence {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests;
