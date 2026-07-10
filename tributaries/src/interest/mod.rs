//! The per-subscription fan-out [`Interest`] mask — the umbrella-owned delivery gate
//! over the source-neutral [`EventKind`] vocabulary.

use crate::event::EventKind;

#[cfg(test)]
mod tests;

/// Which delivered [`EventKind`]s a subscription wants — the umbrella's **own**
/// per-subscription fan-out gate (design §5), one bit per maskable kind.
///
/// The umbrella owns this vocabulary exactly as it owns [`EventKind`]: it is
/// source-neutral, so a fully generic consumer never imports source-flavored flags.
/// Roots are always armed by the source's own **widest** policy (design §4) — an
/// interest narrows what is *delivered* to its subscription, never the underlying
/// source watch.
///
/// # Deliver-everything default
///
/// [`new`](Self::new) equals [`all`](Self::all): a watch delivers everything, and
/// **narrowing is the opt-in act** — matching [`Filter::all`](crate::Filter::all) as
/// the filter default. [`none`](Self::none) is the explicit empty gate (a Rescan-only
/// subscription).
///
/// # The gate applies to the PROJECTED kind
///
/// A [`Moved`](EventKind::Moved) is decomposed per subscriber *before* this gate runs
/// (design §5): a subscriber covering only the move's source sees a move-out — a
/// synthesized [`Removed`](EventKind::Removed), gated by [`removed`](Self::removed);
/// one covering only the destination sees a move-in — a synthesized
/// [`Created`](EventKind::Created), gated by [`created`](Self::created); only a
/// subscriber covering both endpoints sees the whole `Moved`, gated by
/// [`moved`](Self::moved). Endpoint semantics ride the projection, not extra bits.
///
/// # A [`Rescan`](EventKind::Rescan) is structurally unmaskable
///
/// There is no rescan bit: a coverage-loss signal must never be narrowed away, so
/// [`admits`](Self::admits) always admits it (and fan-out bypasses the gate for it
/// entirely, design §5/§7/§8). Even a [`none`](Self::none) subscription still receives
/// its `Rescan`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Interest {
  created: bool,
  modified: bool,
  removed: bool,
  moved: bool,
}

impl Interest {
  /// An interest subscribed to every kind — identical to [`all`](Self::all).
  ///
  /// The umbrella's posture is deliver-everything: narrowing is the opt-in act,
  /// matching [`Filter::all`](crate::Filter::all) as the filter default.
  #[inline]
  pub const fn new() -> Self {
    Self::all()
  }

  /// An interest subscribed to every kind.
  #[inline]
  pub const fn all() -> Self {
    Self {
      created: true,
      modified: true,
      removed: true,
      moved: true,
    }
  }

  /// The explicit empty interest: subscribed to no maskable kind — a **Rescan-only**
  /// subscription.
  ///
  /// Accepted, not rejected: the subscription still holds coverage and still receives
  /// every [`Rescan`](EventKind::Rescan) (which no interest can mask); every other
  /// kind is gated away.
  #[inline]
  pub const fn none() -> Self {
    Self {
      created: false,
      modified: false,
      removed: false,
      moved: false,
    }
  }

  /// Whether [`Created`](EventKind::Created) deliveries are wanted — including the
  /// synthesized move-IN projection of a [`Moved`](EventKind::Moved) whose destination
  /// alone the subscription covers (design §5).
  #[inline]
  pub const fn created(&self) -> bool {
    self.created
  }

  /// Whether [`Modified`](EventKind::Modified) deliveries are wanted.
  #[inline]
  pub const fn modified(&self) -> bool {
    self.modified
  }

  /// Whether [`Removed`](EventKind::Removed) deliveries are wanted — including the
  /// synthesized move-OUT projection of a [`Moved`](EventKind::Moved) whose source
  /// alone the subscription covers (design §5).
  #[inline]
  pub const fn removed(&self) -> bool {
    self.removed
  }

  /// Whether whole [`Moved`](EventKind::Moved) deliveries — both endpoints covered —
  /// are wanted (design §5).
  #[inline]
  pub const fn moved(&self) -> bool {
    self.moved
  }

  /// Whether this interest subscribes to every maskable kind ([`all`](Self::all)).
  #[inline]
  pub const fn is_all(&self) -> bool {
    self.created && self.modified && self.removed && self.moved
  }

  /// Whether this interest subscribes to no maskable kind ([`none`](Self::none)) — a
  /// Rescan-only subscription.
  #[inline]
  pub const fn is_none(&self) -> bool {
    !(self.created || self.modified || self.removed || self.moved)
  }

  /// Whether this interest admits a delivery of `kind` — the per-subscription fan-out
  /// gate (design §5). Every umbrella root is armed with the source's widest interest
  /// (design §4), so this narrows *delivery* only, never the source watch.
  ///
  /// The kind it sees is the already-**projected** one (projection happens before the
  /// gate, design §5): a move-out is a synthesized [`Removed`](EventKind::Removed)
  /// gated by [`removed`](Self::removed), a move-in a synthesized
  /// [`Created`](EventKind::Created) gated by [`created`](Self::created), and only a
  /// whole [`Moved`](EventKind::Moved) is gated by [`moved`](Self::moved).
  ///
  /// A [`Rescan`](EventKind::Rescan) is always admitted (though in practice it never
  /// reaches this gate — fan-out bypasses coverage, interest, and filter for a
  /// coverage-loss signal), and an unknown future kind is admitted conservatively
  /// rather than silently dropped.
  pub fn admits<C>(&self, kind: &EventKind<C>) -> bool {
    match kind {
      EventKind::Created => self.created,
      EventKind::Modified => self.modified,
      EventKind::Removed => self.removed,
      EventKind::Moved { .. } => self.moved,
      EventKind::Rescan => true,
      // `EventKind` is #[non_exhaustive]: a future variant must default to conservative
      // admission here, not a silent drop. Unreachable today only because the defining
      // crate matches its own enum exhaustively — the arm is the forward-compat default.
      #[allow(unreachable_patterns)]
      _ => true,
    }
  }
}

macro_rules! interest_flag {
  ($field:ident, $set:ident, $with:ident, $update:ident, $maybe:ident, $clear:ident) => {
    #[doc = concat!("Subscribes to `", stringify!($field), "` deliveries (sets it true).")]
    #[inline]
    pub const fn $set(&mut self) -> &mut Self {
      self.$field = true;
      self
    }

    #[doc = concat!("Returns this interest subscribed to `", stringify!($field), "` deliveries.")]
    #[inline]
    #[must_use]
    pub const fn $with(mut self) -> Self {
      self.$field = true;
      self
    }

    #[doc = concat!("Sets the `", stringify!($field), "` subscription to `value`.")]
    #[inline]
    pub const fn $update(&mut self, value: bool) -> &mut Self {
      self.$field = value;
      self
    }

    #[doc = concat!("Returns this interest with the `", stringify!($field), "` subscription set to `value`.")]
    #[inline]
    #[must_use]
    pub const fn $maybe(mut self, value: bool) -> Self {
      self.$field = value;
      self
    }

    #[doc = concat!("Clears the `", stringify!($field), "` subscription (sets it false).")]
    #[inline]
    pub const fn $clear(&mut self) -> &mut Self {
      self.$field = false;
      self
    }
  };
}

impl Interest {
  interest_flag!(
    created,
    set_created,
    with_created,
    update_created,
    maybe_created,
    clear_created
  );
  interest_flag!(
    modified,
    set_modified,
    with_modified,
    update_modified,
    maybe_modified,
    clear_modified
  );
  interest_flag!(
    removed,
    set_removed,
    with_removed,
    update_removed,
    maybe_removed,
    clear_removed
  );
  interest_flag!(
    moved,
    set_moved,
    with_moved,
    update_moved,
    maybe_moved,
    clear_moved
  );
}

impl Default for Interest {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}
