//! Values that speak only for the incarnation they were minted under.
//!
//! Several of this crate's protocols sample something about a scope under one
//! incarnation of it — a coverage-work epoch, a transport generation — and read
//! that sample back later to license a decision nothing can take back:
//! certifying a window clean, dispatching a caller's write onto a stream. The
//! sample is evidence about the incarnation it was taken under and about no
//! other, so reading it without re-establishing that that incarnation is still
//! the current one certifies over exactly the records the sample was bought to
//! surface.
//!
//! [`Stamped`] makes the re-check structural instead of remembered: nothing
//! yields the value without being handed the current stamp — no accessor, and no
//! rendering — so a reader cannot obtain it without naming the incarnation it is
//! reading under, and a reader naming the wrong one is given nothing at all.

use std::{cmp::Ordering, fmt};

/// A value that speaks only for the incarnation it was minted under.
///
/// The stamp is whatever names that incarnation; what it counts is the carrier's
/// business, and this type only ever compares one stamp against another for
/// EQUALITY before yielding the value. That is deliberate, and it is the whole
/// guarantee: an incarnation either IS the one the value was minted under or it
/// is not, and a value minted under any other speaks for nothing — there is no
/// partial credit to be had from a stamp being merely older or newer than the
/// one being read under.
///
/// # What it enforces
///
/// The value is reachable only through [`current`](Self::current), and the stored
/// stamp is reachable through nothing at all: there is no accessor that yields
/// it, so a reader cannot satisfy the check by handing the sample its own stamp
/// back — the one comparison that always succeeds and establishes nothing.
/// Anything a reader can pass had to come from somewhere else.
///
/// That covers every route out and not merely the accessors. The fields are
/// private and every carrier lives outside the module declaring them, so none
/// binds them by pattern. The [`Debug`] impl renders neither field, so neither
/// is recoverable from a formatted carrier. And the derived comparisons put a
/// whole `Stamped` on each side, so pitting a guessed value against a sample
/// means minting a rival under a stamp of one's own — and a stamp that makes the
/// guess bite is a stamp that would have read the value outright. None of them
/// answers anything a reader could not already have had.
///
/// Where "somewhere else" is decided by the stamp TYPE, and that is where the
/// strength of the guarantee is actually banked. A stamp its readers can
/// construct leaves a convention: they must still choose to observe the live
/// incarnation rather than name one they already had. A stamp only the state that
/// owns the incarnation can mint leaves no choice, because observing that state
/// is the only way to obtain one — which is why [`CutMark`] stamps with
/// [`CoverageWorkEpoch`], a type nothing outside the Monitor can build.
///
/// It does NOT make a stamp fresh. A reader holding a genuinely observed stamp
/// across a mutation that moves the incarnation on is reading under an
/// incarnation that has since departed, and this type cannot tell. Read the
/// stamp at the point of use.
///
/// # What does not belong here
///
/// A site whose rule genuinely is an ORDERING — one that honours what an earlier
/// incarnation established and refuses only what a later one did — is a
/// different shape and correctly does not use this type. Expressing such a rule
/// here would silently narrow it to equality and refuse the earlier
/// incarnation's work along with the later one's.
///
/// [`CutMark`]: crate::core::CutMark
/// [`CoverageWorkEpoch`]: tributary_proto::monitor::CoverageWorkEpoch
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stamped<S, T> {
  stamp: S,
  value: T,
}

/// Renders neither field, because a rendering is a read and this one would cost
/// no stamp.
///
/// Withholding the value is the point: printing it hands out exactly what
/// [`current`](Stamped::current) exists to charge for. The stamp goes with it
/// because a stamp is unforgeable only while it stays a value — a transparent
/// one, a plain counter say, renders as text that parses straight back into a
/// stamp, and a reader able to mint the stamp a sample carries can read that
/// sample under it. The impl asks nothing of `S` or `T`, so it is the only
/// `Debug` a `Stamped` can have and no carrier acquires a printing one by being
/// formattable itself.
impl<S, T> fmt::Debug for Stamped<S, T> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Stamped").finish_non_exhaustive()
  }
}

impl<S, T> Stamped<S, T> {
  /// Records `value` as minted under the incarnation `stamp` names.
  pub(crate) const fn new(stamp: S, value: T) -> Self {
    Self { stamp, value }
  }
}

impl<S: Eq, T> Stamped<S, T> {
  /// The value — and only when `current` is the incarnation it was minted
  /// under.
  ///
  /// This is the only way to the value. Nothing yields it unconditionally: a
  /// caller with no current stamp to offer has, by construction, nothing to
  /// read it against and so no basis for reading it.
  pub(crate) fn current(&self, current: S) -> Option<&T> {
    (self.stamp == current).then_some(&self.value)
  }
}

impl<S: Ord, T: Ord> Stamped<S, T> {
  /// Whether `other` supersedes `self`: a later incarnation does outright, and
  /// within one incarnation a greater value does.
  ///
  /// This answers which of two samples to keep — never how to combine them, and
  /// values are compared only when both speak for the same incarnation, so
  /// nothing is ever carried from one incarnation onto another. The comparison
  /// is made in here rather than by handing the two values out, because reading
  /// a value must go on costing a current stamp: two samples of a departed
  /// incarnation can be ranked against each other, and neither becomes readable
  /// for it.
  pub(crate) fn supersedes(&self, other: &Self) -> bool {
    match self.stamp.cmp(&other.stamp) {
      Ordering::Greater => true,
      Ordering::Equal => self.value > other.value,
      Ordering::Less => false,
    }
  }
}
