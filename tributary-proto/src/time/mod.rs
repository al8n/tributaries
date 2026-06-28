//! A portable, clock-agnostic monotonic instant.

use core::{ops::Add, time::Duration};

/// A monotonic instant: a [`Duration`] since an opaque per-process origin the
/// driver chooses at startup.
///
/// The pure core never reads a wall clock; every time-dependent input
/// ([`on_os_record`](crate::Monitor::on_os_record),
/// [`handle_timeout`](crate::Monitor::handle_timeout), …) is handed a `now`,
/// and the core only does relative arithmetic with it. Each driver maps its
/// runtime clock into this type at the boundary (`std::time::Instant` minus a
/// captured origin, `embassy_time::Instant`, …), so the same logic is portable
/// across `std`, embedded, and test clocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(Duration);

impl Instant {
  /// The origin instant: zero elapsed since the driver's chosen epoch.
  pub const ORIGIN: Self = Self(Duration::ZERO);

  /// Builds an instant from the [`Duration`] elapsed since the driver's origin.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn from_origin(elapsed: Duration) -> Self {
    Self(elapsed)
  }

  /// The [`Duration`] elapsed since the driver's origin.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn elapsed_since_origin(&self) -> Duration {
    self.0
  }

  /// The [`Duration`] from `earlier` to `self`.
  ///
  /// Saturating: an out-of-order pair yields [`Duration::ZERO`] rather than
  /// panicking, so a driver that hands instants slightly out of order can never
  /// crash the core.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn duration_since(self, earlier: Self) -> Duration {
    self.0.saturating_sub(earlier.0)
  }

  /// Whether `self` is at or after `deadline`.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn reached(self, deadline: Self) -> bool {
    self.0.as_nanos() >= deadline.0.as_nanos()
  }
}

impl Add<Duration> for Instant {
  type Output = Self;

  #[cfg_attr(not(tarpaulin), inline(always))]
  fn add(self, rhs: Duration) -> Self {
    Self(self.0.saturating_add(rhs))
  }
}

#[cfg(test)]
mod tests;
