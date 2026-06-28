//! Classification of a watch-installation outcome.

/// Why the driver could not establish a watch the core requested.
///
/// Reported back through [`on_watch_result`](crate::Monitor::on_watch_result).
/// Feeding this back is **mandatory**: without it the core would believe a watch
/// is live when the kernel refused it (e.g. `ENOSPC`), leaving a silent blind
/// spot. This is a coded classification, not this crate's own error type — the
/// core dispatches on it (a [`NoSpace`](Self::NoSpace) drives the degrade path,
/// a [`Gone`](Self::Gone) drops the node), so each kind is its own variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WatchError {
  /// The kernel watch limit was hit (inotify `ENOSPC` / `max_user_watches`).
  NoSpace,
  /// Permission was denied for the target (`EACCES` / `EPERM`).
  Permission,
  /// The target did not exist when the watch was attempted (`ENOENT`).
  NotFound,
  /// The target existed but vanished during installation (raced unlink / move).
  Gone,
  /// Any other I/O failure not worth a dedicated variant.
  Io,
}

impl WatchError {
  /// The stable snake_case name of this classification.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::NoSpace => "no_space",
      Self::Permission => "permission",
      Self::NotFound => "not_found",
      Self::Gone => "gone",
      Self::Io => "io",
    }
  }

  /// Whether this is [`NoSpace`](Self::NoSpace) — the watch-limit case that
  /// drives per-scope degradation rather than an outright failure.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_no_space(&self) -> bool {
    matches!(self, Self::NoSpace)
  }

  /// Whether this is [`Permission`](Self::Permission).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_permission(&self) -> bool {
    matches!(self, Self::Permission)
  }

  /// Whether this is [`NotFound`](Self::NotFound).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_not_found(&self) -> bool {
    matches!(self, Self::NotFound)
  }

  /// Whether this is [`Gone`](Self::Gone).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_gone(&self) -> bool {
    matches!(self, Self::Gone)
  }

  /// Whether this is [`Io`](Self::Io).
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_io(&self) -> bool {
    matches!(self, Self::Io)
  }
}

impl core::fmt::Display for WatchError {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

#[cfg(test)]
mod tests;
