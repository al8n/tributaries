//! The stub seam for platforms without a backend — and for miri, which cannot
//! execute foreign calls: spawning always fails with
//! [`SourceError::Unsupported`], so a handle can never exist.

use std::path::PathBuf;

use super::{EventReceiver, ResumeToken, SourceConfig, SourceError};

/// The spawn entry point of the stub backend.
pub(crate) struct Source;

impl Source {
  /// Always fails: there is nothing to watch with on this platform.
  pub(crate) fn spawn(config: SourceConfig) -> Result<(SourceHandle, EventReceiver), SourceError> {
    let _ = config;
    Err(SourceError::Unsupported)
  }
}

/// Uninhabited: spawning never succeeds, so no handle value can exist and
/// every method body is statically unreachable.
pub(crate) enum SourceHandle {}

impl SourceHandle {
  /// Tears the (nonexistent) stream down.
  pub(crate) fn shutdown(self) {
    match self {}
  }

  /// Drains the overflow latch.
  pub(crate) fn take_overflow(&self) -> bool {
    match *self {}
  }

  /// The resume point minted so far.
  pub(crate) fn resume_token(&self) -> Option<ResumeToken> {
    match *self {}
  }

  /// The canonicalized roots the stream watches.
  pub(crate) fn roots(&self) -> &[PathBuf] {
    match *self {}
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn spawn_reports_unsupported() {
    let err = Source::spawn(SourceConfig::new(vec![PathBuf::from("/")]))
      .map(|_| ())
      .unwrap_err();
    assert!(matches!(err, SourceError::Unsupported));
  }
}
