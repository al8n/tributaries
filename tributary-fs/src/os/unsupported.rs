//! The stub seam for platforms without a backend — and for miri, which cannot
//! execute foreign calls: spawning always fails with
//! [`SourceError::Unsupported`], so a handle can never exist.

use std::path::{Path, PathBuf};

use super::{EventReceiver, ResumeToken, RootMeta, SourceConfig, SourceError};

/// The spawn entry point of the stub backend.
pub(crate) struct Source;

impl Source {
  /// Always fails: there is nothing to watch with on this platform. The
  /// signature still carries the [`RootMeta`] contract — a spawn finalizes
  /// its root metadata before the stream can enqueue its first event.
  pub(crate) fn spawn(
    config: SourceConfig,
  ) -> Result<(SourceHandle, EventReceiver, RootMeta), SourceError> {
    let _ = config;
    Err(SourceError::Unsupported)
  }
}

/// The mount table cannot be read on a platform with no backend.
pub(crate) fn mounts_under(root: &Path) -> Option<Vec<PathBuf>> {
  let _ = root;
  None
}

/// Uninhabited: spawning never succeeds, so no handle value can exist and
/// every method body is statically unreachable.
pub(crate) enum SourceHandle {}

impl SourceHandle {
  /// Tears the (nonexistent) stream down.
  pub(crate) fn shutdown(self) -> super::Quiesce {
    match self {}
  }

  /// The resume point minted so far.
  // Journal resume is deferred surface; minted, not yet consumed.
  #[allow(dead_code)]
  pub(crate) fn resume_token(&self) -> Option<ResumeToken> {
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
