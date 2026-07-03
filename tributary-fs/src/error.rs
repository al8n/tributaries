//! The watcher's error vocabulary.
//!
//! Errors cover construction and root registration only: once a root is live,
//! every condition — a vanished root, kernel-side loss, a lagging consumer —
//! arrives as an in-band [`Event`](crate::Event) (a `Removed`, a `Rescan`),
//! never as a stream error.

use std::path::PathBuf;

use crate::os::SourceError;

/// Why a [`Watcher`](crate::Watcher) could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
  /// More exclusion paths than the OS honors were configured (the FSEvents
  /// limit is [`WatcherOptions::MAX_EXCLUSIONS`](crate::WatcherOptions::MAX_EXCLUSIONS)).
  #[error(
    "{supplied} exclusion paths exceed the OS limit of {}",
    crate::os::MAX_EXCLUSIONS
  )]
  TooManyExclusions {
    /// How many exclusion paths the options carried.
    supplied: usize,
  },
}

impl BuildError {
  /// Whether this is [`TooManyExclusions`](Self::TooManyExclusions).
  #[inline]
  pub const fn is_too_many_exclusions(&self) -> bool {
    matches!(self, Self::TooManyExclusions { .. })
  }
}

/// Why a root could not be watched.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WatchRootError {
  /// The root does not exist.
  #[error("watch root {} does not exist", path.display())]
  NotFound {
    /// The root as the caller supplied it.
    path: PathBuf,
  },
  /// The root exists but is not a directory.
  #[error("watch root {} is not a directory", path.display())]
  NotADirectory {
    /// The canonicalized root.
    path: PathBuf,
  },
  /// The root overlaps a root this watcher already covers. Roots must be
  /// disjoint; subsuming overlapping trees is the layer above's job.
  #[error("watch root {} overlaps the already-watched {}", path.display(), existing.display())]
  Overlaps {
    /// The canonicalized root that was rejected.
    path: PathBuf,
    /// The already-watched root it overlaps.
    existing: PathBuf,
  },
  /// The platform source could not start.
  #[error("the platform source could not start")]
  Source(#[source] SourceError),
  /// The watcher's driver has already stopped.
  #[error("the watcher is closed")]
  Closed,
}

impl WatchRootError {
  /// Whether this is [`NotFound`](Self::NotFound).
  #[inline]
  pub const fn is_not_found(&self) -> bool {
    matches!(self, Self::NotFound { .. })
  }

  /// Whether this is [`NotADirectory`](Self::NotADirectory).
  #[inline]
  pub const fn is_not_a_directory(&self) -> bool {
    matches!(self, Self::NotADirectory { .. })
  }

  /// Whether this is [`Overlaps`](Self::Overlaps).
  #[inline]
  pub const fn is_overlaps(&self) -> bool {
    matches!(self, Self::Overlaps { .. })
  }

  /// Whether this is [`Source`](Self::Source).
  #[inline]
  pub const fn is_source(&self) -> bool {
    matches!(self, Self::Source(_))
  }

  /// Whether this is [`Closed`](Self::Closed).
  #[inline]
  pub const fn is_closed(&self) -> bool {
    matches!(self, Self::Closed)
  }
}

/// Why a root could not be unwatched.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UnwatchError {
  /// The handle does not name a live root of this watcher (never watched,
  /// already unwatched, or torn down by a root-death event).
  #[error("the root handle is not watched")]
  UnknownRoot,
  /// The watcher's driver has already stopped.
  #[error("the watcher is closed")]
  Closed,
}

impl UnwatchError {
  /// Whether this is [`UnknownRoot`](Self::UnknownRoot).
  #[inline]
  pub const fn is_unknown_root(&self) -> bool {
    matches!(self, Self::UnknownRoot)
  }

  /// Whether this is [`Closed`](Self::Closed).
  #[inline]
  pub const fn is_closed(&self) -> bool {
    matches!(self, Self::Closed)
  }
}

/// Why an orderly [`close`](crate::Watcher::close) could not be confirmed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CloseError {
  /// The driver stopped before confirming the shutdown (it panicked or was
  /// torn down externally); streams are still reclaimed at process exit.
  #[error("the driver stopped before confirming the shutdown")]
  Stopped,
  /// The close grace expired with stream work still executing on the blocking
  /// pool: teardowns still inside their `shutdown` calls, or spawns that may
  /// already own a live stream (the backend starts the stream and then
  /// performs post-live metadata reads inside the same call). Neither proves
  /// quiescence at reply time. Their reclamation stories differ: a wedged
  /// teardown's stream is unreachable until the call returns (the OS reclaims
  /// at process exit), while a wedged spawn's stream is reclaimed by its
  /// undeliverable result dropping the handle once the wedge clears.
  #[error("{pending} stream operation(s) still executing when the close grace expired")]
  NotQuiesced {
    /// How many spawns and teardowns were still executing at grace expiry.
    pending: usize,
  },
}

impl CloseError {
  /// Whether this is [`Stopped`](Self::Stopped).
  #[inline]
  pub const fn is_stopped(&self) -> bool {
    matches!(self, Self::Stopped)
  }

  /// Whether this is [`NotQuiesced`](Self::NotQuiesced).
  #[inline]
  pub const fn is_not_quiesced(&self) -> bool {
    matches!(self, Self::NotQuiesced { .. })
  }
}
