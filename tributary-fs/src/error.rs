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

/// Why [`Watcher::sync_root`](crate::Watcher::sync_root) could not place a
/// sync cookie. The barrier's *observation* is the caller's job (the cookie's
/// event arrives on the stream); this error covers only the placement.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SyncRootError {
  /// The handle does not name a live root of this watcher.
  #[error("the handle does not name a live root of this watcher")]
  UnknownRoot,
  /// The cookie directory is not inside the root's coverage — a cookie
  /// written there could never be reported on this root's stream.
  #[error("cookie directory {} is outside root {}", dir.display(), root.display())]
  DirOutsideRoot {
    /// The requested cookie directory.
    dir: PathBuf,
    /// The root it must be inside.
    root: PathBuf,
  },
  /// The cookie could not be written. A read-only tree surfaces here as
  /// [`std::io::ErrorKind::PermissionDenied`] — the honest refusal: a tree
  /// with no writable covered location cannot support a kernel-mediated
  /// barrier at all.
  #[error("could not write sync cookie {}: {source}", path.display())]
  Write {
    /// The cookie path the write was attempted at.
    path: PathBuf,
    /// The underlying failure.
    #[source]
    source: std::io::Error,
  },
  /// The root died (or was unwatched) while the cookie write was parked on
  /// the coverage-settle fence.
  #[error("the root died while the sync cookie was pending")]
  Retired,
  /// The watcher is closed.
  #[error("the watcher is closed")]
  Closed,
}

/// Why [`Watcher::replace_root`](crate::Watcher::replace_root) failed. The
/// operation is atomic-on-failure: every variant leaves the old root's
/// coverage untouched.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReplaceRootError {
  /// The new root does not exist.
  #[error("replacement root {} does not exist", path.display())]
  NotFound {
    /// The path as the caller supplied it.
    path: PathBuf,
  },
  /// The new root exists but is not a directory.
  #[error("replacement root {} is not a directory", path.display())]
  NotADirectory {
    /// The canonicalized path.
    path: PathBuf,
  },
  /// The new root overlaps a DIFFERENT live (or reserved) root. The root
  /// being replaced is exempt — overlapping it is the operation's point.
  #[error("replacement root {} overlaps live root {}", path.display(), existing.display())]
  Overlaps {
    /// The canonicalized new root.
    path: PathBuf,
    /// The conflicting coverage.
    existing: PathBuf,
  },
  /// The handle does not name a live root of this watcher.
  #[error("the handle does not name a live root of this watcher")]
  UnknownRoot,
  /// A replace is already in flight on this root.
  #[error("a replace is already in flight on this root")]
  ReplaceInFlight,
  /// The new root resolved to a different lowering profile than the live
  /// scope runs (a descending↔kernel-recursive flip, e.g. a Linux
  /// `Backend::Auto` landing on fanotify for one volume and inotify for the
  /// other). A live scope never swaps lowering profiles; unwatch + watch is
  /// the sanctioned transition.
  #[error("the replacement resolved to a different lowering profile")]
  BackendDiverged,
  /// The root died (or was unwatched) while the replacement was starting —
  /// death wins, and the scope ended through its normal lifecycle. The new
  /// stream was torn down; retry against a fresh `watch`.
  #[error("the root died while the replacement was starting")]
  Retired,
  /// The watcher is closed.
  #[error("the watcher is closed")]
  Closed,
  /// The replacement stream could not start.
  #[error(transparent)]
  Source(#[from] SourceError),
}
