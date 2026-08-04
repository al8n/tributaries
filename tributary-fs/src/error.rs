//! The watcher's error vocabulary.
//!
//! Errors cover construction and root registration only: once a root is live,
//! every condition — a vanished root, kernel-side loss, a lagging consumer —
//! arrives as an in-band [`Event`](crate::Event) (a `Removed`, a `Rescan`),
//! never as a stream error.

use std::path::PathBuf;

use crate::{options::OptionsError, os::SourceError};

/// Why a [`Watcher`](crate::Watcher) could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
  /// A configured option lies outside its documented range. The whole
  /// range-checking vocabulary lives with the options
  /// ([`WatcherOptions::validate`](crate::WatcherOptions::validate)), so the
  /// verdict a configuration layer computes and the one the watcher computes
  /// are the same value.
  #[error(transparent)]
  InvalidOptions(#[from] OptionsError),
}

impl BuildError {
  /// Whether this is [`InvalidOptions`](Self::InvalidOptions).
  #[inline]
  pub const fn is_invalid_options(&self) -> bool {
    matches!(self, Self::InvalidOptions(_))
  }

  /// Whether the options carried more exclusion paths than the OS honors.
  #[inline]
  pub const fn is_too_many_exclusions(&self) -> bool {
    matches!(self, Self::InvalidOptions(err) if err.is_too_many_exclusions())
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
  /// Too many native streams are still winding down. Every stream this watcher
  /// retires is handed to a dedicated teardown executor whose `shutdown` call is
  /// UNBOUNDED — a reader parked in a syscall against a wedged mount returns when
  /// the kernel says so — so a watcher that kept admitting new streams while old
  /// ones cannot quiesce would grow retained OS handles, reader threads and
  /// buffers with total churn rather than with live coverage. Admission stops at
  /// the backlog bound instead. Retryable: it clears as the wedged teardowns
  /// return, with no operator action.
  #[error("too many native streams are still winding down; retry later")]
  CleanupBacklog,
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
  /// This root already has the maximum number of awaited unwatches parked on a
  /// teardown that has not quiesced. An awaited unwatch resolves only once the
  /// root's native stream is gone, and that wait is unbounded against a wedged
  /// filesystem — so every duplicate call is retained by the driver until it
  /// ends. The bounded command mailbox limits only requests waiting to be
  /// received, not the ones already admitted, so admission stops here instead of
  /// growing driver state with total calls. The teardown itself was already
  /// triggered by the first call; retry to observe it, or drop the handle.
  #[error("the root's teardown already has the maximum awaited unwatches parked; retry later")]
  Backlogged,
  /// The root stopped being watched, but its native stream was never PROVEN
  /// quiescent: one of the scope's teardowns unwound part-way through the
  /// backend's `shutdown` (a panicking invariant check, a poisoned lock), so
  /// nothing observed the stream stop.
  ///
  /// A successful [`unwatch`](crate::Watcher::unwatch) means the native source
  /// has reached quiescence — that is what makes it safe to release whatever the
  /// stream could still reach (a callback's captured state, a buffer the reader
  /// writes into, the root directory itself). This error withholds exactly that
  /// guarantee: the reader thread, registered callbacks and open descriptors of
  /// the affected stream may still be live, and no later call can prove
  /// otherwise — the driver latches the root's scope, so every subsequent
  /// awaited unwatch of it reports this too, and
  /// [`close`](crate::Watcher::close) counts it among the operations that
  /// refuse a quiescent verdict.
  ///
  /// NOT retryable, and not a request failure: the teardown itself ran and the
  /// root is no longer watched. Treat it as a permanently degraded reclamation —
  /// keep whatever the stream might touch alive for the process's lifetime, or
  /// end the process to reclaim it.
  #[error("the root's native stream was never proven quiescent: its teardown unwound")]
  NotQuiesced,
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

  /// Whether this is [`Backlogged`](Self::Backlogged).
  #[inline]
  pub const fn is_backlogged(&self) -> bool {
    matches!(self, Self::Backlogged)
  }

  /// Whether this is [`NotQuiesced`](Self::NotQuiesced).
  #[inline]
  pub const fn is_not_quiesced(&self) -> bool {
    matches!(self, Self::NotQuiesced)
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
  /// The close grace expired with work still OUTSTANDING: teardowns still inside
  /// their `shutdown` calls, spawns that may already own a live stream (the
  /// backend starts the stream and then performs post-live metadata reads inside
  /// the same call), or a sync cookie the driver wrote but could not CONFIRM
  /// removed within the grace — an unlink still in flight, or one whose retries
  /// the grace outran (a parked record awaiting the terminal sweep is counted
  /// too: it is owned-and-unremoved, not merely executing). None proves
  /// quiescence at reply time. Their reclamation stories differ: a wedged
  /// teardown's stream is unreachable until the call returns (the OS reclaims at
  /// process exit), a wedged spawn's stream is reclaimed by its undeliverable
  /// result dropping the handle once the wedge clears, and an unremoved cookie
  /// leaves its file until the mount unwedges (the registry's best-effort
  /// terminal sweep retries it) — but close reports the outstanding count
  /// honestly rather than hanging on any of them.
  #[error("{pending} operation(s) still outstanding when the close grace expired")]
  NotQuiesced {
    /// How many stream spawns/teardowns and owned-but-unconfirmed cookies were
    /// still outstanding at grace expiry.
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
  /// The [`SyncTicket`](crate::SyncTicket) was minted by a DIFFERENT watcher.
  /// Refused synchronously, before any write: a ticket's sequence numbering is
  /// per-watcher, so honoring a foreign one would let it alias one of this
  /// watcher's incarnations. Mint the ticket from the same watcher the sync runs
  /// on ([`Watcher::mint_sync_ticket`](crate::Watcher::mint_sync_ticket)).
  #[error("the sync ticket was minted by a different watcher")]
  ForeignTicket,
  /// The cookie directory is not inside the root's coverage — a cookie
  /// written there could never be reported on this root's stream. Also raised
  /// when the directory only *appears* inside the root through `..` traversal
  /// (`<root>/../outside`), which a lexical `starts_with` would accept.
  #[error("cookie directory {} is outside root {}", dir.display(), root.display())]
  DirOutsideRoot {
    /// The requested cookie directory.
    dir: PathBuf,
    /// The root it must be inside.
    root: PathBuf,
  },
  /// The cookie directory lies inside the root but under one of the configured
  /// [exclusions](crate::WatcherOptions::with_exclusions) —
  /// so the write would succeed and its event would then be suppressed by the
  /// very option that asked for the suppression, leaving the barrier waiting on
  /// an event that cannot exist. Refused before any write; pick a cookie
  /// directory outside every exclusion.
  ///
  /// Exclusions apply to every root on every platform, so the refusal is the
  /// same everywhere — it does not depend on which backend resolved, and it is
  /// made before the write rather than discovered by waiting.
  #[error(
    "cookie directory {} is under excluded directory {}",
    dir.display(),
    exclusion.display()
  )]
  DirExcluded {
    /// The requested cookie directory.
    dir: PathBuf,
    /// The exclusion covering it, as supplied in the options.
    exclusion: PathBuf,
  },
  /// The cookie name is not a single normal filename component — it holds a
  /// path separator, a `.`/`..`, or is absolute or empty. A name like this
  /// would escape the directory the barrier was validated for, so it is refused
  /// before any write. The umbrella mints names that never trip this; a caller
  /// that hits it violated the reserved-namespace contract.
  #[error("cookie name {name:?} is not a single normal filename component")]
  BadCookieName {
    /// The offending name as supplied.
    name: String,
  },
  /// The cookie could not be written. A read-only tree surfaces here as
  /// [`std::io::ErrorKind::PermissionDenied`] — the honest refusal: a tree
  /// with no writable covered location cannot support a kernel-mediated
  /// barrier at all.
  #[error("could not write sync cookie {}: {source}", path.display())]
  Write {
    /// Where the write was aimed — `dir` joined with the cookie name. It is a
    /// DESCRIPTION of the request, not a landing: a cookie that succeeds lands
    /// one level deeper, in the watcher's own reserved-namespace directory, and
    /// only [`Watcher::sync_root`](crate::Watcher::sync_root)'s return value ever
    /// says where.
    path: PathBuf,
    /// The underlying failure.
    #[source]
    source: std::io::Error,
  },
  /// A physical cookie write for this root is already in flight. The barrier is
  /// single-flighted per root: at most one physical write may be outstanding at
  /// a time, so a caller that times out and retries cannot pile unbounded
  /// blocking writes against a hung mount. Retry once the outstanding write
  /// resolves.
  #[error("a sync cookie write is already in flight for this root")]
  WriteInFlight,
  /// A live sync obligation of this watcher already holds this cookie name —
  /// admitting a second would make cancel-by-name ambiguous and could target
  /// another root's sync. The name is freed when the holding obligation reaches
  /// its terminal (its cookie confirmed removed, or the sync retired), so
  /// sequential reuse of a name admits; concurrent syncs need distinct names
  /// (the umbrella's minted names are always distinct).
  #[error("cookie name {name:?} is already held by a live sync of this watcher")]
  NameInUse {
    /// The contested name as supplied.
    name: String,
  },
  /// A LIVE sync obligation of this watcher already holds this admission's mint
  /// sequence. From the safe [`sync_root`](crate::Watcher::sync_root) API this is
  /// now unreachable — the move-only [`SyncAdmission`](crate::SyncAdmission) makes
  /// presenting one sequence to two syncs a compile error — so it is retained as a
  /// driver-internal invariant. The refusal is pre-birth and creates nothing, so
  /// [`sync_root`](crate::Watcher::sync_root) hands the admission back in
  /// [`SyncRootDenied`](crate::SyncRootDenied) for a same-sequence retry; the
  /// paired [`SyncTicket`](crate::SyncTicket) remains the forever cancel key.
  #[error("the sync ticket is already held by a live sync of this watcher")]
  TicketInUse {},
  /// This root has too many unremoved cookies: its cleanup owner is retrying
  /// failing unlinks (a pathological filesystem where writes succeed but unlinks
  /// keep failing), and the per-root backlog cap has been reached. Retryable —
  /// once the backlog drains, syncs resume with no operator action.
  #[error("the root's sync cookie cleanup is backlogged; retry later")]
  CleanupBacklog,
  /// The barrier outlived the coverage it was to be written under: the root died (or was
  /// unwatched) while the write was parked on the coverage-settle fence, or the scope retired —
  /// or the driver itself shut down — while the write was already in flight. In the latter cases
  /// the cookie file is unlinked again before this is reported, so a refused barrier never leaves
  /// a marker behind.
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
  /// Too many native streams are still winding down; see
  /// [`WatchRootError::CleanupBacklog`]. A make-before-break replacement RETIRES
  /// the old stream, so a supervisor retargeting a watch against a dead mount is
  /// the shortest path to an unbounded pile of handles no teardown can reclaim:
  /// the replaced handle's `shutdown` never returns, yet the replacement reports
  /// success and admits the next one. Admission stops at the backlog bound
  /// instead, leaving the current root's coverage untouched. Retryable.
  #[error("too many native streams are still winding down; retry later")]
  CleanupBacklog,
  /// The watcher is closed.
  #[error("the watcher is closed")]
  Closed,
  /// The replacement stream could not start.
  #[error(transparent)]
  Source(#[from] SourceError),
}
