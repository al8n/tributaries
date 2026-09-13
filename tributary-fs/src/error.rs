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
  /// The driver minted a [`ScopeId`](crate::ScopeId) that already names a live
  /// watched root, so the registration was refused rather than allowed to
  /// overwrite the incumbent's bookkeeping.
  ///
  /// Unreachable through this watcher: its scope ids are minted from a
  /// monotonic counter that never reuses a value, so no `watch` call can
  /// collide. The condition is reported instead of asserted because the refusal
  /// it carries belongs to `tributary-proto`, whose scope ids are supplied by
  /// the driver — an out-of-tree driver CAN collide, and turning its mistake
  /// into a panic here would deny it the one signal it can act on. Treat it as
  /// a bug in whatever minted the id; retrying cannot clear it.
  #[error("the minted scope already names a live watched root")]
  ScopeInUse,
  /// A bounded quantity in the per-root household is out of range — the same
  /// door-side refusal [`BuildError::InvalidOptions`] is for the watcher-wide
  /// one, and for the same reason: a legal-but-extreme configuration value
  /// becomes a typed error before any coverage exists rather than a cost nothing
  /// bounds afterwards.
  #[error(transparent)]
  InvalidOptions(#[from] OptionsError),
  /// The watcher's driver has already stopped.
  #[error("the watcher is closed")]
  Closed,
}

impl WatchRootError {
  /// Whether this is [`InvalidOptions`](Self::InvalidOptions).
  #[inline]
  pub const fn is_invalid_options(&self) -> bool {
    matches!(self, Self::InvalidOptions(_))
  }

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
  /// (`<root>/../outside`), which a lexical `starts_with` would accept, and when
  /// the directory the admission actually reached — every symlink in the
  /// spelling followed — stands outside the root, in which case
  /// [`dir`](Self::DirOutsideRoot::dir) is that location rather than the
  /// spelling.
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
  ///
  /// The verdict is taken THREE times, because a spelling is not a location and
  /// a location is not a history. The admission judges `dir` as supplied, which
  /// costs nothing and refuses the common case synchronously; it then judges
  /// where the directory it opened for this sync actually STOOD when the
  /// barrier's coverage was cut — every symlink in the spelling followed, and
  /// the cookie-goes-beside-a-file rule applied — because a directory that was
  /// unreportable then carries descendants no stream of this root ever reported;
  /// and the write judges the directory it resolves at the moment it creates,
  /// because that is where the marker lands. A link whose spelling clears every
  /// exclusion and whose target sits inside one is refused by the second check,
  /// with [`dir`](Self::DirExcluded::dir) naming the resolved directory rather
  /// than the spelling. Since the caller cannot tell which check refused, the
  /// admission's sequence is treated as spent for all three — re-mint to retry.
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
  /// The set-cover narrowed the root's coverage past this directory; a marker
  /// written there could never be observed.
  ///
  /// A [`set_cover`](crate::Watcher::set_cover) on a descending backend drops the
  /// per-directory watches strictly outside the retained set — that is what it is
  /// for. Ground outside the applied cover therefore has no watch to report a
  /// create, and the barrier would wait on an event no source can produce. The
  /// same shape as [`DirExcluded`](Self::DirExcluded) and
  /// [`DirPruned`](Self::DirPruned) — a configuration word the caller said, this
  /// one through the cover rather than the options — and refused for the same
  /// reason, before anything is created.
  ///
  /// The verdict is LEXICAL, taken against the cover the core last applied: the
  /// directory must be an ancestor or a descendant of a retained prefix. It cannot
  /// arise on a kernel-recursive backend (a whole-subtree stream never narrows) nor
  /// on a scope no cover ever narrowed. It is refused BEFORE the sync is admitted,
  /// so the admission's sequence is untouched — widen the cover to include the
  /// directory (or sync a covered one) and retry with the same
  /// [`SyncTicket`](crate::SyncTicket).
  ///
  /// The watcher's own reserved cookie directory inside a COVERED directory is not
  /// what this refuses: a cover cannot know that directory's name, so the core
  /// keeps its watch armed across the cut rather than obliging every caller to
  /// retain it.
  #[error("cookie directory {} is outside the root's applied cover", dir.display())]
  DirUncovered {
    /// The requested cookie directory.
    dir: PathBuf,
  },
  /// The cookie directory lies inside the root but under a subtree the root's
  /// own [`prune`](crate::RootOptions::prune) seat covers — the per-root,
  /// glob-shaped twin of [`DirExcluded`](Self::DirExcluded), refused for exactly
  /// the same reason. The write would succeed and its event would then be
  /// suppressed by the very pattern that asked for the suppression, leaving the
  /// barrier waiting on an event that cannot exist.
  ///
  /// The pattern is carried because it is the actionable half: a caller reading
  /// "your cookie directory is pruned" cannot fix it, and one reading "…by
  /// `**/.cache`" can. The verdict is taken on the DIRECTORY path, which with a
  /// seat that speaks for directories alone is the only thing a pattern can
  /// prune; pick a cookie directory no pattern covers, or widen the seat.
  ///
  /// [`dir`](Self::DirPruned::dir) is the CANONICAL directory the write itself
  /// resolved — the target's own directory, or its parent when the target is a
  /// file, with every symlink on the way followed — rather than the spelling the
  /// caller passed. That is the path the cookie would truly have landed in, and
  /// judging any other one gets the answer wrong in both directions: a link into a
  /// pruned subtree passes a lexical test it should fail, and a file
  /// subscription's own key fails a test it should never have been given (the seat
  /// speaks for directories, and the file's parent is what the cookie goes in).
  /// The refusal is taken there, before anything is created — which is also why
  /// the admission's sequence is spent by it.
  ///
  /// It is taken at the ADMISSION too, on the same resolved form: where the
  /// directory opened for this sync stood at the moment the barrier's coverage
  /// was cut. Ground the seat covered then is ground whose descendants no stream
  /// of this root ever reported, so a marker placed among them could be ordered
  /// ahead of changes that truly preceded it — a refusal, and one taken before
  /// any coverage window is opened.
  ///
  /// Unlike the exclusions this is per ROOT, so the same directory may be
  /// perfectly writable for a sync on another root of the same watcher.
  #[error("cookie directory {} is pruned by {pattern}", dir.display())]
  DirPruned {
    /// The requested cookie directory.
    dir: PathBuf,
    /// The pattern of the root's prune seat that covers it.
    pattern: tributary_proto::glob::Glob,
  },
  /// The directory the cookie would have gone in is no longer the OBJECT the
  /// sync was admitted for: a peer renamed that directory aside and stood a
  /// replacement at its name after the admission and before the write.
  ///
  /// A barrier certifies ordering for the directory object that existed at
  /// admission, and only for it. A replacement standing at the same name is a
  /// different object, and the queue that would carry the marker's create is not
  /// yet attached to it — so a marker born there rides no ordering this root's
  /// stream reads, and a later cold enumeration of the replacement could
  /// synthesize that create ahead of changes that truly preceded it. The write is
  /// therefore refused with nothing created, rather than reporting a barrier that
  /// certifies an ordering nobody proved.
  ///
  /// It also answers for the watcher's own reserved cookie directory one level
  /// inside `dir`, on the two questions that directory raises. One standing there
  /// must be the object the admission read; one this write CREATED must hold
  /// nothing but this write's marker once that marker exists, because a directory
  /// a peer exchanged in carries changes older than the marker that no queue of
  /// this root reported. The second reading is about the whole directory, so a
  /// second watcher of the same user that creates a marker of its own inside that
  /// one create-and-enumerate window is refused here too — retry, and the reserved
  /// directory now standing is read by the fresh admission and adopted on the
  /// identity instead.
  ///
  /// The admission's sequence is SPENT: the verdict needs the object only the
  /// write's own descriptor walk can reach, so it is taken after the sync was
  /// admitted. Re-mint through
  /// [`mint_sync_ticket`](crate::Watcher::mint_sync_ticket) to retry, which
  /// re-reads the directory that now stands at the name.
  #[error("cookie directory {} was replaced after the sync was admitted", dir.display())]
  DirReplaced {
    /// The cookie parent the write resolved — the name the replacement stands
    /// at, as the descriptor answered it.
    dir: PathBuf,
  },
  /// A directory on the chain from the watched root down to the marker stands
  /// across a MOUNT BOUNDARY: either a component of the descent from the root to
  /// the directory the sync named, or the reserved cookie-directory name itself —
  /// the private directory this watcher's markers go in, one level inside the
  /// directory the sync named.
  ///
  /// The rule is the mount FRAME, not the device. A `mount --bind` of a
  /// same-superblock directory shares its parent's device exactly, so a device
  /// comparison cannot see one at all, while the root's crawl — which fences its
  /// descent on the mount id — treats it as a boundary and never enumerates
  /// anything beneath it. Where no mount id can be read (Linux below 5.8, and
  /// macOS, which has no bind mounts and gives every mount its own device) the
  /// device is the whole of the rule, which is the same honest degrade the crawl
  /// takes.
  ///
  /// A root's crawl does not descend across a mount, so ground beyond one is never
  /// enumerated and no watch is ever armed inside it. A marker created there is
  /// unreportable however it is ordered, and the barrier waiting on its event could
  /// only time out — so the write is refused with nothing created, exactly as
  /// [`DirPruned`](Self::DirPruned) and [`DirExcluded`](Self::DirExcluded) are, and
  /// for the same reason: a barrier no source can report is not a barrier.
  ///
  /// Unlike those two this is not a configuration word but the shape of the tree,
  /// and it is not transient either — a retry finds the same mount. Sync a
  /// directory on the root's own mount instead, or take the mount off the name.
  ///
  /// # Two origins, and one of them precedes the sync's own sequence
  ///
  /// The verdict is reached at the WRITE, on the objects that write's descriptor
  /// walk reaches, and at the ADMISSION, on the mounts the door read off the pins
  /// it took — the same rule at both ends, for the reason every ground verdict is
  /// asked twice: the objects must stand in reportable ground when the coverage cut
  /// is taken AND when the marker is created. The admission's reading is what
  /// refuses a bind alias of outside ground standing inside the root, which is
  /// lexically contained, covered by no seat, and identical to its origin through
  /// the alias — so nothing else the door can read names it.
  ///
  /// Either way the admission's sequence is SPENT, so a retry re-mints through
  /// [`mint_sync_ticket`](crate::Watcher::mint_sync_ticket). A refusal from the
  /// admission is taken before any coverage window opens and creates nothing at
  /// all; a refusal from the write leaves nothing on disk either.
  #[error("cookie directory {} lies across a mount boundary", dir.display())]
  DirCrossesMount {
    /// The directory that crossed, as the descriptor holding it answered its name:
    /// the FIRST component of the descent to stand outside the root's mount frame,
    /// the reserved cookie directory standing at the reserved name when the whole
    /// descent stayed inside it, or — from the admission — the place the pinned
    /// target or reserved directory was standing when the door sampled it.
    dir: PathBuf,
  },
  /// The cookie name is not a single normal filename component — it holds a
  /// path separator, a `.`/`..`, is absolute or empty, or is longer than 255
  /// bytes (`NAME_MAX` on every supported filesystem, so a longer leaf names
  /// nothing that could ever be created). A name like this would escape the
  /// directory the barrier was validated for, so it is refused before any write
  /// — and before it is stored, so an unbounded one cannot be retained by a
  /// bookkeeping that counts records rather than bytes.
  ///
  /// **Not reachable through [`Watcher::sync_root`](crate::Watcher::sync_root).**
  /// That call takes no name: the leaf is minted with the admission
  /// ([`SyncTicket::leaf`](crate::SyncTicket::leaf)) and is one normal component
  /// by construction. The variant survives as the driver's own fail-closed
  /// invariant, and as a stable spelling of what that invariant guards.
  #[error("cookie name {name:?} is not a single normal filename component")]
  BadCookieName {
    /// The offending name as supplied.
    name: String,
  },
  /// The cookie could not be written. A read-only tree surfaces here as
  /// [`std::io::ErrorKind::PermissionDenied`] — the honest refusal: a tree
  /// with no writable covered location cannot support a kernel-mediated
  /// barrier at all.
  ///
  /// It is also what the admission door answers when it cannot HOLD the
  /// directories a sync is judged against — a descriptor table with no room left
  /// (`EMFILE`/`ENFILE`), a directory this process may not open, or a
  /// non-directory standing at the watcher's reserved cookie name. That refusal
  /// creates nothing, but a caller cannot tell it apart from the write's own
  /// failure and neither can the classification, so its sequence is spent with
  /// every other `Write`'s. A name nothing answers at is NOT one of these: an
  /// absent directory is a reading the write reasons from, not a failure to take
  /// one.
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
  /// sequential reuse of a name admits.
  ///
  /// **Not reachable through [`Watcher::sync_root`](crate::Watcher::sync_root).**
  /// Every leaf is minted from its own admission and carries that admission's
  /// nonce, so two live syncs of one watcher cannot collide on a name. The variant
  /// survives as the driver's own fail-closed invariant.
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
  /// A coverage transition on the barrier's ground retired it before it was
  /// installed; the covering `Rescan` is on the stream; retry.
  ///
  /// The barrier is dispatched under a coverage epoch and certifies delivery only
  /// within it. A transition that touches the ground the barrier depends on —
  /// a watch armed or dropped beneath it, a root replaced, a cover shrunk over
  /// it — while the barrier is live retires it, dominated by the located `Rescan`
  /// that transition stands, never as a certificate.
  ///
  /// This is the PRE-INSTALL half of that answer: the obligation was retired
  /// before its reply was sent. It is not
  /// [`CleanupBacklog`](Self::CleanupBacklog)-shaped backpressure — the caller's
  /// barrier is already met by the re-enumeration instruction now on its stream,
  /// so telling it to retry-because-busy would livelock it against a tree
  /// churning faster than one round trip. Re-read the ground the `Rescan` names,
  /// then re-mint if a fresh barrier is still wanted.
  #[error("a coverage transition retired the sync barrier; the covering rescan is on the stream")]
  Dominated,
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
