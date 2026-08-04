//! The umbrella crate's **source-neutral** error vocabulary.
//!
//! The umbrella owns this vocabulary exactly as it owns the event vocabulary
//! ([`EventKind`](crate::EventKind)): every [`Source`](crate::Source) — the fs binding
//! included — maps its own failures into it at its binding, so no source's error enum
//! leaks through the generic seam. A classified failure travels as a [`SourceFault`]
//! (a neutral [`FaultKind`] plus the concrete source error boxed behind the standard
//! error chain), and the concrete error stays recoverable via
//! [`SourceFault::downcast_ref`] — for the default fs source, the
//! [`WatchError::as_fs`] sugar.
//!
//! Note the absence of any overlap variant: subsuming overlapping subscriptions into
//! disjoint roots is precisely this layer's job, so the overlap a source rejects can
//! never reach the caller here (a [`FaultKind::Conflict`] is only ever a genuine live
//! conflict — a source-contract violation, never a subsumed-away overlap). And once a
//! subscription is live, every runtime condition — a vanished root, kernel-side loss, a
//! lagging consumer — arrives in-band as an [`Event`](crate::Event) (a `Removed`, a
//! `Rescan`), never as an error here.

use core::error::Error;

#[cfg(all(test, not(feature = "fs")))]
mod tests;

/// A classified failure reported by a [`Source`](crate::Source): the umbrella-neutral
/// [`FaultKind`] plus, when the source has one, the concrete source error boxed behind
/// the standard error chain (`Send + Sync` payloads only, so errors cross threads).
///
/// A source constructs these at its binding — classify honestly into a [`FaultKind`]
/// and preserve the full concrete error via [`with_source`](Self::with_source) — and
/// the umbrella carries them opaquely inside [`WatchError`] / [`BuildError`]. A caller
/// dispatches on [`kind`](Self::kind) generically, or recovers the concrete error with
/// [`downcast_ref`](Self::downcast_ref) when it knows the source.
///
/// `Display` is the kind; the boxed error is exposed through
/// [`Error::source`](core::error::Error::source), so the standard error-chain walk
/// reaches the concrete failure.
///
/// # Examples
///
/// ```
/// use tributaries::{FaultKind, SourceFault};
///
/// let fault = SourceFault::new(FaultKind::NotFound)
///   .with_source(std::io::Error::from(std::io::ErrorKind::NotFound));
/// assert!(fault.kind().is_not_found());
/// assert!(fault.downcast_ref::<std::io::Error>().is_some());
/// ```
#[derive(Debug, thiserror::Error)]
#[error("{kind}")]
pub struct SourceFault {
  kind: FaultKind,
  #[source]
  source: Option<Box<dyn Error + Send + Sync>>,
}

impl SourceFault {
  /// A fault classified as `kind`, with no concrete source error attached.
  #[inline]
  pub const fn new(kind: FaultKind) -> Self {
    Self { kind, source: None }
  }

  /// Attaches the concrete source error, preserved whole behind the box so
  /// [`get_ref`](Self::get_ref) / [`downcast_ref`](Self::downcast_ref) recover it with
  /// full fidelity.
  #[inline]
  #[must_use]
  pub fn with_source(mut self, source: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
    self.source = Some(source.into());
    self
  }

  /// The umbrella-neutral classification of this fault.
  #[inline]
  pub const fn kind(&self) -> FaultKind {
    self.kind
  }

  /// The boxed concrete source error, if one was attached.
  #[inline]
  pub fn get_ref(&self) -> Option<&(dyn Error + Send + Sync + 'static)> {
    self.source.as_deref()
  }

  /// The concrete source error downcast to `E`, when one is attached and is an `E`.
  #[inline]
  pub fn downcast_ref<E>(&self) -> Option<&E>
  where
    E: Error + 'static,
  {
    self.get_ref()?.downcast_ref()
  }
}

/// The umbrella-neutral classification of a [`SourceFault`] — owned by this crate on
/// the same principle as [`EventKind`](crate::EventKind): sources map their failures
/// honestly into it at their bindings, degrading only ever toward
/// [`Other`](Self::Other) (the boxed concrete error keeps the detail).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FaultKind {
  /// The keyed object does not exist at the source.
  NotFound,
  /// The keyed object exists but cannot anchor a watch (for the fs source, the path is
  /// not a directory).
  NotADirectory,
  /// The source was not permitted to inspect or watch the keyed object.
  PermissionDenied,
  /// A source resource budget is exhausted (for the fs source, the per-user
  /// watch-instance limit).
  Capacity,
  /// The source rejected the watch as conflicting with one it already holds. Never an
  /// overlap between this watcher's own subscriptions — those are subsumed away before
  /// any arm — so a genuine conflict indicates a source-contract violation or a watch
  /// held outside this watcher.
  Conflict,
  /// The source cannot watch at all on this platform or configuration.
  Unsupported,
  /// A failure outside the classified kinds; the boxed concrete error carries the
  /// detail.
  Other,
}

impl FaultKind {
  /// The stable snake_case name of this kind.
  #[inline]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::NotFound => "not_found",
      Self::NotADirectory => "not_a_directory",
      Self::PermissionDenied => "permission_denied",
      Self::Capacity => "capacity",
      Self::Conflict => "conflict",
      Self::Unsupported => "unsupported",
      Self::Other => "other",
    }
  }

  /// Whether this is [`NotFound`](Self::NotFound).
  #[inline]
  pub const fn is_not_found(&self) -> bool {
    matches!(self, Self::NotFound)
  }

  /// Whether this is [`NotADirectory`](Self::NotADirectory).
  #[inline]
  pub const fn is_not_a_directory(&self) -> bool {
    matches!(self, Self::NotADirectory)
  }

  /// Whether this is [`PermissionDenied`](Self::PermissionDenied).
  #[inline]
  pub const fn is_permission_denied(&self) -> bool {
    matches!(self, Self::PermissionDenied)
  }

  /// Whether this is [`Capacity`](Self::Capacity).
  #[inline]
  pub const fn is_capacity(&self) -> bool {
    matches!(self, Self::Capacity)
  }

  /// Whether this is [`Conflict`](Self::Conflict).
  #[inline]
  pub const fn is_conflict(&self) -> bool {
    matches!(self, Self::Conflict)
  }

  /// Whether this is [`Unsupported`](Self::Unsupported).
  #[inline]
  pub const fn is_unsupported(&self) -> bool {
    matches!(self, Self::Unsupported)
  }

  /// Whether this is [`Other`](Self::Other).
  #[inline]
  pub const fn is_other(&self) -> bool {
    matches!(self, Self::Other)
  }
}

impl core::fmt::Display for FaultKind {
  #[inline]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

/// Why a [`Tributaries`](crate::Tributaries) watcher could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
  /// The source could not be built; the classified fault carries the source's concrete
  /// error.
  #[error("the source could not be built")]
  Source(#[source] SourceFault),
}

impl BuildError {
  /// Whether this is [`Source`](Self::Source).
  #[inline]
  pub const fn is_source(&self) -> bool {
    matches!(self, Self::Source(_))
  }

  /// The classified fault this error carries.
  #[inline]
  pub const fn fault(&self) -> Option<&SourceFault> {
    match self {
      Self::Source(fault) => Some(fault),
    }
  }

  /// The underlying `tributary-fs` build error, when this error's fault carries one —
  /// downcast sugar over [`fault`](Self::fault) + [`SourceFault::downcast_ref`] for the
  /// default fs source, riding its `fs` feature (on by default).
  #[cfg(feature = "fs")]
  #[cfg_attr(docsrs, doc(cfg(feature = "fs")))]
  #[inline]
  pub fn as_fs(&self) -> Option<&tributary_fs::BuildError> {
    self.fault()?.downcast_ref()
  }
}

/// Why a subscription could not be established.
///
/// Note the absence of an `Overlaps` variant: overlapping subscriptions are subsumed
/// onto a shared source watch (design §4), so the overlap a source rejects can never
/// reach the caller here (see [`FaultKind::Conflict`] for the never-expected genuine
/// live conflict).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WatchError {
  /// `key` — the source-rendered display form of the caller's key — could not be
  /// canonicalized into the source's canonical coordinate: it does not exist, or its
  /// metadata could not be read. Canonicalization runs at the top of every watch so the
  /// subsumption index keys off the same canonical coordinate space the source reports
  /// events in; the umbrella refuses to commit a key that would receive no events.
  #[error("watch key {key} could not be canonicalized")]
  Canonicalize {
    /// The caller's key in the source's own display rendering (the fs source renders
    /// the supplied path) — diagnostic only; the typed key is in the caller's hand at
    /// the `watch` call site.
    key: Box<str>,
    /// The classified canonicalization failure.
    #[source]
    source: SourceFault,
  },
  /// The source reported a classified fault establishing the watch — arming it failed,
  /// or (for a covered newcomer) its awaited coverage
  /// [`grow`](crate::Source::grow) hit a fault such as the covering root dying
  /// concurrently. Never an overlap caused by subsumed roots (see the enum docs).
  #[error("the source could not establish the watch")]
  Source(#[source] SourceFault),
  /// The source reported the arm as succeeded, but the armed root was **already
  /// gone** — a *dead-on-arrival* handle: the root was removed between the arm
  /// request and its completion, so the source has already forgotten it
  /// ([`Source::root_key`](crate::Source::root_key) answers `None`). The umbrella
  /// refuses to commit a root no live source watch backs — it would publish the
  /// key as watched yet stream no change under it — so it fails the watch at the
  /// arm choke point (design §4, invariant I2); retry it. Distinct from
  /// [`Source`](Self::Source) (the arm itself failed) and
  /// [`CanonicalRace`](Self::CanonicalRace) (the arm succeeded, but at a divergent
  /// coordinate).
  #[error("the watched root was removed before its watch could be armed; retry the watch")]
  DeadOnArrival,
  /// The source's committed canonical key diverged from the planned one in a way that
  /// changes subsumption (design §4, invariant I2): the just-armed root was released and
  /// the reconcile aborted cleanly rather than commit a mis-keyed or overlapping entry.
  /// A retryable race, like [`DeadOnArrival`](Self::DeadOnArrival) — retry the watch.
  #[error("the source's committed canonical key diverged from the planned one; retry the watch")]
  CanonicalRace,
  /// The owner is holding the maximum RETIRED parked-`Rescan` debt — terminal
  /// [`Rescan`](crate::EventKind::Rescan)s owed to subscriptions whose roots died,
  /// parked because the event channel was full, and retained past the subscriptions'
  /// retirement so the deaths are never silently lost. New watch admission
  /// is refused at that cap: each retire-and-rewatch cycle mints another retired entry,
  /// so gating the ONE step the cycle needs — a fresh watch — is what keeps the debt
  /// (each entry retains a key and a cloned value) structurally bounded. Drain
  /// [`next`](crate::Tributaries::next) — delivering the owed terminal `Rescan`s — and
  /// retry; `close` is never gated (it rides its own channel).
  #[error("retired parked-Rescan debt is at its cap; drain the event stream, then retry the watch")]
  RescanBacklog,
  /// The watcher is closed: the owner is gone (closed, torn down, or every handle
  /// dropped), so no watch can be established.
  #[error("the watcher is closed")]
  Closed,
  /// The key is covered by an existing root whose coverage was narrowed below it, and
  /// the awaited [`Source::grow`](crate::Source::grow) could not restore coverage for
  /// the key's subtree (for the fs source, the grow's effect-completion fence settled
  /// degraded). The umbrella refuses to commit a subscription whose subtree has no
  /// live backing and no retry owner (ratified R1, grow-before-commit), so the watch
  /// fails instead — **record-exact**: the coverage record was NOT broadened, so a
  /// later watch under the pruned region classifies outside-cover again and re-issues
  /// the grow (self-healing). Nothing is silently lost meanwhile: the source has
  /// already emitted an in-band dominating [`Rescan`](crate::EventKind::Rescan) to the
  /// root's current subscribers wherever one is owed. Retryable — retry the watch.
  #[error(
    "the source could not restore coverage for the watch; the covering Rescan dominates the gap; \
     retry the watch"
  )]
  CoverageIncomplete,
  /// This watch asked for a [`Filter`](crate::Filter) of its own, and the watcher's filter
  /// plane is **retired**: it will never enter a caller predicate again, so the subscription
  /// could only be created unfiltered.
  ///
  /// A predicate this watcher ran unwound, and the payload that panic carried could not be
  /// disposed of either — its own destructor panicked, so the only containment left was to
  /// leak it. Leaking is bounded to exactly one such payload per watcher precisely because the
  /// plane latches here; a watcher that kept accepting filters would leak another every time a
  /// caller re-created the subscription.
  ///
  /// **NOT retryable on this watcher**, and no coverage was lost to it: every live
  /// subscription stays live and covered, each is owed a dominating
  /// [`Rescan`](crate::EventKind::Rescan) reporting that its admission gate is gone, and
  /// [`Filter::all`](crate::Filter::all) watches — which filter nothing and so can lose
  /// nothing — are still admitted. A caller that needs filtering again builds a new watcher.
  #[error("the watcher's filter plane is retired; this watch could only be created unfiltered")]
  FilterRetired,
}

impl WatchError {
  /// The [`Canonicalize`](Self::Canonicalize) constructor a [`Source`](crate::Source)
  /// uses: the source renders its own coordinate's display form (the fs source renders
  /// the supplied path) and classifies the failure.
  #[inline]
  pub fn canonicalize(key: impl Into<Box<str>>, fault: SourceFault) -> Self {
    Self::Canonicalize {
      key: key.into(),
      source: fault,
    }
  }

  /// The [`Source`](Self::Source) constructor a [`Source`](crate::Source) uses to
  /// report a classified arm failure.
  #[inline]
  pub const fn source(fault: SourceFault) -> Self {
    Self::Source(fault)
  }

  /// Whether this is [`Canonicalize`](Self::Canonicalize).
  #[inline]
  pub const fn is_canonicalize(&self) -> bool {
    matches!(self, Self::Canonicalize { .. })
  }

  /// Whether this is [`Source`](Self::Source).
  #[inline]
  pub const fn is_source(&self) -> bool {
    matches!(self, Self::Source(_))
  }

  /// Whether this is [`DeadOnArrival`](Self::DeadOnArrival).
  #[inline]
  pub const fn is_dead_on_arrival(&self) -> bool {
    matches!(self, Self::DeadOnArrival)
  }

  /// Whether this is [`CanonicalRace`](Self::CanonicalRace).
  #[inline]
  pub const fn is_canonical_race(&self) -> bool {
    matches!(self, Self::CanonicalRace)
  }

  /// Whether this is [`RescanBacklog`](Self::RescanBacklog).
  #[inline]
  pub const fn is_rescan_backlog(&self) -> bool {
    matches!(self, Self::RescanBacklog)
  }

  /// Whether this is [`Closed`](Self::Closed).
  #[inline]
  pub const fn is_closed(&self) -> bool {
    matches!(self, Self::Closed)
  }

  /// Whether this is [`CoverageIncomplete`](Self::CoverageIncomplete) — the retryable,
  /// record-exact refusal to commit a covered newcomer whose awaited coverage grow
  /// could not be applied (no broaden happened; retry the watch).
  #[inline]
  pub const fn is_coverage_incomplete(&self) -> bool {
    matches!(self, Self::CoverageIncomplete)
  }

  /// Whether this is [`FilterRetired`](Self::FilterRetired) — the watcher will never enter a
  /// caller predicate again, so a watch asking for one is refused rather than silently
  /// created unfiltered.
  #[inline]
  pub const fn is_filter_retired(&self) -> bool {
    matches!(self, Self::FilterRetired)
  }

  /// The classified fault this error carries, for the two fault-carrying variants
  /// ([`Canonicalize`](Self::Canonicalize) and [`Source`](Self::Source)).
  #[inline]
  pub const fn fault(&self) -> Option<&SourceFault> {
    match self {
      Self::Canonicalize { source, .. } | Self::Source(source) => Some(source),
      Self::DeadOnArrival
      | Self::CanonicalRace
      | Self::RescanBacklog
      | Self::Closed
      | Self::CoverageIncomplete
      | Self::FilterRetired => None,
    }
  }

  /// The underlying [`tributary_fs::WatchRootError`], when this error's fault carries
  /// one — downcast sugar over [`fault`](Self::fault) + [`SourceFault::downcast_ref`]
  /// for the default fs source, riding its `fs` feature (on by default).
  #[cfg(feature = "fs")]
  #[cfg_attr(docsrs, doc(cfg(feature = "fs")))]
  #[inline]
  pub fn as_fs(&self) -> Option<&tributary_fs::WatchRootError> {
    self.fault()?.downcast_ref()
  }
}

/// Why a subscription could not be dropped.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UnwatchError {
  /// The handle does not name a live subscription of this watcher: never registered,
  /// already dropped, or minted by a **different** watcher instance (its per-owner
  /// brand does not match, so it can never name a subscription here — even if its
  /// [`ScopeId`](crate::Subscription::id) collides with a live local one).
  #[error("the subscription is not live")]
  UnknownSubscription,
  /// The watcher is closed: the owner is gone (closed, torn down, or every handle
  /// dropped), so there is nothing left to drop from.
  #[error("the watcher is closed")]
  Closed,
}

impl UnwatchError {
  /// Whether this is [`UnknownSubscription`](Self::UnknownSubscription).
  #[inline]
  pub const fn is_unknown_subscription(&self) -> bool {
    matches!(self, Self::UnknownSubscription)
  }

  /// Whether this is [`Closed`](Self::Closed).
  #[inline]
  pub const fn is_closed(&self) -> bool {
    matches!(self, Self::Closed)
  }
}

/// Why [`sync`](crate::Tributaries::sync) could not establish the barrier.
///
/// The barrier is kernel-mediated: a cookie file is written under the
/// subscription's coverage, and its own event — riding the root's ordered
/// queue behind every change the backend reported before it — is what proves
/// those changes have exited the pipeline. Every variant here is a failure to
/// establish that proof, never a silent half-barrier.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SyncError {
  /// The handle does not name a live subscription of this watcher.
  #[error("the subscription is not live")]
  UnknownSubscription,
  /// The source does not implement the barrier capability. A source with no
  /// writable in-band marker cannot offer a kernel-mediated barrier, and this
  /// says so rather than pretending an owner-side drain is one.
  #[error("this source does not support a sync barrier")]
  Unsupported,
  /// The cookie could not be written. A read-only tree surfaces as
  /// [`FaultKind::PermissionDenied`] — honest: a tree with no writable covered
  /// location cannot support a kernel-mediated barrier at all.
  #[error("could not write the sync cookie: {0}")]
  CookieWrite(#[source] SourceFault),
  /// The resolved cookie directory lies outside the subscription's root, or
  /// outside the coverage its root actually retains — a cookie written there
  /// could never be reported on this subscription's stream.
  #[error("the sync cookie directory is not inside the subscription's coverage")]
  CookieDirUncovered,
  /// The subscription was unwatched by its caller while the sync was pending.
  /// A caller-unwatch owes no `Rescan`, so the barrier cannot be met honestly
  /// (a ROOT DEATH is different: its terminal `Rescan` dominates, and the sync
  /// resolves [`Dominated`](crate::SyncOutcome::Dominated)).
  #[error("the subscription was unwatched while the sync was pending")]
  Retired,
  /// The deadline elapsed before the cookie was observed.
  #[error("the sync barrier timed out")]
  Timeout,
  /// The barrier could not start because the watcher is momentarily busy in one
  /// of three ways, all transient and RETRYABLE:
  ///
  /// - another barrier is already in flight for the subscription's root (at most
  ///   one physical cookie write per root may be outstanding, so a hung backend
  ///   cannot accumulate blocking writes);
  /// - the root's cookie cleanup is backlogged (a failing unlink the driver is
  ///   retrying has filled the per-root cookie budget);
  /// - the watcher already holds the maximum number of in-flight barriers. A
  ///   barrier is retained by the owner — and its cookie FILE by the filesystem —
  ///   from the write until the cookie is observed, dominated, cancelled or
  ///   retired, and the caller chooses the timeout, so admissions can outrun
  ///   observations indefinitely. The bounded sync mailbox limits only requests
  ///   waiting to be received, so the in-flight population is bounded here
  ///   instead. Refused BEFORE any cookie is written, so a refusal leaves no
  ///   marker behind.
  ///
  /// Retry once the outstanding work resolves.
  #[error(
    "the watcher is busy (a barrier is in flight, cookie cleanup is backlogged, or too \
           many barriers are outstanding)"
  )]
  Busy,
  /// The watcher is closed.
  #[error("the watcher is closed")]
  Closed,
}

impl SyncError {
  /// Whether this is [`UnknownSubscription`](Self::UnknownSubscription).
  #[inline]
  pub const fn is_unknown_subscription(&self) -> bool {
    matches!(self, Self::UnknownSubscription)
  }

  /// Whether this is [`Unsupported`](Self::Unsupported).
  #[inline]
  pub const fn is_unsupported(&self) -> bool {
    matches!(self, Self::Unsupported)
  }

  /// Whether this is [`CookieWrite`](Self::CookieWrite).
  #[inline]
  pub const fn is_cookie_write(&self) -> bool {
    matches!(self, Self::CookieWrite(_))
  }

  /// Whether this is [`CookieDirUncovered`](Self::CookieDirUncovered).
  #[inline]
  pub const fn is_cookie_dir_uncovered(&self) -> bool {
    matches!(self, Self::CookieDirUncovered)
  }

  /// Whether this is [`Retired`](Self::Retired).
  #[inline]
  pub const fn is_retired(&self) -> bool {
    matches!(self, Self::Retired)
  }

  /// Whether this is [`Timeout`](Self::Timeout).
  #[inline]
  pub const fn is_timeout(&self) -> bool {
    matches!(self, Self::Timeout)
  }

  /// Whether this is [`Busy`](Self::Busy) — the retryable "another barrier is in flight" refusal.
  #[inline]
  pub const fn is_busy(&self) -> bool {
    matches!(self, Self::Busy)
  }

  /// Whether this is [`Closed`](Self::Closed).
  #[inline]
  pub const fn is_closed(&self) -> bool {
    matches!(self, Self::Closed)
  }
}

/// Why an orderly [`close`](crate::Tributaries::close) could not be confirmed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CloseError {
  /// The owner had already stopped before confirming the shutdown: a dropped last
  /// handle, a source that closed itself, or another racing `close` already won and
  /// tore the owner down.
  #[error("the watcher stopped before confirming the shutdown")]
  Stopped,
  /// The owner shut down cleanly, but the SOURCE could not prove its own
  /// quiescence. The watcher's own state is gone either way; what this reports is
  /// that native resources the source owns — reader threads, OS handles, marker
  /// files — may still be live, so a program that terminates its runtime on this
  /// result abandons rather than completes that teardown.
  #[error("the watcher closed but its source did not reach quiescence: {0}")]
  Source(#[source] SourceCloseError),
}

impl CloseError {
  /// Whether this is [`Stopped`](Self::Stopped).
  #[inline]
  pub const fn is_stopped(&self) -> bool {
    matches!(self, Self::Stopped)
  }

  /// Whether this is [`Source`](Self::Source).
  #[inline]
  pub const fn is_source(&self) -> bool {
    matches!(self, Self::Source(_))
  }
}

/// Why a [`Source`](crate::Source) could not prove quiescence at close — the
/// result [`LocalSource::join_close`](crate::LocalSource::join_close) reports and
/// [`Tributaries::close`](crate::Tributaries::close) forwards.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SourceCloseError {
  /// The source's own machinery stopped before it could confirm the shutdown, so
  /// nothing was proven about what it still held.
  #[error("the source stopped before confirming its shutdown")]
  Stopped,
  /// The source's close bound expired with work still outstanding — native
  /// streams still winding down, or marker files it wrote and could not confirm
  /// removed. Reported honestly rather than waited out: an unbounded wait against
  /// a wedged filesystem is what the bound exists to refuse.
  #[error("{pending} source obligation(s) still outstanding at close")]
  NotQuiesced {
    /// How many obligations the source still owed.
    pending: usize,
  },
}

impl SourceCloseError {
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
