//! The umbrella crate's error vocabulary.
//!
//! These mirror the [`tributary-fs`](tributary_fs) errors one layer down, minus
//! the one condition this crate exists to absorb: a `watch` never surfaces
//! [`WatchRootError::Overlaps`](tributary_fs::WatchRootError::Overlaps), because
//! subsuming overlapping subscriptions into disjoint roots is precisely this
//! layer's job. Once a subscription is live, every runtime condition — a vanished
//! root, kernel-side loss, a lagging consumer — arrives in-band as an
//! [`Event`](crate::Event) (a `Removed`, a `Rescan`), never as an error here.

use std::path::PathBuf;

/// Why a [`Tributaries`](crate::Tributaries) watcher could not be built.
///
/// A thin re-surfacing of [`tributary_fs::BuildError`]: construction wraps one
/// `tributary-fs` watcher and adds no build-time state of its own.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
  /// The underlying `tributary-fs` watcher could not be built.
  #[error(transparent)]
  Fs(#[from] tributary_fs::BuildError),
}

impl BuildError {
  /// The underlying `tributary-fs` build error, if any.
  #[inline]
  pub const fn as_fs(&self) -> Option<&tributary_fs::BuildError> {
    match self {
      Self::Fs(err) => Some(err),
    }
  }
}

/// Why a subscription could not be established.
///
/// Note the absence of an `Overlaps` variant: overlapping subscriptions are
/// subsumed onto a shared kernel watch (design §4), so the overlap that
/// [`tributary-fs`](tributary_fs) rejects can never reach the caller here.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WatchError {
  /// The path could not be canonicalized: it does not exist, or its metadata
  /// could not be read. Canonicalization runs at this layer so the subsumption
  /// index keys off the same canonical-path space `tributary-fs` reports.
  #[error("watch path {} could not be canonicalized", path.display())]
  Canonicalize {
    /// The path as the caller supplied it.
    path: PathBuf,
    /// The underlying I/O error.
    #[source]
    source: std::io::Error,
  },
  /// Arming the kernel watch failed. Carries the underlying `tributary-fs`
  /// error — never its `Overlaps` case, which is subsumed away before any arm.
  #[error(transparent)]
  Fs(#[from] tributary_fs::WatchRootError),
  /// The source reported the arm as succeeded, but the armed root was **already
  /// gone** — a *dead-on-arrival* handle: the root was removed between the arm
  /// request and its completion, so the source has already forgotten it
  /// ([`Source::root_key`](crate::Source::root_key) answers `None`). The umbrella
  /// refuses to commit a root no live source watch backs — it would publish the
  /// key as watched yet stream no change under it — so it fails the watch at the
  /// arm choke point (design §4, invariant I2); retry it. Distinct from
  /// [`Fs`](Self::Fs) (the arm itself failed) and [`Canonicalize`](Self::Canonicalize)
  /// (the arm succeeded, but at a divergent coordinate).
  #[error("the watched root was removed before its watch could be armed; retry the watch")]
  DeadOnArrival,
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
}

impl WatchError {
  /// Whether this is [`Canonicalize`](Self::Canonicalize).
  #[inline]
  pub const fn is_canonicalize(&self) -> bool {
    matches!(self, Self::Canonicalize { .. })
  }

  /// Whether this is [`DeadOnArrival`](Self::DeadOnArrival).
  #[inline]
  pub const fn is_dead_on_arrival(&self) -> bool {
    matches!(self, Self::DeadOnArrival)
  }

  /// The underlying `tributary-fs` watch error, if this is [`Fs`](Self::Fs).
  #[inline]
  pub const fn as_fs(&self) -> Option<&tributary_fs::WatchRootError> {
    match self {
      Self::Fs(err) => Some(err),
      Self::Canonicalize { .. } | Self::DeadOnArrival | Self::RescanBacklog => None,
    }
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
  /// Releasing the now-empty kernel watch failed at the `tributary-fs` layer.
  #[error(transparent)]
  Fs(#[from] tributary_fs::UnwatchError),
}

impl UnwatchError {
  /// Whether this is [`UnknownSubscription`](Self::UnknownSubscription).
  #[inline]
  pub const fn is_unknown_subscription(&self) -> bool {
    matches!(self, Self::UnknownSubscription)
  }

  /// The underlying `tributary-fs` unwatch error, if this is [`Fs`](Self::Fs).
  #[inline]
  pub const fn as_fs(&self) -> Option<&tributary_fs::UnwatchError> {
    match self {
      Self::Fs(err) => Some(err),
      Self::UnknownSubscription => None,
    }
  }
}

/// Why an orderly [`close`](crate::Tributaries::close) could not be confirmed.
///
/// A thin re-surfacing of [`tributary_fs::CloseError`]: close tears down the one
/// wrapped watcher and adds no teardown state of its own.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CloseError {
  /// The underlying `tributary-fs` watcher could not confirm its shutdown.
  #[error(transparent)]
  Fs(#[from] tributary_fs::CloseError),
}

impl CloseError {
  /// The underlying `tributary-fs` close error, if any.
  #[inline]
  pub const fn as_fs(&self) -> Option<&tributary_fs::CloseError> {
    match self {
      Self::Fs(err) => Some(err),
    }
  }
}
