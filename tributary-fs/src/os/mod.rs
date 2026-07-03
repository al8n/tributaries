//! The platform seam between the async driver and the OS watch primitive.
//!
//! Every platform module exposes the same surface: [`Source::spawn`] starts the
//! native watch and hands back a [`SourceHandle`] plus the ONE ordered queue
//! it reports on. `Batch`, `Overflow`, and `Fatal` all ride that single
//! unbounded FIFO, so per-source ordering between data and the loss/death
//! signals covering it holds by construction, and a signal send can never
//! fail for capacity — a loss can never be recorded without a message left to
//! observe it, and no signal can overtake the batches it postdates. Memory is
//! bounded not by the queue but by the batch budget
//! ([`fsevent::TransportState`]): an over-budget batch is dropped at the
//! callback and degrades to the same in-order `Overflow`.
//!
//! Of the queue the seam assumes exactly three properties — FIFO delivery,
//! unbounded capacity, and a `Closed` signal once the receiver is gone — all
//! of which `async_channel::unbounded` provides.

use std::{io, num::NonZeroUsize, path::PathBuf, time::Duration};

pub(crate) mod fsevent;

#[cfg(all(target_os = "macos", not(miri)))]
mod macos;
#[cfg(all(target_os = "macos", not(miri)))]
pub(crate) use macos::{Source, SourceHandle, mounts_under};

#[cfg(any(not(target_os = "macos"), miri))]
mod unsupported;
#[cfg(any(not(target_os = "macos"), miri))]
pub(crate) use unsupported::{Source, SourceHandle, mounts_under};

pub(crate) use fsevent::{BatchPayload, FsEventFlags, OverflowAck, RawOsEvent};

/// The most exclusion directories one native stream honors
/// (`FSEventStreamSetExclusionPaths` accepts at most eight).
pub(crate) const MAX_EXCLUSIONS: usize = 8;

/// Everything a platform source needs to start watching.
#[derive(Debug, Clone)]
pub(crate) struct SourceConfig {
  /// The watched roots. One stream may carry several, but the driver spawns
  /// one source per root so root add/remove is a pure spawn/teardown.
  pub(crate) roots: Vec<PathBuf>,
  /// Load-shedding exclusion directories (at most [`MAX_EXCLUSIONS`]);
  /// correctness never depends on them.
  pub(crate) exclusions: Vec<PathBuf>,
  /// Resume point from a previous stream generation; `None` = live-only.
  pub(crate) since: Option<ResumeToken>,
  /// The OS event-coalescing latency.
  pub(crate) latency: Duration,
  /// Capacity of the callback→driver channel, in callback batches.
  pub(crate) channel_capacity: NonZeroUsize,
}

impl SourceConfig {
  /// A live-only configuration watching `roots` with the crate defaults.
  pub(crate) fn new(roots: Vec<PathBuf>) -> Self {
    Self {
      roots,
      exclusions: Vec::new(),
      since: None,
      latency: Duration::from_millis(10),
      channel_capacity: NonZeroUsize::new(64).expect("64 is nonzero"),
    }
  }
}

/// One message from the OS callback to the driver task, on the source's
/// single ordered queue.
#[derive(Debug)]
pub(crate) enum SourceMessage {
  /// One callback invocation's decoded events, holding their budget slot.
  Batch(BatchPayload),
  /// Transport-level loss AT THIS QUEUE POSITION: a batch was dropped over
  /// budget, or an event could not be decoded. The receiver treats the
  /// source's subtrees as needing a rescan; dropping the carried
  /// [`OverflowAck`] (before acting) re-arms the dedup for the next loss.
  Overflow(OverflowAck),
  /// The stream is dead and will deliver nothing more (sent at most once).
  /// The driver reacts to the death itself (root invalidation); the carried
  /// class is diagnostic surface for a future health-reporting channel.
  Fatal(#[allow(dead_code)] SourceError),
}

/// Why a platform source could not start, or died.
///
/// Surfaced publicly through
/// [`WatchRootError::Source`](crate::WatchRootError::Source): everything after
/// a root is live arrives as in-band events, so this is the only backend error
/// shape a consumer ever sees.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SourceError {
  /// This platform has no watch backend (or the build cannot run FFI).
  #[error("filesystem watching is not supported on this platform")]
  Unsupported,
  /// No watch root was supplied.
  #[error("a source needs at least one watch root")]
  NoRoots,
  /// A watch root does not exist or could not be resolved.
  #[error("watch root {} is unavailable", root.display())]
  RootUnavailable {
    /// The root as the caller supplied it.
    root: PathBuf,
    /// The underlying resolution failure.
    #[source]
    source: io::Error,
  },
  /// More exclusion paths than the OS honors were supplied.
  #[error("{supplied} exclusion paths exceed the OS limit of {MAX_EXCLUSIONS}")]
  TooManyExclusions {
    /// How many exclusions the configuration carried.
    supplied: usize,
  },
  /// The OS rejected the exclusion path set.
  #[error("the OS rejected the exclusion paths")]
  ExclusionRejected,
  /// The OS could not create the event stream.
  #[error("the OS could not create the event stream")]
  CreateFailed,
  /// The OS could not start the event stream.
  #[error("the OS could not start the event stream")]
  StartFailed,
  /// The decode callback panicked; the stream is poisoned.
  #[error("the event callback panicked")]
  CallbackPanic,
}

/// Where a dead stream's successor can resume from: the last in-sync journal
/// event id plus the device UUID that scopes its validity. Consuming this is
/// a later refinement; sources only mint it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResumeToken {
  last_good: u64,
  device_uuid: Option<[u8; 16]>,
}

// Journal resume is deferred surface: sources mint tokens from day one so the
// capability can land without a redesign, but nothing consumes them yet.
#[allow(dead_code)]
impl ResumeToken {
  /// Builds a token from a last-good event id and its device UUID.
  pub(crate) const fn new(last_good: u64, device_uuid: Option<[u8; 16]>) -> Self {
    Self {
      last_good,
      device_uuid,
    }
  }

  /// The highest journal event id observed while the stream was in sync.
  pub(crate) const fn last_good(&self) -> u64 {
    self.last_good
  }

  /// The UUID of the device the id belongs to, if the OS could supply one.
  /// A token is only valid for resuming against the identical UUID.
  pub(crate) const fn device_uuid(&self) -> Option<[u8; 16]> {
    self.device_uuid
  }
}

/// The driver's receiving end of a source's messages.
pub(crate) type EventReceiver = async_channel::Receiver<SourceMessage>;
