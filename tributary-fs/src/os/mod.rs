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
//! (`transport::TransportState`, compiled only where a backend drives it): an
//! over-budget batch is dropped at the callback and degrades to the same
//! in-order `Overflow`.
//!
//! Of the queue the seam assumes exactly three properties — FIFO delivery,
//! unbounded capacity, and a `Closed` signal once the receiver is gone — all
//! of which `async_channel::unbounded` provides.

use std::{io, num::NonZeroUsize, path::PathBuf, time::Duration};

pub(crate) mod fsevent;
pub(crate) mod linux;
pub(crate) mod transport;

#[cfg(all(target_os = "macos", not(miri)))]
mod macos;
#[cfg(all(target_os = "macos", not(miri)))]
pub(crate) use macos::{Source, SourceHandle, mounts_under};

#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) use linux::{Source, SourceHandle, mounts_under};

#[cfg(any(not(any(target_os = "macos", target_os = "linux")), miri))]
mod unsupported;
#[cfg(any(not(any(target_os = "macos", target_os = "linux")), miri))]
pub(crate) use unsupported::{Source, SourceHandle, mounts_under};

pub(crate) use fsevent::{FsEventFlags, RawOsEvent};

/// Which watch primitive a spawned source is backed by — the capability
/// report [`Watcher::backend_of`](crate::Watcher::backend_of) surfaces for a
/// live root. The core confirms the per-scope lowering profile the
/// registration intended against it, and the `Backend::Auto` probe records the
/// selection it settled on here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
  /// macOS FSEvents — kernel-recursive; flag words are hints.
  FsEvents,
  /// Linux inotify — per-directory (descending); precise verbs, unprivileged.
  Inotify,
  /// Linux fanotify-FILESYSTEM — kernel-recursive; precise verbs, interned-FID
  /// identity. Privileged (`CAP_SYS_ADMIN`); selected by `Backend::Auto` when
  /// its preconditions hold, or forced by [`Backend::Fanotify`].
  Fanotify,
}

impl BackendKind {
  /// The stable lowercase tag of this backend, for logs and diagnostics.
  #[must_use]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::FsEvents => "fsevents",
      Self::Inotify => "inotify",
      Self::Fanotify => "fanotify",
    }
  }

  /// Whether this backend is kernel-recursive (one mark covers the whole root),
  /// as opposed to the descending, per-directory inotify profile.
  #[must_use]
  pub const fn is_kernel_recursive(&self) -> bool {
    matches!(self, Self::FsEvents | Self::Fanotify)
  }
}

impl core::fmt::Display for BackendKind {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

/// The Linux watch primitive a [`Watcher`](crate::Watcher) should use for each
/// root, chosen through [`WatcherOptions::backend`](crate::WatcherOptions::backend).
///
/// [`Auto`](Self::Auto) is the default: the spawn barrier probes for
/// fanotify-FILESYSTEM (privileged, kernel-recursive) and falls back to inotify
/// (universal, unprivileged) at the first failing probe — a per-root decision
/// made once, before the stream goes live, never retried. The two explicit
/// variants pin the choice: [`Inotify`](Self::Inotify) skips the probe;
/// [`Fanotify`](Self::Fanotify) runs it and surfaces the first failure as a
/// typed spawn error rather than falling back.
///
/// macOS ignores this — FSEvents is its one backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Backend {
  /// Probe for fanotify, fall back to inotify — the per-root default.
  #[default]
  Auto,
  /// inotify — per-directory, unprivileged; the probe is skipped.
  Inotify,
  /// fanotify-FILESYSTEM — kernel-recursive, privileged; a failing precondition
  /// is a typed spawn error, not a fallback.
  Fanotify,
}

impl Backend {
  /// The stable lowercase tag of this backend selection.
  #[must_use]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Auto => "auto",
      Self::Inotify => "inotify",
      Self::Fanotify => "fanotify",
    }
  }

  /// Whether the selection is [`Auto`](Self::Auto) (the barrier decides).
  #[must_use]
  pub const fn is_auto(&self) -> bool {
    matches!(self, Self::Auto)
  }

  /// Whether the selection forces inotify.
  #[must_use]
  pub const fn is_inotify(&self) -> bool {
    matches!(self, Self::Inotify)
  }

  /// Whether the selection forces fanotify.
  #[must_use]
  pub const fn is_fanotify(&self) -> bool {
    matches!(self, Self::Fanotify)
  }
}

impl core::fmt::Display for Backend {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

/// The clonable arm/disarm port of one scope's live source, extracted at
/// spawn time so the blocking-pool executors can reach the reader without
/// holding the (teardown-owning) handle. Kernel-recursive backends have no
/// arm traffic and report [`Inert`](Self::Inert); a descending executor
/// meeting `Inert` answers a typed failure — the honest impossible-arm
/// outcome — never a silent success.
#[derive(Debug, Clone)]
pub(crate) enum ScopePort {
  /// A live inotify reader's control port.
  #[cfg(all(target_os = "linux", not(miri)))]
  Inotify(linux::ControlPort),
  /// No arm traffic is possible (kernel-recursive source, or a fake).
  Inert,
}

/// The ONE seam payload every source reports: each backend wraps its own
/// decode into this at forward time, so the queue, the driver, and the core
/// name a single event type on every platform — and the hermetic suites can
/// inject either backend's events on any host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceEvent {
  /// One decoded FSEvents record.
  FsEvents(RawOsEvent),
  /// One decoded, anchor-attributed Linux record.
  Linux(linux::RawLinuxEvent),
}

impl From<RawOsEvent> for SourceEvent {
  fn from(value: RawOsEvent) -> Self {
    Self::FsEvents(value)
  }
}

impl From<linux::RawLinuxEvent> for SourceEvent {
  fn from(value: linux::RawLinuxEvent) -> Self {
    Self::Linux(value)
  }
}

/// One producer batch of [`SourceEvent`]s plus its budget slot.
pub(crate) type BatchPayload = transport::BatchPayload<SourceEvent>;

/// One message from the OS producer to the driver task, on the source's
/// single ordered queue.
pub(crate) type SourceMessage = transport::SourceMessage<SourceEvent>;

/// The driver's receiving end of a source's messages.
pub(crate) type EventReceiver = transport::EventReceiver<SourceEvent>;

/// The most exclusion directories one native stream honors
/// (`FSEventStreamSetExclusionPaths` accepts at most eight).
pub(crate) const MAX_EXCLUSIONS: usize = 8;

/// A filesystem object's identity: its `(device, inode)` pair.
///
/// Two paths name the same object iff their identities are equal — a
/// comparison no byte form can stand in for on volumes where several
/// spellings (case aliases, Unicode-normalization aliases) reach one object.
/// On a case-SENSITIVE volume two spellings are genuinely different objects
/// with different inodes, so identity comparison is volume-correct by
/// construction, with no case-fold tables and no volume-capability lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RootIdentity {
  dev: u64,
  ino: u64,
}

impl RootIdentity {
  /// Wraps a stat-read `(device, inode)` pair. Identities are read off Unix
  /// metadata or minted by test harnesses; on a platform with neither the
  /// wrapped pair is the harmless `(0, 0)` its callers already synthesize
  /// (`dev_of`/`ino_of`/`identity_of`), and no real stream ever mints one.
  pub(crate) const fn new(dev: u64, ino: u64) -> Self {
    Self { dev, ino }
  }
}

/// What a source's spawn learned about its root — finalized strictly BEFORE
/// the stream can enqueue its first event, so nothing here can postdate a
/// message the source delivers, and no fallible metadata path exists after
/// start. Only [`Source::spawn`] mints a `RootMeta`.
///
/// The mount seed is deliberately NOT an authority: a mount appearing between
/// the seed read and stream start lands in neither the seed nor the event
/// stream, so a pre-start snapshot can never prove a path is root-device. The
/// seed only ever REDUCES trust (its prefixes are foreign) and steers probes;
/// authority is installed exclusively by the driver's post-live mount refresh,
/// whose read the live stream orders against every later mount transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RootMeta {
  /// The canonicalized root — the byte-exact prefix event paths arrive under.
  pub(crate) root: PathBuf,
  /// The device the root lives on.
  pub(crate) root_dev: u64,
  /// The trust-reducing mount seed: mount points observed strictly under the
  /// root before the stream started (empty when the table could not be read —
  /// either way, event-side trust stays closed until the post-live refresh).
  pub(crate) mounts: Vec<PathBuf>,
  /// The root object's identity — what root disjointness is decided on
  /// (spelling-aliased paths share it; distinct objects never do).
  pub(crate) identity: RootIdentity,
  /// The identities of every strict ancestor of the canonical root, so
  /// containment ("is this root inside that one, under ANY spelling") is
  /// answerable by pure membership tests with no further syscalls.
  pub(crate) ancestors: Vec<RootIdentity>,
  /// The primitive backing this source — the core confirms its per-scope
  /// lowering profile against it.
  pub(crate) backend: BackendKind,
}

/// Everything a platform source needs to start watching.
#[derive(Debug, Clone)]
pub(crate) struct SourceConfig {
  /// The watched roots. One stream may carry several, but the driver spawns
  /// one source per root so root add/remove is a pure spawn/teardown.
  // Only a real backend's spawn reads the roots and the resume point; the
  // stub rejects the whole config unread, so backend-less builds see the
  // fields as dead. Gating them would fracture the seam type.
  #[cfg_attr(
    not(all(any(target_os = "macos", target_os = "linux"), not(miri))),
    allow(dead_code)
  )]
  pub(crate) roots: Vec<PathBuf>,
  /// Load-shedding exclusion directories (at most [`MAX_EXCLUSIONS`]);
  /// correctness never depends on them.
  pub(crate) exclusions: Vec<PathBuf>,
  /// Resume point from a previous stream generation; `None` = live-only.
  // Only the FSEvents backend consumes resume points today (inotify has no
  // journal to resume from), so every other build sees the field as dead.
  #[cfg_attr(not(all(target_os = "macos", not(miri))), allow(dead_code))]
  pub(crate) since: Option<ResumeToken>,
  /// The OS event-coalescing latency.
  pub(crate) latency: Duration,
  /// Capacity of the callback→driver channel, in callback batches.
  pub(crate) channel_capacity: NonZeroUsize,
  /// Which Linux backend the spawn barrier selects. Ignored on macOS (FSEvents
  /// is the one backend); on Linux [`Backend::Auto`] probes for fanotify and
  /// falls back to inotify, while the explicit variants pin the choice.
  // Only the linux backend reads this; every other build sees it as dead.
  #[cfg_attr(not(all(target_os = "linux", not(miri))), allow(dead_code))]
  pub(crate) backend: Backend,
}

impl SourceConfig {
  /// A live-only configuration watching `roots` with the crate defaults
  /// ([`Backend::Auto`] on Linux — probe for fanotify, fall back to inotify).
  pub(crate) fn new(roots: Vec<PathBuf>) -> Self {
    Self {
      roots,
      exclusions: Vec::new(),
      since: None,
      latency: Duration::from_millis(10),
      channel_capacity: NonZeroUsize::new(64).expect("64 is nonzero"),
      backend: Backend::Auto,
    }
  }
}

/// Which `Backend::Auto` probe stage decided the selection (design §5, rows
/// 2–5). Carried by [`SourceError::BackendProbeFailed`] on a forced
/// [`Backend::Fanotify`] whose preconditions did not hold, so the caller learns
/// exactly which one failed. A pure enum (no FFI), so it is available on every
/// platform the error type is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProbeStage {
  /// `fanotify_init` with the full 5.17 composite flag set was refused — the
  /// kernel/filesystem is too old for the composite, or the process lacks the
  /// notification class (`EINVAL`/`EPERM`).
  Init,
  /// The `FAN_MARK_ADD | FAN_MARK_FILESYSTEM` mark was refused — the real
  /// privilege discriminator (`EPERM` = no `CAP_SYS_ADMIN`), or the filesystem
  /// does not support the superblock mark (`EINVAL`/`EOPNOTSUPP`/`ENODEV`/
  /// `EXDEV`).
  Mark,
  /// `name_to_handle_at` on the root was refused — the filesystem cannot export
  /// file handles, so FID identity is impossible (`EOPNOTSUPP`).
  Handle,
}

impl ProbeStage {
  /// A stable tag naming the failed syscall stage.
  #[must_use]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Init => "fanotify_init",
      Self::Mark => "fanotify_mark(FAN_MARK_FILESYSTEM)",
      Self::Handle => "name_to_handle_at",
    }
  }
}

impl core::fmt::Display for ProbeStage {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
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
  /// The FINAL canonical root is not a directory. The backend re-resolves the
  /// root at spawn, so a path retargeted to a regular file between the
  /// watcher's own check and the pre-start barrier is caught here — a
  /// recursive stream must never be committed for a non-directory.
  #[error("watch root {} is not a directory", root.display())]
  NotADirectory {
    /// The final canonical root the spawn resolved.
    root: PathBuf,
  },
  /// The root OBJECT changed between the pre-start metadata capture and the
  /// stream going live: the path kept its bytes but now names a different
  /// `(dev, ino)`. The just-started stream was torn down — committing it
  /// would anchor coverage and registry identity to two different objects.
  #[error("watch root {} was replaced while the stream was starting", root.display())]
  RootReplaced {
    /// The final canonical root whose object changed.
    root: PathBuf,
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
  /// The per-user watch-instance ceiling was hit (`EMFILE`: the process fd
  /// limit or `fs.inotify.max_user_instances` — one instance per root is the
  /// overflow-isolation trade).
  #[error("the per-user watch-instance limit was reached")]
  InstanceLimit,
  /// The stream's read loop failed; the stream is dead.
  #[error("reading the event stream failed")]
  ReadFailed {
    /// The underlying read failure.
    #[source]
    source: io::Error,
  },
  /// The OS could not start the event stream.
  #[error("the OS could not start the event stream")]
  StartFailed,
  /// A forced [`Backend::Fanotify`] failed a precondition probe (design §5): the
  /// named stage was refused, so the backend cannot start. `Backend::Auto`
  /// falls back to inotify instead of surfacing this.
  #[error("the fanotify backend is unavailable: {stage} was refused")]
  BackendProbeFailed {
    /// The first probe stage that failed.
    stage: ProbeStage,
  },
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
