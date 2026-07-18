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
pub(crate) mod windows;

#[cfg(all(target_os = "macos", not(miri)))]
mod macos;
#[cfg(all(target_os = "macos", not(miri)))]
pub(crate) use macos::{Source, SourceHandle, mounts_under};

#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) use linux::{Source, SourceHandle, mounts_under};

#[cfg(all(target_os = "windows", not(miri)))]
pub(crate) use windows::{Source, SourceHandle, mounts_under};

#[cfg(any(
  not(any(target_os = "macos", target_os = "linux", target_os = "windows")),
  miri
))]
mod unsupported;
#[cfg(any(
  not(any(target_os = "macos", target_os = "linux", target_os = "windows")),
  miri
))]
pub(crate) use unsupported::{Source, SourceHandle, mounts_under};

pub(crate) use fsevent::{FsEventFlags, RawOsEvent};

/// Which watch primitive a spawned source is backed by — the capability
/// report [`Watcher::backend_of`](crate::Watcher::backend_of) surfaces for a
/// live root. The core confirms the per-scope lowering profile the
/// registration intended against it, and the `Backend::Auto` probe records the
/// selection it settled on here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackendKind {
  /// macOS FSEvents — kernel-recursive; flag words are hints.
  FsEvents,
  /// Linux inotify — per-directory (descending); precise verbs, unprivileged.
  Inotify,
  /// Linux fanotify-FILESYSTEM — kernel-recursive; precise verbs, membership-only
  /// admission (no node identity — design §4.9). Privileged (`CAP_SYS_ADMIN`);
  /// selected by `Backend::Auto` when its preconditions hold, or forced by
  /// [`Backend::Fanotify`].
  Fanotify,
  /// Windows `ReadDirectoryChangesW` — kernel-recursive, unprivileged; the
  /// per-volume fallback when the USN journal is unusable, or forced by
  /// [`Backend::Rdcw`].
  Rdcw,
  /// Windows USN change journal — kernel-recursive, journal-cursor sourced;
  /// volume-handle access effectively requires elevation. Selected by
  /// `Backend::Auto` when its per-volume preconditions hold, or forced by
  /// [`Backend::UsnJournal`].
  UsnJournal,
}

impl BackendKind {
  /// The stable lowercase tag of this backend, for logs and diagnostics.
  #[must_use]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::FsEvents => "fsevents",
      Self::Inotify => "inotify",
      Self::Fanotify => "fanotify",
      Self::Rdcw => "rdcw",
      Self::UsnJournal => "usn-journal",
    }
  }

  /// Whether this backend is kernel-recursive (one mark covers the whole root),
  /// as opposed to the descending, per-directory inotify profile.
  #[must_use]
  pub const fn is_kernel_recursive(&self) -> bool {
    matches!(
      self,
      Self::FsEvents | Self::Fanotify | Self::Rdcw | Self::UsnJournal
    )
  }
}

impl core::fmt::Display for BackendKind {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

/// A lightweight, pollable snapshot of one backend's live internals — the
/// observability the operator owes a tripwire on (design §4.9). Surfaced per
/// watched root by
/// [`Watcher::backend_stats`](crate::Watcher::backend_stats); only the fanotify
/// backend populates it (every other backend has no equivalent state), so a
/// non-fanotify root reports `None` rather than a zeroed struct.
///
/// A snapshot, not a live handle: each accessor returns the value at the moment
/// the query read the backend's counters. `#[non_exhaustive]` so more counters
/// can land without a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct BackendStats {
  directories: usize,
  memo_generation: u64,
  seed_walk_last_micros: u64,
  seed_walk_count: u64,
  reseeds: u64,
  memo_hits: u64,
  memo_misses: u64,
}

impl BackendStats {
  /// The number of directories currently in the fanotify admission map — its
  /// live O(directories) footprint (design §4.9: ~250 B/dir, so ~2.5–4 GB at
  /// 10 M directories).
  #[must_use]
  pub const fn directories(&self) -> usize {
    self.directories
  }

  /// The admission map's mutation generation — the batch memo's invalidation
  /// token, monotone across the map's lifetime (a coarse mutation counter).
  #[must_use]
  pub const fn memo_generation(&self) -> u64 {
    self.memo_generation
  }

  /// Microseconds the LAST seed or reseed walk took (0 before the first walk) —
  /// the map-rebuild cost the operator sizes the directory cap against.
  #[must_use]
  pub const fn seed_walk_last_micros(&self) -> u64 {
    self.seed_walk_last_micros
  }

  /// How many seed/reseed walks have completed (the spawn seed plus every
  /// loss-triggered reseed and moved-in subtree walk).
  #[must_use]
  pub const fn seed_walk_count(&self) -> u64 {
    self.seed_walk_count
  }

  /// How many loss-triggered map reseeds have run — a rescan-pressure signal.
  #[must_use]
  pub const fn reseeds(&self) -> u64 {
    self.reseeds
  }

  /// Cumulative batch-memo hits: admitted directory resolutions served from the
  /// per-batch cache rather than a fresh map walk.
  #[must_use]
  pub const fn memo_hits(&self) -> u64 {
    self.memo_hits
  }

  /// Cumulative batch-memo misses: resolutions that fell through to the map
  /// (a cold directory, or a stale entry after a same-batch mutation).
  #[must_use]
  pub const fn memo_misses(&self) -> u64 {
    self.memo_misses
  }
}

/// The shared, atomic backing store the fanotify reader writes and the watcher
/// snapshots — the live counters behind [`BackendStats`]. Kept OS-agnostic
/// (pure atomics, no FFI) so the cross-platform watcher can read it, and behind
/// an `Arc` so the reader thread and the registry entry share one instance. A
/// non-fanotify backend never mints one, so its [`backend_stats`] is `None`.
///
/// [`backend_stats`]: crate::driver::SourceControl::backend_stats
#[derive(Debug, Default)]
pub(crate) struct BackendStatsShared {
  directories: core::sync::atomic::AtomicUsize,
  memo_generation: core::sync::atomic::AtomicU64,
  seed_walk_last_micros: core::sync::atomic::AtomicU64,
  seed_walk_count: core::sync::atomic::AtomicU64,
  reseeds: core::sync::atomic::AtomicU64,
  memo_hits: core::sync::atomic::AtomicU64,
  memo_misses: core::sync::atomic::AtomicU64,
}

// Only the fanotify reader (cfg linux, not miri) writes these; the setters are
// dead on every other build, but gating them would fracture the shared type.
#[cfg_attr(not(all(target_os = "linux", not(miri))), allow(dead_code))]
impl BackendStatsShared {
  /// A consistent-enough snapshot for an operator poll. The counters are read
  /// `Relaxed` and independently, so a snapshot may straddle a reader update
  /// (e.g. `memo_hits` newer than `directories`); for tripwire observability
  /// that skew is immaterial, and no store here gates a correctness decision.
  pub(crate) fn snapshot(&self) -> BackendStats {
    use core::sync::atomic::Ordering::Relaxed;
    BackendStats {
      directories: self.directories.load(Relaxed),
      memo_generation: self.memo_generation.load(Relaxed),
      seed_walk_last_micros: self.seed_walk_last_micros.load(Relaxed),
      seed_walk_count: self.seed_walk_count.load(Relaxed),
      reseeds: self.reseeds.load(Relaxed),
      memo_hits: self.memo_hits.load(Relaxed),
      memo_misses: self.memo_misses.load(Relaxed),
    }
  }

  /// Publishes the map's live footprint (its directory count and generation)
  /// after a batch or a walk.
  pub(crate) fn set_map(&self, directories: usize, memo_generation: u64) {
    use core::sync::atomic::Ordering::Relaxed;
    self.directories.store(directories, Relaxed);
    self.memo_generation.store(memo_generation, Relaxed);
  }

  /// Records one completed seed/reseed walk's duration and bumps the walk count.
  pub(crate) fn record_walk(&self, micros: u64) {
    use core::sync::atomic::Ordering::Relaxed;
    self.seed_walk_last_micros.store(micros, Relaxed);
    self.seed_walk_count.fetch_add(1, Relaxed);
  }

  /// Bumps the loss-triggered reseed counter.
  pub(crate) fn record_reseed(&self) {
    self
      .reseeds
      .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
  }

  /// Adds one batch's memo hit/miss tallies to the cumulative counters.
  pub(crate) fn add_memo(&self, hits: u64, misses: u64) {
    use core::sync::atomic::Ordering::Relaxed;
    self.memo_hits.fetch_add(hits, Relaxed);
    self.memo_misses.fetch_add(misses, Relaxed);
  }
}

/// The clonable handle the driver threads from a live source into the registry
/// so [`Watcher::backend_stats`](crate::Watcher::backend_stats) can snapshot it.
/// `Some` only for a fanotify source.
pub(crate) type BackendStatsHandle = std::sync::Arc<BackendStatsShared>;

/// The watch primitive a [`Watcher`](crate::Watcher) should use for each
/// root, chosen through [`WatcherOptions::backend`](crate::WatcherOptions::backend).
///
/// [`Auto`](Self::Auto) is the default and is native on every platform: the
/// spawn barrier resolves it to the host's primitive — Linux probes for
/// fanotify-FILESYSTEM (privileged, kernel-recursive) and falls back to inotify
/// (unprivileged, the Linux 4.11 baseline) at the first failing probe; macOS
/// resolves to FSEvents; Windows prefers the USN journal per volume and falls
/// back to `ReadDirectoryChangesW` — a per-root decision made once, before the
/// stream goes live, never retried.
///
/// An explicit variant pins one platform's primitive. On the platform that owns
/// it, forcing either skips the probe (inotify, RDCW) or hardens it (fanotify,
/// USN journal — the first failing precondition is a typed spawn error, never a
/// fallback). On any other platform a forced variant fails the spawn with
/// [`ForeignBackend`](SourceError::ForeignBackend) — never a silent ignore.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Backend {
  /// Resolve the host's primitive at the spawn barrier — the per-root default.
  #[default]
  Auto,
  /// Linux inotify — per-directory, unprivileged; the probe is skipped.
  Inotify,
  /// Linux fanotify-FILESYSTEM — kernel-recursive, privileged; a failing
  /// precondition is a typed spawn error, not a fallback.
  Fanotify,
  /// Windows `ReadDirectoryChangesW` — kernel-recursive, unprivileged.
  Rdcw,
  /// Windows USN change journal — kernel-recursive; volume-handle access
  /// effectively requires elevation, and a failing precondition is a typed
  /// spawn error, not a fallback.
  UsnJournal,
}

impl Backend {
  /// The stable lowercase tag of this backend selection.
  #[must_use]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Auto => "auto",
      Self::Inotify => "inotify",
      Self::Fanotify => "fanotify",
      Self::Rdcw => "rdcw",
      Self::UsnJournal => "usn-journal",
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

  /// Whether the selection forces `ReadDirectoryChangesW`.
  #[must_use]
  pub const fn is_rdcw(&self) -> bool {
    matches!(self, Self::Rdcw)
  }

  /// Whether the selection forces the USN change journal.
  #[must_use]
  pub const fn is_usn_journal(&self) -> bool {
    matches!(self, Self::UsnJournal)
  }

  /// Whether this selection can start on the compiling host platform:
  /// [`Auto`](Self::Auto) everywhere (the barrier resolves it), an explicit
  /// variant only on the platform whose primitive it names. The real spawn
  /// seam rejects a foreign selection with
  /// [`SourceError::ForeignBackend`] before any platform code reads it.
  #[must_use]
  pub const fn native_to_host(&self) -> bool {
    match self {
      Self::Auto => true,
      Self::Inotify | Self::Fanotify => cfg!(target_os = "linux"),
      Self::Rdcw | Self::UsnJournal => cfg!(target_os = "windows"),
    }
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
  /// One decoded, pump-paired Windows record.
  Windows(windows::RawWindowsEvent),
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
  ino: u128,
}

impl RootIdentity {
  /// Wraps a stat-read `(device, inode)` pair. Identities are read off Unix
  /// metadata or minted by test harnesses; on a platform with neither the
  /// wrapped pair is the harmless `(0, 0)` its callers already synthesize
  /// (`dev_of`/`ino_of`/`identity_of`), and no real stream ever mints one.
  pub(crate) const fn new(dev: u64, ino: u128) -> Self {
    Self { dev, ino }
  }

  /// The device the identified object lives on.
  pub(crate) const fn dev(&self) -> u64 {
    self.dev
  }

  /// The identified object's inode (or 128-bit file id — ReFS ids exceed
  /// 64 bits, and a folded id would re-open the collision the registry's
  /// disjointness rests on; Unix inodes zero-extend).
  pub(crate) const fn ino(&self) -> u128 {
    self.ino
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
  /// The root's MOUNT id (from `statx(STATX_MNT_ID)` on the pinned root), or
  /// `None` when the source could not read one (below Linux 5.8 where the field
  /// is absent, or a non-Linux backend — FSEvents has no mount id). The core
  /// fences descent across a differing mount id: a `mount --bind` of a
  /// same-device directory shares [`root_dev`](Self::root_dev), so the device
  /// alone cannot mark it a boundary. `None` degrades to the device check.
  pub(crate) root_mnt_id: Option<u64>,
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
  /// The per-root backend selection the spawn barrier honors. The real spawn
  /// seam rejects a selection foreign to the host
  /// ([`SourceError::ForeignBackend`]) before any platform code reads it; on
  /// Linux [`Backend::Auto`] probes for fanotify and falls back to inotify,
  /// while the explicit variants pin the choice.
  pub(crate) backend: Backend,
  /// The fanotify admission-map directory cap (design §4.9); `None` = uncapped.
  /// A seed/reseed walk that would exceed it makes fanotify unviable (fall back
  /// under `Backend::Auto`, typed error when forced); a live create/move-in
  /// growing the map past it kills the scope (never OOM). Only the fanotify
  /// backend reads it.
  #[cfg_attr(not(all(target_os = "linux", not(miri))), allow(dead_code))]
  pub(crate) max_map_directories: Option<usize>,
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
      max_map_directories: None,
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
  /// The volume device hosting the root could not be opened (the USN arm's
  /// privilege discriminator — `\\.\X:` effectively requires elevation), or
  /// the root has no drive letter to name one.
  VolumeAccess,
  /// The volume's change journal is absent, deleted, or speaks no record
  /// version this backend reads (2..=3).
  JournalActive,
  /// The seed walk could not fully enumerate the tree under the root: an
  /// EXISTING in-root directory could not be read or handle-encoded (`EACCES`
  /// and friends), so the FID map would be born blind to that subtree and later
  /// events under it would drop as outside-root with no loss signal. fanotify's
  /// admission model requires a COMPLETE directory map, so an unwalkable tree is
  /// a viability failure — `Backend::Auto` falls back to inotify (which surfaces
  /// an unreadable directory natively through its per-directory arms), while a
  /// forced [`Backend::Fanotify`] surfaces this. A directory that merely VANISHED
  /// mid-walk (a benign race) never lands here — the walk skips it and proceeds.
  Walk,
}

impl ProbeStage {
  /// A stable tag naming the failed syscall stage.
  #[must_use]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::Init => "fanotify_init",
      Self::Mark => "fanotify_mark(FAN_MARK_FILESYSTEM)",
      Self::Handle => "name_to_handle_at",
      Self::VolumeAccess => "volume open",
      Self::JournalActive => "FSCTL_QUERY_USN_JOURNAL",
      Self::Walk => "seed-walk completeness",
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
  /// A forced privileged backend ([`Backend::Fanotify`], [`Backend::UsnJournal`])
  /// failed a precondition: the named stage was refused, or the seed walk found
  /// the tree not fully walkable (`Walk` — an existing in-root directory the
  /// map could not admit), so the backend cannot start. `Backend::Auto` falls
  /// back to the unprivileged arm instead of surfacing this.
  #[error("the probed backend is unavailable: {stage} was refused")]
  BackendProbeFailed {
    /// The precondition stage that failed.
    stage: ProbeStage,
  },
  /// The forced backend names another platform's primitive, so it can never
  /// start on this host. [`Backend::Auto`] is never foreign — the spawn
  /// barrier resolves it to the host's own primitive.
  #[error("the {} backend does not exist on this platform", requested.as_str())]
  ForeignBackend {
    /// The foreign selection.
    requested: Backend,
  },
  /// The decode callback panicked; the stream is poisoned.
  #[error("the event callback panicked")]
  CallbackPanic,
}

/// Where a dead stream's successor can resume from: the last in-sync journal
/// event id plus the device UUID that scopes its validity.
///
/// A root replacement consumes one: the driver takes the retiring stream's
/// token at command time and hands it to the replacement's spawn, so the
/// backend replays the swap window from the journal instead of leaving it to
/// the commit `Rescan` alone. The replay is best-effort by construction — a
/// wrapped id space mints no token, a purged journal replays nothing, and a
/// token is only ever honored against its own device — so the `Rescan` still
/// stands and the consumer contract is unchanged: delivery only gets denser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResumeToken {
  last_good: u64,
  device_uuid: Option<[u8; 16]>,
}

// The journal-replay token is consumed by the macOS FSEvents backend (and, for
// `new`, the cross-platform driver resume tests); on every other target the type
// is interface scaffolding — `SourceControl::resume_token` returns `Option<Self>`
// uniformly — so its accessors are legitimately unused there.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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

#[cfg(test)]
mod tests {
  use super::{Backend, BackendKind};

  #[test]
  fn backend_tags_are_stable() {
    assert_eq!(Backend::Auto.as_str(), "auto");
    assert_eq!(Backend::Inotify.as_str(), "inotify");
    assert_eq!(Backend::Fanotify.as_str(), "fanotify");
    assert_eq!(Backend::Rdcw.as_str(), "rdcw");
    assert_eq!(Backend::UsnJournal.as_str(), "usn-journal");
    assert_eq!(BackendKind::FsEvents.as_str(), "fsevents");
    assert_eq!(BackendKind::Inotify.as_str(), "inotify");
    assert_eq!(BackendKind::Fanotify.as_str(), "fanotify");
    assert_eq!(BackendKind::Rdcw.as_str(), "rdcw");
    assert_eq!(BackendKind::UsnJournal.as_str(), "usn-journal");
  }

  #[test]
  fn inotify_is_the_one_descending_profile() {
    assert!(BackendKind::FsEvents.is_kernel_recursive());
    assert!(!BackendKind::Inotify.is_kernel_recursive());
    assert!(BackendKind::Fanotify.is_kernel_recursive());
    assert!(BackendKind::Rdcw.is_kernel_recursive());
    assert!(BackendKind::UsnJournal.is_kernel_recursive());
  }

  #[test]
  fn auto_is_native_everywhere_and_explicit_variants_are_host_scoped() {
    assert!(Backend::Auto.native_to_host());
    let linux = cfg!(target_os = "linux");
    let windows = cfg!(target_os = "windows");
    assert_eq!(Backend::Inotify.native_to_host(), linux);
    assert_eq!(Backend::Fanotify.native_to_host(), linux);
    assert_eq!(Backend::Rdcw.native_to_host(), windows);
    assert_eq!(Backend::UsnJournal.native_to_host(), windows);
  }

  #[test]
  fn predicates_name_their_variant() {
    assert!(Backend::Auto.is_auto());
    assert!(Backend::Inotify.is_inotify());
    assert!(Backend::Fanotify.is_fanotify());
    assert!(Backend::Rdcw.is_rdcw());
    assert!(Backend::UsnJournal.is_usn_journal());
    assert!(!Backend::Auto.is_rdcw());
    assert!(!Backend::Rdcw.is_usn_journal());
  }
}
