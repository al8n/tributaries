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

use std::{
  io,
  num::{NonZeroU32, NonZeroUsize},
  path::PathBuf,
  time::Duration,
};

pub(crate) mod fsevent;
pub(crate) mod linux;
pub(crate) mod transport;
pub(crate) mod windows;

#[cfg(all(target_os = "macos", not(miri)))]
mod macos;
#[cfg(all(target_os = "macos", not(miri)))]
pub(crate) use macos::{Source, SourceHandle, mounts_under};

// Linux's own table reader stays inside `linux::` (its spawn barriers seed from
// it); the seam here is [`mount_sample`], which is what the refresh reads and the
// only one of the two that proves the table and the root's stat belong together.
#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) use linux::{Source, SourceHandle};

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

/// WHICH INCARNATION of a mount the root was living on when a refresh read it —
/// a token compared for equality and never for order, and the one fact a
/// recycled mount id cannot carry.
///
/// Mount ids are allocated lowest-free and freed on umount, so an A → B → A
/// sequence between two refreshes puts the root back on the id the previous
/// refresh recorded. Nothing in an id COMPARISON can see that: the refresh
/// observes a value, not a transition, and both values are `A`. A scope that
/// reads the match as proof of continuity keeps a descent frame that describes a
/// mount which has since died.
///
/// Both forms answer the same question and neither is ordered against the other,
/// which is why they are variants rather than a bare `u64`: a host answers one
/// KIND for its whole life, and comparing across kinds (which cannot happen)
/// reads as "changed", the conservative direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootIncarnation {
  /// `statx(STATX_MNT_ID_UNIQUE)` (Linux 6.8): a 64-bit id the kernel never
  /// recycles, so equality is proof of the same mount object and inequality is
  /// proof of a different one. Exact in both directions, and the only form that
  /// costs an unrelated namespace nothing.
  Unique(u64),
  /// A count of the mount-namespace TRANSITIONS this process has observed
  /// (`ns->event`, read through a held `/proc/self/mountinfo` fd — see
  /// [`linux::NamespaceWatch`]), for the 4.11–6.7 hosts that have no unique id.
  ///
  /// Equality proves the root's mount is the same object, because it proves
  /// nothing in the namespace moved at all. Inequality proves only that
  /// SOMETHING moved — one honest degrade in one direction: a mount elsewhere on
  /// the host reads as a frame move for every scope, which costs one whole-root
  /// recovery per refresh on a churning pre-6.8 host. The alternative is to keep
  /// reading a recycled id as evidence.
  Namespace(u64),
}

/// The mount-namespace transition counter a refresh reads its
/// [`RootIncarnation::Namespace`] token from — a real one on Linux, an inert
/// placeholder everywhere else.
#[cfg(not(all(target_os = "linux", not(miri))))]
#[derive(Debug, Default)]
pub(crate) struct NamespaceWatch;

#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) use linux::NamespaceWatch;

/// One refresh's coherent reading: the table under `root`, the caller's own
/// sample of the root, and the evidence about the WINDOW the two were taken in.
#[cfg_attr(
  not(any(
    all(
      any(target_os = "macos", target_os = "linux", target_os = "windows"),
      not(miri)
    ),
    test
  )),
  allow(dead_code)
)]
pub(crate) struct MountReading<S> {
  /// The rows strictly under the root, or `None` for a read that failed (or a
  /// window that never held still).
  pub(crate) rows: Option<Vec<MountRow>>,
  /// Whatever the caller sampled about the root itself, taken INSIDE the window.
  pub(crate) root: S,
  /// The mount-namespace generation observed inside the window, or `None` where
  /// the host answers none.
  pub(crate) namespace: Option<u64>,
  /// Whether the mount namespace provably held still across the whole window.
  ///
  /// It is what licenses a caller to pair two SEPARATE reads of the root as one
  /// incarnation token: the legacy mount id and the unique one come from two
  /// `statx` calls, and a transition between them would pair the old mount's
  /// legacy id with the new mount's unique id — a mismatched token that reads as
  /// continuity on the very next refresh.
  pub(crate) stable: bool,
}

/// The refresh's mount sample: the table under `root` AND the caller's own sample
/// of the root, taken so that the two describe ONE moment.
///
/// Linux has to prove that: its table is a `seq_file` generated across many
/// `read(2)` calls with the namespace lock dropped between them, so the rows and
/// a separately-stat'd root frame can straddle a mount transition, and mount ids
/// are recycled lowest-free — which makes "this row's id equals the root's" a
/// coincidence a torn pair can manufacture. Its version holds an fd across both
/// halves and rejects the pair when the namespace generation moved.
///
/// Everywhere else the table is a single call that returns a whole answer
/// (`getfsstat` on macOS, nothing at all on Windows and the unsupported stub), so
/// there is no window to straddle, the pair is just the two reads, and the
/// namespace token those hosts have no notion of is `None`.
#[cfg(not(all(target_os = "linux", not(miri))))]
pub(crate) fn mount_sample<S>(
  root: &std::path::Path,
  _namespace: &NamespaceWatch,
  mut sample_root: impl FnMut() -> S,
) -> MountReading<S> {
  MountReading {
    rows: mounts_under(root),
    root: sample_root(),
    namespace: None,
    stable: true,
  }
}

#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) use linux::mount_sample;

/// The root's UNIQUE mount id where the host has one. Only Linux 6.8+ does; every
/// other host answers `None` and falls back to the namespace token.
#[cfg(not(all(target_os = "linux", not(miri))))]
pub(crate) fn root_mnt_unique_id(_root: &std::path::Path) -> Option<u64> {
  None
}

#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) use linux::root_mnt_unique_id;

pub(crate) use fsevent::{FsEventFlags, RawOsEvent};

/// Whether a teardown PROVED the stream it destroyed had quiesced.
///
/// Every backend's `shutdown` answers this, and the driver's one submission
/// path turns the answer into the terminal it reports: `Proven` becomes
/// `TornDown`, `Unproven` becomes `TeardownFailed`. Both retire the
/// obligation — nothing is still running to wait on either way — but only
/// `Proven` licenses a caller to release everything the stream could still
/// reach, and only `Unproven` is counted against close's backlog and latched
/// against the scope so its awaited unwatches answer `NotQuiesced`.
///
/// # Why a teardown can END without OBSERVING its end
///
/// A reader thread that is JOINED is provably gone, so the Unix backends
/// always answer `Proven`: joining is the observation. The Windows pumps are
/// the shape that forced this vocabulary. Their reads are overlapped, so
/// between a successful issue and the dequeue of that issue's completion the
/// KERNEL owns the buffer and the `OVERLAPPED` — and a pump that panicked, or
/// whose cancellation drain never dequeued the read's final completion, cannot
/// prove that window closed. Such a pump deliberately RETAINS the pinned
/// memory instead of dropping it: freeing a buffer the kernel may still write
/// through would be a use-after-free, so leaking is the correct memory-safety
/// choice and stays.
///
/// What is NOT correct is letting that retention be read as a completed
/// teardown. Without this answer the pump's thread simply returned, its join
/// succeeded, and the driver classified a leak of handles and buffers as
/// `TornDown` — so repeated failures grew unbounded native state while close
/// and unwatch went on claiming quiescence over it. The leak is the honest
/// choice; this type is what makes REPORTING it honest too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "an unproven teardown must reach the driver's terminal, never be dropped as if it were success"]
pub(crate) enum Quiesce {
  /// The teardown observed its own end: nothing of the stream is still
  /// running, and nothing the OS could still write to was retained.
  Proven,
  /// The teardown ended without observing that end. Nothing is still owed to
  /// it — no thread to join, no completion to wait for — but native state may
  /// have been retained precisely because its lifetime could not be proven
  /// over, and no later teardown can prove it in retrospect.
  Unproven,
}

/// A spawn that failed, carrying the live stream — if one had already started —
/// that its failure could not honestly destroy on its own.
///
/// # Why a failing spawn does not tear its own stream down
///
/// Every barrier has a POST-LIVE half. The native stream is already running —
/// its reader started, its kernel-owned buffers pinned — while the barrier is
/// still re-proving the root's identity and reading the ancestor chain. A
/// failure there has to unwind a stream that exists.
///
/// Doing that unwinding inside the spawn looked obviously right, and it hid a
/// leak. The rollback's own `shutdown` answers [`Quiesce`], and a backend that
/// cannot prove its pinned I/O ended answers [`Quiesce::Unproven`] and RETAINS
/// the buffer and the handle — which stays the correct memory-safety choice,
/// because freeing memory the kernel may still write through is a
/// use-after-free. Discarding that answer (`let _ = handle.shutdown()`) reduced
/// a retained buffer and handle to an ordinary spawn error: no
/// `TeardownFailed` terminal reached the driver, so the retained state was
/// counted nowhere, the teardown backlog never slowed admission over it, and
/// `close` went on reporting quiescence. Repeated post-live failures then
/// accumulated native state in silence.
///
/// The reasoning that licensed the discard — "the spawn is failing, so no scope
/// exists and no obligation was ever counted" — is what was wrong. The scope not
/// existing does not make the retained state stop existing.
///
/// So a post-live failure performs NO teardown. It hands the running stream back
/// with the error, and the driver retires it through the same counted submission
/// every committed stream uses, where `Unproven` becomes `TeardownFailed`: counted
/// against the backlog, latched against the scope, and refused over by `close`.
/// The leak is still the honest choice; this type is what makes its REPORTING
/// honest too.
pub(crate) struct SpawnFailed<H> {
  error: SourceError,
  rollback: Option<H>,
}

impl<H> SpawnFailed<H> {
  /// A barrier that failed BEFORE anything went live: no stream exists, so
  /// there is nothing to retire and no quiescence for anyone to claim.
  pub(crate) fn refused(error: SourceError) -> Self {
    Self {
      error,
      rollback: None,
    }
  }

  /// A barrier that failed AFTER its stream went live. The stream rides back
  /// RUNNING and untouched — deliberately, because a teardown performed here
  /// could only produce its verdict where no accounting can hear it.
  // Only a barrier that can fail after going live with a teardown able to answer
  // `Unproven` builds one — today exactly the two Windows barriers. Every other
  // host still needs the constructor to exist: it is part of the seam type.
  #[cfg_attr(not(all(target_os = "windows", not(miri))), allow(dead_code))]
  pub(crate) fn rolled_back(error: SourceError, live: H) -> Self {
    Self {
      error,
      rollback: Some(live),
    }
  }

  /// Splits into the failure and the live stream it left behind.
  ///
  /// The ONE way the handle comes back out, so every caller can be read against
  /// the same rule: it moves the stream into a teardown guard in this very
  /// expression, and never binds it to a plain local.
  pub(crate) fn into_parts(self) -> (SourceError, Option<H>) {
    (self.error, self.rollback)
  }
}

impl<H> From<SourceError> for SpawnFailed<H> {
  /// Every PRE-live refusal converts through here, which is what lets a barrier
  /// keep using `?` on the fallible steps that run before its stream exists.
  fn from(error: SourceError) -> Self {
    Self::refused(error)
  }
}

impl<H> core::fmt::Debug for SpawnFailed<H> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("SpawnFailed")
      .field("error", &self.error)
      .field("rollback", &self.rollback.is_some())
      .finish()
  }
}

/// Starts one native stream — the seam's single spawn entry, and the only
/// caller of a platform `Source::spawn`.
///
/// The Windows barriers answer with [`SpawnFailed`] themselves: their pumps own
/// overlapped reads, so a rollback teardown can end without proving the kernel
/// released the buffer, and that verdict has to reach the driver's counted
/// teardown path rather than being discarded here.
#[cfg(all(target_os = "windows", not(miri)))]
pub(crate) fn spawn_source(
  config: SourceConfig,
) -> Result<(SourceHandle, EventReceiver, RootMeta), SpawnFailed<SourceHandle>> {
  Source::spawn(config)
}

/// Starts one native stream — the seam's single spawn entry, and the only
/// caller of a platform `Source::spawn`.
///
/// These backends refuse with no rollback stream, and that is honest rather
/// than merely convenient: every one of their teardowns is structurally
/// [`Quiesce::Proven`] — a joined reader thread (both Linux primitives), a
/// drained serial queue (FSEvents), or an uninhabited handle (the stub). A
/// thread that has ended has ended the only lifetime there was to observe, so a
/// rollback inside those barriers retains nothing for anyone to count. A
/// backend that ever gains a teardown able to answer `Unproven` must hand its
/// rollback back through [`SpawnFailed::rolled_back`] instead.
#[cfg(not(all(target_os = "windows", not(miri))))]
pub(crate) fn spawn_source(
  config: SourceConfig,
) -> Result<(SourceHandle, EventReceiver, RootMeta), SpawnFailed<SourceHandle>> {
  Source::spawn(config).map_err(SpawnFailed::refused)
}

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
///
/// # Configuration faces
///
/// Both faces spell a variant exactly as [`as_str`](Self::as_str) does — one
/// stable lowercase tag per variant, `usn-journal` included — so a log line, a
/// configuration document and a command line all name a backend the same way:
///
/// ```json
/// { "backend": "fanotify" }
/// ```
///
/// ```text
/// $ app --backend usn-journal
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
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

/// Every [`Backend`] variant, in declaration order — the single list
/// [`BACKEND_NAMES`] and the identifier visitor below both read, so a renamed
/// backend cannot drift between [`Backend::as_str`] and what this door
/// accepts. Adding a variant to [`Backend`] without adding it to
/// [`Backend::as_str`]'s match is already a compile error; adding it to THIS
/// array is not — so this is still a hand-maintained edge, but now the ONLY
/// one: nothing else here needs a second, independent update.
#[cfg(feature = "serde")]
const ALL_BACKENDS: [Backend; 5] = [
  Backend::Auto,
  Backend::Inotify,
  Backend::Fanotify,
  Backend::Rdcw,
  Backend::UsnJournal,
];

/// The legal spellings of a [`Backend`] tag, in variant-declaration order —
/// the same lowercase (kebab-case for `usn-journal`) words [`Backend::as_str`]
/// returns, derived from [`ALL_BACKENDS`] rather than typed out a second time.
#[cfg(feature = "serde")]
const BACKEND_NAMES: [&str; ALL_BACKENDS.len()] = {
  let mut names = [""; ALL_BACKENDS.len()];
  let mut index = 0;
  while index < ALL_BACKENDS.len() {
    names[index] = ALL_BACKENDS[index].as_str();
    index += 1;
  }
  names
};

/// The longest name in [`BACKEND_NAMES`], in bytes — the ceiling a tag is
/// measured against before anything is done with it. Derived from the
/// vocabulary itself, so a renamed or added backend moves it rather than
/// leaving a stale literal behind.
#[cfg(feature = "serde")]
const MAX_BACKEND_NAME_LEN: usize = {
  let mut longest = 0;
  let mut index = 0;
  while index < BACKEND_NAMES.len() {
    if BACKEND_NAMES[index].len() > longest {
      longest = BACKEND_NAMES[index].len();
    }
    index += 1;
  }
  longest
};

/// One variant tag, read through a BOUNDED identifier visitor — the same mold
/// [`Interest`](crate::Interest)'s own bounded tag uses, applied here through
/// `deserialize_identifier`: [`Backend`] is externally tagged, so the tag is the
/// enum's variant identifier rather than the whole value a `deserialize_str`
/// door would read — the identifier arm a non-self-describing format answers
/// with an INDEX rather than a string. Its `Value` is [`Backend`] directly
/// (every variant is a unit variant, so there is no payload left to read once
/// the identifier resolves): both spellings and the index are looked up
/// against [`ALL_BACKENDS`] rather than matched by hand, so a renamed tag
/// cannot drift between [`Backend::as_str`] and what this door accepts.
///
/// Asking the format for an owned `String` first hands an untrusted document
/// one allocation per tag before the five-word vocabulary it is about to fail
/// is ever consulted, and formatting an unknown tag into `unknown_variant` then
/// hands it a second allocation of the same size, live at the same instant. So
/// the ceiling is judged first, on the bytes the format is already holding, and
/// a tag past it is refused with a FIXED message naming the bound and the
/// length — never the value. What reaches `unknown_variant` is by construction
/// at most [`MAX_BACKEND_NAME_LEN`] bytes, so the echo it formats is bounded
/// too.
#[cfg(feature = "serde")]
struct BackendName;

#[cfg(feature = "serde")]
impl<'de> serde::de::DeserializeSeed<'de> for BackendName {
  type Value = Backend;

  fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    deserializer.deserialize_identifier(self)
  }
}

#[cfg(feature = "serde")]
impl serde::de::Visitor<'_> for BackendName {
  type Value = Backend;

  fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    write!(f, "a backend name of at most {MAX_BACKEND_NAME_LEN} bytes")
  }

  /// The one door, and the one every other text arm reaches: `visit_borrowed_str`
  /// and `visit_string` are serde's own forwards to it, so text the format
  /// borrows out of its input is measured without being copied at all, and
  /// text the format already owns is measured before this face does
  /// anything with it.
  fn visit_str<E>(self, name: &str) -> Result<Self::Value, E>
  where
    E: serde::de::Error,
  {
    if name.len() > MAX_BACKEND_NAME_LEN {
      // The length, never the value: an over-long tag is exactly the input
      // whose echo is the hazard.
      return Err(E::custom(format_args!(
        "a backend name is at most {MAX_BACKEND_NAME_LEN} bytes, and this one is {}",
        name.len()
      )));
    }
    ALL_BACKENDS
      .into_iter()
      .find(|backend| backend.as_str() == name)
      .ok_or_else(|| E::unknown_variant(name, &BACKEND_NAMES))
  }

  /// The bytes-identifier door a format reads when its tag comes as raw bytes
  /// rather than `str` (a binary format's map-key, for one) — bounded and
  /// echoed the same way [`visit_str`](Self::visit_str) is, `unknown_variant`
  /// included, since serde's own error only accepts a `str` to echo.
  fn visit_bytes<E>(self, name: &[u8]) -> Result<Self::Value, E>
  where
    E: serde::de::Error,
  {
    if name.len() > MAX_BACKEND_NAME_LEN {
      return Err(E::custom(format_args!(
        "a backend name is at most {MAX_BACKEND_NAME_LEN} bytes, and this one is {}",
        name.len()
      )));
    }
    ALL_BACKENDS
      .into_iter()
      .find(|backend| backend.as_str().as_bytes() == name)
      .ok_or_else(|| E::unknown_variant(&String::from_utf8_lossy(name), &BACKEND_NAMES))
  }

  /// The identifier door a NON-self-describing format answers with — the
  /// variant's declaration-order INDEX, which is what [`Backend`]'s derived
  /// `Serialize` still writes for such a format. Bounds-checked against
  /// [`ALL_BACKENDS`]'s own length rather than hand-counted, so a renamed or
  /// added variant moves the ceiling with it.
  fn visit_u64<E>(self, index: u64) -> Result<Self::Value, E>
  where
    E: serde::de::Error,
  {
    usize::try_from(index)
      .ok()
      .and_then(|index| ALL_BACKENDS.get(index).copied())
      .ok_or_else(|| {
        E::custom(format_args!(
          "a backend variant index is at most {}, and this one is {index}",
          ALL_BACKENDS.len() - 1
        ))
      })
  }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Backend {
  /// One externally-tagged, unit-only vocabulary — the string form
  /// (`"auto"`), the map form a unit variant takes (`{"auto": null}`), and a
  /// non-self-describing format's variant-index form all resolve through a
  /// bounded identifier seed rather than an owned, unbounded `String` serde's
  /// derive would build to match it against the vocabulary.
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    struct BackendVisitor;

    impl<'de> serde::de::Visitor<'de> for BackendVisitor {
      type Value = Backend;

      fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "a backend name of at most {MAX_BACKEND_NAME_LEN} bytes")
      }

      fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
      where
        A: serde::de::EnumAccess<'de>,
      {
        use serde::de::VariantAccess as _;

        let (backend, access) = data.variant_seed(BackendName)?;
        access.unit_variant()?;
        Ok(backend)
      }
    }

    deserializer.deserialize_enum("Backend", &BACKEND_NAMES, BackendVisitor)
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
  /// A live fanotify reader's recovery port. The kernel-recursive source carries
  /// no ARM traffic, but it does carry the one request the coarse mount-change
  /// cover needs of it: rebuild the FID map over the whole root (#74).
  #[cfg(all(target_os = "linux", not(miri)))]
  Fanotify(linux::RecoveryPort),
  /// No control traffic is possible (a source with nothing to arm and no map to
  /// reseed, or a fake).
  Inert,
}

/// Whether one whole-root recovery restored the source's sight (#74).
///
/// Two answers, because there are only two things the core can do with one. A
/// rebuilt map is sight, and the cover the recovery was requested for follows it.
/// A root the walk could not reach at all is a root DEATH — the same verdict a
/// refresh's own liveness gate reaches, funnelled the same way — and no cover is
/// owed for a tree that is gone.
///
/// A walk that failed for any other reason answers
/// [`Unreachable`](Self::Unreachable) too, and deliberately: a fanotify source
/// whose map could not be rebuilt is BLIND under the revealed ground, and a blind
/// source that keeps running is the silent-loss shape this stack exists to
/// refuse. The producer already retries once before conceding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootRecovery {
  /// The whole-root seed walk completed and the source's map was rebuilt from it.
  Reseeded,
  /// The walk could not reach the root, or could not complete: the source has no
  /// trustworthy sight of the tree, and the scope takes the root-death path.
  ///
  /// Only the fanotify producer can answer it — every other backend has no map to
  /// rebuild and answers [`Reseeded`](Self::Reseeded) unconditionally — so an
  /// off-Linux library build constructs it nowhere.
  #[cfg_attr(not(any(all(target_os = "linux", not(miri)), test)), allow(dead_code))]
  Unreachable,
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

/// One row of a live mount table, at a location strictly under a watched root:
/// WHERE the mount lands plus whatever IDENTITY the host can answer for it.
///
/// Linux reads all three identity fields off `/proc/self/mountinfo`, which
/// carries them on every row it already parses — field 1 is the mount id,
/// field 2 the parent mount's id, field 3 the `major:minor` of the mounted
/// filesystem. That is what makes the table an OBSERVER rather than a list of
/// paths: a mount replaced by a different mount at the SAME location is a
/// change in `(mnt_id, parent_id, dev)` and in nothing else, so a paths-only
/// read cannot see it at all.
///
/// Several rows can share one LOCATION — a stack, a `mount --move` onto an
/// occupied mount point, two mounts propagated side by side — and on Linux
/// every one of them is a row here, each with its own id. Nothing in this type
/// or in its producer says which of them a path lookup reaches, and nothing
/// needs to: a consumer that compares whole rows sees any of them arrive,
/// depart or be replaced.
///
/// The fourth identity field, [`mnt_id_unique`](MountRow::mnt_id_unique), is not
/// a mountinfo field at all: it is `statx(STATX_MNT_ID_UNIQUE)` on the row's own
/// location, taken by the producer inside the same namespace-stable window as the
/// table read. It is what makes a same-location replacement visible when the
/// legacy id was RECYCLED.
///
/// Every other host answers `None` for all four. macOS' `getfsstat` reports no
/// mount id, Windows reads no table, and the fakes have no namespace — so they
/// say so rather than inventing a value, and the consumers degrade honestly.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct MountRow {
  /// The mount point — where the kernel rendered this mount's path.
  ///
  /// A best-effort LABEL rather than a stable key on its own:
  /// `show_mountinfo` renders each row's path by its own `seq_path_root` call,
  /// so a rename can land between two rows of one read.
  pub(crate) location: PathBuf,
  /// The mount's own id, unique among LIVE mounts. `None` where the host
  /// answers none, or where the field would not parse.
  ///
  /// This is the LEGACY (non-unique) id, allocated lowest-free, so an unmount
  /// and a mount between two reads hand the new mount the just-freed id almost
  /// deterministically. `parent_id` narrows that window — the recycled id has
  /// to have been re-attached under the SAME mount as well — without closing
  /// it; [`mnt_id_unique`](Self::mnt_id_unique) is what closes it.
  pub(crate) mnt_id: Option<u64>,
  /// The mount's NEVER-RECYCLED id (`statx(STATX_MNT_ID_UNIQUE)`, Linux 6.8), or
  /// `None` on every host and kernel that has none.
  ///
  /// # Why a row carries two ids
  ///
  /// [`mnt_id`](Self::mnt_id) answers *which live mount is this* and nothing
  /// more: the kernel allocates it lowest-free and frees it on umount, so a bind
  /// that departs and a bind that arrives inside one refresh window hand the
  /// newcomer the id the old one gave up. Two reads that agree on the whole
  /// `(mnt_id, parent_id, dev)` tuple at one location are then INDISTINGUISHABLE
  /// from continuity — a value re-read at a cadence taken as confirmation — and
  /// the replacement the consumer is owed a cover for is never derived. This is
  /// the id a recycle cannot forge, so where the host answers one the sequence
  /// reads as the departure plus the arrival it was.
  ///
  /// # It is read through the PATH, so it answers for the TOPMOST mount there
  ///
  /// The producer reads it by `statx`ing the row's rendered location, and a path
  /// lookup reaches whatever is on top at that point. A row HIDDEN under a stack
  /// therefore reports the TOP row's unique id rather than its own. That is the
  /// right answer rather than a defect: a hidden mount's own arrival or departure
  /// reveals nothing while the mount above it stands, and the moment it becomes
  /// the top the path's unique id changes, which a row comparison reads as the
  /// replacement it is.
  ///
  /// # A per-row read that FAILS degrades that row, never the sample
  ///
  /// `None` covers three cases and the consumer may not tell them apart: a kernel
  /// below 6.8 (the mask bit is simply absent), a host with no such id at all, and
  /// a per-row `statx` that failed (a vanished mountpoint, a permission refusal).
  /// A failed read never invalidates the reading it belongs to — the sample's own
  /// namespace-stability bracket is what certifies that, and one unreadable row
  /// says nothing about the others. What it costs is that the row COMPARES
  /// differently, which a consumer reads as a change at that location: one extra
  /// recovery, never a silence.
  pub(crate) mnt_id_unique: Option<u64>,
  /// The id of the mount this one is attached to. `None` where the host answers
  /// none, or where the field would not parse.
  ///
  /// Held as IDENTITY, never as hierarchy. It is COMPARED — two reads that
  /// agree on a mount id but not on its parent are looking at two different
  /// vfsmounts, one of which inherited the other's recycled id — and it is
  /// never WALKED: nothing resolves it to another row, climbs a chain of them,
  /// or derives from the graph these links describe which mount a lookup
  /// reaches.
  pub(crate) parent_id: Option<u64>,
  /// The device of the filesystem mounted here, packed the way `dev_t` packs
  /// `major:minor`. `None` where the host answers none.
  pub(crate) dev: Option<u64>,
}

/// A scope's DESCENT FRAME — the root's device and mount id — carried on every
/// arm so the executor can refuse one that lands ACROSS it.
///
/// The core already fences enumerate descent on exactly these two facts
/// (`crosses_mount_boundary`), but an arm is a second way into the same ground
/// and the fence never sees it: a directory the Monitor learns about from a
/// `Created` record is armed with no enumerate in between, and inotify's
/// `Created` carries no identity at all, so the arm's own object guard
/// ([`ExpectedObject`](linux::ExpectedObject), `None` there) passes and the
/// watch installs on the far side of a mount. Refusing at the arm is what makes
/// the boundary ONE boundary rather than one the crawl honours and the live
/// stream walks straight through.
///
/// Travelling on the REQUEST rather than being held by the executor is
/// deliberate. A widen re-roots the scope onto an ancestor whose frame is its
/// own, and a replace swaps the world outright; an executor-held frame would
/// have to be invalidated at both, whereas a frame minted beside the arm is the
/// frame of the world that asked for it. It also reaches the fakes, which is
/// where the refusal is testable at all.
///
/// # `None` PASSES — the same honest degrade the fence itself makes
///
/// Either half unknown leaves that half inert, exactly as
/// `crosses_mount_boundary`'s own `None` legs do: a host that answers no mount id
/// ANYWHERE reads `None` for every one, and an off-Linux fake answers no frame at
/// all. A check that read unknown as "different" would refuse every arm on those
/// hosts.
///
/// An UNKNOWN is not a FAILED READ, and only the first one reaches here. A
/// `statx`/`fstat` that fails answers nothing about the object, so the executor
/// refuses the arm outright rather than handing this table a `None` that would
/// pass — see the inotify reader's `FrameCheck`. Everything that arrives as
/// `None` here is a value the host genuinely cannot supply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct ScopeFrame {
  /// The scope root's device, or `None` where the host answers none.
  pub(crate) root_dev: Option<u64>,
  /// The scope root's mount id, or `None` where the host answers none — off
  /// Linux, or a kernel below every id oracle.
  pub(crate) root_mnt_id: Option<u64>,
}

impl ScopeFrame {
  /// Whether an object that stat'd to `(dev, mnt_id)` sits ACROSS this frame —
  /// the SAME truth table `crosses_mount_boundary` fences enumerate descent on,
  /// so a refused arm and a declined dir entry agree about what a boundary is.
  ///
  /// Two independent fences, either one a boundary: the DEVICE belt (a different
  /// superblock is always a boundary) and the MOUNT frame (a `mount --bind` of a
  /// same-superblock directory shares the root's device, so only a differing
  /// mount id marks it). Reading the mount id alone would let a subvolume arm
  /// install; reading the device alone would let a bind arm install. Both, or
  /// the two seams disagree about what they are fencing.
  ///
  /// Every unknown leg PASSES (see the type doc).
  // Consumed by the inotify arm's own fence, which is Linux-only, and by the fake
  // executor that models it. Every other build carries the frame without ever
  // being able to ask it anything.
  #[cfg_attr(not(any(all(target_os = "linux", not(miri)), test)), allow(dead_code))]
  pub(crate) fn crossed_by(self, dev: Option<u64>, mnt_id: Option<u64>) -> bool {
    let device_boundary = matches!(
      (self.root_dev, dev),
      (Some(root_dev), Some(landed)) if landed != root_dev
    );
    let mount_boundary = matches!(
      (self.root_mnt_id, mnt_id),
      (Some(root_mnt), Some(landed)) if landed != root_mnt
    );
    device_boundary || mount_boundary
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
  /// The root's MOUNT id, read from the pinned root (`statx(STATX_MNT_ID)`, or
  /// that fd's `/proc/self/fdinfo` line below 5.8), or `None` when the source
  /// could not read one (a non-Linux backend — FSEvents has no mount id — or a
  /// kernel below every id oracle). The core
  /// fences descent across a differing mount id: a `mount --bind` of a
  /// same-device directory shares [`root_dev`](Self::root_dev), so the device
  /// alone cannot mark it a boundary. `None` degrades to the device check.
  pub(crate) root_mnt_id: Option<u64>,
  /// The trust-reducing mount seed: the table rows observed strictly under the
  /// root before the stream started (empty when the table could not be read —
  /// either way, event-side trust stays closed until the post-live refresh).
  ///
  /// The SAME read a refresh runs, so a seeded row carries the identity a later
  /// refresh compares against.
  pub(crate) mounts: Vec<MountRow>,
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

impl RootMeta {
  /// This world's descent frame, for an arm issued BEFORE the meta is committed
  /// into a scope — the widen pre-arm, whose target is the meta's own (wider)
  /// root and whose frame is therefore the meta's, never the scope's still-old
  /// one. Committed scopes read the frame off their state instead.
  pub(crate) const fn frame(&self) -> ScopeFrame {
    ScopeFrame {
      root_dev: Some(self.root_dev),
      root_mnt_id: self.root_mnt_id,
    }
  }
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
  // Only the journal-bearing backends (FSEvents, the USN journal) consume a
  // resume point — the Linux primitives have no journal to resume from — so a
  // Linux or stub build sees the field as dead.
  #[cfg_attr(
    not(all(any(target_os = "macos", target_os = "windows"), not(miri))),
    allow(dead_code)
  )]
  pub(crate) since: Option<ResumeToken>,
  /// The OS event-coalescing latency.
  pub(crate) latency: Duration,
  /// Capacity of the callback→driver channel, in callback batches.
  pub(crate) channel_capacity: NonZeroUsize,
  /// The native read buffer one source reads kernel records into, in bytes.
  /// Deliberately independent of [`channel_capacity`](Self::channel_capacity):
  /// a count of batches and a count of bytes answer to different limits.
  /// FSEvents owns its own buffering and ignores this.
  #[cfg_attr(
    not(all(any(target_os = "linux", target_os = "windows"), not(miri))),
    allow(dead_code)
  )]
  pub(crate) os_buffer_bytes: NonZeroU32,
  /// The per-root backend selection the spawn barrier honors. The real spawn
  /// seam rejects a selection foreign to the host
  /// ([`SourceError::ForeignBackend`]) before any platform code reads it; on
  /// Linux [`Backend::Auto`] probes for fanotify and falls back to inotify,
  /// while the explicit variants pin the choice.
  pub(crate) backend: Backend,
  /// The admission-map directory cap (design §4.9); `None` = uncapped. A
  /// seed/reseed walk that would exceed it makes the backend unviable (fall
  /// back under `Backend::Auto`, typed error when forced); a live create/move-in
  /// growing the map past it kills the scope (never OOM). Read by fanotify and
  /// the USN journal — the two backends that keep their own admission map;
  /// every other backend ignores it.
  #[cfg_attr(not(all(target_os = "linux", not(miri))), allow(dead_code))]
  pub(crate) max_map_directories: Option<usize>,
  /// The ROOT's compiled `prune` seat — the glob-shaped fence the caller armed
  /// this root with, carried into the source so a KERNEL-RECURSIVE backend can
  /// enforce it at its OWN boundary rather than only at the common layer's exit.
  ///
  /// The seat promises that a pruned subtree is never enumerated and never armed.
  /// On a descending backend the core's fence delivers that by never asking for a
  /// watch below a pruned directory. A backend that keeps its own admission MAP
  /// (fanotify, the USN journal) has no such lever: its mark covers a whole
  /// superblock or volume, so a pruned subtree the seed walk mapped would go on
  /// costing map entries and transport admission for churn the caller asked not
  /// to hear about — the same load-shedding hole the exclusion set closes one
  /// layer down. So those two consult this set wherever their map can GROW (the
  /// seed and reseed walks, a moved-in subtree walk, a live learn) and ahead of
  /// bounded transport admission, exactly as they consult
  /// [`exclusions`](Self::exclusions).
  ///
  /// FSEvents and RDCW ignore it: neither keeps a directory map, so there is
  /// nothing under a pruned name for them to spend, and the core's own fence is
  /// the whole enforcement.
  ///
  /// Empty — the overwhelmingly common case — short-circuits every test.
  #[cfg_attr(
    not(all(any(target_os = "linux", target_os = "windows"), not(miri))),
    allow(dead_code)
  )]
  pub(crate) prune: tributary_proto::glob::Globs,
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
      os_buffer_bytes: NonZeroU32::new(64 * 1024).expect("64 KiB is nonzero"),
      backend: Backend::Auto,
      max_map_directories: None,
      prune: tributary_proto::glob::Globs::default(),
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

/// Where a dead stream's successor can resume from — ONE variant per backend
/// that keeps a journal, each carrying its own cursor together with the scope
/// that makes the cursor mean anything.
///
/// A cursor alone is never a resume point: a journal id space is scoped (to a
/// device on macOS, to a journal instance on a volume on Windows), and replaying
/// an id under a different scope names unrelated history. Carrying the scope IN
/// the token is what lets the honoring side answer with one call
/// ([`fsevents_since`](Self::fsevents_since),
/// [`usn_cursor`](Self::usn_cursor)) instead of re-deriving the rule per
/// backend — including the rule that a token minted by ANOTHER backend is not a
/// resume point at all, just a miss.
///
/// # A token advances only over acknowledged ingest
///
/// A root replacement consumes one: the driver takes the retiring stream's token
/// at command time and hands it to the replacement's spawn, so the backend
/// replays the swap window from the journal instead of leaving it to the commit
/// `Rescan` alone. What makes that sound is that the producer never PUBLISHES a
/// cursor — it stages a candidate with the batch that reaches the cursor, and
/// only the driver's ingest of that batch publishes it
/// (`transport::ResumeAck`). So a batch dropped over budget, refused by a gone
/// receiver, or still sitting in the queue leaves the token where it was, and
/// the successor re-reads that span rather than skipping it.
///
/// The replay stays best-effort in the other direction — a wrapped id space
/// mints no token, a purged journal replays nothing, a foreign scope is not
/// honored — so the `Rescan` still stands and the consumer contract is
/// unchanged: delivery only gets denser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResumeToken {
  /// The macOS FSEvents journal: the highest event id observed in sync, scoped
  /// by the device UUID whose journal minted it (`None` when the OS could not
  /// supply one, which no honoring side accepts).
  #[cfg_attr(not(all(target_os = "macos", not(miri))), allow(dead_code))]
  FsEvents {
    /// The highest in-sync journal event id.
    last_good: u64,
    /// The device whose journal the id belongs to.
    device_uuid: Option<[u8; 16]>,
  },
  /// The Windows USN change journal: the next USN to read, scoped by the
  /// journal instance and the volume it lives on. A journal deleted and
  /// recreated gets a fresh id, which is exactly what makes an old cursor
  /// unhonorable.
  #[cfg_attr(not(all(target_os = "windows", not(miri))), allow(dead_code))]
  Usn {
    /// The journal instance the cursor indexes into.
    journal_id: u64,
    /// The USN the next read should start at.
    next_usn: i64,
    /// The volume serial the journal belongs to.
    volume_serial: u64,
  },
}

// Which half of this vocabulary is live is per-target: macOS mints and honors
// the FSEvents variant, Windows the USN one, and a Linux or stub build carries
// the type only because `SourceControl::resume_token` returns `Option<Self>`
// uniformly. The seam deliberately does not fork per platform, so the other
// backend's constructor and accessor are dead on any single one.
impl ResumeToken {
  /// An FSEvents resume point.
  #[cfg_attr(not(all(target_os = "macos", not(miri))), allow(dead_code))]
  pub(crate) const fn fsevents(last_good: u64, device_uuid: Option<[u8; 16]>) -> Self {
    Self::FsEvents {
      last_good,
      device_uuid,
    }
  }

  /// A USN journal resume point.
  #[cfg_attr(not(all(target_os = "windows", not(miri))), allow(dead_code))]
  pub(crate) const fn usn(journal_id: u64, next_usn: i64, volume_serial: u64) -> Self {
    Self::Usn {
      journal_id,
      next_usn,
      volume_serial,
    }
  }

  /// The FSEvents event id to start from on the device currently under
  /// `device_uuid`, or `None` when this token cannot speak for it — another
  /// backend's token, another device's journal, or a device with no UUID at
  /// either end.
  #[cfg_attr(not(all(target_os = "macos", not(miri))), allow(dead_code))]
  pub(crate) fn fsevents_since(&self, device_uuid: Option<[u8; 16]>) -> Option<u64> {
    match (self, device_uuid) {
      (
        Self::FsEvents {
          last_good,
          device_uuid: Some(minted),
        },
        Some(current),
      ) if *minted == current => Some(*last_good),
      _ => None,
    }
  }

  /// The USN to start reading at on the named journal and volume, or `None`
  /// when this token cannot speak for them.
  #[cfg_attr(not(all(target_os = "windows", not(miri))), allow(dead_code))]
  pub(crate) fn usn_cursor(&self, journal_id: u64, volume_serial: u64) -> Option<i64> {
    match self {
      Self::Usn {
        journal_id: minted_journal,
        next_usn,
        volume_serial: minted_volume,
      } if *minted_journal == journal_id && *minted_volume == volume_serial => Some(*next_usn),
      _ => None,
    }
  }

  /// Whether `self` and `other` were minted under the SAME journal scope, so
  /// their cursors are comparable. Two tokens of different backends, devices, or
  /// journal instances never are: the later one REPLACES the earlier rather than
  /// racing it for a maximum.
  pub(crate) fn same_scope(&self, other: &Self) -> bool {
    match (self, other) {
      (
        Self::FsEvents {
          device_uuid: left, ..
        },
        Self::FsEvents {
          device_uuid: right, ..
        },
      ) => left == right,
      (
        Self::Usn {
          journal_id: left_journal,
          volume_serial: left_volume,
          ..
        },
        Self::Usn {
          journal_id: right_journal,
          volume_serial: right_volume,
          ..
        },
      ) => left_journal == right_journal && left_volume == right_volume,
      _ => false,
    }
  }

  /// Whether `self` names a point at or beyond `other` WITHIN one scope. Only
  /// meaningful for same-scope tokens; the publish path checks that first.
  pub(crate) fn reaches(&self, other: &Self) -> bool {
    match (self, other) {
      (Self::FsEvents { last_good: new, .. }, Self::FsEvents { last_good: old, .. }) => new >= old,
      (Self::Usn { next_usn: new, .. }, Self::Usn { next_usn: old, .. }) => new >= old,
      _ => false,
    }
  }
}

#[cfg(test)]
mod tests {
  use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  };

  use super::{Backend, BackendKind, Quiesce, SourceError, SpawnFailed};

  /// A stand-in for a live stream handle that records every way it could be
  /// reclaimed. The Windows barriers cannot run on this host, but the DECISION a
  /// failing post-live barrier makes about its stream is host-testable: whether
  /// the stream is destroyed inside the failing spawn or handed back running.
  struct LiveStream {
    reclaims: Arc<AtomicUsize>,
    verdict: Quiesce,
    shut: bool,
  }

  impl LiveStream {
    fn new(reclaims: &Arc<AtomicUsize>, verdict: Quiesce) -> Self {
      Self {
        reclaims: Arc::clone(reclaims),
        verdict,
        shut: false,
      }
    }

    fn shutdown(mut self) -> Quiesce {
      self.shut = true;
      self.reclaims.fetch_add(1, Ordering::SeqCst);
      self.verdict
    }
  }

  impl Drop for LiveStream {
    /// The real handles' `Drop` backstop: a stream nobody shut down is still
    /// reclaimed, which is exactly why "just drop it" is not a way to avoid the
    /// question.
    fn drop(&mut self) {
      if !self.shut {
        self.reclaims.fetch_add(1, Ordering::SeqCst);
      }
    }
  }

  /// A barrier that fails after its stream is live surrenders the RUNNING
  /// stream, and its verdict survives the trip out.
  ///
  /// This is the decision the finding turned on. The failing spawn used to call
  /// `shutdown` itself and discard the answer, so a rollback that had to retain
  /// kernel-owned buffers reported nothing: the retention was counted nowhere
  /// and `close` still claimed quiescence over it. Nothing about the spawn
  /// failing made that state stop existing — only the reporting was missing.
  ///
  /// FAIL-ON-REVERT: implement `rolled_back` the way the barriers used to behave
  /// — `let _ = live.shutdown(); Self::refused(error)` — and the reclaim count
  /// below is 1 before anyone was told, and `into_parts` yields `None`, so the
  /// verdict has no route to a terminal.
  #[test]
  fn a_post_live_failure_surrenders_its_stream_rather_than_reclaiming_it() {
    let reclaims = Arc::new(AtomicUsize::new(0));
    let failure = SpawnFailed::rolled_back(
      SourceError::RootReplaced {
        root: std::path::PathBuf::from("/r"),
      },
      LiveStream::new(&reclaims, Quiesce::Unproven),
    );
    assert_eq!(
      reclaims.load(Ordering::SeqCst),
      0,
      "the failing barrier neither tears the stream down nor drops it"
    );

    let (error, rollback) = failure.into_parts();
    assert!(matches!(error, SourceError::RootReplaced { .. }));
    let rollback = rollback.expect("the live stream rides out with the error");
    assert_eq!(
      reclaims.load(Ordering::SeqCst),
      0,
      "and it is still live in the caller's hands"
    );

    // The caller — the driver's counted submission — is the one that reclaims
    // it, and the verdict it reads is the stream's own.
    assert_eq!(
      rollback.shutdown(),
      Quiesce::Unproven,
      "an unproven rollback stays unproven all the way to the accounting"
    );
    assert_eq!(reclaims.load(Ordering::SeqCst), 1, "reclaimed exactly once");
  }

  /// A barrier that fails BEFORE anything went live carries no stream, so there
  /// is nothing to retire and no quiescence anyone could be claiming.
  #[test]
  fn a_pre_live_refusal_carries_no_stream() {
    let (error, rollback) = SpawnFailed::<LiveStream>::from(SourceError::NoRoots).into_parts();
    assert!(matches!(error, SourceError::NoRoots));
    assert!(
      rollback.is_none(),
      "a refusal before start owns no stream to hand back"
    );
  }

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

  /// [`Backend`]'s hand-written bounded-visitor [`Deserialize`](serde::Deserialize).
  #[cfg(feature = "serde")]
  mod serde_face {
    use serde::de::{DeserializeSeed as _, value::U64Deserializer};

    use super::super::{BACKEND_NAMES, Backend, BackendName};

    #[test]
    fn every_variant_round_trips() {
      for backend in [
        Backend::Auto,
        Backend::Inotify,
        Backend::Fanotify,
        Backend::Rdcw,
        Backend::UsnJournal,
      ] {
        let json = serde_json::to_string(&backend).unwrap();
        assert_eq!(json, format!(r#""{}""#, backend.as_str()));
        assert_eq!(serde_json::from_str::<Backend>(&json).unwrap(), backend);
      }
    }

    /// The externally-tagged MAP form a unit variant takes — `derive(Deserialize)`
    /// accepted `{"auto": null}` for every variant, and the bounded hand impl
    /// must accept exactly the same shape: `deserialize_enum` frames it, not
    /// `deserialize_str`.
    #[test]
    fn every_variant_round_trips_through_the_map_form() {
      for backend in [
        Backend::Auto,
        Backend::Inotify,
        Backend::Fanotify,
        Backend::Rdcw,
        Backend::UsnJournal,
      ] {
        let document = format!(r#"{{"{}": null}}"#, backend.as_str());
        assert_eq!(
          serde_json::from_str::<Backend>(&document).unwrap(),
          backend,
          "the map form of a unit variant round-trips: {document}"
        );
      }
    }

    /// A tag longer than the longest valid name is refused ON ITS LENGTH, and
    /// the refusal says nothing about the value.
    #[test]
    fn an_over_long_backend_name_is_refused_without_echoing_it() {
      const FILLER: char = 'z';

      let tag: String = core::iter::repeat_n(FILLER, 1024 * 1024).collect();
      let document = format!(r#""{tag}""#);
      let refusal = serde_json::from_str::<Backend>(&document)
        .expect_err("a tag past the vocabulary's longest name is refused")
        .to_string();

      assert!(
        refusal.contains("at most 11 bytes"),
        "the refusal names the bound: {refusal}"
      );
      assert!(
        refusal.contains(&tag.len().to_string()),
        "and the length it measured: {refusal}"
      );
      assert!(
        !refusal.contains(&FILLER.to_string().repeat(9)),
        "and none of the value itself: {refusal}"
      );
    }

    /// The same bound, over the bytes-identifier door — the one a binary
    /// format's map-key reaches, which `serde_json` never drives.
    #[test]
    fn an_over_long_backend_name_is_refused_without_echoing_it_as_bytes() {
      use serde::de::Visitor as _;

      const FILLER: u8 = b'z';

      let tag = alloc_vec(FILLER, 1024 * 1024);
      let refusal = BackendName
        .visit_bytes::<serde_json::Error>(&tag)
        .expect_err("a tag past the vocabulary's longest name is refused")
        .to_string();

      assert!(
        refusal.contains("at most 11 bytes"),
        "the refusal names the bound: {refusal}"
      );
      assert!(
        refusal.contains(&tag.len().to_string()),
        "and the length it measured: {refusal}"
      );
      assert!(
        !refusal.contains(&(FILLER as char).to_string().repeat(9)),
        "and none of the value itself: {refusal}"
      );
    }

    fn alloc_vec(byte: u8, len: usize) -> std::vec::Vec<u8> {
      core::iter::repeat_n(byte, len).collect()
    }

    /// A junk tag inside the bound reaches the vocabulary and is refused as
    /// `unknown_variant`, with the (short, bounded) tag echoed.
    #[test]
    fn a_junk_backend_name_inside_the_bound_is_an_unknown_variant() {
      let refusal = serde_json::from_str::<Backend>(r#""notabackend""#)
        .expect_err("not one of the five spellings")
        .to_string();
      assert!(
        refusal.contains("unknown variant") && refusal.contains("notabackend"),
        "the vocabulary answers an in-bound tag: {refusal}"
      );
    }

    /// A non-self-describing format's identifier door answers with the
    /// variant's declaration-order INDEX rather than a name — the shape
    /// `Backend`'s own derived `Serialize` still writes for such a format.
    /// `U64Deserializer` drives `deserialize_identifier` exactly the way such a
    /// format would: index `0` is the first variant, and an out-of-range index
    /// is refused with a fixed message.
    #[test]
    fn index_zero_resolves_to_the_first_variant_through_a_non_self_describing_identifier() {
      let seed_result = BackendName.deserialize(U64Deserializer::<serde_json::Error>::new(0));
      assert!(
        matches!(seed_result, Ok(Backend::Auto)),
        "index 0 is the first variant, Backend::Auto"
      );
    }

    #[test]
    fn an_out_of_range_backend_index_is_refused() {
      let out_of_range = BACKEND_NAMES.len() as u64;
      let refusal =
        BackendName.deserialize(U64Deserializer::<serde_json::Error>::new(out_of_range));
      let refusal = refusal
        .expect_err("an index at or past the vocabulary's length names no variant")
        .to_string();
      assert!(
        refusal.contains(&format!("at most {}", BACKEND_NAMES.len() - 1)),
        "the refusal names the fixed bound: {refusal}"
      );
    }
  }

  /// The `clap` face ([`clap::ValueEnum`]) is untouched by the bounded-visitor
  /// `Deserialize` rewrite above — it still parses every spelling
  /// [`Backend::as_str`] returns.
  #[cfg(feature = "clap")]
  mod clap_face {
    use clap::ValueEnum as _;

    use super::Backend;

    #[test]
    fn every_variant_parses_from_its_own_tag() {
      for backend in [
        Backend::Auto,
        Backend::Inotify,
        Backend::Fanotify,
        Backend::Rdcw,
        Backend::UsnJournal,
      ] {
        assert_eq!(Backend::from_str(backend.as_str(), false).unwrap(), backend);
      }
    }
  }
}
