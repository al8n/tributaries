//! The platform seam between the async driver and the OS watch primitive.
//!
//! Every platform module exposes the same surface: [`Source::spawn`] starts the
//! native watch and hands back a [`SourceHandle`] plus the ONE ordered queue
//! it reports on. `Batch`, `Boundaries`, `Overflow`, and `Fatal` all ride that
//! single unbounded FIFO, so per-source ordering between data and the loss/death
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
/// reads the match as proof of continuity then admits a walk that ran against an
/// incarnation which has since died — its generation retires boundaries the live
/// root never presented, and its reseeded map describes the dead one.
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
  /// `linux::NamespaceWatch`), for the 4.11–6.7 hosts that have no unique id.
  ///
  /// Equality proves the root's mount is the same object, because it proves
  /// nothing in the namespace moved at all. Inequality proves only that
  /// SOMETHING moved — one honest degrade in one direction: a mount elsewhere on
  /// the host reads as a frame move for every scope, which costs a whole-root
  /// generation per refresh for a scope holding exempt records on a churning
  /// pre-6.8 host, exactly the bound a fail-closed scope already pays. The
  /// alternative is to keep reading a recycled id as evidence.
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
/// or in its producer says which of them a path lookup reaches; the core keys
/// its census by identity, so it does not need to be told.
///
/// Every other host answers `None` for all three. macOS' `getfsstat` reports no
/// mount id, Windows reads no table, and the fakes have no namespace — so they
/// say so rather than inventing a value, and the consumers degrade honestly
/// (the core's census key falls back to the rendered location for a row with no
/// id, and an unknown half never reads as a difference).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MountRow {
  /// The mount point — where the kernel rendered this mount's path.
  ///
  /// A best-effort LABEL, not a key: `show_mountinfo` renders each row's path
  /// by its own `seq_path_root` call, so a rename can land between two rows of
  /// one read. The core carries it as a cover-location hint and keys on the
  /// identity below.
  pub(crate) location: PathBuf,
  /// The mount's own id, unique among LIVE mounts. `None` where the host
  /// answers none, or where the field would not parse.
  ///
  /// This is the LEGACY (non-unique) id, allocated lowest-free, so an unmount
  /// and a mount between two reads hand the new mount the just-freed id almost
  /// deterministically. `parent_id` narrows that window — the recycled id has
  /// to have been re-attached under the SAME mount as well — without closing
  /// it; `STATX_MNT_ID_UNIQUE` (Linux 6.8) is the upgrade where a future reader
  /// can require a genuinely unique one.
  pub(crate) mnt_id: Option<u64>,
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

/// One boundary an os-layer WALK declined to descend — SEAM 2 of the mount
/// design, carried out of the walk instead of discarded at it.
///
/// Deliberately NOT a [`MountRow`], though the two carry the same three facts.
/// A row is a mountinfo line: proof that a vfsmount is (or was) at that
/// location, and therefore something a CENSUS can key and derive transitions
/// for. A decline is only "the walk's fence said stop here" — which a btrfs
/// subvolume trips on the device belt while carrying the walk root's own mount
/// id, with no row, ever. Keeping the two types apart is what stops a future
/// reader from feeding a decline into the census and re-opening the cover storm
/// that "condemn on a transition, never on an absence" exists to prevent (see the
/// core's `CensusRow` and `LedgerEntry`).
///
/// The fields mirror what the fence actually reads at the moment it declines,
/// and no more:
///
/// - `dev` is always known: the walk `fstat`s every child it pins, and the
///   device belt is decided on that stat.
/// - `mnt_id` is ALSO read for every decline, both fences alike, from the fd the
///   walk pinned — so a `None` here means the HOST answers no mount id ANYWHERE
///   it could be asked (neither the `statx` mask nor the fd's `/proc/self/fdinfo`
///   line), never that this observer did not ask. That distinction is
///   load-bearing. An id-less observation is one the core can only record
///   `Standing::Unknown`, which joins no census and fails the whole scope closed
///   while it is held, so producing one from an observation that COULD have
///   answered the id — as the device belt once did, being checked before the
///   `statx` — buys a whole-root cover per refresh in place of a precise
///   departure. Since the fdinfo tier (`os::linux`'s `root_mount_id`) that `None`
///   needs a kernel below BOTH floors, 3.15 fdinfo and 4.11 `statx`, so no
///   supported host reaches it and the type carries the case only because the
///   core must not assume it away. A read that FAILS yields an incomplete walk
///   instead; it never reaches this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeclinedBoundary {
  /// The absolute path of the declined child.
  pub(crate) location: PathBuf,
  /// The declined child's device, from the `fstat` of the pinned fd.
  pub(crate) dev: u64,
  /// The declined child's mount id, read from the pinned fd for EVERY decline;
  /// `None` only where the host answers no mount ids (see the type doc).
  pub(crate) mnt_id: Option<u64>,
}

/// What ONE walk (or one buffer's worth of walks) observed about boundaries —
/// SEAM 2's payload on the source's ordered queue.
///
/// A bare `Vec<DeclinedBoundary>` could only ever ADD, and that was the whole of
/// the growth problem: the core's DEVICE-ONLY partition — records the provenance
/// partition exempts from every condemnation mechanism — had exactly one removal
/// path, a compiled `Removed`/`MovedFrom` in the event stream, and a loss window
/// that swallowed those left the record standing for the scope's life. Saying
/// whether a report is COMPLETE turns the same message into a generation the core
/// can reconcile against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WalkBoundaries {
  /// The boundaries the walk(s) declined to descend.
  pub(crate) declined: Vec<DeclinedBoundary>,
  /// How much of the root [`declined`](Self::declined) speaks for — and, for the
  /// complete form, the frame it was taken in.
  pub(crate) reach: WalkReach,
}

/// How much of the scope root ONE boundary report speaks for.
///
/// The two arms are read oppositely, and the difference is the whole reason the
/// distinction is on the wire: a COMPLETE report is a generation the core
/// reconciles against — what it did not decline is not there any more — while a
/// partial one may only ever ADD.
///
/// # Why only the complete arm carries a frame
///
/// Because only the complete arm RETIRES, and a retirement is the one operation
/// whose licence depends on which root the walk ran under. "Everything still
/// standing under the root" is a claim about a particular root mount; taken under
/// one and applied under another it deletes records for boundaries the walk never
/// looked at, and the device-only partition it deletes from has no other observer
/// that could put them back.
///
/// The additive arm needs no frame because forgoing it is the DANGEROUS direction
/// there: a decline dropped is a boundary recorded nowhere, whose later departure
/// is then derived by nothing, while a decline applied under a moved frame costs
/// at worst one false condemnation that converges through the admission round
/// trip's own re-reading. Safe-to-drop and unsafe-to-drop are opposite here, so
/// the stamp belongs on exactly one of them.
#[cfg_attr(not(any(all(target_os = "linux", not(miri)), test)), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WalkReach {
  /// ONE SUBTREE: a moved-in subtree walk, an admission reseed. It proves nothing
  /// about the rest of the root, so the core only ever adds from it.
  Partial,
  /// THE WHOLE ROOT, from a walk that RAN TO COMPLETION — the post-loss map
  /// reseed (its budget-truncated and failed forms return no seed at all, so they
  /// never reach here). The core reads it as a generation: a device-only record
  /// under the root that this walk did not decline is not there any more, and this
  /// is the only observation on a kernel-recursive profile that can say so — the
  /// mount table cannot, by the partition's own construction.
  ///
  /// # Two stamps, because a mount id is not a generation
  ///
  /// This arm once carried the walked root id alone, and that was sufficient only
  /// against a root that moved and STAYED moved. Linux allocates mount ids
  /// lowest-free, so a root that goes A → B → A is back on the id the core still
  /// holds while the walk that produced this generation ran against the FIRST A —
  /// a mount that has since died. The id comparison passes, the generation retires
  /// device-only records the current incarnation never showed the walk, and the
  /// mount table cannot restore that partition, so every later departure under it
  /// becomes underivable. That is the whole of the loss the id leg cannot see.
  ///
  /// So the report carries the core's own [`epoch`](Self::WholeRoot::epoch)
  /// beside it, exactly as [`RootRecovery`] does. The two legs cover each other:
  /// the epoch counts WORLDS core-side and is never recycled, so no reading of an
  /// id can forge it, while the walked id speaks for the SOURCE and catches a root
  /// that moved before the core ever ran the refresh that would bump an epoch.
  WholeRoot {
    /// The ROOT MOUNT ID this walk fenced its descent against, read from the fd it
    /// reopened — the root the generation actually describes.
    ///
    /// The core installs nothing from a generation whose root is not the one it
    /// holds. This is the leg that speaks for the SOURCE: it is read live, off the
    /// fd the reseed reopened, and no value the core supplied can make it agree.
    ///
    /// `None` PASSES, as every unknown frame leg does — a host that answers no
    /// mount id ANYWHERE reads `None` for every one, and the epoch beside it
    /// carries the check there, exactly as it does for
    /// [`RootRecovery::root_mnt_id`].
    root_mnt_id: Option<u64>,
    /// The core's own [frame epoch](crate::os::AdmitRequest::epoch) as the SOURCE
    /// last heard it, sampled BEFORE the reseed walk began.
    ///
    /// Core-owned, monotone and never recycled — which is the whole point: it is a
    /// count of the worlds the core has adopted, not an identifier the kernel
    /// re-issues. The core publishes it down the same control mailbox that carries
    /// admissions and recoveries (`Control::Frame`), the reader keeps the newest
    /// value it has ever been told, and a walk stamps the value it held when it
    /// STARTED — so a generation whose walk began before a frame move carries the
    /// pre-move count and is refused, however the ids happen to compare.
    ///
    /// Sampling before rather than after is the safe direction and not an
    /// accident: a stamp taken after the walk would claim a world the walk never
    /// saw the whole of. A stale sample only costs one refused generation, which
    /// the next one replaces.
    epoch: u64,
  },
}

impl WalkReach {
  /// The stamps a COMPLETE generation was taken under — `(walked root id, the
  /// core's frame epoch the source last heard)` — or `None` for a partial report,
  /// which retires nothing and is therefore judged against no frame.
  pub(crate) const fn whole_root_stamp(self) -> Option<(Option<u64>, u64)> {
    match self {
      Self::Partial => None,
      Self::WholeRoot { root_mnt_id, epoch } => Some((root_mnt_id, epoch)),
    }
  }
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

/// Correlates one ADMISSION RESEED round trip — the core's request that a
/// kernel-recursive source admit the ground a departed mount revealed, and the
/// [`AdmitReport`] the source answers with.
///
/// Minted by the core, echoed back untouched. It is what lets the core hold the
/// departure's cover PARKED across the round trip and still know, on a reply,
/// which parked cover the answer belongs to — an ordinary path comparison could
/// not, since a second mount may already have arrived and departed at the same
/// location by then.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct AdmitTicket(u64);

impl AdmitTicket {
  /// The ticket for round trip `seq`. Only the core mints these, off its own
  /// monotone counter.
  pub(crate) const fn new(seq: u64) -> Self {
    Self(seq)
  }
}

/// One admission reseed: admit the ground the mount that departed at `location`
/// REVEALED, before the cover for it is emitted.
///
/// # Why the request exists at all
///
/// fanotify admits by directory-handle MEMBERSHIP, and the seed walk declines to
/// descend a mount (`crate::os::linux::fanotify::map`) — so a mount that departs
/// reveals a subtree whose handles were never seeded, and the reader drops every
/// later event on it as provably-outside-root. A located `Rescan` alone would
/// have the consumer re-read ground the source is still blind to, and there is no
/// crawl to fix it: `Monitor::start_rearm` refuses outright on a non-descending
/// scope. So the ground must be walked INTO the map, and the cover must wait for
/// that walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmitRequest {
  /// The round trip this request opens.
  pub(crate) ticket: AdmitTicket,
  /// The departed boundary's location: the walk's root, and the parked cover's
  /// target.
  pub(crate) location: PathBuf,
  /// The scope's descent frame AT PARK TIME. The walk re-opens `location`, reads
  /// the frame of the object it actually pinned, and REFUSES the reseed when that
  /// sits across the root's frame ([`ScopeFrame::crossed_by`]) — a location still
  /// covered, or re-covered by a remount between the refresh's read and the walk,
  /// would otherwise be walked against the BIND's frame and seed an alias subtree
  /// into the admission map, the exact breach the walk's own mount fence exists to
  /// prevent.
  ///
  /// **This value is NOT what the fence is taken against.** The walk re-reads the
  /// ROOT's frame from an fd it holds open beside the location's, because a mount
  /// id is unique among LIVE mounts and means nothing against a reading from
  /// another moment: ids are allocated lowest-free, so a root that re-mounted and
  /// a bind that took the id it gave up would compare EQUAL across the park/walk
  /// interval and the descent would cross the mount. What this value does is
  /// detect exactly that — a live root frame that differs from it means the core
  /// issued the request for a world it has since left, and the request is refused
  /// rather than executed against a frame the core no longer holds.
  pub(crate) frame: ScopeFrame,
  /// The scope's frame EPOCH at park time — the counter the core bumps wherever it
  /// installs a descent frame, so "the frame moved" is a statement no mount-id
  /// comparison across time can fake.
  ///
  /// The executor never reads it. It exists because this request may be COLLAPSED
  /// into a whole-root recovery rather than walked (the mailbox's backlog cap, and
  /// the reader's own blind/superseded rung), and the reply that discharges it must
  /// be stamped with the epoch of the newest obligation it folds — which is this
  /// one whenever this request's ticket becomes the cutoff. See
  /// [`RootRecovery::epoch`].
  pub(crate) epoch: u64,
}

/// One WHOLE-ROOT recovery request: the cutoff it will discharge, and the scope
/// frame epoch it was issued at.
///
/// The two travel together because the reply must carry both back — the ticket so
/// the core knows which parked round trips are discharged, the epoch so it can
/// tell whether the generation it is about to install was walked in the world the
/// core still holds ([`RootRecovery::epoch`]).
///
/// Folding two of these keeps the one with the HIGHER ticket, epoch and all: a
/// recovery discharges a contiguous prefix of the scope's tickets, so the maximum
/// is the whole obligation, and the newest request's epoch is the tightest
/// statement available about the world the walk it authorizes will run in.
#[cfg_attr(not(any(all(target_os = "linux", not(miri)), test)), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RecoveryRequest {
  /// Every parked admission ticket at or below this one is discharged by the
  /// recovery this opens.
  pub(crate) ticket: AdmitTicket,
  /// The issuing scope's [frame epoch](AdmitRequest::epoch) when this was sent.
  pub(crate) epoch: u64,
}

/// What one [`AdmitRequest`] resolved to.
///
/// Every variant RETIRES the parked cover — the round trip has exactly one
/// answer and the core must never be left holding a cover no reply will
/// release. They differ in what the core still owes.
///
/// # There is no "the loss barrier already covered it" variant
///
/// There was one, and it was half of a silent-blindness hole. The reader's
/// ladder answered `Covered` once it had reseeded the whole map and raised an
/// `Overflow`, and the core then RETIRED the parked record and emitted nothing —
/// three separate queue messages (the whole-root generation, the loss, the
/// reply) any one of which could be dropped independently. Losing the generation
/// left the still-live boundaries the reseed re-declined unrecorded while the
/// reply had already discarded the records the verdict took, so no later
/// departure there was derivable at all.
///
/// The whole-root recovery is now ONE message
/// ([`RootRecovery`]) carrying all three facts, and it is
/// non-droppable by construction: a report that cannot claim its permit kills
/// the source instead. So the ladder answers no ticket individually — the
/// recovery's own cutoff retires every ticket at or below it.
//
// Only the fanotify reader mints the two walk verdicts (it is the one backend
// with an admission map); `Unreachable` is the driver's, on every platform. The
// core matches all three everywhere, so cfg-gating the variants would fracture
// that one body.
#[cfg_attr(not(any(all(target_os = "linux", not(miri)), test)), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmitOutcome {
  /// The revealed ground is in the admission map (or there was nothing to admit
  /// — the location vanished after the unmount, or the caller excludes it). The
  /// core emits the parked cover NOW: admission completed first, so a mutation
  /// landing between the consumer's covering re-read and the next event admits
  /// rather than dropping on an unknown handle.
  Admitted,
  /// The location is STILL covered: either the refresh raced a mount the walk
  /// then found live, or a remount re-covered it between the two, or what the
  /// departed mount REVEALED is itself a boundary. No walk ran and nothing was
  /// admitted. The core lapses to the REPLACED handling — cover, and re-record the
  /// boundary in place — because a boundary that is still there must stay recorded
  /// or its eventual departure is underivable.
  ///
  /// # It carries WHAT the walk found, and the whole convergence rests on that
  ///
  /// The refusal fires on [`ScopeFrame::crossed_by`], which is two independent
  /// fences: a different device OR a different mount id. So "still covered" does
  /// not mean "the same thing is still there" — a btrfs subvolume answers it
  /// exactly as a live mount does, on the device leg alone, while carrying the
  /// ROOT's own mount id and having no mountinfo row ever.
  ///
  /// That is the shape a real mount OVER a subvolume leaves behind when it
  /// departs, and re-recording the departed mount's own row-confirmed record for
  /// it never converges: every later authoritative refresh finds that row absent,
  /// condemns it again, parks another admission, and gets the same answer — one
  /// cover and one round trip per tick, forever. The identity read off the fd the
  /// walk actually pinned is what lets the core re-record the boundary that is
  /// THERE instead of the one that left.
  StillCovered {
    /// The device of the object standing at the location, from the walk's own
    /// `fstat` of the fd it opened — `None` only where no walk could read one.
    dev: Option<u64>,
    /// That object's mount id, read from the same fd (`statx(STATX_MNT_ID)`, or
    /// the fd's `/proc/self/fdinfo` line below 5.8), or `None` where the host
    /// answers none.
    mnt_id: Option<u64>,
  },
  /// The request could not be handed to a source at all — no live stream for the
  /// scope, or a reader thread that has already exited. Nothing was admitted and
  /// nothing will be. The core emits the parked cover on the refresh's verdict
  /// alone, exactly as a backend with no admission map does.
  Unreachable,
}

/// ONE whole-root recovery, whole: the generation a complete reseed walk
/// produced, the loss it implies, and the ticket cutoff it discharges — all
/// three in a single message that cannot be split.
///
/// # Why the three facts may not travel separately
///
/// They were three messages, and each was independently droppable. The
/// sequence that made that fatal: a mass unmount collapses into a whole-map
/// reseed; the reseed's `Boundaries` report cannot claim a permit and is dropped
/// for an `Overflow`; the replies still answer every parked ticket, so the core
/// discards every record its departure verdict took. The boundaries the reseed
/// re-declined — the mounts that were STILL THERE — are now recorded nowhere,
/// so their later departure is derived by nothing, their revealed ground is
/// never admitted, and every event under it is rejected as outside the map with
/// no loss signal at all. A positional cover cannot substitute for evidence a
/// LATER departure needs.
///
/// So the recovery is atomic. Either the whole message lands — declines
/// recorded, tickets retired, root covered, in that order, on the source's one
/// ordered queue — or the source dies with a terminal `Fatal`. A dead source is
/// loud; a blind one is not.
///
/// It is also what bounds the reply traffic. The previous shape emitted one
/// reply per collapsed ticket and the core retired each by searching its parked
/// vector, which is quadratic in the size of the very burst the collapse exists
/// to absorb. A cutoff retires the whole run in one linear pass.
#[cfg_attr(not(any(all(target_os = "linux", not(miri)), test)), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RootRecovery {
  /// Every boundary the completed whole-root walk declined — the same COMPLETE
  /// generation a [`WalkBoundaries`] with [`WalkReach::WholeRoot`] carries, and read
  /// the same way: what it did not decline is not a boundary any more, and what
  /// it did decline is re-recorded even if a departure verdict had just taken it.
  pub(crate) declined: Vec<DeclinedBoundary>,
  /// Every parked admission ticket AT OR BELOW this one is discharged by this
  /// recovery. Tickets are minted from one monotone counter and delivered in
  /// order, so a cutoff names a contiguous prefix of the scope's outstanding
  /// round trips — and a ticket the core parked after the recovery was requested
  /// sits above it and is answered on its own terms.
  pub(crate) cutoff: AdmitTicket,
  /// The [frame epoch](AdmitRequest::epoch) of the NEWEST request this recovery
  /// folded — the one whose ticket is [`cutoff`](Self::cutoff), echoed back
  /// untouched.
  ///
  /// The core applies nothing from a recovery whose epoch is not its current one.
  /// Every request folded here was posted BEFORE the walk began (a ticket minted
  /// during it lands in the follow-up instead), so an epoch that still matches
  /// means no frame moved between the newest request and now — and therefore none
  /// between the request and the walk, nor between the walk and this ingest.
  ///
  /// It is the leg [`root_mnt_id`](Self::root_mnt_id) cannot cover: mount ids are
  /// allocated lowest-free, so a root that re-mounted twice can be back on the id
  /// the core still holds while the walk ran against a mount that has since died.
  /// The epoch counts WORLDS, not ids, and counts them core-side, so no reading of
  /// an id from another moment can make it agree.
  pub(crate) epoch: u64,
  /// The ROOT MOUNT ID the reseed walk actually fenced its descent against, read
  /// from the fd it reopened — not a value the core supplied.
  ///
  /// This is the other half of the applicability check, and the half that speaks
  /// for the SOURCE: a walk is on the core's frame only if the root it walked is
  /// the root the core holds. A core that has not yet run the refresh which would
  /// adopt a re-mounted root is one whose coverage set is relative to a frame this
  /// generation is not.
  ///
  /// `None` PASSES, exactly as every unknown leg of [`ScopeFrame::crossed_by`]
  /// does: a host that answers no mount id ANYWHERE reads `None` for every one,
  /// and a check that read unknown as "different" would reject every recovery such
  /// a host could ever produce — leaving the epoch to carry the check alone, which
  /// is what it is for.
  pub(crate) root_mnt_id: Option<u64>,
}

/// One [`AdmitRequest`]'s answer, on its way back to the core over the source's
/// single ordered queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdmitReport {
  /// The round trip being answered.
  pub(crate) ticket: AdmitTicket,
  /// What it resolved to.
  pub(crate) outcome: AdmitOutcome,
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
  /// The SAME read a refresh runs, so the core's coverage set diffs the two
  /// cleanly and a seeded row carries the identity a later refresh compares
  /// against.
  pub(crate) mounts: Vec<MountRow>,
  /// SEAM 2, spawn half: the boundaries this source's own SEED WALK declined to
  /// descend. Empty on every backend whose spawn walks nothing (the descending
  /// primitives seed no map, so they decline nothing at spawn — their boundaries
  /// are observed by the core's enumerate fence instead).
  ///
  /// It rides the meta rather than the queue on purpose. `RootMeta` is the
  /// PRE-LIVE channel — everything on it was learned before the stream could
  /// enqueue its first event — and a seed walk's declines are exactly that kind
  /// of fact. Surfacing them here also means the core records them in the same
  /// step that seeds the coverage baseline from [`mounts`](Self::mounts), so a
  /// scope is never live with a half-built set, and the core never has to
  /// re-derive or guess what the walk declined.
  ///
  /// The walks that run LATER — the post-loss reseed, the moved-in subtree walk
  /// and the admission reseed — cannot use this channel (they run on the reader
  /// thread, long past spawn), so they surface their declines through the
  /// source's one ordered queue instead (`SourceMessage::Boundaries`).
  pub(crate) declined: Vec<DeclinedBoundary>,
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
}
