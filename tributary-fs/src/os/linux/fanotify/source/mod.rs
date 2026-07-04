//! The fanotify Source: the superblock mark, its reader thread, and the spawn
//! barrier. A `FAN_MARK_FILESYSTEM` mark is kernel-recursive — one mark covers
//! the whole root, so unlike inotify there is NO per-directory arming; the map
//! is seeded once at spawn and self-maintains from create events thereafter.
//!
//! The mount seed is trivial: an sb mark never crosses a mount boundary (the
//! kernel scopes it to the superblock the marked path lives on), so a mount
//! under the root simply never delivers events on this fd — its subtree is a
//! different superblock. The seed still installs (born-closed, refreshed
//! post-live) so the identity/device model the KR core shares stays honest.
//!
//! # Objects, not paths: the scope-fence invariant
//!
//! The mark covers the whole superblock, so the FID map is the ONLY thing that
//! keeps an out-of-root directory's events from delivering as in-root: a foreign
//! directory handle that seeds into the admission map admits every later event
//! under that outside subtree forever, with no loss signal — an over-admission
//! breach. The map is therefore kept honest by a hard rule: POST-LIVE, the walk
//! never trusts a reconstructed pathname. Every directory whose handle enters the
//! map is first PINNED as an fd — opened `O_NOFOLLOW` (a swapped-in symlink fails
//! rather than redirecting) and fstat-verified on the root device — and its
//! handle is encoded from that pinned fd (`name_to_handle_at(fd, "",
//! AT_EMPTY_PATH)`), never from a name a same-superblock swap could retarget
//! after a `readdir` listed it. The descent reads each directory's children from
//! its pinned fd and opens each child relative to it (`openat(parent_fd, name,
//! O_NOFOLLOW)`), so a listed entry swapped for a symlink to an outside-root
//! directory can never be descended or handle-encoded — the open fails, the entry
//! is skipped, and no foreign FID is admitted. The walk-root open uses `openat2`
//! with `RESOLVE_NO_SYMLINKS` (kernel floor argued on [`open_walk_dir`]).

use std::{
  ffi::CString,
  fs, io,
  os::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    unix::{ffi::OsStrExt, fs::MetadataExt},
  },
  path::Path,
  sync::{Arc, mpsc},
  thread::JoinHandle,
};

use rustix::{
  fs::{Dir, Mode, OFlags, ResolveFlags, fstat, openat, openat2},
  io::Errno,
};

use super::{
  super::{
    super::{RootIdentity, RootMeta, SourceConfig, SourceError, transport},
    mounts_under,
    wake::WakeState,
  },
  fid::Fid,
  map::{FidMap, SeedEntry},
  reader::{self, Control, ReaderShared},
};
use crate::os::MAX_EXCLUSIONS;

/// The `st_mode` type-bits mask (`S_IFMT`) and the directory type (`S_IFDIR`):
/// `st_mode & S_IFMT == S_IFDIR` is the directory confirmation the pinned-fd
/// `fstat` reads, making a `readdir` `d_type` advisory only.
const S_IFMT: u32 = libc::S_IFMT;
const S_IFDIR: u32 = libc::S_IFDIR;

/// The open flags for a directory pinned during the walk: read-only so the fd
/// can `readdir` (an `O_PATH` fd cannot), `O_DIRECTORY` so a non-directory fails
/// fast, `O_NOFOLLOW` so a symlink swapped in for a listed name fails rather than
/// redirecting outside the root, and `O_CLOEXEC` so a walk fd never leaks across
/// an exec.
const WALK_DIR_FLAGS: OFlags = OFlags::RDONLY
  .union(OFlags::DIRECTORY)
  .union(OFlags::NOFOLLOW)
  .union(OFlags::CLOEXEC);

/// The outcome of a fanotify spawn attempt. Separated from a plain `Result` so
/// the dispatcher can tell a fanotify VIABILITY failure (the tree is not fully
/// walkable — fall back under `Backend::Auto`, typed error under forced
/// `Fanotify`) from a genuine error that both selections propagate.
pub(crate) enum FanotifySpawn {
  /// The source started: its handle, receiver, and root metadata.
  Started(SourceHandle, super::super::super::EventReceiver, RootMeta),
  /// A genuine spawn failure (root vanished, memory/thread exhaustion, …) — both
  /// `Auto` and forced `Fanotify` surface it unchanged.
  Error(SourceError),
  /// fanotify is not viable for this root: the seed walk found an existing in-root
  /// directory it could not map (design §5 `Walk` stage). `config` is handed back
  /// so `Backend::Auto` can fall back to inotify; forced `Fanotify` turns this
  /// into [`SourceError::BackendProbeFailed`] with [`ProbeStage::Walk`].
  NotViable(SourceConfig),
}

/// The internal spawn outcome, mapped to [`FanotifySpawn`] at the boundary. A
/// `SourceError` flows in through `?` unchanged; only the walk's viability miss
/// carries the config back for the dispatcher to fall back on.
enum SpawnFailure {
  Error(SourceError),
  NotViable(SourceConfig),
}

impl From<SourceError> for SpawnFailure {
  fn from(err: SourceError) -> Self {
    Self::Error(err)
  }
}

/// The spawn entry point of the fanotify backend.
pub(crate) struct Source;

impl Source {
  /// Seeds the FID map by walking the root and starts the reader thread, REUSING
  /// the already-created, already-`FAN_MARK_FILESYSTEM`-marked `fd` the
  /// `Backend::Auto` probe (design §5) handed over — the mark is never installed
  /// twice.
  ///
  /// The probe already ran the precondition rows (`fanotify_init`,
  /// `fanotify_mark`, `name_to_handle_at`) on this canonical root, so the
  /// remaining barrier work mirrors the inotify sibling (and the macOS bracket):
  /// capture the root identity and mount seed, seed the map, then re-stat once
  /// the reader is live — a root replaced across the gap is torn down and
  /// rejected, never committed. `canonical` and `fd` are the probe's outputs;
  /// this never re-canonicalizes or re-marks.
  ///
  /// The seed walk is the last fanotify precondition: a tree with an existing
  /// in-root directory it cannot map returns [`FanotifySpawn::NotViable`] (design
  /// §5 `Walk` stage) rather than a live-but-blind source — the caller falls back
  /// to inotify (`Auto`) or surfaces a typed error (forced `Fanotify`).
  pub(crate) fn spawn(
    config: SourceConfig,
    canonical: std::path::PathBuf,
    fd: OwnedFd,
  ) -> FanotifySpawn {
    match Self::try_spawn(config, canonical, fd) {
      Ok((handle, rx, meta)) => FanotifySpawn::Started(handle, rx, meta),
      Err(SpawnFailure::Error(err)) => FanotifySpawn::Error(err),
      Err(SpawnFailure::NotViable(config)) => FanotifySpawn::NotViable(config),
    }
  }

  fn try_spawn(
    config: SourceConfig,
    canonical: std::path::PathBuf,
    fd: OwnedFd,
  ) -> Result<(SourceHandle, super::super::super::EventReceiver, RootMeta), SpawnFailure> {
    if config.exclusions.len() > MAX_EXCLUSIONS {
      return Err(SpawnFailure::Error(SourceError::TooManyExclusions {
        supplied: config.exclusions.len(),
      }));
    }

    // The dispatcher's shared locality gate (design §5 row 1) already refused a
    // remote/virtual root, and the probe's FILESYSTEM mark proved the fs is
    // handle- and superblock-mark-capable; this statfs only reads the `f_fsid`
    // the seed FIDs must match byte-for-byte.
    let fsid = superblock_fsid(&canonical).map_err(SpawnFailure::Error)?;

    let meta = fs::metadata(&canonical).map_err(|source| {
      SpawnFailure::Error(SourceError::RootUnavailable {
        root: canonical.clone(),
        source,
      })
    })?;
    if !meta.is_dir() {
      return Err(SpawnFailure::Error(SourceError::NotADirectory {
        root: canonical,
      }));
    }
    let root_dev = meta.dev();
    let identity = RootIdentity::new(meta.dev(), meta.ino());
    let mounts = mounts_under(&canonical).unwrap_or_default();

    // Seed the map by walking the root: every directory's FID (built from the
    // superblock fsid + its file handle) admits its own later events. The walk is
    // a fanotify PRECONDITION — an existing in-root directory it cannot map is a
    // viability failure (fall back / typed error), NOT a live-but-blind source —
    // while a vanished root is a benign race reported as root-unavailable. The
    // same walk inputs ride into the reader as the reseed context: a loss rebuilds
    // the map from a fresh walk, and there an unmappable tree escalates to Fatal.
    let reseed = ReseedContext {
      root: canonical.clone(),
      fsid,
      root_dev,
    };
    let mut map = FidMap::new();
    let seed = reseed.walk_typed().map_err(|err| match err {
      // The tree is not fully walkable: fanotify is not viable. Hand `config`
      // back so the dispatcher can fall back (Auto) or type the error (forced).
      WalkError::Incomplete(_) => SpawnFailure::NotViable(config.clone()),
      WalkError::RootGone(source) => SpawnFailure::Error(SourceError::RootUnavailable {
        root: canonical.clone(),
        source,
      }),
    })?;
    map.seed(seed);

    let (queue_tx, queue_rx) = async_channel::unbounded();
    let shared = Arc::new(ReaderShared {
      queue: queue_tx,
      transport: transport::TransportState::new(config.channel_capacity.get()),
    });

    let wake = WakeState::new()?;
    let (control_tx, control_rx) = mpsc::channel();
    let thread = reader::start(
      fd,
      Arc::clone(&wake),
      control_rx,
      map,
      reseed,
      Arc::clone(&shared),
    )?;

    let handle = SourceHandle {
      control: control_tx,
      wake,
      thread: Some(thread),
    };

    // The post-live half of the identity bracket: the mark is already live, so
    // the re-stat proves the object survived the barrier→reader gap and the
    // registry identity names the same object the stream reports on.
    let live = match fs::metadata(&canonical) {
      Ok(live) => live,
      Err(source) => {
        handle.shutdown();
        return Err(SpawnFailure::Error(SourceError::RootUnavailable {
          root: canonical,
          source,
        }));
      }
    };
    if !live.is_dir() {
      handle.shutdown();
      return Err(SpawnFailure::Error(SourceError::NotADirectory {
        root: canonical,
      }));
    }
    if RootIdentity::new(live.dev(), live.ino()) != identity {
      handle.shutdown();
      return Err(SpawnFailure::Error(SourceError::RootReplaced {
        root: canonical,
      }));
    }
    let mut ancestors = Vec::new();
    for ancestor in canonical.ancestors().skip(1) {
      match fs::metadata(ancestor) {
        Ok(meta) => ancestors.push(RootIdentity::new(meta.dev(), meta.ino())),
        Err(source) => {
          handle.shutdown();
          return Err(SpawnFailure::Error(SourceError::RootUnavailable {
            root: ancestor.to_path_buf(),
            source,
          }));
        }
      }
    }

    let meta = RootMeta {
      root: canonical,
      root_dev,
      mounts,
      identity,
      ancestors,
      backend: super::super::super::BackendKind::Fanotify,
    };
    Ok((handle, queue_rx, meta))
  }
}

/// Reads `path`'s superblock `f_fsid` bytes — the event-FID scope, laid out so
/// seed FIDs match event FIDs byte-for-byte. The locality `f_type` refusal is
/// not repeated here: the dispatcher runs it once, before backend selection
/// (design §5 row 1), so a remote/virtual root never reaches this spawn.
///
/// Stays on libc `statfs`: rustix's `StatFs` keeps `f_fsid` behind a private
/// field with no accessor, so the FID-seeding fsid — like the sibling
/// `name_to_handle_at` handle read — cannot be sourced through it. This whole
/// FID-seed path is the libc side of the two-style boundary (see the module
/// docs on `os::linux`).
fn superblock_fsid(path: &Path) -> Result<[u8; 8], SourceError> {
  let cpath = cstring(path)?;
  let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
  // SAFETY: cpath is a valid NUL-terminated path and buf is a zeroed statfs
  // the call fully initializes on success.
  let rc = unsafe { libc::statfs(cpath.as_ptr(), &mut buf) };
  if rc != 0 {
    return Err(SourceError::RootUnavailable {
      root: path.to_path_buf(),
      source: io::Error::last_os_error(),
    });
  }
  Ok(fsid_bytes(&buf.f_fsid))
}

/// Copies a `statfs.f_fsid` (an 8-byte `__kernel_fsid_t`) to a byte array —
/// the kernel embeds the identical id in every event's FID record, so the
/// bytes must be taken verbatim (the field's inner array is private on glibc,
/// hence the raw copy).
fn fsid_bytes(fsid: &libc::fsid_t) -> [u8; 8] {
  const _: () = assert!(std::mem::size_of::<libc::fsid_t>() == 8);
  let mut out = [0u8; 8];
  // SAFETY: fsid is a live 8-byte value; the read stays within its size and
  // copies to an equally-sized array with no aliasing.
  unsafe {
    std::ptr::copy_nonoverlapping(
      (fsid as *const libc::fsid_t).cast::<u8>(),
      out.as_mut_ptr(),
      8,
    );
  }
  out
}

/// The inputs the seeding walk needs, carried into the reader so a loss can
/// rebuild the map from a fresh walk. The reader owns one of these and reruns
/// [`walk`](Self::walk) on every `FAN_Q_OVERFLOW` / lossy decode.
pub(crate) struct ReseedContext {
  /// The canonical watched root — the walk's starting point and root anchor.
  root: std::path::PathBuf,
  /// The superblock fsid stamped into every seed FID (kept only so seed FIDs
  /// are byte-identical to a spawn seed; admission never compares it).
  fsid: [u8; 8],
  /// The root device — the single-device descent boundary (a sub-mount lives on
  /// a different superblock this mark never reports on).
  root_dev: u64,
}

impl ReseedContext {
  /// Walks the root and returns its parent-linked directory inventory. Bounded
  /// by the directory count under the root; overflow is rare, so paying a full
  /// walk to restore the map's sight is the honest cost of never going
  /// permanently blind after a covered loss.
  ///
  /// Any [`WalkError`] — a vanished root, an unreadable subtree — folds into the
  /// `io::Error` the reseed path escalates: `reseed_map` retries once, then a
  /// second failure is `ReseedOutcome::Blind` → terminal `Fatal`. The
  /// completeness rule is thus identical at spawn and reseed; only the spawn path
  /// gets to distinguish "not viable, fall back" from "genuinely gone".
  pub(crate) fn walk(&self) -> io::Result<Vec<SeedEntry>> {
    seed_walk(&self.root, self.fsid, self.root_dev).map_err(WalkError::into_io)
  }

  /// The spawn-time walk, keeping the [`WalkError`] class so the dispatcher can
  /// tell an unwalkable tree (fanotify not viable → fall back / typed error) from
  /// a vanished root (root-unavailable). Only the pre-live spawn calls this; the
  /// live reseed uses the `io::Error`-folding [`walk`](Self::walk).
  fn walk_typed(&self) -> Result<Vec<SeedEntry>, WalkError> {
    seed_walk(&self.root, self.fsid, self.root_dev)
  }

  /// Walks the subtree rooted at `subtree` (a directory MOVED IN from outside the
  /// root, already learned under `subtree_fid`) and returns a [`SeedEntry::child`]
  /// for every descendant directory, each linked to its parent — the moved
  /// directory's pre-existing contents the seed walk never saw. The moved
  /// directory itself is NOT re-emitted (the caller already learned it); only its
  /// descendants are produced. `subtree` is the moved dir's CURRENT path, resolved
  /// through the map by the reader (an intervening in-root rename may have
  /// re-parented it since admission).
  ///
  /// Same completeness rule and single-device boundary as [`seed_walk`], but with
  /// NO benign vanished-race at the top: the moved dir is still in-map and pending
  /// its walk, so a `NotFound` opening it is a coverage hole (no rename-out ran),
  /// not an empty subtree — every failure is [`WalkError::Incomplete`], folding to
  /// the `io::Error` the reader escalates through the reseed shape (retry once →
  /// blind → fatal). Bounded by the moved subtree's directory count — the honest
  /// cost of admitting a foreign populated directory.
  pub(crate) fn walk_subtree(
    &self,
    subtree: &Path,
    subtree_fid: &Fid,
  ) -> io::Result<Vec<SeedEntry>> {
    subtree_walk(subtree, subtree_fid, self.fsid, self.root_dev).map_err(WalkError::into_io)
  }
}

/// How a per-entry walk failure is classified. fanotify's admission model needs
/// a COMPLETE directory map (an admitted event resolves its directory FID against
/// the map; a directory absent from the map drops its events as outside-root with
/// NO loss signal), so the walk cannot silently skip an existing in-root
/// directory. The two classes are handled oppositely, so they are named
/// explicitly rather than folded into a bare skip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalkSkip {
  /// The object is no longer a plain in-root directory the walk can pin: it
  /// vanished (`ENOENT`), or the name a prior `readdir` listed now resolves to a
  /// symlink or non-directory (`ELOOP`/`ENOTDIR` from the `O_NOFOLLOW |
  /// O_DIRECTORY` open). All three mean the object CHANGED SHAPE between the
  /// listing and this step — a benign race, not a coverage hole: the parent map
  /// entry exists, so any in-root object that later takes that name arrives
  /// through its own create/rename event and is learned then. Skip and proceed.
  VanishedRace,
  /// An EXISTING in-root directory could not be pinned, read, or handle-encoded
  /// (`EACCES`, I/O, and every failure that is NOT a vanish/shape-change): the
  /// map would be born blind to that subtree. The walk cannot complete, so
  /// fanotify is not viable for this root.
  Incomplete,
}

/// Classifies a per-entry walk failure from the raw [`Errno`] the pinning open,
/// fstat, or handle-encode returned. The vanish/shape-change set — `ENOENT`
/// (gone), `ELOOP` (the `O_NOFOLLOW` open refused a now-symlink final
/// component), and `ENOTDIR` (the `O_DIRECTORY` open refused a now-non-directory)
/// — is the ONLY benign class: a name a prior `readdir` listed as a directory
/// that no longer opens as one is a race between the listing and this step, so
/// the entry is skipped rather than seeded. Crucially, `ELOOP`/`ENOTDIR` is
/// exactly what a same-superblock swap of a listed directory for a symlink (even
/// one pointing OUTSIDE the root) produces, and treating it as a race is what
/// keeps that foreign target from ever being descended or handle-encoded (the
/// scope-fence invariant on the module docs). Every other failure (permission,
/// I/O, an unexportable handle on an object that still exists) leaves an in-root
/// subtree unmapped, which fanotify's membership admission cannot tolerate.
fn classify_walk_skip(err: Errno) -> WalkSkip {
  match err {
    Errno::NOENT | Errno::LOOP | Errno::NOTDIR => WalkSkip::VanishedRace,
    _ => WalkSkip::Incomplete,
  }
}

/// Why the seed walk stopped, when it did not complete. The reseed path folds
/// both into the terminal blind→fatal escalation (`reseed_map` retries once, then
/// `ReseedOutcome::Blind` → `Fatal`); the spawn path distinguishes them so a race
/// is a benign root-unavailable retry while an unwalkable tree is a fanotify
/// viability failure (`Backend::Auto` → inotify, forced `Fanotify` → typed).
#[derive(Debug)]
pub(crate) enum WalkError {
  /// The ROOT itself vanished or cannot export a handle. Without the root anchor
  /// the map admits nothing (every path resolves against it), so this is a hard
  /// spawn failure — but a race the caller reports as root-unavailable, not a
  /// fanotify-unviable verdict (the probe already proved the root exportable).
  RootGone(io::Error),
  /// An EXISTING in-root descendant could not be walked or handle-encoded, so the
  /// tree is not fully mappable: fanotify is not viable for this root.
  Incomplete(io::Error),
}

impl WalkError {
  /// The underlying failure, so the reseed path can escalate it unchanged.
  fn into_io(self) -> io::Error {
    match self {
      Self::RootGone(err) | Self::Incomplete(err) => err,
    }
  }
}

/// Opens the walk-root path `root` as a pinned directory fd for the descent —
/// the ONLY entry point that starts from a path rather than an inherited parent
/// fd, so it carries the whole no-escape burden. Uses `openat2` with
/// `RESOLVE_NO_SYMLINKS`, which forbids traversing ANY symlink in `root` (even a
/// mid-path ancestor swapped in after canonicalization): a swap cannot redirect
/// the open, it fails instead. Every subsequent directory in the descent is
/// opened `openat(parent_fd, single_component, O_NOFOLLOW)` — a single non-`..`
/// name under a held fd cannot escape and `O_NOFOLLOW` blocks a symlink final
/// component — so `RESOLVE_NO_SYMLINKS` on this one path open plus the per-child
/// opens give kernel-enforced no-escape end to end.
///
/// `RESOLVE_NO_SYMLINKS` rather than `RESOLVE_BENEATH`: `root` and the reader's
/// resolved subtree path are ABSOLUTE (canonical / map-resolved), and `BENEATH`
/// rejects an absolute path — it fences a RELATIVE resolution beneath a dirfd,
/// which the per-child `openat`s already are. `NO_SYMLINKS` is the primitive that
/// fences an absolute open.
///
/// # Kernel floor
///
/// `openat2` landed in Linux 5.6; the fanotify-FILESYSTEM backend requires 5.17
/// (design §4, the `FAN_REPORT_TARGET_FID` / `FAN_RENAME` floor), so on every
/// kernel that reaches this walk `openat2` is unconditionally present — no
/// classified fallback is needed. A pre-5.6 kernel could never have started this
/// source.
fn open_walk_dir(root: &Path) -> Result<OwnedFd, Errno> {
  openat2(
    rustix::fs::CWD,
    root,
    WALK_DIR_FLAGS,
    Mode::empty(),
    ResolveFlags::NO_SYMLINKS,
  )
}

/// Walks `root` depth-first, producing a [`SeedEntry`] per directory on the
/// root device — every one an admitted directory, each carrying its parent FID
/// so the map builds the parent-relative structure directly. A mount boundary
/// (`st_dev != root_dev`) is not descended: an sb mark never crosses it, so its
/// subtree lives on a different superblock and never delivers on this fd.
///
/// The root is opened as a PINNED fd ([`open_walk_dir`]) and its handle is
/// encoded from that fd, so nothing about the seed depends on a re-resolvable
/// name — the objects-not-paths invariant (module docs) holds from the very first
/// object.
///
/// Completeness is a fanotify PRECONDITION, not a best-effort target. An admitted
/// event resolves its directory FID against this map; a directory the walk failed
/// to enter is absent, so ITS events drop as outside-root forever with no loss
/// signal — the source goes "healthy" with a blind subtree. So every skip is
/// classified ([`classify_walk_skip`]):
///
/// - A `VanishedRace` skip (`ENOENT`/`ELOOP`/`ENOTDIR` on an entry a prior readdir
///   listed as a directory) is benign and dropped: the object vanished or changed
///   shape, and the parent's map entry exists, so any in-root object later taking
///   that name is learned from its own create/rename event.
/// - An `Incomplete` skip (any other failure on an EXISTING in-root directory —
///   permission, I/O, an unexportable handle) aborts the walk with
///   [`WalkError::Incomplete`]: the tree is not fully mappable, so fanotify is not
///   viable for this root.
/// - A failure to OPEN or handle-encode the ROOT itself is [`WalkError::RootGone`]:
///   the root anchor is load-bearing, but the probe already proved the root
///   openable and exportable, so its absence is a race reported as root-unavailable.
///
/// The same walk seeds the map at spawn AND reseeds it after a loss; the reseed
/// path folds every `WalkError` into its terminal blind→fatal escalation (see
/// [`ReseedContext::walk`]), so an unreadable subtree that survives the reseed's
/// single retry kills the scope rather than leaving it silently blind.
fn seed_walk(root: &Path, fsid: [u8; 8], root_dev: u64) -> Result<Vec<SeedEntry>, WalkError> {
  // Pin the root as an fd (no-symlink resolution) BEFORE anything else: its
  // handle and its children both come from this fd, never a re-resolved name. A
  // failure to open it is a race reported as root-unavailable (the probe already
  // opened it).
  let root_fd = open_walk_dir(root).map_err(|err| WalkError::RootGone(err.into()))?;
  // The root anchor is load-bearing: without its handle the map has no base to
  // resolve any path against, so its absence is a spawn/reseed failure, never an
  // empty success. Encoded from the pinned fd, so it names exactly the object we
  // opened.
  let Some(root_fid) = handle_fid_at(root_fd.as_fd(), fsid) else {
    return Err(WalkError::RootGone(io::Error::new(
      io::ErrorKind::Unsupported,
      "the watched root does not export a file handle",
    )));
  };
  let mut seed = vec![SeedEntry::root(root_fid.clone(), root)];
  descend(root_fd, root_fid, fsid, root_dev, &mut seed)?;
  Ok(seed)
}

/// Walks the descendants of a directory MOVED IN from outside the root and
/// already learned under `subtree_fid`, returning a [`SeedEntry::child`] per
/// descendant directory. The moved directory itself is not re-emitted; the
/// descent starts INSIDE it (from the pinned fd this opens) and links every
/// discovered directory to its parent, so the top descendants hang off
/// `subtree_fid` directly. Same completeness rule, pinned-object discipline, and
/// single-device boundary as [`seed_walk`].
///
/// `subtree` is the moved directory's CURRENT path, resolved through the map by
/// the reader at execution time — the node is still in-map and `pending_walk`, so
/// a `NotFound`/`ELOOP`/`ENOTDIR` opening it is NOT a benign empty walk but a
/// coverage hole: no rename-out was processed (the single-threaded reader would
/// have forgotten it first), so the directory should be present and openable as a
/// directory. It is therefore all classified `Incomplete`, folding to the
/// reader's retry-once-then-blind→fatal escalation — rather than swallowed as an
/// empty subtree that would leave the moved dir's descendants blind forever.
fn subtree_walk(
  subtree: &Path,
  subtree_fid: &Fid,
  fsid: [u8; 8],
  root_dev: u64,
) -> Result<Vec<SeedEntry>, WalkError> {
  // The moved directory is still in-map and pending its walk, so pinning it must
  // succeed: any failure (a vanish/shape-change included) is a coverage hole, not
  // a race — Incomplete, escalated through the reader's retry-then-fatal. Pinned
  // as an fd so the descent never re-resolves the moved dir's name (which an
  // in-root rename in the same batch could have made point elsewhere).
  let subtree_fd = open_walk_dir(subtree).map_err(|err| WalkError::Incomplete(err.into()))?;
  let mut seed = Vec::new();
  descend(subtree_fd, subtree_fid.clone(), fsid, root_dev, &mut seed)?;
  Ok(seed)
}

/// One open directory in the descent: the pinned fd (the descent reads its
/// children from it and opens each child relative to it) and its FID (a
/// discovered child links to it). Holding the fd through its children's
/// processing is what keeps a listed name from being re-resolved into a foreign
/// object.
struct WalkDir {
  /// The `Dir` reader over the pinned directory fd — owns the one fd for this
  /// level and yields its entries.
  reader: Dir,
  /// This directory's FID, the parent link for every child discovered here.
  fid: Fid,
}

/// The shared iterative descent: reads `root_fd` (an already-pinned, already-FID'd
/// directory) and every directory below it on `root_dev`, pushing a
/// [`SeedEntry::child`] per discovered directory into `seed`. FULLY FD-RELATIVE —
/// no path is ever reconstructed: each level holds its directory fd, children are
/// read from it, and each child is opened `openat(parent_fd, name, O_NOFOLLOW |
/// O_DIRECTORY | O_RDONLY | O_CLOEXEC)`. A same-superblock swap of a listed
/// directory for a symlink therefore fails the open (`ELOOP`/`ENOTDIR`) and is
/// skipped as a race — the foreign target is never descended and its handle never
/// seeds the map (the scope-fence invariant).
///
/// An explicit stack keeps the walk iterative (no recursion-depth bound on a deep
/// tree). fd usage is O(DEPTH) live at once — the descent stack holds one open
/// directory fd per level from the root down to the deepest currently-open branch,
/// released as each level is exhausted, never O(tree). Every per-entry failure is
/// classified: a vanish/shape-change (`ENOENT`/`ELOOP`/`ENOTDIR`) is a benign race
/// skipped, anything else on an existing in-root directory aborts as
/// [`WalkError::Incomplete`].
fn descend(
  root_fd: OwnedFd,
  root_fid: Fid,
  fsid: [u8; 8],
  root_dev: u64,
  seed: &mut Vec<SeedEntry>,
) -> Result<(), WalkError> {
  let root_reader = Dir::new(root_fd).map_err(|err| WalkError::Incomplete(err.into()))?;
  let mut stack = vec![WalkDir {
    reader: root_reader,
    fid: root_fid,
  }];

  while let Some(level) = stack.last_mut() {
    let Some(entry) = level.reader.read() else {
      // The directory is exhausted: drop its fd and pop back to its parent.
      stack.pop();
      continue;
    };
    // A readdir iteration error is an in-root directory the walk cannot finish
    // reading: a vanish/shape-change is a race (skip), anything else is a
    // coverage hole (abort).
    let entry = match entry {
      Ok(entry) => entry,
      Err(err) => match classify_walk_skip(err) {
        WalkSkip::VanishedRace => continue,
        WalkSkip::Incomplete => return Err(WalkError::Incomplete(err.into())),
      },
    };

    let name = entry.file_name();
    // `.`/`..` are yielded by the raw directory read (unlike `std::fs::read_dir`)
    // and must be dropped: `openat(parent_fd, "..")` would climb OUT of the pinned
    // subtree, and `openat(parent_fd, ".")` would re-open the parent and loop.
    if name == c"." || name == c".." {
      continue;
    }
    // `d_type` is ADVISORY: a filesystem may report `DT_UNKNOWN`, and a stale
    // cache can name a swapped object's OLD type — never trusted for admission.
    // A definitively-non-directory, non-unknown entry is skipped without an open
    // (a file/symlink/socket the walk does not descend, exactly as before); a
    // `Directory` or `Unknown` entry is verified by the authoritative pinning
    // open below, whose `fstat` on the opened fd — not `d_type` — confirms the
    // type.
    let advisory = entry.file_type();
    if advisory != rustix::fs::FileType::Directory && advisory != rustix::fs::FileType::Unknown {
      continue;
    }

    // Pin the child: open it relative to the PARENT fd with `O_NOFOLLOW |
    // O_DIRECTORY`. A vanished entry fails `ENOENT`, a name now resolving to a
    // symlink fails `ELOOP`, a name now a non-directory fails `ENOTDIR` — all
    // three the benign shape-change race. A swap for a symlink pointing outside
    // the root fails here too (`ELOOP`), so its target is never opened, stat'd, or
    // handle-encoded. Any other error (permission, I/O) on an existing in-root
    // directory is Incomplete.
    let parent_fd = level
      .reader
      .fd()
      .map_err(|err| WalkError::Incomplete(err.into()))?;
    let child_fd = match openat(parent_fd, name, WALK_DIR_FLAGS, Mode::empty()) {
      Ok(fd) => fd,
      Err(err) => match classify_walk_skip(err) {
        WalkSkip::VanishedRace => continue,
        WalkSkip::Incomplete => return Err(WalkError::Incomplete(err.into())),
      },
    };

    // `fstat` the OPENED fd — the object the walk actually pinned, immune to any
    // post-listing swap. `st_dev` is the single-device descent boundary (a
    // directory on another device is a mount point on a different superblock this
    // mark never reports on), and `st_mode` confirms it is truly a directory
    // (making `d_type` advisory only — a filesystem could report `DT_DIR` for an
    // object `O_DIRECTORY` still opened, but `fstat` is authoritative).
    let stat = match fstat(&child_fd) {
      Ok(stat) => stat,
      Err(err) => match classify_walk_skip(err) {
        WalkSkip::VanishedRace => continue,
        WalkSkip::Incomplete => return Err(WalkError::Incomplete(err.into())),
      },
    };
    // `st_dev`/`st_mode` are `u64`/`u32` on every Linux target (the 32-bit
    // `Stat` declares them so explicitly, the 64-bit `c_ulong`/`c_uint` aliases
    // resolve to the same), so the comparisons need no conversion.
    if stat.st_dev != root_dev {
      // A mount boundary: a different superblock, not descended. `O_DIRECTORY`
      // already guaranteed it is a directory, so this is purely the device fence.
      continue;
    }
    if stat.st_mode & S_IFMT != S_IFDIR {
      // Structurally impossible after an `O_DIRECTORY` open succeeded (the kernel
      // would have returned `ENOTDIR`), but the map must never admit a
      // non-directory handle, so a lying stat is skipped as a race rather than
      // seeded.
      continue;
    }

    // Encode the handle FROM THE PINNED fd (`AT_EMPTY_PATH`), never from a name a
    // swap could retarget: the directory exists on the root device (just fstat'd
    // the fd), so a failure to encode leaves it un-admittable — an in-root blind
    // subtree — which is Incomplete, not a silent skip.
    let Some(fid) = handle_fid_at(child_fd.as_fd(), fsid) else {
      return Err(WalkError::Incomplete(io::Error::new(
        io::ErrorKind::Unsupported,
        "an in-root directory does not export a file handle",
      )));
    };
    seed.push(SeedEntry::child(
      fid.clone(),
      level.fid.clone(),
      os_name(name),
    ));
    // Descend: reuse the SAME pinned fd for the child's directory read (the fd was
    // opened `O_RDONLY`, so it can `readdir`; the handle and stat already came from
    // it — one open per directory, not two). A failure to build the reader hides
    // the child's own children, so it is Incomplete like any in-root read failure.
    let reader = Dir::new(child_fd).map_err(|err| WalkError::Incomplete(err.into()))?;
    stack.push(WalkDir { reader, fid });
  }
  Ok(())
}

/// Encodes the file handle of the directory pinned by `dirfd` via the shared
/// dynamically-sized [`encode_handle_at`](super::encode_handle_at) and pairs it
/// with the superblock `fsid` into a [`Fid`] whose byte-form matches the kernel's
/// event FIDs exactly (`handle` = type word + opaque bytes). Fd-relative
/// (`AT_EMPTY_PATH`) so the handle is taken from exactly the object the walk
/// pinned — never a name a same-superblock swap could redirect after a `readdir`
/// listed it. `None` when the filesystem cannot encode a handle for this object,
/// including a handle too large for even the grown buffer (which `encode_handle_at`
/// resolves by retrying at the kernel-reported size).
fn handle_fid_at(dirfd: BorrowedFd<'_>, fsid: [u8; 8]) -> Option<Fid> {
  super::encode_handle_at(dirfd).map(|handle| Fid::new(fsid, handle))
}

/// Interprets a raw directory-entry `CStr` name as an `OsString` for a
/// [`SeedEntry`]. The bytes pass through verbatim on unix (a directory entry name
/// is opaque bytes), so the seed name matches what the kernel reports for the same
/// object in events.
fn os_name(name: &std::ffi::CStr) -> std::ffi::OsString {
  use std::os::unix::ffi::OsStrExt;
  std::ffi::OsStr::from_bytes(name.to_bytes()).to_os_string()
}

/// A NUL-terminated C string for a path, or a typed spawn error on an embedded
/// NUL.
fn cstring(path: &Path) -> Result<CString, SourceError> {
  CString::new(path.as_os_str().as_bytes()).map_err(|_| SourceError::RootUnavailable {
    root: path.to_path_buf(),
    source: io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"),
  })
}

/// A live fanotify source. Dropping it tears the reader down; prefer
/// [`shutdown`](Self::shutdown) at an orderly exit.
pub(crate) struct SourceHandle {
  control: mpsc::Sender<Control>,
  wake: Arc<WakeState>,
  thread: Option<JoinHandle<()>>,
}

impl SourceHandle {
  /// Stops the reader and closes the instance. The reader exits at its next
  /// wake, so this blocks for at most one in-flight read + decode.
  pub(crate) fn shutdown(mut self) {
    self.teardown();
  }

  fn teardown(&mut self) {
    let Some(thread) = self.thread.take() else {
      return;
    };
    let _ = self.control.send(Control::Shutdown);
    self.wake.wake();
    let _ = thread.join();
  }
}

impl Drop for SourceHandle {
  fn drop(&mut self) {
    self.teardown();
  }
}

#[cfg(test)]
mod tests;
