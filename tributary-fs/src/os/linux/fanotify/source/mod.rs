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

use std::{
  ffi::CString,
  fs, io,
  os::{
    fd::OwnedFd,
    unix::{ffi::OsStrExt, fs::MetadataExt},
  },
  path::Path,
  sync::{Arc, mpsc},
  thread::JoinHandle,
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
  /// descendants are produced.
  ///
  /// Same completeness rule and single-device boundary as [`seed_walk`]: a
  /// vanished entry is a benign race skipped, any other failure on an EXISTING
  /// in-root directory is incompleteness. Incompleteness folds to the `io::Error`
  /// the reader escalates through the reseed shape (retry once → blind → fatal),
  /// so a partially-walked moved-in subtree kills the scope rather than leaving it
  /// silently blind. Bounded by the moved subtree's directory count — the honest
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
  /// The object vanished between the parent's readdir and this step (`ENOENT`):
  /// a benign race. The parent map entry exists, so if it is recreated its own
  /// create event re-learns it; the walk skips it and proceeds.
  VanishedRace,
  /// An EXISTING in-root directory could not be read or handle-encoded (`EACCES`
  /// and every non-`ENOENT` failure): the map would be born blind to that
  /// subtree. The walk cannot complete, so fanotify is not viable for this root.
  Incomplete,
}

/// Classifies a per-entry walk failure. `ENOENT` (`NotFound`) is the only benign
/// class — a directory a prior readdir listed but that vanished before this step
/// is a race, not a coverage hole. Every other failure (permission, I/O, an
/// unexportable handle on an object that still exists) leaves an in-root subtree
/// unmapped, which fanotify's membership admission cannot tolerate.
fn classify_walk_skip(err: &io::Error) -> WalkSkip {
  if err.kind() == io::ErrorKind::NotFound {
    WalkSkip::VanishedRace
  } else {
    WalkSkip::Incomplete
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

/// Walks `root` depth-first, producing a [`SeedEntry`] per directory on the
/// root device — every one an admitted directory, each carrying its parent FID
/// so the map builds the parent-relative structure directly. A mount boundary
/// (`st_dev != root_dev`) is not descended: an sb mark never crosses it, so its
/// subtree lives on a different superblock and never delivers on this fd.
///
/// Completeness is a fanotify PRECONDITION, not a best-effort target. An admitted
/// event resolves its directory FID against this map; a directory the walk failed
/// to enter is absent, so ITS events drop as outside-root forever with no loss
/// signal — the source goes "healthy" with a blind subtree. So every skip is
/// classified ([`classify_walk_skip`]):
///
/// - A `VanishedRace` skip (`ENOENT` on an entry a prior readdir listed) is
///   benign and dropped: the parent's map entry exists, so a recreation re-learns
///   the child from its own create event.
/// - An `Incomplete` skip (any non-`ENOENT` failure on an EXISTING in-root
///   directory — permission, I/O, an unexportable handle) aborts the walk with
///   [`WalkError::Incomplete`]: the tree is not fully mappable, so fanotify is not
///   viable for this root.
/// - A failure to encode the ROOT's own handle is [`WalkError::RootGone`]: the
///   root anchor is load-bearing, but the probe already proved the root
///   exportable, so its absence is a race reported as root-unavailable.
///
/// The same walk seeds the map at spawn AND reseeds it after a loss; the reseed
/// path folds every `WalkError` into its terminal blind→fatal escalation (see
/// [`ReseedContext::walk`]), so an unreadable subtree that survives the reseed's
/// single retry kills the scope rather than leaving it silently blind.
fn seed_walk(root: &Path, fsid: [u8; 8], root_dev: u64) -> Result<Vec<SeedEntry>, WalkError> {
  // The root anchor is load-bearing: without it the map has no base to resolve
  // any path against, so its absence is a spawn/reseed failure, never an empty
  // success.
  let Some(root_fid) = handle_fid(root, fsid) else {
    return Err(WalkError::RootGone(io::Error::new(
      io::ErrorKind::Unsupported,
      "the watched root does not export a file handle",
    )));
  };
  // The root must be readable to seed anything; a root that cannot be opened is
  // a race reported as root-unavailable (the probe already read it).
  let reader = fs::read_dir(root).map_err(WalkError::RootGone)?;
  let mut seed = vec![SeedEntry::root(root_fid.clone(), root)];
  descend(
    reader,
    root.to_path_buf(),
    root_fid,
    fsid,
    root_dev,
    &mut seed,
  )?;
  Ok(seed)
}

/// Walks the descendants of a directory MOVED IN from outside the root and
/// already learned under `subtree_fid`, returning a [`SeedEntry::child`] per
/// descendant directory. The moved directory itself is not re-emitted; the
/// descent starts inside it (opening it for the first `read_dir`) and links every
/// discovered directory to its parent, so the top descendants hang off
/// `subtree_fid` directly. Same completeness rule and single-device boundary as
/// [`seed_walk`].
fn subtree_walk(
  subtree: &Path,
  subtree_fid: &Fid,
  fsid: [u8; 8],
  root_dev: u64,
) -> Result<Vec<SeedEntry>, WalkError> {
  // The moved directory was just learned, so it exists; opening it for descent
  // is the same completeness rule as any child — a vanish is a race (nothing
  // descended, an empty subtree), anything else is a blind subtree.
  let reader = match fs::read_dir(subtree) {
    Ok(reader) => reader,
    Err(err) => match classify_walk_skip(&err) {
      WalkSkip::VanishedRace => return Ok(Vec::new()),
      WalkSkip::Incomplete => return Err(WalkError::Incomplete(err)),
    },
  };
  let mut seed = Vec::new();
  descend(
    reader,
    subtree.to_path_buf(),
    subtree_fid.clone(),
    fsid,
    root_dev,
    &mut seed,
  )?;
  Ok(seed)
}

/// The shared iterative descent: reads `reader` (an already-opened directory at
/// `parent_path`, FID `parent_fid`) and every directory below it on `root_dev`,
/// pushing a [`SeedEntry::child`] per discovered directory into `seed`. Explicit
/// stacks keep the walk iterative (no recursion depth bound on a deep tree);
/// `parents` carries each open reader's directory FID so a discovered child links
/// to it. Every per-entry failure is classified — a `NotFound` vanish is a benign
/// race skipped, anything else on an existing in-root directory aborts as
/// [`WalkError::Incomplete`].
fn descend(
  reader: fs::ReadDir,
  parent_path: std::path::PathBuf,
  parent_fid: Fid,
  fsid: [u8; 8],
  root_dev: u64,
  seed: &mut Vec<SeedEntry>,
) -> Result<(), WalkError> {
  let mut pending = vec![reader];
  let mut parents = vec![(parent_path, parent_fid)];

  while let Some(reader) = pending.last_mut() {
    let (parent_path, parent_fid) = parents.last().expect("a parent per reader").clone();
    match reader.next() {
      None => {
        pending.pop();
        parents.pop();
      }
      // A readdir iteration error names an entry the directory listed but could
      // not stat: a vanished entry is a race (skip), anything else is a coverage
      // hole in an in-root directory (abort).
      Some(Err(err)) => match classify_walk_skip(&err) {
        WalkSkip::VanishedRace => continue,
        WalkSkip::Incomplete => return Err(WalkError::Incomplete(err)),
      },
      Some(Ok(entry)) => {
        // `file_type` on a `DirEntry` may re-stat (no cached type); a failure is
        // classified like any other per-entry skip.
        let file_type = match entry.file_type() {
          Ok(file_type) => file_type,
          Err(err) => match classify_walk_skip(&err) {
            WalkSkip::VanishedRace => continue,
            WalkSkip::Incomplete => return Err(WalkError::Incomplete(err)),
          },
        };
        if !file_type.is_dir() {
          continue;
        }
        let name = entry.file_name();
        let path = parent_path.join(&name);
        // Single-device descent: a directory on another device is a mount
        // point — a different superblock this mark never reports on. A stat
        // failure here is NOT a mount boundary (the old code conflated the two
        // via `unwrap_or(false)`); it is a per-entry skip, classified.
        let meta = match fs::symlink_metadata(&path) {
          Ok(meta) => meta,
          Err(err) => match classify_walk_skip(&err) {
            WalkSkip::VanishedRace => continue,
            WalkSkip::Incomplete => return Err(WalkError::Incomplete(err)),
          },
        };
        if meta.dev() != root_dev {
          continue;
        }
        // The directory exists on the root device (just stat'd), so a failure to
        // encode its handle leaves it un-admittable: an in-root blind subtree.
        // `encode_handle` loses the errno, so a re-stat disambiguates a genuine
        // vanish (race, skip) from an existing-but-unexportable dir (incomplete).
        let Some(fid) = handle_fid(&path, fsid) else {
          if fs::symlink_metadata(&path).is_err() {
            continue;
          }
          return Err(WalkError::Incomplete(io::Error::new(
            io::ErrorKind::Unsupported,
            "an in-root directory does not export a file handle",
          )));
        };
        seed.push(SeedEntry::child(fid.clone(), parent_fid.clone(), name));
        // The child is admitted; failing to open it for descent hides ITS
        // children, so the same completeness rule applies — a vanish is a race,
        // anything else aborts.
        match fs::read_dir(&path) {
          Ok(reader) => {
            pending.push(reader);
            parents.push((path, fid));
          }
          Err(err) => match classify_walk_skip(&err) {
            WalkSkip::VanishedRace => continue,
            WalkSkip::Incomplete => return Err(WalkError::Incomplete(err)),
          },
        }
      }
    }
  }
  Ok(())
}

/// Reads `path`'s file handle via the shared dynamically-sized
/// [`encode_handle`](super::encode_handle) and pairs it with the superblock
/// `fsid` into a [`Fid`] whose byte-form matches the kernel's event FIDs exactly
/// (`handle` = type word + opaque bytes). `None` when the filesystem cannot
/// encode a handle for this object — including a handle too large for even the
/// grown buffer, which `encode_handle` resolves by retrying at the
/// kernel-reported size rather than failing on the fixed `MAX_HANDLE_SZ`.
fn handle_fid(path: &Path, fsid: [u8; 8]) -> Option<Fid> {
  super::encode_handle(path).map(|handle| Fid::new(fsid, handle))
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
