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
  pub(crate) fn spawn(
    config: SourceConfig,
    canonical: std::path::PathBuf,
    fd: OwnedFd,
  ) -> Result<(SourceHandle, super::super::super::EventReceiver, RootMeta), SourceError> {
    if config.exclusions.len() > MAX_EXCLUSIONS {
      return Err(SourceError::TooManyExclusions {
        supplied: config.exclusions.len(),
      });
    }

    // The probed FILESYSTEM mark already proved the filesystem is handle- and
    // superblock-mark-capable (a remote/virtual fs fails the mark probe); this
    // statfs only reads the `f_fsid` the seed FIDs must match byte-for-byte.
    let fsid = superblock_fsid(&canonical)?;

    let meta = fs::metadata(&canonical).map_err(|source| SourceError::RootUnavailable {
      root: canonical.clone(),
      source,
    })?;
    if !meta.is_dir() {
      return Err(SourceError::NotADirectory { root: canonical });
    }
    let root_dev = meta.dev();
    let identity = RootIdentity::new(meta.dev(), meta.ino());
    let mounts = mounts_under(&canonical).unwrap_or_default();

    // Seed the map by walking the root: every directory's FID (built from the
    // superblock fsid + its file handle) admits its own later events. A read
    // failure mid-walk is not fatal — the directory simply stays unseeded and a
    // later reseed re-observes it — but a root that cannot be walked at all is
    // an honest spawn failure. The same walk inputs ride into the reader as the
    // reseed context: a loss rebuilds the map from a fresh walk.
    let reseed = ReseedContext {
      root: canonical.clone(),
      fsid,
      root_dev,
    };
    let mut map = FidMap::new();
    let seed = reseed
      .walk()
      .map_err(|source| SourceError::RootUnavailable {
        root: canonical.clone(),
        source,
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
        return Err(SourceError::RootUnavailable {
          root: canonical,
          source,
        });
      }
    };
    if !live.is_dir() {
      handle.shutdown();
      return Err(SourceError::NotADirectory { root: canonical });
    }
    if RootIdentity::new(live.dev(), live.ino()) != identity {
      handle.shutdown();
      return Err(SourceError::RootReplaced { root: canonical });
    }
    let mut ancestors = Vec::new();
    for ancestor in canonical.ancestors().skip(1) {
      match fs::metadata(ancestor) {
        Ok(meta) => ancestors.push(RootIdentity::new(meta.dev(), meta.ino())),
        Err(source) => {
          handle.shutdown();
          return Err(SourceError::RootUnavailable {
            root: ancestor.to_path_buf(),
            source,
          });
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
/// seed FIDs match event FIDs byte-for-byte. The `f_type` allowlist gate the
/// inotify sibling runs is unnecessary here: the probe's FILESYSTEM mark already
/// refused any filesystem that cannot export handles (a remote/virtual fs).
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
  pub(crate) fn walk(&self) -> io::Result<Vec<SeedEntry>> {
    seed_walk(&self.root, self.fsid, self.root_dev)
  }
}

/// Walks `root` depth-first, producing a [`SeedEntry`] per directory on the
/// root device — every one an admitted directory, each carrying its parent FID
/// so the map builds the parent-relative structure directly. A mount boundary
/// (`st_dev != root_dev`) is not descended: an sb mark never crosses it, so its
/// subtree lives on a different superblock and never delivers on this fd.
///
/// Two failure tiers, deliberately distinct:
///
/// - A failure to encode the ROOT's own handle is FATAL — an `Err`. Without the
///   root anchor the map admits NOTHING (every path resolves against it), so a
///   walk that skipped the root would seed an empty map: a live source that
///   drops every event as outside-root. The probe already proved the root is
///   handle-exportable, so this is a race (the root vanished between probe and
///   walk); on a reseed it likewise escalates rather than going silently blind.
/// - A per-DESCENDANT handle-read failure is skipped (with its subtree) — a
///   reseed or the self-maintaining create stream re-observes it; a vanished dir
///   mid-walk is benign.
///
/// The same walk seeds the map at spawn AND reseeds it after a loss: both need
/// the identical parent-linked directory inventory.
fn seed_walk(root: &Path, fsid: [u8; 8], root_dev: u64) -> io::Result<Vec<SeedEntry>> {
  let mut seed = Vec::new();
  // The root anchor is load-bearing: without it the map has no base to resolve
  // any path against, so its absence is a spawn/reseed failure, never an empty
  // success.
  let Some(root_fid) = handle_fid(root, fsid) else {
    return Err(io::Error::new(
      io::ErrorKind::Unsupported,
      "the watched root does not export a file handle",
    ));
  };
  seed.push(SeedEntry::root(root_fid.clone(), root));
  // The root must be readable to seed anything; deeper read failures degrade to
  // a smaller seed, not a spawn failure. Explicit stacks keep the walk
  // iterative (no recursion depth bound on a deep tree); `parents` carries each
  // open reader's directory FID so a discovered child links to it.
  let mut pending = vec![fs::read_dir(root)?];
  let mut parents = vec![(root.to_path_buf(), root_fid)];

  while let Some(reader) = pending.last_mut() {
    let (parent_path, parent_fid) = parents.last().expect("a parent per reader").clone();
    match reader.next() {
      None => {
        pending.pop();
        parents.pop();
      }
      Some(Err(_)) => continue,
      Some(Ok(entry)) => {
        let Ok(file_type) = entry.file_type() else {
          continue;
        };
        if !file_type.is_dir() {
          continue;
        }
        let name = entry.file_name();
        let path = parent_path.join(&name);
        // Single-device descent: a directory on another device is a mount
        // point — a different superblock this mark never reports on.
        let on_root_dev = fs::symlink_metadata(&path)
          .map(|meta| meta.dev() == root_dev)
          .unwrap_or(false);
        if !on_root_dev {
          continue;
        }
        let Some(fid) = handle_fid(&path, fsid) else {
          continue;
        };
        seed.push(SeedEntry::child(fid.clone(), parent_fid.clone(), name));
        if let Ok(reader) = fs::read_dir(&path) {
          pending.push(reader);
          parents.push((path, fid));
        }
      }
    }
  }
  Ok(seed)
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
