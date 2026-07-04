//! The Linux backends: inotify (descending) and, later, fanotify-FILESYSTEM
//! (kernel-recursive), selected per root by `Backend::Auto`.
//!
//! Pure machinery (decode tables, `wd` bookkeeping, event attribution, the
//! mountinfo parser) compiles everywhere tests run, mirroring the
//! transport/fsevent precedent; the FFI Source layer (the per-root fd, its
//! reader thread, and the syscalls) is `cfg(all(target_os = "linux",
//! not(miri)))`.
//!
//! On Linux the platform seam selects this module's [`Source`]: events cross
//! the driver's queue as [`RawLinuxEvent`]s inside the unified
//! [`SourceEvent`](super::SourceEvent) payload, and the driver routes arm
//! traffic to the reader through the scope's [`ControlPort`].
//!
//! # Two FFI styles, one boundary
//!
//! The syscalls split into two families, and the split is deliberate:
//!
//! - **rustix (io-safe, owned/borrowed fds)** for everything it covers — the
//!   inotify instance and watches ([`rustix::fs::inotify`]), the `poll` and
//!   `eventfd` wakeup ([`rustix::event`]), the transient `O_PATH` anchor opens
//!   ([`rustix::fs::openat`]), and the `statfs` filesystem-type gate that refuses
//!   remote/virtual roots (reads the public `f_type`), plus the reads on the
//!   source fds ([`rustix::io::read`]). Errors surface as [`rustix::io::Errno`],
//!   mapped to the crate's [`WatchError`](tributary_proto::WatchError)/
//!   [`SourceError`] taxonomy exactly as the raw errnos were.
//! - **raw libc** for the syscalls rustix v1.1 does NOT expose: ALL of fanotify
//!   (`fanotify_init`/`fanotify_mark` — no rustix coverage), the file-handle pair
//!   (`name_to_handle_at`/`open_by_handle_at` — the FID seeding walk), AND the
//!   fanotify seed's `statfs` fsid read (rustix keeps `StatFs::f_fsid` behind a
//!   private field with no accessor, so the FID scope cannot be read through it).
//!   These keep their `unsafe` blocks and `io::Error::last_os_error` handling.
// The fanotify backend (L4) consumes the remaining reserved surface; the
// container suites exercise the parts a macOS host build cannot reach.
#![allow(dead_code)]

pub(crate) mod fanotify;
pub(crate) mod inotify;

#[cfg(all(target_os = "linux", not(miri)))]
mod probe;

#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) mod wake;

#[cfg(test)]
mod tests;

// `Path`/`PathBuf` back the mountinfo parser and `mounts_under`, both gated to
// unix-or-test; a non-unix lib target (wasm) compiles neither, so the import
// rides the same gate to stay warning-clean on the cross legs.
#[cfg(any(unix, test))]
use std::path::{Path, PathBuf};

// The spawn dispatcher pins the root as an fd and grounds every live-state
// decision on it; the fd traits and `openat2`/`fstatfs` flags ride the same
// FFI-Source gate as `Source::spawn` itself.
#[cfg(all(target_os = "linux", not(miri)))]
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

#[cfg(all(target_os = "linux", not(miri)))]
use rustix::fs::OFlags;

use tributary_proto::WatchId;

pub(crate) use fanotify::AdmittedEvent;
pub(crate) use inotify::decode::RawInotifyEvent;
use inotify::table::WdTable;

/// The decoded Linux event payload — the platform's transport `E` once the
/// seam flips.
///
/// Seam contract: resolution happens AT DECODE, single-threaded in the
/// reader that owns the backend's attribution state. inotify attributes each
/// record's `wd` through its [`WdTable`] while the table is still in lockstep
/// with the record stream, so events cross the channel already carrying every
/// Monitor watch they address ([`anchors`](Self::Inotify::anchors), one per
/// alias of the underlying inode). fanotify admits by directory-FID membership
/// against its per-root map (the superblock-firehose filter) and crosses the
/// channel already path-resolved and identity-interned. The core never sees a
/// `wd` or a raw FID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RawLinuxEvent {
  /// One decoded inotify record with its resolved anchors.
  Inotify {
    /// The Monitor watches this record addresses (aliases fan out).
    anchors: Vec<WatchId>,
    /// The decoded kernel record.
    event: RawInotifyEvent,
  },
  /// One admitted fanotify event: path-resolved against the root's FID map,
  /// with the object's identity already interned.
  Fanotify(AdmittedEvent),
}

impl RawLinuxEvent {
  /// The anchors and record, if this is an inotify event.
  pub(crate) fn as_inotify(&self) -> Option<(&[WatchId], &RawInotifyEvent)> {
    match self {
      Self::Inotify { anchors, event } => Some((anchors.as_slice(), event)),
      Self::Fanotify(_) => None,
    }
  }

  /// The admitted event, if this is a fanotify event.
  pub(crate) fn as_fanotify(&self) -> Option<&AdmittedEvent> {
    match self {
      Self::Fanotify(event) => Some(event),
      Self::Inotify { .. } => None,
    }
  }
}

/// One decoded buffer after attribution: the anchor-carrying events plus
/// whether anything was lost (an overflow sentinel, or decode loss folded in
/// by the caller).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AttributedBatch {
  pub(crate) events: Vec<RawLinuxEvent>,
  pub(crate) lost: bool,
}

/// Resolves each decoded record against the `wd` table (PURE — the reader's
/// only non-syscall step).
///
/// - An overflow sentinel (`wd == -1`) carries no attribution: it marks the
///   batch lost and is not forwarded — the ordered loss signal covers it.
/// - `IN_IGNORED` is the `wd`'s final record: it consumes the table entry
///   ([`WdTable::on_ignored`]) and forwards to the anchors that were still
///   live (a kernel-initiated teardown); a self-induced teardown whose
///   anchors already drained forwards nothing.
/// - Any other record fans out to the `wd`'s live anchors; a record on a
///   draining or unknown `wd` addresses a watch the core already dropped and
///   is skipped without loss.
pub(crate) fn attribute_events(
  decoded: Vec<RawInotifyEvent>,
  table: &mut WdTable,
) -> AttributedBatch {
  let mut events = Vec::with_capacity(decoded.len());
  let mut lost = false;
  for event in decoded {
    if event.mask.is_overflow() {
      lost = true;
      continue;
    }
    if event.mask.is_ignored() {
      let anchors = table.on_ignored(event.wd);
      if !anchors.is_empty() {
        events.push(RawLinuxEvent::Inotify { anchors, event });
      }
      continue;
    }
    let anchors = table.anchors(event.wd).to_vec();
    if anchors.is_empty() {
      continue;
    }
    events.push(RawLinuxEvent::Inotify { anchors, event });
  }
  AttributedBatch { events, lost }
}

/// Filesystem magic numbers (`statfs.f_type`) of network / virtual
/// filesystems a watch root must refuse: inotify on them reports only local
/// VFS activity (other hosts' writes are invisible), the exact silent-gap
/// class the macOS `!MNT_LOCAL` refusal exists for.
const REMOTE_FS_MAGICS: &[i64] = &[
  0x6969,      // NFS
  0x517B,      // SMB
  0xFE53_4D42, // SMB2
  0xFF53_4D42, // CIFS
  0x6573_5546, // FUSE (sshfs and friends; capability unknowable)
  0x0102_1997, // 9P (virtio shares)
  0x5346_414F, // AFS
  0x7375_7245, // CODA
  0x00C3_6400, // CEPH
  0x564C,      // NCP
];

/// Whether `f_type` names a filesystem the spawn barrier refuses.
pub(crate) const fn fs_type_is_remote(f_type: i64) -> bool {
  let mut i = 0;
  while i < REMOTE_FS_MAGICS.len() {
    if REMOTE_FS_MAGICS[i] == f_type {
      return true;
    }
    i += 1;
  }
  false
}

/// Unescapes one `/proc/self/mountinfo` field: the kernel encodes space, tab,
/// newline, and backslash as `\ooo` octal triples.
// Byte-level OsStr construction is a unix capability; the parser rides the
// same gate as `RootIdentity::new` so non-unix lib targets (wasm) skip it.
#[cfg(any(unix, test))]
fn unescape_mountinfo(field: &str) -> Vec<u8> {
  let bytes = field.as_bytes();
  let mut out = Vec::with_capacity(bytes.len());
  let mut at = 0;
  while at < bytes.len() {
    if bytes[at] == b'\\' && at + 3 < bytes.len() {
      let octal = &bytes[at + 1..at + 4];
      if octal.iter().all(|b| (b'0'..=b'7').contains(b)) {
        let value = (octal[0] - b'0') * 64 + (octal[1] - b'0') * 8 + (octal[2] - b'0');
        out.push(value);
        at += 4;
        continue;
      }
    }
    out.push(bytes[at]);
    at += 1;
  }
  out
}

/// Parses `/proc/self/mountinfo` content into the mount points strictly under
/// `root` (PURE — the reader lives in the cfg'd `mounts_under`).
///
/// The mount point is the fifth whitespace-separated field; malformed lines
/// are skipped (the seed is trust-reducing only, so omission fails toward
/// closed trust, never toward false authority).
#[cfg(any(unix, test))]
pub(crate) fn parse_mountinfo(content: &str, root: &Path) -> Vec<PathBuf> {
  use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
  let mut mounts = Vec::new();
  for line in content.lines() {
    let Some(field) = line.split_whitespace().nth(4) else {
      continue;
    };
    let bytes = unescape_mountinfo(field);
    let path = PathBuf::from(OsStr::from_bytes(&bytes));
    if path.starts_with(root) && path.as_path() != root {
      mounts.push(path);
    }
  }
  mounts
}

/// The mount points strictly under `root`, read from `/proc/self/mountinfo`.
/// `None` means the table could not be read — the caller must then treat
/// device boundaries as UNKNOWN rather than absent.
#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) fn mounts_under(root: &Path) -> Option<Vec<PathBuf>> {
  let content = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
  Some(parse_mountinfo(&content, root))
}

/// The `(dev, ino)` an arm confirms the opened object still has before
/// installing its kernel watch — the enumerate→arm rename guard. The driver
/// reads it from the Monitor node (a child) or the barrier meta (the root) and
/// carries it on the arm request; the reader fstats the opened anchor and
/// refuses to install on a mismatch.
#[cfg(all(target_os = "linux", not(miri)))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExpectedObject {
  /// The device the object was read on.
  pub(crate) dev: u64,
  /// The object's inode.
  pub(crate) ino: std::num::NonZeroU64,
}

/// How an arm resolved. Ungated: the sans-I/O core consumes this on every
/// host (an [`Aliased`](WatchOutcome::Aliased) anchor is covered coverage —
/// the wd table fans events to it — so the core maps it to a successful
/// watch-result exactly like a fresh install).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WatchOutcome {
  /// A fresh kernel watch was installed.
  Installed(i32),
  /// The inode was already watched (`EEXIST` under `IN_MASK_CREATE`); the
  /// anchor was registered onto the existing `wd`.
  Aliased(i32),
  /// The arm failed; the caller feeds this to the Monitor's watch-result.
  // `Failed`, not the plan sketch's `Err`: a variant named `Err` reads as
  // the `Result` constructor at every match site.
  Failed(tributary_proto::WatchError),
}

// The descending core (and the container smoke suites) reach the inotify arm
// controls through the seam; until the seam flips the lib build sees the
// re-export as unused.
#[cfg(all(target_os = "linux", not(miri)))]
#[allow(unused_imports)]
pub(crate) use inotify::reader::ControlOp;
#[cfg(all(target_os = "linux", not(miri)))]
#[allow(unused_imports)]
pub(crate) use inotify_source::{AnchorRequest, ArmReply, ControlPort};

/// The Linux spawn dispatcher: routes to the requested per-root backend. The
/// seam names one `Source`/`SourceHandle` per platform, so both Linux
/// primitives hide behind these — the driver never learns which one it got
/// beyond [`RootMeta::backend`](super::RootMeta).
#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) struct Source;

#[cfg(all(target_os = "linux", not(miri)))]
impl Source {
  /// Spawns the source `config.backend` selects, running the `Backend::Auto`
  /// probe (design §5) inside this pre-start barrier when asked.
  ///
  /// - [`Backend::Inotify`](super::Backend::Inotify) skips the probe and spawns
  ///   inotify directly.
  /// - [`Backend::Fanotify`](super::Backend::Fanotify) runs the probe and, on
  ///   any failing stage, returns the typed
  ///   [`BackendProbeFailed`](super::SourceError::BackendProbeFailed) rather
  ///   than falling back.
  /// - [`Backend::Auto`](super::Backend::Auto) runs the probe and, on any
  ///   failing stage, falls back to inotify.
  ///
  /// A passing probe leaves the fanotify instance CREATED and its superblock
  /// mark INSTALLED; that fd is handed straight to the fanotify source, which
  /// reuses it — the mark is never installed twice.
  ///
  /// # One pin, all live state grounded on it
  ///
  /// Right after canonicalization the root is PINNED as a single fd
  /// ([`pin_root`]: `openat2` with `RESOLVE_NO_SYMLINKS`, which fails rather than
  /// redirecting if a symlink was swapped in at ANY component after the
  /// canonicalize). Every decision that commits live kernel state then grounds on
  /// that fd, never on the pathname again:
  ///
  /// - the locality/remote gate (design §5 row 1) is [`fstatfs`](rustix::fs::fstatfs)
  ///   on the pin — a network/virtual filesystem reports only local VFS activity,
  ///   so every backend refuses it identically, and a transient mount/symlink swap
  ///   can no longer smuggle a remote fs past the gate;
  /// - the fanotify `FAN_MARK_FILESYSTEM` mark is installed fd-relative on the pin
  ///   (`fanotify_mark(ffd, …, pin_fd, NULL)`), so it marks the superblock of the
  ///   object the pin refers to — a path swap for THIS one call can no longer mark
  ///   the wrong superblock and leave the kernel listening elsewhere;
  /// - the root identity, the seed fsid, the FID seed walk's root, and the
  ///   post-live liveness re-stat all read the pin.
  ///
  /// Centralizing this ahead of selection is what stops a remote fs that happens
  /// to accept a mark and export handles from going live blind, and stops a
  /// same-path swap from anchoring a live source on an object other than the one
  /// the gate and identity vouched for.
  ///
  /// The pin's lifetime is exactly this call: it is held while the gate, probe
  /// (mark + handle), and backend spawn commit, then dropped on return. Nothing
  /// retains it — the fanotify reader owns the marked instance fd (a distinct
  /// descriptor), and the mark keeps the superblock scoped with no live root fd
  /// needed.
  pub(crate) fn spawn(
    config: super::SourceConfig,
  ) -> Result<(SourceHandle, super::EventReceiver, super::RootMeta), super::SourceError> {
    if config.roots.is_empty() {
      return Err(super::SourceError::NoRoots);
    }
    let supplied = &config.roots[0];
    let canonical =
      std::fs::canonicalize(supplied).map_err(|source| super::SourceError::RootUnavailable {
        root: supplied.clone(),
        source,
      })?;
    let root_fd = pin_root(&canonical)?;
    if root_is_remote(&root_fd, &canonical)? {
      return Err(super::SourceError::RootUnavailable {
        root: canonical,
        source: std::io::Error::new(
          std::io::ErrorKind::Unsupported,
          "network and virtual filesystems deliver no reliable events",
        ),
      });
    }

    match config.backend {
      super::Backend::Inotify => Self::spawn_inotify(config, canonical, root_fd.as_fd()),
      super::Backend::Fanotify => Self::spawn_probed(config, canonical, root_fd.as_fd(), false),
      super::Backend::Auto => Self::spawn_probed(config, canonical, root_fd.as_fd(), true),
    }
  }

  /// The inotify branch (no probe). `canonical` is the dispatcher's already
  /// canonicalized, already locality-checked root, and `root_fd` its pin — the
  /// inotify barrier reads its root identity from the pin (the same grounded
  /// object the gate vouched for), while its per-directory ARMS stay protected by
  /// their own `expected`-`(dev, ino)` open-then-verify.
  fn spawn_inotify(
    config: super::SourceConfig,
    canonical: PathBuf,
    root_fd: BorrowedFd<'_>,
  ) -> Result<(SourceHandle, super::EventReceiver, super::RootMeta), super::SourceError> {
    let (handle, rx, meta) = inotify_source::Source::spawn(config, canonical, root_fd)?;
    Ok((SourceHandle::Inotify(handle), rx, meta))
  }

  /// The probed branch, shared by `Auto` and forced `Fanotify`: run the fanotify
  /// precondition probe on the dispatcher's pinned root and either spawn fanotify
  /// reusing the probed fd, or handle the failure per `fall_back`.
  ///
  /// The seed walk is the last precondition and can only be judged AFTER the
  /// probe hands over the marked fd (it reuses that root), so a tree the walk
  /// cannot fully map surfaces as [`FanotifySpawn::NotViable`] here — folded into
  /// the same fall-back-vs-typed-error decision the probe stages use (the design
  /// §5 `Walk` row). A genuine spawn error (a vanished root, resource exhaustion)
  /// is propagated by BOTH selections: inotify could not start on it either.
  fn spawn_probed(
    config: super::SourceConfig,
    canonical: PathBuf,
    root_fd: BorrowedFd<'_>,
    fall_back: bool,
  ) -> Result<(SourceHandle, super::EventReceiver, super::RootMeta), super::SourceError> {
    match probe::probe_fanotify(root_fd) {
      Ok(probed) => match fanotify::Source::spawn(config, canonical.clone(), probed.fd, root_fd) {
        fanotify::FanotifySpawn::Started(handle, rx, meta) => {
          Ok((SourceHandle::Fanotify(handle), rx, meta))
        }
        fanotify::FanotifySpawn::Error(err) => Err(err),
        // The tree is not fully mappable (design §5 `Walk` stage): Auto falls back
        // to inotify (its per-directory arms surface an unreadable directory
        // natively); a forced `Fanotify` surfaces the typed viability error.
        fanotify::FanotifySpawn::NotViable(config) if fall_back => {
          Self::spawn_inotify(config, canonical, root_fd)
        }
        fanotify::FanotifySpawn::NotViable(_) => Err(probe::probe_error(super::ProbeStage::Walk)),
      },
      // Auto falls through to the universal backend; a forced `Fanotify` never
      // silently downgrades — it surfaces which precondition failed.
      Err(_) if fall_back => Self::spawn_inotify(config, canonical, root_fd),
      Err(stage) => Err(probe::probe_error(stage)),
    }
  }
}

/// Pins the canonical root as one directory fd, the single object every later
/// live-state decision grounds on (design §5, the objects-not-paths spawn
/// discipline). Uses `openat2` with `RESOLVE_NO_SYMLINKS` so a symlink swapped in
/// at ANY component after `canonicalize` fails the open (`ELOOP`) rather than
/// redirecting the pin to a different object — the gate, the mark, the identity,
/// and the seed then cannot be aimed anywhere but the object this open resolved.
/// `O_DIRECTORY` refuses a root retargeted to a non-directory; `O_RDONLY` lets the
/// fanotify seed walk `readdir` the same fd; `O_CLOEXEC` keeps it from leaking.
///
/// A vanished root is [`RootUnavailable`](super::SourceError::RootUnavailable) and
/// a symlink-swapped root fails the same way — both benign races the caller
/// surfaces typed, never a source committed on the wrong object.
///
/// `openat2` landed in Linux 5.6; inotify's floor predates it, so this open is
/// the one place the dispatcher needs the syscall for BOTH backends. It is
/// present on every kernel either backend runs on.
#[cfg(all(target_os = "linux", not(miri)))]
fn pin_root(canonical: &Path) -> Result<OwnedFd, super::SourceError> {
  rustix::fs::openat2(
    rustix::fs::CWD,
    canonical,
    OFlags::RDONLY
      .union(OFlags::DIRECTORY)
      .union(OFlags::NOFOLLOW)
      .union(OFlags::CLOEXEC),
    rustix::fs::Mode::empty(),
    rustix::fs::ResolveFlags::NO_SYMLINKS,
  )
  .map_err(|err| super::SourceError::RootUnavailable {
    root: canonical.to_path_buf(),
    source: err.into(),
  })
}

/// Whether the pinned root lives on a refused remote/virtual filesystem — the
/// shared locality gate every backend passes through the dispatcher (design §5
/// row 1), read from the PINNED fd so a mount/symlink swap cannot smuggle a
/// remote fs past it (a path `statfs` here would race the same window the mark
/// once did). `StatFs.f_type` is the same `__fsword_t` field the denylist keys on
/// (`REMOTE_FS_MAGICS`), so the magic-number comparison is unchanged.
///
/// The seed fsid the fanotify FID map needs is a SEPARATE `fstatfs` on the same
/// pin (rustix hides `StatFs::f_fsid` behind a private field, so the fsid must be
/// read through libc — the documented two-style boundary). The two reads cannot
/// disagree about which object they saw: both name the pin, and no path is
/// resolved in either, so no swap can land between them.
#[cfg(all(target_os = "linux", not(miri)))]
fn root_is_remote(root_fd: &OwnedFd, canonical: &Path) -> Result<bool, super::SourceError> {
  let stat = rustix::fs::fstatfs(root_fd).map_err(|err| super::SourceError::RootUnavailable {
    root: canonical.to_path_buf(),
    source: err.into(),
  })?;
  Ok(fs_type_is_remote(stat.f_type as i64))
}

/// The identities of every strict ancestor of the canonical root — the
/// containment evidence `final_root_conflict` decides root disjointness on
/// (is this root inside a live one, or a live one inside it, under ANY spelling).
/// Shared by both Linux backends' post-live bracket.
///
/// Each ancestor is PINNED before its identity is read: `openat2` with
/// `RESOLVE_NO_SYMLINKS` and `O_PATH | O_NOFOLLOW | O_DIRECTORY` (the same
/// object-grounding the arm anchors use), then `fstat` on that fd — never a bare
/// path stat. `canonicalize` left the ancestor chain symlink-free, so the
/// no-symlink open succeeds on the honest chain and fails (`ELOOP`) only if a
/// symlink was swapped in for an ancestor after canonicalization, which is
/// surfaced as [`RootUnavailable`](super::SourceError::RootUnavailable) rather than
/// silently recording a swapped-in object's identity as an ancestor. `O_PATH`
/// needs only search permission (like the previous `metadata`), so a normal
/// search-but-not-read ancestor still resolves.
///
/// Grounding this matters because the identities gate a TRUST decision (admitting
/// or refusing a second overlapping watch); a corrupted ancestor could only ever
/// mis-decide THAT — never redirect the live source, whose object is the pin — but
/// the objects-not-paths discipline still leaves no path-stat feeding a trust
/// decision unpinned.
#[cfg(all(target_os = "linux", not(miri)))]
fn ancestor_identities(canonical: &Path) -> Result<Vec<super::RootIdentity>, super::SourceError> {
  let mut ancestors = Vec::new();
  for ancestor in canonical.ancestors().skip(1) {
    let fd = rustix::fs::openat2(
      rustix::fs::CWD,
      ancestor,
      OFlags::PATH
        .union(OFlags::NOFOLLOW)
        .union(OFlags::DIRECTORY)
        .union(OFlags::CLOEXEC),
      rustix::fs::Mode::empty(),
      rustix::fs::ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|err| super::SourceError::RootUnavailable {
      root: ancestor.to_path_buf(),
      source: err.into(),
    })?;
    let stat = rustix::fs::fstat(&fd).map_err(|err| super::SourceError::RootUnavailable {
      root: ancestor.to_path_buf(),
      source: err.into(),
    })?;
    ancestors.push(super::RootIdentity::new(stat.st_dev, stat.st_ino));
  }
  Ok(ancestors)
}

/// The MOUNT id of the pinned root, read fd-relative via
/// `statx(root_fd, "", AT_EMPTY_PATH, STATX_MNT_ID)` — the descent boundary both
/// backends carry on [`RootMeta`](super::RootMeta) so the core (inotify) and the
/// seed walk (fanotify) can fence a submount by mount id rather than device. A
/// `mount --bind` of a same-superblock directory shares the root's device, so the
/// device alone cannot mark the boundary; the mount id differs across any mount.
///
/// `None` when the kernel did not report a mount id: `statx` unavailable (returns
/// `NOSYS` below Linux 4.11), the `STATX_MNT_ID` field absent (below 5.8), or the
/// returned `stx_mask` leaving the bit unset. inotify's kernel floor is well below
/// 5.8, so `None` is a real path there — the core degrades to the device check
/// (the settled single-device policy). fanotify's 5.17 floor always reports it,
/// but `None` is still handled rather than asserted.
#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) fn root_mount_id(root_fd: BorrowedFd<'_>) -> Option<u64> {
  use rustix::fs::{AtFlags, StatxFlags, statx};
  let stx = statx(root_fd, c"", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID).ok()?;
  (stx.stx_mask & StatxFlags::MNT_ID.bits() != 0).then_some(stx.stx_mnt_id)
}

/// A live Linux source, one variant per backend. Dropping it tears the reader
/// down; prefer [`shutdown`](Self::shutdown) at an orderly exit.
#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) enum SourceHandle {
  /// A live inotify source (descending; has arm traffic).
  Inotify(inotify_source::SourceHandle),
  /// A live fanotify source (kernel-recursive; no arm traffic).
  Fanotify(fanotify::SourceHandle),
}

#[cfg(all(target_os = "linux", not(miri)))]
impl SourceHandle {
  /// Stops the reader and closes the instance.
  pub(crate) fn shutdown(self) {
    match self {
      Self::Inotify(handle) => handle.shutdown(),
      Self::Fanotify(handle) => handle.shutdown(),
    }
  }

  /// The clonable arm/disarm port: the inotify control port, or `Inert` for
  /// the kernel-recursive fanotify source (no per-directory arming).
  pub(crate) fn scope_port(&self) -> super::ScopePort {
    match self {
      Self::Inotify(handle) => super::ScopePort::Inotify(handle.port()),
      Self::Fanotify(_) => super::ScopePort::Inert,
    }
  }

  /// The source's live stats handle: `Some` for a fanotify source (the reader's
  /// counters), `None` for inotify (no pollable admission map — design §4.9).
  pub(crate) fn backend_stats(&self) -> Option<super::BackendStatsHandle> {
    match self {
      Self::Inotify(_) => None,
      Self::Fanotify(handle) => Some(handle.backend_stats()),
    }
  }

  /// Installs (or aliases) a kernel watch on the inotify source. The
  /// kernel-recursive fanotify source has no arming and answers the honest
  /// typed refusal — the driver routes arms through [`scope_port`](Self::scope_port),
  /// so this is exercised only by the inotify smoke tests.
  #[cfg(test)]
  pub(crate) fn add_watch(&self, request: AnchorRequest) -> ArmReply {
    match self {
      Self::Inotify(handle) => handle.add_watch(request),
      Self::Fanotify(_) => ArmReply {
        outcome: WatchOutcome::Failed(tributary_proto::WatchError::Io),
        anchor: None,
      },
    }
  }

  /// Removes an anchor from the inotify source's attribution; a no-op on the
  /// arming-less fanotify source.
  #[cfg(test)]
  pub(crate) fn remove_watch(&self, anchor: WatchId) {
    if let Self::Inotify(handle) = self {
      handle.remove_watch(anchor);
    }
  }
}

#[cfg(all(target_os = "linux", not(miri)))]
mod inotify_source {
  //! The inotify Source: the per-root fd, its reader thread, and the spawn
  //! barrier. Watches are NOT armed at spawn — the driver arms the root (and
  //! every descendant) through the control path, so arm handling is uniform
  //! and the Monitor's watch-result contract drives everything.

  use std::{
    ffi::OsString,
    fs,
    os::{
      fd::{BorrowedFd, OwnedFd},
      unix::fs::MetadataExt,
    },
    sync::{Arc, mpsc},
    thread::JoinHandle,
  };

  use tributary_proto::{WatchError, WatchId};

  use super::{
    super::{RootIdentity, RootMeta, SourceConfig, SourceError, transport},
    ExpectedObject, WatchOutcome, ancestor_identities, mounts_under, root_mount_id,
    wake::WakeState,
  };
  use crate::os::MAX_EXCLUSIONS;

  use super::inotify::reader::{self, Control, ControlOp, ReaderShared};

  /// One arm request: install a kernel watch for `watch` on the directory
  /// named by `name` under `parent` (`None` = `name` is the absolute canonical
  /// root). The open is anchor-relative (`openat`), so a parent rename between
  /// the caller's enumerate and this arm cannot retarget the add.
  #[derive(Debug)]
  pub(crate) struct AnchorRequest {
    /// The Monitor watch the kernel watch will attribute to.
    pub(crate) watch: WatchId,
    /// The parent's transient anchor, when arming a child.
    pub(crate) parent: Option<OwnedFd>,
    /// The child's name under `parent`, or the absolute root path.
    pub(crate) name: OsString,
    /// The `(dev, ino)` the opened object must still have before the watch
    /// installs — the enumerate→arm rename guard. `None` leaves the arm
    /// unverified (identity was unavailable at enumerate time).
    pub(crate) expected: Option<ExpectedObject>,
  }

  /// An arm's reply: the outcome plus, on success, the target's transient
  /// `O_PATH` anchor — held by the caller through the cold enumerate
  /// (anchor-relative readdir), then closed. fd usage stays O(in-flight
  /// operations), never O(tree).
  #[derive(Debug)]
  pub(crate) struct ArmReply {
    pub(crate) outcome: WatchOutcome,
    pub(crate) anchor: Option<OwnedFd>,
  }

  /// The spawn entry point of the inotify backend.
  pub(crate) struct Source;

  impl Source {
    /// Runs the pre-start barrier, creates the per-root inotify instance, and
    /// starts its reader thread. No watch exists on return — the driver arms
    /// the root through [`SourceHandle::add_watch`], so nothing can be
    /// delivered (and nothing missed) before the Monitor's own watch flow
    /// runs.
    ///
    /// `canonical` is the dispatcher's already canonicalized, already
    /// locality-checked root (design §5 row 1 runs once, before selection), and
    /// `root_fd` the dispatcher's PINNED root — the same object the shared gate
    /// vouched for. The barrier reads the root identity from that pin
    /// (object-grounded, not a path stat), captures the mount seed strictly before
    /// the fd exists, then re-stats once the reader is live — a root replaced
    /// across the gap is torn down and rejected, never committed.
    ///
    /// The inotify ARMS do not consume this pin: each per-directory arm opens its
    /// own transient `O_PATH` anchor and verifies the opened object still carries
    /// the enumerate-time `expected` `(dev, ino)` before installing, so the root
    /// arm is protected by that open-then-verify regardless of this fd's lifetime
    /// (which ends when the dispatcher's `spawn` returns).
    pub(crate) fn spawn(
      config: SourceConfig,
      canonical: std::path::PathBuf,
      root_fd: BorrowedFd<'_>,
    ) -> Result<(SourceHandle, super::super::EventReceiver, RootMeta), SourceError> {
      if config.exclusions.len() > MAX_EXCLUSIONS {
        return Err(SourceError::TooManyExclusions {
          supplied: config.exclusions.len(),
        });
      }

      // Identity from the PIN (fstat): the registry anchors on exactly the object
      // the gate saw, never an object a path stat could be redirected to. The pin's
      // `O_DIRECTORY` already refused a non-directory root, so no `is_dir` recheck
      // is needed here.
      let stat = rustix::fs::fstat(root_fd).map_err(|err| SourceError::RootUnavailable {
        root: canonical.clone(),
        source: err.into(),
      })?;
      let root_dev = stat.st_dev;
      // The root's mount id from the same PIN — the core's descent boundary. inotify
      // runs below 5.8, so this may be `None` (statx has no mount id there); the
      // core then falls back to the device check. Read once here, carried on
      // `RootMeta` like `root_dev`.
      let root_mnt_id = root_mount_id(root_fd);
      let identity = RootIdentity::new(stat.st_dev, stat.st_ino);
      let mounts = mounts_under(&canonical).unwrap_or_default();

      let (queue_tx, queue_rx) = async_channel::unbounded();
      let shared = Arc::new(ReaderShared {
        queue: queue_tx,
        transport: transport::TransportState::new(config.channel_capacity.get()),
      });

      let fd = reader::create_instance()?;
      let wake = WakeState::new()?;
      let (control_tx, control_rx) = mpsc::channel();
      let thread = reader::start(fd, Arc::clone(&wake), control_rx, Arc::clone(&shared))?;

      let handle = SourceHandle {
        port: ControlPort {
          control: control_tx,
          wake,
        },
        thread: Some(thread),
      };

      // The post-live half of the identity bracket, two complementary signals
      // (the fanotify sibling documents the split in full):
      //   - the PINNED-fd re-stat proves the seeded/identified object survived the
      //     barrier→reader gap (same-object liveness);
      //   - the PATH re-stat proves the path still resolves to that object
      //     (replaced-at-path — the distinct question `RootReplaced` names, which
      //     the driver's path-re-resolving refresh must reject up front).
      let pinned = match rustix::fs::fstat(root_fd) {
        Ok(pinned) => pinned,
        Err(err) => {
          handle.shutdown();
          return Err(SourceError::RootUnavailable {
            root: canonical,
            source: err.into(),
          });
        }
      };
      if RootIdentity::new(pinned.st_dev, pinned.st_ino) != identity {
        handle.shutdown();
        return Err(SourceError::RootReplaced { root: canonical });
      }
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
      let ancestors = match ancestor_identities(&canonical) {
        Ok(ancestors) => ancestors,
        Err(err) => {
          handle.shutdown();
          return Err(err);
        }
      };

      let meta = RootMeta {
        root: canonical,
        root_dev,
        root_mnt_id,
        mounts,
        identity,
        ancestors,
        backend: super::super::BackendKind::Inotify,
      };
      Ok((handle, queue_rx, meta))
    }
  }

  /// The clonable arm/disarm port of a live source: the control channel plus
  /// its wake state. Executors on the blocking pool hold one of these per
  /// scope, so arm traffic never needs the (non-clonable, teardown-owning)
  /// [`SourceHandle`] itself.
  #[derive(Debug, Clone)]
  pub(crate) struct ControlPort {
    control: mpsc::Sender<Control>,
    wake: Arc<WakeState>,
  }

  impl ControlPort {
    /// Sends one batch of arms/disarms and returns the arms' outcomes in order
    /// (index-aligned to the `Arm` entries — disarms produce no reply). One
    /// message, one potential wake, N results: the reader executes the whole
    /// batch in a single pass between reads. Blocks until the reader replies;
    /// callers run it on the blocking pool. A dead reader answers `Failed(Io)`
    /// for every arm — the scope's stream death carries the real signal.
    ///
    /// Enqueue-then-conditional-wake is the wake-elision contract: the message
    /// lands on the channel BEFORE [`WakeState::wake_if_parked`] checks the
    /// park flag, so a reader about to block cannot miss it (the lost-wakeup
    /// argument lives on [`WakeState`]).
    pub(crate) fn batch(&self, ops: Vec<ControlOp>) -> Vec<ArmReply> {
      let arm_count = ops
        .iter()
        .filter(|op| matches!(op, ControlOp::Arm(_)))
        .count();
      let (reply_tx, reply_rx) = mpsc::sync_channel(1);
      if self
        .control
        .send(Control::Batch {
          ops,
          reply: reply_tx,
        })
        .is_err()
      {
        return dead_replies(arm_count);
      }
      self.wake.wake_if_parked();
      reply_rx.recv().unwrap_or_else(|_| dead_replies(arm_count))
    }

    /// Installs (or aliases) one kernel watch. A single-entry [`batch`]; the
    /// smoke suites arm one watch at a time.
    ///
    /// [`batch`]: Self::batch
    #[cfg(test)]
    pub(crate) fn add_watch(&self, request: AnchorRequest) -> ArmReply {
      self
        .batch(vec![ControlOp::Arm(request)])
        .into_iter()
        .next()
        .unwrap_or(ArmReply {
          outcome: WatchOutcome::Failed(WatchError::Io),
          anchor: None,
        })
    }

    /// Removes `anchor` from attribution, issuing the kernel removal when the
    /// last alias drains. A single-entry [`batch`].
    ///
    /// [`batch`]: Self::batch
    #[cfg(test)]
    pub(crate) fn remove_watch(&self, anchor: WatchId) {
      let _ = self.batch(vec![ControlOp::Disarm(anchor)]);
    }
  }

  /// A reader-is-dead reply for every arm in a batch that never landed.
  fn dead_replies(arm_count: usize) -> Vec<ArmReply> {
    (0..arm_count)
      .map(|_| ArmReply {
        outcome: WatchOutcome::Failed(WatchError::Io),
        anchor: None,
      })
      .collect()
  }

  /// A live inotify source. Dropping it tears the reader down; prefer
  /// [`shutdown`](Self::shutdown) at an orderly exit.
  pub(crate) struct SourceHandle {
    port: ControlPort,
    thread: Option<JoinHandle<()>>,
  }

  impl SourceHandle {
    /// A clonable arm/disarm port onto this source's reader.
    pub(crate) fn port(&self) -> ControlPort {
      self.port.clone()
    }

    /// Installs (or aliases) a kernel watch. See [`ControlPort::add_watch`].
    #[cfg(test)]
    pub(crate) fn add_watch(&self, request: AnchorRequest) -> ArmReply {
      self.port.add_watch(request)
    }

    /// Removes `anchor` from attribution. See [`ControlPort::remove_watch`].
    #[cfg(test)]
    pub(crate) fn remove_watch(&self, anchor: WatchId) {
      self.port.remove_watch(anchor)
    }

    /// Stops the reader and closes the instance. The reader exits at its next
    /// wake, so this blocks for at most one in-flight read + decode.
    pub(crate) fn shutdown(mut self) {
      self.teardown();
    }

    fn teardown(&mut self) {
      let Some(thread) = self.thread.take() else {
        return;
      };
      let _ = self.port.control.send(Control::Shutdown);
      self.port.wake.wake();
      let _ = thread.join();
    }
  }

  impl Drop for SourceHandle {
    fn drop(&mut self) {
      self.teardown();
    }
  }
}
