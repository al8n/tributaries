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
//!
//! # Kernel floor contract
//!
//! The two backends advertise two different floors, and each is honored END TO
//! END — every syscall on a backend's spawn path is available on that backend's
//! floor, or degrades to one that is:
//!
//! - **inotify: Linux 4.11** — the `statx` floor, the honest minimum for the
//!   descending backend. Every live-path fact (root liveness, directory-entry
//!   identity) is a `statx` in the driver (`stat_sample`), so the spawn barrier
//!   ([`Source`]) PROBES `statx` ONCE up front — a fd-relative `statx` on the
//!   pinned root ([`require_statx`]), arch-independently — and refuses a pre-4.11
//!   kernel (or a seccomp sandbox that blocks `statx`) with a typed
//!   [`RootUnavailable`](super::SourceError::RootUnavailable) rather than limping
//!   below the floor into a confusing statx-backed-`fstat` `NOSYS` deeper in the
//!   identity capture. Linux 4.11 (May 2017) predates every supported distro
//!   (RHEL 8 4.18, Ubuntu 18.04 4.15, Debian 10 4.19, SLES 15 4.12); a kernel below
//!   it — and a `statx`-blocking seccomp policy — is explicitly unsupported for the
//!   Linux backends. Above the floor, `openat2` (5.6) is only a FAST PATH: the root
//!   pin ([`pin_root`]) and the post-live ancestor identities
//!   ([`ancestor_identities`]) degrade on `ENOSYS` to the shared hand-rolled
//!   [`open_no_symlinks`] component walk, so a 4.11–5.5 kernel still pins, starts
//!   the reader, AND reads the ancestor chain without ever hitting an unhandled
//!   `ENOSYS`. `statx`'s mount id (`STATX_MNT_ID`, 5.8) is a masked read
//!   ([`root_mount_id`] here, and the driver's `stat_sample`) that yields `Ok(None)`
//!   — the device-belt fence — on a 4.11–5.7 kernel rather than failing. The scope
//!   fence rests on one invariant: **a `None` mount frame means `statx` SUCCEEDED
//!   without the `STATX_MNT_ID` bit (a pre-5.8 belt), and NEVER that `statx`
//!   failed.** A `statx` failure is always a spawn failure ([`require_statx`] fails
//!   closed on EVERY error, and the mount-id capture turns `Err` into a spawn
//!   refusal) or a walk failure — so the belt is never reached by silently
//!   swallowing a denied `statx`, which would disable the fence. `inotify_init` and
//!   `eventfd` are far below the floor.
//! - **fanotify: 5.17+** (the `FAN_REPORT_TARGET_FID` / `FAN_RENAME` composite,
//!   design §4), well above the `statx` floor, so the up-front gate never trips on
//!   it. Every fanotify-only call — including the seed walk's `openat2` roots in
//!   `fanotify::source` — relies on that floor and stays `openat2`-only with no
//!   fallback: a pre-5.6 kernel could never have started the source.
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
///   batch lost and is not forwarded — the ordered loss signal covers it. It also
///   reaps the table's draining tombstones ([`WdTable::on_loss`]) at the
///   sentinel's in-order position: an overflow can drop the very `IN_IGNORED` a
///   tombstone awaits, and nothing else would ever erase it. This is one of two
///   DECODE-level losses that reap; a decode-truncation is the other, which the
///   reader applies once the decoded prefix is attributed (gated on
///   `decoded.lossy`).
/// - `IN_IGNORED` is a `wd`'s final record: it consumes the table entry
///   ([`WdTable::on_ignored`]) and forwards to the anchors that were still
///   live (a kernel-initiated teardown); a self-induced teardown whose
///   anchors already drained forwards nothing, and a marker on an unmapped
///   `wd` (straggling behind its entry's erase) no-ops. The marker always
///   belongs to the mapping it lands on — the table's adoption invariant: a
///   fresh install's `wd` is granted past every mapped one (the reader
///   rebuilds the instance before the allocator can wrap), so no stale
///   marker can ever address a fresh binding.
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
      // The kernel dropped queued events (inotify(7)); a draining tombstone's
      // awaited final marker may be among the dropped, so reap the tombstones
      // HERE, at the sentinel's in-order position: after any in-buffer marker
      // that preceded it. This is one of the two DECODE-level losses that
      // reap; a decode-truncation is the other, applied by the reader once
      // the decoded prefix is attributed (gated on `decoded.lossy`).
      table.on_loss();
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
    let anchors = table.attribute(event.wd);
    if !anchors.is_empty() {
      events.push(RawLinuxEvent::Inotify {
        anchors: anchors.to_vec(),
        event,
      });
    }
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
  let mut mounts = Vec::new();
  for line in content.lines() {
    let Some(field) = line.split_whitespace().nth(4) else {
      continue;
    };
    let bytes = unescape_mountinfo(field);
    // A mount point is raw path bytes — only unix carries non-UTF-8 verbatim.
    // The non-unix arm serves solely the cross-platform parser tests (the `test`
    // half of the gate), whose fixtures are UTF-8, so the lossy decode matches.
    #[cfg(unix)]
    let path = {
      use std::os::unix::ffi::OsStrExt;
      PathBuf::from(std::ffi::OsStr::from_bytes(&bytes))
    };
    #[cfg(not(unix))]
    let path = PathBuf::from(String::from_utf8_lossy(&bytes).into_owned());
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
pub(crate) use inotify_source::{AnchorRequest, ArmReply, BatchOutcome, BatchReply, ControlPort};

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
    // The kernel-floor gate (design §3): every live-path fact both backends read
    // is a `statx`, so a kernel without it cannot honestly be watched. Probe once
    // here — before the fstat-based identity capture, where a statx-backed `fstat`
    // would surface a confusing `NOSYS` on 32-bit — and refuse a pre-4.11 kernel
    // outright. fanotify's 5.17 floor never trips this.
    require_statx(root_fd.as_fd(), &canonical)?;
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
      // The real spawn seam rejects foreign selections before dispatch; a
      // direct spawn (the os-level suites) gets the same typed refusal.
      foreign => Err(super::SourceError::ForeignBackend { requested: foreign }),
    }
  }

  /// The spawn barrier's METADATA half with NO stream creation — what a
  /// same-transport widen commits with. Identical discipline to
  /// [`spawn`](Self::spawn): canonicalize, then PIN the root
  /// ([`pin_root`]: `RESOLVE_NO_SYMLINKS`) and ground every fact on the pin —
  /// the statx floor, the locality gate, the identity and mount frame — plus
  /// the trust-reducing mount seed and the ancestor identities. The backend is
  /// pinned to inotify: the widen route never re-runs the `Auto` ladder (the
  /// live stream IS the backend), which is also how the KR↔descending
  /// diagonal stays structurally unreachable on it.
  pub(crate) fn resolve_root_meta(supplied: &Path) -> Result<super::RootMeta, super::SourceError> {
    let canonical =
      std::fs::canonicalize(supplied).map_err(|source| super::SourceError::RootUnavailable {
        root: supplied.to_path_buf(),
        source,
      })?;
    let root_fd = pin_root(&canonical)?;
    require_statx(root_fd.as_fd(), &canonical)?;
    if root_is_remote(&root_fd, &canonical)? {
      return Err(super::SourceError::RootUnavailable {
        root: canonical,
        source: std::io::Error::new(
          std::io::ErrorKind::Unsupported,
          "network and virtual filesystems deliver no reliable events",
        ),
      });
    }
    let stat = rustix::fs::fstat(&root_fd).map_err(|err| super::SourceError::RootUnavailable {
      root: canonical.clone(),
      source: err.into(),
    })?;
    let root_mnt_id =
      root_mount_id(root_fd.as_fd()).map_err(|err| super::SourceError::RootUnavailable {
        root: canonical.clone(),
        source: err.into(),
      })?;
    let identity = super::RootIdentity::new(stat.st_dev, stat.st_ino.into());
    let mounts = mounts_under(&canonical).unwrap_or_default();
    let ancestors = ancestor_identities(&canonical)?;
    Ok(super::RootMeta {
      root: canonical,
      root_dev: stat.st_dev,
      root_mnt_id,
      mounts,
      identity,
      ancestors,
      backend: super::BackendKind::Inotify,
    })
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
/// discipline). The `openat2` fast path uses `RESOLVE_NO_SYMLINKS` so a symlink
/// swapped in at ANY component after `canonicalize` fails the open (`ELOOP`)
/// rather than redirecting the pin to a different object — the gate, the mark,
/// the identity, and the seed then cannot be aimed anywhere but the object this
/// open resolved. `O_DIRECTORY` refuses a root retargeted to a non-directory;
/// `O_RDONLY` lets the fanotify seed walk `readdir` the same fd; `O_CLOEXEC`
/// keeps it from leaking.
///
/// A vanished root is [`RootUnavailable`](super::SourceError::RootUnavailable) and
/// a symlink-swapped root fails the same way — both benign races the caller
/// surfaces typed, never a source committed on the wrong object.
///
/// # Kernel floor contract
///
/// `openat2` landed in Linux 5.6. fanotify-FILESYSTEM requires 5.17, so on the
/// fanotify path `openat2` is always present (the internal walk-root opens in
/// `fanotify::source` rely on that same 5.17 floor and stay `openat2`-only). But
/// **inotify's floor is Linux 4.11** (the `statx` floor the spawn barrier gates —
/// e.g. RHEL 8 ships 4.18), well below 5.6, so an `openat2` here would have made
/// forced [`Inotify`](super::Backend::Inotify) and `Auto`'s inotify fallback fail
/// with `RootUnavailable` on any 4.11–5.5 kernel — breaking that floor at the pin.
/// So on `ENOSYS` (the kernel has no `openat2`) this degrades to a component-wise
/// walk that reproduces the identical no-symlink pin by hand ([`open_no_symlinks`],
/// the walker [`ancestor_identities`] shares for the same reason); the resulting
/// fd, used only by inotify (fanotify cannot run this low), is the same object
/// with the same `O_RDONLY | O_DIRECTORY` final flags and downstream semantics.
#[cfg(all(target_os = "linux", not(miri)))]
fn pin_root(canonical: &Path) -> Result<OwnedFd, super::SourceError> {
  let final_flags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
  match rustix::fs::openat2(
    rustix::fs::CWD,
    canonical,
    final_flags,
    rustix::fs::Mode::empty(),
    rustix::fs::ResolveFlags::NO_SYMLINKS,
  ) {
    Ok(fd) => Ok(fd),
    // No `openat2` on this kernel (pre-5.6): pin by the component walk instead.
    // Only inotify reaches this — fanotify's 5.17 floor is far above it. The final
    // component keeps `O_RDONLY | O_DIRECTORY`, matching the fast path exactly.
    Err(rustix::io::Errno::NOSYS) => {
      open_no_symlinks(canonical, final_flags).map_err(|err| super::SourceError::RootUnavailable {
        root: canonical.to_path_buf(),
        source: err.into(),
      })
    }
    Err(err) => Err(super::SourceError::RootUnavailable {
      root: canonical.to_path_buf(),
      source: err.into(),
    }),
  }
}

/// The pre-`openat2` no-symlink open, SHARED by [`pin_root`] and
/// [`ancestor_identities`] on `ENOSYS`: walks `path` one component at a time under
/// held fds, so the no-symlink guarantee `RESOLVE_NO_SYMLINKS` gives in one syscall
/// is rebuilt by hand. It opens the anchor ("/" for an absolute path, or
/// [`CWD`](rustix::fs::CWD) as the base for a relative one) and then, for each
/// `Normal` component, `openat(parent_fd, name, …, O_NOFOLLOW | O_DIRECTORY)`.
/// `openat`'s `O_NOFOLLOW` governs the FINAL component of the path it is handed —
/// and each hop hands exactly one component — so a symlink at ANY component is
/// refused rather than traversed, exactly the no-follow guarantee the fast path's
/// whole-path `RESOLVE_NO_SYMLINKS` open gives. The refusal errno is a kernel
/// detail: `O_NOFOLLOW | O_PATH` opens the link object itself and the accompanying
/// `O_DIRECTORY` then rejects it (`ENOTDIR`), or the resolver refuses the link
/// outright (`ELOOP`) — either way the link is never followed to its target.
/// `canonicalize` already resolved every `.`/`..`/prefix, so a canonical path (or a
/// strict ancestor of one) yields only an anchor plus `Normal` components; any other
/// component kind is a non-canonical input and is refused (`EINVAL`).
///
/// The INTERMEDIATE hops open `O_PATH | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC` —
/// ancestors that should need only search permission — while the FINAL component
/// opens with the caller's `final_flags`, so each caller keeps its exact permission
/// behavior: `pin_root` ends on `O_RDONLY | O_DIRECTORY` (matching its fast path),
/// `ancestor_identities` on `O_PATH | O_DIRECTORY` (search-only, like its `metadata`
/// predecessor). When `path` is the anchor itself (no `Normal` components, e.g.
/// `"/"`), the anchor open carries `final_flags` — the anchor is the final object.
///
/// Errors surface as the raw [`Errno`](rustix::io::Errno) for the caller to map onto
/// its own `RootUnavailable` (each names the right `root`): a vanished component is
/// `ENOENT` (the caller's NotFound race); a symlinked or non-directory component is
/// `ELOOP`/`ENOTDIR` — the same typed refusal the fast path gives — never a pin on
/// the wrong object.
#[cfg(all(target_os = "linux", not(miri)))]
fn open_no_symlinks(path: &Path, final_flags: OFlags) -> Result<OwnedFd, rustix::io::Errno> {
  use std::path::Component;

  let walk_flags = OFlags::PATH
    .union(OFlags::NOFOLLOW)
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);

  // Collect the `Normal` components up front so the LAST hop can be opened with
  // `final_flags` (the caller's permission) while the rest stay `O_PATH`. A
  // non-`Normal`, non-anchor component is a non-canonical input.
  let mut names = Vec::new();
  let mut components = path.components();
  let has_root = matches!(components.clone().next(), Some(Component::RootDir));
  if has_root {
    components.next();
  }
  for component in components {
    let Component::Normal(name) = component else {
      // `.`/`..`/prefix cannot appear in a canonical path; reject a
      // non-canonical input rather than climb or loop.
      return Err(rustix::io::Errno::INVAL);
    };
    names.push(name);
  }

  // The anchor fd: the filesystem root for an absolute path, else the cwd. Opening
  // "/" with O_NOFOLLOW is safe — "/" is never a symlink. If there are no `Normal`
  // components the anchor IS the target, so it carries `final_flags`.
  let anchor_flags = if names.is_empty() {
    final_flags
  } else {
    walk_flags
  };
  let anchor = if has_root { c"/" } else { c"." };
  let mut current = rustix::fs::openat(
    rustix::fs::CWD,
    anchor,
    anchor_flags,
    rustix::fs::Mode::empty(),
  )?;

  let last = names.len().saturating_sub(1);
  for (index, name) in names.into_iter().enumerate() {
    // `openat` relative to the held parent fd: the single component's O_NOFOLLOW is
    // the per-hop no-symlink guarantee. The final component uses the caller's flags.
    let flags = if index == last {
      final_flags
    } else {
      walk_flags
    };
    current = rustix::fs::openat(&current, name, flags, rustix::fs::Mode::empty())?;
  }
  Ok(current)
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

/// The inotify floor gate: refuses a kernel that cannot RUN `statx` (Linux 4.11,
/// May 2017) up front, so the descending backend never limps below — or beside —
/// the floor it depends on. Every live-path fact the driver reports — root liveness
/// and directory-entry identity (the driver's `stat_sample`) — is a `statx`, AND the
/// mount-id scope fence ([`root_mount_id`], the same fd-relative shape) is a `statx`
/// too, so a kernel or sandbox that cannot run it cannot be watched honestly.
/// Probing ONCE here, on the pinned root (`statx(root_fd, "", AT_EMPTY_PATH, …)`),
/// fails such an environment with a typed
/// [`RootUnavailable`](super::SourceError::RootUnavailable) instead of a confusing
/// statx-backed-`fstat` `NOSYS` surfacing arch-dependently in the identity capture
/// (rustix's `fstat`/`lstat` are `statx`-backed on 32-bit and fall back only on
/// `NOSYS`). fanotify's 5.17 floor is far above this, so the gate is a real path
/// only for inotify below 4.11 and for a `statx`-blocking sandbox.
///
/// # Requiring statx means requiring it to WORK — fail closed
///
/// EVERY `statx` error refuses the spawn, not only the below-floor set: a successful
/// `statx` is the ONLY way past the gate ([`statx_gate_error`] maps every errno to a
/// typed refusal). This is load-bearing for the mount-id scope fence — a seccomp
/// policy answering `EPERM`/`EACCES` for `statx` would otherwise let a source go LIVE
/// while [`root_mount_id`] silently degraded to `None` and the core's
/// `crosses_mount_boundary` fell back to the device belt, reopening the
/// same-superblock bind-mount over-admission class the mount id exists to close. So a
/// `statx`-blocking sandbox is explicitly UNSUPPORTED: allowlist `statx`. The errno
/// only selects the refusal MESSAGE (the below-4.11
/// floor text for the [`statx_unavailable`] set, the raw errno otherwise); it never
/// selects Ok.
#[cfg(all(target_os = "linux", not(miri)))]
fn require_statx(root_fd: BorrowedFd<'_>, canonical: &Path) -> Result<(), super::SourceError> {
  use rustix::fs::{AtFlags, StatxFlags, statx};
  match statx(root_fd, c"", AtFlags::EMPTY_PATH, StatxFlags::TYPE) {
    Ok(_) => Ok(()),
    Err(errno) => Err(statx_gate_error(errno, canonical)),
  }
}

/// The typed spawn refusal for a `statx` that did not succeed on the pinned root
/// (PURE — row-tested). The gate is fail-closed, so EVERY errno becomes a
/// [`RootUnavailable`](super::SourceError::RootUnavailable); the errno only picks the
/// source message. The unsupported-floor set ([`statx_unavailable`]) names the Linux
/// 4.11 floor (a pre-4.11 kernel, or a filesystem/sandbox with no `statx` at all —
/// `EOPNOTSUPP`), carried as an `Unsupported` I/O error; every other errno (`EPERM`
/// and `EACCES` from a `statx`-blocking seccomp policy, `EIO`, …) surfaces as itself.
/// Both refuse the spawn: a source must never go live with `statx` unavailable,
/// because the mount-id scope fence structurally depends on it.
#[cfg(all(target_os = "linux", not(miri)))]
fn statx_gate_error(errno: rustix::io::Errno, canonical: &Path) -> super::SourceError {
  let source = if statx_unavailable(errno) {
    std::io::Error::new(
      std::io::ErrorKind::Unsupported,
      "the Linux backends require statx (Linux 4.11+)",
    )
  } else {
    errno.into()
  };
  super::SourceError::RootUnavailable {
    root: canonical.to_path_buf(),
    source,
  }
}

/// Whether a `statx` errno means the syscall is UNAVAILABLE on this kernel — the
/// pure MESSAGE selector [`statx_gate_error`] uses to name the floor (row-tested).
/// `statx` landed in Linux 4.11, so an older kernel answers `NOSYS`; a filesystem or
/// sandbox with no `statx` support at all can answer `EOPNOTSUPP`. Both mean "no
/// `statx` here", which the Linux backends require, so both carry the below-4.11
/// floor message. Every other errno — `EPERM`/`EACCES` (a seccomp policy that BLOCKS
/// `statx` rather than removing it), `EIO`, … — is NOT the floor and keeps its own
/// message. It does NOT, however, pass the gate: [`require_statx`] refuses on EVERY
/// error (fail closed); this classifier only chooses which message the refusal
/// carries, never whether to refuse. A `statx`-blocking seccomp profile is an
/// unsupported environment (allowlist `statx`), not one the gate rescues.
#[cfg(all(target_os = "linux", not(miri)))]
fn statx_unavailable(errno: rustix::io::Errno) -> bool {
  matches!(
    errno,
    rustix::io::Errno::NOSYS | rustix::io::Errno::OPNOTSUPP
  )
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
/// This runs in the inotify spawn's post-live bracket AFTER the reader is live, so
/// it shares [`pin_root`]'s kernel floor: `openat2` is pre-5.6, but inotify's floor
/// is Linux 4.11, so on `ENOSYS` each ancestor falls back to the SAME component walk
/// [`open_no_symlinks`] the pin uses (final flags `O_PATH | O_DIRECTORY`, search
/// permission). Without this fallback a 4.11–5.5 kernel would pin the root by the
/// walk, start the reader, then die `RootUnavailable` one call later — the floor
/// broken end to end rather than per-call-site.
///
/// Grounding this matters because the identities gate a TRUST decision (admitting
/// or refusing a second overlapping watch); a corrupted ancestor could only ever
/// mis-decide THAT — never redirect the live source, whose object is the pin — but
/// the objects-not-paths discipline still leaves no path-stat feeding a trust
/// decision unpinned.
#[cfg(all(target_os = "linux", not(miri)))]
fn ancestor_identities(canonical: &Path) -> Result<Vec<super::RootIdentity>, super::SourceError> {
  let final_flags = OFlags::PATH
    .union(OFlags::NOFOLLOW)
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);
  let mut ancestors = Vec::new();
  for ancestor in canonical.ancestors().skip(1) {
    let unavailable = |err: rustix::io::Errno| super::SourceError::RootUnavailable {
      root: ancestor.to_path_buf(),
      source: err.into(),
    };
    let fd = match rustix::fs::openat2(
      rustix::fs::CWD,
      ancestor,
      final_flags,
      rustix::fs::Mode::empty(),
      rustix::fs::ResolveFlags::NO_SYMLINKS,
    ) {
      Ok(fd) => fd,
      // Pre-5.6 kernel with no `openat2`: pin the ancestor by the shared component
      // walk, same no-symlink guarantee, same `O_PATH` final flags.
      Err(rustix::io::Errno::NOSYS) => {
        open_no_symlinks(ancestor, final_flags).map_err(unavailable)?
      }
      Err(err) => return Err(unavailable(err)),
    };
    let stat = rustix::fs::fstat(&fd).map_err(unavailable)?;
    ancestors.push(super::RootIdentity::new(stat.st_dev, stat.st_ino.into()));
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
/// # `Ok(None)` is the pre-5.8 belt; `Err` is a syscall failure — never conflated
///
/// A SUCCESSFUL `statx` whose `stx_mask` lacks the `STATX_MNT_ID` bit returns
/// `Ok(None)` — the legitimate device-belt degrade below Linux 5.8 (RHEL 8's 4.18,
/// Ubuntu 20.04's 5.4), where the core's `crosses_mount_boundary` falls back to the
/// device check (the settled single-device policy). A `statx` SYSCALL FAILURE returns
/// `Err(errno)` and is NEVER laundered into that `None`: the spawn-time frame capture
/// (`RootMeta.root_mnt_id`, both backends) turns it into a spawn failure, and the live
/// reseed/subtree walks turn it into a walk failure — so a `None` mount frame ALWAYS
/// means `statx` succeeded without the mount-id bit and NEVER means `statx` failed.
/// The spawn barrier already gated the 4.11 `statx` floor ([`require_statx`], fail
/// closed), so an `Err` here is not expected — but it fails closed rather than
/// silently disabling the fence. inotify's 4.11 floor is below 5.8, so `Ok(None)` is a
/// real path there; fanotify's 5.17 floor always reports the id, but `Ok(None)` is
/// still handled rather than asserted.
#[cfg(all(target_os = "linux", not(miri)))]
pub(crate) fn root_mount_id(root_fd: BorrowedFd<'_>) -> Result<Option<u64>, rustix::io::Errno> {
  use rustix::fs::{AtFlags, StatxFlags, statx};
  let stx = statx(root_fd, c"", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)?;
  Ok(mnt_id_from_mask(stx.stx_mask, stx.stx_mnt_id))
}

/// The mount id a SUCCESSFUL `statx` reported, or `None` when its `stx_mask` left the
/// `STATX_MNT_ID` bit unset (PURE — the below-5.8 belt decision, split out so it is
/// row-testable without a live fd). This distinguishes only mask-present from
/// mask-absent; a `statx` syscall failure never reaches here (the caller propagates it
/// as `Err`), so a `None` from this function is ALWAYS the legitimate mask-absent belt,
/// never a swallowed error.
#[cfg(all(target_os = "linux", not(miri)))]
fn mnt_id_from_mask(stx_mask: u32, stx_mnt_id: u64) -> Option<u64> {
  use rustix::fs::StatxFlags;
  (stx_mask & StatxFlags::MNT_ID.bits() != 0).then_some(stx_mnt_id)
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
      // runs below 5.8, so a SUCCESSFUL read may be `None` (statx reports no mount id
      // there) and the core falls back to the device check; a statx SYSCALL failure,
      // by contrast, is a spawn failure — never a silent `None` that would disable the
      // fence (the barrier already required statx to work). Read once here, carried on
      // `RootMeta` like `root_dev`.
      let root_mnt_id = root_mount_id(root_fd).map_err(|err| SourceError::RootUnavailable {
        root: canonical.clone(),
        source: err.into(),
      })?;
      let identity = RootIdentity::new(stat.st_dev, stat.st_ino.into());
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
      if RootIdentity::new(pinned.st_dev, pinned.st_ino.into()) != identity {
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
      if RootIdentity::new(live.dev(), live.ino().into()) != identity {
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

  /// What one control batch came back with: the arms' replies, and — told apart
  /// from them — whether the READER is what produced them.
  ///
  /// The replies alone cannot carry the second fact. A batch with no arms has no
  /// replies either, so one the reader served and one whose reader died both
  /// come back as an empty vector; and the empty batch is exactly the
  /// ordering-proof round trip, whose entire meaning is that the reader reached
  /// it and cut its kernel queue onto the lane first. An empty vector must not
  /// mean both "the cut happened" and "nobody was left to cut", so
  /// [`answered`](Self::answered) carries that apart from the payload.
  #[derive(Debug)]
  pub(crate) struct BatchOutcome {
    /// Index-aligned to the batch's `Arm` entries, in order — a `Disarm`
    /// produces none. Filled on EVERY path, answered or not: a parked
    /// registration is owed its watch result whether or not the reader survived.
    pub(crate) replies: Vec<ArmReply>,
    /// Whether the reader itself answered this batch. False means the reader was
    /// already gone or died before replying, so the batch's ops are not known to
    /// have run and nothing about the ordering of the stream may be inferred
    /// from its return.
    pub(crate) answered: bool,
  }

  impl ControlPort {
    /// Enqueues one batch of arms/disarms, arranging for `deliver` to receive
    /// the arms' outcomes in order (index-aligned to the `Arm` entries — disarms
    /// produce no reply) together with whether the reader answered at all. One
    /// message, one potential wake, N results: the reader executes the whole
    /// batch in a single pass between reads. A dead reader answers `Failed(Io)`
    /// for every arm — the scope's stream death carries the real signal.
    ///
    /// RETURNS AS SOON AS THE BATCH IS ENQUEUED, and never waits for the reader.
    /// That wait has no bound: a reader already admitted into a syscall against a
    /// wedged filesystem observes nothing — not this batch, not its own shutdown
    /// — until the kernel returns. A caller that held its thread across it would
    /// spend one unit of whatever executor dispatched the batch for as long as
    /// the filesystem stays wedged, and a driver can have arbitrarily many such
    /// batches outstanding at once, one per transport it has retired out from
    /// under a stuck reader. `deliver` is instead invoked by whoever ends up
    /// OWNING the batch — the reader when it replies, or the destruction of a
    /// message no reader survived to serve (see [`BatchReply`]).
    ///
    /// Enqueue-then-conditional-wake is the wake-elision contract: the message
    /// lands on the channel BEFORE [`WakeState::wake_if_parked`] checks the
    /// park flag, so a reader about to block cannot miss it (the lost-wakeup
    /// argument lives on [`WakeState`]).
    pub(crate) fn dispatch(
      &self,
      ops: Vec<ControlOp>,
      deliver: impl FnOnce(BatchOutcome) + Send + 'static,
    ) {
      let arm_count = ops
        .iter()
        .filter(|op| matches!(op, ControlOp::Arm(_)))
        .count();
      let reply = BatchReply::new(arm_count, deliver);
      if let Err(mpsc::SendError(undelivered)) = self.control.send(Control::Batch { ops, reply }) {
        // The reader is already gone. Destroying the message answers the batch
        // through the sink's own drop, so a closed channel needs no separate
        // reply path — and cannot leave an arm unanswered by taking one.
        drop(undelivered);
        return;
      }
      self.wake.wake_if_parked();
    }

    /// [`dispatch`](Self::dispatch) awaited on the CALLING thread, for the
    /// callers that own one outright and have no completion to park on: a
    /// replace's pre-arm, and the single-op smoke helpers.
    ///
    /// Every batch the driver emits on behalf of a scope goes through
    /// `dispatch` instead. The wait below is the unbounded one, so a caller
    /// reaching for this is asserting that its thread is its own to spend.
    pub(crate) fn batch(&self, ops: Vec<ControlOp>) -> BatchOutcome {
      let arm_count = ops
        .iter()
        .filter(|op| matches!(op, ControlOp::Arm(_)))
        .count();
      let (reply_tx, reply_rx) = mpsc::sync_channel(1);
      self.dispatch(ops, move |outcome| {
        let _ = reply_tx.send(outcome);
      });
      // The sink answers on every path, its own destruction included, so the
      // receive cannot come back empty; the fallback keeps the reply contract
      // total rather than relying on that.
      reply_rx.recv().unwrap_or_else(|_| dead_batch(arm_count))
    }

    /// Installs (or aliases) one kernel watch. A single-entry [`batch`]; the
    /// smoke suites arm one watch at a time.
    ///
    /// [`batch`]: Self::batch
    #[cfg(test)]
    pub(crate) fn add_watch(&self, request: AnchorRequest) -> ArmReply {
      self
        .batch(vec![ControlOp::Arm(request)])
        .replies
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

    /// A port onto an explicit control channel, standing in for a live source's
    /// so a test can play the reader — including by dying like one.
    #[cfg(all(test, target_os = "linux", not(miri)))]
    pub(crate) fn detached(control: mpsc::Sender<Control>, wake: Arc<WakeState>) -> Self {
      Self { control, wake }
    }
  }

  /// The answer for a batch no reader ran: `Failed(Io)` for every arm it
  /// carried, marked as never answered. Each arm is still replied to, because a
  /// Monitor node parked on a watch acknowledgement must be released whichever
  /// way the reader went; `answered` is what keeps those replies from reading as
  /// work the reader performed.
  fn dead_batch(arm_count: usize) -> BatchOutcome {
    BatchOutcome {
      replies: (0..arm_count)
        .map(|_| ArmReply {
          outcome: WatchOutcome::Failed(WatchError::Io),
          anchor: None,
        })
        .collect(),
      answered: false,
    }
  }

  /// The sink one dispatched control batch's outcome leaves through, exactly
  /// once, from whoever ends up OWNING the batch.
  ///
  /// Ownership is what carries the obligation, which is why the obligation
  /// cannot be dropped on the floor. A batch no reader survives to dequeue is
  /// destroyed along with the control channel, and a reader that unwinds holding
  /// one destroys it on the way out; this type's `Drop` is what turns either
  /// destruction into the refusal every arm's caller is parked on. So a
  /// dispatcher needs no dead-reader path of its own, and no registration can be
  /// stranded by a reader that died between the send and the reply.
  pub(crate) struct BatchReply {
    /// The batch's `Arm` count. Kept here because the ops are gone by the time
    /// an un-dequeued message drops, and the refusals must still be one per arm
    /// so they stay index-aligned to them.
    arm_count: usize,
    /// Taken by whichever of [`answer`](Self::answer) and the drop runs first;
    /// the other then finds `None` and delivers nothing.
    deliver: Option<Box<dyn FnOnce(BatchOutcome) + Send>>,
  }

  impl BatchReply {
    pub(crate) fn new(
      arm_count: usize,
      deliver: impl FnOnce(BatchOutcome) + Send + 'static,
    ) -> Self {
      Self {
        arm_count,
        deliver: Some(Box::new(deliver)),
      }
    }

    /// The READER's own answer: `replies` are index-aligned to the batch's `Arm`
    /// entries, and the reader cut its kernel queue onto the lane before
    /// reaching here, so this — and only this — is the end a caller may read an
    /// ordering proof out of.
    pub(crate) fn answer(mut self, replies: Vec<ArmReply>) {
      if let Some(deliver) = self.deliver.take() {
        deliver(BatchOutcome {
          replies,
          answered: true,
        });
      }
    }
  }

  impl Drop for BatchReply {
    fn drop(&mut self) {
      // Nobody answered: the sink is being destroyed with a message no reader
      // dequeued, or with a reader that unwound holding it — possibly part-way
      // through the cut it owed the batch. Nothing it would have done is known to
      // have happened, so the outcome reports that BESIDE the replies rather than
      // through them: folded in, the fact would vanish on the arm-less
      // ordering-proof round trip, whose served and unserved returns are one
      // identical empty vector, and a barrier would certify clean over a cut that
      // never ran.
      if let Some(deliver) = self.deliver.take() {
        deliver(dead_batch(self.arm_count));
      }
    }
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

    /// Stops the reader and closes the instance, JOINING the reader thread —
    /// so nothing of this source is still running when it returns.
    ///
    /// The reader exits at its next wake, which on a healthy filesystem costs
    /// one in-flight read + decode. It is not a bound: the flag and the
    /// `Shutdown` message are both observed only BETWEEN operations, so a reader
    /// already admitted into an arm's `inotify_add_watch` against a wedged mount
    /// returns when the kernel says so and this waits exactly that long. The
    /// driver therefore never performs this join on its blocking pool.
    pub(crate) fn shutdown(mut self) {
      self.teardown();
    }

    fn teardown(&mut self) {
      let Some(thread) = self.thread.take() else {
        return;
      };
      // Raise the shutdown flag BEFORE the control send, so a reader partway
      // through a long cold-enumerate `Control::Batch` observes it between ops and
      // preempts (failing the remaining arms) rather than executing the whole batch
      // before it dequeues this `Shutdown`. The message + wake remain the correctness
      // floor; the flag only makes teardown prompt under an arm storm.
      self.port.wake.request_shutdown();
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
