//! The `Backend::Auto` selection probe (design §5), executed inside the
//! pre-start barrier — once per root, before any stream goes live, never
//! retried.
//!
//! The probe is the fanotify-FILESYSTEM precondition test AND its bootstrap:
//! on success it leaves the fanotify instance already created and the
//! superblock mark already installed, and hands that live fd back so the
//! fanotify source reuses it (no second `fanotify_init`, no double mark).
//! Selection:
//!
//! - `Backend::Auto` runs the probe and falls back to inotify at the first
//!   failing stage.
//! - `Backend::Fanotify` runs the same probe but surfaces the first failure as
//!   a typed [`SourceError::BackendProbeFailed`] instead of falling back.
//! - `Backend::Inotify` skips the probe entirely.
//!
//! Probe order (design §5, container-validated correction embedded): an
//! unprivileged `fanotify_init` WITH the FID flags succeeds on modern kernels,
//! so the `FAN_MARK_FILESYSTEM` mark — not the init — is the real privilege
//! discriminator (it is what returns `EPERM` without `CAP_SYS_ADMIN`).

use std::{
  os::{
    fd::{AsRawFd, FromRawFd, OwnedFd},
    unix::ffi::OsStrExt,
  },
  path::Path,
};

use super::{
  super::{ProbeStage, SourceError},
  fanotify::{FAN_INIT_FLAGS, FAN_MARK_MASK},
};

/// A live fanotify instance whose superblock mark is already installed — the
/// probe's success artifact, reused by the fanotify source's spawn so the mark
/// is never installed twice.
pub(crate) struct ProbedFanotify {
  /// The created, `FAN_MARK_FILESYSTEM`-marked fanotify fd.
  pub(crate) fd: OwnedFd,
}

/// Runs the fanotify precondition probe on the canonical root (design §5 rows
/// 2–5; row 1, the statfs locality allowlist, is the barrier step each source
/// already runs). On success the returned fd is init'd AND marked — the
/// fanotify source reuses it. On failure the [`ProbeStage`] names the first
/// stage that failed; the caller decides fall-back vs typed error.
///
/// Every fd opened here is closed before returning on any failure path — a
/// probe never leaks the instance it was testing.
pub(crate) fn probe_fanotify(root: &Path) -> Result<ProbedFanotify, ProbeStage> {
  // Row 2/3: create the instance with the full composite. EINVAL/EPERM here is
  // the kernel/filesystem being too old, or the class being unavailable.
  let fd = create_instance().map_err(|()| ProbeStage::Init)?;

  // Row 4 — THE discriminator: the FILESYSTEM mark. Unprivileged init with FID
  // flags succeeds on modern kernels; this is what returns EPERM without
  // CAP_SYS_ADMIN (container-validated). The fd drops (closing the instance) on
  // failure via the early return.
  if mark_filesystem(&fd, root).is_err() {
    return Err(ProbeStage::Mark);
  }

  // Row 5: the root must be handle-exportable, or the FID map cannot be seeded.
  if !root_exports_handle(root) {
    return Err(ProbeStage::Handle);
  }

  Ok(ProbedFanotify { fd })
}

/// Maps a probe failure to the forced-`Fanotify` spawn error (design §5: a
/// forced backend surfaces the failure typed rather than falling back).
pub(crate) fn probe_error(stage: ProbeStage) -> SourceError {
  SourceError::BackendProbeFailed { stage }
}

/// Row 2/3: `fanotify_init` with the golden composite. `Err(())` on any
/// refusal — the probe only needs "did it work", not the errno.
fn create_instance() -> Result<OwnedFd, ()> {
  // SAFETY: plain syscall; the returned fd is owned exclusively here.
  let fd = unsafe {
    libc::fanotify_init(
      FAN_INIT_FLAGS | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
      (libc::O_RDONLY | libc::O_LARGEFILE) as libc::c_uint,
    )
  };
  if fd < 0 {
    return Err(());
  }
  // SAFETY: fd is a fresh, owned descriptor.
  Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Row 4: `FAN_MARK_ADD | FAN_MARK_FILESYSTEM` with the dirent + self-event
/// mask. `Err(())` on any refusal (EPERM is the privilege discriminator).
fn mark_filesystem(fd: &OwnedFd, root: &Path) -> Result<(), ()> {
  let Ok(cpath) = std::ffi::CString::new(root.as_os_str().as_bytes()) else {
    return Err(());
  };
  // SAFETY: cpath is NUL-terminated; fd is the owned fanotify instance.
  let rc = unsafe {
    libc::fanotify_mark(
      fd.as_raw_fd(),
      libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
      FAN_MARK_MASK,
      libc::AT_FDCWD,
      cpath.as_ptr(),
    )
  };
  if rc != 0 { Err(()) } else { Ok(()) }
}

/// Row 5: whether the root's filesystem can actually encode a file handle for
/// it — the FID map's seeding precondition. This runs the SAME dynamically-sized
/// [`encode_handle`](super::fanotify::encode_handle) the seed walk uses, so the
/// probe's success is the real handle round-trip succeeding at the filesystem's
/// TRUE handle size, not a weaker "an EOVERFLOW proves a handle exists" signal:
/// an oversized-handle filesystem (larger than `MAX_HANDLE_SZ`) answered
/// `EOVERFLOW` before, which the old row accepted as proof — yet the fixed-buffer
/// seed then failed to encode and turned the whole spawn fatal. Retrying at the
/// kernel-reported size in both places keeps the probe and the seed in lockstep.
///
/// A failure here (a non-exporting filesystem, a permission/transient error, or
/// the double-`EOVERFLOW` broken-kernel case) falls to inotify under `Auto`, or
/// surfaces the typed probe-stage error under forced `Fanotify` — never a
/// live-but-empty source (an admitted root the FID map can never seed, which
/// would drop every event as outside-root).
fn root_exports_handle(root: &Path) -> bool {
  super::fanotify::encode_handle(root).is_some()
}
