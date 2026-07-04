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

use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

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

/// Runs the fanotify precondition probe on the PINNED root fd (design §5 rows
/// 2–5; row 1, the statfs locality allowlist, is the shared gate the dispatcher
/// runs once before selection). Both live-state rows ground on `root_fd`, never a
/// pathname: the `FAN_MARK_FILESYSTEM` mark is installed fd-relative
/// (`fanotify_mark(ffd, …, root_fd, NULL)`) so it marks the superblock of exactly
/// the object the dispatcher pinned — a path swap for this one call can no longer
/// mark the wrong superblock — and the handle row encodes from the same fd
/// (`AT_EMPTY_PATH`). On success the returned fd is init'd AND marked; the
/// fanotify source reuses it. On failure the [`ProbeStage`] names the first stage
/// that failed; the caller decides fall-back vs typed error.
///
/// Every fd opened here is closed before returning on any failure path — a
/// probe never leaks the instance it was testing.
pub(crate) fn probe_fanotify(root_fd: BorrowedFd<'_>) -> Result<ProbedFanotify, ProbeStage> {
  // Row 2/3: create the instance with the full composite. EINVAL/EPERM here is
  // the kernel/filesystem being too old, or the class being unavailable.
  let fd = create_instance().map_err(|()| ProbeStage::Init)?;

  // Row 4 — THE discriminator: the FILESYSTEM mark. Unprivileged init with FID
  // flags succeeds on modern kernels; this is what returns EPERM without
  // CAP_SYS_ADMIN (container-validated). The fd drops (closing the instance) on
  // failure via the early return.
  if mark_filesystem(&fd, root_fd).is_err() {
    return Err(ProbeStage::Mark);
  }

  // Row 5: the root must be handle-exportable, or the FID map cannot be seeded.
  // Encoded from the pinned fd, so the probe's success proves the SAME object the
  // mark covers can export a handle.
  if !root_exports_handle(root_fd) {
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
/// mask, installed FD-RELATIVE on the pinned root. `Err(())` on any refusal
/// (EPERM is the privilege discriminator).
///
/// A NULL pathname with a real dirfd makes `fanotify_mark` operate on the object
/// the dirfd refers to, so the mark scopes to the superblock of exactly the
/// object the dispatcher pinned — never a superblock a transient path swap could
/// redirect this one call to.
fn mark_filesystem(fd: &OwnedFd, root_fd: BorrowedFd<'_>) -> Result<(), ()> {
  // SAFETY: fd is the owned fanotify instance; root_fd is a live directory fd;
  // a NULL pathname with a valid dirfd marks the object the dirfd refers to.
  let rc = unsafe {
    libc::fanotify_mark(
      fd.as_raw_fd(),
      libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
      FAN_MARK_MASK,
      root_fd.as_raw_fd(),
      std::ptr::null(),
    )
  };
  if rc != 0 { Err(()) } else { Ok(()) }
}

/// Row 5: whether the PINNED root can actually encode a file handle — the FID
/// map's seeding precondition. Runs the SAME dynamically-sized fd-relative
/// [`encode_handle_at`](super::fanotify::encode_handle_at) the seed walk uses, on
/// the same object the mark just covered, so the probe's success is the real
/// handle round-trip succeeding at the filesystem's TRUE handle size, not a
/// weaker "an EOVERFLOW proves a handle exists" signal: an oversized-handle
/// filesystem (larger than `MAX_HANDLE_SZ`) answered `EOVERFLOW` before, which
/// the old row accepted as proof — yet the fixed-buffer seed then failed to
/// encode and turned the whole spawn fatal. Retrying at the kernel-reported size
/// in both places keeps the probe and the seed in lockstep.
///
/// A failure here (a non-exporting filesystem, a permission/transient error, or
/// the double-`EOVERFLOW` broken-kernel case) falls to inotify under `Auto`, or
/// surfaces the typed probe-stage error under forced `Fanotify` — never a
/// live-but-empty source (an admitted root the FID map can never seed, which
/// would drop every event as outside-root).
fn root_exports_handle(root_fd: BorrowedFd<'_>) -> bool {
  super::fanotify::encode_handle_at(root_fd).is_some()
}
