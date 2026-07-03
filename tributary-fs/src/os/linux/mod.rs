//! The Linux backends: inotify (descending) and, later, fanotify-FILESYSTEM
//! (kernel-recursive), selected per root by `Backend::Auto`.
//!
//! Pure machinery (decode tables, `wd` bookkeeping, event attribution, the
//! mountinfo parser) compiles everywhere tests run, mirroring the
//! transport/fsevent precedent; the FFI Source layer (the per-root fd, its
//! reader thread, and the syscalls) is `cfg(all(target_os = "linux",
//! not(miri)))`.
//!
//! The platform seam still selects the `unsupported` stub on Linux: the
//! driver's lowering speaks [`RawOsEvent`](super::RawOsEvent) until the
//! descending core lands, at which point `PlatformEvent` rebinds to
//! [`RawLinuxEvent`] and the seam flips here.
// The descending core is this module's consumer; until it lands the Source
// layer is exercised only by its own suites (the container runs them live).
#![allow(dead_code)]

pub(crate) mod inotify;

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

use tributary_proto::WatchId;

pub(crate) use inotify::decode::RawInotifyEvent;
use inotify::table::WdTable;

/// The decoded Linux event payload — the platform's transport `E` once the
/// seam flips. The fanotify arm joins when that backend lands.
///
/// Seam contract: attribution happens AT DECODE — the reader resolves each
/// record's `wd` through its [`WdTable`] while the table is still in lockstep
/// with the record stream, so events cross the channel already carrying every
/// Monitor watch they address ([`anchors`](Self::Inotify::anchors), one per
/// alias of the underlying inode). The core fans the record out per anchor;
/// it never sees a `wd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RawLinuxEvent {
  /// One decoded inotify record with its resolved anchors.
  Inotify {
    /// The Monitor watches this record addresses (aliases fan out).
    anchors: Vec<WatchId>,
    /// The decoded kernel record.
    event: RawInotifyEvent,
  },
}

impl RawLinuxEvent {
  /// The anchors and record, if this is an inotify event.
  pub(crate) fn as_inotify(&self) -> Option<(&[WatchId], &RawInotifyEvent)> {
    match self {
      Self::Inotify { anchors, event } => Some((anchors.as_slice(), event)),
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

// The descending core (and the container smoke suites) consume the Source;
// until the seam flips the lib build sees the re-export as unused.
#[cfg(all(target_os = "linux", not(miri)))]
#[allow(unused_imports)]
pub(crate) use source::{AnchorRequest, ArmReply, Source, SourceHandle};

#[cfg(all(target_os = "linux", not(miri)))]
mod source {
  //! The inotify Source: the per-root fd, its reader thread, and the spawn
  //! barrier. Watches are NOT armed at spawn — the driver arms the root (and
  //! every descendant) through the control path, so arm handling is uniform
  //! and the Monitor's watch-result contract drives everything.

  use std::{
    ffi::OsString,
    fs, io,
    os::{fd::OwnedFd, unix::fs::MetadataExt},
    sync::{Arc, mpsc},
    thread::JoinHandle,
  };

  use tributary_proto::{WatchError, WatchId};

  use super::{
    super::{RootIdentity, RootMeta, SourceConfig, SourceError, transport},
    WatchOutcome, fs_type_is_remote, mounts_under,
  };
  use crate::os::MAX_EXCLUSIONS;

  use super::inotify::reader::{self, Control, ReaderShared};

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
    /// Barrier order mirrors the macOS bracket: refuse remote/virtual
    /// filesystems, canonicalize, capture the root identity and mount seed
    /// strictly before the fd exists, then re-stat once the reader is live —
    /// a root replaced across the gap is torn down and rejected, never
    /// committed.
    pub(crate) fn spawn(
      config: SourceConfig,
    ) -> Result<(SourceHandle, super::super::EventReceiver, RootMeta), SourceError> {
      if config.roots.is_empty() {
        return Err(SourceError::NoRoots);
      }
      if config.exclusions.len() > MAX_EXCLUSIONS {
        return Err(SourceError::TooManyExclusions {
          supplied: config.exclusions.len(),
        });
      }

      let supplied = &config.roots[0];
      let canonical =
        fs::canonicalize(supplied).map_err(|source| SourceError::RootUnavailable {
          root: supplied.clone(),
          source,
        })?;

      if is_remote_fs(&canonical)? {
        return Err(SourceError::RootUnavailable {
          root: canonical,
          source: io::Error::new(
            io::ErrorKind::Unsupported,
            "network and virtual filesystems deliver no reliable events",
          ),
        });
      }

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

      let (queue_tx, queue_rx) = async_channel::unbounded();
      let shared = Arc::new(ReaderShared {
        queue: queue_tx,
        transport: transport::TransportState::new(config.channel_capacity.get()),
      });

      let fd = reader::create_instance()?;
      let (wake_tx, wake_rx) = reader::wake_pipe()?;
      let (control_tx, control_rx) = mpsc::channel();
      let thread = reader::start(fd, wake_rx, control_rx, Arc::clone(&shared));

      let handle = SourceHandle {
        control: control_tx,
        wake: wake_tx,
        thread: Some(thread),
      };

      // The post-live half of the identity bracket: nothing is watched yet,
      // but the re-stat proves the object survived the barrier→reader gap, so
      // the registry identity and the (about-to-be-armed) stream anchor name
      // one object.
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
        backend: super::super::BackendKind::Inotify,
      };
      Ok((handle, queue_rx, meta))
    }
  }

  /// Whether the filesystem holding `path` is a refused remote/virtual kind.
  fn is_remote_fs(path: &std::path::Path) -> Result<bool, SourceError> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    let cpath = std::ffi::CString::new(bytes).map_err(|_| SourceError::RootUnavailable {
      root: path.to_path_buf(),
      source: io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"),
    })?;
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: cpath is a valid NUL-terminated path and buf is a zeroed
    // statfs the call fully initializes on success.
    let rc = unsafe { libc::statfs(cpath.as_ptr(), &mut buf) };
    if rc != 0 {
      return Err(SourceError::RootUnavailable {
        root: path.to_path_buf(),
        source: io::Error::last_os_error(),
      });
    }
    Ok(fs_type_is_remote(buf.f_type as i64))
  }

  /// A live inotify source. Dropping it tears the reader down; prefer
  /// [`shutdown`](Self::shutdown) at an orderly exit.
  pub(crate) struct SourceHandle {
    control: mpsc::Sender<Control>,
    wake: OwnedFd,
    thread: Option<JoinHandle<()>>,
  }

  impl SourceHandle {
    /// Installs (or aliases) a kernel watch for the request's Monitor watch.
    /// Executed by the reader thread — the fd and the `wd` table are
    /// single-threaded by construction. Blocks until the reader replies;
    /// callers run it on the blocking pool.
    pub(crate) fn add_watch(&self, request: AnchorRequest) -> ArmReply {
      let (reply_tx, reply_rx) = mpsc::sync_channel(1);
      if self
        .control
        .send(Control::AddWatch {
          request,
          reply: reply_tx,
        })
        .is_err()
      {
        return ArmReply {
          outcome: WatchOutcome::Failed(WatchError::Io),
          anchor: None,
        };
      }
      reader::wake(&self.wake);
      reply_rx.recv().unwrap_or(ArmReply {
        outcome: WatchOutcome::Failed(WatchError::Io),
        anchor: None,
      })
    }

    /// Removes `anchor` from attribution, issuing the kernel removal when the
    /// last alias drains. Blocks until the reader acknowledges.
    pub(crate) fn remove_watch(&self, anchor: WatchId) {
      let (reply_tx, reply_rx) = mpsc::sync_channel(1);
      if self
        .control
        .send(Control::RemoveWatch {
          anchor,
          reply: reply_tx,
        })
        .is_ok()
      {
        reader::wake(&self.wake);
        let _ = reply_rx.recv();
      }
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
      let _ = self.control.send(Control::Shutdown);
      reader::wake(&self.wake);
      let _ = thread.join();
    }
  }

  impl Drop for SourceHandle {
    fn drop(&mut self) {
      self.teardown();
    }
  }
}
