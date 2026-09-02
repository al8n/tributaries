//! The macOS FSEvents backend.
//!
//! One native `FSEventStream` per spawn, callbacks on a private serial
//! dispatch queue, full decode inside the callback (only owned Rust data ever
//! crosses the channel), and a teardown that is provably callback-free before
//! any state is released: the serial queue totally orders a synchronous
//! Stop+Invalidate block against every callback, and the context release hook
//! ties the shared state's lifetime to the stream itself by refcount.

mod decode;
mod ffi;
#[cfg(test)]
mod tests;

use std::{
  fs, io,
  os::{
    fd::AsRawFd,
    unix::fs::{MetadataExt, OpenOptionsExt},
  },
  path::PathBuf,
  sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
  },
};

use dispatch2::{DispatchQueue, DispatchRetained};
use objc2_core_services::{
  FSEventStreamInvalidate, FSEventStreamRef, FSEventStreamRelease, FSEventStreamStop,
  kFSEventStreamEventIdSinceNow,
};

use super::{
  EventReceiver, MAX_EXCLUSIONS, Quiesce, ResumeToken, RootMeta, SourceConfig, SourceError,
  transport::{self, TransportState},
};

/// The state the event callback reads. Owned jointly by the [`SourceHandle`]
/// and — via the context release hook — by the stream itself, so it outlives
/// whichever dies last.
pub(super) struct CallbackShared {
  /// The source's single ordered queue (unbounded; the transport budget
  /// bounds its memory).
  pub(super) queue: async_channel::Sender<super::SourceMessage>,
  /// The batch budget and signal dedups.
  pub(super) transport: TransportState,
  /// Turns the callback into a no-op the moment teardown begins (belt; the
  /// on-queue Stop+Invalidate barrier is the suspenders).
  pub(super) stopped: AtomicBool,
  /// Set after a callback panic; the stream delivers nothing further.
  pub(super) poisoned: AtomicBool,
  /// The resume point the DRIVER has acknowledged. The callback only stages a
  /// candidate onto each batch; nothing here advances until that batch is
  /// ingested.
  pub(super) resume: Arc<transport::ResumeShared>,
  /// The device whose journal scopes every id this stream reports — carried
  /// here because the callback mints the candidate token.
  pub(super) device_uuid: Option<[u8; 16]>,
  /// The journal's id counter wrapped; every id it ever minted is invalid for
  /// resume, whether acknowledged or not.
  pub(super) ids_wrapped: AtomicBool,
}

/// The raw stream pointer.
///
/// Control calls (`SetDispatchQueue`/`Start`/`Stop`/`Invalidate`/`Release`)
/// have no thread affinity — the dispatch-queue delivery model decouples the
/// callback venue from the control venue — so the pointer may move between
/// threads. Deliberately NOT `Sync`: every use is `&mut`/consuming.
#[derive(Clone, Copy)]
struct StreamPtr(FSEventStreamRef);

// SAFETY: see the type docs — FSEvents control calls are venue-agnostic, and
// the handle serializes all uses.
unsafe impl Send for StreamPtr {}

/// The spawn entry point of the FSEvents backend.
pub(crate) struct Source;

impl Source {
  /// Creates, schedules, and starts one FSEvents stream over
  /// `config.roots`, delivering decoded batches and in-band loss/death
  /// signals on the returned queue, in source order.
  ///
  /// Trust- and lifecycle-bearing metadata follows the BRACKET rule: capture
  /// before start, prove after live. The canonical root bytes, the root
  /// identity, the root device, the mount seed, and the device UUID are read
  /// strictly BEFORE the stream starts, so nothing can postdate an event the
  /// queue will ever carry; once the stream is LIVE the root is re-statted,
  /// and the spawn commits only if the object — its `(dev, ino)` and its
  /// directory-ness — is unchanged, so the stream anchor, the registry
  /// identity, and every disjointness decision provably name one object
  /// across start. A mismatch tears the just-started stream down and rejects
  /// before anything reaches the caller. The kind, the identity and the
  /// volume's LOCALITY all come off one opened description of the root, so a
  /// swap cannot answer them separately. Per datum: the mount seed claims no
  /// authority (see [`RootMeta`] — the driver's post-live refresh installs
  /// it); the root device is re-proven by the same post-live stat (identity
  /// equality includes it); the device UUID only ever SCOPES a resume token, a
  /// mismatch degrading to live-only; exclusions only ever reduce coverage; the
  /// ancestor identities are read strictly AFTER the stream is live, so any
  /// ancestor change past that read fires the stream's own root-changed
  /// death (`WatchRoot` covers every ancestor) instead of leaving a live
  /// scope's containment chain silently stale.
  ///
  /// On any partial failure the stream is invalidated and released before the
  /// error returns: a handle existing means created + scheduled + started.
  pub(crate) fn spawn(
    config: SourceConfig,
  ) -> Result<(SourceHandle, EventReceiver, RootMeta), SourceError> {
    if config.roots.is_empty() {
      return Err(SourceError::NoRoots);
    }
    if config.exclusions.len() > MAX_EXCLUSIONS {
      return Err(SourceError::TooManyExclusions {
        supplied: config.exclusions.len(),
      });
    }

    // Resolve every root through realpath AND the same CoreFoundation
    // filesystem-representation transform the event decode uses, so prefix
    // comparison can never drift on Unicode normalization (FSEvents reports
    // decomposed bytes) or on a symlinked root (watching the symlink itself
    // would deliver nothing).
    let mut roots = Vec::with_capacity(config.roots.len());
    for root in &config.roots {
      let canonical = fs::canonicalize(root).map_err(|source| SourceError::RootUnavailable {
        root: root.clone(),
        source,
      })?;
      let canonical =
        ffi::fs_representation_of(&canonical).ok_or_else(|| SourceError::RootUnavailable {
          root: root.clone(),
          source: io::Error::new(
            io::ErrorKind::InvalidData,
            "the path has no filesystem representation",
          ),
        })?;
      roots.push(canonical);
    }
    // The root's own description, opened ONCE, so the kind, the identity and
    // the volume's locality become three reads of ONE object instead of three
    // path resolutions a mount swap could answer differently.
    //
    // `O_SEARCH` asks for TRAVERSAL, not readability — a watch root the caller
    // may enter but not list is still watchable, and a root without even the
    // execute bit has nothing the driver could probe inside it. Its
    // `O_DIRECTORY` half folds the kind recheck into the open, which belongs to
    // the same pre-start barrier as the device and mount reads: canonicalization
    // already re-resolved the root, so a path retargeted from a directory to a
    // file since the caller's own check fails here, before any stream exists.
    // `O_NOFOLLOW` refuses a final component that became a symlink after
    // canonicalization (a swap, by definition), and `O_NONBLOCK` keeps a fifo
    // or device named as a root from parking the spawn inside `open`.
    let root_fd = fs::OpenOptions::new()
      .read(true)
      .custom_flags(libc::O_SEARCH | libc::O_NOFOLLOW | libc::O_NONBLOCK)
      .open(&roots[0])
      .map_err(|source| match source.raw_os_error() {
        Some(libc::ENOTDIR) => SourceError::NotADirectory {
          root: roots[0].clone(),
        },
        _ => SourceError::RootUnavailable {
          root: roots[0].clone(),
          source,
        },
      })?;
    let root_meta = root_fd
      .metadata()
      .map_err(|source| SourceError::RootUnavailable {
        root: roots[0].clone(),
        source,
      })?;
    // Belt to `O_DIRECTORY`'s suspenders: the kind the description reports is
    // the kind the identity below is minted for.
    if !root_meta.is_dir() {
      return Err(SourceError::NotADirectory {
        root: roots[0].clone(),
      });
    }
    // The locality gate (design §5 row 1). FSEvents' journal records what THIS
    // host's VFS performed, so a change another client makes to a network
    // volume never reaches fseventsd and never reaches us — a silent,
    // unrecoverable gap with no loss signal to degrade through. Refuse the root
    // instead of publishing a coverage claim the volume cannot honor; the
    // read rides the same open as the identity capture, so the verdict
    // provably describes the volume the bracketed root object lives on.
    let flags = volume_flags(&root_fd).map_err(|source| SourceError::RootUnavailable {
      root: roots[0].clone(),
      source,
    })?;
    if let Some(refusal) = remote_volume_refusal(&roots[0], flags) {
      return Err(refusal);
    }
    // Every fact the description had to prove is proven; holding it further
    // would only pin the volume against an unmount for the rest of the spawn.
    drop(root_fd);
    let root_dev = root_meta.dev() as libc::dev_t;
    let identity = super::RootIdentity::new(root_meta.dev(), root_meta.ino().into());
    // The mount seed and device UUID are part of the pre-start barrier: taken
    // here they cannot postdate any event. The seed is trust-reducing only —
    // a mount in the read→start gap would be in neither the seed nor the
    // event stream, so authority waits for the driver's post-live refresh.
    let mounts = mounts_under(&roots[0]).unwrap_or_default();
    let device_uuid = ffi::device_uuid(root_dev);

    let (queue_tx, queue_rx) = async_channel::unbounded();
    let shared = Arc::new(CallbackShared {
      queue: queue_tx,
      transport: TransportState::new(config.channel_capacity.get()),
      stopped: AtomicBool::new(false),
      poisoned: AtomicBool::new(false),
      resume: Arc::default(),
      device_uuid,
      ids_wrapped: AtomicBool::new(false),
    });

    let queue = DispatchQueue::new("tributary-fs.fsevents", None);
    #[cfg(debug_assertions)]
    ffi::mark_stream_queue(&queue);

    // A resume point is honored only against the device that minted it: the
    // journal id space is per-device, so replaying an id from another volume
    // (a cross-volume replace) would name unrelated history. The token answers
    // that itself; a foreign device, an unknowable one, or another backend's
    // token falls back to live-only — the commit `Rescan` still covers the
    // window, so the fallback loses nothing but density.
    let since = config
      .since
      .and_then(|token| token.fsevents_since(device_uuid))
      .unwrap_or(kFSEventStreamEventIdSinceNow);
    let stream = ffi::create_scheduled_stream(&shared, &roots, since, config.latency, &queue)?;

    if !config.exclusions.is_empty() && !ffi::set_exclusions(stream.0, &config.exclusions) {
      ffi::invalidate_and_release(stream.0);
      return Err(SourceError::ExclusionRejected);
    }

    if !ffi::start(stream.0) {
      ffi::invalidate_and_release(stream.0);
      return Err(SourceError::StartFailed);
    }

    // From here the stream is live, so failures tear it down through the one
    // proven teardown path (the handle) before rejecting. These teardowns
    // DISCARD the quiescence verdict, and only they may: the spawn is failing,
    // so no scope exists, no obligation was ever counted and there is no
    // terminal for a verdict to ride.
    let handle = SourceHandle {
      stream: Some(stream),
      queue: Some(queue),
      shared,
    };

    // The post-live half of the identity bracket: an object that still
    // matches the pre-start capture while the stream is delivering matched
    // it across the entire capture→start gap — the stream anchor and the
    // registry identity provably name one object.
    let live = match fs::metadata(&roots[0]) {
      Ok(meta) => meta,
      Err(source) => {
        let _ = handle.shutdown();
        return Err(SourceError::RootUnavailable {
          root: roots[0].clone(),
          source,
        });
      }
    };
    if !live.is_dir() {
      let _ = handle.shutdown();
      return Err(SourceError::NotADirectory {
        root: roots[0].clone(),
      });
    }
    if super::RootIdentity::new(live.dev(), live.ino().into()) != identity {
      let _ = handle.shutdown();
      return Err(SourceError::RootReplaced {
        root: roots[0].clone(),
      });
    }
    // The ancestor identities feed root-disjointness containment: byte
    // comparison cannot see that two spellings reach one object on a
    // case-insensitive volume, but `(dev, ino)` can. Read strictly AFTER the
    // stream is live, so the chain reflects the delivering stream's world;
    // any ancestor change past this read fires the root-changed death path
    // (`WatchRoot` covers every ancestor) rather than going silently stale.
    let mut ancestors = Vec::new();
    for ancestor in roots[0].ancestors().skip(1) {
      match fs::metadata(ancestor) {
        Ok(meta) => ancestors.push(super::RootIdentity::new(meta.dev(), meta.ino().into())),
        Err(source) => {
          let _ = handle.shutdown();
          return Err(SourceError::RootUnavailable {
            root: ancestor.to_path_buf(),
            source,
          });
        }
      }
    }

    let meta = RootMeta {
      root: roots[0].clone(),
      root_dev: root_dev as u64,
      // FSEvents has no mount-id notion; the core's descent fence falls back to the
      // device check (the settled single-device policy) on this backend.
      root_mnt_id: None,
      mounts,
      declined: Vec::new(),
      identity,
      ancestors,
      backend: super::BackendKind::FsEvents,
    };
    Ok((handle, queue_rx, meta))
  }
}

/// The volume-mount flags of the object `fd` names.
fn volume_flags(fd: &fs::File) -> io::Result<u32> {
  let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
  // SAFETY: `fd` is a live description and the buffer is writable for one
  // `statfs`; a non-zero return means the kernel wrote nothing.
  if unsafe { libc::fstatfs(fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
    return Err(io::Error::last_os_error());
  }
  // SAFETY: fstatfs returning 0 initialized the whole struct.
  Ok(unsafe { stat.assume_init() }.f_flags)
}

/// Whether `f_flags` (from `statfs`) marks a LOCAL volume.
///
/// `MNT_LOCAL` is the kernel's own answer to "is this volume served by a
/// filesystem on this host", which is exactly the question FSEvents coverage
/// turns on: fseventsd journals what this host's VFS performed, so a volume
/// served from elsewhere can change without any event ever existing. Absence of
/// the bit is therefore a refusal, not a degradation — there is no loss signal
/// for a change that was never observed.
pub(crate) const fn volume_is_local(f_flags: u32) -> bool {
  f_flags & (libc::MNT_LOCAL as u32) != 0
}

/// The spawn barrier's locality verdict for a root on a volume whose `statfs`
/// reported `f_flags`. `Some` refuses the spawn; the refusal is
/// [`Unsupported`](io::ErrorKind::Unsupported) rather than a degraded guarantee
/// because there is nothing to degrade THROUGH — a remote write produces no
/// event and therefore no loss signal either, so the coverage claim would be
/// silently false rather than coarsely true.
fn remote_volume_refusal(root: &std::path::Path, f_flags: u32) -> Option<SourceError> {
  (!volume_is_local(f_flags)).then(|| SourceError::RootUnavailable {
    root: root.to_path_buf(),
    source: io::Error::new(
      io::ErrorKind::Unsupported,
      "network volumes deliver no reliable events",
    ),
  })
}

/// The most mount-table entries the reader will materialize.
///
/// The ceiling has to be applied to the FIRST sizing round, not only to a
/// growth doubling: the count comes from the kernel and so the table's own size
/// decides how much one spawn — or one post-loss mount refresh, which runs on
/// every scope loss — asks for. A limit reachable only after doubling is a
/// limit an over-large table walks straight past.
const MAX_MOUNT_ENTRIES: usize = 4096;

/// Headroom added to the sizing count so mounts appearing between the count and
/// the read do not force a second round.
const MOUNT_TABLE_SLACK: usize = 8;

/// The capacity one sizing round asks for, or `None` when the ceiling (or the
/// addition itself) refuses it — checked BEFORE any allocation.
const fn mount_table_capacity(count: usize) -> Option<usize> {
  match count.checked_add(MOUNT_TABLE_SLACK) {
    Some(capacity) if capacity <= MAX_MOUNT_ENTRIES => Some(capacity),
    _ => None,
  }
}

/// The capacity the next round asks for after a full-buffer read (which may be
/// a truncated view), or `None` once doubling would pass the ceiling.
const fn grown_mount_table_capacity(capacity: usize) -> Option<usize> {
  match capacity.checked_mul(2) {
    Some(grown) if grown <= MAX_MOUNT_ENTRIES => Some(grown),
    _ => None,
  }
}

/// The byte length the table read is handed for `capacity` entries of `T`, or
/// `None` when it does not fit the `c_int` the syscall takes — a wrapped or
/// negative length would describe a buffer the kernel could overrun.
const fn mount_table_bytes<T>(capacity: usize) -> Option<libc::c_int> {
  match capacity.checked_mul(size_of::<T>()) {
    Some(bytes) if bytes <= libc::c_int::MAX as usize => Some(bytes as libc::c_int),
    _ => None,
  }
}

/// Sizes and fills an owned mount-table buffer, applying everything the syscall
/// does not decide: the entry ceiling before the first allocation, checked
/// sizing arithmetic, a FALLIBLE allocation, and a bounded growth loop.
///
/// `None` is always "the table is UNKNOWN" — refused by the ceiling, unreadable,
/// or unallocatable — and never "there are no mounts": the caller fails device
/// trust closed on it. Allocation is `try_reserve_exact` for the same reason a
/// ceiling exists at all: a table the machine cannot hold must become an
/// unknown table, not an abort.
///
/// Split from the syscalls so the whole policy is exercisable without a mount
/// table.
///
/// # Safety
///
/// `read(ptr, bytes)` must write only within `bytes` starting at `ptr`, and must
/// initialize exactly the number of entries it returns.
unsafe fn read_mount_table<T, R>(count: libc::c_int, mut read: R) -> Option<Vec<T>>
where
  R: FnMut(*mut T, libc::c_int) -> libc::c_int,
{
  if count < 0 {
    return None;
  }
  let mut capacity = mount_table_capacity(count as usize)?;
  loop {
    let bytes = mount_table_bytes::<T>(capacity)?;
    let mut buf: Vec<T> = Vec::new();
    buf.try_reserve_exact(capacity).ok()?;
    let written = read(buf.as_mut_ptr(), bytes);
    if written < 0 {
      return None;
    }
    let written = written as usize;
    if written < capacity {
      // SAFETY: by the contract above, `read` initialized exactly `written`
      // entries, and `written < capacity <= buf.capacity()`.
      unsafe { buf.set_len(written) };
      return Some(buf);
    }
    // A full buffer may be a truncated view (mounts appeared since sizing):
    // grow and re-read, bounded — fail closed rather than trust a possibly
    // partial table.
    capacity = grown_mount_table_capacity(capacity)?;
  }
}

/// The mount rows strictly under `root`, read from the live mount table
/// (`getfsstat`). `None` means the table could not be read — the caller must
/// then treat device boundaries as UNKNOWN rather than absent. Each mount
/// path is run through the same filesystem-representation transform as event
/// paths, so prefix comparison cannot drift on Unicode normalization.
///
/// Every row carries `None` for all three identity fields: `statfs` reports no
/// mount id and no parent, and inventing one from `f_fsid` would hand the core a
/// value it would compare as an identity. macOS is the platform that signals
/// its volume changes in band anyway (`plan_mount`), so the table here is a
/// belt whose locations are the whole of what it can honestly say.
pub(crate) fn mounts_under(root: &std::path::Path) -> Option<Vec<crate::os::MountRow>> {
  use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
  // getfsstat into an owned buffer: the getmntinfo convenience wrapper hands
  // out one shared per-process buffer and is not thread-safe — concurrent
  // spawns raced it into spurious failures. MNT_NOWAIT avoids blocking on
  // unresponsive filesystems.
  //
  // SAFETY: a null buffer asks only for the mounted-filesystem count.
  let count = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
  let read = |ptr: *mut libc::statfs, bytes: libc::c_int| {
    // SAFETY: `ptr` is writable for `bytes`.
    unsafe { libc::getfsstat(ptr, bytes, libc::MNT_NOWAIT) }
  };
  // SAFETY: getfsstat writes at most `bytes` and reports exactly the entries it
  // initialized.
  let entries = unsafe { read_mount_table::<libc::statfs, _>(count, read) }?;
  let mut mounts: Vec<crate::os::MountRow> = Vec::new();
  for entry in &entries {
    let name = &entry.f_mntonname;
    let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    let bytes: Vec<u8> = name[..len].iter().map(|&c| c as u8).collect();
    let path = PathBuf::from(OsStr::from_bytes(&bytes));
    let path = ffi::fs_representation_of(&path).unwrap_or(path);
    if !path.starts_with(root) || path.as_path() == root {
      continue;
    }
    // One row per location — unlike Linux, which returns every member of a
    // stack. These rows carry NO id, so the core keys each of them by its
    // rendered location: a stacked mount listed twice would be one key twice,
    // which the census drops on the way in anyway and which would otherwise
    // read as one mount arriving and departing twice. Every row here carries
    // the same (absent) identity, so which duplicate survives is immaterial —
    // that only one does is not.
    if !mounts.iter().any(|m| m.location == path) {
      mounts.push(crate::os::MountRow {
        location: path,
        mnt_id: None,
        parent_id: None,
        dev: None,
      });
    }
  }
  Some(mounts)
}

/// A live FSEvents stream. Dropping it tears the stream down; prefer
/// [`shutdown`](Self::shutdown) at an orderly exit.
pub(crate) struct SourceHandle {
  /// `None` once torn down — teardown runs exactly once.
  stream: Option<StreamPtr>,
  queue: Option<DispatchRetained<DispatchQueue>>,
  shared: Arc<CallbackShared>,
}

impl SourceHandle {
  /// The resume point the driver has ACKNOWLEDGED, if the journal ids are still
  /// valid. A wrapped id space, or a stream whose batches never reached the
  /// core, mints nothing — the successor then starts live-only and leans on the
  /// covering `Rescan`.
  pub(crate) fn resume_token(&self) -> Option<ResumeToken> {
    if self.shared.ids_wrapped.load(Ordering::Acquire) {
      return None;
    }
    self.shared.resume.published()
  }

  /// Quiesces and destroys the stream. Blocks for at most the tail of one
  /// in-flight callback batch. Must not be called from the stream's own
  /// dispatch queue (structurally impossible for consumers; debug-asserted).
  ///
  /// Always [`Quiesce::Proven`], and structurally so: the private queue is
  /// SERIAL, so an `exec_sync` that returned is a total order against every
  /// callback — none is running and Stop+Invalidate have unregistered and
  /// unscheduled the stream, so none will run again. Nothing here is retained
  /// against a lifetime this call could not observe (the framework's own
  /// deallocation rides a refcount, not this teardown), which is what
  /// separates this backend from the Windows pumps, where the kernel can
  /// still own a buffer after the pump has stopped looking.
  pub(crate) fn shutdown(mut self) -> Quiesce {
    self.teardown();
    Quiesce::Proven
  }

  fn teardown(&mut self) {
    let Some(stream) = self.stream.take() else {
      return;
    };
    self.shared.stopped.store(true, Ordering::Release);
    let queue = self
      .queue
      .take()
      .expect("the queue lives exactly as long as the stream");
    #[cfg(debug_assertions)]
    ffi::debug_assert_off_stream_queue();
    // The private queue is serial, so this block is totally ordered against
    // every callback: when exec_sync returns no callback is running, Stop has
    // unregistered the client, and Invalidate has unscheduled the stream —
    // none will run again.
    queue.exec_sync(move || {
      // Rebind the whole wrapper so the closure captures the Send type, not
      // the raw pointer field (disjoint closure capture would otherwise).
      let stream = stream;
      // SAFETY: the stream is live (teardown runs once) and Stop→Invalidate
      // is the header-mandated order for a scheduled stream.
      unsafe {
        FSEventStreamStop(stream.0);
        FSEventStreamInvalidate(stream.0);
      }
    });
    // Drops the create-time refcount. Deallocation — whenever the framework
    // performs it — runs the context release hook, which frees the stream's
    // strong count on the shared state; the handle's own Arc keeps the state
    // alive meanwhile, so freeing is safe regardless of timing.
    //
    // SAFETY: this pairs with the implicit +1 from FSEventStreamCreate.
    unsafe { FSEventStreamRelease(stream.0) };
    drop(queue);
  }
}

impl Drop for SourceHandle {
  fn drop(&mut self) {
    self.teardown();
  }
}
