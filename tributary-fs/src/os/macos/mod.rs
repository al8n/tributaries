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
  os::unix::fs::MetadataExt,
  path::PathBuf,
  sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
  },
};

use dispatch2::{DispatchQueue, DispatchRetained};
use objc2_core_services::{
  FSEventStreamInvalidate, FSEventStreamRef, FSEventStreamRelease, FSEventStreamStop,
  kFSEventStreamEventIdSinceNow,
};

use super::{
  EventReceiver, MAX_EXCLUSIONS, ResumeToken, RootMeta, SourceConfig, SourceError,
  transport::TransportState,
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
  /// Highest journal event id seen while in sync. Zero means none: id zero
  /// itself (the `ROOT_CHANGED` marker) is never recorded, and ids arriving
  /// with a lost-sync flag do not advance it.
  pub(super) last_good: AtomicU64,
  /// The journal's id counter wrapped; every stored id is invalid for resume.
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
  /// before anything reaches the caller. Per datum: the mount seed claims no
  /// authority (see [`RootMeta`] — the driver's post-live refresh installs
  /// it); the root device is re-proven by the same post-live stat (identity
  /// equality includes it); the device UUID is advisory (resume tokens are
  /// minted, never yet consumed); exclusions only ever reduce coverage; the
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
    let root_meta = fs::metadata(&roots[0]).map_err(|source| SourceError::RootUnavailable {
      root: roots[0].clone(),
      source,
    })?;
    // The kind recheck belongs to the same pre-start barrier as the device
    // and mount reads: canonicalization already re-resolved the root, so a
    // path retargeted from a directory to a file since the caller's own
    // check must fail here, before any stream exists.
    if !root_meta.is_dir() {
      return Err(SourceError::NotADirectory {
        root: roots[0].clone(),
      });
    }
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
      last_good: AtomicU64::new(0),
      ids_wrapped: AtomicBool::new(false),
    });

    let queue = DispatchQueue::new("tributary-fs.fsevents", None);
    #[cfg(debug_assertions)]
    ffi::mark_stream_queue(&queue);

    let since = config
      .since
      .map(|token| token.last_good())
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
    // proven teardown path (the handle) before rejecting.
    let handle = SourceHandle {
      stream: Some(stream),
      queue: Some(queue),
      shared,
      device_uuid,
    };

    // The post-live half of the identity bracket: an object that still
    // matches the pre-start capture while the stream is delivering matched
    // it across the entire capture→start gap — the stream anchor and the
    // registry identity provably name one object.
    let live = match fs::metadata(&roots[0]) {
      Ok(meta) => meta,
      Err(source) => {
        handle.shutdown();
        return Err(SourceError::RootUnavailable {
          root: roots[0].clone(),
          source,
        });
      }
    };
    if !live.is_dir() {
      handle.shutdown();
      return Err(SourceError::NotADirectory {
        root: roots[0].clone(),
      });
    }
    if super::RootIdentity::new(live.dev(), live.ino().into()) != identity {
      handle.shutdown();
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
          handle.shutdown();
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
      identity,
      ancestors,
      backend: super::BackendKind::FsEvents,
    };
    Ok((handle, queue_rx, meta))
  }
}

/// The mount points strictly under `root`, read from the live mount table
/// (`getfsstat`). `None` means the table could not be read — the caller must
/// then treat device boundaries as UNKNOWN rather than absent. Each mount
/// path is run through the same filesystem-representation transform as event
/// paths, so prefix comparison cannot drift on Unicode normalization.
pub(crate) fn mounts_under(root: &std::path::Path) -> Option<Vec<PathBuf>> {
  use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
  // getfsstat into an owned buffer: the getmntinfo convenience wrapper hands
  // out one shared per-process buffer and is not thread-safe — concurrent
  // spawns raced it into spurious failures. MNT_NOWAIT avoids blocking on
  // unresponsive filesystems.
  let mut capacity = {
    // SAFETY: a null buffer asks only for the mounted-filesystem count.
    let count = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
    if count < 0 {
      return None;
    }
    count as usize + 8
  };
  let entries = loop {
    let mut buf: Vec<libc::statfs> = Vec::with_capacity(capacity);
    let bytes = (capacity * size_of::<libc::statfs>()) as libc::c_int;
    // SAFETY: `buf` has room for `capacity` entries totalling `bytes`;
    // getfsstat initializes and reports how many entries it wrote.
    let written = unsafe { libc::getfsstat(buf.as_mut_ptr(), bytes, libc::MNT_NOWAIT) };
    if written < 0 {
      return None;
    }
    let written = written as usize;
    if written < capacity {
      // SAFETY: getfsstat initialized exactly `written` entries.
      unsafe { buf.set_len(written) };
      break buf;
    }
    // A full buffer may be a truncated view (mounts appeared since sizing):
    // grow and re-read, bounded — fail closed rather than trust a possibly
    // partial table.
    capacity *= 2;
    if capacity > 4096 {
      return None;
    }
  };
  let mut mounts = Vec::new();
  for entry in &entries {
    let name = &entry.f_mntonname;
    let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    let bytes: Vec<u8> = name[..len].iter().map(|&c| c as u8).collect();
    let path = PathBuf::from(OsStr::from_bytes(&bytes));
    let path = ffi::fs_representation_of(&path).unwrap_or(path);
    if path.starts_with(root) && path.as_path() != root {
      mounts.push(path);
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
  // Read only by the deferred journal-resume surface.
  #[allow(dead_code)]
  device_uuid: Option<[u8; 16]>,
}

impl SourceHandle {
  /// The resume point minted so far, if the journal ids are still valid.
  // Journal resume is deferred surface; minted, not yet consumed.
  #[allow(dead_code)]
  pub(crate) fn resume_token(&self) -> Option<ResumeToken> {
    if self.shared.ids_wrapped.load(Ordering::Acquire) {
      return None;
    }
    match self.shared.last_good.load(Ordering::Acquire) {
      0 => None,
      id => Some(ResumeToken::new(id, self.device_uuid)),
    }
  }

  /// Quiesces and destroys the stream. Blocks for at most the tail of one
  /// in-flight callback batch. Must not be called from the stream's own
  /// dispatch queue (structurally impossible for consumers; debug-asserted).
  pub(crate) fn shutdown(mut self) {
    self.teardown();
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
