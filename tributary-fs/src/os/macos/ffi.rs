//! The unsafe boundary: every touch of the FSEvents C API and libdispatch
//! lives here, reduced to narrow helpers with their safety arguments.

use std::{
  ffi::c_void,
  panic::{AssertUnwindSafe, catch_unwind},
  path::{Path, PathBuf},
  ptr::NonNull,
  sync::{Arc, atomic::Ordering},
  time::Duration,
};

use dispatch2::DispatchQueue;
use objc2_core_foundation::{CFArray, CFRetained, CFString};
use objc2_core_services::{
  ConstFSEventStreamRef, FSEventStreamContext, FSEventStreamCreate, FSEventStreamCreateFlags,
  FSEventStreamEventFlags, FSEventStreamEventId, FSEventStreamInvalidate, FSEventStreamRef,
  FSEventStreamRelease, FSEventStreamSetDispatchQueue, FSEventStreamSetExclusionPaths,
  FSEventStreamStart, FSEventsCopyUUIDForDevice, kFSEventStreamCreateFlagFileEvents,
  kFSEventStreamCreateFlagNoDefer, kFSEventStreamCreateFlagUseCFTypes,
  kFSEventStreamCreateFlagUseExtendedData, kFSEventStreamCreateFlagWatchRoot,
};

use super::{CallbackShared, SourceError, SourceMessage, StreamPtr, decode};

/// The stream configuration this backend always runs with: CF-typed extended
/// data (the only source of per-event inodes; requires `FileEvents`),
/// first-event immediacy (`NoDefer`), and root-death signaling (`WatchRoot`).
const CREATE_FLAGS: FSEventStreamCreateFlags = kFSEventStreamCreateFlagUseCFTypes
  | kFSEventStreamCreateFlagUseExtendedData
  | kFSEventStreamCreateFlagFileEvents
  | kFSEventStreamCreateFlagNoDefer
  | kFSEventStreamCreateFlagWatchRoot;

/// Runs `path` through the CoreFoundation filesystem-representation
/// transform — the same one event decode uses — so the returned bytes are
/// prefix-comparable with event paths.
pub(super) fn fs_representation_of(path: &Path) -> Option<PathBuf> {
  let s = CFString::from_str(path.to_str()?);
  decode::cfstring_to_path(&s)
}

/// The event callback. Decode-and-hand-off only; never blocks, never unwinds
/// into the framework.
///
/// # Safety
///
/// Invoked only by FSEvents with `info` = the `Arc<CallbackShared>` strong
/// count transferred at create, and payload pointers valid for `num_events`
/// entries in the `UseCFTypes | UseExtendedData` shape.
pub(super) unsafe extern "C-unwind" fn event_callback(
  _stream: ConstFSEventStreamRef,
  info: *mut c_void,
  num_events: usize,
  event_paths: NonNull<c_void>,
  event_flags: NonNull<FSEventStreamEventFlags>,
  event_ids: NonNull<FSEventStreamEventId>,
) {
  // SAFETY: `info` is the live CallbackShared the context owns; callbacks
  // cannot outlive the stream (teardown proves quiescence before release),
  // and this reborrow never touches the refcount.
  let shared = unsafe { &*info.cast_const().cast::<CallbackShared>() };
  if shared.stopped.load(Ordering::Acquire) || shared.poisoned.load(Ordering::Acquire) {
    return;
  }
  let outcome = catch_unwind(AssertUnwindSafe(|| {
    // Surface a previously latched drop before newer data, so loss is
    // observed in order. Re-latch if the channel is still full.
    if shared.overflowed.swap(false, Ordering::AcqRel)
      && shared.sender.try_send(SourceMessage::Overflow).is_err()
    {
      shared.overflowed.store(true, Ordering::Release);
    }

    // SAFETY: forwarded verbatim from the callback contract.
    let batch = unsafe { decode::decode_batch(num_events, event_paths, event_flags, event_ids) };
    if batch.lossy {
      shared.overflowed.store(true, Ordering::Release);
    }
    for event in &batch.events {
      if event.flags.event_ids_wrapped() {
        shared.ids_wrapped.store(true, Ordering::Release);
      }
      if event.event_id != 0 && !event.flags.lost_sync() {
        shared.last_good.fetch_max(event.event_id, Ordering::AcqRel);
      }
    }
    if !batch.events.is_empty() {
      match shared.sender.try_send(SourceMessage::Batch(batch.events)) {
        Ok(()) => {}
        Err(async_channel::TrySendError::Full(_)) => {
          // Never block the dispatch queue: drop the batch, latch the loss.
          shared.overflowed.store(true, Ordering::Release);
        }
        Err(async_channel::TrySendError::Closed(_)) => {}
      }
    }
  }));
  if outcome.is_err() {
    // A decode bug must not abort the host process; poison the stream and
    // report in-band instead.
    shared.poisoned.store(true, Ordering::Release);
    let _ = shared
      .sender
      .try_send(SourceMessage::Fatal(SourceError::CallbackPanic));
  }
}

/// The context release hook: frees the strong count transferred to the stream
/// at create. FSEvents invokes it exactly once, when the stream deallocates.
///
/// # Safety
///
/// Invoked only by FSEvents, with the pointer `create_scheduled_stream`
/// installed as the context info.
unsafe extern "C-unwind" fn release_context(info: *const c_void) {
  // SAFETY: pairs with the `Arc::into_raw` at create.
  drop(unsafe { Arc::from_raw(info.cast::<CallbackShared>()) });
}

/// Creates a stream over `roots` and schedules it on `queue`.
///
/// On success the stream owns one strong count of `shared` (released by
/// [`release_context`] at dealloc). On failure nothing is retained.
pub(super) fn create_scheduled_stream(
  shared: &Arc<CallbackShared>,
  roots: &[PathBuf],
  since: FSEventStreamEventId,
  latency: Duration,
  queue: &DispatchQueue,
) -> Result<StreamPtr, SourceError> {
  let cf_paths: Vec<CFRetained<CFString>> = roots
    .iter()
    .map(|root| root.to_str().map(CFString::from_str))
    .collect::<Option<_>>()
    .ok_or(SourceError::CreateFailed)?;
  let path_refs: Vec<&CFString> = cf_paths.iter().map(|s| &**s).collect();
  let paths = CFArray::from_objects(&path_refs);

  let info = Arc::into_raw(Arc::clone(shared)) as *mut c_void;
  let mut context = FSEventStreamContext {
    version: 0,
    info,
    retain: None,
    release: Some(release_context),
    copyDescription: None,
  };
  // SAFETY: the callback matches the UseCFTypes|UseExtendedData payload it
  // is registered with; the context carries an owned strong count with a
  // release hook; the array holds CFStrings.
  let stream = unsafe {
    FSEventStreamCreate(
      None,
      Some(event_callback),
      &mut context,
      paths.as_opaque(),
      since,
      latency.as_secs_f64(),
      CREATE_FLAGS,
    )
  };
  if stream.is_null() {
    // Create retained nothing: reclaim the transferred count.
    // SAFETY: pairs with the `Arc::into_raw` above.
    drop(unsafe { Arc::from_raw(info.cast_const().cast::<CallbackShared>()) });
    return Err(SourceError::CreateFailed);
  }
  // SAFETY: the stream is live and not yet scheduled anywhere else.
  unsafe { FSEventStreamSetDispatchQueue(stream, Some(queue)) };
  Ok(StreamPtr(stream))
}

/// Installs the exclusion set; `false` means the OS rejected it.
pub(super) fn set_exclusions(stream: FSEventStreamRef, exclusions: &[PathBuf]) -> bool {
  let cf_paths: Vec<CFRetained<CFString>> = exclusions
    .iter()
    .filter_map(|path| path.to_str().map(CFString::from_str))
    .collect();
  if cf_paths.len() != exclusions.len() {
    return false;
  }
  let path_refs: Vec<&CFString> = cf_paths.iter().map(|s| &**s).collect();
  let paths = CFArray::from_objects(&path_refs);
  // SAFETY: the stream is live; the array holds CFStrings.
  unsafe { FSEventStreamSetExclusionPaths(stream, paths.as_opaque()) }
}

/// Starts event delivery; `false` means the OS refused (fseventsd pressure,
/// corrupted journal, …).
pub(super) fn start(stream: FSEventStreamRef) -> bool {
  // SAFETY: the stream is live and scheduled.
  unsafe { FSEventStreamStart(stream) }
}

/// Unschedules and releases a scheduled-but-failed stream (the create-error
/// unwind path; the running path tears down through the handle instead).
pub(super) fn invalidate_and_release(stream: FSEventStreamRef) {
  // SAFETY: the stream is live and scheduled (SetDispatchQueue precedes every
  // call site), which Invalidate requires; Release drops the create count.
  unsafe {
    FSEventStreamInvalidate(stream);
    FSEventStreamRelease(stream);
  }
}

/// The UUID scoping this device's journal ids, if it has one (a NULL return
/// means no journal — e.g. a read-only volume).
pub(super) fn device_uuid(dev: libc::dev_t) -> Option<[u8; 16]> {
  // SAFETY: sound for any dev_t; the OS returns NULL for unknown devices.
  let uuid = unsafe { FSEventsCopyUUIDForDevice(dev) }?;
  let b = uuid.uuid_bytes();
  Some([
    b.byte0, b.byte1, b.byte2, b.byte3, b.byte4, b.byte5, b.byte6, b.byte7, b.byte8, b.byte9,
    b.byte10, b.byte11, b.byte12, b.byte13, b.byte14, b.byte15,
  ])
}

#[cfg(debug_assertions)]
static STREAM_QUEUE_MARKER: u8 = 0;

/// Tags a stream's private queue so [`debug_assert_off_stream_queue`] can
/// detect teardown running on it (a self-deadlock in `exec_sync`).
#[cfg(debug_assertions)]
pub(super) fn mark_stream_queue(queue: &DispatchQueue) {
  queue.set_specific(NonNull::from(&STREAM_QUEUE_MARKER).cast::<()>(), || {});
}

/// Asserts the current thread is not executing on any tributary-fs stream
/// queue. `dispatch_get_specific` resolves against the CURRENT queue only, so
/// a non-null marker means "running on one of our stream queues".
#[cfg(debug_assertions)]
pub(super) fn debug_assert_off_stream_queue() {
  let key = NonNull::from(&STREAM_QUEUE_MARKER).cast::<c_void>();
  // SAFETY: dispatch_get_specific is callable from any thread; outside a
  // dispatch queue (or on one without the key) it returns null.
  let current = unsafe { dispatch2::dispatch_get_specific(key) };
  debug_assert!(
    current.is_null(),
    "teardown must not run on a stream's own dispatch queue"
  );
}
