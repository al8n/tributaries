//! CoreFoundation payload decode: reduces the framework-owned CF objects of
//! one callback invocation to owned [`RawOsEvent`]s before anything crosses a
//! thread boundary (CF objects are not `Send`; the framework releases them
//! when the callback returns).

use std::{ffi::c_void, path::PathBuf, ptr::NonNull};

use objc2_core_foundation::{CFArray, CFDictionary, CFIndex, CFNumber, CFString, CFType};
use objc2_core_services::{FSEventStreamEventFlags, FSEventStreamEventId};

use crate::os::fsevent::{FsEventFlags, RawOsEvent, file_id_from_extended, path_from_fs_repr};

/// One callback's decode outcome. `lossy` records that at least one entry
/// could not be represented OR did not fit the materialization budget — the
/// caller latches it as an overflow, never a silent drop.
pub(super) struct DecodedBatch {
  pub(super) events: Vec<RawOsEvent>,
  pub(super) lossy: bool,
  /// Whether the journal's id counter wrapped anywhere in this payload.
  ///
  /// Read off the RAW flag words of every entry the callback was handed, not
  /// off the decoded ones: the wrap INVALIDATES every id the stream will ever
  /// report, so an entry that failed to decode or fell outside the
  /// materialization budget must still be able to latch it. Missing the wrap
  /// would let a later batch's candidate be published against a reused id
  /// space, and a successor would then replay unrelated history.
  pub(super) ids_wrapped: bool,
}

/// The most events one callback payload may materialize.
///
/// The transport budget counts BATCHES, so without a per-batch cap the retained
/// memory is `budget × (whatever one callback happened to carry)` — and a
/// callback's size is chosen by whoever is writing to the tree, not by us.
pub(super) const MAX_BATCH_EVENTS: usize = 2048;

/// The most decoded path bytes one callback payload may materialize.
///
/// An event count alone does not bound bytes: each entry owns a path, and a
/// deep tree makes those long. Sized so a single ordinary path can never be the
/// thing that overruns it (that would truncate every batch to nothing and turn
/// the stream into a rescan loop).
pub(super) const MAX_BATCH_PATH_BYTES: usize = 512 * 1024;

/// What one callback payload may materialize before the decode stops.
///
/// The remainder does not vanish: the decode marks the batch lossy, so the
/// producer stages no resume point for it and enqueues an `Overflow` at the
/// batch's own queue position. That signal fails device trust closed and
/// rescans the scope, which dominates every classification the truncated prefix
/// could have got wrong (a same-fileID rename chain cut in half, a `MOUNT` left
/// in the discarded tail) — the same degrade a batch refused by the transport
/// budget already takes, just triggered by one batch's size instead of the
/// number in flight.
pub(super) struct DecodeBudget {
  events: usize,
  bytes: usize,
}

impl DecodeBudget {
  /// The budget one callback payload is decoded under.
  pub(super) const fn new(events: usize, bytes: usize) -> Self {
    Self { events, bytes }
  }

  /// Whether anything at all can still be admitted. Checked BEFORE an entry is
  /// decoded, so a payload past the cap allocates nothing further.
  pub(super) const fn open(&self) -> bool {
    self.events > 0 && self.bytes > 0
  }

  /// Charges one decoded entry of `bytes`; `false` means it did not fit and the
  /// decode must stop.
  pub(super) const fn admit(&mut self, bytes: usize) -> bool {
    if self.events == 0 || bytes > self.bytes {
      return false;
    }
    self.events -= 1;
    self.bytes -= bytes;
    true
  }
}

impl Default for DecodeBudget {
  fn default() -> Self {
    Self::new(MAX_BATCH_EVENTS, MAX_BATCH_PATH_BYTES)
  }
}

/// Decodes one callback payload.
///
/// # Safety
///
/// Must be called with the pointers of a live FSEvents callback registered
/// with `UseCFTypes | UseExtendedData`: `event_paths` is a `CFArrayRef` of
/// `CFDictionaryRef` and the flag/id arrays hold `num_events` entries, all
/// valid for the duration of the call.
pub(super) unsafe fn decode_batch(
  num_events: usize,
  event_paths: NonNull<c_void>,
  event_flags: NonNull<FSEventStreamEventFlags>,
  event_ids: NonNull<FSEventStreamEventId>,
) -> DecodedBatch {
  // The extended-data dictionary keys are CFSTR macros in the header — not
  // linkable symbols — so they are minted locally; CFDictionary lookup is
  // CFEqual-based, and CFString is not Sync, so per-batch minting also keeps
  // the shared state free of CF types.
  let path_key = CFString::from_static_str("path");
  let file_id_key = CFString::from_static_str("fileID");

  // SAFETY: the payload is a CFArray per the UseCFTypes contract.
  let array = unsafe { event_paths.cast::<CFArray>().as_ref() };
  let present = usize::try_from(array.count()).unwrap_or(0);
  let n = num_events.min(present);
  // SAFETY: the flag/id arrays hold num_events entries per the contract.
  let flags = unsafe { core::slice::from_raw_parts(event_flags.as_ptr(), num_events) };
  let ids = unsafe { core::slice::from_raw_parts(event_ids.as_ptr(), num_events) };

  // The id-space wrap is latched from the raw flag words, so no decode failure
  // and no budget truncation can hide it.
  let ids_wrapped = flags
    .iter()
    .any(|word| FsEventFlags::new(*word).event_ids_wrapped());

  // The batch is sized to what the budget can actually admit, so an oversized
  // payload never even reserves for its own event count.
  let mut budget = DecodeBudget::default();
  let mut events = Vec::with_capacity(n.min(MAX_BATCH_EVENTS));
  let mut lossy = n != num_events;
  for i in 0..n {
    if !budget.open() {
      lossy = true;
      break;
    }
    // SAFETY: i < count; the framework owns the value for the callback.
    let value = unsafe { array.value_at_index(i as CFIndex) };
    let entry = NonNull::new(value.cast_mut())
      // SAFETY: CF collection values are valid CF objects.
      .map(|ptr| unsafe { ptr.cast::<CFType>().as_ref() })
      .and_then(|ty| ty.downcast_ref::<CFDictionary>())
      .and_then(|dict| {
        // SAFETY: the dictionary is framework-owned for the callback's
        // duration and not mutated; the keys are valid CFStrings.
        let path = unsafe { cf_dict_get(dict, &path_key) }
          .and_then(|ty| ty.downcast_ref::<CFString>())
          .and_then(cfstring_to_path)?;
        // A missing fileID is legitimate (dropped/root-changed/dir-level
        // events); only the PATH is load-bearing for decode.
        let file_id = unsafe { cf_dict_get(dict, &file_id_key) }
          .and_then(|ty| ty.downcast_ref::<CFNumber>())
          .and_then(CFNumber::as_i64)
          .and_then(file_id_from_extended);
        Some((path, file_id))
      });
    match entry {
      Some((path, file_id)) => {
        if !budget.admit(path.as_os_str().len()) {
          lossy = true;
          break;
        }
        events.push(RawOsEvent {
          path,
          flags: FsEventFlags::new(flags[i]),
          event_id: ids[i],
          file_id,
        });
      }
      None => lossy = true,
    }
  }
  DecodedBatch {
    events,
    lossy,
    ids_wrapped,
  }
}

/// Untyped `CFDictionaryGetValue` with the result reborrowed as a `CFType`.
///
/// # Safety
///
/// The dictionary must stay alive and unmutated while the reference is used.
unsafe fn cf_dict_get<'a>(dict: &'a CFDictionary, key: &CFString) -> Option<&'a CFType> {
  let key_ptr: *const CFString = key;
  // SAFETY: the key is a valid CF object; a CF dictionary's values are CF
  // objects and cannot be NULL when present.
  let value = unsafe { dict.value(key_ptr.cast::<c_void>()) };
  NonNull::new(value.cast_mut()).map(|ptr| unsafe { ptr.cast::<CFType>().as_ref() })
}

/// Extracts a CFString as filesystem-representation bytes (decomposed UTF-8)
/// and rebuilds the path from them.
pub(super) fn cfstring_to_path(s: &CFString) -> Option<PathBuf> {
  let max = s.maximum_size_of_file_system_representation();
  if max <= 0 {
    return None;
  }
  let mut buf = vec![0u8; max as usize];
  // SAFETY: the buffer is valid for max bytes.
  if !unsafe { s.file_system_representation(buf.as_mut_ptr().cast(), max) } {
    return None;
  }
  path_from_fs_repr(&buf)
}
