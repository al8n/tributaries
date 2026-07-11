//! The unsafe boundary: every Win32 call of the Windows backends lives here,
//! reduced to narrow io-safe helpers with their safety arguments — the
//! `os::macos::ffi` discipline.
//!
//! Handles cross this module as [`OwnedHandle`]/[`BorrowedHandle`], so
//! lifetime and closure are the type system's problem; the OVERLAPPED and
//! buffer pinning contracts (invariants P1/P2) belong to the pump, which is
//! the only caller of the read/completion helpers.

// The pump is that caller and lands next; until it does, the msvc cross-gate
// keeps this surface compiling and nothing on any host constructs it.
#![allow(dead_code)]

use std::{
  io,
  os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
  path::Path,
};

use windows_sys::Win32::{
  Foundation::{
    ERROR_IO_PENDING, GENERIC_READ, GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_TIMEOUT,
  },
  Storage::FileSystem::{
    CreateFileW, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED, FILE_ID_INFO,
    FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE_ATTRIBUTES, FILE_NOTIFY_CHANGE_CREATION,
    FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE,
    FILE_NOTIFY_CHANGE_SECURITY, FILE_NOTIFY_CHANGE_SIZE, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TYPE_DISK, FileBasicInfo, FileIdInfo, GetFileInformationByHandleEx,
    GetFileType, OPEN_EXISTING, ReadDirectoryChangesExW, ReadDirectoryChangesW,
    ReadDirectoryNotifyExtendedInformation,
  },
  System::IO::{
    CancelIoEx, CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED,
    PostQueuedCompletionStatus,
  },
};

/// The notify filter both record layouts subscribe: every dirent, write,
/// size, attribute, creation, and security transition — the RDCW projection
/// of the proto Interest universe (per-subscription narrowing happens in the
/// core, never by thinning the kernel subscription).
pub(super) const NOTIFY_FILTER: u32 = FILE_NOTIFY_CHANGE_FILE_NAME
  | FILE_NOTIFY_CHANGE_DIR_NAME
  | FILE_NOTIFY_CHANGE_ATTRIBUTES
  | FILE_NOTIFY_CHANGE_SIZE
  | FILE_NOTIFY_CHANGE_LAST_WRITE
  | FILE_NOTIFY_CHANGE_CREATION
  | FILE_NOTIFY_CHANGE_SECURITY;

/// The `(VolumeSerialNumber, FILE_ID_128)` identity of an open object — the
/// spawn bracket's capture, read from the PINNED handle so it can never name
/// a different object than the stream watches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct HandleIdentity {
  /// The volume serial the handle lives on.
  pub(super) volume_serial: u64,
  /// The full 128-bit file reference number (exact on ReFS; NTFS zero-extends).
  pub(super) file_id: u128,
}

/// Encodes `path` as the NUL-terminated UTF-16 the wide APIs take.
fn wide(path: &Path) -> Vec<u16> {
  use std::os::windows::ffi::OsStrExt;
  path.as_os_str().encode_wide().chain([0]).collect()
}

/// Opens a directory for watching: readable listing, all sharing (the watch
/// must never pin the root against mutation or deletion — the
/// held-fd-perturbs-teardown hazard class), backup semantics (directories
/// refuse `CreateFileW` without it), and OVERLAPPED for the pump's reads.
pub(super) fn open_directory(path: &Path) -> io::Result<OwnedHandle> {
  let wide = wide(path);
  // SAFETY: `wide` is NUL-terminated and outlives the call; no security
  // attributes and no template handle are passed (null is the documented
  // "none" for both).
  let raw = unsafe {
    CreateFileW(
      wide.as_ptr(),
      GENERIC_READ | FILE_LIST_DIRECTORY,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      std::ptr::null(),
      OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
      std::ptr::null_mut(),
    )
  };
  if raw == INVALID_HANDLE_VALUE {
    return Err(io::Error::last_os_error());
  }
  // SAFETY: the handle is freshly returned by a successful CreateFileW and
  // owned by no one else; OwnedHandle takes over its closure.
  Ok(unsafe { OwnedHandle::from_raw_handle(raw as _) })
}

/// Whether the open object is a real disk object (`FILE_TYPE_DISK`) — pipes,
/// character devices, and the unknown class are refused at the spawn barrier.
pub(super) fn is_disk_object(handle: BorrowedHandle<'_>) -> bool {
  // SAFETY: the borrowed handle is live for the call by construction.
  let file_type = unsafe { GetFileType(handle.as_raw_handle() as HANDLE) };
  file_type == FILE_TYPE_DISK
}

/// Whether the open object is a directory, read from the handle itself
/// (`FILE_ATTRIBUTE_DIRECTORY` in its basic info) — the bracket's
/// not-a-directory check, racing nothing because it asks the pinned object.
pub(super) fn is_directory(handle: BorrowedHandle<'_>) -> io::Result<bool> {
  let mut info: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };
  // SAFETY: `info` is a properly-sized, writable FILE_BASIC_INFO and the
  // class constant matches the struct; the handle is live for the call.
  let ok = unsafe {
    GetFileInformationByHandleEx(
      handle.as_raw_handle() as HANDLE,
      FileBasicInfo,
      (&raw mut info).cast(),
      size_of::<FILE_BASIC_INFO>() as u32,
    )
  };
  if ok == 0 {
    return Err(io::Error::last_os_error());
  }
  const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
  Ok(info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0)
}

/// The `(volume serial, 128-bit id)` identity of the open object.
pub(super) fn identity_of(handle: BorrowedHandle<'_>) -> io::Result<HandleIdentity> {
  let mut info: FILE_ID_INFO = unsafe { std::mem::zeroed() };
  // SAFETY: `info` is a properly-sized, writable FILE_ID_INFO and the class
  // constant matches the struct; the handle is live for the call.
  let ok = unsafe {
    GetFileInformationByHandleEx(
      handle.as_raw_handle() as HANDLE,
      FileIdInfo,
      (&raw mut info).cast(),
      size_of::<FILE_ID_INFO>() as u32,
    )
  };
  if ok == 0 {
    return Err(io::Error::last_os_error());
  }
  Ok(HandleIdentity {
    volume_serial: info.VolumeSerialNumber,
    file_id: u128::from_le_bytes(info.FileId.Identifier),
  })
}

/// Creates a fresh completion port with single-thread concurrency — each
/// source owns its own pump thread, so one dequeuer is the whole design.
pub(super) fn iocp_new() -> io::Result<OwnedHandle> {
  // SAFETY: a null file handle with a null existing port is the documented
  // create-new form; the returned handle is owned by no one else.
  let raw = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, std::ptr::null_mut(), 0, 1) };
  if raw.is_null() {
    return Err(io::Error::last_os_error());
  }
  // SAFETY: freshly created above; OwnedHandle takes over closure.
  Ok(unsafe { OwnedHandle::from_raw_handle(raw as _) })
}

/// Associates `file` with the port under `key`. Every later completion of an
/// I/O issued on `file` arrives on the port carrying `key`.
pub(super) fn iocp_associate(
  port: BorrowedHandle<'_>,
  file: BorrowedHandle<'_>,
  key: usize,
) -> io::Result<()> {
  // SAFETY: both handles are live for the call; associating returns the
  // existing port handle (not a new ownership) or null on failure.
  let raw = unsafe {
    CreateIoCompletionPort(
      file.as_raw_handle() as HANDLE,
      port.as_raw_handle() as HANDLE,
      key,
      0,
    )
  };
  if raw.is_null() {
    return Err(io::Error::last_os_error());
  }
  Ok(())
}

/// One dequeued completion packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Completion {
  /// An I/O completion (or a posted control packet): the transferred byte
  /// count, the association (or post) key, and the OVERLAPPED pointer the
  /// operation was issued with (null for a keyed control post).
  Packet {
    /// Bytes the operation transferred (0 is meaningful: RDCW overflow).
    bytes: u32,
    /// The completion key.
    key: usize,
    /// The issuing OVERLAPPED, if any.
    overlapped: *mut OVERLAPPED,
    /// The failed-completion error, if the packet reports one
    /// (`GetQueuedCompletionStatus` returned FALSE with a non-null
    /// OVERLAPPED — a cancelled or errored I/O, delivered in queue order).
    error: Option<i32>,
  },
  /// The wait elapsed with nothing to dequeue.
  TimedOut,
}

/// Dequeues one packet, blocking up to `timeout_ms` (`u32::MAX` = forever).
pub(super) fn iocp_wait(port: BorrowedHandle<'_>, timeout_ms: u32) -> io::Result<Completion> {
  let mut bytes = 0u32;
  let mut key = 0usize;
  let mut overlapped: *mut OVERLAPPED = std::ptr::null_mut();
  // SAFETY: the port handle is live and every out-pointer targets a local;
  // the call writes them before returning.
  let ok = unsafe {
    GetQueuedCompletionStatus(
      port.as_raw_handle() as HANDLE,
      &raw mut bytes,
      &raw mut key,
      &raw mut overlapped,
      timeout_ms,
    )
  };
  if ok != 0 {
    return Ok(Completion::Packet {
      bytes,
      key,
      overlapped,
      error: None,
    });
  }
  // SAFETY: trivially safe; reads the calling thread's last-error slot.
  let error = unsafe { GetLastError() };
  if overlapped.is_null() {
    // No packet was dequeued: a timeout is the one benign shape.
    return if error == WAIT_TIMEOUT {
      Ok(Completion::TimedOut)
    } else {
      Err(io::Error::from_raw_os_error(error as i32))
    };
  }
  // A packet WAS dequeued for a failed operation (cancellation included):
  // the caller maps it — a drain consumes it, a live loop lowers it.
  Ok(Completion::Packet {
    bytes,
    key,
    overlapped,
    error: Some(error as i32),
  })
}

/// Posts a keyed control packet — the wake analog: the packet is
/// simultaneously the message and the wakeup, one ordered lane with the I/O
/// completions, so the lost-wakeup class is structurally absent.
pub(super) fn iocp_post(port: BorrowedHandle<'_>, key: usize) -> io::Result<()> {
  // SAFETY: the port handle is live; a null OVERLAPPED with zero bytes is
  // the documented control-post form.
  let ok = unsafe {
    PostQueuedCompletionStatus(port.as_raw_handle() as HANDLE, 0, key, std::ptr::null_mut())
  };
  if ok == 0 {
    return Err(io::Error::last_os_error());
  }
  Ok(())
}

/// Issues one directory-changes read into `buffer` under `overlapped`.
///
/// `extended` selects `ReadDirectoryChangesExW` (the identity-carrying
/// layout); the caller picked it by the one-time spawn probe.
///
/// # Safety
///
/// The caller guarantees the P1 pin: `buffer` and `overlapped` are
/// address-stable and unread from issue until the completion for this
/// `overlapped` is dequeued from the port (or proven never-issued by an
/// `Err` return here), and at most one read is outstanding per handle (P2).
pub(super) unsafe fn issue_read(
  handle: BorrowedHandle<'_>,
  buffer: &mut [u8],
  extended: bool,
  overlapped: *mut OVERLAPPED,
) -> io::Result<()> {
  let len = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
  // SAFETY: the handle is live and OVERLAPPED-opened; buffer/overlapped
  // validity and exclusivity are the caller's P1/P2 contract; no completion
  // routine is passed (the port delivers).
  let ok = unsafe {
    if extended {
      ReadDirectoryChangesExW(
        handle.as_raw_handle() as HANDLE,
        buffer.as_mut_ptr().cast(),
        len,
        1, // bWatchSubtree: the kernel-recursive profile
        NOTIFY_FILTER,
        std::ptr::null_mut(),
        overlapped,
        None,
        ReadDirectoryNotifyExtendedInformation,
      )
    } else {
      ReadDirectoryChangesW(
        handle.as_raw_handle() as HANDLE,
        buffer.as_mut_ptr().cast(),
        len,
        1,
        NOTIFY_FILTER,
        std::ptr::null_mut(),
        overlapped,
        None,
      )
    }
  };
  if ok == 0 {
    // SAFETY: trivially safe; reads the calling thread's last-error slot.
    let error = unsafe { GetLastError() };
    // Pending IS the success shape for an overlapped issue.
    if error != ERROR_IO_PENDING {
      return Err(io::Error::from_raw_os_error(error as i32));
    }
  }
  Ok(())
}

/// Cancels every outstanding I/O this thread or any other issued on
/// `handle`. The cancelled operations still complete through the port
/// (`ERROR_OPERATION_ABORTED` packets) — the teardown drain consumes them
/// before the handle closes (P8).
pub(super) fn cancel_io(handle: BorrowedHandle<'_>) {
  // SAFETY: the handle is live; a null OVERLAPPED cancels all of its
  // outstanding operations. A FALSE return with ERROR_NOT_FOUND (nothing
  // outstanding) is benign by contract.
  let _ = unsafe { CancelIoEx(handle.as_raw_handle() as HANDLE, std::ptr::null()) };
}
