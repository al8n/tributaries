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

use windows_sys::{
  Wdk::{
    Foundation::OBJECT_ATTRIBUTES,
    Storage::FileSystem::{
      FILE_CREATE, FILE_DIRECTORY_FILE, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    },
  },
  Win32::{
    Foundation::{
      ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_IO_PENDING, ERROR_NO_MORE_FILES,
      ERROR_NOT_SUPPORTED, GENERIC_READ, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
      OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, UNICODE_STRING, WAIT_TIMEOUT,
    },
    Storage::FileSystem::{
      CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO,
      FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO,
      FILE_DISPOSITION_INFO_EX, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
      FILE_FLAG_OVERLAPPED, FILE_ID_INFO, FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE_ATTRIBUTES,
      FILE_NOTIFY_CHANGE_CREATION, FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME,
      FILE_NOTIFY_CHANGE_LAST_ACCESS, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SECURITY,
      FILE_NOTIFY_CHANGE_SIZE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
      FILE_TYPE_DISK, FileAttributeTagInfo, FileBasicInfo, FileDispositionInfo,
      FileDispositionInfoEx, FileIdExtdDirectoryInfo, FileIdExtdDirectoryRestartInfo, FileIdInfo,
      GetFileInformationByHandleEx, GetFileType, OPEN_EXISTING, ReadDirectoryChangesExW,
      ReadDirectoryChangesW, ReadDirectoryNotifyExtendedInformation, SYNCHRONIZE,
      SetFileInformationByHandle,
    },
    System::{
      IO::{
        CancelIoEx, CreateIoCompletionPort, DeviceIoControl, GetOverlappedResult,
        GetQueuedCompletionStatus, IO_STATUS_BLOCK, OVERLAPPED, PostQueuedCompletionStatus,
      },
      Ioctl::{
        FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_USN_JOURNAL, READ_USN_JOURNAL_DATA_V1,
        USN_JOURNAL_DATA_V1,
      },
    },
  },
};

/// The notify filter both record layouts subscribe — defined, and tested, in
/// host-compiled code (see [`notify`](super::rdcw::notify)).
pub(super) use super::rdcw::notify::FILTER as NOTIFY_FILTER;

/// The ABI pin: every filter bit the vendored bindings declare must equal the
/// literal the host-compiled vocabulary spells, so a typo there cannot survive
/// a Windows build. The extended-attribute and named-stream bits live in the
/// WDK half of the surface rather than Win32 — which is precisely how the
/// filter came to be written half in imports and half not — so they are pinned
/// from there and no call is made through it.
const _: () = {
  use windows_sys::Wdk::Storage::FileSystem::{
    FILE_NOTIFY_CHANGE_EA, FILE_NOTIFY_CHANGE_STREAM_NAME, FILE_NOTIFY_CHANGE_STREAM_SIZE,
    FILE_NOTIFY_CHANGE_STREAM_WRITE,
  };

  use super::rdcw::notify;
  assert!(notify::FILE_NAME == FILE_NOTIFY_CHANGE_FILE_NAME);
  assert!(notify::DIR_NAME == FILE_NOTIFY_CHANGE_DIR_NAME);
  assert!(notify::ATTRIBUTES == FILE_NOTIFY_CHANGE_ATTRIBUTES);
  assert!(notify::SIZE == FILE_NOTIFY_CHANGE_SIZE);
  assert!(notify::LAST_WRITE == FILE_NOTIFY_CHANGE_LAST_WRITE);
  assert!(notify::LAST_ACCESS == FILE_NOTIFY_CHANGE_LAST_ACCESS);
  assert!(notify::CREATION == FILE_NOTIFY_CHANGE_CREATION);
  assert!(notify::EA == FILE_NOTIFY_CHANGE_EA);
  assert!(notify::SECURITY == FILE_NOTIFY_CHANGE_SECURITY);
  assert!(notify::STREAM_NAME == FILE_NOTIFY_CHANGE_STREAM_NAME);
  assert!(notify::STREAM_SIZE == FILE_NOTIFY_CHANGE_STREAM_SIZE);
  assert!(notify::STREAM_WRITE == FILE_NOTIFY_CHANGE_STREAM_WRITE);
};

/// The same pin for the `NTSTATUS` values the cookie directory's create decides
/// on by name. The mint's whole retry rule hangs off
/// `STATUS_OBJECT_NAME_COLLISION` in particular: spell that literal wrong in the
/// host-compiled vocabulary and an occupied candidate stops reaching the loop as
/// `AlreadyExists`, which no host cell could notice because the value never
/// reaches one from a kernel.
const _: () = {
  use windows_sys::Win32::Foundation::{
    STATUS_ACCESS_DENIED, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_EXISTS,
  };

  use super::security::nt_status;
  assert!(nt_status::OBJECT_NAME_COLLISION == STATUS_OBJECT_NAME_COLLISION);
  assert!(nt_status::OBJECT_NAME_EXISTS == STATUS_OBJECT_NAME_EXISTS);
  assert!(nt_status::ACCESS_DENIED == STATUS_ACCESS_DENIED);
};

/// The `(VolumeSerialNumber, FILE_ID_128)` identity of an open object — the
/// spawn bracket's capture, read from the PINNED handle so it can never name
/// a different object than the stream watches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HandleIdentity {
  /// The volume serial the handle lives on.
  pub(crate) volume_serial: u64,
  /// The full 128-bit file reference number (exact on ReFS; NTFS zero-extends).
  pub(crate) file_id: u128,
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
pub(crate) fn open_directory(path: &Path) -> io::Result<OwnedHandle> {
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

/// Opens a directory WITHOUT following a reparse point at the leaf
/// (`FILE_FLAG_OPEN_REPARSE_POINT`): the walks' child open, which must land
/// on the object the parent's enumeration named — never on a junction or
/// symlink TARGET, whose volume and identity are someone else's.
pub(crate) fn open_directory_no_follow(path: &Path) -> io::Result<OwnedHandle> {
  let wide = wide(path);
  // SAFETY: `wide` is NUL-terminated and outlives the call; null security
  // attributes and template are the documented "none".
  let raw = unsafe {
    CreateFileW(
      wide.as_ptr(),
      GENERIC_READ | FILE_LIST_DIRECTORY,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      std::ptr::null(),
      OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED | FILE_FLAG_OPEN_REPARSE_POINT,
      std::ptr::null_mut(),
    )
  };
  if raw == INVALID_HANDLE_VALUE {
    return Err(io::Error::last_os_error());
  }
  // SAFETY: freshly returned by a successful CreateFileW, owned by no one
  // else; OwnedHandle takes over closure.
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
pub(crate) fn identity_of(handle: BorrowedHandle<'_>) -> io::Result<HandleIdentity> {
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

/// Destroys the object `handle` refers to — the primitive Linux and macOS do
/// not have.
///
/// The disposition is set on an ALREADY-OPEN handle, so no name is resolved and
/// nothing can be swapped in between a caller's verification of that handle and
/// this call: the object destroyed is provably the object verified. A path-based
/// delete offers no such guarantee, which is why every removal that has a handle
/// should come through here.
///
/// POSIX semantics are asked for first: the link leaves the visible namespace as
/// soon as the handle the disposition was set through — THIS one — is closed, and
/// no OTHER open handle (the cookie's own pinned create) delays it. How long the
/// name stands is therefore the caller's choice of how long to hold that handle —
/// a cookie removal deletes through a local it drops as it returns, while a cookie
/// directory's disposal deletes through a handle its obligation may still be
/// sharing (see `driver::CookieDir`). Where the filesystem or the OS build has no
/// such flag, the classic disposition is the fallback and the entry instead
/// survives until the last handle to the object closes — the object is unreachable
/// by name either way, since the name is refused to every opener from this point on.
pub(crate) fn delete_by_handle(handle: BorrowedHandle<'_>) -> io::Result<()> {
  let raw = handle.as_raw_handle() as HANDLE;
  let ex = FILE_DISPOSITION_INFO_EX {
    Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
  };
  // SAFETY: `ex` is a properly-sized, initialized FILE_DISPOSITION_INFO_EX and
  // the class constant matches the struct; the handle is live for the call.
  let ok = unsafe {
    SetFileInformationByHandle(
      raw,
      FileDispositionInfoEx,
      (&raw const ex).cast(),
      size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
    )
  };
  if ok != 0 {
    return Ok(());
  }
  let err = io::Error::last_os_error();
  // Only "this build/filesystem does not know the Ex class" falls back. Every
  // other failure — a sharing violation, a read-only volume — is the caller's to
  // retry, and retrying it under a different class would just fail again while
  // hiding which call reported what.
  let unsupported = matches!(
    err.raw_os_error().map(|code| code as u32),
    Some(ERROR_INVALID_PARAMETER | ERROR_INVALID_FUNCTION | ERROR_NOT_SUPPORTED)
  );
  if !unsupported {
    return Err(err);
  }
  let classic = FILE_DISPOSITION_INFO { DeleteFile: true };
  // SAFETY: `classic` is a properly-sized, initialized FILE_DISPOSITION_INFO and
  // the class constant matches the struct; the handle is live for the call.
  let ok = unsafe {
    SetFileInformationByHandle(
      raw,
      FileDispositionInfo,
      (&raw const classic).cast(),
      size_of::<FILE_DISPOSITION_INFO>() as u32,
    )
  };
  if ok == 0 {
    return Err(io::Error::last_os_error());
  }
  Ok(())
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

/// The open object's `(FileAttributes, ReparseTag)`, in ONE query.
///
/// Both facts come off the same sample deliberately: `FILE_ATTRIBUTE_TAG_INFO`
/// answers them together, and a caller that reads the attribute to learn whether
/// the object is a reparse point AT ALL and the tag to learn WHICH one must not
/// take those from two queries that could describe two different states.
pub(super) fn attributes_and_tag(handle: BorrowedHandle<'_>) -> io::Result<(u32, u32)> {
  let mut info: FILE_ATTRIBUTE_TAG_INFO = unsafe { std::mem::zeroed() };
  // SAFETY: `info` is a properly-sized, writable FILE_ATTRIBUTE_TAG_INFO and
  // the class constant matches the struct; the handle is live for the call.
  let ok = unsafe {
    GetFileInformationByHandleEx(
      handle.as_raw_handle() as HANDLE,
      FileAttributeTagInfo,
      (&raw mut info).cast(),
      size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
    )
  };
  if ok == 0 {
    return Err(io::Error::last_os_error());
  }
  Ok((info.FileAttributes, info.ReparseTag))
}

/// Whether the open object is a reparse point (junction, symlink, mount) —
/// the containment boundary the seed walk never descends.
pub(super) fn is_reparse_point(handle: BorrowedHandle<'_>) -> io::Result<bool> {
  const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
  let (attributes, _) = attributes_and_tag(handle)?;
  Ok(attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
}

/// Opens the directory a cookie directory will be created INSIDE, purely so the
/// create can be anchored beneath it.
///
/// Nothing is ever read or written through this handle. It is the
/// `RootDirectory` of the create's `OBJECT_ATTRIBUTES`, which is what lets that
/// create name only a LEAF and resolve no path at all — see
/// [`create_directory_at`], which is where the anchoring earns its keep.
///
/// The requested access is ZERO, and that is the whole requirement rather than a
/// shortcut. Microsoft defines `RootDirectory` only as the directory a relative
/// `ObjectName` is resolved against and specifies no access for it; name
/// resolution checks `FILE_TRAVERSE` against each INTERMEDIATE component of the
/// path, never against the root the walk starts from — and this create names a
/// bare leaf, so there is no intermediate component at all. The right the create
/// truly needs on this directory is `FILE_ADD_SUBDIRECTORY`, and the create
/// itself checks that, against the parent's security descriptor rather than
/// against anything this handle was granted.
///
/// So do NOT add `FILE_LIST_DIRECTORY` back. Enumerating is a right this handle
/// never exercises, and Windows makes listing a directory and creating a
/// subdirectory in it INDEPENDENT rights. A watched descendant whose ACL permits
/// the create and denies the listing would fail this open, killing every
/// sync-cookie write beneath it before the mint ever ran.
/// `FILE_TRAVERSE` is no safer: a right named in `dwDesiredAccess` is checked
/// against the DACL of the object BEING OPENED, and `SeChangeNotifyPrivilege` —
/// held by essentially everyone — only skips the checks on a path's intermediate
/// directories, so it buys no relief for a traverse denied on this one. Any bit
/// beyond zero can only turn a create this process is permitted to make into
/// `ACCESS_DENIED`.
///
/// That is the rule every mask in the cookie path is written to, not a special
/// case for this one: derive the bits from the operations the handle actually
/// performs, and refuse a right on the grounds that it is unused rather than
/// keep it on the grounds that it is permitted. [`create_directory_at`] and
/// `driver::CookieDir`'s own two opens each carry the same derivation.
///
/// `FILE_FLAG_BACKUP_SEMANTICS` is required for a handle on a directory at all,
/// and total sharing keeps this handle — like every other one here — from
/// pinning the tree against a peer's rename or delete.
///
/// This open is BY PATH and follows reparse points exactly as the `create_dir`
/// it replaced did, so a component swapped in between the caller's
/// `canonicalize` and this call is still followed. That residual is the caller's
/// (see `FsOps::write_cookie`) and is deliberately not widened here: what the
/// anchor removes is everything BELOW it, because the leaf is never looked up
/// twice.
pub(crate) fn open_cookie_parent(path: &Path) -> io::Result<OwnedHandle> {
  let path = wide(path);
  // SAFETY: `path` is NUL-terminated and outlives the call; null security
  // attributes and template are the documented "none".
  let raw = unsafe {
    CreateFileW(
      path.as_ptr(),
      0,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      std::ptr::null(),
      OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS,
      std::ptr::null_mut(),
    )
  };
  if raw == INVALID_HANDLE_VALUE {
    return Err(io::Error::last_os_error());
  }
  // SAFETY: freshly returned by a successful CreateFileW and owned by no one
  // else; OwnedHandle takes over closure.
  Ok(unsafe { OwnedHandle::from_raw_handle(raw as _) })
}

/// CREATES a directory named `leaf` directly inside the directory `parent`
/// refers to, and answers the handle THAT CREATE produced.
///
/// One call binds the name and yields the object, which is the whole point.
/// `CreateDirectoryW` returns no handle — Microsoft documents that obtaining one
/// means opening the name again — and between those two calls a peer with write
/// access to the parent can unlink the new directory and stand its own there, so
/// the retained handle would describe an object this process never made and the
/// disposal at retirement would destroy it. `NtCreateFile` has no such window:
/// the handle it returns IS the object it created.
///
/// The parameters, and why each is what it is:
///
/// * `FILE_CREATE` fails if the name exists at all, so nothing pre-existing can
///   ever be adopted and no reparse point can be followed into. An occupied name
///   comes back as `AlreadyExists`, which is exactly what the mint loop retries
///   on (`driver::mint_step`).
/// * `FILE_DIRECTORY_FILE` makes the created object a directory, so there is no
///   later verdict to take about what kind of object this is.
/// * `FILE_SYNCHRONOUS_IO_NONALERT` keeps the handle synchronous, and is also
///   what puts `SYNCHRONIZE` in the access mask — see the derivation below.
/// * `FILE_OPEN_REPARSE_POINT` is deliberately NOT here, and its absence takes
///   nothing away. `FILE_CREATE` fails on a pre-existing leaf of ANY kind, a
///   reparse point included, so the no-follow guarantee is already total without
///   it. What the flag could add is a failure: it is not among the options
///   Microsoft documents as compatible with `FILE_DIRECTORY_FILE`, so a driver
///   holding to that contract can reject the whole create with
///   `STATUS_INVALID_PARAMETER` — which `security::nt_create` reads as `Failed`
///   rather than a collision, so the mint would abort and every sync-cookie
///   write on such a filesystem would fail.
/// * `OBJ_CASE_INSENSITIVE` is what makes an occupied name collide the way
///   Windows resolves names. Unlike Win32, which always sets it, the NT layer
///   leaves the name match to the kernel's own case policy without it — so on a
///   system where that resolves case-sensitively, a differently-cased spelling
///   of a candidate would NOT collide and the mint would bind a case-variant
///   sibling of a directory somebody else owns. Asking for it makes the
///   collision the same fact on every system.
/// * Sharing is total, so retaining the handle pins nothing: a peer may still
///   delete or rename the tree around it, exactly as the cookie file's own
///   retained handle already allows.
///
/// The security descriptor is null, so the new directory inherits the parent's
/// access-control list — the same thing `create_dir` did, and the reason the
/// contract on `driver::CookieDir` says the directory takes no permission away
/// on this platform.
///
/// # The access mask, derived from what the handle DOES
///
/// `DELETE | SYNCHRONIZE`, and each bit is there because an operation this call
/// performs cannot proceed without it. That is the test the mask is written
/// against — not whether a right sounds related to a directory, and not whether
/// the create's contract permits it. "Legal" and "required" are different
/// questions, and only the second one keeps a permitted create off
/// `ACCESS_DENIED`.
///
/// The handle this returns performs exactly ONE operation for its whole life:
/// the delete disposition [`delete_by_handle`] sets at retirement.
/// `driver::CookieDir` holds it for nothing else — no attribute read, no
/// enumeration, no identity read, and no reparse verdict, since the mint takes
/// its answer from this create's own `NTSTATUS` instead. So:
///
/// * `DELETE` is what that disposition requires. `NtSetInformationFile`
///   documents it for both classes [`delete_by_handle`] can set —
///   `FileDispositionInformation` and `FileDispositionInformationEx` each say
///   the caller must have opened the file with the DELETE flag set in
///   `DesiredAccess` — and `SetFileInformationByHandle` says the same for the
///   Win32 spelling. It is MANDATORY rather than opportunistic: a volume or ACL
///   that refuses it fails the CREATE — a loud, bounded, typed write failure —
///   instead of yielding a directory this process can never clean up. The
///   deleted reading (retry without `DELETE` and carry on) leaked one directory
///   per obligation, forever and uncounted, precisely because a fresh one is
///   minted each time.
/// * `SYNCHRONIZE` is what `FILE_SYNCHRONOUS_IO_NONALERT` requires:
///   `NtCreateFile` states that if that flag is set, the SYNCHRONIZE flag must
///   be set in `DesiredAccess`. It is the create OPTION's requirement rather
///   than an operation's, and it is the reason the option is worth naming at
///   all here.
///
/// And nothing else. `FILE_READ_ATTRIBUTES` stood here and is deliberately
/// gone: what it authorises is the attribute-reading query classes
/// (`FileBasicInformation`, `FileAttributeTagInformation`,
/// `FileNetworkOpenInformation` — the ones `NtQueryInformationFile` names it
/// for), and this handle issues none of them. A right the create merely MAY ask
/// for is not thereby one it needs: Windows makes creating a subdirectory and
/// reading a directory's attributes independent rights, so an ACL that grants
/// `FILE_ADD_SUBDIRECTORY` and `DELETE` while denying attribute reads would
/// fail this create outright — and with it every sync-cookie write beneath that
/// directory, which is the whole cost of one unused bit. Do NOT add it back,
/// and do not add `FILE_LIST_DIRECTORY` or `FILE_TRAVERSE` either:
/// [`open_cookie_parent`] states the same rule for the anchor, whose requested
/// access is zero for exactly this reason.
pub(crate) fn create_directory_at(
  parent: BorrowedHandle<'_>,
  leaf: &str,
) -> io::Result<OwnedHandle> {
  use crate::os::windows::security::{self, NtCreate};

  let name: Vec<u16> = leaf.encode_utf16().collect();
  // A `UNICODE_STRING` measures BYTES, not code units, in a `u16` — so the
  // conversion is checked rather than cast. A cookie directory's name is ~36
  // characters, so this can only fire on a name nothing in this crate mints.
  let bytes = u16::try_from(size_of_val(name.as_slice())).map_err(|_| {
    io::Error::new(
      io::ErrorKind::InvalidInput,
      "a cookie directory name longer than a UNICODE_STRING can measure",
    )
  })?;
  let unicode = UNICODE_STRING {
    Length: bytes,
    MaximumLength: bytes,
    Buffer: name.as_ptr().cast_mut(),
  };
  let attributes = OBJECT_ATTRIBUTES {
    Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
    RootDirectory: parent.as_raw_handle() as HANDLE,
    ObjectName: &raw const unicode,
    Attributes: OBJ_CASE_INSENSITIVE,
    SecurityDescriptor: std::ptr::null(),
    SecurityQualityOfService: std::ptr::null(),
  };
  let mut status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
  let mut opened: HANDLE = std::ptr::null_mut();
  // SAFETY: every pointer handed over is to a live local that outlives the call,
  // and the kernel reads or writes each exactly as documented.
  //
  // * `&raw mut opened` is a writable `HANDLE` the call fills in on success.
  // * `&raw const attributes` is a fully initialized `OBJECT_ATTRIBUTES` whose
  //   `Length` is its own `size_of`, which is how the kernel versions it.
  // * `attributes.ObjectName` points at `unicode`, a live `UNICODE_STRING` bound
  //   to a local — not a temporary — so it is not dropped before the call.
  // * `unicode.Buffer` points at `name`, a `Vec<u16>` bound to a local for the
  //   same reason, and `Length`/`MaximumLength` are its size in BYTES (checked
  //   into `u16` above), which is the unit `UNICODE_STRING` is defined in. The
  //   buffer is only read: this create takes a name, it does not return one.
  // * `attributes.RootDirectory` is borrowed for the call by the type system.
  // * A null security descriptor and null quality-of-service are the documented
  //   "none" (inherit the parent's ACL, no impersonation).
  // * `&raw mut status_block` is a writable, zeroed `IO_STATUS_BLOCK`.
  // * A null allocation size and a null extended-attribute buffer with length 0
  //   are the documented "none" for both.
  let status = unsafe {
    NtCreateFile(
      &raw mut opened,
      DELETE | SYNCHRONIZE,
      &raw const attributes,
      &raw mut status_block,
      std::ptr::null(),
      FILE_ATTRIBUTE_NORMAL,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      FILE_CREATE,
      FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
      std::ptr::null(),
      0,
    )
  };
  // Taken over BEFORE the verdict below, so no arm of it can leak a handle the
  // kernel did hand back — including the informational name status, which is a
  // success by NT's severity rule and still not this call's own directory.
  let handle = (status >= 0 && !opened.is_null()).then(||
    // SAFETY: a success-severity `NtCreateFile` wrote a fresh handle owned by no
    // one else into `opened`; `OwnedHandle` takes over its closure.
    unsafe { OwnedHandle::from_raw_handle(opened as _) });

  match security::nt_create(status) {
    NtCreate::Bound => handle
      .ok_or_else(|| io::Error::other("NtCreateFile reported success without returning a handle")),
    // Nothing was created, so nothing behind that name is this call's to enter
    // or to remove: the handle — if the kernel returned one at all — is closed
    // here and the name is left exactly as it was found.
    NtCreate::Collided => Err(io::Error::new(
      io::ErrorKind::AlreadyExists,
      "the cookie directory's name was already bound",
    )),
    NtCreate::Denied => Err(io::Error::new(
      io::ErrorKind::PermissionDenied,
      "creating a cookie directory was denied",
    )),
    NtCreate::Failed => {
      // SAFETY: `RtlNtStatusToDosError` reads no memory beyond its argument and
      // cannot fail; it is the documented lowering of an `NTSTATUS` to the Win32
      // error code `io::Error` speaks.
      let code = unsafe { RtlNtStatusToDosError(status) };
      Err(if code == 0 {
        // No Win32 code for this status. Reporting it as error 0 would render
        // the failure as "the operation completed successfully".
        io::Error::other(format!(
          "creating a cookie directory failed with NTSTATUS {:#010x}",
          status as u32
        ))
      } else {
        io::Error::from_raw_os_error(code as i32)
      })
    }
  }
}

/// What `FSCTL_QUERY_USN_JOURNAL` reports about a volume's live journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct JournalFacts {
  /// The journal's identity — a read cursor is valid only against it.
  pub(super) journal_id: u64,
  /// The oldest USN still in the journal.
  pub(super) first_usn: i64,
  /// The next USN the journal will mint (the live-only anchor).
  pub(super) next_usn: i64,
  /// The lowest record major version the volume emits.
  pub(super) min_major: u16,
  /// The highest record major version the volume emits.
  pub(super) max_major: u16,
}

/// Opens the volume device (`\\.\X:`) hosting `drive` for journal reads.
/// Effectively requires elevation — the probe ladder's privilege
/// discriminator.
pub(super) fn open_volume(drive: char) -> io::Result<OwnedHandle> {
  let device: Vec<u16> = format!(r"\\.\{drive}:").encode_utf16().chain([0]).collect();
  // SAFETY: `device` is NUL-terminated and outlives the call; null security
  // attributes and template are the documented "none".
  let raw = unsafe {
    CreateFileW(
      device.as_ptr(),
      GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      std::ptr::null(),
      OPEN_EXISTING,
      FILE_FLAG_OVERLAPPED,
      std::ptr::null_mut(),
    )
  };
  if raw == INVALID_HANDLE_VALUE {
    return Err(io::Error::last_os_error());
  }
  // SAFETY: freshly returned by a successful CreateFileW, owned by no one
  // else; OwnedHandle takes over closure.
  Ok(unsafe { OwnedHandle::from_raw_handle(raw as _) })
}

/// Queries the volume's journal state (synchronous — the query is cheap and
/// the barrier runs before the pump exists).
pub(super) fn query_journal(volume: BorrowedHandle<'_>) -> io::Result<JournalFacts> {
  let mut data: USN_JOURNAL_DATA_V1 = unsafe { std::mem::zeroed() };
  let mut returned = 0u32;
  // SAFETY: the handle is live; `data` is a properly-sized, writable
  // USN_JOURNAL_DATA_V1 and the control code matches the struct; a null
  // OVERLAPPED makes the call synchronous on this handle... the handle is
  // OVERLAPPED-opened, so an OVERLAPPED is REQUIRED: use a local zeroed one
  // and wait inline via GetOverlappedResult.
  let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
  let ok = unsafe {
    DeviceIoControl(
      volume.as_raw_handle() as HANDLE,
      FSCTL_QUERY_USN_JOURNAL,
      std::ptr::null(),
      0,
      (&raw mut data).cast(),
      size_of::<USN_JOURNAL_DATA_V1>() as u32,
      &raw mut returned,
      &raw mut overlapped,
    )
  };
  if ok == 0 {
    // SAFETY: reads the calling thread's last-error slot.
    let error = unsafe { GetLastError() };
    if error != ERROR_IO_PENDING {
      return Err(io::Error::from_raw_os_error(error as i32));
    }
    // SAFETY: the overlapped and handle are live; bWait blocks until the
    // pended query completes.
    let done = unsafe {
      GetOverlappedResult(
        volume.as_raw_handle() as HANDLE,
        &raw const overlapped,
        &raw mut returned,
        1,
      )
    };
    if done == 0 {
      return Err(io::Error::last_os_error());
    }
  }
  Ok(JournalFacts {
    journal_id: data.UsnJournalID,
    first_usn: data.FirstUsn,
    next_usn: data.NextUsn,
    min_major: data.MinSupportedMajorVersion,
    max_major: data.MaxSupportedMajorVersion,
  })
}

/// Issues one overlapped journal read from `start_usn` into `buffer`.
///
/// `BytesToWaitFor = 1` with `Timeout = 0` pends until the journal grows —
/// the IOCP delivers the completion, so the pump's wait model is identical
/// to the RDCW read. `MinMajorVersion..=MaxMajorVersion` is pinned 2..=3
/// (the decode's ceiling; V4 range-tracking is never enabled).
///
/// # Safety
///
/// The caller guarantees the P1 pin for `buffer`, `overlapped`, AND `read`
/// (the kernel reads the request struct for the operation's lifetime), and
/// at most one journal read outstanding per volume handle (P2).
pub(super) unsafe fn issue_journal_read(
  volume: BorrowedHandle<'_>,
  read: *mut READ_USN_JOURNAL_DATA_V1,
  buffer: &mut [u8],
  overlapped: *mut OVERLAPPED,
) -> io::Result<()> {
  let len = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
  // SAFETY: the handle is live and OVERLAPPED-opened; request/buffer/
  // overlapped validity and exclusivity are the caller's contract; the
  // returned-bytes pointer may be null for an overlapped call.
  let ok = unsafe {
    DeviceIoControl(
      volume.as_raw_handle() as HANDLE,
      FSCTL_READ_USN_JOURNAL,
      read.cast(),
      size_of::<READ_USN_JOURNAL_DATA_V1>() as u32,
      buffer.as_mut_ptr().cast(),
      len,
      std::ptr::null_mut(),
      overlapped,
    )
  };
  if ok == 0 {
    // SAFETY: reads the calling thread's last-error slot.
    let error = unsafe { GetLastError() };
    if error != ERROR_IO_PENDING {
      return Err(io::Error::from_raw_os_error(error as i32));
    }
  }
  Ok(())
}

/// Reads one directory-enumeration page THROUGH the handle
/// (`FileIdExtdDirectoryInfo`): `Ok(Some(bytes))` = a page landed in
/// `buffer`, `Ok(None)` = the listing is exhausted. `restart` selects the
/// restart class for the first page. Enumerating through the handle — never
/// a path — is what binds the walk to the verified directory OBJECT.
pub(crate) fn read_directory_page(
  handle: BorrowedHandle<'_>,
  buffer: &mut [u8],
  restart: bool,
) -> io::Result<Option<usize>> {
  let class = if restart {
    FileIdExtdDirectoryRestartInfo
  } else {
    FileIdExtdDirectoryInfo
  };
  // SAFETY: the handle is live; the buffer is writable for its full length
  // and the class matches the record layout the kernel writes.
  let ok = unsafe {
    GetFileInformationByHandleEx(
      handle.as_raw_handle() as HANDLE,
      class,
      buffer.as_mut_ptr().cast(),
      u32::try_from(buffer.len()).unwrap_or(u32::MAX),
    )
  };
  if ok == 0 {
    // SAFETY: reads the calling thread's last-error slot.
    let error = unsafe { GetLastError() };
    if error == ERROR_NO_MORE_FILES {
      return Ok(None);
    }
    return Err(io::Error::from_raw_os_error(error as i32));
  }
  // The kernel does not report bytes written; the chain's own
  // NextEntryOffset walk terminates it, so the full buffer is handed to
  // the bounds-proven decoder.
  Ok(Some(buffer.len()))
}
