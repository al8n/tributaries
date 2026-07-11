//! The Windows backends: `ReadDirectoryChangesW` (unprivileged) and, later,
//! the USN change journal (privileged-preferred), selected per volume by
//! `Backend::Auto`.
//!
//! Pure machinery (the record decode, the payload vocabulary) compiles
//! everywhere tests run, mirroring the transport/fsevent/linux precedent; the
//! FFI layer (directory handles, OVERLAPPED reads, the per-source IOCP pump
//! thread) is `cfg(all(target_os = "windows", not(miri)))` and reduces every
//! completion to these types as early as possible.

pub(crate) mod rdcw;

pub(crate) use rdcw::decode::{DecodedBuffer, RdcwAction, RdcwName, RdcwRecord};

/// One decoded Windows source event as it crosses the pump→driver queue.
///
/// The USN arm arrives with the journal backend; the enum exists from the
/// start so the seam payload, the driver lowering, and the hermetic twins
/// name one Windows shape throughout the campaign.
#[derive(Debug, Clone, PartialEq, Eq)]
// The driver lowering consumes this in the next stage; the vocabulary and its
// decode land first so the twins pin the byte-level contract early.
#[allow(dead_code)]
pub(crate) enum RawWindowsEvent {
  /// One decoded `ReadDirectoryChangesW` record.
  Rdcw(RdcwRecord),
}
