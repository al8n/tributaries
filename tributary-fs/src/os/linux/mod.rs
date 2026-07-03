//! The Linux backends: inotify (descending) and, later, fanotify-FILESYSTEM
//! (kernel-recursive), selected per root by `Backend::Auto`.
//!
//! Pure machinery (decode tables, `wd` bookkeeping) compiles everywhere tests
//! run, mirroring the transport/fsevent precedent; the FFI Source layer is
//! `cfg(all(target_os = "linux", not(miri)))` and lands with the reader
//! thread.
// The Source layer is this module's consumer; until it lands the items here
// are exercised only by their test suites.
#![allow(dead_code)]

pub(crate) mod inotify;

use inotify::decode::RawInotifyEvent;

/// The decoded Linux event payload — the platform's transport `E`. The
/// fanotify arm joins when that backend lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RawLinuxEvent {
  /// One decoded inotify record.
  Inotify(RawInotifyEvent),
}

impl RawLinuxEvent {
  /// The inotify record, if this is one.
  pub(crate) fn as_inotify(&self) -> Option<&RawInotifyEvent> {
    match self {
      Self::Inotify(event) => Some(event),
    }
  }
}
