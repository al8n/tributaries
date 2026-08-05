#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]

mod core;
mod driver;
mod error;
mod event;
mod options;
mod os;
mod stamped;
mod watcher;

pub use driver::is_sync_cookie_dir_name;
pub use error::{
  BuildError, CloseError, ReplaceRootError, SyncRootError, UnwatchError, WatchRootError,
};
pub use event::{Event, EventKind, MovedEvent};
pub use options::{OptionsError, WatcherOptions};
pub use os::{Backend, BackendKind, BackendStats, ProbeStage, SourceError};
pub use watcher::{
  CoverOutcome, RequestOutcome, RootHandle, SkipReason, SyncAdmission, SyncRootDenied, SyncTicket,
  Watcher,
};

pub use tributary_proto::{ChangeId, Epoch, Interest, Location, ScopeId, Segment};

// Test-only surface for the real-kernel integration suites: forcing an
// inotify instance rebuild deterministically requires lowering the reader's
// descriptor threshold, which no production configuration exposes.
#[cfg(all(target_os = "linux", not(miri), any(test, feature = "_integration")))]
#[doc(hidden)]
pub use os::linux::inotify::reader::override_rebuild_threshold_for_tests;

// Test-only surface for the real-journal integration suite. The USN measurement
// that licensed a deletion has to be ENFORCED by the cell that takes it, and the
// enforcement has to be the source's own delta arithmetic rather than a second
// copy of it in a test — so the decision lives beside the code that relies on it
// and the cell asks it here.
#[cfg(all(target_os = "windows", not(miri), any(test, feature = "_integration")))]
#[doc(hidden)]
pub use os::windows::usn::premise::{
  ExpectedMove, PremiseRecord, PremiseVerdict, RenameHalf, moves_are_recorded_afresh,
};

/// A [`Watcher`] driven by the tokio runtime.
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub type TokioWatcher = Watcher<agnostic_lite::tokio::TokioRuntime>;

/// A [`Watcher`] driven by the smol runtime.
#[cfg(feature = "smol")]
#[cfg_attr(docsrs, doc(cfg(feature = "smol")))]
pub type SmolWatcher = Watcher<agnostic_lite::smol::SmolRuntime>;
