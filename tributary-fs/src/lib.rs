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
mod watcher;

pub use error::{
  BuildError, CloseError, ReplaceRootError, SyncRootError, UnwatchError, WatchRootError,
};
pub use event::{Event, EventKind, MovedEvent};
pub use options::WatcherOptions;
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

/// A [`Watcher`] driven by the tokio runtime.
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub type TokioWatcher = Watcher<agnostic_lite::tokio::TokioRuntime>;

/// A [`Watcher`] driven by the smol runtime.
#[cfg(feature = "smol")]
#[cfg_attr(docsrs, doc(cfg(feature = "smol")))]
pub type SmolWatcher = Watcher<agnostic_lite::smol::SmolRuntime>;
