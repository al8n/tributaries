//! Filesystem source crate for the `tributaries` stack.
//!
//! `tributary-fs` is the `std`, async driver layer over the Sans-I/O
//! [`tributary-proto`] Monitor: it performs the real OS filesystem watching
//! and lowers raw kernel events into the Monitor's normalized vocabulary. The
//! first backend is macOS FSEvents — kernel-recursive, one native stream per
//! watched root — with every unsafe platform call confined to the internal
//! `os` module behind a platform-neutral seam.
//!
//! The crate is runtime-agnostic through [`agnostic_lite::RuntimeLite`]:
//! enable the `tokio` (or `smol`) feature and use the [`TokioWatcher`]
//! ([`SmolWatcher`]) alias, or bring any other `RuntimeLite` implementation.
//! On platforms without a backend the crate still compiles; watching returns
//! [`SourceError::Unsupported`].
//!
//! # Quick start
//!
//! ```no_run
//! # #[cfg(feature = "tokio")]
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use tributary_fs::{Interest, TokioWatcher, WatcherOptions};
//!
//! let mut watcher = TokioWatcher::new(WatcherOptions::new())?;
//! let root = watcher.watch("/path/to/project", Interest::all()).await?;
//! println!("watching {:?}", watcher.root_path(root));
//! while let Some(event) = watcher.next().await {
//!   println!("{}: {}", event.kind(), event.path().display());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # The two contracts
//!
//! - **Watching means "changes from now on."** No initial inventory is
//!   delivered. Consumers that need a snapshot start the watch first, then
//!   crawl — see [`Watcher::watch`].
//! - **Loss is never silent.** Every coverage gap surfaces as a
//!   [`Rescan`](EventKind::Rescan) event whose [`Event::epoch`] dominates
//!   everything delivered before it — see [`Event::epoch`] for the
//!   re-enumeration contract.
//!
//! [`tributary-proto`]: tributary_proto

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

pub use error::{BuildError, CloseError, UnwatchError, WatchRootError};
pub use event::{Event, EventKind, MovedEvent};
pub use options::WatcherOptions;
pub use os::{Backend, BackendKind, BackendStats, SourceError};
pub use watcher::{CoverOutcome, RootHandle, SkipReason, Watcher};

pub use tributary_proto::{ChangeId, Epoch, Interest, Location, ScopeId, Segment};

/// A [`Watcher`] driven by the tokio runtime.
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub type TokioWatcher = Watcher<agnostic_lite::tokio::TokioRuntime>;

/// A [`Watcher`] driven by the smol runtime.
#[cfg(feature = "smol")]
#[cfg_attr(docsrs, doc(cfg(feature = "smol")))]
pub type SmolWatcher = Watcher<agnostic_lite::smol::SmolRuntime>;
