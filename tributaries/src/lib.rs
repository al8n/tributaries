#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]

mod coalesce;
mod demux;
mod driver;
mod error;
mod event;
mod filter;
mod interest;
mod options;
mod route;
mod source;
mod subscription;
pub(crate) mod subsume;
mod view;

pub use demux::{Demux, Lane};
pub use driver::Tributaries;
pub use error::{
  BuildError, CloseError, FaultKind, SourceCloseError, SourceFault, UnwatchError, WatchError,
  WordsConflict,
};
pub use event::{Event, EventKind};
pub use filter::{Filter, FilterInput};
pub use interest::Interest;
pub use options::{
  Debounce, DebounceConfig, OptionsError, RootGlobs, TributariesOptions, WatchOptions,
};
pub use source::{Armed, LocalSource, Source, SourceEvent};

/// The sync barrier's vocabulary, behind the experimental `sync` feature.
#[cfg(feature = "sync")]
#[cfg_attr(docsrs, doc(cfg(feature = "sync")))]
pub use crate::{
  error::SyncError,
  source::{Begun, SyncOutcome, SyncToken},
};
pub use subscription::{InstanceId, Subscription};
pub use view::{Snapshot, WatchView};

#[cfg(feature = "fs")]
#[cfg_attr(docsrs, doc(cfg(feature = "fs")))]
pub use source::FsSource;

#[cfg(all(feature = "fs", feature = "tokio"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "fs", feature = "tokio"))))]
pub use driver::TokioTributaries;

#[cfg(all(feature = "fs", feature = "smol"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "fs", feature = "smol"))))]
pub use driver::SmolTributaries;

/// The umbrella **owns** the source-neutral event vocabulary ([`EventKind`], with the
/// move endpoint carried in-kind): each source — the fs binding included — maps into it
/// at its binding, so the fs-only event types (`tributary_fs::EventKind`,
/// `tributary_fs::MovedEvent`) stay in [`tributary-fs`](tributary_fs) for fs consumers.
/// Only the two fs-binding types surface here (with the default `fs` feature):
/// [`RootHandle`] is the [`FsSource`] armed-root token ([`Source::Handle`]), and
/// [`WatcherOptions`] configures the underlying filesystem watcher it drives.
///
/// [`Backend`] and [`BackendKind`] ride beside them because A KNOB'S TYPE HAS TO
/// BE NAMEABLE BY WHOEVER NAMES THE HOUSEHOLD: [`WatcherOptions::backend`] is a
/// `Backend`, so a consumer that reaches this crate for the household and not for
/// the fs binding under it — a configuration layer holding a [`WatcherOptions`],
/// anything restating its knobs — had no path to that field's type at all, and
/// could not spell the value for a setter this crate already gives it. The two
/// are one question and its RESOLVED answer: `Backend` is what a deployment ASKS
/// for (`Auto` included) and `BackendKind` is what a watcher actually armed.
#[cfg(feature = "fs")]
#[cfg_attr(docsrs, doc(cfg(feature = "fs")))]
pub use tributary_fs::{Backend, BackendKind, RootHandle, WatcherOptions};

/// The identity/coordinate primitives — change id, epoch, location — and the glob
/// vocabulary the per-root seats ([`RootGlobs`]) are spelled in are owned by
/// `tributary-proto` and re-exported from there directly (`tributary-fs` merely
/// re-exports them itself). The per-watch [`Interest`] is **not** among them: the
/// umbrella owns its own source-neutral mask (aligned to [`EventKind`]), and the
/// proto/fs `Interest` stays a purely fs-internal arm mask for consumers driving a raw
/// fs watcher.
pub use tributary_proto::{
  ChangeId, Epoch, Location, Segment,
  glob::{Glob, GlobError, Globs},
};
