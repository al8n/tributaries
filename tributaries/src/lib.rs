//! The public top-level crate of the `tributaries` filesystem-notification stack.
//!
//! [`tributary-fs`](tributary_fs) deliberately watches only **disjoint** roots
//! (it rejects a new root that overlaps an existing one) because subsuming
//! overlapping trees is the layer above's job. `tributaries` is that layer. It:
//!
//! 1. accepts possibly-**overlapping** watch subscriptions from the caller and
//!    **subsumes** them into the disjoint roots `tributary-fs` requires — N
//!    overlapping subscriptions collapse to one kernel watch of their common
//!    ancestor;
//! 2. **attributes** each raw event back to *every* caller subscription that
//!    covers its path, retagged with that subscription's id;
//! 3. offers optional consumer conveniences — a filter and an opt-in
//!    settle/debounce coalescer — without touching the hardened core.
//!
//! Everything hard (identity, move-pairing, loss-is-a-`Rescan`, epoch dominance)
//! already lives in the Monitor and ships through [`tributary_fs::Event`];
//! `tributaries` adds routing and consumer ergonomics, not new correctness logic.
//!
//! # Quick start
//!
//! Watch possibly-overlapping paths — each with its own [`Filter`] — optionally settle
//! bursts with a [`DebounceConfig`], and pull the merged, attributed stream. Each event
//! is retagged with the [`Subscription`] it belongs to, so one change under an overlap
//! is delivered to every covering subscription under its own id.
//!
//! ```no_run
//! # #[cfg(feature = "tokio")]
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use std::{ffi::OsString, path::Path};
//!
//! use tributaries::{DebounceConfig, Filter, Interest, TokioTributaries, TributariesOptions};
//!
//! // The local-fs source keys on a path's components (the caller supplies canonical paths).
//! fn key(path: &str) -> Vec<OsString> {
//!   Path::new(path)
//!     .components()
//!     .map(|c| c.as_os_str().to_os_string())
//!     .collect()
//! }
//!
//! // Opt into the settle coalescer (omit `.debounce(..)` for raw pass-through).
//! let options = TributariesOptions::new().debounce(DebounceConfig::new());
//! let mut tributaries = TokioTributaries::new(options)?;
//!
//! // A subscription that only reports Rust sources — the filter is live-swappable.
//! let sources = Filter::new(|event| event.path().extension().is_some_and(|x| x == "rs"));
//! let handle = sources.clone(); // shares the swappable slot with the one `watch` holds
//! let project = tributaries
//!   .watch(key("/path/to/project"), (), Interest::all(), sources)
//!   .await?;
//!
//! // An OVERLAPPING watch of a subtree — accepted, never `Overlaps`: it is subsumed
//! // onto the same kernel watch, and a change under it fans out to both subscriptions.
//! let tests = tributaries
//!   .watch(key("/path/to/project/tests"), (), Interest::all(), Filter::all())
//!   .await?;
//!
//! // Re-scope what `project` delivers at any time — no re-watch:
//! handle.swap(|_| true);
//!
//! while let Some(event) = tributaries.next().await {
//!   // `event.subscription()` is `project` or `tests`; a `Rescan` reaches every
//!   // subscriber of the affected root regardless of filter (coverage loss).
//!   println!(
//!     "{} [{}]: {}",
//!     event.kind(),
//!     event.subscription(),
//!     event.path().display()
//!   );
//!   let _ = (project, tests);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Subsumption
//!
//! The subsumption engine is the control plane: a sans-I/O state machine over an
//! [`iradix`] radix keyed by canonical root paths. It plans each `watch` into one
//! of three cases — the subtree is already covered, the new path *widens* over
//! existing roots (which are drained and re-pointed onto it), or it is disjoint —
//! keeping the live root set pairwise disjoint at all times. It is pure logic over
//! paths and an abstract root-id, so it is exhaustively property-tested with no
//! real filesystem, clock, or runtime.
//!
//! # Settle / debounce (opt-in)
//!
//! A caller that only cares about the *settled* state of a file — not every
//! intermediate write of an editor-save or a `cp` — can opt into the coalescer by
//! setting a [`DebounceConfig`] on [`TributariesOptions`]. It is a second sans-I/O
//! state machine: it buffers attributed events per `(subscription, path)` and
//! collapses a burst to a single emission on a settle timer, while treating a
//! [`Moved`](EventKind::Moved) atomically and flushing on a
//! [`Rescan`](EventKind::Rescan) so coverage loss is never held back or lost. Absent a
//! `DebounceConfig`, events pass through untouched at zero cost.

#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]

mod coalesce;
mod driver;
mod error;
mod event;
mod filter;
mod options;
mod route;
mod source;
mod subscription;
pub(crate) mod subsume;
mod view;

pub use driver::Tributaries;
pub use error::{BuildError, CloseError, UnwatchError, WatchError};
pub use event::Event;
pub use filter::{Filter, FilterInput};
pub use options::{DebounceConfig, TributariesOptions};
pub use source::{Armed, FsSource, Source, SourceEvent};
pub use subscription::{InstanceId, Subscription};
pub use view::{Snapshot, WatchView};

#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub use driver::TokioTributaries;

#[cfg(feature = "smol")]
#[cfg_attr(docsrs, doc(cfg(feature = "smol")))]
pub use driver::SmolTributaries;

/// The event vocabulary, options, root handle, and change-id/epoch/location types are
/// re-exported from [`tributary-fs`](tributary_fs) unchanged — this crate retags events,
/// it does not redefine them. [`RootHandle`] is the [`FsSource`] armed-root token
/// ([`Source::Handle`]).
pub use tributary_fs::{
  ChangeId, Epoch, EventKind, Interest, Location, MovedEvent, RootHandle, Segment, WatcherOptions,
};
