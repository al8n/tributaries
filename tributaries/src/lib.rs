//! The public top-level crate of the `tributaries` filesystem-notification stack.
//!
//! `tributary-fs` deliberately watches only **disjoint** roots
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
//! already lives in the Monitor and ships through `tributary-fs`'s own event type;
//! `tributaries` adds routing and consumer ergonomics, not new correctness logic.
//!
//! The local-filesystem binding — `FsSource`, the `RootHandle`/`WatcherOptions`
//! re-exports, the pure-fs constructor and runtime aliases — rides the **`fs` feature,
//! on by default**. With it off, the crate is the generic core over `tributary-proto`
//! alone: bring your own [`Source`] (or [`LocalSource`]) and construct through
//! [`Tributaries::with_source`]/[`Tributaries::parts`]/[`Tributaries::parts_local`].
//!
//! # Quick start
//!
//! Watch possibly-overlapping paths — each under its own per-watch [`WatchOptions`]
//! (interest, [`Filter`], [`Debounce`] posture) — optionally settle bursts with a
//! [`DebounceConfig`], and pull the merged, attributed stream. Each event is retagged
//! with the [`Subscription`] it belongs to, so one change under an overlap is delivered
//! to every covering subscription under its own id.
//!
//! ```no_run
//! # #[cfg(all(feature = "tokio", feature = "fs"))]
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use std::{ffi::OsString, path::Path};
//!
//! use tributaries::{
//!   Debounce, DebounceConfig, Filter, TokioTributaries, TributariesOptions, WatchOptions,
//!   WatcherOptions,
//! };
//!
//! // The local-fs source keys on a path's components (the caller supplies canonical paths).
//! fn key(path: &str) -> Vec<OsString> {
//!   Path::new(path)
//!     .components()
//!     .map(|c| c.as_os_str().to_os_string())
//!     .collect()
//! }
//!
//! // The fs watcher's own transport options ride separately from the umbrella's knobs.
//! // Opt into the settle coalescer (omit `.debounce(..)` for raw pass-through).
//! let options = TributariesOptions::new().debounce(DebounceConfig::new());
//! let mut tributaries = TokioTributaries::new(WatcherOptions::new(), options)?;
//!
//! // A subscription that only reports Rust sources — the filter is live-swappable.
//! let sources = Filter::new(|event| event.path().extension().is_some_and(|x| x == "rs"));
//! let handle = sources.clone(); // shares the swappable slot with the one `watch` holds
//! let project = tributaries
//!   .watch(
//!     key("/path/to/project"),
//!     (),
//!     WatchOptions::new().with_filter(sources),
//!   )
//!   .await?;
//!
//! // An OVERLAPPING watch of a subtree — accepted, never `Overlaps`: it is subsumed
//! // onto the same kernel watch, and a change under it fans out to both subscriptions.
//! // Its per-watch Debounce::Off overrides the global debounce: raw pass-through for
//! // this subscription while `project` keeps settling.
//! let logs = tributaries
//!   .watch(
//!     key("/path/to/project/logs"),
//!     (),
//!     WatchOptions::new().with_debounce(Debounce::Off),
//!   )
//!   .await?;
//!
//! // Re-scope what `project` delivers at any time — no re-watch:
//! handle.swap(|_| true);
//!
//! while let Some(event) = tributaries.next().await {
//!   // `event.subscription()` is `project` or `logs`; a `Rescan` reaches every
//!   // subscriber of the affected root regardless of filter (coverage loss).
//!   println!(
//!     "{} [{}]: {}",
//!     event.kind(),
//!     event.subscription(),
//!     event.path().display()
//!   );
//!   let _ = (project, logs);
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
//! [`Rescan`](EventKind::Rescan) so coverage loss is never held back or lost.
//!
//! The global config is a per-subscription **default**: each watch can override its own
//! posture with a [`Debounce`] on its [`WatchOptions`] — [`Debounce::Off`] for raw
//! pass-through while siblings settle, [`Debounce::Custom`] for its own windows (which
//! also *enables* settling when the global debounce is off). Absent a `DebounceConfig`
//! and absent any `Custom` override, events pass through untouched at zero cost.

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
pub use error::{BuildError, CloseError, FaultKind, SourceFault, UnwatchError, WatchError};
pub use event::{Event, EventKind};
pub use filter::{Filter, FilterInput};
pub use interest::Interest;
pub use options::{Debounce, DebounceConfig, TributariesOptions, WatchOptions};
pub use source::{Armed, LocalSource, Source, SourceEvent};
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
#[cfg(feature = "fs")]
#[cfg_attr(docsrs, doc(cfg(feature = "fs")))]
pub use tributary_fs::{RootHandle, WatcherOptions};

/// The identity/coordinate primitives — change id, epoch, location — are owned by
/// `tributary-proto` and re-exported from there directly (`tributary-fs` merely
/// re-exports them itself). The per-watch [`Interest`] is **not** among them: the
/// umbrella owns its own source-neutral mask (aligned to [`EventKind`]), and the
/// proto/fs `Interest` stays a purely fs-internal arm mask for consumers driving a raw
/// fs watcher.
pub use tributary_proto::{ChangeId, Epoch, Location, Segment};
