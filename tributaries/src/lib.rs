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
//! # Subsumption
//!
//! The subsumption engine is the control plane: a sans-I/O state machine over an
//! [`iradix`] radix keyed by canonical root paths. It plans each `watch` into one
//! of three cases — the subtree is already covered, the new path *widens* over
//! existing roots (which are drained and re-pointed onto it), or it is disjoint —
//! keeping the live root set pairwise disjoint at all times. It is pure logic over
//! paths and an abstract root-id, so it is exhaustively property-tested with no
//! real filesystem, clock, or runtime.

#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]

mod driver;
mod error;
mod event;
mod route;
mod subscription;
pub(crate) mod subsume;

pub use driver::Tributaries;
pub use error::{BuildError, CloseError, UnwatchError, WatchError};
pub use event::Event;
pub use subscription::Subscription;

#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub use driver::TokioTributaries;

#[cfg(feature = "smol")]
#[cfg_attr(docsrs, doc(cfg(feature = "smol")))]
pub use driver::SmolTributaries;

/// The event vocabulary, options, and change-id/epoch/location types are re-exported
/// from [`tributary-fs`](tributary_fs) unchanged — this crate retags events, it does
/// not redefine them.
pub use tributary_fs::{
  ChangeId, Epoch, EventKind, Interest, Location, MovedEvent, Segment, WatcherOptions,
};
