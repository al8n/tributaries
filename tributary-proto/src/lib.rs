//! Pure Sans-I/O state machine — the *brain* of the `tributaries`
//! filesystem-notification stack.
//!
//! This crate is `no_std` (with `alloc`) and contains **no I/O, no syscalls, and
//! no clock reads**. It is the quinn-proto-style core that the `tributaries`
//! driver feeds normalized [`OsRecord`]s and drains [`Action`]s and [`Change`]s
//! from. All the logic the design calls out as easy to get wrong — recursion,
//! overflow handling, move pairing, watch-limit degradation — lives here as a
//! pure, testable state machine, written once and shared across every backend.
//!
//! # Shape
//!
//! The [`Monitor`] is the primitive-agnostic *top half*: it owns the
//! proto-minted handle registries ([`WatchId`], [`ReqId`], [`ChangeId`]), the
//! parent-relative watch tree (so paths are reconstructed by walking to a root),
//! delivery dedup, move normalization, overflow → [`ChangeKind::Rescan`],
//! emission, and — given the object [`Identity`] the driver supplies — whether a
//! same-name reappearance is the same object. Backend-specific behavior enters only
//! as *data*, never as a trait the engine is generic over: the static
//! [`Capabilities`] a monitor is built with (whether the core descends per-directory
//! or leans on a kernel-recursive watch is gated by
//! [`Capabilities::kernel_recursive`]) and the optional [`Identity`] carried on each
//! record and entry. The concrete per-backend driver — the syscalls, the
//! `WatchId` ↔ raw-handle table, identity sourcing — lives in the `tributaries` crate.
//!
//! # Driver contract
//!
//! Inputs (driver → core): [`Monitor::on_os_record`],
//! [`Monitor::on_enumerate`], [`Monitor::on_watch_result`],
//! [`Monitor::on_overflow`], [`Monitor::handle_timeout`]. Outputs (core →
//! driver): [`Monitor::poll_action`], [`Monitor::poll_event`],
//! [`Monitor::poll_timeout`]. The driver owns the `WatchId` ↔ raw-handle table;
//! the core never sees a raw OS handle.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
#![deny(missing_docs)]

// The crate floor is alloc: every configuration needs collections and strings,
// so the alias is unconditional off-std rather than gated behind a feature.
#[cfg(not(feature = "std"))]
extern crate alloc as std;

#[cfg(feature = "std")]
extern crate std;

pub mod action;
pub mod capabilities;
pub mod change;
pub mod error;
pub mod id;
pub mod interest;
pub mod monitor;
pub mod path;
pub mod record;
pub mod scope;
pub mod time;

pub mod fanotify;
pub mod fsevents;
pub mod inotify;

pub use action::{
  Action, EnumerateCommand, StatChild, StatCommand, StatTarget, WatchAck, WatchChild, WatchCommand,
  WatchTarget,
};
pub use capabilities::Capabilities;
pub use change::{Change, ChangeKind};
pub use error::WatchError;
pub use id::{ChangeId, Epoch, Identity, MoveCookie, ReqId, ScopeId, WatchId};
pub use interest::Interest;
pub use monitor::Monitor;
pub use path::{Location, Segment};
pub use record::{DirEntry, EnumerateResult, FileKind, IoClass, OsRecord, RecordKind};
pub use scope::{Scope, SubtreeScope};
pub use time::Instant;
