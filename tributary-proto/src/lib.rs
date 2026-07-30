#![doc = include_str!("../README.md")]
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
