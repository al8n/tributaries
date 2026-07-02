//! Filesystem source crate for the `tributaries` stack.
//!
//! `tributary-fs` is the `std`, async driver layer over the Sans-I/O
//! [`tributary-proto`] Monitor: it performs the real OS filesystem watching and
//! lowers raw kernel events into the Monitor's normalized vocabulary. The first
//! backend is macOS FSEvents — kernel-recursive, one native stream per watched
//! root — with every unsafe platform call confined to the internal `os` module
//! behind a platform-neutral seam.
//!
//! The consumer-facing watcher API is not exposed yet; the crate currently
//! provides the OS seam, the sans-I/O driver core, the async driver task,
//! and their test suites.
//!
//! [`tributary-proto`]: tributary_proto

#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
// The public watcher facade (the crate's consumer surface) sits above this
// machinery; until it lands, only the test suites exercise the top layer.
#![allow(dead_code, unused_imports)]

mod core;
mod driver;
mod os;
