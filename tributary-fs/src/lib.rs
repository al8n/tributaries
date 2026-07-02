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
//! provides the OS seam and its test suites.
//!
//! [`tributary-proto`]: tributary_proto

#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
// The seam's in-crate consumers (the driver task and the public watcher) sit
// above this layer; until they land, only the test suites exercise it.
#![allow(dead_code, unused_imports)]

mod os;
