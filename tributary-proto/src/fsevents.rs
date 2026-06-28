//! macOS FSEvents sub-machine (kernel-recursive).
//!
//! The macOS backend. One `FSEventStream` per root with `FileEvents` +
//! `UseExtendedData` (inode / file id), kernel-recursive — no per-directory
//! watches, no walk race, no watch limit. This sub-machine owns FSEvents
//! identity: pairing two `ItemRenamed` records by file id into a move, and
//! mapping `MustScanSubDirs` / `UserDropped` / `KernelDropped` to a rescan.
//!
//! This module is a placeholder for the foundation milestone.

// TODO: implement the FSEvents sub-machine per docs/2026-06-28-tributaries-design.md §7.
