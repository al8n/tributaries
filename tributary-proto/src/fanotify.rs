//! Linux fanotify-FILESYSTEM backend profile (kernel-recursive, privileged).
//!
//! A privileged Linux accelerator selected per disjoint root when the preconditions
//! hold (`CAP_SYS_ADMIN`, a recent kernel, a file-handle-encoding filesystem, a
//! whole-volume scope). One `FAN_MARK_FILESYSTEM` per root watches the entire subtree;
//! the core does not descend. Its concrete driver lives in the future `tributaries`
//! crate: kernel-recursive but path-by-handle, it sources object identity from FIDs and
//! filters the superblock firehose by parent-FID membership in a seeded
//! `fsid+handle → path` map.
//!
//! This module is a placeholder for that backend profile.

// TODO: the fanotify-FILESYSTEM driver lives in the `tributaries` crate; see docs/2026-06-28-tributaries-design.md §6b.
