//! Linux fanotify-FILESYSTEM sub-machine (kernel-recursive, privileged).
//!
//! A privileged Linux accelerator selected per disjoint root when the
//! preconditions hold (`CAP_SYS_ADMIN`, a recent kernel, a file-handle-encoding
//! filesystem, a whole-volume scope). One `FAN_MARK_FILESYSTEM` per root watches
//! the entire subtree; the core does not descend. A third sub-machine shape —
//! kernel-recursive but path-by-handle — filtering the superblock firehose by
//! parent-FID membership in a seeded `fsid+handle → path` map.
//!
//! This module is a placeholder for the foundation milestone.

// TODO: implement the fanotify-FILESYSTEM sub-machine per docs/2026-06-28-tributaries-design.md §6b.
