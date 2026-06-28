//! Linux inotify sub-machine (per-directory, not kernel-recursive).
//!
//! The universal, unprivileged Linux default. One watch per directory; the core
//! descends, arming a watch before reading each new directory. This sub-machine
//! owns inotify's identity quirks: inode aliasing (one `wd` backing several
//! anchors), `wd`-reuse / ABA detection, `IN_IGNORED` teardown, and
//! `IN_MOVED_FROM` / `IN_MOVED_TO` cookie pairing.
//!
//! This module is a placeholder for the foundation milestone.

// TODO: implement the inotify sub-machine per docs/2026-06-28-tributaries-design.md §6.
