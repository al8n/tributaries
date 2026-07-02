//! Linux inotify backend profile (per-directory, not kernel-recursive).
//!
//! The universal, unprivileged Linux default. One watch per directory; the core
//! descends, arming a watch before reading each new directory. Its concrete driver
//! lives in the future `tributaries` crate: it lowers raw inotify events into
//! [`OsRecord`](crate::OsRecord)s, sources object [`Identity`](crate::Identity) (a
//! `(dev, ino)` hash) and `IN_MOVED_FROM` / `IN_MOVED_TO` cookies for the
//! [`Monitor`](crate::Monitor) to consume, and owns the `WatchId` ↔ `wd` table so
//! `wd`-reuse / ABA, `IN_IGNORED` teardown, and inode aliasing (one `wd` backing
//! several anchors) stay below the core.
//!
//! This module is a placeholder for that backend profile.
