//! macOS FSEvents backend profile (kernel-recursive).
//!
//! The macOS backend. One `FSEventStream` per root with `FileEvents` +
//! `UseExtendedData` (inode / file id), kernel-recursive — no per-directory watches,
//! no walk race, no watch limit. Its concrete driver is the `tributary-fs` crate: it
//! lowers each full event path to a root-relative record target, sources object
//! [`Identity`](crate::Identity) from the file id (pairing two `ItemRenamed` records
//! into a move, with the file id as the cookie), and maps `MustScanSubDirs` /
//! `UserDropped` / `KernelDropped` to an overflow — a located
//! [`SubtreeScope`](crate::SubtreeScope) for the targeted form — that the
//! [`Monitor`](crate::Monitor) turns into a rescan.
//!
//! This module is a placeholder for that backend profile.
