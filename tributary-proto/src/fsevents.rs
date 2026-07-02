//! macOS FSEvents backend profile (kernel-recursive).
//!
//! The macOS backend. One `FSEventStream` per root with `FileEvents` +
//! `UseExtendedData` (inode / file id), kernel-recursive — no per-directory watches,
//! no walk race, no watch limit. Its concrete driver lives in the future `tributaries`
//! crate: it sources object [`Identity`](crate::Identity) from the file id (pairing two
//! `ItemRenamed` records into a move) and maps `MustScanSubDirs` / `UserDropped` /
//! `KernelDropped` to an overflow the [`Monitor`](crate::Monitor) turns into a rescan.
//!
//! This module is a placeholder for that backend profile.
