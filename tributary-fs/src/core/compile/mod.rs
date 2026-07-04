//! Per-backend lowerings of raw source events into planned Monitor inputs.
//!
//! `DriverCore::compile` dispatches here by the scope's backend profile:
//! FSEvents flag words are hints and probe-ground (see [`fsevents`]); inotify
//! records are precise verbs with native cookies and lower directly (see
//! [`inotify`]); fanotify records are precise verbs on a kernel-recursive
//! stream, lowered to root-relative targets with interned-FID identity and
//! atomic rename pairing (see [`fanotify`]). The shared vocabulary
//! (`PendingBatch`, `Planned`, the trust and identity policies) stays in the
//! core — a lowering produces inputs, it never owns state.

pub(super) mod fanotify;
pub(super) mod fsevents;
pub(super) mod inotify;
