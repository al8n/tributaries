//! The `wd → anchors` attribution table.
//!
//! One kernel watch descriptor can back SEVERAL Monitor watches: arming an
//! already-watched inode fails `EEXIST` under `IN_MASK_CREATE`, and the
//! second anchor is then registered onto the existing `wd` ([`WdTable::alias`])
//! so records fan out per anchor instead of silently mis-attributing.
//!
//! Draining discipline: `inotify_rm_watch` is issued only when the last live
//! anchor leaves ([`WdTable::begin_drain`] returns [`DrainDecision::RemoveWd`]
//! exactly once), and the entry itself survives — draining — until the queued
//! `IN_IGNORED` is consumed: `IN_IGNORED` is the guaranteed final event for a
//! `wd` and therefore the authoritative erase point ([`WdTable::on_ignored`]).

use std::collections::BTreeMap;

use tributary_proto::WatchId;

/// What the caller must do with the kernel watch after an anchor drained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DrainDecision {
  /// The last live anchor left: issue `inotify_rm_watch(fd, wd)`. Returned at
  /// most once per `wd` lifetime.
  RemoveWd(i32),
  /// Live anchors remain (or the entry is already draining): the kernel watch
  /// stays.
  KeepWd,
}

/// One `wd`'s bookkeeping: the anchors still attributing, and whether the
/// kernel-side removal was already issued.
#[derive(Debug, Default)]
struct WdEntry {
  live: Vec<WatchId>,
  draining: bool,
}

/// The `wd ↔ anchors` table (attribution below the core, per the proto's
/// inotify profile contract).
#[derive(Debug, Default)]
pub(crate) struct WdTable {
  entries: BTreeMap<i32, WdEntry>,
  by_anchor: BTreeMap<WatchId, i32>,
}

impl WdTable {
  /// An empty table.
  pub(crate) fn new() -> Self {
    Self::default()
  }

  /// Records a freshly-installed kernel watch backing `anchor`.
  pub(crate) fn register(&mut self, wd: i32, anchor: WatchId) {
    self.entries.entry(wd).or_default().live.push(anchor);
    self.by_anchor.insert(anchor, wd);
  }

  /// Records an additional anchor onto an EXISTING `wd` — the `EEXIST`
  /// aliasing path (one inode reached through two names).
  pub(crate) fn alias(&mut self, wd: i32, anchor: WatchId) {
    self.register(wd, anchor);
  }

  /// The anchors a record on `wd` fans out to. Empty for an unknown or fully
  /// drained `wd` (a late record for an unwatched anchor is dropped by the
  /// core's own liveness checks).
  pub(crate) fn anchors(&self, wd: i32) -> &[WatchId] {
    self
      .entries
      .get(&wd)
      .map(|entry| entry.live.as_slice())
      .unwrap_or(&[])
  }

  /// Whether `wd` is known at all — live or draining.
  pub(crate) fn contains(&self, wd: i32) -> bool {
    self.entries.contains_key(&wd)
  }

  /// Removes `anchor` from attribution. Returns
  /// [`DrainDecision::RemoveWd`] iff this was the last live anchor and the
  /// kernel removal has not been issued yet — the entry then survives as
  /// draining until [`Self::on_ignored`].
  pub(crate) fn begin_drain(&mut self, anchor: WatchId) -> DrainDecision {
    let Some(wd) = self.by_anchor.remove(&anchor) else {
      return DrainDecision::KeepWd;
    };
    let Some(entry) = self.entries.get_mut(&wd) else {
      return DrainDecision::KeepWd;
    };
    entry.live.retain(|a| *a != anchor);
    if entry.live.is_empty() && !entry.draining {
      entry.draining = true;
      DrainDecision::RemoveWd(wd)
    } else {
      DrainDecision::KeepWd
    }
  }

  /// Consumes the `wd`'s `IN_IGNORED` — the authoritative erase. Returns the
  /// anchors that were still live (kernel-initiated teardown fans an
  /// `Ignored` record out to each); empty when the teardown was self-induced
  /// and the anchors already drained.
  pub(crate) fn on_ignored(&mut self, wd: i32) -> Vec<WatchId> {
    let Some(entry) = self.entries.remove(&wd) else {
      return Vec::new();
    };
    for anchor in &entry.live {
      self.by_anchor.remove(anchor);
    }
    entry.live
  }
}
