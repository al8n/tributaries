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
//!
//! Generation safety across `wd` reuse: the kernel's cyclic `wd` allocator makes
//! reuse of a still-draining `wd` remote (~2³¹ arms), but the table stays correct
//! on its own regardless. Registering onto a draining `wd` REPLACES the tombstone
//! with a fresh live entry AND records that one stale `IN_IGNORED` is still queued
//! for the OLD watch — the next `IN_IGNORED` clears that pending mark WITHOUT
//! erasing the new live anchor set (which would silently drop a live watch). The
//! `IN_IGNORED` after that (impossible under the kernel's one-final-event
//! contract, but not assumed) erases legitimately.
//!
//! Attribution across the reuse window: the kernel queues a watch's final
//! `IN_IGNORED` BEFORE the `wd` can be handed to a new `add_watch`, so the queue
//! reads `old records…, old IN_IGNORED, new records…`. Between a reuse
//! [`register`](WdTable::register) and the stale `IN_IGNORED` that closes it, a
//! NON-`IN_IGNORED` record on the `wd` is therefore one of those OLD records:
//! attributing it to the fresh anchor set would be a silent wrong-watch delivery.
//! So while `pending_stale_ignored > 0` the `wd` is in an AMBIGUOUS window and
//! [`attribute`](WdTable::attribute) returns [`Attribution::Ambiguous`] for every
//! non-`IN_IGNORED` record — the reader fences it behind the loss barrier (a
//! covering rescan re-enumerates and re-attributes truthfully) rather than
//! guessing. Each stale `IN_IGNORED` still routes to
//! [`on_ignored`](WdTable::on_ignored), decrementing the count; when it reaches
//! zero the window closes and attribution resumes over the new set (whose own
//! arm-enumerate already covered its initial state). Removals can stack, so
//! `pending_stale_ignored` is a COUNT and the fence holds until the LAST stale
//! marker drains — never a per-`wd` bool that a first IGNORED would clear early.

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

/// The attribution outcome for one decoded NON-`IN_IGNORED` record on a `wd`
/// (the `IN_IGNORED` marker itself routes through [`WdTable::on_ignored`], never
/// here).
#[derive(Debug)]
pub(crate) enum Attribution<'a> {
  /// The record fans out to these live anchors. Empty for an unknown or fully
  /// drained `wd` — the caller skips it without loss (the core's own liveness
  /// already dropped that watch).
  Attributed(&'a [WatchId]),
  /// The `wd` is in the AMBIGUOUS REUSE WINDOW: a fresh anchor set was installed
  /// over a not-yet-drained old incarnation whose stale `IN_IGNORED` is still
  /// queued ahead of any of the new watch's events (see the module invariant).
  /// This record therefore belongs to the OLD watch, so attributing it to the
  /// new set would be a silent wrong-watch delivery; the caller fences it behind
  /// the loss barrier (a covering rescan re-attributes truthfully) instead.
  Ambiguous,
}

/// One `wd`'s bookkeeping: the anchors still attributing, whether the
/// kernel-side removal was already issued, and how many stale `IN_IGNORED`s from
/// a previous (drained) incarnation of this `wd` are still queued ahead of this
/// live entry.
#[derive(Debug, Default)]
struct WdEntry {
  live: Vec<WatchId>,
  draining: bool,
  /// Stale `IN_IGNORED`s a previous incarnation left queued. Registering onto a
  /// draining `wd` bumps this so the next IGNORED clears the tombstone remnant
  /// WITHOUT erasing this fresh live set. Non-zero only across a `wd`-reuse race.
  pending_stale_ignored: u32,
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
  ///
  /// Registering onto a DRAINING `wd` (a fresh install landed on a `wd` whose
  /// tombstone still awaits its `IN_IGNORED`) is a `wd`-reuse race: the tombstone
  /// is replaced with a fresh live entry and the stale IGNORED is remembered
  /// (`pending_stale_ignored`) so it clears the remnant rather than erasing the
  /// new anchor. A live entry just appends.
  pub(crate) fn register(&mut self, wd: i32, anchor: WatchId) {
    let entry = self.entries.entry(wd).or_default();
    if entry.draining {
      // The old incarnation's IGNORED is still queued; step out of draining into
      // a fresh live generation and mark that one IGNORED must be absorbed.
      entry.draining = false;
      entry.live.clear();
      entry.pending_stale_ignored = entry.pending_stale_ignored.saturating_add(1);
    }
    entry.live.push(anchor);
    self.by_anchor.insert(anchor, wd);
  }

  /// Records an additional anchor onto an EXISTING `wd` — the `EEXIST`
  /// aliasing path (one inode reached through two names). `EEXIST` is returned
  /// by the kernel only for a LIVE watch, so the target entry is never draining
  /// here; the shared `register` path handles it either way.
  pub(crate) fn alias(&mut self, wd: i32, anchor: WatchId) {
    debug_assert!(
      self.entries.get(&wd).is_some_and(|entry| !entry.draining),
      "EEXIST aliasing targets a live kernel watch, never a draining tombstone"
    );
    self.register(wd, anchor);
  }

  /// The attribution decision for a NON-`IN_IGNORED` record on `wd`.
  ///
  /// [`Attribution::Ambiguous`] while the `wd` is in the reuse window
  /// (`pending_stale_ignored > 0`, per the module invariant): the record may
  /// belong to the OLD incarnation queued ahead of its stale `IN_IGNORED`, so it
  /// is fenced to loss rather than mis-attributed to the fresh set. Otherwise
  /// [`Attribution::Attributed`] over the live anchor set — empty for an unknown
  /// or fully drained `wd` (a late record for an unwatched anchor is dropped by
  /// the core's own liveness checks).
  pub(crate) fn attribute(&self, wd: i32) -> Attribution<'_> {
    match self.entries.get(&wd) {
      Some(entry) if entry.pending_stale_ignored > 0 => Attribution::Ambiguous,
      Some(entry) => Attribution::Attributed(&entry.live),
      None => Attribution::Attributed(&[]),
    }
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
  ///
  /// A STALE IGNORED left over from a drained incarnation this `wd` was reused
  /// for is absorbed instead of erasing: it clears one `pending_stale_ignored`
  /// and leaves the fresh live set (and its `by_anchor` links) intact, so a
  /// live watch that reused the `wd` is never silently dropped.
  pub(crate) fn on_ignored(&mut self, wd: i32) -> Vec<WatchId> {
    if let Some(entry) = self.entries.get_mut(&wd)
      && entry.pending_stale_ignored > 0
    {
      entry.pending_stale_ignored -= 1;
      return Vec::new();
    }
    let Some(entry) = self.entries.remove(&wd) else {
      return Vec::new();
    };
    for anchor in &entry.live {
      self.by_anchor.remove(anchor);
    }
    entry.live
  }
}
