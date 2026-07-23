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
//! Its by-construction corollary: a draining tombstone exists only while the
//! kernel can still OWE its marker, so proof that it cannot — the removal
//! answering `EINVAL` on a valid owned fd — erases the entry immediately
//! ([`WdTable::erase_dead`]).
//!
//! # The adoption invariant (uniqueness safety without `wd` reuse)
//!
//! A `wd` is ADOPTABLE only while this table maps nothing on it — and the
//! reader makes that unconditional by never letting a `wd` be granted twice
//! on one fd. The kernel's per-instance allocator (`inotify_new_watch`'s
//! `idr_alloc_cyclic`, start 1) grants strictly increasing `wd`s until a
//! grant past `i32::MAX` would wrap its cursor back over freed values; the
//! reader tracks the high-water mark and REBUILDS the instance — a fresh fd
//! and a fresh table, with a whole-instance loss signalled so the Monitor
//! re-proves every retained binding on the new fd — before the cursor could
//! get there (the reader's `Instance`). A table therefore maps only `wd`s
//! its own fd granted below the wrap edge, every fresh install's `wd` is
//! strictly greater than all of them, and the invariant every consumer leans
//! on holds by construction:
//!
//! *everything consumed on a mapped `wd` belongs to that mapping.*
//!
//! Why this must be structural rather than handled: a stale mapping — a
//! binding whose kernel watch died with its teardown records swallowed by a
//! queue loss — may still have leftovers queued (its final `IN_IGNORED`, or
//! pre-death records), and whether they are still coming is unknowable
//! table-side. Any fresh binding sharing that `wd` could be erased by the
//! surviving marker (a silently unwatched live subtree under a settleable
//! barrier), and any fence provisioned against the marker must guess whether
//! a loss dropped it — wrong in one direction or the other. With `wd`s never
//! re-granted, no such sharing can exist to be disposed of.
//!
//! - An `IN_IGNORED` consumed on a mapped `wd` is the mapping's own final
//!   marker: erasing the entry and fanning its remaining live anchors into
//!   the kernel-teardown funnel is truthful — a live-mapped entry whose watch
//!   died lost its OBJECT with it (deletion or unmount is the only way a
//!   kernel watch dies underneath a mapping this table did not drain itself).
//!   On an unmapped `wd` the marker no-ops.
//! - A record consumed on a mapped `wd` is the mapping's own traffic and fans
//!   out to its live anchors; on an unmapped or draining `wd` it addresses a
//!   watch the core already dropped and is skipped without loss.
//!
//! Loss recovery: a DECODE-level loss (an `IN_Q_OVERFLOW` sentinel — the
//! kernel dropped queued events, inotify(7) — or a truncated / absurd-length /
//! malformed record that stops the decode walk) can drop a draining
//! tombstone's awaited `IN_IGNORED`, and nothing else would ever reap the
//! tombstone. [`WdTable::on_loss`] erases every draining tombstone: safe even
//! when the marker actually survived behind the sentinel, because the erased
//! `wd` is never granted again on this fd (no-wrap), so the straggling marker
//! no-ops on the unmapped `wd` unconditionally, and the covering rescan the
//! loss triggers rebuilds coverage truthfully. Live entries are left intact —
//! they await no marker: a live mapping whose markers were dropped is
//! reconciled by that same rescan's binding re-proof (its anchor's re-add
//! supersedes the binding, or its parent's re-enumerate reports the removal).

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

  /// The `wd` currently backing `anchor`, if any — the reader's rebind
  /// pre-check (a re-add landing on a different `wd` supersedes this binding).
  pub(crate) fn wd_of(&self, anchor: WatchId) -> Option<i32> {
    self.by_anchor.get(&anchor).copied()
  }

  /// Records a FRESHLY-INSTALLED kernel watch backing `anchor`. Only an
  /// UNMAPPED `wd` is ever adopted (the module's adoption invariant): a
  /// fresh install's `wd` is granted strictly past every `wd` this table
  /// maps, because the reader rebuilds the instance before the allocator
  /// could wrap. A prior binding of `anchor` on a different `wd` must be
  /// drained by the caller first ([`begin_drain`](Self::begin_drain)).
  pub(crate) fn register(&mut self, wd: i32, anchor: WatchId) {
    debug_assert!(
      !self.entries.contains_key(&wd),
      "a fresh install's wd is granted past every mapped one (no-wrap)"
    );
    debug_assert!(
      !self.by_anchor.contains_key(&anchor),
      "a rebind drains the old binding before registering"
    );
    self.entries.entry(wd).or_default().live.push(anchor);
    self.by_anchor.insert(anchor, wd);
  }

  /// Records an additional anchor onto an EXISTING `wd` — the `EEXIST`
  /// aliasing path (one inode reached through two names, or a re-add of a
  /// binding that was live all along). `EEXIST` is the kernel's proof the
  /// watch is LIVE, and every live watch on the fd was adopted through
  /// [`register`](Self::register), so its `wd` is mapped live here (the
  /// reader refuses the `EEXIST` path's one counterexample — the target
  /// watch dying between the probe and the re-add turns the re-add into a
  /// fresh create on a fresh, unmapped `wd` — before it can reach this
  /// aliasing). An anchor already on the entry keeps a single live slot (the
  /// re-add dedup — a duplicate would fan every record out twice).
  pub(crate) fn alias(&mut self, wd: i32, anchor: WatchId) {
    debug_assert!(
      self.is_live(wd),
      "EEXIST aliasing targets a live mapped watch"
    );
    debug_assert!(
      self.by_anchor.get(&anchor).is_none_or(|bound| *bound == wd),
      "a cross-wd rebind drains the old binding before aliasing"
    );
    let entry = self.entries.entry(wd).or_default();
    self.by_anchor.insert(anchor, wd);
    if entry.live.contains(&anchor) {
      return;
    }
    entry.live.push(anchor);
  }

  /// The anchors a NON-`IN_IGNORED` record on `wd` fans out to (the
  /// `IN_IGNORED` marker itself routes through [`on_ignored`](Self::on_ignored),
  /// never here). Empty for an unknown or draining `wd` — the record addresses
  /// a watch the core already dropped, and the caller skips it without loss.
  pub(crate) fn attribute(&self, wd: i32) -> &[WatchId] {
    self
      .entries
      .get(&wd)
      .map_or(&[], |entry| entry.live.as_slice())
  }

  /// Whether `wd` is known at all — live or draining. A known `wd` is not
  /// adoptable — and a fresh install can never land on one, its grant being
  /// strictly past every mapped `wd` (the module's adoption invariant).
  pub(crate) fn contains(&self, wd: i32) -> bool {
    self.entries.contains_key(&wd)
  }

  /// Whether `wd` is mapped with live anchors (not draining) — the aliasing
  /// gate: an `EEXIST` re-add's `wd` must land here, anything else is a
  /// fresh create in disguise (its target watch died between the two adds)
  /// and is refused.
  pub(crate) fn is_live(&self, wd: i32) -> bool {
    self.entries.get(&wd).is_some_and(|entry| !entry.draining)
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

  /// Consumes an `IN_IGNORED` on `wd` — the authoritative erase. Returns the
  /// anchors that were still live (kernel-initiated teardown fans an
  /// `Ignored` record out to each); empty when the teardown was self-induced
  /// and the anchors already drained, or when the `wd` is unmapped (a marker
  /// straggling behind its entry's erase — a refused disguised-create's
  /// removal marker, or a tombstone's own after a loss reaped it — no-ops
  /// harmlessly).
  ///
  /// The marker always belongs to the mapping it lands on (the adoption
  /// invariant), so erasing here can never take down a binding the marker did
  /// not address.
  pub(crate) fn on_ignored(&mut self, wd: i32) -> Vec<WatchId> {
    let Some(entry) = self.entries.remove(&wd) else {
      return Vec::new();
    };
    for anchor in &entry.live {
      self.by_anchor.remove(anchor);
    }
    entry.live
  }

  /// Erases every draining tombstone after a DECODE-level loss — an
  /// `IN_Q_OVERFLOW` sentinel or a truncated / absurd-length / malformed
  /// record that dropped the decode tail.
  ///
  /// Such a loss means bytes the stream would have carried are gone
  /// (inotify(7)): a tombstone's awaited final `IN_IGNORED` may be among
  /// them, and nothing else ever reaps a tombstone — it would strand as a
  /// leaked entry for the fd's whole life. Erasing is safe even when the
  /// marker actually survived (queued behind the sentinel): the erased `wd`
  /// is never granted again on this fd (no-wrap), so the straggling marker
  /// is consumed as an unmapped no-op ([`on_ignored`](Self::on_ignored)) —
  /// no fresh binding can ever stand where it lands. Live entries are left
  /// intact — they never await a marker, and the covering rescan the loss
  /// triggers reconciles them (a re-add supersedes a dead one, a
  /// re-enumerate reports its object's removal). A draining tombstone has an
  /// empty live set and no `by_anchor` link pointing at it (both cleared
  /// when its last anchor drained), so erasing it keeps the reverse index
  /// consistent.
  pub(crate) fn on_loss(&mut self) {
    self.entries.retain(|_wd, entry| !entry.draining);
  }

  /// Erases ONE draining tombstone whose marker the kernel can no longer owe:
  /// `inotify_rm_watch` answered `EINVAL` on a valid owned fd, which is the
  /// kernel's statement that no such watch exists — so either its `IN_IGNORED`
  /// is already queued (the benign auto-removal race) or a queue loss
  /// swallowed it, and nothing else would ever reap the entry.
  ///
  /// A draining tombstone exists only while the kernel can still owe its
  /// marker; proof that it cannot erases it at once. Safe in both cases by the
  /// module's adoption invariant, exactly as [`on_loss`](Self::on_loss) is: the
  /// erased `wd` is never granted again on this fd, so a marker that DID
  /// survive is consumed as an unmapped no-op, and records arriving between
  /// now and that marker were already skipped identically under `draining` and
  /// under unmapped.
  pub(crate) fn erase_dead(&mut self, wd: i32) {
    debug_assert!(
      self
        .entries
        .get(&wd)
        .is_some_and(|entry| entry.draining && entry.live.is_empty()),
      "only a draining tombstone is erased by proof of a marker the kernel cannot owe"
    );
    self.entries.remove(&wd);
  }
}
