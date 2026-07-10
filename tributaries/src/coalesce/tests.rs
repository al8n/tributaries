use core::{num::NonZeroU64, time::Duration};
use std::{
  ffi::OsString,
  path::{Path, PathBuf},
  time::Instant,
};

use tributary_proto::{Epoch, Location, ScopeId};

use super::Coalescer;
use crate::{
  event::{Event, EventKind},
  options::DebounceConfig,
  subscription::Subscription,
};

/// The delivered-event type this coalescer buffers: the fs `C = OsString`, `V = ()`.
type Ev = Event<OsString, ()>;

/// A subscription with the given non-zero id.
fn sub(id: u64) -> Subscription {
  Subscription::for_test(ScopeId::new(NonZeroU64::new(id).expect("nonzero id")))
}

/// A path's `OsString` components — the located-key form the fs source keys on.
fn key(path: &str) -> Vec<OsString> {
  Path::new(path)
    .components()
    .map(|c| c.as_os_str().to_os_string())
    .collect()
}

/// A synthetic event of `kind` for `s` at `path`, stamped `epoch`. The coalescer only
/// reads `subscription`/`key`/`kind`/`epoch`/`location`, so a synthetic stand-in
/// exercises it without the private `tributary_fs::Event` constructor. Its `location`
/// is a fresh (root-anchored) one — the coalescer never keys on `location`.
fn ev(s: Subscription, path: &str, kind: EventKind<OsString>, epoch: u64) -> Ev {
  Event::synthetic(s, key(path), Location::new(), kind, Epoch::new(epoch))
}

fn created(s: Subscription, path: &str, epoch: u64) -> Ev {
  ev(s, path, EventKind::Created, epoch)
}

fn modified(s: Subscription, path: &str, epoch: u64) -> Ev {
  ev(s, path, EventKind::Modified, epoch)
}

fn removed(s: Subscription, path: &str, epoch: u64) -> Ev {
  ev(s, path, EventKind::Removed, epoch)
}

/// A synthetic whole-move fixture: an [`EventKind::Moved`] whose in-kind `from` is the
/// rename source — directly constructible now that the umbrella owns the vocabulary.
/// The coalescer keys on `move_from` (the kind's payload); tests inspect it via
/// [`is_moved`] / `move_from`.
fn moved(s: Subscription, path: &str, from: &str, epoch: u64) -> Ev {
  ev(s, path, EventKind::Moved { from: key(from) }, epoch)
}

/// Whether `ev` is a move — the same wrapper-level detector the coalescer uses.
fn is_moved(ev: &Ev) -> bool {
  ev.move_from().is_some()
}

/// The move source of `ev` as a path — reconstructed from its located source key.
fn move_from_path(ev: &Ev) -> PathBuf {
  PathBuf::from_iter(ev.move_from().expect("a move source"))
}

fn rescan(s: Subscription, path: &str, epoch: u64) -> Ev {
  ev(s, path, EventKind::Rescan, epoch)
}

/// A short settle window and a hold cap a few windows out — round numbers so the
/// deadline arithmetic in the tests is obvious.
fn config() -> DebounceConfig {
  DebounceConfig::new()
    .with_quiet_window(Duration::from_millis(10))
    .with_max_hold(Duration::from_millis(100))
}

/// A fixed clock origin plus a `+ms` helper, so every test uses an explicit manual
/// clock and never reads real time.
struct Clock {
  origin: Instant,
}

impl Clock {
  fn new() -> Self {
    Self {
      origin: Instant::now(),
    }
  }

  /// `origin + ms` milliseconds.
  fn at(&self, ms: u64) -> Instant {
    self.origin + Duration::from_millis(ms)
  }
}

/// Drain everything due at `now` into a fresh `Vec`.
fn drain(coalescer: &mut Coalescer<OsString, ()>, now: Instant) -> Vec<Ev> {
  let mut out = Vec::new();
  coalescer.drain_ready(now, &mut out);
  out
}

// -------------------------------------------------------------------------------
// Collapse table (design §6): one test per named row.
// -------------------------------------------------------------------------------

#[test]
fn created_then_modified_stays_created() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config());
  let s = sub(1);

  assert!(c.admit(created(s, "/a/f", 1), clk.at(0)).is_none());
  assert!(c.admit(modified(s, "/a/f", 2), clk.at(1)).is_none());

  // Nothing before the settle window; one Created after it.
  assert!(
    drain(&mut c, clk.at(5)).is_empty(),
    "held during the window"
  );
  let out = drain(&mut c, clk.at(11));
  assert_eq!(out.len(), 1, "the burst collapses to a single event");
  assert!(
    out[0].kind().is_created(),
    "a created-then-modified stays Created"
  );
  assert_eq!(out[0].path(), PathBuf::from("/a/f"));
}

#[test]
fn modified_coalesces() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config());
  let s = sub(1);

  for (n, epoch) in [1, 2, 3, 4].into_iter().enumerate() {
    assert!(
      c.admit(modified(s, "/a/f", epoch), clk.at(n as u64))
        .is_none()
    );
  }
  let out = drain(&mut c, clk.at(20));
  assert_eq!(out.len(), 1, "four Modifieds coalesce to one");
  assert!(out[0].kind().is_modified());
}

#[test]
fn created_then_removed_annihilates() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config());
  let s = sub(1);

  assert!(c.admit(created(s, "/a/tmp", 1), clk.at(0)).is_none());
  assert!(c.admit(removed(s, "/a/tmp", 2), clk.at(1)).is_none());

  // A file that lived and died inside the window emits NOTHING — and nothing is left
  // to ever emit.
  assert!(
    drain(&mut c, clk.at(50)).is_empty(),
    "the transient annihilates"
  );
  assert_eq!(c.next_deadline(), None, "no entry lingers");
}

#[test]
fn modified_then_removed_is_removed() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config());
  let s = sub(1);

  assert!(c.admit(modified(s, "/a/f", 1), clk.at(0)).is_none());
  assert!(c.admit(removed(s, "/a/f", 2), clk.at(1)).is_none());

  let out = drain(&mut c, clk.at(20));
  assert_eq!(out.len(), 1);
  assert!(
    out[0].kind().is_removed(),
    "modified-then-removed nets to Removed"
  );
}

#[test]
fn removed_then_created_is_modified() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config());
  let s = sub(1);

  assert!(c.admit(removed(s, "/a/f", 1), clk.at(0)).is_none());
  assert!(c.admit(created(s, "/a/f", 2), clk.at(1)).is_none());

  let out = drain(&mut c, clk.at(20));
  assert_eq!(out.len(), 1);
  assert!(
    out[0].kind().is_modified(),
    "removed-then-created churn nets to a synthetic Modified"
  );
  assert_eq!(out[0].path(), PathBuf::from("/a/f"));
  assert_eq!(
    out[0].change_id(),
    None,
    "the synthesized Modified carries no change id"
  );
}

// -------------------------------------------------------------------------------
// Invariants that override coalescing (design §6).
// -------------------------------------------------------------------------------

#[test]
fn moved_is_atomic_and_flushes() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config());
  let s = sub(1);

  // Buffer changes at both endpoints of the coming rename.
  assert!(c.admit(modified(s, "/a/src", 1), clk.at(0)).is_none());
  assert!(c.admit(created(s, "/a/dst", 2), clk.at(1)).is_none());

  // A rename /a/src -> /a/dst. It is atomic: it flushes both buffered endpoints and
  // emits WHOLE, undelayed — never split, never coalesced.
  assert!(
    c.admit(moved(s, "/a/dst", "/a/src", 3), clk.at(2))
      .is_none()
  );

  let out = drain(&mut c, clk.at(2));
  // The two flushed endpoints, then the Moved (FIFO: flushed-before-the-signal).
  assert_eq!(
    out.len(),
    3,
    "both buffered endpoints flush plus the Moved emits"
  );
  let moved_events: Vec<_> = out.iter().filter(|e| is_moved(e)).collect();
  assert_eq!(moved_events.len(), 1, "the Moved emits exactly once, whole");
  let m = moved_events[0];
  assert_eq!(m.path(), PathBuf::from("/a/dst"), "the rename destination");
  assert_eq!(
    move_from_path(m),
    PathBuf::from("/a/src"),
    "the rename source is intact — the Moved was not split"
  );
  assert_eq!(
    c.next_deadline(),
    None,
    "nothing lingers after the atomic flush"
  );
}

#[test]
fn moved_emits_undelayed_not_after_a_settle_window() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config()); // quiet 10ms
  let s = sub(1);

  // A rename with NOTHING else buffered for the subscription: it must be due at its own
  // instant (undelayed), not after the quiet window — unlike a plain lifecycle change,
  // which would settle for `quiet_window` first.
  assert!(
    c.admit(moved(s, "/a/dst", "/a/src", 1), clk.at(0))
      .is_none()
  );

  assert_eq!(
    c.next_deadline(),
    Some(clk.at(0)),
    "a Moved is due immediately (its ready instant), not at now + quiet_window"
  );
  let out = drain(&mut c, clk.at(0));
  assert_eq!(out.len(), 1, "the undelayed Moved is due at once");
  assert!(is_moved(&out[0]));
  assert_eq!(c.next_deadline(), None, "nothing lingers");
}

#[test]
fn debounced_moved_flushes_subscription_buffer_preserving_epoch_order() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config());
  let s = sub(1);

  // Buffer an older-epoch change at an UNRELATED path (neither the coming rename's
  // source nor its destination). The pre-fix Moved path flushed only its two endpoint
  // paths, so this entry would stay buffered and drain LATER than the immediate Moved —
  // its epoch 1 delivered after the Moved's epoch 2, i.e. epochs going backwards.
  assert!(c.admit(modified(s, "/a/other", 1), clk.at(0)).is_none());

  // A rename at other paths (epoch 2) — immediate. It must flush the whole subscription
  // buffer first, so /a/other's epoch-1 Modified emits BEFORE the Moved.
  assert!(
    c.admit(moved(s, "/a/dst", "/a/src", 2), clk.at(1))
      .is_none()
  );

  let out = drain(&mut c, clk.at(1));
  assert_eq!(
    out.len(),
    2,
    "the unrelated buffered entry is flushed alongside the immediate Moved"
  );
  // FIFO: the flushed older-epoch entry precedes the Moved that flushed it.
  assert!(
    !is_moved(&out[0]),
    "the flushed older-epoch buffered entry emits first"
  );
  assert_eq!(out[0].path(), PathBuf::from("/a/other"));
  assert_eq!(out[0].epoch(), Epoch::new(1), "the older buffered epoch");
  assert!(
    is_moved(&out[1]),
    "the immediate Moved emits after the flush"
  );
  assert_eq!(out[1].epoch(), Epoch::new(2), "the newer Moved epoch");
  // The delivered epochs are monotone-nondecreasing (1 then 2), not backwards.
  assert!(
    out.windows(2).all(|w| w[0].epoch() <= w[1].epoch()),
    "a debounced Moved never delivers an older buffered entry's epoch after itself"
  );
  assert_eq!(
    c.next_deadline(),
    None,
    "the whole subscription was flushed"
  );
}

#[test]
fn rescan_flushes_and_bypasses() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config());
  let s = sub(1);

  // Buffer a couple of bursts for this subscription.
  assert!(c.admit(modified(s, "/a/one", 1), clk.at(0)).is_none());
  assert!(c.admit(created(s, "/a/two", 2), clk.at(1)).is_none());

  // A Rescan stamped with an umbrella epoch that DOMINATES the buffered stamps.
  assert!(c.admit(rescan(s, "/a", 9), clk.at(2)).is_none());

  let out = drain(&mut c, clk.at(2));
  // Every buffered entry is flushed AND the Rescan emits — all undelayed.
  assert_eq!(
    out.len(),
    3,
    "both buffered entries flush plus the Rescan emits"
  );
  let rescans: Vec<_> = out.iter().filter(|e| e.is_rescan()).collect();
  assert_eq!(rescans.len(), 1, "exactly one Rescan");
  assert_eq!(
    rescans[0].epoch(),
    Epoch::new(9),
    "the Rescan's upstream umbrella epoch stamp is preserved unchanged"
  );
  // The Rescan is emitted last (FIFO: after the entries it flushed), and its stamp
  // dominates every flushed entry.
  let last = out.last().expect("non-empty");
  assert!(
    last.is_rescan(),
    "the Rescan bypasses to the end of the flush"
  );
  for e in &out {
    assert!(
      e.epoch() <= Epoch::new(9),
      "no flushed entry carries an epoch dominating the Rescan"
    );
  }
  assert_eq!(
    c.next_deadline(),
    None,
    "the Rescan drained everything for the sub"
  );
}

#[test]
fn rescan_only_flushes_its_own_subscription() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config());
  let (s1, s2) = (sub(1), sub(2));

  assert!(c.admit(modified(s1, "/a/f", 1), clk.at(0)).is_none());
  assert!(c.admit(modified(s2, "/b/f", 1), clk.at(0)).is_none());

  // A Rescan for s1 must not disturb s2's buffered burst.
  assert!(c.admit(rescan(s1, "/a", 5), clk.at(1)).is_none());

  let out = drain(&mut c, clk.at(1));
  assert_eq!(out.len(), 2, "s1's flushed burst plus its Rescan");
  assert!(
    out.iter().all(|e| e.subscription() == s1),
    "only s1 is touched"
  );
  // s2's burst still settles on its own timer.
  let out2 = drain(&mut c, clk.at(20));
  assert_eq!(
    out2.len(),
    1,
    "s2's burst is untouched and settles normally"
  );
  assert_eq!(out2[0].subscription(), s2);
}

/// Codex R11 F2 regression (forward-compat, design §6): the coalescer coalesces ONLY the known
/// lifecycle kinds (`Created` / `Modified` / `Removed`). The umbrella's own `EventKind` is
/// `#[non_exhaustive]`; a non-lifecycle kind must NOT be folded into the collapse table (whose
/// default arm would relabel or drop it), but flushed-and-emitted immediately — the same path as
/// `Moved`/`Rescan` — so it is delivered in-order and never collapsed.
///
/// LIMITATION: a truly-unknown future `EventKind` cannot be constructed, even from within the
/// defining crate — the enum has no variant beyond the five known ones, and every one of those
/// dispatches to a dedicated `admit` branch (the `matches!` trio, `move_from`, `is_rescan`), so
/// no buildable input reaches the unknown-kind `else` arm today. This test therefore exercises
/// the observable classification the arm generalizes, using a `Moved` (a constructible
/// non-lifecycle kind) as the representative: a buffered lifecycle entry is flushed AHEAD of the
/// immediately-emitted non-lifecycle event, and neither is collapsed — the exact flush-and-emit
/// machinery the `else` arm routes a future variant through. The unknown-kind arm itself is
/// verified by inspection (it mirrors this `Moved`/`Rescan` path).
#[test]
fn a_non_lifecycle_kind_flushes_and_emits_never_coalesced() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config());
  let s = sub(1);

  // A known lifecycle Modified enters `coalesce` — buffered, nothing ready before its settle.
  assert!(c.admit(modified(s, "/a/f", 1), clk.at(0)).is_none());
  assert!(
    drain(&mut c, clk.at(0)).is_empty(),
    "a lifecycle kind is buffered (enters coalesce), not immediately emitted"
  );

  // A non-lifecycle kind for the same subscription is NOT coalesced onto the buffered entry: it
  // flushes the subscription's buffer and emits immediately, both undelayed and in-order.
  assert!(
    c.admit(moved(s, "/a/dst", "/a/src", 2), clk.at(1))
      .is_none()
  );
  let out = drain(&mut c, clk.at(1));
  assert_eq!(
    out.len(),
    2,
    "the buffered lifecycle entry and the non-lifecycle kind BOTH emit — neither coalesced away"
  );
  assert!(
    out[0].kind().is_modified() && !is_moved(&out[0]),
    "the buffered lifecycle Modified is flushed FIRST (older-epoch, ahead of the immediate emit)"
  );
  assert!(
    is_moved(&out[1]),
    "the non-lifecycle kind emits immediately AFTER the flushed entry"
  );
  assert!(
    out[0].epoch() < out[1].epoch(),
    "epochs stay monotone: the flushed buffered entry precedes the immediate emit (design §8)"
  );
  assert!(
    c.next_deadline().is_none(),
    "nothing lingers buffered — the non-lifecycle kind was not held for a settle window"
  );
}

#[test]
fn max_hold_forces_emission() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config()); // quiet 10ms, max_hold 100ms
  let s = sub(1);

  // Touch the path every 5 ms so the 10 ms settle window NEVER elapses on its own.
  let mut t = 0;
  while t <= 130 {
    assert!(c.admit(modified(s, "/a/f", t / 5 + 1), clk.at(t)).is_none());
    // Before the hold cap (first_seen=0 + 100ms) nothing emits.
    if t < 100 {
      assert!(
        drain(&mut c, clk.at(t)).is_empty(),
        "still held before the max_hold cap at t={t}"
      );
    }
    t += 5;
  }

  // The entry was forced out at first_seen + max_hold = 100 ms regardless of the
  // still-arriving touches — a continuously-touched path cannot settle forever.
  // Drain at the cap: exactly one coalesced Modified.
  let out = drain(&mut c, clk.at(100));
  assert_eq!(
    out.len(),
    1,
    "the bounded hold forces one emission at the cap"
  );
  assert!(out[0].kind().is_modified());
}

// -------------------------------------------------------------------------------
// Epoch preservation (design §8).
// -------------------------------------------------------------------------------

#[test]
fn coalesced_pair_emits_with_the_newest_stamp() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config());
  let s = sub(1);

  // Monotone stamps within the burst; the emitted event must carry the NEWEST (4).
  assert!(c.admit(created(s, "/a/f", 2), clk.at(0)).is_none());
  assert!(c.admit(modified(s, "/a/f", 3), clk.at(1)).is_none());
  assert!(c.admit(modified(s, "/a/f", 4), clk.at(2)).is_none());

  let out = drain(&mut c, clk.at(20));
  assert_eq!(out.len(), 1);
  assert_eq!(
    out[0].epoch(),
    Epoch::new(4),
    "the coalesced event keeps the newest observation's umbrella stamp"
  );
  assert!(
    out[0].kind().is_created(),
    "…while still reporting the collapsed kind"
  );
}

#[test]
fn become_modified_keeps_the_newest_stamp() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config());
  let s = sub(1);

  // Removed(5) then Created(7) → synthetic Modified carrying the newest stamp (7).
  assert!(c.admit(removed(s, "/a/f", 5), clk.at(0)).is_none());
  assert!(c.admit(created(s, "/a/f", 7), clk.at(1)).is_none());

  let out = drain(&mut c, clk.at(20));
  assert_eq!(out.len(), 1);
  assert!(out[0].kind().is_modified());
  assert_eq!(
    out[0].epoch(),
    Epoch::new(7),
    "the synthetic Modified carries the newest stamp"
  );
}

#[test]
fn post_rescan_emission_never_carries_a_dominated_epoch() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config());
  let s = sub(1);

  // A Rescan at umbrella epoch 10, then genuine post-Rescan changes rebased ABOVE it
  // upstream (epoch 11, 12). A conforming consumer must never see a post-Rescan event
  // dominated by the Rescan.
  assert!(c.admit(rescan(s, "/a", 10), clk.at(0)).is_none());
  assert!(c.admit(modified(s, "/a/f", 11), clk.at(1)).is_none());
  assert!(c.admit(modified(s, "/a/f", 12), clk.at(2)).is_none());

  // The Rescan is already ready (undelayed); the burst settles after its window.
  let rescan_out = drain(&mut c, clk.at(2));
  assert_eq!(rescan_out.len(), 1, "the Rescan emits undelayed");
  assert_eq!(rescan_out[0].epoch(), Epoch::new(10));

  let burst_out = drain(&mut c, clk.at(20));
  assert_eq!(burst_out.len(), 1, "the post-Rescan burst settles");
  assert!(
    burst_out[0].epoch() >= Epoch::new(10),
    "the post-Rescan emission is NOT dominated by the Rescan"
  );
  assert_eq!(
    burst_out[0].epoch(),
    Epoch::new(12),
    "…and carries the newest stamp"
  );
}

// -------------------------------------------------------------------------------
// next_deadline / drain ordering.
// -------------------------------------------------------------------------------

#[test]
fn next_deadline_is_the_earliest_pending() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config());
  let s = sub(1);

  assert_eq!(c.next_deadline(), None, "empty: no deadline");

  assert!(c.admit(modified(s, "/a/f", 1), clk.at(0)).is_none());
  assert_eq!(
    c.next_deadline(),
    Some(clk.at(10)),
    "one buffered entry: due at now + quiet_window"
  );

  // A Rescan makes something immediately ready — the deadline drops to that ready
  // instant (in the past relative to the burst's), so the driver drains at once.
  assert!(c.admit(rescan(s, "/b", 3), clk.at(1)).is_none());
  assert_eq!(
    c.next_deadline(),
    Some(clk.at(1)),
    "a ready item pulls the deadline to its (earlier) ready instant"
  );
}

#[test]
fn flush_all_drains_everything_for_stream_close() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config());
  let s = sub(1);

  assert!(c.admit(modified(s, "/a/f", 1), clk.at(0)).is_none());
  assert!(c.admit(created(s, "/b/g", 2), clk.at(0)).is_none());

  // On stream close no further change can settle the bursts — flush the tail.
  let mut out = Vec::new();
  c.flush_all(&mut out);
  assert_eq!(
    out.len(),
    2,
    "every still-settling entry is force-emitted on close"
  );
  assert_eq!(c.next_deadline(), None, "the coalescer is left empty");
}

/// `drop_subscription` (the driver's parked-overflow-`Rescan` path, design backpressure
/// doc) discards every buffered AND ready entry for one subscription — now dominated by the
/// parked `Rescan` — while leaving every other subscription untouched. Unlike the inline
/// `Rescan`/`Moved` flush, it drops rather than enqueues (the parked `Rescan` cannot be
/// delivered inline, so re-emitting the suspect deltas would deliver a stale epoch after
/// it).
#[test]
fn drop_subscription_discards_only_that_subscriptions_entries() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config());
  let (s1, s2) = (sub(1), sub(2));

  // A buffered entry for s1, then a Rescan for s1 flushes it into the ready queue and
  // enqueues itself — so s1 now holds entries in the READY queue…
  assert!(c.admit(modified(s1, "/a/f", 1), clk.at(0)).is_none());
  assert!(c.admit(rescan(s1, "/a", 2), clk.at(0)).is_none());
  // …and a fresh buffered entry after the flush — so s1 also holds a BUFFER entry.
  assert!(c.admit(modified(s1, "/a/h", 3), clk.at(0)).is_none());
  // An unrelated subscription's buffered entry, which the drop must not touch.
  assert!(c.admit(modified(s2, "/b/f", 4), clk.at(0)).is_none());
  assert!(
    c.next_deadline().is_some(),
    "entries are pending before the drop"
  );

  // Drop s1: its buffered (/a/h) AND ready (/a/f, the Rescan) entries all vanish.
  c.drop_subscription(s1);

  let out = drain(&mut c, clk.at(1000));
  assert_eq!(out.len(), 1, "only s2's entry survives the drop of s1");
  assert_eq!(
    out[0].subscription(),
    s2,
    "the survivor belongs to the un-dropped subscription"
  );
  assert_eq!(out[0].path(), Path::new("/b/f"));
  assert_eq!(
    c.next_deadline(),
    None,
    "no s1 entry lingers in the buffer or ready queue after the drop"
  );
}

// -------------------------------------------------------------------------------
// Per-subscription admission-order drains (design §8, Codex R18).
//
// Every multi-entry drain must emit a subscription's entries in admission (= epoch) order,
// NOT BTreeMap path-key order. Each test uses the same fixture: two paths whose lexical
// order OPPOSES their epoch order — `/z` admitted earlier at the LOWER epoch 1, `/a`
// admitted later at the HIGHER epoch 2 (`/a` < `/z` lexically, but epoch 2 > 1). The
// pre-fix path-key drain emitted `/a` (epoch 2) before `/z` (epoch 1) — a subscription's
// epochs going backwards, which a monotone-epoch consumer silently drops. The fix orders
// by the admission sequence, so `/z` (epoch 1) precedes `/a` (epoch 2).
// -------------------------------------------------------------------------------

#[test]
fn drain_ready_emits_buffered_in_epoch_order_not_path_order() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config());
  let s = sub(1);

  // `/z` admitted FIRST at the LOWER epoch; `/a` admitted SECOND at the HIGHER epoch.
  assert!(c.admit(modified(s, "/z", 1), clk.at(0)).is_none());
  assert!(c.admit(modified(s, "/a", 2), clk.at(1)).is_none());

  // Both settle by t=20; the settle-timer drain releases them together.
  let out = drain(&mut c, clk.at(20));
  assert_eq!(
    out.len(),
    2,
    "both distinct paths emit (no cross-path collapse)"
  );
  assert_eq!(
    out[0].path(),
    PathBuf::from("/z"),
    "the earlier-admitted lower-epoch path emits first — NOT the lexically-first /a"
  );
  assert_eq!(out[0].epoch(), Epoch::new(1));
  assert_eq!(
    out[1].path(),
    PathBuf::from("/a"),
    "the later-admitted higher-epoch path emits second"
  );
  assert_eq!(out[1].epoch(), Epoch::new(2));
  assert!(
    out.windows(2).all(|w| w[0].epoch() <= w[1].epoch()),
    "a subscription's buffered epochs never emit backwards"
  );
}

#[test]
fn flush_all_emits_buffered_in_epoch_order_not_path_order() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config());
  let s = sub(1);

  assert!(c.admit(modified(s, "/z", 1), clk.at(0)).is_none());
  assert!(c.admit(modified(s, "/a", 2), clk.at(1)).is_none());

  // Force-emit the still-settling tail (as a stream close would), regardless of deadline.
  let mut out = Vec::new();
  c.flush_all(&mut out);
  assert_eq!(out.len(), 2);
  assert_eq!(
    out[0].path(),
    PathBuf::from("/z"),
    "lower-epoch tail entry first"
  );
  assert_eq!(out[0].epoch(), Epoch::new(1));
  assert_eq!(
    out[1].path(),
    PathBuf::from("/a"),
    "higher-epoch tail entry second"
  );
  assert_eq!(out[1].epoch(), Epoch::new(2));
  assert!(
    out.windows(2).all(|w| w[0].epoch() <= w[1].epoch()),
    "the teardown flush never delivers a subscription's epochs out of order"
  );
}

#[test]
fn rescan_flush_emits_buffered_in_epoch_order_not_path_order() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config());
  let s = sub(1);

  assert!(c.admit(modified(s, "/z", 1), clk.at(0)).is_none());
  assert!(c.admit(modified(s, "/a", 2), clk.at(1)).is_none());

  // A Rescan (epoch 3) flushes the whole subscription buffer into the ready queue ahead of
  // itself — in admission (seq) order, so the FIFO replay is lowest-epoch-first.
  assert!(c.admit(rescan(s, "/root", 3), clk.at(2)).is_none());

  let out = drain(&mut c, clk.at(2));
  assert_eq!(out.len(), 3, "both flushed entries plus the Rescan");
  assert_eq!(
    out[0].path(),
    PathBuf::from("/z"),
    "lower-epoch buffered entry flushed first"
  );
  assert_eq!(out[0].epoch(), Epoch::new(1));
  assert_eq!(
    out[1].path(),
    PathBuf::from("/a"),
    "higher-epoch buffered entry flushed second"
  );
  assert_eq!(out[1].epoch(), Epoch::new(2));
  assert!(
    out[2].is_rescan(),
    "the Rescan bypasses to the end of the flush"
  );
  assert_eq!(out[2].epoch(), Epoch::new(3));
  assert!(
    out.windows(2).all(|w| w[0].epoch() <= w[1].epoch()),
    "flushed epochs stay monotone: 1, 2, then the Rescan's 3"
  );
}

#[test]
fn moved_flush_emits_buffered_in_epoch_order_not_path_order() {
  let clk = Clock::new();
  let mut c = Coalescer::new(config());
  let s = sub(1);

  assert!(c.admit(modified(s, "/z", 1), clk.at(0)).is_none());
  assert!(c.admit(modified(s, "/a", 2), clk.at(1)).is_none());

  // A Moved (epoch 3) at unrelated endpoints flushes the WHOLE subscription buffer ahead of
  // itself — the same seq-ordered flush machinery a Rescan uses.
  assert!(c.admit(moved(s, "/dst", "/src", 3), clk.at(2)).is_none());

  let out = drain(&mut c, clk.at(2));
  assert_eq!(out.len(), 3, "both flushed entries plus the Moved");
  assert_eq!(
    out[0].path(),
    PathBuf::from("/z"),
    "lower-epoch buffered entry flushed first"
  );
  assert_eq!(out[0].epoch(), Epoch::new(1));
  assert_eq!(
    out[1].path(),
    PathBuf::from("/a"),
    "higher-epoch buffered entry flushed second"
  );
  assert_eq!(out[1].epoch(), Epoch::new(2));
  assert!(is_moved(&out[2]), "the Moved emits whole after the flush");
  assert_eq!(out[2].epoch(), Epoch::new(3));
  assert!(
    out.windows(2).all(|w| w[0].epoch() <= w[1].epoch()),
    "flushed epochs stay monotone: 1, 2, then the Moved's 3"
  );
}

// -------------------------------------------------------------------------------
// Property tests (design §10): no silent loss, determinism, no dominated post-Rescan.
// -------------------------------------------------------------------------------

mod proptests {
  use super::*;
  use proptest::prelude::*;

  /// A scripted admission: a kind selector (0..5), a small path index, an epoch delta,
  /// and a time delta (ms). Epochs are made monotone-nondecreasing before feeding the
  /// coalescer (the umbrella stamps are monotone per subscription), so a coalescing
  /// pair never straddles a dominance boundary — the invariant the coalescer relies on.
  #[derive(Debug, Clone)]
  struct Step {
    kind: u8,
    path: u8,
    epoch_delta: u16,
    time_delta: u16,
  }

  fn step_strategy() -> impl Strategy<Value = Step> {
    (0u8..5, 0u8..4, 0u16..3, 0u16..30).prop_map(|(kind, path, epoch_delta, time_delta)| Step {
      kind,
      path,
      epoch_delta,
      time_delta,
    })
  }

  /// Build one event for `step` for subscription `s`, at monotone epoch `epoch`.
  /// One fixed subscription keeps the property focused on the collapse/flush logic.
  fn event_for(s: Subscription, step: &Step, epoch: u64) -> Ev {
    let path = format!("/root/p{}", step.path);
    match step.kind {
      0 => created(s, &path, epoch),
      1 => modified(s, &path, epoch),
      2 => removed(s, &path, epoch),
      3 => moved(s, &path, "/root/src", epoch),
      _ => rescan(s, &path, epoch),
    }
  }

  /// Case budget: a full sweep natively, a handful under miri (where each case runs
  /// the interpreter, so the native count would blow the time budget).
  const CASES: u32 = if cfg!(miri) { 4 } else { 200 };

  proptest! {
    // No failure-persistence file: keeps miri from calling getcwd, and keeps the run
    // hermetic.
    #![proptest_config(ProptestConfig { cases: CASES, failure_persistence: None, ..ProptestConfig::default() })]

    /// Every admitted event is accounted for: it is emitted, folded into an emitted
    /// entry, or intentionally annihilated per the create-then-remove row — never
    /// silently dropped. We assert the strong, checkable half: at least one event is
    /// emitted whenever a non-annihilating event was admitted, and the count of
    /// distinct emitted `(path, kind-class)` is bounded by what was admitted.
    #[test]
    fn no_admitted_event_is_silently_lost(steps in prop::collection::vec(step_strategy(), 1..40)) {
      let clk = Clock::new();
      let mut c = Coalescer::new(config());
      let s = sub(1);

      let mut epoch = 0u64;
      let mut admitted = 0usize;
      let mut emitted = Vec::new();
      let mut t = 0u64;
      for step in &steps {
        epoch += u64::from(step.epoch_delta); // monotone-nondecreasing
        t += u64::from(step.time_delta);
        assert!(c.admit(event_for(s, step, epoch), clk.at(t)).is_none());
        admitted += 1;
        // Drain whatever became ready as time advanced.
        c.drain_ready(clk.at(t), &mut emitted);
      }
      // Flush the settling tail (as a stream close would).
      c.flush_all(&mut emitted);

      // Every emitted event is a real, well-formed delivery for our subscription.
      for e in &emitted {
        prop_assert_eq!(e.subscription(), s);
      }
      // A Moved or Rescan is NEVER coalesced away: each admitted one must appear.
      let admitted_atomic = steps.iter().filter(|st| st.kind >= 3).count();
      let emitted_atomic = emitted.iter().filter(|e| is_moved(e) || e.is_rescan()).count();
      prop_assert_eq!(
        emitted_atomic,
        admitted_atomic,
        "every Moved/Rescan is emitted whole, none coalesced or dropped"
      );
      // The coalescer is fully drained.
      prop_assert_eq!(c.next_deadline(), None);
      let _ = admitted;
    }

    /// Determinism: the same script fed twice yields byte-identical output (no
    /// HashMap-iteration nondeterminism in the drain order).
    #[test]
    fn determinism(steps in prop::collection::vec(step_strategy(), 1..40)) {
      fn run(steps: &[Step]) -> Vec<(PathBuf, &'static str, Epoch)> {
        let clk = Clock::new();
        let mut c = Coalescer::new(config());
        let s = sub(1);
        let mut epoch = 0u64;
        let mut t = 0u64;
        let mut out = Vec::new();
        for step in steps {
          epoch += u64::from(step.epoch_delta);
          t += u64::from(step.time_delta);
          assert!(c.admit(event_for(s, step, epoch), clk.at(t)).is_none());
          c.drain_ready(clk.at(t), &mut out);
        }
        c.flush_all(&mut out);
        out
          .into_iter()
          .map(|e| (e.path().to_path_buf(), e.kind().as_str(), e.epoch()))
          .collect()
      }
      prop_assert_eq!(run(&steps), run(&steps));
    }

    /// No emission after an immediate (undelayed) one ever carries an epoch it
    /// dominated: once an immediate emission at epoch `r` has drained — a Rescan OR a
    /// Moved, since BOTH now flush the whole subscription buffer before emitting — every
    /// later emission has epoch >= r. This is the per-subscription monotone-epoch
    /// contract across ALL immediate emissions, not just Rescan (the pre-fix Moved
    /// flushed only its two endpoint paths, so an older buffered entry for another path
    /// could drain after the Moved and go backwards).
    #[test]
    fn no_post_immediate_dominated_epoch(steps in prop::collection::vec(step_strategy(), 1..40)) {
      let clk = Clock::new();
      let mut c = Coalescer::new(config());
      let s = sub(1);
      let mut epoch = 0u64;
      let mut t = 0u64;
      let mut emitted = Vec::new();
      for step in &steps {
        epoch += u64::from(step.epoch_delta);
        t += u64::from(step.time_delta);
        assert!(c.admit(event_for(s, step, epoch), clk.at(t)).is_none());
        c.drain_ready(clk.at(t), &mut emitted);
      }
      c.flush_all(&mut emitted);

      // Walk the emission order; track the highest epoch of any immediate emission
      // (Rescan or Moved) seen so far. Because each flushes its subscription's whole
      // buffer, everything it dominated is emitted BEFORE it — so no LATER emission may
      // carry an epoch < that immediate emission's.
      let mut immediate_hw: Option<Epoch> = None;
      for e in &emitted {
        if let Some(r) = immediate_hw {
          prop_assert!(
            e.epoch() >= r,
            "an emission after an immediate one is dominated by it: {:?} < {:?}",
            e.epoch(),
            r
          );
        }
        if e.is_rescan() || is_moved(e) {
          immediate_hw = Some(immediate_hw.map_or(e.epoch(), |r| r.max(e.epoch())));
        }
      }
    }
  }
}

// -------------------------------------------------------------------------------
// Runtime-touching: the settle timer under paused tokio time (design §6). This is the
// only test that touches a runtime; it drives a `Coalescer` through the exact clock
// bridge the driver uses (`R::now()` → std `Instant`, `sleep_until`/`timeout_at`).
// -------------------------------------------------------------------------------

#[cfg(feature = "tokio")]
mod tokio_timer {
  use super::*;
  use agnostic_lite::RuntimeLite;

  type Rt = agnostic_lite::tokio::TokioRuntime;

  /// A burst of Modifieds to one path collapses to a single delivered event after the
  /// quiet window; a Rescan admitted mid-burst jumps the queue — it drains before the
  /// buffered burst's deadline. Paused time makes the timing exact and instant.
  #[tokio::test(start_paused = true)]
  async fn burst_coalesces_and_rescan_jumps_the_queue() {
    let cfg = config(); // quiet 10ms, max_hold 100ms
    let mut c = Coalescer::new(cfg);
    let s = sub(1);

    // Admit a burst of three Modifieds to one path at the current (paused) instant.
    let start = Rt::now();
    for epoch in 1..=3 {
      assert!(c.admit(modified(s, "/a/f", epoch), start.into()).is_none());
    }

    // The burst is not yet due: draining now yields nothing.
    let mut out = Vec::new();
    c.drain_ready(Rt::now().into(), &mut out);
    assert!(out.is_empty(), "the burst is still settling");

    // A Rescan mid-burst is immediately ready — it must NOT wait for the burst's
    // deadline. Sleep until the coalescer's next deadline (now the ready Rescan) and
    // drain: the flushed burst + the Rescan come out well before quiet_window elapses.
    assert!(c.admit(rescan(s, "/a", 9), Rt::now().into()).is_none());
    let deadline = c.next_deadline().expect("the ready Rescan sets a deadline");
    Rt::sleep_until(deadline.into()).await;
    c.drain_ready(Rt::now().into(), &mut out);

    assert!(
      Rt::now().duration_since(start) < cfg.quiet_window(),
      "the Rescan jumped the queue: drained before the burst's settle window elapsed"
    );
    // The flushed burst collapsed to one Modified, plus the Rescan — the Rescan last.
    assert_eq!(out.len(), 2, "the coalesced burst plus the Rescan");
    assert!(out[0].kind().is_modified(), "the flushed, coalesced burst");
    assert_eq!(out[0].epoch(), Epoch::new(3), "…carrying the newest stamp");
    assert!(
      out[1].is_rescan(),
      "the Rescan, jumped ahead of the burst's own deadline"
    );
    assert_eq!(
      out[1].epoch(),
      Epoch::new(9),
      "its umbrella stamp preserved"
    );
    assert_eq!(c.next_deadline(), None, "everything drained");
  }
}

/// Codex R55: the buffered-entry cap is the structural memory bound in FRONT of the
/// bounded event channel. A high-cardinality burst (10,000 distinct keys) against a
/// cap of 64 never grows the buffer past the cap; every admission past it signals the
/// overflowed subscription (owed a dominating parked Rescan by the driver), and
/// collapses onto existing entries stay exempt at the cap.
#[test]
fn buffered_entry_cap_bounds_high_cardinality_bursts() {
  let now = Instant::now();
  let mut coalescer = Coalescer::new(crate::options::DebounceConfig::new().with_max_buffered(64));
  let s = sub(1);

  let mut overflows = 0usize;
  for i in 0..10_000u32 {
    let outcome = coalescer.admit(created(s, &format!("/k{i}"), u64::from(i) + 1), now);
    assert!(
      coalescer.buffer.len() <= 64,
      "the buffer NEVER exceeds the cap (got {} at admission {i})",
      coalescer.buffer.len()
    );
    if let Some(overflowed) = outcome {
      assert_eq!(overflowed, s, "the shed names the admitting subscription");
      overflows += 1;
    }
  }
  assert_eq!(
    overflows,
    10_000 - 64,
    "every admission past the cap signalled the shed — none was silently dropped"
  );

  // Collapsing onto an ALREADY-buffered entry never counts against the cap: a second
  // observation of a buffered key is admitted even while the buffer sits at the cap.
  assert!(
    coalescer.admit(modified(s, "/k0", 20_000), now).is_none(),
    "a collapse onto an existing entry is exempt at the cap"
  );
  assert_eq!(coalescer.buffer.len(), 64, "still exactly at the cap");
}
