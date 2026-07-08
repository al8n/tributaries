use core::num::NonZeroU64;
use std::{ffi::OsString, path::Path};

use tributary_fs::Epoch;
use tributary_proto::ScopeId;

use super::EpochLedger;
use crate::{route::RoutableEvent, subscription::Subscription};

/// A path's `OsString` components — the located-key form the fs source keys on.
fn key(path: &str) -> Vec<OsString> {
  Path::new(path)
    .components()
    .map(|c| c.as_os_str().to_os_string())
    .collect()
}

/// A minimal stand-in for a raw event — the same shape `route::tests` uses, so the
/// ledger's fan-out + stamp is exercised without the private `tributary_fs::Event`
/// constructor. Routing reads its endpoint keys and whether it is a `Rescan`; its
/// per-subscriber delivery is the [`Subscription`] paired with which projection it got,
/// which the ledger then stamps — so a move test can confirm every projection of one
/// raw move carries that subscriber's stamp.
struct FakeEvent {
  key: Vec<OsString>,
  from: Option<Vec<OsString>>,
  rescan: bool,
}

/// Which projection a subscriber received (mirrors `route::tests`), so a move test can
/// assert the stamp lands on the right projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Projection {
  Whole,
  MoveOut,
  MoveIn,
}

impl FakeEvent {
  fn change(path: &str) -> Self {
    Self {
      key: key(path),
      from: None,
      rescan: false,
    }
  }

  fn rescan(path: &str) -> Self {
    Self {
      key: key(path),
      from: None,
      rescan: true,
    }
  }

  fn moved(from: &str, to: &str) -> Self {
    Self {
      key: key(to),
      from: Some(key(from)),
      rescan: false,
    }
  }
}

impl RoutableEvent<OsString> for FakeEvent {
  type Delivered = (Subscription, Projection);

  fn key(&self) -> &[OsString] {
    self.key.as_slice()
  }

  fn move_from(&self) -> Option<&[OsString]> {
    self.from.as_deref()
  }

  fn is_rescan(&self) -> bool {
    self.rescan
  }

  fn deliver(&self, sub: Subscription) -> (Subscription, Projection) {
    (sub, Projection::Whole)
  }

  fn deliver_move_out(&self, sub: Subscription) -> (Subscription, Projection) {
    (sub, Projection::MoveOut)
  }

  fn deliver_move_in(&self, sub: Subscription) -> (Subscription, Projection) {
    (sub, Projection::MoveIn)
  }
}

fn sub(id: u64) -> Subscription {
  Subscription::new(ScopeId::new(NonZeroU64::new(id).expect("nonzero id")))
}

/// A root serving the given subscribers, each registered at its own key (the two
/// inputs `stamp_and_fan_out`'s coverage step needs). The root path itself is
/// immaterial — the coverage step keys on the subscribers and their own keys.
struct Fixture {
  subscribers: Vec<Subscription>,
  keys: Vec<(Subscription, Vec<OsString>)>,
}

impl Fixture {
  fn new(_root_path: &str, subscribers: &[(u64, &str)]) -> Self {
    let mut subs = Vec::new();
    let mut keys = Vec::new();
    for &(id, path) in subscribers {
      let s = sub(id);
      subs.push(s);
      keys.push((s, key(path)));
    }
    Self {
      subscribers: subs,
      keys,
    }
  }

  fn canonical_of(&self, s: Subscription) -> Option<&[OsString]> {
    self
      .keys
      .iter()
      .find(|(candidate, _)| *candidate == s)
      .map(|(_, k)| k.as_slice())
  }

  /// Fan `event` (raw fs epoch `raw`) out through `ledger`, returning each covered
  /// subscriber paired with the umbrella stamp the ledger assigned it.
  fn deliver(
    &self,
    ledger: &mut EpochLedger,
    event: &FakeEvent,
    raw: Epoch,
  ) -> Vec<(Subscription, Epoch)> {
    self
      .deliver_projected(ledger, event, raw)
      .into_iter()
      .map(|(s, _projection, stamp)| (s, stamp))
      .collect()
  }

  /// Like [`deliver`](Self::deliver) but also returns each delivery's projection, so a
  /// move test can assert the stamp lands on the right per-endpoint projection.
  fn deliver_projected(
    &self,
    ledger: &mut EpochLedger,
    event: &FakeEvent,
    raw: Epoch,
  ) -> Vec<(Subscription, Projection, Epoch)> {
    ledger.stamp_and_fan_out(
      event,
      raw,
      &self.subscribers,
      |s| self.canonical_of(s),
      // These tests exercise coverage + epoch rebasing, not the filter, so admit
      // every covered delivery (the filter gate is covered in `route::tests`).
      |_sub, _delivered| true,
      |(s, _projection)| *s,
      |(s, projection), stamp| (s, projection, stamp),
    )
  }
}

/// The single-subscription stamp path is monotone within one root: fs epochs 0,1,2
/// stamp to 0,1,2 from base START.
#[test]
fn stamps_are_monotone_within_a_root() {
  let mut ledger = EpochLedger::new();
  let fx = Fixture::new("/a", &[(1, "/a")]);
  let s = sub(1);

  let mut stamps = Vec::new();
  for raw in 0..3 {
    let delivered = fx.deliver(&mut ledger, &FakeEvent::change("/a/file"), Epoch::new(raw));
    assert_eq!(
      delivered,
      vec![(s, Epoch::new(raw))],
      "stamp = base(0) + raw"
    );
    stamps.push(delivered[0].1);
  }
  assert!(
    stamps.windows(2).all(|w| w[0] <= w[1]),
    "stamps are monotone-nondecreasing within one root"
  );
}

/// The RISK-1 regression: on a widen re-point, the new root's genuine post-widen
/// events (which restart at fs epoch 0) must NOT be dominated by the synthetic widen
/// `Rescan`. The pre-fix bug fed raw fs epochs into a single linear high-water and
/// minted the Rescan above it, so 0,1 came out < the Rescan and a conforming consumer
/// would drop them — silent loss. Rebasing stamps them at `hw.next()+0,+1`.
#[test]
fn post_widen_new_root_events_are_not_dominated_by_the_widen_rescan() {
  let mut ledger = EpochLedger::new();
  let s = sub(1);

  // Root A serves subscription 1. Three events at fs epochs 0,1,2.
  let root_a = Fixture::new("/a/b", &[(1, "/a/b")]);
  let mut pre_widen = Vec::new();
  for raw in 0..3 {
    let delivered = root_a.deliver(&mut ledger, &FakeEvent::change("/a/b/f"), Epoch::new(raw));
    assert_eq!(delivered.len(), 1, "the lone covering sub is served");
    pre_widen.push(delivered[0].1);
  }
  assert_eq!(
    pre_widen,
    vec![Epoch::new(0), Epoch::new(1), Epoch::new(2)],
    "pre-widen stamps track the raw fs epochs from base START"
  );

  // WIDEN re-point of subscription 1 onto the new wider root /a. Its high-water is 2,
  // so the synthetic Rescan is minted at 3 (= hw.next()).
  let rescan_stamp = ledger.repoint(s);
  assert_eq!(
    rescan_stamp,
    Epoch::new(3),
    "the widen Rescan is minted one past the subscription's high-water"
  );

  // The newly-armed wider root /a now delivers genuine events, whose fs epochs
  // RESTART at 0,1 (per-ScopeId, fresh kernel arm). Rebasing stamps them at 3+0, 3+1.
  let root_b = Fixture::new("/a", &[(1, "/a")]);
  let mut post_widen = Vec::new();
  for raw in 0..2 {
    let delivered = root_b.deliver(&mut ledger, &FakeEvent::change("/a/b/f"), Epoch::new(raw));
    assert_eq!(delivered.len(), 1, "the sub still covers events under /a/b");
    post_widen.push(delivered[0].1);
  }
  assert_eq!(
    post_widen,
    vec![Epoch::new(3), Epoch::new(4)],
    "post-widen stamps rebase onto hw.next()+raw, not the raw fs epoch"
  );

  // (a) Every pre-widen event is DOMINATED by the Rescan (strictly less) — correct:
  // the consumer re-enumerates over them.
  assert!(
    pre_widen.iter().all(|&e| e < rescan_stamp),
    "pre-widen events are dominated by the widen Rescan"
  );

  // (b) THE FIX: every post-widen new-root event is NOT dominated by the Rescan
  // (tie-or-exceeds it). The pre-fix bug would make these < rescan_stamp and lose
  // them.
  assert!(
    post_widen.iter().all(|&e| e >= rescan_stamp),
    "post-widen new-root events are NOT dominated by the widen Rescan (RISK-1)"
  );

  // (c) The whole delivered stamp sequence for the subscription — pre-widen, the
  // Rescan, then post-widen — is monotone-nondecreasing.
  let whole: Vec<Epoch> = pre_widen
    .iter()
    .copied()
    .chain(core::iter::once(rescan_stamp))
    .chain(post_widen.iter().copied())
    .collect();
  assert!(
    whole.windows(2).all(|w| w[0] <= w[1]),
    "the whole stamped sequence across the re-point is monotone-nondecreasing"
  );
}

/// Two subscriptions re-pointed onto the SAME new root rebase INDEPENDENTLY, each
/// from its own high-water — so they get different `epoch_base`s and different stamps
/// for the very same raw fs epoch on the shared new root.
#[test]
fn two_subscriptions_onto_one_new_root_rebase_independently() {
  let mut ledger = EpochLedger::new();
  let (s1, s2) = (sub(1), sub(2));

  // Drive the two subscriptions to DIFFERENT high-waters on their own narrow roots.
  let root1 = Fixture::new("/a/b", &[(1, "/a/b")]);
  for raw in 0..5 {
    root1.deliver(&mut ledger, &FakeEvent::change("/a/b/f"), Epoch::new(raw));
  }
  let root2 = Fixture::new("/a/c", &[(2, "/a/c")]);
  for raw in 0..2 {
    root2.deliver(&mut ledger, &FakeEvent::change("/a/c/f"), Epoch::new(raw));
  }

  // Widen both onto the shared new root /a. s1 (high-water 4) rebases to 5; s2
  // (high-water 1) rebases to 2 — independently.
  let r1 = ledger.repoint(s1);
  let r2 = ledger.repoint(s2);
  assert_eq!(
    r1,
    Epoch::new(5),
    "s1's Rescan is one past its own high-water 4"
  );
  assert_eq!(
    r2,
    Epoch::new(2),
    "s2's Rescan is one past its own high-water 1"
  );

  // The SAME raw fs epoch 0 on the shared new root /a stamps DIFFERENTLY for each,
  // because each carries its own rebased base.
  let shared = Fixture::new("/a", &[(1, "/a"), (2, "/a")]);
  let delivered = shared.deliver(&mut ledger, &FakeEvent::change("/a/x"), Epoch::new(0));
  let stamp_of = |who: Subscription| {
    delivered
      .iter()
      .find(|(s, _)| *s == who)
      .map(|(_, e)| *e)
      .expect("both subs are covered by /a")
  };
  assert_eq!(
    stamp_of(s1),
    Epoch::new(5),
    "s1 rebases raw 0 onto its base 5 (independent of s2)"
  );
  assert_eq!(
    stamp_of(s2),
    Epoch::new(2),
    "s2 rebases raw 0 onto its base 2 (independent of s1)"
  );
  // Neither post-widen event is dominated by its own subscription's widen Rescan.
  assert!(stamp_of(s1) >= r1 && stamp_of(s2) >= r2);
}

/// A `Rescan` fs itself reports is stamped and fanned out to EVERY subscriber of the
/// root (coverage bypassed), and its umbrella stamp dominates each subscriber's prior
/// stream — the same dominance the synthetic widen Rescan gives, but for an
/// fs-sourced one.
#[test]
fn fs_rescan_is_stamped_and_dominates_prior_stream() {
  let mut ledger = EpochLedger::new();
  // Root /a serves /a and the narrower /a/b/deep (which a plain event at /a/x would
  // NOT cover — but a Rescan reaches it anyway).
  let fx = Fixture::new("/a", &[(1, "/a"), (2, "/a/b/deep")]);
  let (s1, s2) = (sub(1), sub(2));

  // Give /a a couple of prior events so its high-water is non-trivial.
  fx.deliver(&mut ledger, &FakeEvent::change("/a/x"), Epoch::new(0));
  let prior = fx.deliver(&mut ledger, &FakeEvent::change("/a/x"), Epoch::new(1));
  assert_eq!(
    prior,
    vec![(s1, Epoch::new(1))],
    "plain event only covers /a"
  );

  // A Rescan located at /a/x — which /a/b/deep does NOT cover — is delivered to BOTH,
  // stamped in each subscriber's own space (from each one's base START, raw 2 → 2).
  let delivered = fx.deliver(&mut ledger, &FakeEvent::rescan("/a/x"), Epoch::new(2));
  let stamp_of = |who: Subscription| delivered.iter().find(|(s, _)| *s == who).map(|(_, e)| *e);
  assert_eq!(
    stamp_of(s1),
    Some(Epoch::new(2)),
    "the Rescan reaches /a and dominates its prior stamp of 1"
  );
  assert_eq!(
    stamp_of(s2),
    Some(Epoch::new(2)),
    "the Rescan reaches /a/b/deep despite coverage (loss is never narrowed away)"
  );
  assert!(
    stamp_of(s1).unwrap() > Epoch::new(1),
    "the fs Rescan's stamp dominates /a's prior stream"
  );
}

/// Every projection of one raw move carries its subscriber's umbrella stamp (design
/// §5/§8): a move between sibling subs yields a Removed for the source-sub and a
/// Created for the dest-sub, and each is stamped in that subscriber's own epoch space —
/// not the raw fs epoch, and not skipped.
#[test]
fn move_decomposition_stamps_each_projection() {
  let mut ledger = EpochLedger::new();
  let (s1, s2) = (sub(1), sub(2));
  // Two sibling subs on one root, at different high-waters so their stamps differ.
  let fx = Fixture::new("/a", &[(1, "/a/src"), (2, "/a/dst")]);
  fx.deliver(&mut ledger, &FakeEvent::change("/a/src/x"), Epoch::new(3)); // s1 hw = 3
  fx.deliver(&mut ledger, &FakeEvent::change("/a/dst/x"), Epoch::new(1)); // s2 hw = 1

  // A move /a/src/f -> /a/dst/f at raw fs epoch 4: source-sub gets a stamped Removed,
  // dest-sub a stamped Created.
  let out = fx.deliver_projected(
    &mut ledger,
    &FakeEvent::moved("/a/src/f", "/a/dst/f"),
    Epoch::new(4),
  );
  let find = |who: Subscription| out.iter().find(|(s, _, _)| *s == who).copied();

  let (_, p1, e1) = find(s1).expect("the source-sub is served");
  assert_eq!(
    p1,
    Projection::MoveOut,
    "source-sub gets the move-out Removed"
  );
  assert_eq!(e1, Epoch::new(4), "…stamped in s1's space (base 0 + raw 4)");

  let (_, p2, e2) = find(s2).expect("the dest-sub is served");
  assert_eq!(p2, Projection::MoveIn, "dest-sub gets the move-in Created");
  assert_eq!(e2, Epoch::new(4), "…stamped in s2's space (base 0 + raw 4)");
}

/// The overflow shed primitive (design backpressure doc): `shed_rescan` mints a
/// strictly-dominating `Rescan` epoch WITHOUT rebasing the subscription's base (it stays on
/// the same live root). The `Rescan` dominates the whole pre-shed stream. This exercises the
/// case where the raw fs epoch has **advanced** across the shed (a later reconciliation
/// generation — raw 5,6,7): those deltas stamp `base + raw` and so sort at or above the
/// `Rescan`. The complementary case — a later **same-generation** event whose raw has NOT
/// advanced (the common one, since the raw fs epoch is a generation, not a per-event
/// counter), which relies on [`stamp`](EpochLedger::stamp)'s high-water clamp — is covered by
/// [`post_shed_same_generation_event_is_not_dominated_by_the_shed_rescan`]. `repoint`'s
/// base-rebasing is not used for a shed: it is sound only for a widen onto a fresh root.
#[test]
fn shed_rescan_dominates_prior_stream_and_same_root_deltas_sort_at_or_above() {
  let mut ledger = EpochLedger::new();
  let s = sub(1);
  let root = Fixture::new("/a", &[(1, "/a")]);

  // Same-root events at raw fs epochs 0..5 stamp 0..4 (base START), driving high-water to 4.
  let mut pre = Vec::new();
  for raw in 0..5 {
    let delivered = root.deliver(&mut ledger, &FakeEvent::change("/a/f"), Epoch::new(raw));
    pre.push(delivered[0].1);
  }
  assert_eq!(
    pre,
    vec![
      Epoch::new(0),
      Epoch::new(1),
      Epoch::new(2),
      Epoch::new(3),
      Epoch::new(4),
    ],
    "pre-shed stamps track the raw fs epochs from base START"
  );

  // Overflow shed: the parked Rescan is minted one past the high-water (strictly dominating
  // the whole pre-shed stream).
  let rescan = ledger.shed_rescan(s);
  assert_eq!(rescan, Epoch::new(5), "shed_rescan = high_water.next()");
  assert!(
    pre.iter().all(|&e| e < rescan),
    "the shed Rescan strictly dominates every pre-shed delivery"
  );

  // The SAME live root keeps delivering — its raw fs epochs keep climbing (5,6,7), NOT
  // restarting at 0 (no re-arm). Because base was NOT rebased, they stamp base + raw =
  // 5,6,7, tying-or-exceeding the Rescan, so a conforming consumer never drops them.
  let mut post = Vec::new();
  for raw in 5..8 {
    let delivered = root.deliver(&mut ledger, &FakeEvent::change("/a/f"), Epoch::new(raw));
    post.push(delivered[0].1);
  }
  assert_eq!(
    post,
    vec![Epoch::new(5), Epoch::new(6), Epoch::new(7)],
    "same-root post-shed deltas stamp base + raw (base unchanged)"
  );
  assert!(
    post.iter().all(|&e| e >= rescan),
    "no same-root delta after the shed sorts BELOW the Rescan (the non-rebasing guarantee)"
  );

  // Repeated sheds are monotone/idempotent: a second shed mints strictly above the first
  // and above every same-root stamp since (high-water is now 7).
  let rescan2 = ledger.shed_rescan(s);
  assert_eq!(
    rescan2,
    Epoch::new(8),
    "a second shed mints one past the new high-water (strictly increasing)"
  );
  assert!(rescan2 > rescan, "sheds are monotone");
}

/// Codex R6 regression (design backpressure doc, no silent loss): the raw fs epoch is a
/// per-scope reconciliation **generation** — constant across ordinary events, advanced only
/// on a `Rescan`/overflow (see `tributary_proto`'s monitor) — NOT a per-event counter. So
/// after an overflow [`shed_rescan`](EpochLedger::shed_rescan) mints a dominating `Rescan` at
/// `high_water.next()`, a later SAME-generation event (same raw) must still not sort below
/// it. [`stamp`](EpochLedger::stamp)'s high-water clamp lifts such an event up to TIE the
/// shed `Rescan` (a tie is not dominated).
///
/// Fail-on-old: without the clamp (`stamp = base + raw`), the post-shed same-generation event
/// stamps `base + 0 = 0`, one BELOW the shed `Rescan` (1) → a dominance-applying consumer
/// drops it → silent loss. This is exactly the class the climbing-raw shed test above (which
/// models raw as a per-event counter) cannot see.
#[test]
fn post_shed_same_generation_event_is_not_dominated_by_the_shed_rescan() {
  let mut ledger = EpochLedger::new();
  let s = sub(1);
  let root = Fixture::new("/a", &[(1, "/a")]);

  // Ordinary events in ONE reconciliation generation all carry the SAME raw fs epoch (0);
  // they stamp base + 0 = 0 and high-water stays 0.
  for _ in 0..3 {
    let delivered = root.deliver(&mut ledger, &FakeEvent::change("/a/f"), Epoch::new(0));
    assert_eq!(
      delivered[0].1,
      Epoch::new(0),
      "same-generation events stamp base + 0"
    );
  }

  // Overflow shed: the parked Rescan is minted one past the high-water.
  let rescan = ledger.shed_rescan(s);
  assert_eq!(rescan, Epoch::new(1), "shed_rescan = high_water.next()");

  // A LATER event in the SAME generation still carries raw 0 (no fs re-arm, no generation
  // bump). Its natural stamp base + 0 = 0 would sort BELOW the shed Rescan (1); the clamp
  // lifts it to tie the Rescan (1) instead, so it is never dominated.
  let post = root.deliver(&mut ledger, &FakeEvent::change("/a/f"), Epoch::new(0));
  assert_eq!(
    post[0].1,
    Epoch::new(1),
    "the post-shed same-generation event is clamped up to tie the shed Rescan, not base + 0 = 0"
  );
  assert!(
    post[0].1 >= rescan,
    "no post-shed same-generation event sorts below the shed Rescan (Codex R6: no silent loss)"
  );
}

/// Codex R7 regression (design backpressure doc, no silent loss): a SOURCE-emitted `Rescan`
/// must STRICTLY dominate every prior delivery. The R6 clamp lets an ordinary post-shed
/// same-generation event deliver *at* the shed `Rescan`'s epoch (a tie). If the source then
/// emits its own `Rescan`, the ordinary clamp (`max(base + raw, high_water)`) would only tie
/// that already-delivered event — losing strict dominance and the lower layer's coverage-loss
/// signal. [`stamp_rescan`](EpochLedger::stamp_rescan) (`max(base + raw, high_water.next())`)
/// restores it.
///
/// Fail-on-old: routing the source `Rescan` through the ordinary `stamp` clamp stamps it AT
/// the post-shed event's epoch (a tie, not strictly above) → the assertion FAILS.
#[test]
fn source_rescan_strictly_dominates_a_post_shed_same_generation_event() {
  let mut ledger = EpochLedger::new();
  let s = sub(1);
  let root = Fixture::new("/a", &[(1, "/a")]);

  // One generation of ordinary events (raw 0): stamp base + 0 = 0, high-water 0.
  root.deliver(&mut ledger, &FakeEvent::change("/a/f"), Epoch::new(0));

  // Overflow shed → dominating Rescan at 1.
  let shed = ledger.shed_rescan(s);
  assert_eq!(shed, Epoch::new(1), "shed_rescan = high_water.next()");

  // A post-shed SAME-generation ordinary event (raw 0) is clamped up to tie the shed Rescan.
  let post = root.deliver(&mut ledger, &FakeEvent::change("/a/f"), Epoch::new(0));
  assert_eq!(
    post[0].1,
    Epoch::new(1),
    "R6: the post-shed ordinary event ties the shed Rescan"
  );

  // Now the SOURCE emits its own `Rescan` in the SAME generation (raw 0). It must STRICTLY
  // dominate the epoch-1 event just delivered — not merely tie it.
  let src_rescan = root.deliver(&mut ledger, &FakeEvent::rescan("/a/f"), Epoch::new(0));
  assert_eq!(
    src_rescan[0].1,
    Epoch::new(2),
    "the source Rescan is stamped strictly above the post-shed event (high_water.next()), not tying it"
  );
  assert!(
    src_rescan[0].1 > post[0].1,
    "a source Rescan strictly dominates every prior delivery (Codex R7: coverage-loss signal preserved)"
  );
}
