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
