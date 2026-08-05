use core::num::NonZeroU64;
use std::{collections::HashMap, ffi::OsString, path::Path};

use tributary_proto::ScopeId;

use super::{ReservedEndpoints, RoutableEvent, Subscription, fan_out};

/// A path's `OsString` components — the located-key form the fs source keys on, and
/// the coordinate `fan_out` covers over.
fn key(path: &str) -> Vec<OsString> {
  Path::new(path)
    .components()
    .map(|c| c.as_os_str().to_os_string())
    .collect()
}

/// Which projection a subscriber received for one raw event — the move decompositions
/// (design §5) and the clamped recovery projection, plus the whole delivery. Carried on
/// the fake `Delivered` so a test can assert *which* projection each covering subscriber
/// got, not merely that it was covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Projection {
  /// The event as-is: a non-move change, a located Rescan, or a both-covering Moved.
  Whole,
  /// The synthesized move-out `Removed(from)` (source-only coverage).
  MoveOut,
  /// The synthesized move-in `Created(to)` (destination-only coverage).
  MoveIn,
  /// A Rescan that CONTAINED the subscriber, re-keyed to the subscriber's own key.
  RescanClamped,
}

/// What fan-out did to a delivery's coordinate for its receiving subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rebased {
  /// Stripped this many leading location segments — the subscriber's depth below the
  /// root the event was captured against.
  Strip(usize),
  /// Degraded to the root-anchored empty location: the subscriber sits ABOVE that root,
  /// so its coordinate is not expressible from what the delivery carries.
  AtRoot,
}

/// A fake delivery: the subscriber it was routed to, the projection it received, the key
/// that projection names, and how fan-out re-expressed its coordinate for this
/// subscriber.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Delivered {
  sub: Subscription,
  projection: Projection,
  key: Vec<OsString>,
  rebased: Rebased,
}

/// A minimal stand-in for a raw event: routing reads its endpoint keys, whether it
/// is a `Rescan`, and the depth of the root it was captured against. Its delivery
/// records the subscriber and which projection it got, so a test asserts the covered set
/// **and** each move decomposition without touching any real source's private event
/// constructor. A `Some(from)` makes it a move whose destination is `key`.
#[derive(Clone)]
struct FakeEvent {
  key: Vec<OsString>,
  from: Option<Vec<OsString>>,
  rescan: bool,
  /// Which endpoints the source reserves — the classification the driver decides at its
  /// [`Source`](crate::Source) seam and this seam only carries.
  reserved: ReservedEndpoints,
  /// The root depth this event's location is measured from — a property of the EVENT,
  /// which a queued change carries unchanged across a widen of the root it rides.
  /// `None` is "captured against whatever root the fixture is routing on", filled in at
  /// route time; [`captured_under`](Self::captured_under) pins it instead, modelling the
  /// change that queued before a widen and drained after it.
  captured_root_depth: Option<usize>,
}

impl FakeEvent {
  fn change(path: &str) -> Self {
    Self {
      key: key(path),
      from: None,
      rescan: false,
      reserved: ReservedEndpoints::None,
      captured_root_depth: None,
    }
  }

  fn rescan(path: &str) -> Self {
    Self {
      key: key(path),
      from: None,
      rescan: true,
      reserved: ReservedEndpoints::None,
      captured_root_depth: None,
    }
  }

  /// A move from `from` to `to` (the destination is `key`).
  fn moved(from: &str, to: &str) -> Self {
    Self {
      key: key(to),
      from: Some(key(from)),
      rescan: false,
      reserved: ReservedEndpoints::None,
      captured_root_depth: None,
    }
  }

  /// Declares which of this event's endpoints lie in the source's reserved namespace —
  /// the sync-artifact classification fan-out masks out of every subscriber's coverage.
  fn reserving(mut self, reserved: ReservedEndpoints) -> Self {
    self.reserved = reserved;
    self
  }

  /// Pins the root this event's location was captured against, independently of the root
  /// the fixture is routing on now — the pre-widen queued change.
  fn captured_under(mut self, root_path: &str) -> Self {
    self.captured_root_depth = Some(key(root_path).len());
    self
  }
}

impl RoutableEvent<OsString> for FakeEvent {
  type Delivered = Delivered;

  fn key(&self) -> &[OsString] {
    self.key.as_slice()
  }

  fn move_from(&self) -> Option<&[OsString]> {
    self.from.as_deref()
  }

  fn is_rescan(&self) -> bool {
    self.rescan
  }

  fn reserved(&self) -> ReservedEndpoints {
    self.reserved
  }

  fn deliver(&self, sub: Subscription) -> Delivered {
    Delivered {
      sub,
      projection: Projection::Whole,
      key: self.key.clone(),
      rebased: Rebased::Strip(0),
    }
  }

  fn deliver_move_out(&self, sub: Subscription) -> Delivered {
    Delivered {
      sub,
      projection: Projection::MoveOut,
      key: self
        .from
        .clone()
        .expect("move-out is only minted for a move"),
      rebased: Rebased::Strip(0),
    }
  }

  fn deliver_move_in(&self, sub: Subscription) -> Delivered {
    Delivered {
      sub,
      projection: Projection::MoveIn,
      key: self.key.clone(),
      rebased: Rebased::Strip(0),
    }
  }

  fn deliver_rescan_clamped(&self, sub: Subscription, key: &[OsString]) -> Delivered {
    Delivered {
      sub,
      projection: Projection::RescanClamped,
      key: key.to_vec(),
      rebased: Rebased::Strip(0),
    }
  }

  fn captured_root_depth(&self) -> usize {
    self
      .captured_root_depth
      .expect("the fixture anchors every routed event")
  }

  fn rebase(&self, delivered: &mut Delivered, strip: usize) {
    delivered.rebased = Rebased::Strip(strip);
  }

  fn anchor_at_root(&self, delivered: &mut Delivered) {
    delivered.rebased = Rebased::AtRoot;
  }
}

/// A test root's subscriber list plus a side table of each subscriber's key — the
/// inputs `fan_out` needs (the matched root's key and subscribers, and the key resolver).
struct Fixture {
  root_depth: usize,
  subscribers: Vec<Subscription>,
  keys: HashMap<Subscription, Vec<OsString>>,
}

impl Fixture {
  /// A root at `root_path` whose subscribers are the given `(id, key path)` pairs, in
  /// that (registration) order. The root path fixes the coordinate the raw event's
  /// location is in, which fan-out rebases each delivery out of.
  fn new(root_path: &str, subscribers: &[(u64, &str)]) -> Self {
    let mut subs = Vec::new();
    let mut keys = HashMap::new();
    for &(id, path) in subscribers {
      let sub = Subscription::for_test(ScopeId::new(NonZeroU64::new(id).expect("nonzero id")));
      subs.push(sub);
      keys.insert(sub, key(path));
    }
    Self {
      root_depth: key(root_path).len(),
      subscribers: subs,
      keys,
    }
  }

  fn sub(&self, id: u64) -> Subscription {
    Subscription::for_test(ScopeId::new(NonZeroU64::new(id).expect("nonzero id")))
  }

  /// `event` as this fixture routes it: an event that did not pin its own capture root
  /// was captured against the root being routed on.
  fn anchored(&self, event: &FakeEvent) -> FakeEvent {
    let mut event = event.clone();
    event.captured_root_depth = Some(event.captured_root_depth.unwrap_or(self.root_depth));
    event
  }

  /// The full deliveries `event` fans out to (subscriber + projection), every
  /// subscriber's gate admitting — the move-decomposition assertions read this.
  fn route_full(&self, event: &FakeEvent) -> Vec<Delivered> {
    fan_out(
      &self.anchored(event),
      &self.subscribers,
      |sub| self.keys.get(&sub).map(Vec::as_slice),
      |_sub, _delivered| true,
    )
  }

  /// The subscribers `event` fans out to, with every subscriber's gate admitting (so
  /// this isolates the coverage/Rescan logic from the filter/interest gate).
  fn route(&self, event: &FakeEvent) -> Vec<Subscription> {
    self.route_full(event).into_iter().map(|d| d.sub).collect()
  }

  /// The subscribers `event` fans out to, admitting a delivery only when `admits`
  /// returns `true` for its `(subscription, delivered)` — the filter/interest gate
  /// under test (it sees the *projected* delivery).
  fn route_filtered(
    &self,
    event: &FakeEvent,
    admits: impl Fn(Subscription, &Delivered) -> bool,
  ) -> Vec<Subscription> {
    fan_out(
      &self.anchored(event),
      &self.subscribers,
      |sub| self.keys.get(&sub).map(Vec::as_slice),
      admits,
    )
    .into_iter()
    .map(|d| d.sub)
    .collect()
  }
}

#[test]
fn covers_single_subscriber() {
  let fx = Fixture::new("/a", &[(1, "/a")]);
  let delivered = fx.route(&FakeEvent::change("/a/file"));
  assert_eq!(
    delivered,
    vec![fx.sub(1)],
    "the lone covering sub is served"
  );
}

#[test]
fn overlap_fans_to_all_covering() {
  // Root /a carries two subscriptions: /a and /a/b.
  let fx = Fixture::new("/a", &[(1, "/a"), (2, "/a/b")]);

  // An event under /a/b is covered by both /a and /a/b.
  let both = fx.route(&FakeEvent::change("/a/b/c"));
  assert_eq!(
    both,
    vec![fx.sub(1), fx.sub(2)],
    "an event under /a/b reaches both /a and /a/b"
  );

  // An event under /a/x is covered only by /a — /a/b is a sibling, not an ancestor.
  let only_a = fx.route(&FakeEvent::change("/a/x"));
  assert_eq!(
    only_a,
    vec![fx.sub(1)],
    "an event under /a/x reaches only /a"
  );
}

#[test]
fn coverage_is_component_wise_not_prefix() {
  // /a/b must not "cover" /a/bc — the ancestor test is component-wise.
  let fx = Fixture::new("/a", &[(1, "/a/b")]);
  assert_eq!(
    fx.route(&FakeEvent::change("/a/bc")),
    Vec::<Subscription>::new(),
    "/a/b does not cover the sibling /a/bc"
  );
  assert_eq!(
    fx.route(&FakeEvent::change("/a/b")),
    vec![fx.sub(1)],
    "/a/b covers itself (ancestor-or-equal)"
  );
}

/// A rescan naming the WHOLE root still reaches every subscriber — the property the
/// unconditional fan-out was protecting — but each narrow subscriber's instruction is
/// clamped to its own key, so none is handed a path outside its watch.
#[test]
fn whole_root_rescan_reaches_every_subscriber_clamped_to_its_own_key() {
  let fx = Fixture::new("/a", &[(1, "/a"), (2, "/a/b/deep")]);
  let out = fx.route_full(&FakeEvent::rescan("/a"));
  assert_eq!(
    out.iter().map(|d| d.sub).collect::<Vec<_>>(),
    vec![fx.sub(1), fx.sub(2)],
    "a root-wide loss still reaches every subscriber"
  );
  assert_eq!(
    (out[0].projection, out[0].key.as_slice()),
    (Projection::Whole, key("/a").as_slice()),
    "the root-key subscriber's own key IS the rescan key — delivered verbatim"
  );
  assert_eq!(
    (out[1].projection, out[1].key.as_slice()),
    (Projection::RescanClamped, key("/a/b/deep").as_slice()),
    "the narrow subscriber is told to re-enumerate ITS OWN subtree, not /a"
  );
}

/// A rescan located at or below a subscription is delivered verbatim: the located key is
/// already inside the subscription's boundary, and narrowing it further would lose
/// precision the source paid for.
#[test]
fn rescan_below_a_subscription_is_delivered_located() {
  let fx = Fixture::new("/a", &[(1, "/a")]);
  let out = fx.route_full(&FakeEvent::rescan("/a/x/y"));
  assert_eq!(out.len(), 1);
  assert_eq!(
    (out[0].projection, out[0].key.as_slice()),
    (Projection::Whole, key("/a/x/y").as_slice()),
    "a located rescan keeps its key for an ancestor subscription"
  );
}

/// The finding: a rescan DISJOINT from a subscription must not be delivered to it. It
/// names a subtree the subscription owns none of, so re-enumerating it recovers nothing —
/// and, delivered, it becomes parked debt that suppresses that subscription's real deltas.
#[test]
fn a_disjoint_rescan_is_not_delivered() {
  // Root /a carries /a/b/deep, which shares the physical root with the loss at /a/x but
  // covers none of it.
  let fx = Fixture::new("/a", &[(1, "/a/b/deep")]);
  assert_eq!(
    fx.route(&FakeEvent::rescan("/a/x")),
    Vec::<Subscription>::new(),
    "a rescan whose subtree is disjoint from the subscription reaches it not at all"
  );
  // A sibling sharing the same root but covering the loss still receives it, so the
  // narrowing above is geometry, not a blanket suppression.
  let fx = Fixture::new("/a", &[(1, "/a/b/deep"), (2, "/a/x")]);
  assert_eq!(
    fx.route(&FakeEvent::rescan("/a/x")),
    vec![fx.sub(2)],
    "only the intersecting subscriber is served"
  );
}

/// The component-wise ancestor test governs the rescan geometry too: `/a/b` neither
/// contains nor is contained by `/a/bc`.
#[test]
fn rescan_geometry_is_component_wise() {
  let fx = Fixture::new("/a", &[(1, "/a/bc")]);
  assert_eq!(
    fx.route(&FakeEvent::rescan("/a/b")),
    Vec::<Subscription>::new(),
    "/a/b does not contain the sibling /a/bc"
  );
  assert_eq!(
    fx.route(&FakeEvent::rescan("/a/bc")),
    vec![fx.sub(1)],
    "an exact-key rescan reaches its subscription"
  );
}

/// Every delivery is rebased out of the physical armed root's coordinate and into the
/// receiving subscriber's own: the strip count is the subscriber's depth below the root,
/// independent of where the event landed. A subscriber AT the root strips nothing.
#[test]
fn deliveries_are_rebased_into_each_subscribers_coordinate() {
  let fx = Fixture::new("/a", &[(1, "/a"), (2, "/a/b"), (3, "/a/b/c")]);
  let out = fx.route_full(&FakeEvent::change("/a/b/c/file"));
  assert_eq!(
    out
      .iter()
      .map(|d| (d.sub.id().as_u64(), d.rebased))
      .collect::<Vec<_>>(),
    vec![
      (1, Rebased::Strip(0)),
      (2, Rebased::Strip(1)),
      (3, Rebased::Strip(2)),
    ],
    "each subscriber strips exactly its own depth below the armed root"
  );
}

/// The rebase is applied to a rescan too — including the clamped projection, whose key
/// IS the subscription root and whose location must therefore end up empty.
#[test]
fn rescan_projections_are_rebased_too() {
  // /a/b is an ancestor of the loss (located delivery); /a/b/x/deep is contained by it
  // (clamped delivery). Both are rebased by their own depth below the armed root /a.
  let fx = Fixture::new("/a", &[(1, "/a/b"), (2, "/a/b/x/deep")]);
  let out = fx.route_full(&FakeEvent::rescan("/a/b/x"));
  assert_eq!(
    out
      .iter()
      .map(|d| (d.sub.id().as_u64(), d.projection, d.rebased))
      .collect::<Vec<_>>(),
    vec![
      (1, Projection::Whole, Rebased::Strip(1)),
      (2, Projection::RescanClamped, Rebased::Strip(3)),
    ],
    "the located rescan and the clamped projection are both rebased by the subscriber's depth"
  );
}

/// The coordinate anchor belongs to the EVENT, not to the call. A change captured while
/// the root was `/a/b` and delivered after an in-place widen moved that root to `/a`
/// still rebases by its own capture depth — so the subscription whose key never moved
/// (`/a/b`) strips nothing, exactly as it did before the widen.
///
/// FAIL-ON-REVERT: anchor the rebase on the root fan-out is called with (`/a` here, depth
/// 2) instead of `captured_root_depth`, and `/a/b` strips 1 — the queued change is
/// re-coordinated one level up and `/a/b/c`'s two-level filter starts silently rejecting.
#[test]
fn a_queued_pre_widen_change_rebases_by_its_capture_depth() {
  // The root has already widened to /a; the event still carries its /a/b coordinate.
  let fx = Fixture::new("/a", &[(2, "/a/b"), (3, "/a/b/c")]);
  let out = fx.route_full(&FakeEvent::change("/a/b/c/file").captured_under("/a/b"));
  assert_eq!(
    out
      .iter()
      .map(|d| (d.sub.id().as_u64(), d.rebased))
      .collect::<Vec<_>>(),
    vec![(2, Rebased::Strip(0)), (3, Rebased::Strip(1))],
    "each subscriber strips its depth below the root the CHANGE was captured against"
  );
}

/// The one coordinate that cannot be stated: the widener itself, handed a change queued
/// from before its own widen. Its location would need leading segments the delivery never
/// recorded, so the delivery degrades to root-anchored — with its key, which is absolute,
/// left as the authoritative signal — rather than reporting a capture-relative location
/// that names a path the subscription does not contain.
///
/// FAIL-ON-REVERT: `saturating_sub` in place of the `checked_sub` split silently strips
/// nothing and hands `/a` the location `[file]` for a change at `/a/b/c/file`.
#[test]
fn a_subscriber_above_the_capture_root_is_anchored_not_mis_stated() {
  let fx = Fixture::new("/a", &[(1, "/a"), (2, "/a/b")]);
  let out = fx.route_full(&FakeEvent::change("/a/b/file").captured_under("/a/b"));
  assert_eq!(
    out
      .iter()
      .map(|d| (d.sub.id().as_u64(), d.rebased))
      .collect::<Vec<_>>(),
    vec![(1, Rebased::AtRoot), (2, Rebased::Strip(0))],
    "the widener is anchored at its root; the subscription at the capture root is exact"
  );
}

#[test]
fn filter_narrows_the_covered_set() {
  // Root /a carries two covering subscriptions: /a and /a/b.
  let fx = Fixture::new("/a", &[(1, "/a"), (2, "/a/b")]);

  // An event under /a/b is COVERED by both, but subscription 2's filter rejects it —
  // the filter is an additional gate that narrows the covered set (§7).
  let admitted = fx.route_filtered(&FakeEvent::change("/a/b/c"), |sub, _| sub != fx.sub(2));
  assert_eq!(
    admitted,
    vec![fx.sub(1)],
    "the filter excludes the covering subscription that does not admit"
  );

  // With every filter admitting, both covering subscriptions receive it — proving the
  // narrowing above was the filter, not coverage.
  let both = fx.route_filtered(&FakeEvent::change("/a/b/c"), |_, _| true);
  assert_eq!(both, vec![fx.sub(1), fx.sub(2)], "both cover it");
}

#[test]
fn filter_only_sees_covered_deliveries() {
  // Root /a carries /a and /a/b. An event at /a/x is covered only by /a; the filter
  // must never be consulted for /a/b (it does not cover the event), so a filter that
  // panics for /a/b proves coverage is checked FIRST.
  let fx = Fixture::new("/a", &[(1, "/a"), (2, "/a/b")]);
  let admitted = fx.route_filtered(&FakeEvent::change("/a/x"), |sub, _| {
    assert_ne!(
      sub,
      fx.sub(2),
      "the filter is only asked about covering subs"
    );
    true
  });
  assert_eq!(
    admitted,
    vec![fx.sub(1)],
    "only the covering /a is admitted"
  );
}

#[test]
fn rescan_bypasses_the_filter() {
  // Root /a carries /a and /a/b, and the loss at /a covers both. A Rescan must reach
  // BOTH even when every filter rejects — coverage loss is never filtered away (§7/§8).
  // A filter that would reject everything (and must never even be consulted for a
  // Rescan) proves the bypass.
  let fx = Fixture::new("/a", &[(1, "/a"), (2, "/a/b")]);
  let admitted = fx.route_filtered(&FakeEvent::rescan("/a"), |_, _| {
    panic!("the filter must not be consulted for a Rescan");
  });
  assert_eq!(
    admitted,
    vec![fx.sub(1), fx.sub(2)],
    "a Rescan bypasses the filter and reaches every intersecting subscriber"
  );
}

// -------------------------------------------------------------------------------
// Moved decomposition (design §5): a move has two endpoints; each subscriber gets
// exactly one projection from its two-endpoint coverage.
// -------------------------------------------------------------------------------

/// The projection each subscriber received, as `(id, Projection)` pairs, so a move
/// test asserts the per-subscriber decomposition directly.
fn projections(fx: &Fixture, event: &FakeEvent) -> Vec<(u64, Projection)> {
  fx.route_full(event)
    .into_iter()
    .map(|d| (d.sub.id().as_u64(), d.projection))
    .collect()
}

/// A subscription covering only the move SOURCE gets a move-out `Removed(from)` — it
/// must learn the file left its tree, even though the destination is outside its watch.
/// (The pre-fix bug tested only the destination path, so a source-only sub silently
/// missed the move entirely.)
#[test]
fn move_out_delivers_removed_to_source_only_sub() {
  // Root /a; the sub watches only /a/src. A move /a/src/f -> /a/dst/f: it covers the
  // source, not the destination.
  let fx = Fixture::new("/a", &[(1, "/a/src")]);
  let out = projections(&fx, &FakeEvent::moved("/a/src/f", "/a/dst/f"));
  assert_eq!(
    out,
    vec![(1, Projection::MoveOut)],
    "a source-only sub gets the move-out Removed(from) — never silently skipped"
  );
}

/// A subscription covering only the move DESTINATION gets a move-in `Created(to)` — the
/// file arrived from outside its watch.
#[test]
fn move_in_delivers_created_to_dest_only_sub() {
  let fx = Fixture::new("/a", &[(1, "/a/dst")]);
  let out = projections(&fx, &FakeEvent::moved("/a/src/f", "/a/dst/f"));
  assert_eq!(
    out,
    vec![(1, Projection::MoveIn)],
    "a destination-only sub gets the move-in Created(to)"
  );
}

/// A subscription covering BOTH endpoints gets exactly one whole `Moved` — never also a
/// Removed/Created (structural dedup).
#[test]
fn move_within_one_sub_delivers_one_moved() {
  // The sub watches all of /a, covering both /a/src/f and /a/dst/f.
  let fx = Fixture::new("/a", &[(1, "/a")]);
  let out = projections(&fx, &FakeEvent::moved("/a/src/f", "/a/dst/f"));
  assert_eq!(
    out,
    vec![(1, Projection::Whole)],
    "a both-covering sub gets exactly one whole Moved — dedup, no extra Removed/Created"
  );
}

/// A move between two SIBLING subscriptions decomposes per subscriber: the source-sub
/// gets a Removed, the dest-sub gets a Created — each sees its own side of the move.
#[test]
fn move_between_sibling_subs() {
  // Root /a carries two sibling subs: /a/src and /a/dst.
  let fx = Fixture::new("/a", &[(1, "/a/src"), (2, "/a/dst")]);
  let out = projections(&fx, &FakeEvent::moved("/a/src/f", "/a/dst/f"));
  assert_eq!(
    out,
    vec![(1, Projection::MoveOut), (2, Projection::MoveIn)],
    "the source-sub gets a Removed, the dest-sub a Created"
  );
}

/// A subscription covering NEITHER endpoint of a move gets nothing.
#[test]
fn move_covering_neither_endpoint_delivers_nothing() {
  let fx = Fixture::new("/a", &[(1, "/a/other")]);
  let out = projections(&fx, &FakeEvent::moved("/a/src/f", "/a/dst/f"));
  assert!(
    out.is_empty(),
    "a sub covering neither endpoint gets nothing"
  );
}

/// Dedup across a mixed subscriber set: one both-covering sub gets exactly one Moved,
/// while narrower siblings get their single-endpoint projection — no duplicate for the
/// both-coverer.
#[test]
fn move_dedup_both_covering_sub_gets_exactly_one_moved() {
  // /a covers both endpoints; /a/src covers only the source; /a/dst only the dest.
  let fx = Fixture::new("/a", &[(1, "/a"), (2, "/a/src"), (3, "/a/dst")]);
  let out = projections(&fx, &FakeEvent::moved("/a/src/f", "/a/dst/f"));
  assert_eq!(
    out,
    vec![
      (1, Projection::Whole), // both endpoints → one Moved, never also Removed/Created
      (2, Projection::MoveOut), // source only → Removed
      (3, Projection::MoveIn), // dest only → Created
    ],
    "the both-covering sub gets exactly one Moved; siblings get their one-sided projection"
  );
}

/// The filter/interest gate sees the *projected* delivery, so it can gate a move-out
/// and a move-in independently by their projected kind (a sub with `removed` interest
/// keeps a move-out but a `created`-only one would drop it). Here the gate rejects the
/// move-out projection specifically, proving the projection is minted before the gate.
#[test]
fn move_projection_is_gated_by_the_projected_kind() {
  let fx = Fixture::new("/a", &[(1, "/a/src"), (2, "/a/dst")]);
  // Admit everything EXCEPT the move-out projection (as a `created`-only interest would).
  let admitted = fx.route_filtered(&FakeEvent::moved("/a/src/f", "/a/dst/f"), |_sub, d| {
    d.projection != Projection::MoveOut
  });
  assert_eq!(
    admitted,
    vec![fx.sub(2)],
    "the gate drops the move-out projection; the move-in still reaches the dest-sub"
  );
}

// -------------------------------------------------------------------------------
// The reserved namespace masks an ENDPOINT, never the whole change: a rename can put a
// source's own sync artifact at one end and a user object at the other, and the user end
// is exactly what its subscribers are watching for.
// -------------------------------------------------------------------------------

/// A user object renamed INTO the reserved namespace. The destination is masked out of
/// every subscriber's coverage, so a subscriber covering the source is left covering one
/// endpoint — and receives the move-out `Removed(from)` that says the object left its
/// tree, which is the whole truth it is allowed to be told.
///
/// FAIL-ON-REVERT: drop the destination mask from `project` (`covers_to` back to a bare
/// `to.starts_with(canonical)`) and this delivers a whole `Moved` naming the reserved
/// destination — leaking the artifact path the namespace exists to hide. That revert
/// unmasks `All` too, so it also fails the two total-suppression cells below; the mutation
/// isolating THIS cell is the narrower `masks_destination` → `matches!(self, Self::All)`.
#[test]
fn a_move_into_the_reserved_namespace_still_delivers_its_source_endpoint() {
  let fx = Fixture::new("/r", &[(1, "/r")]);
  let out = projections(
    &fx,
    &FakeEvent::moved("/r/important/file", "/r/.cookies/x")
      .reserving(ReservedEndpoints::Destination),
  );
  assert_eq!(
    out,
    vec![(1, Projection::MoveOut)],
    "the covering subscriber learns the file left, and learns nothing of where it went"
  );
}

/// The mirror: an artifact renamed OUT to an ordinary name. The source is masked, so a
/// subscriber covering the destination receives the move-in `Created(to)` — a user object
/// appeared in its tree, from somewhere it may not be told about.
///
/// FAIL-ON-REVERT: drop the source mask (`covers_from` back to a bare
/// `from.starts_with(canonical)`) and this delivers a whole `Moved` whose `from` is the
/// artifact's own path. That revert unmasks `All` too, so it also fails the
/// rename-between-two-artifacts cell below; the mutation isolating THIS cell is the
/// narrower `masks_source` → `matches!(self, Self::All)`.
#[test]
fn a_move_out_of_the_reserved_namespace_still_delivers_its_destination_endpoint() {
  let fx = Fixture::new("/r", &[(1, "/r")]);
  let out = projections(
    &fx,
    &FakeEvent::moved("/r/.cookies/x", "/r/adopted").reserving(ReservedEndpoints::Source),
  );
  assert_eq!(
    out,
    vec![(1, Projection::MoveIn)],
    "the covering subscriber learns an object arrived, and nothing of the artifact it was"
  );
}

/// Both endpoints reserved — a rename BETWEEN two artifact names. Nobody covers either
/// end, so the four-case decomposition lands on its own `(false, false)` arm and no
/// subscriber is told anything.
///
/// This is the router's own answer, independent of the driver's `is_total` short-circuit
/// (which settles such a change before it is ever routed): the two layers suppress it
/// separately, and this cell pins the lower one.
///
/// FAIL-ON-REVERT: drop `Self::All` from `masks_source` (→ `matches!(self, Self::Source)`)
/// and the suppression degrades to a move-out `Removed` naming one artifact's own path.
#[test]
fn a_move_within_the_reserved_namespace_reaches_nobody() {
  let fx = Fixture::new("/r", &[(1, "/r")]);
  let out = projections(
    &fx,
    &FakeEvent::moved("/r/.cookies/x", "/r/.cookies/y").reserving(ReservedEndpoints::All),
  );
  assert!(
    out.is_empty(),
    "a change reserved at every endpoint it has reaches no consumer: {out:?}"
  );
}

/// A single-endpoint change at a reserved key reaches nobody either — the same mask, read
/// on the one endpoint such a change has.
///
/// FAIL-ON-REVERT: drop the mask from `project`'s single-endpoint arm (`return
/// to.starts_with(canonical).then(|| event.deliver(sub))`) and the cookie's own create is
/// delivered whole to every covering subscriber.
#[test]
fn a_single_endpoint_change_at_a_reserved_key_reaches_nobody() {
  let fx = Fixture::new("/r", &[(1, "/r")]);
  let out = projections(
    &fx,
    &FakeEvent::change("/r/.cookies/x").reserving(ReservedEndpoints::All),
  );
  assert!(
    out.is_empty(),
    "the cookie's own create/unlink is covered by nobody: {out:?}"
  );
}

/// The over-suppression guard: with nothing reserved, the identical geometry delivers the
/// whole move. The mask is what changes the projection — not the shape of the rename.
///
/// FAIL-ON-REVERT: extend `masks_source` with `Self::None` and this degrades to a move-in.
/// It states the contrast at this seam rather than adding an independent kill: any mutation
/// that reaches it necessarily also fails the unreserved move cells above, which assert the
/// same contract without going near the namespace. The cells that DO isolate over-reach are
/// the driver's, where the classifier's own two grounds can be widened one at a time.
#[test]
fn an_unreserved_move_is_not_masked() {
  let fx = Fixture::new("/r", &[(1, "/r")]);
  let out = projections(&fx, &FakeEvent::moved("/r/important/file", "/r/plain/x"));
  assert_eq!(
    out,
    vec![(1, Projection::Whole)],
    "an ordinary rename keeps its whole-move delivery"
  );
}
