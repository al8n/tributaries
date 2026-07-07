use core::num::NonZeroU64;
use std::{collections::HashMap, ffi::OsString, path::Path};

use tributary_proto::ScopeId;

use super::{RoutableEvent, Subscription, fan_out};

/// A path's `OsString` components — the located-key form the fs source keys on, and
/// the coordinate `fan_out` covers over.
fn key(path: &str) -> Vec<OsString> {
  Path::new(path)
    .components()
    .map(|c| c.as_os_str().to_os_string())
    .collect()
}

/// Which projection a subscriber received for one raw event — the four move
/// decompositions (design §5) plus the whole delivery for a non-move / Rescan. Carried
/// on the fake `Delivered` so a test can assert *which* projection each covering
/// subscriber got, not merely that it was covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Projection {
  /// The event as-is: a non-move change, a Rescan, or a both-covering Moved.
  Whole,
  /// The synthesized move-out `Removed(from)` (source-only coverage).
  MoveOut,
  /// The synthesized move-in `Created(to)` (destination-only coverage).
  MoveIn,
}

/// A fake delivery: the subscriber it was routed to and the projection it received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Delivered {
  sub: Subscription,
  projection: Projection,
}

/// A minimal stand-in for a raw event: routing reads its endpoint keys and whether it
/// is a `Rescan`. Its delivery records the subscriber and which projection it got, so a
/// test asserts the covered set **and** each move decomposition without touching the
/// private `tributary_fs::Event` constructor. A `Some(from)` makes it a move whose
/// destination is `key`.
struct FakeEvent {
  key: Vec<OsString>,
  from: Option<Vec<OsString>>,
  rescan: bool,
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

  /// A move from `from` to `to` (the destination is `key`).
  fn moved(from: &str, to: &str) -> Self {
    Self {
      key: key(to),
      from: Some(key(from)),
      rescan: false,
    }
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

  fn deliver(&self, sub: Subscription) -> Delivered {
    Delivered {
      sub,
      projection: Projection::Whole,
    }
  }

  fn deliver_move_out(&self, sub: Subscription) -> Delivered {
    Delivered {
      sub,
      projection: Projection::MoveOut,
    }
  }

  fn deliver_move_in(&self, sub: Subscription) -> Delivered {
    Delivered {
      sub,
      projection: Projection::MoveIn,
    }
  }
}

/// A test root's subscriber list plus a side table of each subscriber's key — the two
/// inputs `fan_out` needs (the matched root's subscribers and the key resolver).
struct Fixture {
  subscribers: Vec<Subscription>,
  keys: HashMap<Subscription, Vec<OsString>>,
}

impl Fixture {
  /// A root whose subscribers are the given `(id, key path)` pairs, in that
  /// (registration) order. The root path itself is immaterial to `fan_out` (it keys on
  /// the subscribers and their own keys), so only the subscribers are recorded.
  fn new(_root_path: &str, subscribers: &[(u64, &str)]) -> Self {
    let mut subs = Vec::new();
    let mut keys = HashMap::new();
    for &(id, path) in subscribers {
      let sub = Subscription::new(ScopeId::new(NonZeroU64::new(id).expect("nonzero id")));
      subs.push(sub);
      keys.insert(sub, key(path));
    }
    Self {
      subscribers: subs,
      keys,
    }
  }

  fn sub(&self, id: u64) -> Subscription {
    Subscription::new(ScopeId::new(NonZeroU64::new(id).expect("nonzero id")))
  }

  /// The full deliveries `event` fans out to (subscriber + projection), every
  /// subscriber's gate admitting — the move-decomposition assertions read this.
  fn route_full(&self, event: &FakeEvent) -> Vec<Delivered> {
    fan_out(
      event,
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
      event,
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

#[test]
fn rescan_reaches_all_subscribers() {
  // Root /a carries /a and the narrower /a/b/deep.
  let fx = Fixture::new("/a", &[(1, "/a"), (2, "/a/b/deep")]);

  // A non-Rescan at /a/x reaches only /a (coverage narrows out /a/b/deep).
  assert_eq!(
    fx.route(&FakeEvent::change("/a/x")),
    vec![fx.sub(1)],
    "a plain event honors coverage narrowing"
  );

  // A Rescan — even one located at /a/x, which /a/b/deep does not cover — reaches
  // EVERY subscriber of the root: coverage loss is never narrowed away.
  assert_eq!(
    fx.route(&FakeEvent::rescan("/a/x")),
    vec![fx.sub(1), fx.sub(2)],
    "a Rescan bypasses coverage and reaches all subscribers"
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
  // Root /a carries /a and /a/b. A Rescan must reach BOTH even when every filter
  // rejects — coverage loss is never filtered away (§7/§8). A filter that would reject
  // everything (and must never even be consulted for a Rescan) proves the bypass.
  let fx = Fixture::new("/a", &[(1, "/a"), (2, "/a/b")]);
  let admitted = fx.route_filtered(&FakeEvent::rescan("/a/x"), |_, _| {
    panic!("the filter must not be consulted for a Rescan");
  });
  assert_eq!(
    admitted,
    vec![fx.sub(1), fx.sub(2)],
    "a Rescan bypasses the filter and reaches every subscriber"
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
