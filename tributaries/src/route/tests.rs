use core::num::NonZeroU64;
use std::{
  collections::HashMap,
  path::{Path, PathBuf},
};

use tributary_proto::{Interest, ScopeId};

use super::{RootEntry, RoutableEvent, Subscription, fan_out};

/// A minimal stand-in for a raw event: routing reads only its path and whether it
/// is a `Rescan`. Its delivery is just the `Subscription` it was routed to, so a
/// test asserts on the *set of covered subscribers* without touching the private
/// `tributary_fs::Event` constructor.
struct FakeEvent {
  path: PathBuf,
  rescan: bool,
}

impl FakeEvent {
  fn change(path: &str) -> Self {
    Self {
      path: PathBuf::from(path),
      rescan: false,
    }
  }

  fn rescan(path: &str) -> Self {
    Self {
      path: PathBuf::from(path),
      rescan: true,
    }
  }
}

impl RoutableEvent for FakeEvent {
  type Delivered = Subscription;

  fn path(&self) -> &Path {
    self.path.as_path()
  }

  fn is_rescan(&self) -> bool {
    self.rescan
  }

  fn deliver(&self, sub: Subscription) -> Subscription {
    sub
  }
}

/// A test root plus a side table of each subscriber's canonical path — the two
/// inputs `fan_out` needs (the matched entry and the path resolver).
struct Fixture {
  entry: RootEntry,
  paths: HashMap<Subscription, PathBuf>,
}

impl Fixture {
  /// A root at `root_path` whose subscribers are the given `(id, canonical path)`
  /// pairs, in that (registration) order.
  fn new(root_path: &str, subscribers: &[(u64, &str)]) -> Self {
    let mut subs = Vec::new();
    let mut paths = HashMap::new();
    for &(id, path) in subscribers {
      let sub = Subscription::new(ScopeId::new(NonZeroU64::new(id).expect("nonzero id")));
      subs.push(sub);
      paths.insert(sub, PathBuf::from(path));
    }
    Self {
      entry: RootEntry {
        path: PathBuf::from(root_path),
        interest: Interest::all(),
        subscribers: subs,
      },
      paths,
    }
  }

  fn sub(&self, id: u64) -> Subscription {
    Subscription::new(ScopeId::new(NonZeroU64::new(id).expect("nonzero id")))
  }

  /// The subscribers `event` fans out to, with every subscriber's filter admitting
  /// (so this isolates the coverage/Rescan logic from the filter gate).
  fn route(&self, event: &FakeEvent) -> Vec<Subscription> {
    fan_out(
      event,
      &self.entry,
      |sub| self.paths.get(&sub).map(PathBuf::as_path),
      |_sub, _delivered| true,
    )
  }

  /// The subscribers `event` fans out to, admitting a delivery only when `admits`
  /// returns `true` for its `(subscription, delivered)` — the filter gate under test.
  fn route_filtered(
    &self,
    event: &FakeEvent,
    admits: impl Fn(Subscription, &Subscription) -> bool,
  ) -> Vec<Subscription> {
    fan_out(
      event,
      &self.entry,
      |sub| self.paths.get(&sub).map(PathBuf::as_path),
      admits,
    )
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
