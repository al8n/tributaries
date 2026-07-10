use super::{Snapshot, WatchView};
use crate::{
  interest::Interest,
  subscription::Subscription,
  subsume::{Subsumer, WatchOutcome},
};

/// A tiny generic instantiation (key component `u8`, caller value `u32`, handle `u32`)
/// exercising the view over a non-`OsString` `C` — proof the read plane is
/// key-generic.
type S = Subsumer<u8, u32, u32>;

/// Installs a disjoint root at `key` valued `value` under `handle`, returning the
/// engine-minted subscription. Drives the same plan → commit the driver does, so the
/// commit republishes into the shared slot every [`WatchView`] reads.
fn install(s: &mut S, handle: u32, key: &[u8], value: u32) -> Subscription {
  let outcome = s.plan_watch(key, value, Interest::all());
  let sub = match &outcome {
    WatchOutcome::Covered { sub, .. }
    | WatchOutcome::Widen { sub, .. }
    | WatchOutcome::Disjoint { sub, .. } => *sub,
  };
  s.commit_watch(&outcome, handle, key);
  sub
}

/// The view is `Clone + Send + Sync` (the concurrent-read contract, design §5).
#[test]
fn view_is_clone_send_sync() {
  fn assert_bounds<T: Clone + Send + Sync>() {}
  assert_bounds::<WatchView<u8, u32, u32>>();
}

/// A committed change is visible on a freshly-loaded snapshot: membership
/// (`is_watched`/`contains`) and attribution (`covering`/`resolve`) reflect the last
/// committed watch-set (design §5).
#[test]
fn view_reflects_committed_watch_set() {
  let mut s = S::new();
  let view = s.view();

  // Empty to start.
  assert!(view.is_empty());
  assert_eq!(view.len(), 0);
  assert!(!view.is_watched(b"a"));
  assert_eq!(view.covering(b"a"), None);

  install(&mut s, 1, b"a", 100);

  // Eventually consistent: after commit + publish, the snapshot the view loads sees it.
  assert!(!view.is_empty());
  assert_eq!(view.len(), 1);
  assert!(view.contains(b"a"), "the exact root is present");
  assert!(view.is_watched(b"a"), "an exact watch is watched");
  assert!(
    view.is_watched(b"ab"),
    "a descendant is covered by the ancestor watch"
  );
  assert!(!view.contains(b"ab"), "…but it is not an exact root");
  assert!(!view.is_watched(b"b"), "a disjoint key is not watched");

  // Attribution: covering / resolve return the owning root's value.
  assert_eq!(view.covering(b"ab").map(Snapshot::into_inner), Some(100));
  assert_eq!(view.resolve(b"a").map(|snap| *snap.get()), Some(100));
  assert_eq!(
    view.covering(b"b"),
    None,
    "an unwatched key resolves to nothing"
  );
}

/// A clone shares the same published slot: a change committed after the clone is made
/// is visible through both handles (design §5).
#[test]
fn a_clone_shares_the_published_slot() {
  let mut s = S::new();
  let view = s.view();
  let clone = view.clone();

  install(&mut s, 1, b"x", 7);

  assert!(
    view.is_watched(b"xy"),
    "the original handle observes the commit"
  );
  assert!(
    clone.is_watched(b"xy"),
    "the clone observes the same commit (shared slot)"
  );
  assert_eq!(clone.covering(b"x").map(Snapshot::into_inner), Some(7));

  // A view taken BEFORE a later commit tracks the live slot (it holds the slot, not a
  // frozen snapshot), so that commit is visible through it too.
  let pre = s.view();
  install(&mut s, 2, b"z", 9);
  assert!(
    pre.is_watched(b"z"),
    "a pre-commit view sees a later commit"
  );
  assert_eq!(pre.len(), 2);
}

/// The view reflects an unwatch: releasing a root's last subscriber republishes an
/// empty watch-set, and the view no longer reports it (design §5).
#[test]
fn view_reflects_unwatch() {
  let mut s = S::new();
  let view = s.view();

  let sub = install(&mut s, 1, b"a", 1);
  assert!(view.contains(b"a"));

  s.plan_unwatch(sub);
  assert!(
    !view.contains(b"a"),
    "the released root is gone from the view"
  );
  assert!(
    !view.is_watched(b"ab"),
    "…and no longer covers its former descendants"
  );
  assert!(view.is_empty());
}

/// Attribution is per-subscription: a covered subscription resolves to its **own** value, not
/// the covering armed root's — and once the root's own watch departs (leaving the armed root
/// broader than any live subscription) attribution still returns the surviving covered sub's
/// value, never the departed root-owner's (design §5, longest-live-subscription attribution).
///
/// Regression: the `Covered` commit path used to discard the covered watch's value and
/// `covering`/`resolve` read the covering root's stored value, gated only by live coverage. So
/// `watch(/a)=A` then `watch(/a/b)=B` (covered), then `unwatch(/a)` left `/a/b` live yet
/// `resolve(/a/b/file)` returned the departed root `/a`'s stale A — misattributing live events
/// across ownership boundaries. Fail-on-old (resolve on the root plane): returns 100 → FAILS.
#[test]
fn covered_sub_resolves_to_its_own_value_not_the_departed_root() {
  let mut s = S::new();
  let view = s.view();

  // watch /a = 100 [disjoint root, handle 1]; watch /a/b = 200 [Covered by /a's root, handle 1].
  let a = install(&mut s, 1, b"a", 100);
  let _b = install(&mut s, 1, b"ab", 200);

  // While both live: attribution is the LONGEST live subscription's value — /a/b/x → B(200) (the
  // covered `/a/b` sub, not the covering `/a` root), and /a/x → A(100) (only `/a` covers it).
  assert_eq!(
    view.resolve(b"abx").map(Snapshot::into_inner),
    Some(200),
    "a covered key resolves to the covered subscription's OWN value (longest live sub)"
  );
  assert_eq!(
    view.resolve(b"ax").map(Snapshot::into_inner),
    Some(100),
    "a key only the broader root covers resolves to the root subscription's value"
  );

  // Unwatch /a's own watch: the armed root /a lives on for /a/b, now broader than any live sub.
  s.plan_unwatch(a);

  assert_eq!(
    view.resolve(b"abx").map(Snapshot::into_inner),
    Some(200),
    "/a/b/x still resolves to the surviving covered sub's value (200), NOT the departed root's \
     stale 100"
  );
  assert_eq!(
    view.resolve(b"ax"),
    None,
    "/a/x is no longer covered by any live subscription (only /a/b is live) → nothing"
  );
}
