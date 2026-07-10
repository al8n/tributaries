use std::{
  collections::{BTreeSet, HashMap, HashSet},
  ffi::OsString,
  path::{Path, PathBuf},
  vec::Vec,
};

use proptest::prelude::*;
use tributary_proto::Interest;

use super::{Subscription, Subsumer, UnwatchOutcome, WatchOutcome};

/// The subsumer under test: fs key component `OsString`, no per-watch value, `u32`
/// handles (the trivial stand-in for the real `tributary-fs` handle).
type S = Subsumer<OsString, (), u32>;

/// A path's `OsString` components — the key form the fs source uses.
fn key(path: &str) -> Vec<OsString> {
  key_of(Path::new(path))
}

/// The `OsString` components of a path.
fn key_of(path: &Path) -> Vec<OsString> {
  path
    .components()
    .map(|c| c.as_os_str().to_os_string())
    .collect()
}

/// A monotonic minter of `u32` fs-root test handles — stands in for the real
/// `tributary-fs` handle the driver obtains by arming a kernel watch.
#[derive(Default)]
struct Handles {
  next: u32,
}

impl Handles {
  fn mint(&mut self) -> u32 {
    self.next += 1;
    self.next
  }
}

/// A test-side driver mirroring what the real driver does: plan the watch, mint a fresh
/// handle for a new/widened root (reuse the existing one when covered), then commit.
/// Returns the committed root handle plus the engine-minted subscription. The tests use
/// a fs-canonical key identical to the planned one (no TOCTOU), so the committed key is
/// the planned one itself.
fn watch(s: &mut S, handles: &mut Handles, path: &str, interest: Interest) -> (u32, Subscription) {
  let k = key(path);
  let outcome = s.plan_watch(&k, (), interest);
  let (fs_root, sub) = match &outcome {
    WatchOutcome::Covered { fs_root, sub, .. } => (*fs_root, *sub),
    WatchOutcome::Widen { sub, .. } | WatchOutcome::Disjoint { sub, .. } => (handles.mint(), *sub),
  };
  s.commit_watch(&outcome, fs_root, &k);
  (fs_root, sub)
}

/// The keys of every live root, as a set.
fn root_keys(s: &S) -> BTreeSet<Vec<OsString>> {
  s.roots().map(|(k, _)| k.to_vec()).collect()
}

#[test]
fn disjoint_paths_stay_separate() {
  let mut s = S::new();
  let mut h = Handles::default();

  let (ra, sa) = watch(&mut s, &mut h, "/a", Interest::all());
  let (rb, sb) = watch(&mut s, &mut h, "/b", Interest::all());

  assert_ne!(ra, rb, "unrelated paths get distinct roots");
  assert_ne!(sa, sb, "each watch mints a distinct subscription");
  assert_eq!(root_keys(&s), BTreeSet::from([key("/a"), key("/b")]));
  assert_eq!(s.entry(ra).unwrap().subscribers, vec![sa]);
  assert_eq!(s.entry(rb).unwrap().subscribers, vec![sb]);
  // The side table records each subscription's registration key.
  assert_eq!(s.subscription_key(sa), Some(key("/a").as_slice()));
  assert_eq!(s.subscription_key(sb), Some(key("/b").as_slice()));
}

#[test]
fn descendant_is_covered() {
  let mut s = S::new();
  let mut h = Handles::default();

  let (ra, sa) = watch(&mut s, &mut h, "/a", Interest::all());

  // `/a/b` is already covered by `/a`: no new root, no new kernel watch.
  let outcome = s.plan_watch(&key("/a/b"), (), Interest::all());
  let sb = match &outcome {
    WatchOutcome::Covered {
      fs_root,
      sub,
      outside_cover,
    } => {
      assert_eq!(*fs_root, ra, "covered by the /a root");
      assert!(
        !outside_cover,
        "a Covered newcomer under a full-coverage (never-narrowed) root is not outside_cover"
      );
      *sub
    }
    other => panic!("expected Covered by /a, got {other:?}"),
  };
  s.commit_watch(&outcome, ra, &key("/a/b"));

  assert_eq!(root_keys(&s), BTreeSet::from([key("/a")]));
  assert_eq!(s.entry(ra).unwrap().subscribers, vec![sa, sb]);
  // The covered subscription records its own (narrower) key and its interest.
  assert_eq!(s.subscription_key(sb), Some(key("/a/b").as_slice()));
  assert_eq!(s.subscription_interest(sb), Some(Interest::all()));
}

#[test]
fn ancestor_widens_and_repoints() {
  let mut s = S::new();
  let mut h = Handles::default();

  let (narrow, s_narrow) = watch(&mut s, &mut h, "/a/b", Interest::all());

  // Watching the strict ancestor `/a` subsumes `/a/b`.
  let outcome = s.plan_watch(&key("/a"), (), Interest::all());
  let s_wide = match &outcome {
    WatchOutcome::Widen {
      new_root_key,
      repointed,
      unwatch,
      sub,
    } => {
      assert_eq!(new_root_key, &key("/a"));
      assert_eq!(
        repointed,
        &vec![s_narrow],
        "the /a/b subscriber is re-pointed"
      );
      assert_eq!(unwatch, &vec![narrow], "the old /a/b root is released");
      *sub
    }
    other => panic!("expected Widen, got {other:?}"),
  };
  let wide = h.mint();
  s.commit_watch(&outcome, wide, &key("/a"));

  assert_ne!(wide, narrow);
  assert_eq!(root_keys(&s), BTreeSet::from([key("/a")]));
  // The old narrow root is gone; both subs now ride the wider root.
  assert!(s.entry(narrow).is_none());
  assert_eq!(s.entry(wide).unwrap().subscribers, vec![s_narrow, s_wide]);
  assert_eq!(s.entry(wide).unwrap().key, key("/a"));
}

#[test]
fn unwatch_last_subscriber_empties_root() {
  let mut s = S::new();
  let mut h = Handles::default();

  let (ra, sa) = watch(&mut s, &mut h, "/a", Interest::all());
  let (_covered_root, sb) = watch(&mut s, &mut h, "/a/b", Interest::all());

  // Dropping the covered subscriber leaves the root alive (still one subscriber). Not over-broad:
  // the departing sub's key (/a/b) is narrower than the root (/a), so its departure widens no gap —
  // the root's own /a subscriber still pins it.
  assert!(matches!(
    s.plan_unwatch(sb),
    Some(UnwatchOutcome::Dropped { shrink: None })
  ));
  assert_eq!(s.entry(ra).unwrap().subscribers, vec![sa]);

  // Dropping the last subscriber empties (and removes) the root.
  assert!(matches!(
    s.plan_unwatch(sa),
    Some(UnwatchOutcome::RootEmptied { fs_root, .. }) if fs_root == ra,
  ));
  assert!(s.entry(ra).is_none());
  assert!(root_keys(&s).is_empty());

  // Unknown / already-dropped subscriptions report nothing.
  assert!(s.plan_unwatch(sa).is_none());
}

/// Each subscription records its own interest in the side table (design §4): the root
/// is armed `Interest::all`, so a heterogeneous set of subscriptions on one root each
/// keeps its own gate. A widen re-point preserves each re-pointed sub's interest.
#[test]
fn side_table_records_per_subscription_interest() {
  let mut s = S::new();
  let mut h = Handles::default();

  let created = Interest::new().with_created();
  let removed = Interest::new().with_removed();

  // A disjoint root and a covered sub with a DIFFERENT interest.
  let (_ra, sa) = watch(&mut s, &mut h, "/a", created);
  let (_rb, sb) = watch(&mut s, &mut h, "/a/b", removed);
  assert_eq!(s.subscription_interest(sa), Some(created));
  assert_eq!(s.subscription_interest(sb), Some(removed));

  // Widen the whole tree with /: both /a's subs re-point, each keeping its interest.
  let modified = Interest::new().with_modified();
  let (_root, sroot) = watch(&mut s, &mut h, "/", modified);
  assert_eq!(
    s.subscription_interest(sa),
    Some(created),
    "a re-pointed sub keeps its own interest across a widen"
  );
  assert_eq!(s.subscription_interest(sb), Some(removed));
  assert_eq!(s.subscription_interest(sroot), Some(modified));
  assert_eq!(root_keys(&s), BTreeSet::from([key("/")]));
}

/// The fs-key TOCTOU guard (design §4): committing at a fs-canonical key is safe iff it
/// keeps the planned subsumption — same disjointness, subsuming exactly the planned
/// roots — and unsafe (the driver aborts) when the fs key is now covered by, or
/// overlaps a different set of, existing roots.
#[test]
fn fs_path_preserves_plan_detects_subsumption_divergence() {
  let mut s = S::new();
  let mut h = Handles::default();
  let (_ra, _sa) = watch(&mut s, &mut h, "/a", Interest::all());

  // A disjoint plan (unwatch empty): a fs key still disjoint from /a preserves it…
  assert!(
    s.fs_path_preserves_plan(&key("/b"), &[]),
    "a still-disjoint fs key preserves a Disjoint plan"
  );
  // …but a fs key now COVERED by the existing /a does not (it should have been Covered).
  assert!(
    !s.fs_path_preserves_plan(&key("/a/x"), &[]),
    "a fs key covered by an existing root invalidates a Disjoint plan"
  );

  // A widen plan that drained a specific root: the fs key must subsume exactly it.
  let (rb, _sb) = watch(&mut s, &mut h, "/c/d", Interest::all());
  assert!(
    s.fs_path_preserves_plan(&key("/c"), &[rb]),
    "a fs key subsuming exactly the planned root preserves the Widen plan"
  );
  assert!(
    !s.fs_path_preserves_plan(&key("/c"), &[]),
    "a fs key that now subsumes a root the plan did not drain invalidates it"
  );
}

/// A stale broad root must not make [`WatchView::is_watched`] over-report (regression:
/// unwatch-after-widen / unwatch-a-covering-parent leaves the armed root broader than any
/// live subscription; deriving membership from the root then wrongly reports a key watched
/// that fan-out delivers to nobody, so a dedup caller skips it and silently loses changes).
///
/// `is_watched` must reflect **live-subscription** coverage: true iff some live
/// subscription's own key is an ancestor-or-equal of the queried key — exactly the set
/// fan-out delivers to. Both siblings of the class are exercised, then the self-heal:
/// re-installing the falsely-uncovered key is `Covered` under the still-armed broad root.
#[test]
fn stale_broad_root_does_not_over_report_is_watched() {
  // Sibling 1 — widen then unwatch the widening watch.
  let mut s = S::new();
  let mut h = Handles::default();
  let view = s.view();

  let (_narrow, _s_narrow) = watch(&mut s, &mut h, "/a/b", Interest::all());
  // Widen /a: subsumes /a/b onto a wider root /a; the /a watch's own key equals the root.
  let outcome = s.plan_watch(&key("/a"), (), Interest::all());
  let s_wide = match &outcome {
    WatchOutcome::Widen { sub, .. } => *sub,
    other => panic!("expected Widen, got {other:?}"),
  };
  let wide = h.mint();
  s.commit_watch(&outcome, wide, &key("/a"));
  // Unwatch the widening /a watch: the root /a lives on for /a/b, now broader than it — exactly the
  // over-broad case shrink-in-place reclaims (the set-cover design). The departing key /a equals the root key
  // and no survivor is at /a, so the drop reports a shrink to the /a/b survivor cover.
  match s.plan_unwatch(s_wide) {
    Some(UnwatchOutcome::Dropped {
      shrink: Some((handle, retained)),
    }) => {
      assert_eq!(
        handle, wide,
        "the over-broad wide root /a is reported for shrink"
      );
      assert_eq!(
        retained,
        vec![key("/a/b")],
        "the retained cover is the /a/b survivor"
      );
    }
    other => panic!("expected Dropped with a shrink to /a/b, got {other:?}"),
  }

  assert!(
    view.contains(&key("/a")),
    "the armed root /a is deliberately left broad (no re-narrow)"
  );
  assert!(
    view.is_watched(&key("/a/b")),
    "the live /a/b subscription is watched (fan-out delivers under it)"
  );
  assert!(
    !view.is_watched(&key("/a/c")),
    "/a/c is NOT watched: no live subscription covers it, so fan-out delivers it to \
     nobody — is_watched must not over-report the stale broad root",
  );
  assert!(
    view.resolve(&key("/a/c")).is_none(),
    "attribution follows coverage: /a/c resolves to nothing, not a departed watch"
  );

  // Self-heal: a dedup caller re-installs /a/c. It is Covered under the still-armed /a root
  // (no new arm), and is now truthfully watched.
  let re = s.plan_watch(&key("/a/c"), (), Interest::all());
  assert!(
    matches!(re, WatchOutcome::Covered { .. }),
    "re-installing /a/c is Covered under the still-armed broad root — no re-arm",
  );
  s.commit_watch(&re, wide, &key("/a/c"));
  assert!(
    view.is_watched(&key("/a/c")),
    "after re-install /a/c is watched again (self-healing, no silent loss)"
  );

  // Sibling 2 — a Covered watch then unwatch of the root's OWN watch (no widen involved).
  let mut s = S::new();
  let mut h = Handles::default();
  let view = s.view();

  let (rx, s_x) = watch(&mut s, &mut h, "/x", Interest::all());
  let (_covered, _s_xy) = watch(&mut s, &mut h, "/x/y", Interest::all());
  assert_eq!(_covered, rx, "/x/y is covered by the /x root (no new arm)");
  // Unwatch /x's own watch: the root /x lives on for /x/y, now broader than it — over-broad, so the
  // drop reports a shrink to the /x/y survivor cover.
  match s.plan_unwatch(s_x) {
    Some(UnwatchOutcome::Dropped {
      shrink: Some((handle, retained)),
    }) => {
      assert_eq!(
        handle, rx,
        "the over-broad wide root /x is reported for shrink"
      );
      assert_eq!(
        retained,
        vec![key("/x/y")],
        "the retained cover is the /x/y survivor"
      );
    }
    other => panic!("expected Dropped with a shrink to /x/y, got {other:?}"),
  }
  assert!(
    view.is_watched(&key("/x/y")),
    "the live /x/y subscription is still watched"
  );
  assert!(
    !view.is_watched(&key("/x/z")),
    "/x/z is NOT watched: only /x/y is live, and it does not cover /x/z (same class)",
  );
}

/// set-cover shrink-in-place DETECTION (design §5): when the subscription whose key equalled the armed
/// root's own key departs and every survivor sits under a NARROWER key, the drop reports the root
/// OVER-BROAD plus the retained cover — the survivor antichain the source may shrink coverage down to
/// (no gap, no re-crawl). Here /a widened over disjoint /a/b and /a/c; unwatching /a leaves the wide
/// root serving only /a/b and /a/c, so it shrinks to exactly that antichain.
#[test]
fn over_broad_drop_reports_survivor_antichain() {
  let mut s = S::new();
  let mut h = Handles::default();

  let (_rb, _s_b) = watch(&mut s, &mut h, "/a/b", Interest::all());
  let (_rc, _s_c) = watch(&mut s, &mut h, "/a/c", Interest::all());
  // Widen /a over both disjoint roots: the wide root /a now serves /a/b, /a/c, and its own /a watch.
  let outcome = s.plan_watch(&key("/a"), (), Interest::all());
  let s_a = match &outcome {
    WatchOutcome::Widen { sub, .. } => *sub,
    other => panic!("expected Widen, got {other:?}"),
  };
  let wide = h.mint();
  s.commit_watch(&outcome, wide, &key("/a"));

  // Unwatch the widening /a: departing key /a == root key /a and no survivor is at /a, so the root is
  // over-broad and shrinks to the {/a/b, /a/c} survivor cover.
  match s.plan_unwatch(s_a) {
    Some(UnwatchOutcome::Dropped {
      shrink: Some((handle, retained)),
    }) => {
      assert_eq!(
        handle, wide,
        "the over-broad wide root is reported for shrink"
      );
      assert_eq!(
        retained,
        vec![key("/a/b"), key("/a/c")],
        "the retained cover is the two survivor subtrees (a minimal antichain)"
      );
    }
    other => panic!("expected an over-broad Dropped, got {other:?}"),
  }
}

/// Not over-broad when a SURVIVOR's key still equals the root key (design §5): two subscriptions at
/// the SAME key /a share one root; dropping one leaves the other pinning /a legitimately, so no shrink
/// is reported — the root is exactly as wide as a live subscriber needs.
#[test]
fn drop_with_survivor_at_root_key_is_not_over_broad() {
  let mut s = S::new();
  let mut h = Handles::default();

  let (ra, s_a1) = watch(&mut s, &mut h, "/a", Interest::all());
  let (ra2, _s_a2) = watch(&mut s, &mut h, "/a", Interest::all()); // Covered: same key, one root.
  assert_eq!(ra2, ra, "the second /a shares the one root");

  assert!(
    matches!(
      s.plan_unwatch(s_a1),
      Some(UnwatchOutcome::Dropped { shrink: None })
    ),
    "a survivor still at the root key keeps it legitimately watched — not over-broad"
  );
}

/// Antichain MINIMALITY when survivors nest (the set-cover design): survivors at /a/b and /a/b/c reduce to the
/// single prefix /a/b — /a/b/c is already covered by it — so the retained cover is the minimal
/// prefix-free set, never the raw survivor keys.
#[test]
fn over_broad_antichain_collapses_nested_survivors() {
  let mut s = S::new();
  let mut h = Handles::default();

  let (_rb, _s_b) = watch(&mut s, &mut h, "/a/b", Interest::all());
  // /a/b/c is Covered by the /a/b root (no new root); both ride /a/b.
  let (_rbc, _s_bc) = watch(&mut s, &mut h, "/a/b/c", Interest::all());
  // Widen /a: subsumes the /a/b root with BOTH its subscribers → wide /a serves /a/b, /a/b/c, /a.
  let outcome = s.plan_watch(&key("/a"), (), Interest::all());
  let s_a = match &outcome {
    WatchOutcome::Widen { sub, .. } => *sub,
    other => panic!("expected Widen, got {other:?}"),
  };
  let wide = h.mint();
  s.commit_watch(&outcome, wide, &key("/a"));

  match s.plan_unwatch(s_a) {
    Some(UnwatchOutcome::Dropped {
      shrink: Some((handle, retained)),
    }) => {
      assert_eq!(handle, wide, "the over-broad wide root is reported");
      assert_eq!(
        retained,
        vec![key("/a/b")],
        "nested survivors /a/b and /a/b/c collapse to the single cover /a/b"
      );
    }
    other => panic!("expected an over-broad Dropped, got {other:?}"),
  }
}

/// set-cover F2: a non-root unwatch that shrinks an ALREADY-NARROWED cover reports a
/// re-prune. A wide /a narrowed to {/a/b, /a/c}: dropping the non-root /a/c survivor (departing key
/// /a/c != root key /a) leaves the cover reclaimable to {/a/b} — so `detect_shrink` reports a shrink
/// to the shrunken antichain. The old detection, gated on the departing key EQUALLING the root key,
/// missed this and left /a/c's grown coverage pinned forever.
#[test]
fn narrowed_cover_non_root_unwatch_reprunes() {
  let mut s = S::new();
  let mut h = Handles::default();

  let (_rb, _s_b) = watch(&mut s, &mut h, "/a/b", Interest::all());
  let (_rc, s_c) = watch(&mut s, &mut h, "/a/c", Interest::all());
  // Widen /a over /a/b and /a/c, then drop /a, leaving the wide root serving only /a/b and /a/c.
  let outcome = s.plan_watch(&key("/a"), (), Interest::all());
  let s_a = match &outcome {
    WatchOutcome::Widen { sub, .. } => *sub,
    other => panic!("expected Widen, got {other:?}"),
  };
  let wide = h.mint();
  s.commit_watch(&outcome, wide, &key("/a"));
  s.plan_unwatch(s_a).expect("unwatch the widening /a");
  // Record the source's narrowed coverage exactly as the driver would (narrow-on-prune-issue).
  s.set_retained_cover(wide, Some(vec![key("/a/b"), key("/a/c")]));

  // Drop the NON-ROOT /a/c survivor: the survivor antichain {/a/b} is STRICTLY narrower than the
  // recorded {/a/b, /a/c}, so the drop reports a re-prune to {/a/b}.
  match s.plan_unwatch(s_c) {
    Some(UnwatchOutcome::Dropped {
      shrink: Some((handle, retained)),
    }) => {
      assert_eq!(
        handle, wide,
        "the narrowed wide root is reported for the re-prune"
      );
      assert_eq!(
        retained,
        vec![key("/a/b")],
        "the re-prune carries the shrunken survivor antichain"
      );
    }
    other => panic!("expected a re-prune Dropped, got {other:?}"),
  }
}

/// set-cover F2: a non-root unwatch that leaves the survivor antichain EQUAL to the recorded cover
/// reports NO re-prune — dropping a survivor already covered by a shallower sibling reclaims nothing.
/// A wide /a narrowed to {/a/b, /a/c} with an extra /a/b/deep sub under /a/b: dropping /a/b/deep
/// leaves the antichain {/a/b, /a/c} unchanged, so no re-prune fires.
#[test]
fn equal_survivor_antichain_reports_no_reprune() {
  let mut s = S::new();
  let mut h = Handles::default();

  let (_rb, _s_b) = watch(&mut s, &mut h, "/a/b", Interest::all());
  let (_rdeep, s_deep) = watch(&mut s, &mut h, "/a/b/deep", Interest::all()); // Covered by /a/b.
  let (_rc, _s_c) = watch(&mut s, &mut h, "/a/c", Interest::all());
  let outcome = s.plan_watch(&key("/a"), (), Interest::all());
  let s_a = match &outcome {
    WatchOutcome::Widen { sub, .. } => *sub,
    other => panic!("expected Widen, got {other:?}"),
  };
  let wide = h.mint();
  s.commit_watch(&outcome, wide, &key("/a"));
  s.plan_unwatch(s_a).expect("unwatch the widening /a");
  // The narrowed cover the driver would record: the minimal antichain {/a/b, /a/c}.
  s.set_retained_cover(wide, Some(vec![key("/a/b"), key("/a/c")]));

  // Drop /a/b/deep — already covered by the shallower /a/b survivor — so the survivor antichain is
  // unchanged: {/a/b, /a/c} still, EQUAL to the recorded cover → no re-prune.
  assert!(
    matches!(
      s.plan_unwatch(s_deep),
      Some(UnwatchOutcome::Dropped { shrink: None })
    ),
    "a survivor covered by a shallower sibling reclaims nothing — no re-prune"
  );
}

/// set-cover freshness re-issue: `retained_cover_for` recomputes a root's retained cover from
/// its CURRENT live membership — the query the driver re-issues on every Covered commit to keep a
/// queued shrink fresh. A subscriber still pinning the root at its own key reports `None` (the driver
/// re-issues the cancel-equivalent for it); once that pinning subscriber departs, the over-broad root
/// reports the survivor antichain; an unknown handle reports `None`.
#[test]
fn retained_cover_for_tracks_current_membership() {
  let mut s = S::new();
  let mut h = Handles::default();

  let (_rb, _s_b) = watch(&mut s, &mut h, "/a/b", Interest::all());
  let (_rc, _s_c) = watch(&mut s, &mut h, "/a/c", Interest::all());
  // Widen /a over both disjoint roots: the wide root serves /a/b, /a/c, and its own /a watch.
  let outcome = s.plan_watch(&key("/a"), (), Interest::all());
  let s_a = match &outcome {
    WatchOutcome::Widen { sub, .. } => *sub,
    other => panic!("expected Widen, got {other:?}"),
  };
  let wide = h.mint();
  s.commit_watch(&outcome, wide, &key("/a"));

  // The /a subscriber still pins the wide root at its own key → not over-broad → None.
  assert_eq!(
    s.retained_cover_for(wide),
    None,
    "a subscriber at the root key pins it — not over-broad, so the re-issue is the cancel-equivalent"
  );

  // Drop the /a subscriber: the wide root now serves only the narrower /a/b, /a/c → over-broad.
  s.plan_unwatch(s_a).expect("unwatch the widening /a");
  assert_eq!(
    s.retained_cover_for(wide),
    Some(vec![key("/a/b"), key("/a/c")]),
    "the recomputed cover is the CURRENT survivor antichain"
  );

  // An unknown handle names no live root → nothing to reclaim.
  assert_eq!(
    s.retained_cover_for(9999),
    None,
    "an unknown handle has no cover"
  );
}

/// `retained_cover_for` collapses nested survivors to the minimal antichain, exactly as the unwatch
/// detection does: /a/b and its covered /a/b/c reduce to the single cover /a/b.
#[test]
fn retained_cover_for_collapses_nested_survivors() {
  let mut s = S::new();
  let mut h = Handles::default();

  let (_rb, _s_b) = watch(&mut s, &mut h, "/a/b", Interest::all());
  let (_rbc, _s_bc) = watch(&mut s, &mut h, "/a/b/c", Interest::all()); // Covered by /a/b.
  let outcome = s.plan_watch(&key("/a"), (), Interest::all());
  let s_a = match &outcome {
    WatchOutcome::Widen { sub, .. } => *sub,
    other => panic!("expected Widen, got {other:?}"),
  };
  let wide = h.mint();
  s.commit_watch(&outcome, wide, &key("/a"));
  s.plan_unwatch(s_a).expect("unwatch the widening /a");

  assert_eq!(
    s.retained_cover_for(wide),
    Some(vec![key("/a/b")]),
    "nested survivors /a/b and /a/b/c collapse to the single cover /a/b"
  );
}

/// The over-broad-join core: a Covered watch under an already-over-broad root JOINS the recomputed cover, so the
/// driver's re-issue reflects the newcomer — never a stale pre-newcomer snapshot. Over-broad /a serves
/// only /a/b; watching /a/c (Covered, sharing the wide handle) grows the cover to {/a/b, /a/c}.
#[test]
fn retained_cover_for_includes_a_newly_covered_subscriber() {
  let mut s = S::new();
  let mut h = Handles::default();

  // Make /a over-broad, serving only /a/b: widen /a over /a/b, then drop the /a sub.
  let (_rb, _s_b) = watch(&mut s, &mut h, "/a/b", Interest::all());
  let outcome = s.plan_watch(&key("/a"), (), Interest::all());
  let s_a = match &outcome {
    WatchOutcome::Widen { sub, .. } => *sub,
    other => panic!("expected Widen, got {other:?}"),
  };
  let wide = h.mint();
  s.commit_watch(&outcome, wide, &key("/a"));
  s.plan_unwatch(s_a).expect("unwatch the widening /a");
  assert_eq!(
    s.retained_cover_for(wide),
    Some(vec![key("/a/b")]),
    "before the covered newcomer, the cover is just the /a/b survivor"
  );

  // Watch /a/c: Covered under the still-live wide /a (arms nothing), sharing the wide handle.
  let (rc, _s_c) = watch(&mut s, &mut h, "/a/c", Interest::all());
  assert_eq!(rc, wide, "the covered /a/c rides the wide root");
  assert_eq!(
    s.retained_cover_for(wide),
    Some(vec![key("/a/b"), key("/a/c")]),
    "the covered /a/c JOINS the recomputed cover — the fresh membership, not the stale {{/a/b}}"
  );
}

/// set-cover retained-cover bookkeeping: [`set_retained_cover`](S::set_retained_cover)
/// records the cover last issued to the source and [`retained_cover_of`](S::retained_cover_of) reads
/// it back. A fresh root is `None` (full coverage), a narrowing round-trips, a reset to `None` restores
/// full, and an unknown handle is `None`.
#[test]
fn retained_cover_bookkeeping_round_trips() {
  let mut s = S::new();
  let mut h = Handles::default();

  let (ra, _sa) = watch(&mut s, &mut h, "/a", Interest::all());
  assert_eq!(
    s.retained_cover_of(ra),
    None,
    "a fresh root is never narrowed — full coverage"
  );

  s.set_retained_cover(ra, Some(vec![key("/a/b"), key("/a/c")]));
  assert_eq!(
    s.retained_cover_of(ra),
    Some(vec![key("/a/b"), key("/a/c")]),
    "the issued cover round-trips through the bookkeeping"
  );

  s.set_retained_cover(ra, None);
  assert_eq!(
    s.retained_cover_of(ra),
    None,
    "resetting to None restores the full-coverage bookkeeping (the cancel-equivalent)"
  );

  assert_eq!(
    s.retained_cover_of(9999),
    None,
    "an unknown handle has no recorded cover"
  );
}

/// set-cover `outside_cover` classification: [`plan_watch`](S::plan_watch) flags a `Covered`
/// newcomer that falls OUTSIDE the covering root's recorded retained cover — the region an applied
/// set_cover pruned — and does NOT flag one under a full-coverage (`None`) root, one inside a retained
/// prefix, or one whose key equals a retained prefix. Each probe plan is aborted so it leaks no pending
/// reservation.
#[test]
fn plan_watch_flags_covered_outside_the_narrowed_cover() {
  let mut s = S::new();
  let mut h = Handles::default();

  let (ra, _sa) = watch(&mut s, &mut h, "/a", Interest::all());

  // Full coverage (None): no Covered newcomer is outside.
  let outcome = s.plan_watch(&key("/a/x"), (), Interest::all());
  match &outcome {
    WatchOutcome::Covered { outside_cover, .. } => assert!(
      !outside_cover,
      "under a full-coverage (never-narrowed) root no newcomer is outside_cover"
    ),
    other => panic!("expected Covered, got {other:?}"),
  }
  s.abort_watch(&outcome);

  // Narrow the recorded cover to {/a/b}: the source pruned everything else under /a.
  s.set_retained_cover(ra, Some(vec![key("/a/b")]));

  // A newcomer OUTSIDE {/a/b} → flagged.
  let outcome = s.plan_watch(&key("/a/c"), (), Interest::all());
  match &outcome {
    WatchOutcome::Covered {
      fs_root,
      outside_cover,
      ..
    } => {
      assert_eq!(*fs_root, ra, "still Covered by the wide /a root");
      assert!(
        *outside_cover,
        "a newcomer under NONE of the narrowed cover's prefixes is outside_cover"
      );
    }
    other => panic!("expected Covered, got {other:?}"),
  }
  s.abort_watch(&outcome);

  // A newcomer INSIDE the retained prefix /a/b → not flagged.
  let outcome = s.plan_watch(&key("/a/b/deep"), (), Interest::all());
  match &outcome {
    WatchOutcome::Covered { outside_cover, .. } => assert!(
      !outside_cover,
      "a newcomer under a retained prefix is already backed by the source — not outside_cover"
    ),
    other => panic!("expected Covered, got {other:?}"),
  }
  s.abort_watch(&outcome);

  // A newcomer whose key EQUALS a retained prefix → not flagged (an ancestor-or-equal is covered).
  let outcome = s.plan_watch(&key("/a/b"), (), Interest::all());
  match &outcome {
    WatchOutcome::Covered { outside_cover, .. } => assert!(
      !outside_cover,
      "a newcomer exactly at a retained prefix is covered — not outside_cover"
    ),
    other => panic!("expected Covered, got {other:?}"),
  }
  s.abort_watch(&outcome);
}

// ---------------------------------------------------------------------------
// Property tests: invariants over any random watch/unwatch sequence.
// ---------------------------------------------------------------------------

/// Whether `ancestor` is an ancestor of (or equal to) `descendant` in the
/// component-wise key space (the same relation iradix keys on).
fn is_ancestor_or_equal(ancestor: &[OsString], descendant: &[OsString]) -> bool {
  descendant.starts_with(ancestor)
}

/// One scripted operation against the engine. `Unwatch(idx)` drops the live
/// subscription at `idx % live_count` (a stable index into the live set), so the
/// script exercises both draining and re-pointing without knowing minted ids.
#[derive(Debug, Clone)]
enum Op {
  Watch(PathBuf),
  Unwatch(usize),
}

/// A pool of short, overlapping absolute paths drawn from a tiny component alphabet, so
/// watches genuinely nest and subsume rather than staying disjoint.
fn path_strategy() -> impl Strategy<Value = PathBuf> {
  proptest::collection::vec(prop_oneof!["a", "b", "c"], 1..=4)
    .prop_map(|parts| PathBuf::from(format!("/{}", parts.join("/"))))
}

fn op_strategy() -> impl Strategy<Value = Op> {
  prop_oneof![
    path_strategy().prop_map(Op::Watch),
    any::<usize>().prop_map(Op::Unwatch),
  ]
}

/// Replays `ops` against a fresh engine, returning it and the live
/// `Subscription -> registration path` model the script implies. Both sides agree on
/// liveness: the model records exactly the subscription each `watch` minted and removes
/// exactly the one each `unwatch` dropped.
fn run(ops: &[Op]) -> (S, HashMap<Subscription, PathBuf>) {
  let mut s = S::new();
  let mut h = Handles::default();
  // Insertion-ordered so an `Unwatch(idx)` selection is deterministic.
  let mut live: Vec<(Subscription, PathBuf)> = Vec::new();

  for op in ops {
    match op {
      Op::Watch(path) => {
        let (_root, sub) = watch(&mut s, &mut h, &path.to_string_lossy(), Interest::all());
        live.push((sub, path.clone()));
      }
      Op::Unwatch(idx) => {
        if live.is_empty() {
          continue;
        }
        let (sub, _) = live.remove(idx % live.len());
        assert!(
          s.plan_unwatch(sub).is_some(),
          "a live subscription must be dropped",
        );
      }
    }
  }
  (s, live.into_iter().collect())
}

/// Case budget: a full sweep natively, a handful under miri. Each miri case runs the
/// interpreter over a 40-op model, and the full count exhausts the 32-bit address
/// space on i686 (miri recycles addresses too slowly for that much churn).
const CASES: u32 = if cfg!(miri) { 4 } else { 256 };

proptest! {
  // No on-disk regression file: it would resolve the current directory (a `getcwd`
  // syscall) at setup, which trips Miri's isolation on an otherwise sans-I/O suite.
  #![proptest_config(ProptestConfig { cases: CASES, failure_persistence: None, ..ProptestConfig::default() })]

  /// (a) The live roots are pairwise disjoint (no root is an ancestor of another).
  #[test]
  fn roots_are_pairwise_disjoint(ops in proptest::collection::vec(op_strategy(), 0..40)) {
    let (s, _live) = run(&ops);
    let roots: Vec<Vec<OsString>> = s.roots().map(|(k, _)| k.to_vec()).collect();
    for (i, a) in roots.iter().enumerate() {
      for (j, b) in roots.iter().enumerate() {
        if i != j {
          prop_assert!(
            !is_ancestor_or_equal(a, b),
            "roots {a:?} and {b:?} overlap",
          );
        }
      }
    }
  }

  /// (b) Every live subscription is covered by exactly one root that is an
  /// ancestor-or-equal of its key. The key is read from the engine's own side table
  /// (via `subscription_key`), so this also checks the side table stays consistent with
  /// the script across widening re-points.
  #[test]
  fn every_sub_covered_by_exactly_one_root(ops in proptest::collection::vec(op_strategy(), 0..40)) {
    let (s, live) = run(&ops);
    let roots: Vec<Vec<OsString>> = s.roots().map(|(k, _)| k.to_vec()).collect();
    for (sub, expected_path) in &live {
      let recorded = s
        .subscription_key(*sub)
        .expect("a live subscription has a recorded key");
      let expected = key_of(expected_path);
      prop_assert_eq!(recorded, expected.as_slice(), "side-table key drifted");
      let covering = roots.iter().filter(|r| is_ancestor_or_equal(r, recorded)).count();
      prop_assert_eq!(
        covering, 1,
        "sub {} at {:?} is covered by {} roots, want exactly 1",
        sub, recorded, covering,
      );
    }
  }

  /// (c) No live root has an empty subscriber set, and every indexed root has an entry
  /// (the index and the reverse index stay in lockstep).
  #[test]
  fn no_zero_subscriber_root(ops in proptest::collection::vec(op_strategy(), 0..40)) {
    let (s, _live) = run(&ops);
    for (_key, handle) in s.roots() {
      let entry = s.entry(handle).expect("indexed root has an entry");
      prop_assert!(!entry.subscribers.is_empty(), "root {handle} has no subscribers");
    }
  }

  /// The whole live subscription set is exactly what the script implies — nothing is
  /// dropped or duplicated across widening re-points.
  #[test]
  fn live_sub_set_matches_model(ops in proptest::collection::vec(op_strategy(), 0..40)) {
    let (s, live) = run(&ops);
    let engine_subs: HashSet<Subscription> = s
      .roots()
      .flat_map(|(_k, h)| s.entry(h).unwrap().subscribers.clone())
      .collect();
    let model_subs: HashSet<Subscription> = live.keys().copied().collect();
    prop_assert_eq!(engine_subs, model_subs);
  }
}

/// retiring an N-cohort root is LINEAR in value clones — the batched
/// `force_remove_root` clones each same-key cover entry once and retains through it
/// once, instead of the per-subscriber clone-of-the-shrinking-cohort that cost
/// O(N squared) deep clones. Fail-on-old: 256 subscribers cost ~32k clones quadratic;
/// the assert allows a generous linear budget only.
#[test]
fn cohort_retirement_clones_values_linearly() {
  use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  };

  #[derive(Debug)]
  struct CountedValue(Arc<AtomicUsize>);
  impl Clone for CountedValue {
    fn clone(&self) -> Self {
      self.0.fetch_add(1, Ordering::Relaxed);
      Self(Arc::clone(&self.0))
    }
  }

  const COHORT: usize = 256;
  let clones = Arc::new(AtomicUsize::new(0));
  let mut s: Subsumer<OsString, CountedValue, u32> = Subsumer::new();

  // Build the same-key cohort: the first watch arms the root, the rest subsume as
  // Covered onto it.
  let k = key("/cohort");
  let mut root_handle = 0u32;
  for i in 0..COHORT {
    let outcome = s.plan_watch(&k, CountedValue(Arc::clone(&clones)), Interest::all());
    let fs_root = match &outcome {
      WatchOutcome::Covered { fs_root, .. } => *fs_root,
      WatchOutcome::Widen { .. } | WatchOutcome::Disjoint { .. } => {
        root_handle = 1;
        1
      }
    };
    let _ = i;
    s.commit_watch(&outcome, fs_root, &k);
  }

  // Count ONLY the retirement's clones.
  clones.store(0, Ordering::Relaxed);
  let retired = s.force_remove_root(root_handle);
  assert_eq!(retired.len(), COHORT, "the whole cohort retired");
  let spent = clones.load(Ordering::Relaxed);
  assert!(
    spent <= COHORT * 2,
    "cohort retirement is linear in value clones (spent {spent} for {COHORT} — \
     the old per-subscriber path spent ~{})",
    COHORT * COHORT / 2
  );
}
