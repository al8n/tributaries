use std::{
  ffi::OsString,
  path::{Path, PathBuf},
};

use super::{Fid, FidMap, SeedEntry};

/// A FID with `fsid = [tag; 8]` and a distinct handle byte, so two FIDs differ
/// in their handle whenever their `handle` byte differs.
fn fid(tag: u8) -> Fid {
  Fid::new([tag; 8], Box::from(&[tag, tag, tag][..]))
}

/// The SAME handle bytes as `fid(tag)` but a DIFFERENT fsid — the btrfs shape,
/// where the kernel's per-superblock event fsid diverges from the
/// per-subvolume `statfs` fsid the seed captured. Admission must key on the
/// handle alone, so this resolves identically to `fid(tag)`.
fn fid_other_fsid(tag: u8) -> Fid {
  Fid::new([0xEE; 8], Box::from(&[tag, tag, tag][..]))
}

/// A FID sharing the root's fsid but a wholly different handle — same
/// superblock, different object.
fn fid_same_sb(handle: u8) -> Fid {
  Fid::new([1; 8], Box::from(&[handle][..]))
}

/// `/root` (fid 1) with a child `/root/sub` (fid 2) under it.
fn seeded() -> FidMap {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("sub")),
  ]);
  map
}

/// Admission is pure directory membership keyed on the HANDLE: a seeded handle
/// resolves to its path; an unknown handle (provably outside the root) drops.
#[test]
fn admit_is_membership_not_fsid() {
  let mut map = seeded();
  assert_eq!(map.admit(&fid(1)), Some(PathBuf::from("/root")));
  assert_eq!(map.admit(&fid(2)), Some(PathBuf::from("/root/sub")));
  // Same superblock as the root, different object: NOT admitted. Membership
  // rejects it.
  assert_eq!(map.admit(&fid_same_sb(99)), None);
  // A wholly foreign handle is dropped.
  assert_eq!(map.admit(&fid(42)), None);
}

/// The btrfs regression: the seeded FID's fsid differs from the event FID's
/// fsid, but the handles match — so admission (handle-keyed) MUST resolve. An
/// fsid comparison would have wrongly rejected every in-root event here.
#[test]
fn admit_ignores_fsid_divergence() {
  let mut map = seeded();
  // The event carries the per-superblock fsid, not the seed's per-subvolume
  // one — divergent bytes, identical handle.
  assert_ne!(fid(2).fsid(), fid_other_fsid(2).fsid());
  assert_eq!(fid(2).handle(), fid_other_fsid(2).handle());
  assert_eq!(
    map.admit(&fid_other_fsid(2)),
    Some(PathBuf::from("/root/sub")),
    "a divergent event fsid still admits on a matching handle (btrfs)"
  );
  assert_eq!(
    map.admit(&fid_other_fsid(1)),
    Some(PathBuf::from("/root")),
    "the root admits on its handle regardless of the event fsid"
  );
}

/// Interned ids are sequential, exact, and stable: the same handle always
/// returns the same id, distinct handles never collide, re-interning is
/// idempotent — and interning keys on the handle, so a divergent fsid does not
/// mint a second id for the same object.
#[test]
fn intern_is_sequential_and_stable() {
  let mut map = FidMap::new();
  let a = map.intern(&fid(10));
  let b = map.intern(&fid(20));
  assert_ne!(a, b, "distinct handles get distinct ids");
  assert_eq!(map.intern(&fid(10)), a, "the same handle is stable");
  assert_eq!(map.intern(&fid(20)), b);
  // A third distinct handle advances the counter (sequential, not hashed).
  let c = map.intern(&fid(30));
  assert_ne!(c, a);
  assert_ne!(c, b);
  // The same handle under a different fsid is the SAME object (btrfs): its id
  // is unchanged.
  assert_eq!(
    map.intern(&fid_other_fsid(10)),
    a,
    "a divergent fsid does not fork identity"
  );
}

/// Seeding a directory also interns it, so an admitted directory always has a
/// stable identity that matches a later explicit `intern`.
#[test]
fn seeding_interns_the_directory() {
  let mut map = seeded();
  let root_id = map.intern(&fid(1));
  let sub_id = map.intern(&fid(2));
  assert_ne!(root_id, sub_id);
  assert_eq!(map.intern(&fid(1)), root_id);
  assert_eq!(map.intern(&fid(2)), sub_id);
}

/// `learn` admits a newly-created in-root directory under its parent's path,
/// using the child's TARGET_FID — later events on the child then admit, and
/// its path is resolved through the live parent chain.
#[test]
fn learn_admits_new_child_directory() {
  let mut map = seeded();
  assert_eq!(map.dir_count(), 2);
  let child = fid(3);
  map.learn(&fid(2), b"created", Some(&child));
  assert_eq!(
    map.admit(&child),
    Some(PathBuf::from("/root/sub/created")),
    "the new directory admits under its parent"
  );
  assert_eq!(map.dir_count(), 3);
}

/// `contains` is a pure membership query — no path resolution, no eviction
/// (unlike `admit`): a seeded directory is contained, an unknown one is not, and
/// the query neither resolves nor mutates. This is the move-flavor discriminator
/// (checked on the moved object's own FID, always a directly-stored node), so it
/// must reflect raw storage, not reachability.
#[test]
fn contains_is_raw_membership_without_eviction() {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("a")),
    SeedEntry::child(fid(3), fid(2), OsString::from("child")),
  ]);
  assert!(map.contains(&fid(1)), "the root is contained");
  assert!(map.contains(&fid(2)), "a seeded child is contained");
  assert!(map.contains(&fid(3)), "a seeded grandchild is contained");
  assert!(
    !map.contains(&fid(99)),
    "an unknown handle is not contained"
  );
  // `contains` did not mutate the map — the count is unchanged (no eviction).
  assert_eq!(map.dir_count(), 3, "contains does not evict");
  map.assert_adjacency();

  // `forget` of the parent prunes the WHOLE subtree eagerly (adjacency walk), so
  // the grandchild is gone from storage at once — `contains` reflects that
  // immediately, with no lingering orphan for a later `admit` miss to reap.
  map.forget(&fid(2));
  assert!(!map.contains(&fid(2)), "the forgotten node is gone");
  assert!(
    !map.contains(&fid(3)),
    "the forget pruned the descendant too — no lingering orphan"
  );
  assert_eq!(map.admit(&fid(3)), None, "and it no longer resolves");
  map.assert_adjacency();
}

/// `learn` under an unknown parent is a no-op: a create outside the watched
/// root must not enter the map.
#[test]
fn learn_under_unknown_parent_is_ignored() {
  let mut map = seeded();
  let child = fid(3);
  map.learn(&fid(99), b"created", Some(&child));
  assert_eq!(map.admit(&child), None);
  assert_eq!(map.dir_count(), 2);
}

/// `learn` with no child FID (a create without TARGET_FID) cannot
/// self-maintain and admits nothing — the eventual admission is a reseed's job.
#[test]
fn learn_without_child_fid_is_ignored() {
  let mut map = seeded();
  map.learn(&fid(2), b"created", None);
  assert_eq!(map.dir_count(), 2);
}

/// `learn` rejects non-component names (`.`, `..`, an embedded separator) — a
/// malicious or malformed name never escapes the parent directory.
#[test]
fn learn_rejects_non_component_names() {
  let mut map = seeded();
  map.learn(&fid(2), b"..", Some(&fid(3)));
  map.learn(&fid(2), b"a/b", Some(&fid(4)));
  map.learn(&fid(2), b".", Some(&fid(5)));
  assert_eq!(map.dir_count(), 2, "no non-component name is admitted");
}

/// `forget` drops a directory from BOTH admission and the intern table (delete /
/// rename-out): pruning the id bounds the table at O(live directories). A
/// departed-and-returned directory mints a FRESH identity — the conservative
/// direction (the Monitor reads inequality as a replacement, never a false
/// survivor), and safe because only the SAME handle (the same object) could ever
/// re-mint the old id.
#[test]
fn forget_prunes_admission_and_identity() {
  let mut map = seeded();
  let sub_id = map.intern(&fid(2));
  assert_eq!(map.interned_count(), 2, "root + sub interned");
  map.forget(&fid(2));
  assert_eq!(
    map.admit(&fid(2)),
    None,
    "forgotten directory stops admitting"
  );
  assert_eq!(map.dir_count(), 1);
  assert_eq!(
    map.interned_count(),
    1,
    "the forgotten directory's id is pruned — only the root remains interned"
  );
  assert_ne!(
    map.intern(&fid(2)),
    sub_id,
    "a returned directory mints a new identity, never reuses the departed id"
  );
}

/// An in-root directory rename RE-PARENTS the one node IN PLACE (the real
/// `admit_rename` path calls `learn` only — no `forget`, since the object did not
/// depart), and every descendant's resolved path follows automatically through
/// the parent walk with no per-descendant rewrite. Re-parenting in place must
/// PRESERVE the moved dir's descendants (they move with it) and keep the `children`
/// adjacency consistent under both parents.
#[test]
fn in_root_rename_reparents_the_whole_subtree() {
  let mut map = FidMap::new();
  // /root, /root/a, /root/a/child, plus a second parent /root/b.
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("a")),
    SeedEntry::child(fid(3), fid(2), OsString::from("child")),
    SeedEntry::child(fid(4), fid(1), OsString::from("b")),
  ]);
  assert_eq!(map.admit(&fid(3)), Some(PathBuf::from("/root/a/child")));
  let child_id = map.intern(&fid(3));

  // Rename /root/a → /root/b/a: re-parent `a` under `b` IN PLACE (learn, no
  // forget) — exactly the in-root re-parent `admit_rename` performs.
  map.learn(&fid(4), b"a", Some(&fid(2)));

  // The moved dir AND its pre-seeded child both resolve under the NEW path, and
  // the child kept its identity (it never departed).
  assert_eq!(map.admit(&fid(2)), Some(PathBuf::from("/root/b/a")));
  assert_eq!(
    map.admit(&fid(3)),
    Some(PathBuf::from("/root/b/a/child")),
    "the descendant follows the parent's rename with no rewrite"
  );
  assert_eq!(
    map.intern(&fid(3)),
    child_id,
    "an in-root re-parent preserves the descendant's identity (no fork)"
  );
  map.assert_adjacency();

  // Now forget the re-parented `a`: its child prunes with it, from the NEW
  // location, proving the adjacency followed the re-parent.
  map.forget(&fid(2));
  assert_eq!(
    map.admit(&fid(3)),
    None,
    "the descendant prunes with its re-parented ancestor"
  );
  map.assert_adjacency();
}

/// A directory renamed OUT of the root leaves its descendants un-admitting:
/// the moved dir's node is gone, so a descendant's parent walk breaks before
/// reaching the root and resolves to `None` — no stale in-root path for
/// out-of-root activity.
#[test]
fn move_out_of_root_orphans_the_subtree() {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("a")),
    SeedEntry::child(fid(3), fid(2), OsString::from("child")),
  ]);
  assert_eq!(map.admit(&fid(3)), Some(PathBuf::from("/root/a/child")));

  // Move /root/a to some out-of-root directory (not in the map): only the
  // forget runs (the new parent is not admitted, so no relearn).
  map.forget(&fid(2));

  assert_eq!(map.admit(&fid(2)), None, "the moved dir stops admitting");
  assert_eq!(
    map.admit(&fid(3)),
    None,
    "the descendant no longer reaches the root and does not admit"
  );
  map.assert_adjacency();
}

/// A move INTO the root then straight back OUT: the subtree admits while in,
/// and stops admitting once out — the parent chain tracks each re-parent.
#[test]
fn move_in_then_out_tracks_admission() {
  let mut map = seeded();
  // A subtree arrives under /root/sub: dir `moved` (fid 5) with a child
  // (fid 6). The move-in learns the top; its child was already part of the
  // moved subtree, so once the top is admitted the child resolves through it.
  map.learn(&fid(2), b"moved", Some(&fid(5)));
  map.learn(&fid(5), b"leaf", Some(&fid(6)));
  assert_eq!(map.admit(&fid(5)), Some(PathBuf::from("/root/sub/moved")));
  assert_eq!(
    map.admit(&fid(6)),
    Some(PathBuf::from("/root/sub/moved/leaf"))
  );

  // Now move `moved` back out of the root: forget the top; both it and its
  // child stop admitting.
  map.forget(&fid(5));
  assert_eq!(map.admit(&fid(5)), None);
  assert_eq!(
    map.admit(&fid(6)),
    None,
    "the child orphans with its parent"
  );
}

/// A populated move-out (`forget` of a directory with descendants) prunes the
/// WHOLE subtree from BOTH the admission map and the intern table in one step, via
/// the `children` adjacency — the O(subtree) departure. Dropping only the top would
/// leak every descendant's id: the lazy admission miss only ever reaped `dirs`,
/// never `ids`, so the intern table would grow past O(live directories).
#[test]
fn move_out_prunes_the_whole_subtree_from_both_maps() {
  let mut map = FidMap::new();
  // /root plus a 4-directory subtree under /root/a: a → b → c, and a sibling
  // /root/a/d — so `a` has a descendant fan-out to prune.
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("a")),
    SeedEntry::child(fid(3), fid(2), OsString::from("b")),
    SeedEntry::child(fid(4), fid(3), OsString::from("c")),
    SeedEntry::child(fid(5), fid(2), OsString::from("d")),
  ]);
  assert_eq!(map.dir_count(), 5);
  assert_eq!(map.interned_count(), 5, "every seeded dir is interned");
  map.assert_adjacency();

  // Move /root/a out of the root: forget it. The whole subtree (a, b, c, d) goes.
  map.forget(&fid(2));
  assert_eq!(map.dir_count(), 1, "only the root survives");
  assert_eq!(
    map.interned_count(),
    1,
    "the departed subtree's four ids are all pruned at once — no leak"
  );
  for tag in 2..=5u8 {
    assert_eq!(
      map.admit(&fid(tag)),
      None,
      "no descendant resolves after the move-out"
    );
  }
  map.assert_adjacency();

  // Fresh-identity-on-return holds for DESCENDANTS too: a returned descendant
  // mints a new id, never the pruned one.
  let mut fresh = FidMap::new();
  fresh.seed([SeedEntry::root(fid(1), Path::new("/root"))]);
  let first = fresh.intern(&fid(4));
  fresh.forget(&fid(4));
  assert_ne!(
    fresh.intern(&fid(4)),
    first,
    "a departed descendant mints a fresh identity on return"
  );
}

/// The lazy `admit`-miss eviction remains as a belt: an `admit` on an unknown
/// handle returns `None` and mutates nothing harmful (it never panics and never
/// resolves), so the firehose-drop path stays cheap even though `forget` now
/// prunes departed subtrees eagerly.
#[test]
fn admit_miss_on_unknown_handle_is_a_clean_drop() {
  let mut map = seeded();
  let before = map.dir_count();
  assert_eq!(map.admit(&fid(99)), None, "an unknown handle drops");
  assert_eq!(
    map.dir_count(),
    before,
    "a clean miss leaves the map unchanged"
  );
  map.assert_adjacency();
}

/// The reseed rebuilds the admission structure from a fresh walk and swaps it
/// in: a directory the firehose dropped during a loss window (never learned) is
/// admitted after the reseed re-observes it, a directory that vanished is pruned,
/// and a directory that PERSISTED keeps its interned identity — while a vanished
/// directory's id is pruned so the intern table stays O(live directories).
#[test]
fn reseed_preserves_live_ids_and_prunes_vanished() {
  let mut map = FidMap::new();
  // /root, /root/sub, /root/keep — three seeded directories.
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("sub")),
    SeedEntry::child(fid(3), fid(1), OsString::from("keep")),
  ]);
  // Identities minted before the loss.
  let root_id = map.intern(&fid(1));
  let keep_id = map.intern(&fid(3));
  let sub_id = map.intern(&fid(2));
  assert_eq!(map.interned_count(), 3);
  // During the loss, /root/sub was removed and /root/fresh (fid 7, with a child
  // fid 8) was created; /root/keep persisted — the firehose missed all of it.
  assert_eq!(
    map.admit(&fid(7)),
    None,
    "the fresh dir is unknown pre-reseed"
  );

  // Reseed from the fresh walk: /root, /root/keep, /root/fresh, /root/fresh/deep.
  map.reseed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(3), fid(1), OsString::from("keep")),
    SeedEntry::child(fid(7), fid(1), OsString::from("fresh")),
    SeedEntry::child(fid(8), fid(7), OsString::from("deep")),
  ]);

  // The reseed rebuilt the adjacency from the fresh walk (parents before
  // children), so the dual links are consistent after the swap.
  map.assert_adjacency();
  // The previously-unknown directories now admit.
  assert_eq!(map.admit(&fid(7)), Some(PathBuf::from("/root/fresh")));
  assert_eq!(map.admit(&fid(8)), Some(PathBuf::from("/root/fresh/deep")));
  // The vanished directory is pruned from admission.
  assert_eq!(
    map.admit(&fid(2)),
    None,
    "a vanished dir is gone after reseed"
  );
  // The intern table now holds exactly the four LIVE directories (root, keep,
  // fresh, deep) — the vanished sub's id was pruned, never leaked.
  assert_eq!(
    map.interned_count(),
    4,
    "reseed pruned the vanished dir's id and kept the four live ones"
  );
  // Live directories keep their identities across the reseed.
  assert_eq!(map.intern(&fid(1)), root_id, "the root keeps its id");
  assert_eq!(
    map.intern(&fid(3)),
    keep_id,
    "a directory that persisted through the loss keeps its id"
  );
  // The intern table is bounded by the LIVE directory count: the vanished dir's
  // id was pruned, so re-interning it mints a fresh id (never the departed one).
  assert_ne!(
    map.intern(&fid(2)),
    sub_id,
    "a vanished directory's id is pruned; a reappearance mints fresh"
  );
}

/// An unknown handle is dropped even when it shares the root's superblock — the
/// admission-drop path is exercised as the firehose filter's core behavior.
#[test]
fn unknown_handle_dropped_is_the_firehose_filter() {
  let mut map = seeded();
  for handle in 100..110u8 {
    assert!(
      map.admit(&fid_same_sb(handle)).is_none(),
      "same-sb churn outside the map is filtered out"
    );
  }
  assert!(!map.contains_dir(&fid_same_sb(100)));
}

/// `learn_moved_in` marks the top as `pending_walk`, and `pending_walk_target`
/// reports its CURRENT resolved path plus the pending flag — the reader's
/// deferred-walk lookup. An ordinary `learn` (a mkdir) is NOT pending: its
/// contents are empty by construction, so no walk is owed.
#[test]
fn learn_moved_in_marks_pending_walk() {
  let mut map = seeded();
  // A directory moved in under /root/sub, learned as a pending-walk top.
  map.learn_moved_in(&fid(2), b"arrived", &fid(5));
  assert_eq!(
    map.pending_walk_target(&fid(5)),
    Some((PathBuf::from("/root/sub/arrived"), true)),
    "a moved-in top resolves to its current path and is pending its walk"
  );
  // An ordinary create (mkdir) is empty by construction — never pending.
  map.learn(&fid(2), b"mkdir", Some(&fid(6)));
  assert_eq!(
    map.pending_walk_target(&fid(6)),
    Some((PathBuf::from("/root/sub/mkdir"), false)),
    "a mkdir owes no walk"
  );
  // An unknown FID has no target.
  assert_eq!(map.pending_walk_target(&fid(99)), None);
}

/// `clear_pending_walk` discharges the obligation once the walk completes, so a
/// later `NotFound` at the path is again a benign race (the node no longer owes
/// descendants).
#[test]
fn clear_pending_walk_discharges_the_obligation() {
  let mut map = seeded();
  map.learn_moved_in(&fid(2), b"arrived", &fid(5));
  assert_eq!(map.pending_walk_target(&fid(5)).map(|(_, p)| p), Some(true));
  map.clear_pending_walk(&fid(5));
  assert_eq!(
    map.pending_walk_target(&fid(5)).map(|(_, p)| p),
    Some(false),
    "the walk obligation is discharged"
  );
  // Clearing an absent node is a no-op (does not panic).
  map.clear_pending_walk(&fid(99));
}

/// The burst scenario at the MAP layer: a populated dir moved IN to /root/a
/// (learned pending) then re-parented in-root to /root/b in the SAME batch.
/// `pending_walk_target` must report the CURRENT path (/root/b, through the updated
/// parent link), NOT the stale admission-time /root/a — so the deferred walk
/// resolves the moved dir where it actually is and maps its descendants.
#[test]
fn pending_walk_target_follows_an_in_root_reparent() {
  let mut map = FidMap::new();
  // /root with two in-root parents a and b already present.
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("a")),
    SeedEntry::child(fid(3), fid(1), OsString::from("b")),
  ]);
  // Event 1 of the batch: a populated dir (fid 9) moved in under /root/a, learned
  // as a pending-walk top. Its deferred walk has NOT run yet.
  map.learn_moved_in(&fid(2), b"moved", &fid(9));
  assert_eq!(
    map.pending_walk_target(&fid(9)),
    Some((PathBuf::from("/root/a/moved"), true))
  );
  // Event 2 of the SAME batch: /root/a/moved re-parented in-root to /root/b/moved
  // (an in-root rename → learn re-parents in place, keeping it known and pending).
  map.learn(&fid(3), b"moved", Some(&fid(9)));
  // The deferred walk, run AFTER both events, must resolve the CURRENT path.
  assert_eq!(
    map.pending_walk_target(&fid(9)),
    Some((PathBuf::from("/root/b/moved"), true)),
    "the walk target follows the in-root re-parent — not the stale /root/a"
  );
  map.assert_adjacency();
}

/// A `forget` (rename-out / delete) of a `pending_walk` top CANCELS its walk: the
/// node is gone, so `pending_walk_target` returns `None` and the reader treats the
/// walk as cancelled (a departed subtree owes nothing).
#[test]
fn forget_cancels_a_pending_walk() {
  let mut map = seeded();
  map.learn_moved_in(&fid(2), b"arrived", &fid(5));
  assert!(map.pending_walk_target(&fid(5)).is_some());
  map.forget(&fid(5));
  assert_eq!(
    map.pending_walk_target(&fid(5)),
    None,
    "forgetting the moved-in top cancels its pending walk"
  );
}
