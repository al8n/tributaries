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

/// `forget` drops a directory from admission (delete / rename-out) but keeps
/// its interned id — a stale record for the old handle keeps its old identity
/// rather than colliding with a fresh object.
#[test]
fn forget_drops_admission_but_keeps_identity() {
  let mut map = seeded();
  let sub_id = map.intern(&fid(2));
  map.forget(&fid(2));
  assert_eq!(
    map.admit(&fid(2)),
    None,
    "forgotten directory stops admitting"
  );
  assert_eq!(map.dir_count(), 1);
  assert_eq!(
    map.intern(&fid(2)),
    sub_id,
    "the identity is retained, never recycled"
  );
}

/// A directory rename (re-parent under a NEW in-root parent, or a rename in
/// place) updates ONE node's `(parent, name)`, and every descendant's resolved
/// path follows automatically through the parent walk — no per-descendant
/// rewrite.
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

  // Rename /root/a → /root/b/a: forget the moved dir, relearn it under `b`.
  map.forget(&fid(2));
  map.learn(&fid(4), b"a", Some(&fid(2)));

  // The moved dir AND its pre-seeded child both resolve under the NEW path.
  assert_eq!(map.admit(&fid(2)), Some(PathBuf::from("/root/b/a")));
  assert_eq!(
    map.admit(&fid(3)),
    Some(PathBuf::from("/root/b/a/child")),
    "the descendant follows the parent's rename with no rewrite"
  );
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

/// An orphaned directory is evicted on its admission miss, so the stale node is
/// not retained indefinitely.
#[test]
fn orphaned_node_is_evicted_on_miss() {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("a")),
    SeedEntry::child(fid(3), fid(2), OsString::from("child")),
  ]);
  map.forget(&fid(2));
  assert_eq!(map.dir_count(), 2, "root + orphaned child still stored");
  // The miss on the orphan evicts it.
  assert_eq!(map.admit(&fid(3)), None);
  assert_eq!(map.dir_count(), 1, "the orphan was evicted at its miss");
}

/// The reseed rebuilds the admission structure from a fresh walk and swaps it
/// in: a directory the firehose dropped during a loss window (never learned)
/// is admitted after the reseed re-observes it, and a directory that vanished
/// is pruned — while every interned identity survives.
#[test]
fn reseed_rebuilds_and_preserves_identity() {
  let mut map = seeded();
  // Identities minted before the loss.
  let root_id = map.intern(&fid(1));
  let sub_id = map.intern(&fid(2));
  // During the loss, /root/sub was removed and /root/fresh (fid 7, with a child
  // fid 8) was created — the firehose missed both, so the live map is stale.
  assert_eq!(
    map.admit(&fid(7)),
    None,
    "the fresh dir is unknown pre-reseed"
  );

  // Reseed from the fresh walk: /root, /root/fresh, /root/fresh/deep.
  map.reseed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(7), fid(1), OsString::from("fresh")),
    SeedEntry::child(fid(8), fid(7), OsString::from("deep")),
  ]);

  // The previously-unknown directories now admit.
  assert_eq!(map.admit(&fid(7)), Some(PathBuf::from("/root/fresh")));
  assert_eq!(map.admit(&fid(8)), Some(PathBuf::from("/root/fresh/deep")));
  // The vanished directory is pruned.
  assert_eq!(
    map.admit(&fid(2)),
    None,
    "a vanished dir is gone after reseed"
  );
  // Identities are stable across the reseed (never recycled).
  assert_eq!(map.intern(&fid(1)), root_id);
  assert_eq!(
    map.intern(&fid(2)),
    sub_id,
    "even a pruned directory keeps its old identity"
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
