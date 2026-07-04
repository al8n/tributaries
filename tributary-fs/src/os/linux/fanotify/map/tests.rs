use std::path::{Path, PathBuf};

use super::{Fid, FidMap, SeedEntry};

fn fid(tag: u8) -> Fid {
  Fid::new([tag; 8], Box::from(&[tag, tag, tag][..]))
}

/// A distinct FID with the SAME fsid as `fid(tag)` but a different handle — the
/// btrfs-quirk shape (one superblock, many objects) admission must handle
/// without any fsid comparison.
fn fid_same_sb(tag: u8, handle: u8) -> Fid {
  Fid::new([tag; 8], Box::from(&[handle][..]))
}

fn seeded() -> FidMap {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::new(fid(1), PathBuf::from("/root")),
    SeedEntry::new(fid(2), PathBuf::from("/root/sub")),
  ]);
  map
}

/// Admission is pure directory membership: a seeded handle resolves to its
/// path; an unknown handle (provably outside the root) is dropped.
#[test]
fn admit_is_membership_not_fsid() {
  let map = seeded();
  assert_eq!(map.admit(&fid(1)), Some(Path::new("/root")));
  assert_eq!(map.admit(&fid(2)), Some(Path::new("/root/sub")));
  // Same superblock as the root, different object: NOT admitted. An fsid-based
  // filter would wrongly admit this (the btrfs quirk); membership rejects it.
  assert_eq!(map.admit(&fid_same_sb(1, 99)), None);
  // A wholly foreign handle is dropped.
  assert_eq!(map.admit(&fid(42)), None);
}

/// Interned ids are sequential, exact, and stable: the same FID always returns
/// the same id, distinct FIDs never collide, and re-interning is idempotent.
#[test]
fn intern_is_sequential_and_stable() {
  let mut map = FidMap::new();
  let a = map.intern(&fid(10));
  let b = map.intern(&fid(20));
  assert_ne!(a, b, "distinct FIDs get distinct ids");
  assert_eq!(map.intern(&fid(10)), a, "the same FID is stable");
  assert_eq!(map.intern(&fid(20)), b);
  // A third distinct FID advances the counter (sequential, not hashed).
  let c = map.intern(&fid(30));
  assert_ne!(c, a);
  assert_ne!(c, b);
}

/// Seeding a directory also interns it, so an admitted directory always has a
/// stable identity that matches a later explicit `intern`.
#[test]
fn seeding_interns_the_directory() {
  let mut map = seeded();
  let root_id = map.intern(&fid(1));
  let sub_id = map.intern(&fid(2));
  assert_ne!(root_id, sub_id);
  // Re-interning the seed handles returns the SAME ids (seeding already
  // minted them).
  assert_eq!(map.intern(&fid(1)), root_id);
  assert_eq!(map.intern(&fid(2)), sub_id);
}

/// `learn` admits a newly-created in-root directory under its parent's path,
/// using the child's TARGET_FID — later events on the child then admit.
#[test]
fn learn_admits_new_child_directory() {
  let mut map = seeded();
  assert_eq!(map.dir_count(), 2);
  let child = fid(3);
  map.learn(&fid(2), b"created", Some(&child));
  assert_eq!(
    map.admit(&child),
    Some(Path::new("/root/sub/created")),
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
/// self-maintain and admits nothing — the eventual admission is a rescan's job.
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

/// The heal hook re-seeds a subtree after a rescan: a directory the firehose
/// dropped during a loss window is re-admitted from a fresh walk.
#[test]
fn heal_reseeds_a_subtree() {
  let mut map = seeded();
  map.forget(&fid(2));
  assert_eq!(map.admit(&fid(2)), None);
  map.heal([
    SeedEntry::new(fid(2), PathBuf::from("/root/sub")),
    SeedEntry::new(fid(4), PathBuf::from("/root/sub/deep")),
  ]);
  assert_eq!(map.admit(&fid(2)), Some(Path::new("/root/sub")));
  assert_eq!(map.admit(&fid(4)), Some(Path::new("/root/sub/deep")));
}

/// An unknown handle is dropped even when it shares the root's superblock — the
/// admission-drop path is exercised as the firehose filter's core behavior.
#[test]
fn unknown_handle_dropped_is_the_firehose_filter() {
  let map = seeded();
  for handle in 100..110u8 {
    assert!(
      map.admit(&fid_same_sb(1, handle)).is_none(),
      "same-sb churn outside the map is filtered out"
    );
  }
  assert!(!map.contains_dir(&fid_same_sb(1, 100)));
}
