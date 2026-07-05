use std::{
  ffi::OsString,
  path::{Path, PathBuf},
};

use super::{
  Admission, AdmittedEvent, MemoBatch, classify,
  fid::{
    FAN_ATTRIB, FAN_CREATE, FAN_DELETE, FAN_DELETE_SELF, FAN_MODIFY, FAN_MOVE_SELF, FAN_ONDIR,
    FAN_RENAME, FanMask, Fid, RawFanotifyEvent, RenameInfo,
  },
  map::{FidMap, SeedEntry},
};

fn fid(tag: u8) -> Fid {
  Fid::new([tag; 8], Box::from(&[tag][..]))
}

/// Classifies a single event through a fresh one-shot memo — the per-event shape
/// most of these row tests use (the batch-spanning memo has its own suite below).
fn classify_one(map: &mut FidMap, event: &RawFanotifyEvent) -> Admission {
  classify(map, event, &mut MemoBatch::new())
}

fn seeded() -> FidMap {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("sub")),
  ]);
  map
}

fn dirent(mask: u64, dir_fid: Fid, name: &[u8], target: Option<Fid>) -> RawFanotifyEvent {
  RawFanotifyEvent {
    mask: FanMask::new(mask),
    dir_fid: Some(dir_fid),
    target_fid: target,
    name: Some(name.to_vec()),
    rename: None,
  }
}

/// A name-less self-event in the `DFID` shape — the object's own FID as `dir_fid`.
fn self_dfid(mask: u64, dir_fid: Fid) -> RawFanotifyEvent {
  RawFanotifyEvent {
    mask: FanMask::new(mask),
    dir_fid: Some(dir_fid),
    target_fid: None,
    name: None,
    rename: None,
  }
}

/// A name-less self-event in the `FID`-only shape — the object's own FID as
/// `target_fid`, `dir_fid = None` (the R25 root-death shape).
fn self_fid_only(mask: u64, self_fid: Fid) -> RawFanotifyEvent {
  RawFanotifyEvent {
    mask: FanMask::new(mask),
    dir_fid: None,
    target_fid: Some(self_fid),
    name: None,
    rename: None,
  }
}

fn rename_ev(
  mask: u64,
  target: Option<Fid>,
  old_dir: Fid,
  old_name: &[u8],
  new_dir: Fid,
  new_name: &[u8],
) -> RawFanotifyEvent {
  RawFanotifyEvent {
    mask: FanMask::new(mask),
    dir_fid: None,
    target_fid: target,
    name: None,
    rename: Some(RenameInfo {
      old_dir,
      old_name: old_name.to_vec(),
      new_dir,
      new_name: new_name.to_vec(),
    }),
  }
}

/// The forwarded event of any admission that forwards one, else panics — the row
/// tests assert the resolved path/rename off this.
fn forwarded(admission: Admission) -> AdmittedEvent {
  match admission {
    Admission::Forward(event)
    | Admission::LearnDir(event)
    | Admission::ForgetDir(event)
    | Admission::RootDeath(event)
    | Admission::Rename { event, .. } => event,
    other => panic!("expected a forwarded admission, got {other:?}"),
  }
}

/// A FILE create inside an admitted directory forwards the child's absolute path —
/// the whole admitted form under the KR profile (design §4.9), and no map mutation.
#[test]
fn file_create_resolves_path() {
  let mut map = seeded();
  let ev = dirent(FAN_CREATE, fid(2), b"file.txt", Some(fid(7)));
  let admission = classify_one(&mut map, &ev);
  assert!(
    matches!(admission, Admission::Forward(_)),
    "a file create mutates no directory node"
  );
  assert_eq!(
    forwarded(admission).path.as_deref(),
    Some(Path::new("/root/sub/file.txt"))
  );
}

/// A DIRECTORY create is `LearnDir`: it learns the new child, then forwards the
/// resolved path. The child FID (`target_fid`) is REQUIRED — its absence is caught
/// as `Lossy` in the totality table.
#[test]
fn directory_create_is_learn_dir() {
  let mut map = seeded();
  let ev = dirent(FAN_CREATE | FAN_ONDIR, fid(2), b"newdir", Some(fid(7)));
  let admission = classify_one(&mut map, &ev);
  assert!(matches!(admission, Admission::LearnDir(_)));
  assert_eq!(
    forwarded(admission).path.as_deref(),
    Some(Path::new("/root/sub/newdir"))
  );
}

/// A long churn of DISTINCT file target FIDs never grows the map — files are not
/// admitted directories, so they never enter it. The memo-generation stays put
/// because a plain file event mutates nothing (the O(live directories) bound).
#[test]
fn file_event_churn_never_grows_the_map() {
  let mut map = seeded();
  let generation = map.generation();
  for tag in 20..120u8 {
    let modify = dirent(FAN_MODIFY, fid(2), b"f.txt", Some(fid(tag)));
    assert!(
      matches!(classify_one(&mut map, &modify), Admission::Forward(_)),
      "in-root file modify forwards with no mutation"
    );
  }
  assert_eq!(
    map.dir_count(),
    2,
    "file churn left the two seeded directories"
  );
  assert_eq!(
    map.generation(),
    generation,
    "a file event mutates nothing, so the generation is unchanged"
  );
}

/// An event whose directory FID is not in the map is provably outside the watched
/// root — the whole superblock-firehose filter — and is a `ForeignDrop`.
#[test]
fn classify_drops_unknown_directory() {
  let mut map = seeded();
  let ev = dirent(FAN_MODIFY, fid(99), b"elsewhere", None);
  assert!(matches!(
    classify_one(&mut map, &ev),
    Admission::ForeignDrop
  ));
}

/// A directory create self-maintains the map: the new directory's own later events
/// then admit.
#[test]
fn directory_create_is_learned() {
  let mut map = seeded();
  let ev = dirent(FAN_CREATE | FAN_ONDIR, fid(2), b"newdir", Some(fid(3)));
  assert!(matches!(
    classify_one(&mut map, &ev),
    Admission::LearnDir(_)
  ));
  // A modify inside the newly-learned directory now admits.
  let inside = dirent(FAN_MODIFY, fid(3), b"inside.txt", None);
  assert_eq!(
    forwarded(classify_one(&mut map, &inside)).path.as_deref(),
    Some(Path::new("/root/sub/newdir/inside.txt"))
  );
}

/// A `DELETE_SELF` on an admitted NON-ROOT directory is `ForgetDir`: it resolves to
/// that directory's own path and forgets it (its stale handle stops admitting).
#[test]
fn delete_self_of_subdir_forgets_it() {
  let mut map = seeded();
  let admission = classify_one(&mut map, &self_dfid(FAN_DELETE_SELF | FAN_ONDIR, fid(2)));
  assert!(matches!(admission, Admission::ForgetDir(_)));
  assert_eq!(
    forwarded(admission).path.as_deref(),
    Some(Path::new("/root/sub"))
  );
  assert!(!map.contains_dir(&fid(2)), "the directory is forgotten");
}

/// A name-less `MOVE_SELF` on an admitted non-root directory is a self-rescan
/// (`Forward`) that does NOT forget it — the node is re-parented by its
/// rename/dirent, not by this self-event.
#[test]
fn move_self_of_subdir_forwards_without_forgetting() {
  let mut map = seeded();
  let admission = classify_one(&mut map, &self_dfid(FAN_MOVE_SELF | FAN_ONDIR, fid(2)));
  assert!(matches!(admission, Admission::Forward(_)));
  assert_eq!(
    forwarded(admission).path.as_deref(),
    Some(Path::new("/root/sub"))
  );
  assert!(
    map.contains_dir(&fid(2)),
    "a move-self does not forget the node — its rename re-parents it"
  );
}

/// A DIRECTORY delete reported as a PARENT dirent (`FAN_DELETE|ONDIR` with the
/// parent's `dir_fid`, the child name, AND the child's `target_fid`) is `ForgetDir`:
/// it prunes the whole child subtree via that target FID. The deleted directory and
/// its descendants stop admitting, and the map returns to the pre-child count.
#[test]
fn directory_delete_dirent_forgets_the_subtree() {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("sub")),
    SeedEntry::child(fid(3), fid(2), OsString::from("child")),
  ]);
  let ev = dirent(FAN_DELETE | FAN_ONDIR, fid(1), b"sub", Some(fid(2)));
  let admission = classify_one(&mut map, &ev);
  assert!(matches!(admission, Admission::ForgetDir(_)));
  assert_eq!(
    forwarded(admission).path.as_deref(),
    Some(Path::new("/root/sub"))
  );
  assert_eq!(
    map.admit(&fid(2)),
    None,
    "the deleted directory is forgotten"
  );
  assert_eq!(
    map.admit(&fid(3)),
    None,
    "and its descendant prunes with it — no stale subtree left admitting"
  );
  assert_eq!(map.dir_count(), 1, "only the root remains");
}

/// A FILE `FAN_RENAME` with both ends in-root resolves both absolute paths in one
/// event — the atomic pair, no window. It carries only the two paths (no identity —
/// design §4.9), and a file rename mutates nothing (`seed = None`).
#[test]
fn file_rename_resolves_both_ends() {
  let mut map = seeded();
  let generation = map.generation();
  let ev = rename_ev(FAN_RENAME, Some(fid(8)), fid(1), b"a.txt", fid(2), b"b.txt");
  let admission = classify_one(&mut map, &ev);
  assert!(matches!(admission, Admission::Rename { seed: None, .. }));
  let rename = forwarded(admission).rename.expect("rename info");
  assert_eq!(rename.old_path, PathBuf::from("/root/a.txt"));
  assert_eq!(rename.new_path, PathBuf::from("/root/sub/b.txt"));
  assert_eq!(
    map.generation(),
    generation,
    "a file rename left the map (and its two seeded directories) unchanged"
  );
}

/// A rename with BOTH ends outside the root is churn elsewhere on the superblock
/// and is a `ForeignDrop`.
#[test]
fn rename_outside_root_is_dropped() {
  let mut map = seeded();
  let ev = rename_ev(FAN_RENAME, None, fid(90), b"x", fid(91), b"y");
  assert!(matches!(
    classify_one(&mut map, &ev),
    Admission::ForeignDrop
  ));
}

/// A rename INTO the root (source outside, destination in-root) admits, with the
/// in-root end fully resolved.
#[test]
fn rename_into_root_admits_with_resolved_destination() {
  let mut map = seeded();
  let ev = rename_ev(
    FAN_RENAME,
    Some(fid(8)),
    fid(90),
    b"outside",
    fid(2),
    b"arrived.txt",
  );
  let admission = classify_one(&mut map, &ev);
  assert!(matches!(admission, Admission::Rename { seed: None, .. }));
  let rename = forwarded(admission).rename.expect("rename info");
  assert_eq!(rename.new_path, PathBuf::from("/root/sub/arrived.txt"));
}

/// A DIRECTORY moved IN from outside the root (its own FID unknown, destination
/// parent in-root) is a `Rename` with `seed = Some(moved)`: the reader must walk its
/// pre-existing descendants in. The moved directory is already learned AND marked
/// `pending_walk`, and the seed carries ONLY the FID (the reader resolves its
/// current path at walk time).
#[test]
fn dir_move_in_from_outside_requests_a_subtree_walk() {
  let mut map = seeded();
  assert!(!map.contains_dir(&fid(9)), "the moved dir starts unknown");
  let ev = rename_ev(
    FAN_RENAME | FAN_ONDIR,
    Some(fid(9)),
    fid(90),
    b"arrived",
    fid(2),
    b"arrived",
  );
  let admission = classify_one(&mut map, &ev);
  let Admission::Rename {
    event,
    seed: Some(moved_fid),
  } = admission
  else {
    panic!("a populated dir moved in from outside must request a subtree walk");
  };
  assert_eq!(
    moved_fid,
    fid(9),
    "the walk hangs descendants off the moved FID"
  );
  assert_eq!(
    event.rename.expect("rename info").new_path,
    PathBuf::from("/root/sub/arrived"),
    "the forwarded move still carries the destination path"
  );
  assert_eq!(
    map.pending_walk_target(&fid(9)),
    Some((PathBuf::from("/root/sub/arrived"), true)),
    "the moved directory is admitted and pending its subtree walk"
  );
}

/// An IN-ROOT directory rename (the moved directory was ALREADY known, so its
/// descendants are already mapped) is a `Rename` with `seed = None` — NO walk. The
/// completeness invariant is met by the parent-relative re-parent.
#[test]
fn in_root_dir_rename_requests_no_walk() {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("sub")),
    SeedEntry::child(fid(4), fid(1), OsString::from("dest")),
  ]);
  let ev = rename_ev(
    FAN_RENAME | FAN_ONDIR,
    Some(fid(2)),
    fid(1),
    b"sub",
    fid(4),
    b"sub",
  );
  assert!(
    matches!(
      classify_one(&mut map, &ev),
      Admission::Rename { seed: None, .. }
    ),
    "an in-root rename of an already-mapped directory needs no subtree walk"
  );
  assert_eq!(
    map.admit(&fid(2)),
    Some(PathBuf::from("/root/dest/sub")),
    "the moved directory re-parents under the new in-root parent"
  );
}

/// A directory moved OUT then straight back IN re-walks: the move-out forgets it, so
/// on the way back it is UNKNOWN again — a move-in, which re-requests the walk.
#[test]
fn dir_move_out_then_back_in_re_walks() {
  let mut map = seeded();
  let out = rename_ev(
    FAN_RENAME | FAN_ONDIR,
    Some(fid(2)),
    fid(1),
    b"sub",
    fid(90),
    b"sub",
  );
  assert!(matches!(
    classify_one(&mut map, &out),
    Admission::Rename { seed: None, .. }
  ));
  assert!(!map.contains_dir(&fid(2)), "the moved-out dir is forgotten");

  let back = rename_ev(
    FAN_RENAME | FAN_ONDIR,
    Some(fid(2)),
    fid(90),
    b"sub",
    fid(1),
    b"sub",
  );
  assert!(
    matches!(
      classify_one(&mut map, &back),
      Admission::Rename { seed: Some(_), .. }
    ),
    "a move back in from outside re-requests the subtree walk"
  );
}

/// A populated directory moved IN to /root/a then IMMEDIATELY renamed in-root to
/// /root/b in the SAME batch, driven through the classify seam. The first learns the
/// moved dir pending; the second is an in-root re-parent that KEEPS it pending and
/// re-parents it, so the still-owed walk resolves the CURRENT path /root/b.
#[test]
fn burst_move_in_then_in_root_rename_keeps_walk_pending_at_current_path() {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("a")),
    SeedEntry::child(fid(3), fid(1), OsString::from("b")),
  ]);
  let move_in = rename_ev(
    FAN_RENAME | FAN_ONDIR,
    Some(fid(9)),
    fid(90),
    b"moved",
    fid(2),
    b"moved",
  );
  assert!(matches!(
    classify_one(&mut map, &move_in),
    Admission::Rename { seed: Some(_), .. }
  ));
  assert_eq!(
    map.pending_walk_target(&fid(9)),
    Some((PathBuf::from("/root/a/moved"), true)),
    "after event 1 the moved dir is pending at /root/a"
  );

  let in_root = rename_ev(
    FAN_RENAME | FAN_ONDIR,
    Some(fid(9)),
    fid(2),
    b"moved",
    fid(3),
    b"moved",
  );
  assert!(
    matches!(
      classify_one(&mut map, &in_root),
      Admission::Rename { seed: None, .. }
    ),
    "the in-root re-parent of the now-known dir needs no second walk"
  );
  assert_eq!(
    map.pending_walk_target(&fid(9)),
    Some((PathBuf::from("/root/b/moved"), true)),
    "the deferred walk target followed the in-root re-parent to /root/b and stays pending"
  );
  map.assert_adjacency();
}

/// A FILE moved in from outside (non-directory target, non-`ONDIR`) never requests a
/// subtree walk — only directories carry descendants.
#[test]
fn file_move_in_requests_no_walk() {
  let mut map = seeded();
  let ev = rename_ev(
    FAN_RENAME,
    Some(fid(9)),
    fid(90),
    b"f.txt",
    fid(2),
    b"f.txt",
  );
  assert!(
    matches!(
      classify_one(&mut map, &ev),
      Admission::Rename { seed: None, .. }
    ),
    "a file move-in carries no descendants, so no walk"
  );
}

/// A directory `FAN_RENAME` within the root re-parents the moved directory's whole
/// subtree: after the rename, a pre-seeded descendant's own event resolves under the
/// NEW path — the parent-relative map, not a stale absolute one.
#[test]
fn dir_rename_reparents_descendants() {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("sub")),
    SeedEntry::child(fid(3), fid(2), OsString::from("child")),
  ]);
  let rename = rename_ev(
    FAN_RENAME | FAN_ONDIR,
    Some(fid(2)),
    fid(1),
    b"sub",
    fid(1),
    b"moved",
  );
  assert!(matches!(
    classify_one(&mut map, &rename),
    Admission::Rename { seed: None, .. }
  ));

  let child_event = dirent(FAN_MODIFY, fid(3), b"leaf.txt", None);
  assert_eq!(
    forwarded(classify_one(&mut map, &child_event))
      .path
      .as_deref(),
    Some(Path::new("/root/moved/child/leaf.txt")),
    "the descendant resolves under the renamed parent, not the stale path"
  );
}

/// An in-root directory rename RE-PARENTS the moved directory in place and resolves
/// the pair's paths. No identity rides the rename (design §4.9).
#[test]
fn dir_rename_in_root_reparents_and_keeps_membership() {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("sub")),
    SeedEntry::child(fid(3), fid(2), OsString::from("child")),
  ]);
  let rename = rename_ev(
    FAN_RENAME | FAN_ONDIR,
    Some(fid(2)),
    fid(1),
    b"sub",
    fid(1),
    b"moved",
  );
  let admission = classify_one(&mut map, &rename);
  assert!(matches!(admission, Admission::Rename { seed: None, .. }));
  let rename = forwarded(admission).rename.expect("rename info");
  assert_eq!(rename.old_path, PathBuf::from("/root/sub"));
  assert_eq!(rename.new_path, PathBuf::from("/root/moved"));
  assert_eq!(map.admit(&fid(2)), Some(PathBuf::from("/root/moved")));
  assert_eq!(
    map.admit(&fid(3)),
    Some(PathBuf::from("/root/moved/child")),
    "the descendant follows the in-root rename"
  );
  assert_eq!(
    map.dir_count(),
    3,
    "an in-root rename does not grow the map"
  );
}

/// A directory moved OUT of the root is FORGOTTEN (it departed), bounding the map at
/// the live directory count.
#[test]
fn dir_move_out_forgets_the_directory() {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("sub")),
  ]);
  let rename = rename_ev(
    FAN_RENAME | FAN_ONDIR,
    Some(fid(2)),
    fid(1),
    b"sub",
    fid(90),
    b"sub",
  );
  assert!(matches!(
    classify_one(&mut map, &rename),
    Admission::Rename { seed: None, .. }
  ));
  assert_eq!(
    map.dir_count(),
    1,
    "the departed directory was forgotten — only the root remains"
  );
  assert_eq!(map.admit(&fid(2)), None, "and it no longer admits");
}

/// A directory moved OUT of the root stops admitting its descendants: after the
/// move-out, a pre-seeded child's event no longer admits.
#[test]
fn dir_move_out_of_root_stops_descendant_admission() {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("sub")),
    SeedEntry::child(fid(3), fid(2), OsString::from("child")),
  ]);
  let rename = rename_ev(
    FAN_RENAME | FAN_ONDIR,
    Some(fid(2)),
    fid(1),
    b"sub",
    fid(90),
    b"sub",
  );
  assert!(matches!(
    classify_one(&mut map, &rename),
    Admission::Rename { seed: None, .. }
  ));
  let child_event = dirent(FAN_MODIFY, fid(3), b"leaf.txt", None);
  assert!(
    matches!(classify_one(&mut map, &child_event), Admission::ForeignDrop),
    "a descendant of a moved-out directory no longer admits"
  );
}

/// An attrib event on a file in an admitted directory forwards its path — the whole
/// admitted form (no identity, design §4.9).
#[test]
fn attrib_resolves_its_path() {
  let mut map = seeded();
  let ev = dirent(FAN_ATTRIB, fid(1), b"meta.txt", None);
  let admission = classify_one(&mut map, &ev);
  assert!(matches!(admission, Admission::Forward(_)));
  assert_eq!(
    forwarded(admission).path.as_deref(),
    Some(Path::new("/root/meta.txt"))
  );
}

/// The classification totality table — the single source of truth, exercised across
/// every `(mask, field-presence, map-state)` shape including EVERY prior finding.
/// Each row asserts the exact action, and a closing cartesian sweep proves the
/// classifier is TOTAL (returns for every combination, no silent fall-through and no
/// panic). The action's required fields ARE the validation: a missing field is
/// `Lossy` here, not in a separate decode matrix.
mod classification_totality {
  use super::*;

  /// The variant identity a row expects — `Rename` splits on whether a move-in walk
  /// is owed (`seed`), the discriminator the reader keys the deferred walk on.
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  enum Kind {
    Forward,
    LearnDir,
    ForgetDir,
    Rename,
    RenameSeed,
    RootDeath,
    ForeignDrop,
    Lossy,
  }

  fn kind(admission: &Admission) -> Kind {
    match admission {
      Admission::Forward(_) => Kind::Forward,
      Admission::LearnDir(_) => Kind::LearnDir,
      Admission::ForgetDir(_) => Kind::ForgetDir,
      Admission::Rename { seed: None, .. } => Kind::Rename,
      Admission::Rename { seed: Some(_), .. } => Kind::RenameSeed,
      Admission::RootDeath(_) => Kind::RootDeath,
      Admission::ForeignDrop => Kind::ForeignDrop,
      Admission::Lossy => Kind::Lossy,
    }
  }

  /// A fresh map per row: `/root` (fid 1, the root anchor), `/root/sub` (fid 2, a
  /// known non-root directory), `/root/sub/child` (fid 3). fid 99 is unknown
  /// (outside the root). Rows build their own map when they need a different shape.
  fn deep_map() -> FidMap {
    let mut map = FidMap::new();
    map.seed([
      SeedEntry::root(fid(1), Path::new("/root")),
      SeedEntry::child(fid(2), fid(1), OsString::from("sub")),
      SeedEntry::child(fid(3), fid(2), OsString::from("child")),
    ]);
    map
  }

  fn assert_row(label: &str, event: RawFanotifyEvent, expected: Kind) {
    let mut map = deep_map();
    let got = kind(&classify_one(&mut map, &event));
    assert_eq!(
      got, expected,
      "row `{label}`: expected {expected:?}, got {got:?}"
    );
  }

  /// Every non-rename dirent + self-event shape → its exact action, one fresh map
  /// per row.
  #[test]
  fn dirent_and_self_event_rows() {
    // In-root file dirents (no tree mutation) → Forward.
    assert_row(
      "file create",
      dirent(FAN_CREATE, fid(2), b"f", Some(fid(7))),
      Kind::Forward,
    );
    assert_row(
      "file delete",
      dirent(FAN_DELETE, fid(2), b"f", None),
      Kind::Forward,
    );
    assert_row(
      "file modify",
      dirent(FAN_MODIFY, fid(2), b"f", None),
      Kind::Forward,
    );
    assert_row(
      "file attrib",
      dirent(FAN_ATTRIB, fid(2), b"f", None),
      Kind::Forward,
    );
    // A non-structural ONDIR modify/attrib mutates no tree node → Forward, no target.
    assert_row(
      "dir modify",
      dirent(FAN_MODIFY | FAN_ONDIR, fid(2), b"d", None),
      Kind::Forward,
    );
    assert_row(
      "dir attrib",
      dirent(FAN_ATTRIB | FAN_ONDIR, fid(2), b"d", None),
      Kind::Forward,
    );

    // Directory create/delete WITH the child FID → LearnDir / ForgetDir.
    assert_row(
      "dir create + target",
      dirent(FAN_CREATE | FAN_ONDIR, fid(2), b"new", Some(fid(8))),
      Kind::LearnDir,
    );
    assert_row(
      "dir delete dirent + target",
      dirent(FAN_DELETE | FAN_ONDIR, fid(2), b"child", Some(fid(3))),
      Kind::ForgetDir,
    );
    // A named MOVE_SELF|ONDIR dirent (a dir move reported by the parent) forgets the
    // named child via its target FID → ForgetDir.
    assert_row(
      "dir move dirent + target",
      dirent(FAN_MOVE_SELF | FAN_ONDIR, fid(2), b"child", Some(fid(3))),
      Kind::ForgetDir,
    );

    // R23/R24 relocation: a directory mutation MISSING its child FID, in-root → Lossy
    // (the action needs the field). A FILE mutation needs none → Forward.
    assert_row(
      "dir create no target (in-root)",
      dirent(FAN_CREATE | FAN_ONDIR, fid(2), b"new", None),
      Kind::Lossy,
    );
    assert_row(
      "dir delete no target (in-root)",
      dirent(FAN_DELETE | FAN_ONDIR, fid(2), b"child", None),
      Kind::Lossy,
    );
    assert_row(
      "file delete no target",
      dirent(FAN_DELETE, fid(2), b"f", None),
      Kind::Forward,
    );

    // A dir mutation missing its child FID whose PARENT is OUT of root → ForeignDrop
    // (membership fails first — the firehose filter, never a spurious reseed).
    assert_row(
      "dir create no target (out-of-root)",
      dirent(FAN_CREATE | FAN_ONDIR, fid(99), b"new", None),
      Kind::ForeignDrop,
    );

    // R23 name gate: a named dirent whose name is absent/empty (decode folds empty →
    // None) → Lossy in-root, ForeignDrop out-of-root.
    assert_row(
      "create empty name (in-root)",
      RawFanotifyEvent {
        mask: FanMask::new(FAN_CREATE),
        dir_fid: Some(fid(2)),
        target_fid: Some(fid(7)),
        name: None,
        rename: None,
      },
      Kind::Lossy,
    );
    assert_row(
      "modify no name (out-of-root)",
      RawFanotifyEvent {
        mask: FanMask::new(FAN_MODIFY),
        dir_fid: Some(fid(99)),
        target_fid: None,
        name: None,
        rename: None,
      },
      Kind::ForeignDrop,
    );

    // The firehose: an in-root unknown directory FID, and a FID-only non-self event.
    assert_row(
      "unknown dir fid",
      dirent(FAN_MODIFY, fid(99), b"x", None),
      Kind::ForeignDrop,
    );
    assert_row(
      "fid-only non-self attrib",
      RawFanotifyEvent {
        mask: FanMask::new(FAN_ATTRIB),
        dir_fid: None,
        target_fid: Some(fid(99)),
        name: None,
        rename: None,
      },
      Kind::ForeignDrop,
    );

    // Self-events on a KNOWN non-root directory: delete_self forgets (ForgetDir),
    // move_self is a self-rescan (Forward). Both DFID and FID-only shapes.
    assert_row(
      "subdir delete_self (dfid)",
      self_dfid(FAN_DELETE_SELF | FAN_ONDIR, fid(2)),
      Kind::ForgetDir,
    );
    assert_row(
      "subdir delete_self (fid-only)",
      self_fid_only(FAN_DELETE_SELF | FAN_ONDIR, fid(2)),
      Kind::ForgetDir,
    );
    assert_row(
      "subdir move_self (dfid)",
      self_dfid(FAN_MOVE_SELF | FAN_ONDIR, fid(2)),
      Kind::Forward,
    );
    assert_row(
      "subdir move_self (fid-only)",
      self_fid_only(FAN_MOVE_SELF | FAN_ONDIR, fid(2)),
      Kind::Forward,
    );

    // A self-event on an UNKNOWN (foreign) object → ForeignDrop, never a root death.
    assert_row(
      "foreign delete_self (dfid)",
      self_dfid(FAN_DELETE_SELF | FAN_ONDIR, fid(99)),
      Kind::ForeignDrop,
    );
    assert_row(
      "foreign delete_self (fid-only)",
      self_fid_only(FAN_DELETE_SELF, fid(99)),
      Kind::ForeignDrop,
    );
    // A self-event with NO fid at all → ForeignDrop (unaddressable noise).
    assert_row(
      "self-event no fid",
      RawFanotifyEvent {
        mask: FanMask::new(FAN_DELETE_SELF),
        dir_fid: None,
        target_fid: None,
        name: None,
        rename: None,
      },
      Kind::ForeignDrop,
    );
  }

  /// The R25 closure at the classification layer: a root self-event is `RootDeath` in
  /// BOTH the `DFID` shape AND the `FID`-only shape (dir_fid = None) — the latter is
  /// what the old admission dropped, leaving the root's death to the liveness tick.
  /// The forwarded event carries the ROOT's own path, so compile lowers it to the
  /// death lifecycle even with the tick disabled.
  #[test]
  fn root_self_event_is_root_death_in_both_shapes() {
    for mask in [
      FAN_DELETE_SELF | FAN_ONDIR,
      FAN_MOVE_SELF | FAN_ONDIR,
      FAN_DELETE_SELF | FAN_ATTRIB,
    ] {
      let mut map = deep_map();
      let dfid = classify_one(&mut map, &self_dfid(mask, fid(1)));
      assert!(
        matches!(dfid, Admission::RootDeath(_)),
        "DFID root self-event {mask:#x}"
      );
      assert_eq!(
        forwarded(dfid).path.as_deref(),
        Some(Path::new("/root")),
        "RootDeath carries the root's own path for the death lowering"
      );

      let mut map = deep_map();
      let fid_only = classify_one(&mut map, &self_fid_only(mask, fid(1)));
      assert!(
        matches!(fid_only, Admission::RootDeath(_)),
        "FID-only root self-event {mask:#x} — the R25 shape — is RootDeath, not a drop"
      );
      assert_eq!(
        forwarded(fid_only).path.as_deref(),
        Some(Path::new("/root"))
      );
    }
  }

  /// Every rename shape → its exact action, keyed on which ends are in-root and
  /// whether the moved dir is already known (the move flavor).
  #[test]
  fn rename_rows() {
    // File renames (non-ONDIR) never need a target: both-in, into-root, out-of-root.
    assert_row(
      "file rename both-in",
      rename_ev(FAN_RENAME, Some(fid(7)), fid(1), b"a", fid(2), b"b"),
      Kind::Rename,
    );
    assert_row(
      "file rename into-root (no target)",
      rename_ev(FAN_RENAME, None, fid(99), b"a", fid(2), b"b"),
      Kind::Rename,
    );
    assert_row(
      "rename both-out",
      rename_ev(FAN_RENAME, None, fid(90), b"a", fid(91), b"b"),
      Kind::ForeignDrop,
    );

    // A directory rename WITH its target FID: in-root re-parent (known) → Rename;
    // move-in (unknown dest-in-root) → RenameSeed; move-out (dest-out) → Rename.
    assert_row(
      "dir rename in-root reparent",
      rename_ev(
        FAN_RENAME | FAN_ONDIR,
        Some(fid(2)),
        fid(1),
        b"sub",
        fid(1),
        b"moved",
      ),
      Kind::Rename,
    );
    assert_row(
      "dir move-in from outside",
      rename_ev(
        FAN_RENAME | FAN_ONDIR,
        Some(fid(9)),
        fid(90),
        b"in",
        fid(1),
        b"in",
      ),
      Kind::RenameSeed,
    );
    assert_row(
      "dir move-out of root",
      rename_ev(
        FAN_RENAME | FAN_ONDIR,
        Some(fid(2)),
        fid(1),
        b"sub",
        fid(90),
        b"sub",
      ),
      Kind::Rename,
    );

    // R24 relocation: a targetless ONDIR rename is Lossy for EVERY in-root move shape
    // (the action needs the moved FID), but ForeignDrop when both ends are outside.
    for (label, old_dir, new_dir) in [
      ("targetless ondir reparent", fid(1), fid(1)),
      ("targetless ondir move-out", fid(1), fid(90)),
      ("targetless ondir move-in", fid(90), fid(1)),
    ] {
      assert_row(
        label,
        rename_ev(FAN_RENAME | FAN_ONDIR, None, old_dir, b"x", new_dir, b"x"),
        Kind::Lossy,
      );
    }
    assert_row(
      "targetless ondir both-out",
      rename_ev(FAN_RENAME | FAN_ONDIR, None, fid(90), b"x", fid(91), b"x"),
      Kind::ForeignDrop,
    );
  }

  /// TOTALITY: the classifier returns for EVERY combination of a mask (over the
  /// backend's vocabulary), each field present-or-absent, and each map-state — no
  /// combination panics or falls through. The type system guarantees an `Admission`
  /// is returned; this sweep proves no internal `unwrap`/`expect` trips on any shape.
  #[test]
  fn every_combination_classifies_without_panic() {
    let masks = [
      FAN_CREATE,
      FAN_DELETE,
      FAN_MODIFY,
      FAN_ATTRIB,
      FAN_CREATE | FAN_ONDIR,
      FAN_DELETE | FAN_ONDIR,
      FAN_DELETE_SELF,
      FAN_MOVE_SELF,
      FAN_DELETE_SELF | FAN_ONDIR,
      FAN_MOVE_SELF | FAN_ONDIR,
      FAN_DELETE_SELF | FAN_ATTRIB,
      FAN_RENAME,
      FAN_RENAME | FAN_ONDIR,
    ];
    // Each candidate FID is drawn from {root anchor, known non-root, unknown} so the
    // sweep spans every map-state the classifier branches on.
    let fids = [Some(fid(1)), Some(fid(2)), Some(fid(99)), None];
    let names: [Option<&[u8]>; 2] = [Some(b"n".as_slice()), None];
    let mut classified = 0u64;
    for &mask in &masks {
      for dir in &fids {
        for target in &fids {
          for &name in &names {
            for rename in [false, true] {
              let mut map = deep_map();
              let event = RawFanotifyEvent {
                mask: FanMask::new(mask),
                dir_fid: dir.clone(),
                target_fid: target.clone(),
                name: name.map(<[u8]>::to_vec),
                rename: rename.then(|| RenameInfo {
                  old_dir: fid(1),
                  old_name: b"o".to_vec(),
                  new_dir: fid(2),
                  new_name: b"n".to_vec(),
                }),
              };
              // The call itself is the totality assertion: it must return one action,
              // never panic. `kind` additionally proves the result is a known variant.
              let _ = kind(&classify_one(&mut map, &event));
              classified += 1;
            }
          }
        }
      }
    }
    assert_eq!(
      classified,
      masks.len() as u64 * 4 * 4 * 2 * 2,
      "every mask × dir × target × name × rename combination was classified"
    );
  }
}

/// The batch admission memo (design §4.9): the reader shares ONE [`MemoBatch`]
/// across a read buffer, so a second event under an already-resolved directory hits
/// the cache, while a map MUTATION between two events bumps the generation and forces
/// the second to miss — the generation-tagged soundness argument.
mod batch_memo {
  use super::*;

  /// Two events under the SAME directory in one batch: the first resolves against the
  /// map (a miss that fills the cache), the second is served from the memo (a hit).
  #[test]
  fn second_event_under_same_dir_hits() {
    let mut map = seeded();
    let mut memo = MemoBatch::new();
    let a = dirent(FAN_MODIFY, fid(2), b"a.txt", None);
    let b = dirent(FAN_MODIFY, fid(2), b"b.txt", None);
    assert!(matches!(
      classify(&mut map, &a, &mut memo),
      Admission::Forward(_)
    ));
    assert_eq!((memo.hits, memo.misses), (0, 1), "the first is a cold miss");
    assert!(matches!(
      classify(&mut map, &b, &mut memo),
      Admission::Forward(_)
    ));
    assert_eq!(
      (memo.hits, memo.misses),
      (1, 1),
      "the second under the same dir is a memo hit"
    );
  }

  /// A mutation between two events under the same directory (a `learn` of a new
  /// child) bumps the generation, so a lookup AFTER it re-resolves — a miss. The
  /// learning event itself still HITS its directory (the lookup precedes its
  /// mutation).
  #[test]
  fn a_learn_between_events_invalidates_the_memo() {
    let mut map = seeded();
    let mut memo = MemoBatch::new();
    let modify = dirent(FAN_MODIFY, fid(2), b"a.txt", None);
    assert!(matches!(
      classify(&mut map, &modify, &mut memo),
      Admission::Forward(_)
    ));
    assert_eq!((memo.hits, memo.misses), (0, 1));
    let mkdir = dirent(FAN_CREATE | FAN_ONDIR, fid(2), b"newdir", Some(fid(3)));
    assert!(matches!(
      classify(&mut map, &mkdir, &mut memo),
      Admission::LearnDir(_)
    ));
    assert_eq!(
      (memo.hits, memo.misses),
      (1, 1),
      "the learning event still hits its directory — the lookup precedes its mutation"
    );
    let modify2 = dirent(FAN_MODIFY, fid(2), b"b.txt", None);
    assert!(matches!(
      classify(&mut map, &modify2, &mut memo),
      Admission::Forward(_)
    ));
    assert_eq!(
      (memo.hits, memo.misses),
      (1, 2),
      "the post-learn lookup re-resolves: the learn invalidated the pre-learn entry"
    );
  }

  /// A `forget` (delete of a directory) likewise invalidates the memo via the
  /// generation bump: a later event that would otherwise hit misses.
  #[test]
  fn a_forget_invalidates_the_memo() {
    let mut map = FidMap::new();
    map.seed([
      SeedEntry::root(fid(1), Path::new("/root")),
      SeedEntry::child(fid(2), fid(1), OsString::from("a")),
      SeedEntry::child(fid(3), fid(1), OsString::from("b")),
    ]);
    let mut memo = MemoBatch::new();
    let under_root = dirent(FAN_MODIFY, fid(1), b"x.txt", None);
    assert!(matches!(
      classify(&mut map, &under_root, &mut memo),
      Admission::Forward(_)
    ));
    // Delete directory /root/b (a DELETE_SELF forgets it) — a mutation.
    let delete_b = self_dfid(FAN_DELETE_SELF | FAN_ONDIR, fid(3));
    assert!(matches!(
      classify(&mut map, &delete_b, &mut memo),
      Admission::ForgetDir(_)
    ));
    let under_root2 = dirent(FAN_MODIFY, fid(1), b"y.txt", None);
    assert!(matches!(
      classify(&mut map, &under_root2, &mut memo),
      Admission::Forward(_)
    ));
    assert_eq!(memo.hits, 0, "the forget invalidated the root's memo entry");
  }

  /// A fresh memo (a new read batch) starts empty — the reader builds one per buffer,
  /// so a resolution in one batch never leaks into the next.
  #[test]
  fn a_fresh_batch_memo_starts_cold() {
    let mut map = seeded();
    let modify = dirent(FAN_MODIFY, fid(2), b"a.txt", None);
    let mut first = MemoBatch::new();
    assert!(matches!(
      classify(&mut map, &modify, &mut first),
      Admission::Forward(_)
    ));
    assert_eq!((first.hits, first.misses), (0, 1));
    let mut second = MemoBatch::new();
    assert!(matches!(
      classify(&mut map, &modify, &mut second),
      Admission::Forward(_)
    ));
    assert_eq!(
      (second.hits, second.misses),
      (0, 1),
      "a new batch memo does not inherit the prior batch's entries"
    );
  }
}

/// The DIFFERENTIAL CORRECTNESS ORACLE — the classifier's correctness contract.
///
/// [`classify`] is proven CORRECT (not merely non-panicking) against an INDEPENDENT
/// reference derived from the SPEC, never copied from classify's control flow. The
/// spec, in three steps:
///
///   1. resolve the event's ADDRESSING object — a named event addresses the child's
///      parent (`dir_fid`); a name-less event addresses its OWN object by its self-FID
///      (`dir_fid`, or the `FID`-only shape's `target_fid`); a rename addresses either
///      of its two directory ends — and read that object's admittance from the map;
///   2. an addressing object OUTSIDE the root (or none at all) is superblock firehose
///      noise — `ForeignDrop`;
///   3. an ADMITTED addressing object takes the action its mask dictates, and an
///      action missing a required field is `Lossy`.
///
/// [`classify_oracle`] encodes exactly that, computing admittance UNIFORMLY for every
/// mask and never mutating the map (a pure predicate, not classify's act-as-you-go
/// machinery). So a future `classify` that re-introduced a mask special-case or a
/// pre-classification gate dropping an admitted-FID event would DISAGREE with it. On
/// top of agreement, two invariants are asserted DIRECTLY against the event + map,
/// independent of BOTH classifiers:
///
///   (i)  no-admitted-drop — an event whose addressing object is admitted is NEVER
///        `ForeignDrop` (the whole class: a name-less ATTRIB/MODIFY on an admitted
///        directory, addressed only by `target_fid`, once fell to the `dir_fid == None`
///        gate and was silently dropped);
///   (ii) field-correctness — every forwarded (non-`Lossy`, non-`Drop`) action carries
///        exactly the field compile consumes (a single-object action its `path`, a
///        rename its `rename` pair), so no forward reaches compile without its target.
///
/// An exhaustive generator sweeps the whole small input space and asserts all three
/// per case. This SUBSUMES the totality table's non-panic sweep: totality proved
/// classify RETURNS for every shape; the oracle proves it returns the RIGHT action.
mod classification_oracle {
  use super::*;

  /// The action taxonomy of [`Admission`], stripped of resolved paths — the level at
  /// which correctness is defined (which action, and for a rename whether a move-in
  /// walk is owed). Path BYTES are the map's resolution machinery, pinned by the
  /// targeted row tests; the oracle audits the DECISION.
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  enum Action {
    Forward,
    LearnDir,
    ForgetDir,
    /// A rename; `seed` is whether a moved-in subtree must be walked.
    Rename {
      seed: bool,
    },
    RootDeath,
    ForeignDrop,
    Lossy,
  }

  /// Projects a real [`Admission`] onto the action taxonomy.
  fn action_of(admission: &Admission) -> Action {
    match admission {
      Admission::Forward(_) => Action::Forward,
      Admission::LearnDir(_) => Action::LearnDir,
      Admission::ForgetDir(_) => Action::ForgetDir,
      Admission::Rename { seed, .. } => Action::Rename {
        seed: seed.is_some(),
      },
      Admission::RootDeath(_) => Action::RootDeath,
      Admission::ForeignDrop => Action::ForeignDrop,
      Admission::Lossy => Action::Lossy,
    }
  }

  /// The addressing object the SPEC resolves for a non-rename event, and its
  /// admittance — read-only against a fixed map state, shared by the oracle and the
  /// no-admitted-drop invariant.
  enum Addressing {
    /// A named event under an ADMITTED parent directory.
    Dirent,
    /// A name-less event whose ADMITTED self-object is the root anchor (`is_root`) or
    /// a non-root directory.
    SelfObject { is_root: bool },
    /// The addressing object is a genuine outsider (out-of-root) — the firehose.
    Foreign,
    /// No FID at all to address by.
    Unaddressable,
  }

  /// Resolves a non-rename event's addressing object and admittance from the SPEC: a
  /// named event's parent is `dir_fid`; a name-less event's own object is its self-FID
  /// (`dir_fid`, else the `FID`-only shape's `target_fid`). Admittance is a read-only
  /// path resolution (ancestry reaches the root), never mutating the map.
  fn addressing(map: &FidMap, event: &RawFanotifyEvent) -> Addressing {
    match event.name.as_ref() {
      Some(_) => match event.dir_fid.as_ref() {
        None => Addressing::Unaddressable,
        Some(parent) => {
          if map.resolve_path(parent).is_some() {
            Addressing::Dirent
          } else {
            Addressing::Foreign
          }
        }
      },
      None => match event.dir_fid.as_ref().or(event.target_fid.as_ref()) {
        None => Addressing::Unaddressable,
        Some(self_fid) => {
          if map.resolve_path(self_fid).is_some() {
            Addressing::SelfObject {
              is_root: map.is_root(self_fid),
            }
          } else {
            Addressing::Foreign
          }
        }
      },
    }
  }

  /// The SPEC's reference classifier: what SHOULD happen for `event` against `map`,
  /// derived from first principles (resolve addressing → drop outsiders → action by
  /// mask + required fields), NEVER from classify's code. Immutable — the oracle only
  /// reads the map, so it is evaluated on the pre-classify state classify then decides
  /// against.
  fn classify_oracle(map: &FidMap, event: &RawFanotifyEvent) -> Action {
    // A rename addresses two directory ends; at least one in-root admits it.
    if let Some(rename) = &event.rename {
      let old_in = map.resolve_path(&rename.old_dir).is_some();
      let new_in = map.resolve_path(&rename.new_dir).is_some();
      if !old_in && !new_in {
        return Action::ForeignDrop;
      }
      if event.mask.ondir() {
        // An ONDIR rename mutates the tree and REQUIRES the moved object's own FID.
        let Some(moved) = event.target_fid.as_ref() else {
          return Action::Lossy;
        };
        // A move IN from outside (destination in-root, moved object not yet known)
        // owes a subtree walk; every other in-root ONDIR rename is walk-free.
        let seed = new_in && !map.contains(moved);
        return Action::Rename { seed };
      }
      return Action::Rename { seed: false };
    }

    match addressing(map, event) {
      Addressing::Foreign | Addressing::Unaddressable => Action::ForeignDrop,
      Addressing::Dirent => dirent_action(event),
      Addressing::SelfObject { is_root } => nameless_action(event, is_root),
    }
  }

  /// The action a NAMED event under an admitted parent takes: a directory
  /// create/delete/move needs the child's `target_fid`; a file dirent or a
  /// non-structural directory modify/attrib needs none.
  fn dirent_action(event: &RawFanotifyEvent) -> Action {
    let mask = event.mask;
    if mask.ondir() {
      if mask.created() {
        return field_gated(event.target_fid.is_some(), Action::LearnDir);
      }
      if mask.removed() || mask.move_self() {
        return field_gated(event.target_fid.is_some(), Action::ForgetDir);
      }
    }
    Action::Forward
  }

  /// The action a NAME-LESS event on an admitted self-object takes: a root
  /// self-delete/move is the root's death; a non-root self-delete forgets; a self-move
  /// is a self-rescan; a bare modify/attrib is the object's own change; a name-less
  /// create/delete lost the child name it requires.
  fn nameless_action(event: &RawFanotifyEvent, is_root: bool) -> Action {
    let mask = event.mask;
    if mask.delete_self() || mask.move_self() {
      if is_root {
        return Action::RootDeath;
      }
      return if mask.delete_self() {
        Action::ForgetDir
      } else {
        Action::Forward
      };
    }
    if mask.created() || mask.removed() {
      return Action::Lossy;
    }
    Action::Forward
  }

  /// An action whose required field is present, else `Lossy`.
  fn field_gated(present: bool, action: Action) -> Action {
    if present { action } else { Action::Lossy }
  }

  /// The oracle's map: `/root` (fid 1, the root anchor), `/root/sub` (fid 2), and
  /// `/root/sub/child` (fid 3); fid 99 is a foreign handle outside the root.
  fn oracle_map() -> FidMap {
    let mut map = FidMap::new();
    map.seed([
      SeedEntry::root(fid(1), Path::new("/root")),
      SeedEntry::child(fid(2), fid(1), OsString::from("sub")),
      SeedEntry::child(fid(3), fid(2), OsString::from("child")),
    ]);
    map
  }

  /// Whether the event's addressing object is admitted — computed DIRECTLY from the
  /// map, independent of both classifiers, for the no-admitted-drop invariant. A
  /// rename is admitted when EITHER end is in-root.
  fn addressing_admitted(map: &FidMap, event: &RawFanotifyEvent) -> bool {
    if let Some(rename) = &event.rename {
      return map.resolve_path(&rename.old_dir).is_some()
        || map.resolve_path(&rename.new_dir).is_some();
    }
    matches!(
      addressing(map, event),
      Addressing::Dirent | Addressing::SelfObject { .. }
    )
  }

  /// Asserts the three contract properties for one event against a fresh map:
  /// AGREEMENT (classify's action == the oracle's), NO-ADMITTED-DROP (an admitted
  /// addressing object is never dropped), and FIELD-CORRECTNESS (a forwarded action
  /// carries the field compile consumes).
  fn assert_contract(label: &str, event: &RawFanotifyEvent) {
    let mut map = oracle_map();
    // The oracle reads the PRE-classify state; classify decides against the same state
    // (mutating as it acts). Snapshot both spec facts before classify runs.
    let expected = classify_oracle(&map, event);
    let admitted = addressing_admitted(&map, event);
    let admission = classify(&mut map, event, &mut MemoBatch::new());
    let got = action_of(&admission);

    // (1) Agreement: classify selects exactly the spec's action.
    assert_eq!(got, expected, "agreement `{label}`: {admission:?}");

    // (2) No-admitted-drop: an admitted addressing object is never the firehose drop.
    if admitted {
      assert_ne!(
        got,
        Action::ForeignDrop,
        "no-admitted-drop `{label}`: an admitted addressing object was dropped"
      );
    }

    // (3) Field-correctness: every forwarded action carries exactly the field compile
    // consumes — a single-object action its `path`, a rename its `rename` pair.
    match &admission {
      Admission::Forward(e)
      | Admission::LearnDir(e)
      | Admission::ForgetDir(e)
      | Admission::RootDeath(e) => assert!(
        e.path.is_some() && e.rename.is_none(),
        "field-correctness `{label}`: a single-object action must carry its path: {e:?}"
      ),
      Admission::Rename { event, .. } => assert!(
        event.rename.is_some() && event.path.is_none(),
        "field-correctness `{label}`: a rename must carry both halves: {event:?}"
      ),
      Admission::ForeignDrop | Admission::Lossy => {}
    }
  }

  /// The whole non-rename input space: every mask over the backend's vocabulary ×
  /// every `dir_fid`/`target_fid` drawn from {none, root, admitted child, foreign} ×
  /// every name shape {none, empty, present}. Empty folds to none at decode, but
  /// feeding it here proves classify and the oracle dispatch it identically.
  #[test]
  fn oracle_agrees_on_every_dirent_and_self_event_shape() {
    let masks = [
      FAN_CREATE,
      FAN_CREATE | FAN_ONDIR,
      FAN_DELETE,
      FAN_DELETE | FAN_ONDIR,
      FAN_MODIFY,
      FAN_MODIFY | FAN_ONDIR,
      FAN_ATTRIB,
      FAN_ATTRIB | FAN_ONDIR,
      FAN_DELETE_SELF,
      FAN_DELETE_SELF | FAN_ONDIR,
      FAN_MOVE_SELF,
      FAN_MOVE_SELF | FAN_ONDIR,
      FAN_DELETE_SELF | FAN_ATTRIB,
    ];
    let fids = [None, Some(fid(1)), Some(fid(2)), Some(fid(99))];
    let names: [Option<&[u8]>; 3] = [None, Some(b""), Some(b"n")];
    let mut checked = 0u64;
    for &mask in &masks {
      for dir in &fids {
        for target in &fids {
          for &name in &names {
            let event = RawFanotifyEvent {
              mask: FanMask::new(mask),
              dir_fid: dir.clone(),
              target_fid: target.clone(),
              name: name.map(<[u8]>::to_vec),
              rename: None,
            };
            assert_contract(
              &format!("mask={mask:#x} dir={dir:?} target={target:?} name={name:?}"),
              &event,
            );
            checked += 1;
          }
        }
      }
    }
    assert_eq!(checked, masks.len() as u64 * 4 * 4 * 3);
  }

  /// The whole rename input space: {file, ONDIR} × each directory end drawn from
  /// {root, admitted child, foreign} × the moved object's `target_fid` drawn from
  /// {none, root, admitted child, foreign}. Both names are present (a rename with a
  /// missing/empty half is wire-lossy and never reaches classify).
  #[test]
  fn oracle_agrees_on_every_rename_shape() {
    let masks = [FAN_RENAME, FAN_RENAME | FAN_ONDIR];
    let dirs = [fid(1), fid(2), fid(99)];
    let targets = [None, Some(fid(1)), Some(fid(2)), Some(fid(99))];
    let mut checked = 0u64;
    for &mask in &masks {
      for old_dir in &dirs {
        for new_dir in &dirs {
          for target in &targets {
            let event = RawFanotifyEvent {
              mask: FanMask::new(mask),
              dir_fid: None,
              target_fid: target.clone(),
              name: None,
              rename: Some(RenameInfo {
                old_dir: old_dir.clone(),
                old_name: b"old".to_vec(),
                new_dir: new_dir.clone(),
                new_name: b"new".to_vec(),
              }),
            };
            assert_contract(
              &format!("rename mask={mask:#x} old={old_dir:?} new={new_dir:?} target={target:?}"),
              &event,
            );
            checked += 1;
          }
        }
      }
    }
    assert_eq!(checked, masks.len() as u64 * 3 * 3 * 4);
  }

  /// The exact class the fix closes, isolated as a targeted row: a name-less
  /// ATTRIB/MODIFY addressed ONLY by `target_fid` (an admitted dir, or the root, with
  /// `dir_fid = None`) is FORWARDED on the object's OWN path — never the silent
  /// `ForeignDrop` the pre-classification `dir_fid == None` gate produced.
  #[test]
  fn fid_only_attrib_on_admitted_object_is_forwarded_not_dropped() {
    for (self_fid, own_path) in [(fid(1), "/root"), (fid(2), "/root/sub")] {
      for mask in [FAN_ATTRIB, FAN_MODIFY, FAN_ATTRIB | FAN_ONDIR] {
        let mut map = oracle_map();
        let event = self_fid_only(mask, self_fid.clone());
        let admission = classify(&mut map, &event, &mut MemoBatch::new());
        assert!(
          matches!(admission, Admission::Forward(_)),
          "a FID-only {mask:#x} on admitted {self_fid:?} forwards, not drops: {admission:?}"
        );
        assert_eq!(
          forwarded(admission).path.as_deref(),
          Some(Path::new(own_path)),
          "the forward carries the admitted object's OWN path"
        );
      }
    }
  }
}
