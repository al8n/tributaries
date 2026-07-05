use std::{
  ffi::OsString,
  path::{Path, PathBuf},
};

use super::{
  Admission, MemoBatch, admit,
  fid::{
    FAN_ATTRIB, FAN_CREATE, FAN_DELETE, FAN_DELETE_SELF, FAN_MODIFY, FAN_ONDIR, FAN_RENAME,
    FanMask, Fid, RawFanotifyEvent, RenameInfo,
  },
  map::{FidMap, SeedEntry},
};

fn fid(tag: u8) -> Fid {
  Fid::new([tag; 8], Box::from(&[tag][..]))
}

/// Admits a single event through a fresh one-shot memo — the per-event shape most
/// of these row tests use (the batch-spanning memo has its own suite below).
/// Returns the [`Admission`] so the caller can match its arm.
fn admit_one(map: &mut FidMap, event: &RawFanotifyEvent) -> Admission {
  admit(map, event, &mut MemoBatch::new())
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

/// A FILE create inside an admitted directory resolves to the child's absolute
/// path — the whole admitted form under the KR profile. Records carry no node
/// identity (design §4.9), so there is nothing beyond the path to assert.
#[test]
fn file_create_resolves_path() {
  let mut map = seeded();
  let ev = dirent(FAN_CREATE, fid(2), b"file.txt", Some(fid(7)));
  let Admission::Admit(admitted) = admit_one(&mut map, &ev) else {
    panic!("in-root create must admit");
  };
  assert_eq!(
    admitted.path.as_deref(),
    Some(Path::new("/root/sub/file.txt"))
  );
}

/// A DIRECTORY create resolves its path exactly like a file create — no identity
/// is attached to either (the no-identity contract, design §4.9). The directory's
/// membership self-maintenance is covered by
/// [`directory_create_is_learned`](directory_create_is_learned).
#[test]
fn directory_create_resolves_path() {
  let mut map = seeded();
  let ev = dirent(FAN_CREATE | FAN_ONDIR, fid(2), b"newdir", Some(fid(7)));
  let Admission::Admit(admitted) = admit_one(&mut map, &ev) else {
    panic!("in-root directory create must admit");
  };
  assert_eq!(
    admitted.path.as_deref(),
    Some(Path::new("/root/sub/newdir"))
  );
}

/// A long churn of DISTINCT file target FIDs never grows the map — files are not
/// admitted directories, so they never enter it. This is the O(live directories)
/// bound the no-identity model rests on: the memo-generation stays put because
/// a plain file event mutates nothing.
#[test]
fn file_event_churn_never_grows_the_map() {
  let mut map = seeded();
  let generation = map.generation();
  for tag in 20..120u8 {
    let modify = dirent(FAN_MODIFY, fid(2), b"f.txt", Some(fid(tag)));
    assert!(
      matches!(admit_one(&mut map, &modify), Admission::Admit(_)),
      "in-root file modify must admit"
    );
  }
  assert_eq!(
    map.dir_count(),
    2,
    "file-event churn left the map at the two seeded directories"
  );
  assert_eq!(
    map.generation(),
    generation,
    "a file event mutates nothing, so the generation is unchanged"
  );
}

/// An event whose directory FID is not in the map is provably outside the
/// watched root — the whole superblock-firehose filter — and is dropped.
#[test]
fn admit_drops_unknown_directory() {
  let mut map = seeded();
  let ev = dirent(FAN_MODIFY, fid(99), b"elsewhere", None);
  assert!(matches!(admit_one(&mut map, &ev), Admission::Drop));
}

/// A directory create self-maintains the map: the new directory's own later
/// events then admit.
#[test]
fn directory_create_is_learned() {
  let mut map = seeded();
  let ev = dirent(FAN_CREATE | FAN_ONDIR, fid(2), b"newdir", Some(fid(3)));
  let _ = admit_one(&mut map, &ev);
  // A modify inside the newly-learned directory now admits.
  let inside = dirent(FAN_MODIFY, fid(3), b"inside.txt", None);
  let Admission::Admit(admitted) = admit_one(&mut map, &inside) else {
    panic!("the learned directory must admit its own events");
  };
  assert_eq!(
    admitted.path.as_deref(),
    Some(Path::new("/root/sub/newdir/inside.txt"))
  );
}

/// A `DELETE_SELF` on an admitted directory resolves to that directory's own
/// path and forgets it (its stale handle stops admitting).
#[test]
fn delete_self_resolves_and_forgets() {
  let mut map = seeded();
  let ev = RawFanotifyEvent {
    mask: FanMask::new(FAN_DELETE_SELF | FAN_ONDIR),
    dir_fid: Some(fid(2)),
    target_fid: None,
    name: None,
    rename: None,
  };
  let Admission::Admit(admitted) = admit_one(&mut map, &ev) else {
    panic!("delete-self on an admitted directory must admit");
  };
  assert_eq!(admitted.path.as_deref(), Some(Path::new("/root/sub")));
  assert!(!map.contains_dir(&fid(2)), "the directory is forgotten");
}

/// A DIRECTORY delete reported as a PARENT dirent (`FAN_DELETE|ONDIR` with the
/// parent's `dir_fid`, the child name, AND the child's `target_fid`) forgets the
/// whole child subtree via that target FID — the well-formed counterpart to the
/// decode gate that makes a targetless one lossy. The deleted directory and its
/// descendants stop admitting, and the map returns to the pre-child count.
#[test]
fn directory_delete_dirent_forgets_the_subtree() {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("sub")),
    SeedEntry::child(fid(3), fid(2), OsString::from("child")),
  ]);
  // /root/sub (fid 2) is deleted: the parent /root (fid 1) reports the dirent with
  // the child's own FID as `target_fid`.
  let ev = dirent(FAN_DELETE | FAN_ONDIR, fid(1), b"sub", Some(fid(2)));
  let Admission::Admit(admitted) = admit_one(&mut map, &ev) else {
    panic!("an in-root directory delete must admit");
  };
  assert_eq!(admitted.path.as_deref(), Some(Path::new("/root/sub")));
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

/// A FILE `FAN_RENAME` with both ends in-root resolves both absolute paths in
/// one event — the atomic pair, no window. The admitted rename carries only the
/// two paths (no identity — design §4.9), and a file rename mutates nothing.
#[test]
fn file_rename_resolves_both_ends() {
  let mut map = seeded();
  let generation = map.generation();
  let ev = RawFanotifyEvent {
    mask: FanMask::new(FAN_RENAME),
    dir_fid: None,
    target_fid: Some(fid(8)),
    name: None,
    rename: Some(RenameInfo {
      old_dir: fid(1),
      old_name: b"a.txt".to_vec(),
      new_dir: fid(2),
      new_name: b"b.txt".to_vec(),
    }),
  };
  let Admission::Admit(admitted) = admit_one(&mut map, &ev) else {
    panic!("an in-root rename must admit");
  };
  let rename = admitted.rename.expect("rename info");
  assert_eq!(rename.old_path, PathBuf::from("/root/a.txt"));
  assert_eq!(rename.new_path, PathBuf::from("/root/sub/b.txt"));
  assert_eq!(
    map.generation(),
    generation,
    "a file rename left the map (and its two seeded directories) unchanged"
  );
}

/// A rename with BOTH ends outside the root is churn elsewhere on the
/// superblock and is dropped.
#[test]
fn rename_outside_root_is_dropped() {
  let mut map = seeded();
  let ev = RawFanotifyEvent {
    mask: FanMask::new(FAN_RENAME),
    dir_fid: None,
    target_fid: None,
    name: None,
    rename: Some(RenameInfo {
      old_dir: fid(90),
      old_name: b"x".to_vec(),
      new_dir: fid(91),
      new_name: b"y".to_vec(),
    }),
  };
  assert!(matches!(admit_one(&mut map, &ev), Admission::Drop));
}

/// A rename INTO the root (source outside, destination in-root) admits, with
/// the in-root end fully resolved.
#[test]
fn rename_into_root_admits_with_resolved_destination() {
  let mut map = seeded();
  let ev = RawFanotifyEvent {
    mask: FanMask::new(FAN_RENAME),
    dir_fid: None,
    target_fid: Some(fid(8)),
    name: None,
    rename: Some(RenameInfo {
      old_dir: fid(90),
      old_name: b"outside".to_vec(),
      new_dir: fid(2),
      new_name: b"arrived.txt".to_vec(),
    }),
  };
  let Admission::Admit(admitted) = admit_one(&mut map, &ev) else {
    panic!("a rename into the root must admit");
  };
  let rename = admitted.rename.expect("rename info");
  assert_eq!(rename.new_path, PathBuf::from("/root/sub/arrived.txt"));
}

/// A DIRECTORY moved IN from outside the root (its own FID unknown to the map,
/// destination parent in-root) returns [`Admission::AdmitAndSeed`]: the moved
/// directory carries pre-existing descendants the seed walk never saw, so the
/// reader must walk its subtree in. The request carries ONLY the moved
/// directory's FID (not a captured path — the reader resolves the current path
/// through the map at walk time), and the moved directory is already learned AND
/// marked `pending_walk` (its own later events admit; a `NotFound` at its resolved
/// path during the walk is an incompleteness, not a benign empty walk).
#[test]
fn dir_move_in_from_outside_requests_a_subtree_walk() {
  let mut map = seeded();
  // fid(9) — a directory that lived OUTSIDE the watched root, so it is unknown to
  // the seeded map — moves under /root/sub as `arrived`.
  assert!(!map.contains_dir(&fid(9)), "the moved dir starts unknown");
  let ev = RawFanotifyEvent {
    mask: FanMask::new(FAN_RENAME | FAN_ONDIR),
    dir_fid: None,
    target_fid: Some(fid(9)),
    name: None,
    rename: Some(RenameInfo {
      old_dir: fid(90),
      old_name: b"arrived".to_vec(),
      new_dir: fid(2),
      new_name: b"arrived".to_vec(),
    }),
  };
  let Admission::AdmitAndSeed { event, moved_fid } = admit_one(&mut map, &ev) else {
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
  // The moved directory itself is learned as a pending-walk top; the reader will
  // resolve its CURRENT path through the map at walk time.
  assert_eq!(
    map.pending_walk_target(&fid(9)),
    Some((PathBuf::from("/root/sub/arrived"), true)),
    "the moved directory is admitted and pending its subtree walk"
  );
}

/// An IN-ROOT directory rename (the moved directory was ALREADY a known in-root
/// directory, so its descendants are already mapped) returns a plain
/// [`Admission::Admit`] — NO subtree walk. The completeness invariant is met by
/// the parent-relative re-parent, not by a walk.
#[test]
fn in_root_dir_rename_requests_no_walk() {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("sub")),
    // A second in-root parent to receive the moved directory.
    SeedEntry::child(fid(4), fid(1), OsString::from("dest")),
  ]);
  let ev = RawFanotifyEvent {
    mask: FanMask::new(FAN_RENAME | FAN_ONDIR),
    dir_fid: None,
    // The moved directory fid(2) is already in-root (known) — an in-root rename.
    target_fid: Some(fid(2)),
    name: None,
    rename: Some(RenameInfo {
      old_dir: fid(1),
      old_name: b"sub".to_vec(),
      new_dir: fid(4),
      new_name: b"sub".to_vec(),
    }),
  };
  assert!(
    matches!(admit_one(&mut map, &ev), Admission::Admit(_)),
    "an in-root rename of an already-mapped directory needs no subtree walk"
  );
  assert_eq!(
    map.admit(&fid(2)),
    Some(PathBuf::from("/root/dest/sub")),
    "the moved directory re-parents under the new in-root parent"
  );
}

/// A directory moved OUT then straight back IN re-walks: the move-out forgets it
/// (the fresh-identity direction), so on the way back it is UNKNOWN again — a
/// move-in, which re-requests the subtree walk. Its descendants are re-seeded
/// with fresh identities, never reusing the departed ones (forget prunes the id,
/// so a reappearance mints anew — the conservative direction).
#[test]
fn dir_move_out_then_back_in_re_walks() {
  let mut map = seeded();
  // Move fid(2) (in-root /root/sub) OUT to an out-of-root parent: forgotten.
  let out = RawFanotifyEvent {
    mask: FanMask::new(FAN_RENAME | FAN_ONDIR),
    dir_fid: None,
    target_fid: Some(fid(2)),
    name: None,
    rename: Some(RenameInfo {
      old_dir: fid(1),
      old_name: b"sub".to_vec(),
      new_dir: fid(90),
      new_name: b"sub".to_vec(),
    }),
  };
  assert!(matches!(admit_one(&mut map, &out), Admission::Admit(_)));
  assert!(!map.contains_dir(&fid(2)), "the moved-out dir is forgotten");

  // Move it back IN under /root (the root fid(1) is in-root): now unknown, so it
  // is a move-in and re-requests the walk.
  let back = RawFanotifyEvent {
    mask: FanMask::new(FAN_RENAME | FAN_ONDIR),
    dir_fid: None,
    target_fid: Some(fid(2)),
    name: None,
    rename: Some(RenameInfo {
      old_dir: fid(90),
      old_name: b"sub".to_vec(),
      new_dir: fid(1),
      new_name: b"sub".to_vec(),
    }),
  };
  assert!(
    matches!(admit_one(&mut map, &back), Admission::AdmitAndSeed { .. }),
    "a move back in from outside re-requests the subtree walk"
  );
}

/// A populated directory moved IN to /root/a then IMMEDIATELY renamed in-root to
/// /root/b in the SAME batch, driven through the admit seam. The first admit learns
/// the moved dir pending (its deferred walk not yet run); the second admit is an
/// in-root re-parent (the dir is now KNOWN) that must KEEP it pending and re-parent
/// it, so the still-owed walk resolves the CURRENT path /root/b — NOT the stale
/// /root/a — and maps the descendants. Without the pending flag and current-path
/// resolution, the walk would see the already-vanished /root/a as an empty success
/// and the second rename would see a known FID and skip the walk, leaving the
/// descendants blind forever.
#[test]
fn burst_move_in_then_in_root_rename_keeps_walk_pending_at_current_path() {
  let mut map = FidMap::new();
  // /root with two in-root destination parents a and b.
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("a")),
    SeedEntry::child(fid(3), fid(1), OsString::from("b")),
  ]);
  // Event 1: populated dir fid(9) moved IN from outside under /root/a.
  let move_in = RawFanotifyEvent {
    mask: FanMask::new(FAN_RENAME | FAN_ONDIR),
    dir_fid: None,
    target_fid: Some(fid(9)),
    name: None,
    rename: Some(RenameInfo {
      old_dir: fid(90),
      old_name: b"moved".to_vec(),
      new_dir: fid(2),
      new_name: b"moved".to_vec(),
    }),
  };
  assert!(
    matches!(
      admit_one(&mut map, &move_in),
      Admission::AdmitAndSeed { .. }
    ),
    "the move-in requests a subtree walk"
  );
  assert_eq!(
    map.pending_walk_target(&fid(9)),
    Some((PathBuf::from("/root/a/moved"), true)),
    "after event 1 the moved dir is pending at /root/a"
  );

  // Event 2 (SAME batch, BEFORE the deferred walk runs): /root/a/moved renamed
  // in-root to /root/b/moved. The dir is now KNOWN, so this is an in-root
  // re-parent — a plain Admit, no second walk requested.
  let in_root = RawFanotifyEvent {
    mask: FanMask::new(FAN_RENAME | FAN_ONDIR),
    dir_fid: None,
    target_fid: Some(fid(9)),
    name: None,
    rename: Some(RenameInfo {
      old_dir: fid(2),
      old_name: b"moved".to_vec(),
      new_dir: fid(3),
      new_name: b"moved".to_vec(),
    }),
  };
  assert!(
    matches!(admit_one(&mut map, &in_root), Admission::Admit(_)),
    "the in-root re-parent of the now-known dir needs no second walk"
  );
  // The still-owed walk (requested by event 1) now resolves the CURRENT path —
  // the re-parent moved it to /root/b, and the flag stayed set so the reader will
  // walk it there rather than skip it.
  assert_eq!(
    map.pending_walk_target(&fid(9)),
    Some((PathBuf::from("/root/b/moved"), true)),
    "the deferred walk target followed the in-root re-parent to /root/b and stays pending"
  );
  map.assert_adjacency();
}

/// A FILE moved in from outside (non-directory target) never requests a subtree
/// walk — only directories carry descendants. The move admits plainly with the
/// destination path resolved.
#[test]
fn file_move_in_requests_no_walk() {
  let mut map = seeded();
  let ev = RawFanotifyEvent {
    mask: FanMask::new(FAN_RENAME),
    dir_fid: None,
    target_fid: Some(fid(9)),
    name: None,
    rename: Some(RenameInfo {
      old_dir: fid(90),
      old_name: b"f.txt".to_vec(),
      new_dir: fid(2),
      new_name: b"f.txt".to_vec(),
    }),
  };
  assert!(
    matches!(admit_one(&mut map, &ev), Admission::Admit(_)),
    "a file move-in carries no descendants, so no walk"
  );
}

/// A directory `FAN_RENAME` within the root re-parents the moved directory's
/// whole subtree: after the rename, a pre-seeded descendant's own event
/// resolves under the NEW path — the parent-relative map, not a stale absolute
/// one. (`/root/sub` renamed to `/root/moved`; a child under it follows.)
#[test]
fn dir_rename_reparents_descendants() {
  let mut map = FidMap::new();
  // /root, /root/sub (fid 2), /root/sub/child (fid 3, pre-seeded).
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("sub")),
    SeedEntry::child(fid(3), fid(2), OsString::from("child")),
  ]);

  // Rename the directory fid(2) from /root/sub to /root/moved (same parent,
  // new name). The moved object's own FID is target_fid; both ends in-root.
  let rename = RawFanotifyEvent {
    mask: FanMask::new(FAN_RENAME | FAN_ONDIR),
    dir_fid: None,
    target_fid: Some(fid(2)),
    name: None,
    rename: Some(RenameInfo {
      old_dir: fid(1),
      old_name: b"sub".to_vec(),
      new_dir: fid(1),
      new_name: b"moved".to_vec(),
    }),
  };
  assert!(matches!(admit_one(&mut map, &rename), Admission::Admit(_)));

  // A later modify on the PRE-SEEDED child resolves under the new parent path.
  let child_event = dirent(FAN_MODIFY, fid(3), b"leaf.txt", None);
  let Admission::Admit(admitted) = admit_one(&mut map, &child_event) else {
    panic!("the descendant must still admit after the parent rename");
  };
  assert_eq!(
    admitted.path.as_deref(),
    Some(Path::new("/root/moved/child/leaf.txt")),
    "the descendant resolves under the renamed parent, not the stale path"
  );
}

/// An in-root directory rename RE-PARENTS the moved directory in place (the map
/// keeps its membership node, so its descendants follow via the parent link) and
/// resolves the pair's paths. No identity rides the rename (design §4.9).
#[test]
fn dir_rename_in_root_reparents_and_keeps_membership() {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("sub")),
    SeedEntry::child(fid(3), fid(2), OsString::from("child")),
  ]);

  let rename = RawFanotifyEvent {
    mask: FanMask::new(FAN_RENAME | FAN_ONDIR),
    dir_fid: None,
    target_fid: Some(fid(2)),
    name: None,
    rename: Some(RenameInfo {
      old_dir: fid(1),
      old_name: b"sub".to_vec(),
      new_dir: fid(1),
      new_name: b"moved".to_vec(),
    }),
  };
  let Admission::Admit(admitted) = admit_one(&mut map, &rename) else {
    panic!("an in-root directory rename must admit");
  };
  let rename = admitted.rename.expect("rename info");
  assert_eq!(rename.old_path, PathBuf::from("/root/sub"));
  assert_eq!(rename.new_path, PathBuf::from("/root/moved"));
  // The moved directory keeps its membership node under the new name, and its
  // pre-seeded child resolves under the re-parented path — no per-node rewrite.
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

/// A directory moved OUT of the root is FORGOTTEN (it departed the map), bounding
/// the map at the live directory count. A later move back re-enters through its
/// own move-in event — the map holds only membership.
#[test]
fn dir_move_out_forgets_the_directory() {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("sub")),
  ]);

  let rename = RawFanotifyEvent {
    mask: FanMask::new(FAN_RENAME | FAN_ONDIR),
    dir_fid: None,
    target_fid: Some(fid(2)),
    name: None,
    rename: Some(RenameInfo {
      old_dir: fid(1),
      old_name: b"sub".to_vec(),
      new_dir: fid(90),
      new_name: b"sub".to_vec(),
    }),
  };
  assert!(matches!(admit_one(&mut map, &rename), Admission::Admit(_)));
  assert_eq!(
    map.dir_count(),
    1,
    "the departed directory was forgotten — only the root remains"
  );
  assert_eq!(map.admit(&fid(2)), None, "and it no longer admits");
}

/// A directory moved OUT of the root stops admitting its descendants: after the
/// move-out, a pre-seeded child's event does NOT admit — no stale in-root path
/// is emitted for out-of-root activity.
#[test]
fn dir_move_out_of_root_stops_descendant_admission() {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("sub")),
    SeedEntry::child(fid(3), fid(2), OsString::from("child")),
  ]);

  // Move /root/sub OUT to an out-of-root directory (fid 90, not in the map):
  // the destination end does not admit, so only the old admission is dropped.
  let rename = RawFanotifyEvent {
    mask: FanMask::new(FAN_RENAME | FAN_ONDIR),
    dir_fid: None,
    target_fid: Some(fid(2)),
    name: None,
    rename: Some(RenameInfo {
      old_dir: fid(1),
      old_name: b"sub".to_vec(),
      new_dir: fid(90),
      new_name: b"sub".to_vec(),
    }),
  };
  // The rename still admits (the old end is in-root — a move across the
  // boundary is the tree's business), but the map self-maintenance detaches
  // the subtree.
  assert!(matches!(admit_one(&mut map, &rename), Admission::Admit(_)));

  // A later event on the pre-seeded descendant is now outside the root.
  let child_event = dirent(FAN_MODIFY, fid(3), b"leaf.txt", None);
  assert!(
    matches!(admit_one(&mut map, &child_event), Admission::Drop),
    "a descendant of a moved-out directory no longer admits"
  );
}

/// An attrib event on a file in an admitted directory resolves its path — the
/// whole admitted form (no identity, design §4.9).
#[test]
fn attrib_resolves_its_path() {
  let mut map = seeded();
  let ev = dirent(FAN_ATTRIB, fid(1), b"meta.txt", None);
  let Admission::Admit(admitted) = admit_one(&mut map, &ev) else {
    panic!("must admit");
  };
  assert_eq!(admitted.path.as_deref(), Some(Path::new("/root/meta.txt")));
}

/// The batch admission memo (design §4.9): the reader shares ONE [`MemoBatch`]
/// across a read buffer, so a second event under an already-resolved directory
/// hits the cache, while a map MUTATION between two events bumps the generation
/// and forces the second to miss — the generation-tagged soundness argument.
mod batch_memo {
  use super::*;

  /// Two events under the SAME directory in one batch: the first resolves the
  /// directory against the map (a miss that fills the cache), the second is served
  /// from the memo (a hit) — the rename-storm win.
  #[test]
  fn second_event_under_same_dir_hits() {
    let mut map = seeded();
    let mut memo = MemoBatch::new();
    // Two file modifies under /root/sub (dir fid 2), no mutation between them.
    let a = dirent(FAN_MODIFY, fid(2), b"a.txt", None);
    let b = dirent(FAN_MODIFY, fid(2), b"b.txt", None);
    assert!(matches!(
      admit(&mut map, &a, &mut memo),
      Admission::Admit(_)
    ));
    assert_eq!((memo.hits, memo.misses), (0, 1), "the first is a cold miss");
    assert!(matches!(
      admit(&mut map, &b, &mut memo),
      Admission::Admit(_)
    ));
    assert_eq!(
      (memo.hits, memo.misses),
      (1, 1),
      "the second under the same dir is a memo hit"
    );
  }

  /// A mutation between two events under the same directory (a `learn` of a new
  /// child) bumps the map generation, so a lookup AFTER the mutation finds its
  /// pre-mutation tag stale and re-resolves — a miss. The memo can never serve a
  /// path the map mutated out from under it.
  ///
  /// The ordering within one `admit` matters: the directory lookup runs BEFORE any
  /// learn/forget the event performs, so the learning event itself still HITS its
  /// directory (its entry was tagged current at lookup time); only the NEXT event's
  /// lookup sees the post-learn generation and misses.
  #[test]
  fn a_learn_between_events_invalidates_the_memo() {
    let mut map = seeded();
    let mut memo = MemoBatch::new();
    // Event 1: a file modify under /root/sub — a cold miss that fills dir fid 2.
    let modify = dirent(FAN_MODIFY, fid(2), b"a.txt", None);
    assert!(matches!(
      admit(&mut map, &modify, &mut memo),
      Admission::Admit(_)
    ));
    assert_eq!((memo.hits, memo.misses), (0, 1));
    // Event 2: a DIRECTORY create under /root/sub. Its dir-fid-2 lookup runs first
    // (a HIT — still current), THEN the learn bumps the generation.
    let mkdir = dirent(FAN_CREATE | FAN_ONDIR, fid(2), b"newdir", Some(fid(3)));
    assert!(matches!(
      admit(&mut map, &mkdir, &mut memo),
      Admission::Admit(_)
    ));
    assert_eq!(
      (memo.hits, memo.misses),
      (1, 1),
      "the learning event still hits its directory — the lookup precedes its mutation"
    );
    // Event 3: another modify under /root/sub. Its memo entry was tagged BEFORE the
    // learn, so the stale generation forces a re-resolve — a miss, not a hit.
    let modify2 = dirent(FAN_MODIFY, fid(2), b"b.txt", None);
    assert!(matches!(
      admit(&mut map, &modify2, &mut memo),
      Admission::Admit(_)
    ));
    assert_eq!(
      (memo.hits, memo.misses),
      (1, 2),
      "the post-learn lookup re-resolves: the learn invalidated the pre-learn entry"
    );
  }

  /// A `forget` (rename-out / delete of a directory) likewise invalidates the memo
  /// via the generation bump: a later event that would otherwise hit misses.
  #[test]
  fn a_forget_invalidates_the_memo() {
    let mut map = FidMap::new();
    map.seed([
      SeedEntry::root(fid(1), Path::new("/root")),
      SeedEntry::child(fid(2), fid(1), OsString::from("a")),
      SeedEntry::child(fid(3), fid(1), OsString::from("b")),
    ]);
    let mut memo = MemoBatch::new();
    // Fill the memo for dir fid 1 (the root) via an event under it.
    let under_root = dirent(FAN_MODIFY, fid(1), b"x.txt", None);
    assert!(matches!(
      admit(&mut map, &under_root, &mut memo),
      Admission::Admit(_)
    ));
    // Delete directory /root/b (a DELETE_SELF forgets it) — a mutation.
    let delete_b = RawFanotifyEvent {
      mask: FanMask::new(super::FAN_DELETE_SELF | FAN_ONDIR),
      dir_fid: Some(fid(3)),
      target_fid: None,
      name: None,
      rename: None,
    };
    assert!(matches!(
      admit(&mut map, &delete_b, &mut memo),
      Admission::Admit(_)
    ));
    // Another event under the root: the pre-forget memo entry is stale → miss.
    let under_root2 = dirent(FAN_MODIFY, fid(1), b"y.txt", None);
    assert!(matches!(
      admit(&mut map, &under_root2, &mut memo),
      Admission::Admit(_)
    ));
    assert_eq!(memo.hits, 0, "the forget invalidated the root's memo entry");
  }

  /// A fresh memo (a new read batch) starts empty — the reader builds one per
  /// buffer, so the memo is cleared at batch end by construction and a resolution
  /// in one batch never leaks into the next.
  #[test]
  fn a_fresh_batch_memo_starts_cold() {
    let mut map = seeded();
    let modify = dirent(FAN_MODIFY, fid(2), b"a.txt", None);
    // Batch 1 resolves dir fid 2 (a miss that fills batch 1's memo).
    let mut first = MemoBatch::new();
    assert!(matches!(
      admit(&mut map, &modify, &mut first),
      Admission::Admit(_)
    ));
    assert_eq!((first.hits, first.misses), (0, 1));
    // Batch 2 (a new buffer) starts cold: the same directory misses again.
    let mut second = MemoBatch::new();
    assert!(matches!(
      admit(&mut map, &modify, &mut second),
      Admission::Admit(_)
    ));
    assert_eq!(
      (second.hits, second.misses),
      (0, 1),
      "a new batch memo does not inherit the prior batch's entries"
    );
  }
}
