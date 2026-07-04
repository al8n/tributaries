use std::{
  ffi::OsString,
  path::{Path, PathBuf},
};

use super::{
  Admission, admit,
  fid::{
    FAN_ATTRIB, FAN_CREATE, FAN_DELETE_SELF, FAN_MODIFY, FAN_ONDIR, FAN_RENAME, FanMask, Fid,
    RawFanotifyEvent, RenameInfo,
  },
  map::{FidMap, SeedEntry},
};

fn fid(tag: u8) -> Fid {
  Fid::new([tag; 8], Box::from(&[tag][..]))
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
/// path but attaches NO identity even when the kernel supplied a target FID:
/// identity is directory-only (interning file targets would grow the map's
/// intern table unboundedly under churn), and file identity is inert under the
/// kernel-recursive Monitor profile regardless.
#[test]
fn file_create_resolves_path_with_no_identity() {
  let mut map = seeded();
  let ev = dirent(FAN_CREATE, fid(2), b"file.txt", Some(fid(7)));
  let Admission::Admit(admitted) = admit(&mut map, &ev) else {
    panic!("in-root create must admit");
  };
  assert_eq!(
    admitted.path.as_deref(),
    Some(Path::new("/root/sub/file.txt"))
  );
  assert!(
    admitted.identity.is_none(),
    "a file target FID is never interned — identity is directory-only"
  );
}

/// A DIRECTORY create resolves its path AND interns the directory's target FID
/// as the record identity (directory handles are already required for admission,
/// so interning them is free and bounded by the directory count).
#[test]
fn directory_create_resolves_path_and_identity() {
  let mut map = seeded();
  let ev = dirent(FAN_CREATE | FAN_ONDIR, fid(2), b"newdir", Some(fid(7)));
  let Admission::Admit(admitted) = admit(&mut map, &ev) else {
    panic!("in-root directory create must admit");
  };
  assert_eq!(
    admitted.path.as_deref(),
    Some(Path::new("/root/sub/newdir"))
  );
  assert_eq!(
    admitted.identity,
    Some(map.intern(&fid(7))),
    "a directory target FID is interned as the record identity"
  );
}

/// Neither a file modify nor a file attrib carrying a target FID mints an
/// identity — the intern table never grows on file events, the whole point of
/// the O(directories) bound. A create/delete churn of files therefore leaves the
/// table untouched.
#[test]
fn file_events_never_intern_their_target() {
  let mut map = seeded();
  // A long churn of DISTINCT file target FIDs on file (non-ONDIR) events.
  for tag in 20..120u8 {
    let modify = dirent(FAN_MODIFY, fid(2), b"f.txt", Some(fid(tag)));
    let Admission::Admit(admitted) = admit(&mut map, &modify) else {
      panic!("in-root file modify must admit");
    };
    assert!(
      admitted.identity.is_none(),
      "a file modify never interns its target FID"
    );
  }
  // The intern table still holds only the two seeded directories: no file target
  // ever entered it.
  assert_eq!(
    map.interned_count(),
    2,
    "file-event churn left the intern table at O(live directories)"
  );
}

/// An event whose directory FID is not in the map is provably outside the
/// watched root — the whole superblock-firehose filter — and is dropped.
#[test]
fn admit_drops_unknown_directory() {
  let mut map = seeded();
  let ev = dirent(FAN_MODIFY, fid(99), b"elsewhere", None);
  assert!(matches!(admit(&mut map, &ev), Admission::Drop));
}

/// A directory create self-maintains the map: the new directory's own later
/// events then admit.
#[test]
fn directory_create_is_learned() {
  let mut map = seeded();
  let ev = dirent(FAN_CREATE | FAN_ONDIR, fid(2), b"newdir", Some(fid(3)));
  let _ = admit(&mut map, &ev);
  // A modify inside the newly-learned directory now admits.
  let inside = dirent(FAN_MODIFY, fid(3), b"inside.txt", None);
  let Admission::Admit(admitted) = admit(&mut map, &inside) else {
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
  let Admission::Admit(admitted) = admit(&mut map, &ev) else {
    panic!("delete-self on an admitted directory must admit");
  };
  assert_eq!(admitted.path.as_deref(), Some(Path::new("/root/sub")));
  assert!(!map.contains_dir(&fid(2)), "the directory is forgotten");
}

/// A FILE `FAN_RENAME` with both ends in-root resolves both absolute paths in
/// one event — the atomic pair, no window — with NO identity (a file target is
/// never interned).
#[test]
fn file_rename_resolves_both_ends_without_identity() {
  let mut map = seeded();
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
  let Admission::Admit(admitted) = admit(&mut map, &ev) else {
    panic!("an in-root rename must admit");
  };
  let rename = admitted.rename.expect("rename info");
  assert_eq!(rename.old_path, PathBuf::from("/root/a.txt"));
  assert_eq!(rename.new_path, PathBuf::from("/root/sub/b.txt"));
  assert!(
    rename.identity.is_none(),
    "a file rename target FID is never interned"
  );
  assert_eq!(
    map.interned_count(),
    2,
    "a file rename left the intern table at the two seeded directories"
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
  assert!(matches!(admit(&mut map, &ev), Admission::Drop));
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
  let Admission::Admit(admitted) = admit(&mut map, &ev) else {
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
  let Admission::AdmitAndSeed { event, moved_fid } = admit(&mut map, &ev) else {
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
    matches!(admit(&mut map, &ev), Admission::Admit(_)),
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
  assert!(matches!(admit(&mut map, &out), Admission::Admit(_)));
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
    matches!(admit(&mut map, &back), Admission::AdmitAndSeed { .. }),
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
    matches!(admit(&mut map, &move_in), Admission::AdmitAndSeed { .. }),
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
    matches!(admit(&mut map, &in_root), Admission::Admit(_)),
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
    matches!(admit(&mut map, &ev), Admission::Admit(_)),
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
  assert!(matches!(admit(&mut map, &rename), Admission::Admit(_)));

  // A later modify on the PRE-SEEDED child resolves under the new parent path.
  let child_event = dirent(FAN_MODIFY, fid(3), b"leaf.txt", None);
  let Admission::Admit(admitted) = admit(&mut map, &child_event) else {
    panic!("the descendant must still admit after the parent rename");
  };
  assert_eq!(
    admitted.path.as_deref(),
    Some(Path::new("/root/moved/child/leaf.txt")),
    "the descendant resolves under the renamed parent, not the stale path"
  );
}

/// An in-root directory rename PRESERVES the moved directory's identity: the same
/// object keeps its interned id across the move (the re-parent overwrites its node
/// in place rather than pruning-then-re-minting), so the Monitor never mistakes a
/// renamed directory for a replacement.
#[test]
fn dir_rename_in_root_preserves_identity() {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("sub")),
  ]);
  let before = map.intern(&fid(2));
  let count_before = map.interned_count();

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
  let Admission::Admit(admitted) = admit(&mut map, &rename) else {
    panic!("an in-root directory rename must admit");
  };
  assert_eq!(
    admitted.rename.and_then(|r| r.identity),
    Some(before),
    "the rename reports the moved directory's stable identity"
  );
  assert_eq!(
    map.intern(&fid(2)),
    before,
    "the renamed directory keeps its interned id — no fork across the move"
  );
  assert_eq!(
    map.interned_count(),
    count_before,
    "an in-root rename does not grow the intern table"
  );
}

/// A directory moved OUT of the root has its identity PRUNED (it departed the
/// map), bounding the intern table at the live directory count. A later move back
/// would mint a fresh id — the conservative direction the Monitor reads as a
/// replacement.
#[test]
fn dir_move_out_prunes_identity() {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), OsString::from("sub")),
  ]);
  let departed = map.intern(&fid(2));

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
  assert!(matches!(admit(&mut map, &rename), Admission::Admit(_)));
  assert_eq!(
    map.interned_count(),
    1,
    "the departed directory's id was pruned — only the root remains"
  );
  // A reappearance mints a FRESH id (identity discontinuity for a
  // departed-and-returned directory — the safe direction).
  assert_ne!(
    map.intern(&fid(2)),
    departed,
    "a returned directory mints a new identity"
  );
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
  assert!(matches!(admit(&mut map, &rename), Admission::Admit(_)));

  // A later event on the pre-seeded descendant is now outside the root.
  let child_event = dirent(FAN_MODIFY, fid(3), b"leaf.txt", None);
  assert!(
    matches!(admit(&mut map, &child_event), Admission::Drop),
    "a descendant of a moved-out directory no longer admits"
  );
}

/// An attrib event on a file in an admitted directory resolves its path with no
/// identity when the kernel reported no target FID (the file's identity stays
/// enumerate-sourced).
#[test]
fn attrib_without_target_fid_has_no_identity() {
  let mut map = seeded();
  let ev = dirent(FAN_ATTRIB, fid(1), b"meta.txt", None);
  let Admission::Admit(admitted) = admit(&mut map, &ev) else {
    panic!("must admit");
  };
  assert_eq!(admitted.path.as_deref(), Some(Path::new("/root/meta.txt")));
  assert!(admitted.identity.is_none());
}
