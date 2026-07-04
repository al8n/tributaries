use std::path::{Path, PathBuf};

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
    SeedEntry::new(fid(1), PathBuf::from("/root")),
    SeedEntry::new(fid(2), PathBuf::from("/root/sub")),
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

/// A create inside an admitted directory resolves to the child's absolute
/// path and interns the child's target FID as the record identity.
#[test]
fn admit_resolves_path_and_identity() {
  let mut map = seeded();
  let ev = dirent(FAN_CREATE, fid(2), b"file.txt", Some(fid(7)));
  let Admission::Admit(admitted) = admit(&mut map, &ev) else {
    panic!("in-root create must admit");
  };
  assert_eq!(
    admitted.path.as_deref(),
    Some(Path::new("/root/sub/file.txt"))
  );
  assert!(admitted.identity.is_some());
  assert_eq!(
    admitted.identity,
    Some(map.intern(&fid(7))),
    "the identity is the interned target FID"
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

/// A `FAN_RENAME` with both ends in-root resolves both absolute paths in one
/// event — the atomic pair, no window.
#[test]
fn rename_resolves_both_ends() {
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
  assert!(rename.identity.is_some());
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
