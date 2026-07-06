use std::{
  ffi::OsString,
  path::{Path, PathBuf},
};

use super::{
  Admission, AdmittedEvent, MemoBatch, classify,
  fid::{
    FAN_ATTRIB, FAN_CREATE, FAN_DELETE, FAN_DELETE_SELF, FAN_EVENT_INFO_TYPE_DFID_NAME, FAN_MODIFY,
    FAN_MOVE_SELF, FAN_ONDIR, FAN_RENAME, FanMask, Fid, RawFanotifyEvent, RenameInfo,
    decode_events,
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

/// The exact `Fid` `decode_events` yields from a wire FID: the stored handle is
/// `handle_type` (native-endian i32) followed by `opaque`, so a map seeded with
/// this matches the decoded event's FID byte-for-byte (the map keys on the handle
/// bytes). Lets the decode→classify rows below seed a map the decoded "." buffer
/// then resolves against.
fn wire_fid(fsid: [u8; 8], handle_type: i32, opaque: &[u8]) -> Fid {
  let mut handle = handle_type.to_ne_bytes().to_vec();
  handle.extend_from_slice(opaque);
  Fid::new(fsid, handle.into_boxed_slice())
}

/// A one-record fanotify buffer: a single `DFID_NAME` info record (fsid + file
/// handle + a NUL-terminated `name`) wrapped in an event of `mask` — the packed
/// wire shape the kernel delivers a directory self-event in when it uses the "."
/// self-name. Mirrors the layout `decode_events` parses (see the `fid` suite's
/// builders); kept local so the decode→classify rows exercise the real decode.
fn dfid_name_event(
  mask: u64,
  fsid: [u8; 8],
  handle_type: i32,
  opaque: &[u8],
  name: &[u8],
) -> Vec<u8> {
  // struct file_handle: handle_bytes (u32) + handle_type (i32) + opaque bytes.
  let mut fh = (opaque.len() as u32).to_ne_bytes().to_vec();
  fh.extend_from_slice(&handle_type.to_ne_bytes());
  fh.extend_from_slice(opaque);
  // DFID_NAME payload: fsid + file_handle + NUL-terminated name.
  let mut payload = fsid.to_vec();
  payload.extend_from_slice(&fh);
  payload.extend_from_slice(name);
  payload.push(0);
  // info record header: info_type (u8) + pad (u8) + record_len (u16).
  let record_len = (4 + payload.len()) as u16;
  let mut info = vec![FAN_EVENT_INFO_TYPE_DFID_NAME, 0];
  info.extend_from_slice(&record_len.to_ne_bytes());
  info.extend_from_slice(&payload);
  // fanotify_event_metadata (24 bytes) + the info region.
  let event_len = (24 + info.len()) as u32;
  let mut buf = event_len.to_ne_bytes().to_vec();
  buf.push(3); // vers
  buf.push(0); // reserved
  buf.extend_from_slice(&24u16.to_ne_bytes()); // metadata_len
  buf.extend_from_slice(&mask.to_ne_bytes());
  buf.extend_from_slice(&(-1i32).to_ne_bytes()); // fd = FAN_NOFD
  buf.extend_from_slice(&0i32.to_ne_bytes()); // pid
  buf.extend_from_slice(&info);
  buf
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

/// The WATCHED ROOT deleted from its FOREIGN parent, reported as a pure
/// `FAN_DELETE|FAN_ONDIR` dirent (`dir_fid` = the root's out-of-root parent, name = the
/// root's name, `target_fid` = the root anchor itself). The dir_fid-only gate dropped this
/// as firehose noise — losing the root's death to the liveness tick; the action-aware
/// foreign-parent path consults `target_fid` and routes it to `RootDeath` on the root's OWN
/// path, normalized to the `DELETE_SELF` self form compile lowers to a terminal Removed +
/// Rescan. The map is untouched (a read-only decision).
#[test]
fn root_delete_from_foreign_parent_is_root_death() {
  let mut map = seeded();
  let generation = map.generation();
  let ev = dirent(FAN_DELETE | FAN_ONDIR, fid(99), b"root", Some(fid(1)));
  let admission = classify_one(&mut map, &ev);
  assert!(
    matches!(admission, Admission::RootDeath(_)),
    "the root deleted from its foreign parent is RootDeath, not a firehose drop: {admission:?}"
  );
  let event = forwarded(admission);
  assert_eq!(
    event.path.as_deref(),
    Some(Path::new("/root")),
    "RootDeath carries the root's OWN path, never a <foreign-parent>/root child"
  );
  assert!(
    event.mask.delete_self(),
    "a dirent-reported root delete normalizes to the DELETE_SELF self form for compile"
  );
  assert_eq!(
    map.generation(),
    generation,
    "the foreign-parent root death is a read-only decision — the map is untouched"
  );
}

/// The WATCHED ROOT renamed/moved between two FOREIGN parents, reported as a pure
/// `FAN_RENAME|FAN_ONDIR` whose `target_fid` is the root anchor while BOTH ends are
/// out-of-root. The both-ends-out gate dropped it; the action-aware path routes it to
/// `RootDeath` normalized to `MOVE_SELF` (compile's terminal Rescan — a moved root's new
/// path is unknowable).
#[test]
fn root_rename_from_foreign_parents_is_root_death() {
  let mut map = seeded();
  let generation = map.generation();
  let ev = rename_ev(
    FAN_RENAME | FAN_ONDIR,
    Some(fid(1)),
    fid(90),
    b"root",
    fid(91),
    b"moved",
  );
  let admission = classify_one(&mut map, &ev);
  assert!(
    matches!(admission, Admission::RootDeath(_)),
    "the root moved between two foreign parents is RootDeath, not both-ends-out ForeignDrop: {admission:?}"
  );
  let event = forwarded(admission);
  assert_eq!(event.path.as_deref(), Some(Path::new("/root")));
  assert!(
    event.mask.move_self(),
    "a moved root normalizes to the MOVE_SELF self form (terminal Rescan)"
  );
  assert_eq!(
    map.generation(),
    generation,
    "the foreign-parent root move is a read-only decision — the map is untouched"
  );
}

/// The action-aware foreign-parent path does NOT over-reach. A foreign parent whose
/// `target_fid` is an in-map NON-ROOT directory (unreachable on a consistent tree — an
/// in-root directory's parent is in-root) takes the LOSS BARRIER, never a guessed single
/// mutation; a fully-foreign event (parent AND target out-of-root) still `ForeignDrop`s,
/// so the firehose filter is intact; and a normal in-root child dirent is unchanged.
#[test]
fn foreign_parent_over_reaches_nothing() {
  // Foreign parent, in-map NON-root target → the safe loss barrier, mutating nothing.
  let mut map = seeded();
  let generation = map.generation();
  let non_root = dirent(FAN_DELETE | FAN_ONDIR, fid(99), b"sub", Some(fid(2)));
  assert!(
    matches!(classify_one(&mut map, &non_root), Admission::Lossy),
    "a foreign parent over an in-map non-root target is the loss barrier, not a guess"
  );
  assert_eq!(
    map.generation(),
    generation,
    "the barrier decision mutates nothing before the reseed rebuilds truth"
  );

  // Fully foreign (parent AND target out-of-root) → still the clean firehose drop.
  let mut map = seeded();
  let foreign = dirent(FAN_DELETE | FAN_ONDIR, fid(99), b"x", Some(fid(98)));
  assert!(
    matches!(classify_one(&mut map, &foreign), Admission::ForeignDrop),
    "a fully-foreign dirent is still dropped — the superblock firehose filter"
  );
  let foreign_rename = rename_ev(
    FAN_RENAME | FAN_ONDIR,
    Some(fid(98)),
    fid(90),
    b"a",
    fid(91),
    b"b",
  );
  assert!(
    matches!(
      classify_one(&mut map, &foreign_rename),
      Admission::ForeignDrop
    ),
    "a fully-foreign rename is still dropped"
  );

  // A normal in-root child directory delete (parent in-root) is unchanged → ForgetDir.
  let mut map = seeded();
  let child = dirent(FAN_DELETE | FAN_ONDIR, fid(1), b"sub", Some(fid(2)));
  assert!(
    matches!(classify_one(&mut map, &child), Admission::ForgetDir(_)),
    "an in-root child delete still classifies by its in-root parent, untouched by the fix"
  );
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

/// The kernel encodes a directory's OWN self-event (`DELETE_SELF`/`MOVE_SELF`) as
/// a `DFID_NAME` record whose name is the self-name ".". Driven decode → classify,
/// a "." buffer for the ROOT reaches `RootDeath` on the root's OWN path (`/root`)
/// — the terminal death lowering — never `classify_dirent`'s `<root>/.` child (a
/// located rescan of "root/." that would delay or lose the root-death lifecycle).
#[test]
fn dfid_name_dot_root_self_event_reaches_root_death() {
  const FSID: [u8; 8] = [7; 8];
  for mask in [FAN_DELETE_SELF | FAN_ONDIR, FAN_MOVE_SELF | FAN_ONDIR] {
    let root = wire_fid(FSID, 1, b"root-handle");
    let mut map = FidMap::new();
    map.seed([SeedEntry::root(root, Path::new("/root"))]);

    let buf = dfid_name_event(mask, FSID, 1, b"root-handle", b".");
    let decoded = decode_events(&buf);
    assert!(!decoded.lossy && decoded.events.len() == 1);
    assert!(
      decoded.events[0].name.is_none(),
      "decode folded the '.' self-name to the name-less self shape"
    );

    let admission = classify_one(&mut map, &decoded.events[0]);
    assert!(
      matches!(admission, Admission::RootDeath(_)),
      "a '.' root self-event {mask:#x} is the root's death, not a child dirent: {admission:?}"
    );
    assert_eq!(
      forwarded(admission).path.as_deref(),
      Some(Path::new("/root")),
      "the root death carries the root's OWN path, never /root/."
    );
  }
}

/// A "." `DFID_NAME` on an admitted NON-ROOT directory (a directory's own
/// `ATTRIB`/`MODIFY`) forwards the directory's OWN path, not a bogus `<dir>/.`
/// child — decode → classify, the sibling of the root case.
#[test]
fn dfid_name_dot_dir_metadata_forwards_own_path() {
  const FSID: [u8; 8] = [7; 8];
  for mask in [FAN_ATTRIB | FAN_ONDIR, FAN_MODIFY | FAN_ONDIR] {
    let root = wire_fid(FSID, 1, b"root-handle");
    let sub = wire_fid(FSID, 1, b"sub-handle");
    let mut map = FidMap::new();
    map.seed([
      SeedEntry::root(root.clone(), Path::new("/root")),
      SeedEntry::child(sub, root, OsString::from("sub")),
    ]);

    let buf = dfid_name_event(mask, FSID, 1, b"sub-handle", b".");
    let decoded = decode_events(&buf);
    assert!(!decoded.lossy && decoded.events.len() == 1 && decoded.events[0].name.is_none());

    let admission = classify_one(&mut map, &decoded.events[0]);
    assert!(
      matches!(admission, Admission::Forward(_)),
      "a '.' dir metadata event {mask:#x} forwards the dir's own path: {admission:?}"
    );
    assert_eq!(
      forwarded(admission).path.as_deref(),
      Some(Path::new("/root/sub")),
      "dir metadata forwards the directory's OWN path, never /root/sub/."
    );
  }
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
///      noise — `ForeignDrop` — UNLESS the event still carries an in-map object in its
///      `target_fid`: the watched root deleted/moved from its own FOREIGN parent (the
///      dirent parent, or both rename ends, out-of-root while `target_fid` = the root) is
///      the root's terminal death (`RootDeath`), and any other in-map `target_fid` under a
///      foreign parent takes the loss barrier — never a silent drop;
///   3. an ADMITTED addressing object whose mask is AMBIGUOUS — a merged bitmask with
///      two or more distinct structural verbs, `FAN_RENAME` counted among them (man 7
///      fanotify merges consecutive events for one object) — is `Lossy` (the loss
///      barrier, never a one-sided map mutation), through ONE universal gate every
///      shape passes before dispatch; otherwise it takes the single action its mask
///      dictates, and an action missing a required field is `Lossy`.
///
/// [`classify_oracle`] encodes exactly that, applying the universal gate FIRST for
/// every shape, computing admittance UNIFORMLY and never mutating the map (a pure
/// predicate, not classify's act-as-you-go machinery), and re-deriving the
/// multi-structural rule from the mask's own bits ([`multi_structural_spec`]) rather
/// than from classify. So a future `classify` that re-introduced a mask special-case, a
/// pre-classification gate dropping an admitted-FID event, the single-verb priority
/// (running one verb of a merged mask and dropping the rest), the rename-before-gate
/// dispatch (applying a merged rename's re-parent and dropping its co-merged delete), or a
/// per-shape gate that dropped a foreign-parent event still carrying the in-map root
/// `target_fid` would DISAGREE with it. On top of agreement, FOUR invariants are asserted
/// DIRECTLY against the event + map:
///
///   (i)   no-admitted-drop — an event whose ADDRESSING OBJECT is admitted is NEVER
///         `ForeignDrop` (the whole class: a name-less ATTRIB/MODIFY on an admitted
///         directory, addressed only by `target_fid`, once fell to the `dir_fid == None`
///         gate and was silently dropped);
///   (ii)  field-correctness — every forwarded (non-`Lossy`, non-`Drop`) action carries
///         exactly the field compile consumes (a single-object action its `path`, a
///         rename its `rename` pair), so no forward reaches compile without its target;
///   (iii) no-one-sided-mutation — an ACTION-AWARE-admitted event whose merged mask names
///         two or more structural verbs (rename counted among them) is `Lossy`, never a
///         single-verb mutation that drops the other verb(s) (a merged create+delete
///         leaving a deleted dir learned; a merged rename+delete applying only the
///         re-parent — the class R27's rename-separate sweep + the mirrored model both
///         missed);
///   (iv)  raw-membership — the INDEPENDENT, UNIFORM backstop: an event carrying ANY
///         map-resident raw FID is NEVER `ForeignDrop`, decided from RAW handle membership
///         ([`FidMap::contains`]) over the COMPLETE set of the event's carried FIDs, gated on
///         NO shape and NO verb count, reusing NEITHER admittance model. Invariants (i)–(iii)
///         all ride an admittance helper (`addressing_object_admitted` / `addressing_admitted`),
///         so a blind spot SHARED between classify and the spec — a per-shape gate that ignores
///         a carried FID (the rename-only admittance that ignored `target_fid`; the dir_fid-only
///         dirent gate that ignored an in-map root `target_fid`), the recurring trap of an oracle
///         inheriting the very gap it was written to catch — would hide from them together; (iv)
///         reasons over `(raw event FIDs, raw map membership)` with no shape/priority/admittance
///         logic, so it trips on exactly that class where the others are blind.
///
/// An exhaustive generator sweeps the whole reachable mask space — the POWER SET of ALL
/// subscribed action bits, `FAN_RENAME` INCLUDED, so every merged bitmask appears with
/// NO EXCLUDED REGION (a merged rename+delete no longer escapes the sweep the way R27's
/// rename-separate sweep let it) — and asserts all five properties (agreement + (i)–(iv))
/// per case. This SUBSUMES the totality table's non-panic sweep: totality proved classify
/// RETURNS for every shape; the oracle proves it returns the RIGHT action.
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
    // THE UNIVERSAL multi-structural gate, mirroring classify: an ADMITTED event whose
    // merged mask names two or more structural verbs — `FAN_RENAME` counted among them
    // ([`multi_structural_spec`]) — is ambiguous and takes the loss barrier BEFORE any
    // shape dispatch. Admittance here is ACTION-AWARE ([`addressing_admitted`]): in-root by
    // ANY carried structural-verb FID (the rename parents, `dir_fid`, AND the moved/self
    // `target_fid`), so a merged rename+self whose only in-root FID is `target_fid` — its
    // rename parents foreign — is barred here, not dropped. Derived from the mask's own
    // decode-level bit count and a read-only admittance, never from classify, so a classify
    // that dropped the universal gate — dispatched a merged rename to a one-sided re-parent,
    // ran one verb of a merged dirent, or reverted to the rename-only admittance that
    // ignored `target_fid` — would DISAGREE with the oracle.
    if multi_structural_spec(event.mask) && addressing_admitted(map, event) {
      return Action::Lossy;
    }

    // A rename addresses two directory ends; at least one in-root admits it. Only a
    // single-structural (pure) rename reaches here — the gate barred a merged one.
    if let Some(rename) = &event.rename {
      let old_in = map.resolve_path(&rename.old_dir).is_some();
      let new_in = map.resolve_path(&rename.new_dir).is_some();
      if !old_in && !new_in {
        // Both ends foreign — but the moved object may itself be the root (renamed
        // between two foreign parents), so consult its `target_fid` before dropping.
        return foreign_parent_action(map, event);
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
      // A foreign/absent addressing PARENT does not drop on the parent alone: the
      // affected `target_fid` can still be the root deleted/moved from its foreign
      // parent (the exact class the dir_fid-only gate lost). Consult it.
      Addressing::Foreign | Addressing::Unaddressable => foreign_parent_action(map, event),
      Addressing::Dirent => dirent_action(event),
      Addressing::SelfObject { is_root } => nameless_action(event, is_root),
    }
  }

  /// The SPEC's OWN count of distinct structural verbs — create, delete, delete_self,
  /// move_self, and rename, each a distinct tree mutation — read from the mask's
  /// decode-level bits, INDEPENDENT of classify's [`FanMask::multi_structural`].
  /// `FAN_MODIFY`/`FAN_ATTRIB` are metadata and `FAN_ONDIR` flags the subject, so none
  /// counts. `FAN_RENAME` IS counted: the kernel can merge a rename with another
  /// structural verb (a directory renamed AND deleted in one event), and such a merge
  /// is as ambiguous as any other — so the spec bars it from a one-sided re-parent too,
  /// and only a PURE rename (one structural verb) dispatches to the rename shape. Two or
  /// more is a merged bitmask the spec routes to the loss barrier — a rule the oracle
  /// asserts from first principles so re-deriving it here can never share classify's
  /// blind spot.
  fn multi_structural_spec(mask: FanMask) -> bool {
    let verbs = mask.created() as u8
      + mask.removed() as u8
      + mask.delete_self() as u8
      + mask.move_self() as u8
      + mask.rename() as u8;
    verbs >= 2
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

  /// The SPEC action when an event's addressing PARENT(s) are foreign — a named dirent's
  /// out-of-root/absent `dir_fid`, a name-less event's out-of-root self-FID, or a rename's
  /// BOTH ends out-of-root. Derived from first principles, mirroring
  /// [`super::classify_foreign_parent`]: on a consistent single-superblock tree an in-root
  /// directory's parent is itself in-root, so the ONLY in-map object reportable under a
  /// foreign parent is the ROOT anchor (real parent outside the watched root). A structural
  /// death of the root reported from its foreign parent is the root's death; any other
  /// in-map target is unreachable and takes the loss barrier rather than a guess; a foreign
  /// or absent target is the firehose drop. Read-only against the pre-classify map.
  fn foreign_parent_action(map: &FidMap, event: &RawFanotifyEvent) -> Action {
    let Some(target) = event.target_fid.as_ref() else {
      return Action::ForeignDrop;
    };
    if map.resolve_path(target).is_none() {
      return Action::ForeignDrop;
    }
    if map.is_root(target) && root_death_verb(event.mask) {
      return Action::RootDeath;
    }
    Action::Lossy
  }

  /// Whether the mask names a structural DEATH of the affected object — a removal
  /// (`FAN_DELETE` dirent or `FAN_DELETE_SELF`) or a move (`FAN_MOVE_SELF` or a
  /// `FAN_RENAME` relocation). A create is structural but not a death, and metadata bits
  /// are not structural, so neither counts. Independent of classify's `root_death_mask`,
  /// stated over the mask's own bits.
  fn root_death_verb(mask: FanMask) -> bool {
    mask.removed() || mask.delete_self() || mask.move_self() || mask.rename()
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

  /// Whether the event REACHES any in-root object by ANY structural-verb FID it carries —
  /// the ACTION-AWARE admittance for the universal multi-structural gate in
  /// [`classify_oracle`] and the no-one-sided-mutation invariant, mirroring classify's fixed
  /// `addresses_in_root`. A merged mask's verbs each address through their own FID, so the
  /// event touches the root when ANY carried FID does: the rename halves' `old_dir`/
  /// `new_dir`, the `dir_fid`, AND the `target_fid` (the moved/self object of a rename/
  /// self-event — the class the rename-only model, which checked only the rename parents,
  /// missed). A read-only path resolution, never mutating the map. Enumerated INLINE (not
  /// via [`raw_fids`]) so the independent membership invariant, which does use [`raw_fids`],
  /// shares no enumeration with the admittance model it backstops — reinjecting this model's
  /// blind spot cannot silently shrink that invariant's FID set too.
  fn addressing_admitted(map: &FidMap, event: &RawFanotifyEvent) -> bool {
    let rename_ends = event
      .rename
      .iter()
      .flat_map(|rename| [&rename.old_dir, &rename.new_dir]);
    let singles = [event.dir_fid.as_ref(), event.target_fid.as_ref()]
      .into_iter()
      .flatten();
    rename_ends
      .chain(singles)
      .any(|fid| map.resolve_path(fid).is_some())
  }

  /// Whether the event's ADDRESSING OBJECT — the directory whose event this IS — is
  /// admitted, the concept the no-admitted-drop invariant guards: a rename addresses its
  /// two directory ENDS (in-root when EITHER resolves); a named event its parent `dir_fid`;
  /// a name-less event its own self-FID. A rename's moved/child `target_fid` is deliberately
  /// NOT an addressing object here — a rename whose ends are both foreign is genuinely
  /// foreign even if its moved FID coincides with a mapped handle, so this stays the
  /// per-shape addressing gate, distinct from the action-aware [`addressing_admitted`] the
  /// ambiguity gate uses.
  fn addressing_object_admitted(map: &FidMap, event: &RawFanotifyEvent) -> bool {
    if let Some(rename) = &event.rename {
      return map.resolve_path(&rename.old_dir).is_some()
        || map.resolve_path(&rename.new_dir).is_some();
    }
    matches!(
      addressing(map, event),
      Addressing::Dirent | Addressing::SelfObject { .. }
    )
  }

  /// Every raw FID the event carries — `dir_fid`, `target_fid`, and (for a rename) both
  /// halves' `old_dir`/`new_dir`, whichever are `Some`. The COMPLETE present set, listed
  /// with NO shape or mask reasoning, so the independent membership invariant that consumes
  /// it cannot inherit a shape-selection blind spot (an admittance model that FORGETS a
  /// carried FID — the rename-only gate that ignored `target_fid`). Deliberately NOT shared
  /// with [`addressing_admitted`], so reinjecting that model's blind spot leaves this
  /// enumeration complete and the invariant's teeth intact.
  fn raw_fids(event: &RawFanotifyEvent) -> Vec<&Fid> {
    let mut fids = Vec::new();
    if let Some(dir) = event.dir_fid.as_ref() {
      fids.push(dir);
    }
    if let Some(target) = event.target_fid.as_ref() {
      fids.push(target);
    }
    if let Some(rename) = event.rename.as_ref() {
      fids.push(&rename.old_dir);
      fids.push(&rename.new_dir);
    }
    fids
  }

  /// Asserts the FIVE contract properties for one event against a fresh map: AGREEMENT
  /// (classify's action == the oracle's), NO-ADMITTED-DROP (an admitted addressing object is
  /// never dropped), FIELD-CORRECTNESS (a forwarded action carries the field compile
  /// consumes), NO-ONE-SIDED-MUTATION (an action-aware-admitted multi-structural mask is
  /// Lossy), and the INDEPENDENT RAW-MEMBERSHIP invariant (a multi-structural mask over any
  /// map-resident raw FID is Lossy, checked via raw handle membership rather than either
  /// admittance model). Returns whether the raw-membership invariant FIRED, so the sweep can
  /// prove it is exercised, not vacuous.
  fn assert_contract(label: &str, event: &RawFanotifyEvent) -> bool {
    let mut map = oracle_map();
    // The oracle reads the PRE-classify state; classify decides against the same state
    // (mutating as it acts). Snapshot every spec fact before classify runs.
    let expected = classify_oracle(&map, event);
    let object_admitted = addressing_object_admitted(&map, event);
    let reaches_in_root = addressing_admitted(&map, event);
    // The INDEPENDENT membership fact: any raw FID present on the event is a stored map
    // node (RAW [`FidMap::contains`] — a `dirs.contains_key`, a stored node incl. the root
    // anchor, with NO parent-walk and NO `resolve_path`/`addressing`), read against the
    // PRE-classify map and reusing NEITHER admittance model.
    let resident = raw_fids(event).into_iter().any(|fid| map.contains(fid));
    let admission = classify(&mut map, event, &mut MemoBatch::new());
    let got = action_of(&admission);

    // (1) Agreement: classify selects exactly the spec's action.
    assert_eq!(got, expected, "agreement `{label}`: {admission:?}");

    // (2) No-admitted-drop: an admitted ADDRESSING OBJECT (the rename ends / dirent parent
    // / self-FID — NOT a rename's moved `target_fid`) is never the firehose drop.
    if object_admitted {
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

    // (4) No-one-sided-mutation: an event that REACHES the root by any carried
    // structural-verb FID (action-aware admittance) whose merged bitmask names two or more
    // structural verbs — a rename counted among them — MUST route to the loss barrier, never
    // a single-verb map mutation that silently drops the other verb(s) (a merged
    // create+delete leaving a deleted dir learned; a merged rename+delete applying only the
    // re-parent). Spans the WHOLE power set including rename, with no shape carved out.
    if reaches_in_root && multi_structural_spec(event.mask) {
      assert_eq!(
        got,
        Action::Lossy,
        "no-one-sided-mutation `{label}`: an admitted multi-structural mask must be Lossy: {admission:?}"
      );
    }

    // (5) INDEPENDENT raw-membership invariant — the UNIFORM safety net, reusing NEITHER
    // admittance model and gated on NO shape and NO verb count. If the map contains ANY raw
    // FID the event carries ([`raw_fids`], the complete present set) via raw handle
    // membership, then classify MUST NOT drop it as firehose noise: it must take an ADMITTED
    // action (the proper mutation, RootDeath, or the loss barrier). Reasoning over the
    // complete present-FID set via raw `contains` — never a shape-selected subset, never
    // `addresses_in_root` / `addressing_admitted` — it trips on the exact blind-spot class
    // where a per-shape gate ignores a carried FID: a SINGLE-structural dirent/rename whose
    // parent is foreign but whose `target_fid` is the in-map root (the root deleted/moved
    // from its foreign parent), which the dir_fid-only gate dropped. Dropping the
    // multi_structural gate this invariant once carried is what widens it from a merged-mask
    // check to the guarantee that closes the single-structural gap too; (4)'s model-based
    // Lossy check still rides the admittance model a shared blind spot would corrupt, so
    // this stays the independent backstop.
    let raw_membership_fired = resident;
    if raw_membership_fired {
      assert_ne!(
        got,
        Action::ForeignDrop,
        "raw-membership `{label}`: an event carrying a map-resident raw FID must not be dropped: {admission:?}"
      );
    }
    raw_membership_fired
  }

  /// The COMPLETE input space: the POWER SET of ALL subscribed action bits — the seven
  /// non-rename verbs AND `FAN_RENAME` — so every merged bitmask the kernel can deliver
  /// appears, with NO EXCLUDED REGION. This closes the carve-out the two prior sweeps
  /// left: R27 swept the `2^7` non-rename subsets and swept rename SEPARATELY as its own
  /// single-structural shape, so a mask merging `FAN_RENAME` with another structural
  /// verb (a directory renamed AND deleted in one event) never appeared — and classify
  /// dispatched it to a one-sided re-parent. `FAN_RENAME` is now a structural verb in
  /// both classify and the spec, and this ONE sweep visits all `2^8 = 256` subsets.
  ///
  /// The event SHAPE follows the mask: a subset containing `FAN_RENAME` builds a rename
  /// event (both halves present — a missing/empty half is wire-lossy and never reaches
  /// classify — each end drawn from {root, admitted child, foreign}, the moved object's
  /// `target_fid` from {none, root, admitted child, foreign}); a subset without it
  /// builds a non-rename event (`dir_fid`/`target_fid` from {none, root, admitted child,
  /// foreign} × name {none, empty, present}). Empty name folds to none at decode, but
  /// feeding it here proves classify and the oracle dispatch it identically.
  /// [`assert_contract`] checks all FIVE properties (agreement, no-admitted-drop,
  /// field-correctness, no-one-sided-mutation, and — the invariant THIS fix widens from a
  /// merged-mask check to a uniform every-shape backstop — the independent raw-membership
  /// guarantee) per case.
  ///
  /// Under miri each case builds and walks a fresh `FidMap` (interpreted, no unsafe to
  /// inspect — miri's value here is the FID parse's pointer arithmetic in the `fid`
  /// suite, not re-checking classify's safe logic), so the field cross-product is
  /// trimmed to a REPRESENTATIVE {admitted child, foreign} object set while the host
  /// keeps the full one. The mask loop still visits every one of the 256 subsets on
  /// both — exercising the universal multi-structural gate across the whole rename-
  /// inclusive mask space — so the coverage assertion below is identical host and miri.
  #[test]
  fn oracle_agrees_on_the_full_subscribed_mask_power_set() {
    const SUBSCRIBED: [u64; 8] = [
      FAN_CREATE,
      FAN_DELETE,
      FAN_MODIFY,
      FAN_ATTRIB,
      FAN_DELETE_SELF,
      FAN_MOVE_SELF,
      FAN_ONDIR,
      FAN_RENAME,
    ];
    #[cfg(not(miri))]
    let fids = [None, Some(fid(1)), Some(fid(2)), Some(fid(99))];
    #[cfg(not(miri))]
    let names: [Option<&[u8]>; 3] = [None, Some(b""), Some(b"n")];
    #[cfg(not(miri))]
    let rename_dirs = [fid(1), fid(2), fid(99)];
    #[cfg(not(miri))]
    let targets = [None, Some(fid(1)), Some(fid(2)), Some(fid(99))];
    #[cfg(miri)]
    let fids = [Some(fid(2)), Some(fid(99))];
    #[cfg(miri)]
    let names: [Option<&[u8]>; 2] = [None, Some(b"n")];
    #[cfg(miri)]
    let rename_dirs = [fid(2), fid(99)];
    // The multi-structural gate is admittance-scoped and target-INDEPENDENT, so a single
    // representative `target_fid` still exercises it in every shape; miri fixes it (the
    // interpreter builds a fresh `FidMap` per case) while the host sweeps all four.
    #[cfg(miri)]
    let targets = [Some(fid(2))];

    let mut checked = 0u64;
    let mut multi_structural_seen = 0u64;
    // How many cases the INDEPENDENT raw-membership invariant (5) actually asserted on —
    // pinned below so a regression that made it vacuous (e.g. a `raw_fids` that dropped a
    // FID slot, or a `contains` that stopped seeing the root anchor) trips the guard.
    let mut raw_membership_fired = 0u64;
    for subset in 0u32..(1u32 << SUBSCRIBED.len()) {
      let mut mask = 0u64;
      for (bit, flag) in SUBSCRIBED.iter().enumerate() {
        if subset & (1u32 << bit) != 0 {
          mask |= *flag;
        }
      }
      if FanMask::new(mask).multi_structural() {
        multi_structural_seen += 1;
      }
      if mask & FAN_RENAME != 0 {
        // A rename SHAPE: both halves present, each directory end and the moved
        // object's `target_fid` swept — so a merged rename+verb is exercised too.
        for old_dir in &rename_dirs {
          for new_dir in &rename_dirs {
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
              raw_membership_fired += assert_contract(
                &format!("rename mask={mask:#x} old={old_dir:?} new={new_dir:?} target={target:?}"),
                &event,
              ) as u64;
              checked += 1;
            }
          }
        }
      } else {
        // A non-rename SHAPE: the dirent / self-event field cross-product.
        for dir in &fids {
          for target in &targets {
            for &name in &names {
              let event = RawFanotifyEvent {
                mask: FanMask::new(mask),
                dir_fid: dir.clone(),
                target_fid: target.clone(),
                name: name.map(<[u8]>::to_vec),
                rename: None,
              };
              raw_membership_fired += assert_contract(
                &format!("mask={mask:#x} dir={dir:?} target={target:?} name={name:?}"),
                &event,
              ) as u64;
              checked += 1;
            }
          }
        }
      }
    }

    // The exact case count, shape-dependent: half the 256 subsets carry `FAN_RENAME`
    // (the rename field cross-product) and half do not (the non-rename one).
    let half = 1u64 << (SUBSCRIBED.len() - 1);
    let rename_cases = (rename_dirs.len() * rename_dirs.len() * targets.len()) as u64;
    let non_rename_cases = (fids.len() * targets.len() * names.len()) as u64;
    assert_eq!(checked, half * rename_cases + half * non_rename_cases);

    // The rename-inclusive power set actually EXERCISES every merged-mask class the
    // universal gate closes. Five structural bits now (create, delete, delete_self,
    // move_self, RENAME) among the eight; the subsets with two or more of them are the
    // ambiguous merges, each combinable with any of the 2^3 = 8 metadata/ONDIR subsets:
    // (2^5 - C(5,0) - C(5,1)) * 8 = (32 - 1 - 5) * 8 = 26 * 8 = 208. A regression that
    // shrank the sweep back toward a rename-excluded or single-action list would drop
    // this below the count and trip here.
    assert_eq!(
      multi_structural_seen, 208,
      "the rename-inclusive power set must span every multi-structural merge"
    );

    // The INDEPENDENT raw-membership invariant is NON-VACUOUSLY exercised: the sweep drives
    // many multi-structural masks over map-resident FIDs (a rename with an in-root end or
    // target, a dirent under an in-root parent, a self-event on an admitted object), each of
    // which fires assertion (5). A regression that silently stopped it firing — the invariant
    // reduced to a no-op — drops this to zero and trips here, so the backstop can never
    // rot into a rubber stamp.
    assert!(
      raw_membership_fired > 0,
      "the independent raw-membership invariant must be exercised across the sweep, not vacuous"
    );
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

  /// The exact class THIS fix closes, isolated as targeted rows: a MERGED bitmask
  /// carrying two or more structural verbs — `FAN_RENAME` now counted among them —
  /// routes to `Lossy` (the reseed barrier), never a single-verb map mutation that
  /// silently drops the other verb(s). Each row also proves the map was NOT
  /// one-sided-mutated — its generation is unchanged and the node's membership/path is
  /// exactly as before — so no departed directory is left learned, no live node is
  /// spuriously forgotten, and no rename half-applies its re-parent from an ambiguous
  /// mask.
  #[test]
  fn merged_multi_structural_mask_is_lossy_never_one_sided() {
    // Merged create+delete of the same dirent under an admitted parent: the old
    // single-verb priority LEARNED the child and dropped the delete (`LearnDir`); now
    // it is `Lossy` and the map is untouched — no phantom directory.
    let mut map = oracle_map();
    let generation = map.generation();
    let create_delete = dirent(
      FAN_CREATE | FAN_DELETE | FAN_ONDIR,
      fid(2),
      b"merged",
      Some(fid(8)),
    );
    assert!(
      matches!(classify_one(&mut map, &create_delete), Admission::Lossy),
      "a merged create+delete dirent is ambiguous → Lossy, not a one-sided learn"
    );
    assert_eq!(
      map.generation(),
      generation,
      "the ambiguous event mutated nothing — no phantom directory learned"
    );
    assert!(
      !map.contains_dir(&fid(8)),
      "the merged create did not learn the child its co-merged delete removed"
    );

    // Merged delete_self+move_self on an admitted NON-ROOT directory: the old priority
    // FORGOT it (`ForgetDir`); now `Lossy`, and it stays mapped — the reseed barrier,
    // not a one-sided forget, rebuilds the truth.
    let mut map = oracle_map();
    let generation = map.generation();
    let delete_move_self = self_dfid(FAN_DELETE_SELF | FAN_MOVE_SELF | FAN_ONDIR, fid(2));
    assert!(
      matches!(classify_one(&mut map, &delete_move_self), Admission::Lossy),
      "a merged delete_self+move_self is ambiguous → Lossy, not a one-sided forget"
    );
    assert_eq!(
      map.generation(),
      generation,
      "the ambiguous self-event forgot nothing — no live node dropped from one bit"
    );
    assert!(
      map.contains_dir(&fid(2)),
      "the node is still mapped; the reseed barrier rebuilds it, not a one-sided forget"
    );

    // Merged delete_self+move_self on the ROOT is `Lossy` too — never a one-sided
    // `RootDeath` from an ambiguous mask. A genuinely-dead root is still observed by
    // the reseed walk / liveness tick; a survivable ambiguity heals into a truthful map.
    let mut map = oracle_map();
    let root_merged = self_fid_only(FAN_DELETE_SELF | FAN_MOVE_SELF, fid(1));
    assert!(
      matches!(classify_one(&mut map, &root_merged), Admission::Lossy),
      "a merged root self-event is ambiguous → Lossy, not a one-sided RootDeath"
    );

    // Merged rename+delete of a directory — a dir renamed AND deleted in ONE
    // kernel-merged event (`FAN_RENAME|FAN_DELETE`). This is the class the
    // rename-before-guard dispatch missed: because `FAN_RENAME` now counts as a
    // structural verb, the merged mask is multi-structural and the UNIVERSAL gate routes
    // it to `Lossy` BEFORE the rename dispatch — never the one-sided re-parent (learn)
    // classify_rename would apply while silently dropping the co-merged delete. The map
    // is untouched: fid(2) stays at /root/sub, not re-parented to /root/moved.
    let mut map = oracle_map();
    let generation = map.generation();
    let rename_delete = rename_ev(
      FAN_RENAME | FAN_DELETE | FAN_ONDIR,
      Some(fid(2)),
      fid(1),
      b"sub",
      fid(1),
      b"moved",
    );
    assert!(
      matches!(classify_one(&mut map, &rename_delete), Admission::Lossy),
      "a merged rename+delete is ambiguous → Lossy, not a one-sided re-parent"
    );
    assert_eq!(
      map.generation(),
      generation,
      "the ambiguous rename mutated nothing — no one-sided re-parent applied"
    );
    assert_eq!(
      map.admit(&fid(2)),
      Some(PathBuf::from("/root/sub")),
      "the directory stays at its original path; the reseed barrier rebuilds truth, not a half-applied rename"
    );
  }

  /// The EXACT class the action-aware admittance closes, as targeted rows: a MERGED
  /// bitmask that is a rename co-merged with the moved object's own self-death
  /// (`FAN_RENAME|FAN_MOVE_SELF` and `FAN_RENAME|FAN_DELETE_SELF`, both `ONDIR`) whose
  /// rename PARENTS are both foreign but whose moved `target_fid` IS an in-root object.
  /// The rename-only admittance saw only the foreign parents and dropped it
  /// (`ForeignDrop`), silently losing an in-root — possibly ROOT — death instead of taking
  /// the barrier; the action-aware gate sees the in-root `target_fid` and routes the
  /// ambiguity to `Lossy`. Swept for target = the root anchor AND an admitted non-root
  /// directory, and each row proves the barrier mutated nothing (the reseed rebuilds truth,
  /// not a one-sided re-parent/forget).
  #[test]
  fn merged_rename_self_with_foreign_parents_but_in_root_target_is_lossy() {
    let foreign = fid(99);
    for mask in [
      FAN_RENAME | FAN_MOVE_SELF | FAN_ONDIR,
      FAN_RENAME | FAN_DELETE_SELF | FAN_ONDIR,
    ] {
      for target in [fid(1), fid(2)] {
        let mut map = oracle_map();
        let generation = map.generation();
        let event = rename_ev(
          mask,
          Some(target.clone()),
          foreign.clone(),
          b"x",
          foreign.clone(),
          b"y",
        );
        let admission = classify_one(&mut map, &event);
        assert!(
          matches!(admission, Admission::Lossy),
          "a merged rename+self with foreign parents but in-root target {target:?} (mask {mask:#x}) must be Lossy, not ForeignDrop: {admission:?}"
        );
        assert_eq!(
          map.generation(),
          generation,
          "the ambiguous merge took the barrier before any shape acted — no one-sided mutation"
        );
        assert_eq!(
          map.admit(&fid(2)),
          Some(PathBuf::from("/root/sub")),
          "the node is untouched; the reseed barrier rebuilds the truth"
        );
      }
    }
  }
}
