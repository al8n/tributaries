use std::io;

use rustix::io::Errno;

use super::{
  AdmitWalk, MAX_WALK_DECLINES, SeedEntry, WalkError, WalkFrame, WalkSeed, WalkSkip,
  classify_walk_skip, fence_declines, fence_entries, handle_fid_at, handles_match, revealed_walk,
  seed_from_fd, seed_walk, subtree_walk,
};
use crate::os::{ScopeFrame, linux::fanotify::fid::Fid};

/// Opens `path` as a pinned directory `OwnedFd` the same no-symlink way the walk
/// does, for the tests that feed [`seed_from_fd`] a real root fd directly. `None`
/// when the open fails (the caller skips loudly).
fn open_dir_fd(path: &std::path::Path) -> Option<std::os::fd::OwnedFd> {
  use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
  openat2(
    rustix::fs::CWD,
    path,
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
    Mode::empty(),
    ResolveFlags::NO_SYMLINKS,
  )
  .ok()
}

/// A throwaway FID whose handle bytes are the given tag — a stand-in the walk's
/// FID-verification gate rejects when it does not equal a reopened object's true
/// handle. `fsid` is zeroed so it matches the `[0u8; 8]` the seed-walk rows pass.
fn some_fid(tag: u8) -> Fid {
  Fid::new([0u8; 8], Box::from(&[tag][..]))
}

/// Encodes the REAL FID of an existing directory the same way the walk does
/// (fd-relative `name_to_handle_at`), so a matching-FID row can hand `seed_walk`
/// the exact anchor its reopen must equal. `None` when the temp filesystem exports
/// no handle (the caller skips loudly, exactly like the walk rows already do).
fn real_dir_fid(path: &std::path::Path, fsid: [u8; 8]) -> Option<Fid> {
  use std::os::fd::AsFd;

  use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
  let fd = openat2(
    rustix::fs::CWD,
    path,
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
    Mode::empty(),
    ResolveFlags::NO_SYMLINKS,
  )
  .ok()?;
  handle_fid_at(fd.as_fd(), fsid)
}

/// Rebuilds a `Fid` with the same handle bytes but a DIFFERENT `fsid` — the
/// btrfs shape where the kernel's per-superblock event fsid diverges from the
/// `statfs` per-subvolume fsid for the SAME object. Used to hand a reopen gate a
/// request FID whose fsid differs from the seed `statfs` fsid, proving the gate
/// keys on the handle alone (a full-`Fid` compare would falsely reject it).
fn with_fsid(fsid: [u8; 8]) -> impl Fn(Fid) -> Fid {
  move |fid| Fid::new(fsid, Box::from(fid.handle()))
}

/// A root that cannot export a file handle is a FATAL seed/reseed failure, never
/// an empty successful seed: the root anchor is the base every admitted path
/// resolves against, so without it the map admits nothing. A nonexistent path
/// stands in for `name_to_handle_at` failing on the root — the walk must return
/// [`WalkError::RootGone`] (a race the spawn reports as root-unavailable and the
/// reseed escalates), not a live-but-blind source.
#[test]
fn root_without_a_handle_is_a_fatal_seed_failure() {
  let missing = std::path::Path::new("/tributary-fs-nonexistent-root-for-seed-walk");
  // The open fails (ENOENT) before the FID check is reached, so any expected FID
  // will do — the point is the RootGone class, not the mismatch.
  let result = seed_walk(
    missing,
    [0u8; 8],
    0,
    &some_fid(1),
    &[],
    None,
    MAX_WALK_DECLINES,
  );
  assert!(
    matches!(result, Err(WalkError::RootGone(_))),
    "a root with no encodable handle fails the walk as RootGone, not an empty seed"
  );
}

/// The walk-skip classifier is the completeness decision, extracted pure so its
/// classes are row-tested without a live filesystem. The benign vanish/shape-change
/// set is exactly `{ENOENT, ELOOP, ENOTDIR}`: a directory a prior readdir listed
/// that VANISHED (`ENOENT`), was SWAPPED FOR A SYMLINK — so the `O_NOFOLLOW` open
/// refuses it (`ELOOP`) — or was SWAPPED FOR A NON-DIRECTORY — so the `O_DIRECTORY`
/// open refuses it (`ENOTDIR`) — is a race, not a coverage hole. Crucially the
/// symlink-swap case (`ELOOP`/`ENOTDIR`) is the scope-fence race: it is what a
/// same-superblock swap of an in-root directory for a symlink pointing OUTSIDE the
/// root produces, and classifying it a race is what keeps the foreign target out
/// of the map. Every OTHER failure — permission, I/O, unsupported — is an in-root
/// coverage hole that makes the tree `Incomplete` (fanotify not viable).
#[test]
fn classify_walk_skip_vanish_and_shape_change_are_races() {
  for (errno, label) in [
    (Errno::NOENT, "a vanished entry (ENOENT)"),
    (Errno::LOOP, "a listed dir swapped for a symlink (ELOOP)"),
    (
      Errno::NOTDIR,
      "a listed dir swapped for a non-directory (ENOTDIR)",
    ),
  ] {
    assert_eq!(
      classify_walk_skip(errno),
      WalkSkip::VanishedRace,
      "{label} is a benign shape-change race the walk skips — never a foreign admission"
    );
  }
  // Every non-vanish/shape-change failure on an existing in-root directory is an
  // incompleteness: under Auto the spawn falls back to inotify, under forced
  // Fanotify it is a typed viability error.
  for (errno, label) in [
    (Errno::ACCESS, "EACCES (the chmod-000 subdirectory case)"),
    (Errno::IO, "EIO"),
    (Errno::PERM, "EPERM"),
    (Errno::NOMEM, "ENOMEM"),
  ] {
    assert_eq!(
      classify_walk_skip(errno),
      WalkSkip::Incomplete,
      "{label} on an existing in-root directory is an incompleteness, not a race"
    );
  }
}

/// `WalkError` folds both classes to the `io::Error` the reseed path escalates
/// through its terminal blind→fatal, so a live reseed over an unwalkable tree
/// composes with the existing `ReseedOutcome::Blind` machinery unchanged.
#[test]
fn walk_error_folds_to_io_for_the_reseed_path() {
  let incomplete = WalkError::Incomplete(io::Error::from(io::ErrorKind::PermissionDenied));
  assert_eq!(incomplete.into_io().kind(), io::ErrorKind::PermissionDenied);
  let gone = WalkError::RootGone(io::Error::from(io::ErrorKind::NotFound));
  assert_eq!(gone.into_io().kind(), io::ErrorKind::NotFound);
}

/// The pure reopened-vs-expected gate ([`handles_match`]) — the FID-verification
/// decision extracted so its policy is row-tested without a live fd. It compares
/// HANDLE BYTES only: an equal handle is a match; an unequal handle, and a `None`
/// (reopened object exports no handle), are both mismatches. A PATH-reopen whose
/// identity the request fixed (the live-reseed root vs the spawn anchor, a pending
/// move-in subtree vs its learned FID) must not seed/reseed the map unless the
/// object it reopened is provably the expected one.
#[test]
fn handles_match_only_on_an_equal_reopened_handle() {
  let expected = some_fid(1);
  assert!(
    handles_match(Some(expected.handle()), expected.handle()),
    "an equal reopened handle is a match — the reopen landed on the expected object"
  );
  assert!(
    !handles_match(Some(some_fid(2).handle()), expected.handle()),
    "a different reopened handle is a mismatch — a same-superblock replacement, rejected"
  );
  assert!(
    !handles_match(None, expected.handle()),
    "a reopened object that exports no handle is a mismatch, never a silent match"
  );
}

/// The gate keys on HANDLE BYTES alone, so identical handles carrying DIFFERENT
/// fsids MATCH — the finding's exact shape. `expected` here is an event-style FID
/// (the kernel's per-superblock fsid) and the reopened FID a walk-style one (the
/// `statfs` per-subvolume fsid on btrfs); the SAME directory is stamped with
/// different fsids on each side, yet its handle is identical, so a genuine
/// moved-in directory must not be rejected as a replacement. Conversely a
/// different handle sharing one fsid is still a mismatch: fsid is never part of
/// the decision, in either direction.
#[test]
fn handles_match_ignores_fsid_matching_the_map_key() {
  let handle = Box::<[u8]>::from(&[1u8, 2, 3][..]);
  let walk_fsid = Fid::new([0u8; 8], handle.clone());
  let event_fsid = Fid::new([9u8; 8], handle.clone());
  assert!(
    handles_match(Some(walk_fsid.handle()), event_fsid.handle()),
    "identical handles with different fsids MATCH — the btrfs event-vs-statfs \
     divergence must not reject the genuine object"
  );
  let same_fsid_other_handle = Fid::new([9u8; 8], Box::from(&[1u8, 2, 4][..]));
  assert!(
    !handles_match(Some(same_fsid_other_handle.handle()), event_fsid.handle()),
    "a different handle is a mismatch even sharing an fsid — fsid never gates the decision"
  );
}

/// The reseed-root FID gate, exercised on a REAL filesystem: `seed_walk` over an
/// existing, walkable root whose reopened handle does NOT equal the `expected`
/// anchor fails [`WalkError::RootGone`] — the replaced-at-path signal the reseed
/// folds to retry-once-then-blind→fatal — WITHOUT descending or seeding.
/// This is the same-superblock root-replacement the pin's `RESOLVE_NO_SYMLINKS`
/// cannot catch (no symlink involved): only the anchor equality tells the
/// replacement from the true root. A wrong expected FID stands in for "the object
/// at the root path is not the one the map anchors on".
#[test]
fn reseed_root_fid_mismatch_is_rootgone_without_seeding() {
  use std::os::unix::fs::MetadataExt;

  let root = std::env::temp_dir().join(format!(
    "tributary-fs-reseed-mismatch-{}",
    std::process::id()
  ));
  let _ = std::fs::remove_dir_all(&root);
  std::fs::create_dir_all(root.join("sub")).expect("create a walkable root");
  let Ok(meta) = std::fs::metadata(&root) else {
    let _ = std::fs::remove_dir_all(&root);
    return;
  };
  let root_dev = meta.dev();
  // Prove the root DOES export a handle (else the mismatch is indistinguishable
  // from the non-encodable case and the cell cannot assert its property).
  if real_dir_fid(&root, [0u8; 8]).is_none() {
    let _ = std::fs::remove_dir_all(&root);
    eprintln!(
      "SKIP reseed_root_fid_mismatch_is_rootgone_without_seeding: temp root exports no handle"
    );
    return;
  }
  // A DELIBERATELY WRONG anchor: the real root will never encode to these bytes,
  // so the reopen-verification must reject it.
  let wrong = some_fid(0xEE);
  let result = seed_walk(
    &root,
    [0u8; 8],
    root_dev,
    &wrong,
    &[],
    None,
    MAX_WALK_DECLINES,
  );
  let _ = std::fs::remove_dir_all(&root);
  assert!(
    matches!(result, Err(WalkError::RootGone(_))),
    "a reopened root whose handle does not equal the expected anchor is RootGone (replaced at \
     path), never a seed of the replacement tree"
  );
}

/// The exclusion fence at the walk, on a real tree.
///
/// A `FAN_MARK_FILESYSTEM` mark cannot be told about an exclusion — the kernel has
/// no notion of one — so the ONLY place a kernel-recursive backend can honor it is
/// the admission map: an excluded directory that gets mapped admits every event
/// under it forever. This asserts the walk keeps the whole excluded subtree out,
/// the boundary directory included, while its siblings are seeded untouched. The
/// nested `cache/deep` is the load-shedding half: the fence must SKIP the descent,
/// not merely drop the one entry.
#[test]
fn the_seed_walk_maps_no_directory_at_or_under_an_exclusion() {
  use std::os::unix::fs::MetadataExt;

  let root = std::env::temp_dir().join(format!("tributary-fs-excl-walk-{}", std::process::id()));
  let _ = std::fs::remove_dir_all(&root);
  std::fs::create_dir_all(root.join("cache/deep")).expect("create the excluded subtree");
  std::fs::create_dir_all(root.join("cachex")).expect("create the prefix-sharing sibling");
  std::fs::create_dir_all(root.join("kept/inner")).expect("create the reported subtree");
  let Ok(meta) = std::fs::metadata(&root) else {
    let _ = std::fs::remove_dir_all(&root);
    return;
  };
  let root_dev = meta.dev();
  let Some(expected) = real_dir_fid(&root, [0u8; 8]) else {
    let _ = std::fs::remove_dir_all(&root);
    eprintln!("SKIP the_seed_walk_maps_no_directory_at_or_under_an_exclusion: no handle");
    return;
  };

  // Control: with NO exclusions every directory is mapped, so the assertions below
  // are about the fence and not about the walk failing to reach these names.
  let all = seed_walk(
    &root,
    [0u8; 8],
    root_dev,
    &expected,
    &[],
    None,
    MAX_WALK_DECLINES,
  )
  .expect("the unexcluded walk seeds the whole tree");
  let named = |entries: &[crate::os::linux::fanotify::map::SeedEntry], name: &str| {
    entries
      .iter()
      .any(|e| e.name == std::ffi::OsStr::new(name) && e.parent.is_some())
  };
  assert!(
    named(&all.entries, "cache"),
    "control: cache is mapped unexcluded"
  );
  assert!(
    named(&all.entries, "deep"),
    "control: cache/deep is mapped unexcluded"
  );

  let exclusions = vec![root.join("cache")];
  let fenced = seed_walk(
    &root,
    [0u8; 8],
    root_dev,
    &expected,
    &exclusions,
    None,
    MAX_WALK_DECLINES,
  )
  .expect("the excluded walk still seeds the rest of the tree");
  let _ = std::fs::remove_dir_all(&root);

  assert!(
    !named(&fenced.entries, "cache"),
    "the exclusion directory itself is never mapped — a mapped one admits its whole \
     subtree's events forever"
  );
  assert!(
    !named(&fenced.entries, "deep"),
    "the fence SKIPS the descent, so nothing under the exclusion is mapped either"
  );
  assert!(
    named(&fenced.entries, "cachex"),
    "a sibling sharing a byte prefix is still mapped — containment is component-wise"
  );
  assert!(
    named(&fenced.entries, "kept") && named(&fenced.entries, "inner"),
    "unrelated subtrees are mapped exactly as before"
  );
  assert!(
    fenced.entries.iter().any(|e| e.parent.is_none()),
    "the root anchor is seeded"
  );
}

/// The reseed-root gate's MATCHING-FID row on a real filesystem: `seed_walk` handed
/// the root's REAL FID as `expected` proceeds normally — the gate passes and the
/// root anchor is seeded. `expected` carries an EVENT-STYLE fsid that differs from
/// the seed `statfs` fsid the walk passes, exercising the same handle-only rule the
/// btrfs divergence forces at the subtree gate: the anchor is matched by handle
/// bytes, never fsid, so the reseed does not falsely fatal when the two fsids
/// diverge. Also guards against the verification over-rejecting the genuine root (a
/// false-positive that would turn every real reseed into a fatal).
#[test]
fn reseed_root_fid_match_seeds_normally() {
  use std::os::unix::fs::MetadataExt;

  let root = std::env::temp_dir().join(format!("tributary-fs-reseed-match-{}", std::process::id()));
  let _ = std::fs::remove_dir_all(&root);
  std::fs::create_dir_all(root.join("sub")).expect("create a walkable root");
  let Ok(meta) = std::fs::metadata(&root) else {
    let _ = std::fs::remove_dir_all(&root);
    return;
  };
  let root_dev = meta.dev();
  // The expected anchor's fsid is event-style ([9; 8]); the walk seeds with the
  // statfs fsid ([0; 8]). On a handle-only gate the divergence is irrelevant.
  let Some(expected) = real_dir_fid(&root, [0u8; 8]).map(with_fsid([9u8; 8])) else {
    let _ = std::fs::remove_dir_all(&root);
    eprintln!("SKIP reseed_root_fid_match_seeds_normally: temp root exports no handle");
    return;
  };
  let result = seed_walk(
    &root,
    [0u8; 8],
    root_dev,
    &expected,
    &[],
    None,
    MAX_WALK_DECLINES,
  );
  let _ = std::fs::remove_dir_all(&root);
  let entries = result
    .expect("the genuine root passes the FID gate and seeds")
    .entries;
  // The root anchor plus its `sub` child — the gate did not block the real root.
  assert!(
    entries.iter().any(|e| e.parent.is_none()),
    "the matching-FID walk seeded the root anchor"
  );
  assert!(
    entries
      .iter()
      .any(|e| e.name == std::ffi::OsStr::new("sub") && e.parent.is_some()),
    "the matching-FID walk descended into the child"
  );
}

/// The pending move-in subtree FID gate on a real filesystem: `subtree_walk`
/// whose reopened directory's handle does NOT equal the `subtree_fid` the map
/// learned fails [`WalkError::Incomplete`] — folding to the reader's
/// retry-then-fatal — WITHOUT linking any descendant under the moved-in identity.
/// A wrong `subtree_fid` stands in for a same-superblock directory swapped in at
/// the resolved path (whose descendants would otherwise seed under the moved dir's
/// FID — foreign admission).
#[test]
fn subtree_fid_mismatch_is_incomplete_without_seeding() {
  use std::os::unix::fs::MetadataExt;

  let subtree = std::env::temp_dir().join(format!(
    "tributary-fs-subtree-mismatch-{}",
    std::process::id()
  ));
  let _ = std::fs::remove_dir_all(&subtree);
  std::fs::create_dir_all(subtree.join("child")).expect("create a walkable subtree");
  let Ok(meta) = std::fs::metadata(&subtree) else {
    let _ = std::fs::remove_dir_all(&subtree);
    return;
  };
  let root_dev = meta.dev();
  if real_dir_fid(&subtree, [0u8; 8]).is_none() {
    let _ = std::fs::remove_dir_all(&subtree);
    eprintln!("SKIP subtree_fid_mismatch_is_incomplete_without_seeding: temp fs exports no handle");
    return;
  }
  // A wrong learned FID: the real reopened subtree will not encode to these bytes.
  let wrong = some_fid(0xAB);
  let result = subtree_walk(
    &subtree,
    &wrong,
    [0u8; 8],
    root_dev,
    &[],
    None,
    MAX_WALK_DECLINES,
  );
  let _ = std::fs::remove_dir_all(&subtree);
  assert!(
    matches!(result, Err(WalkError::Incomplete(_))),
    "a reopened subtree whose handle does not equal the learned FID is Incomplete, never a seed \
     of the replacement's descendants under the moved-in identity"
  );
}

/// The move-in subtree gate's MATCHING-FID row on a real filesystem, in the
/// finding's exact shape: `subtree_fid` is the EVENT FID (its fsid stamped by the
/// kernel per-superblock), while the walk seeds with the `statfs` per-subvolume
/// fsid — the btrfs divergence. On the handle-only gate the two fsids being
/// unequal is IRRELEVANT: the walk PROCEEDS and maps the descendants under the
/// event FID. A full-`Fid` compare would falsely reject this genuine moved-in
/// directory → false `Incomplete` → retry → false FATAL on a valid scope. Guards
/// the verification against both over-rejecting the genuine moved dir AND
/// re-importing fsid into the trust decision.
#[test]
fn subtree_fid_match_seeds_descendants() {
  use std::os::unix::fs::MetadataExt;

  let subtree =
    std::env::temp_dir().join(format!("tributary-fs-subtree-match-{}", std::process::id()));
  let _ = std::fs::remove_dir_all(&subtree);
  std::fs::create_dir_all(subtree.join("child")).expect("create a walkable subtree");
  let Ok(meta) = std::fs::metadata(&subtree) else {
    let _ = std::fs::remove_dir_all(&subtree);
    return;
  };
  let root_dev = meta.dev();
  // The learned FID carries an EVENT-style fsid ([9; 8]); the walk seeds with the
  // statfs fsid ([0; 8]). The reopened object's real handle equals this FID's
  // handle, so a handle-only gate matches despite the diverging fsids.
  let Some(subtree_fid) = real_dir_fid(&subtree, [0u8; 8]).map(with_fsid([9u8; 8])) else {
    let _ = std::fs::remove_dir_all(&subtree);
    eprintln!("SKIP subtree_fid_match_seeds_descendants: temp fs exports no handle");
    return;
  };
  let result = subtree_walk(
    &subtree,
    &subtree_fid,
    [0u8; 8],
    root_dev,
    &[],
    None,
    MAX_WALK_DECLINES,
  );
  let _ = std::fs::remove_dir_all(&subtree);
  let entries = result.map(|seed| seed.entries).expect(
    "the genuine subtree passes the handle-only FID gate and seeds descendants, even with an \
     event fsid diverging from the statfs fsid",
  );
  assert!(
    entries
      .iter()
      .any(|e| e.name == std::ffi::OsStr::new("child") && e.parent.as_ref() == Some(&subtree_fid)),
    "the matching-FID subtree walk mapped the descendant under the moved dir's event FID"
  );
}

/// The real walk over a root whose CHILD directory this process cannot read
/// returns [`WalkError::Incomplete`] — the seed walk itself (not just the pure
/// classifier) refuses to seed a blind subtree. Self-probing: root with
/// `CAP_DAC_OVERRIDE` reads the `chmod 000` child regardless, so the assertion
/// only fires where permissions genuinely bite (an unprivileged runner); it skips
/// loudly otherwise. The `fsid`/`root_dev` are read from the real temp root so the
/// walk descends into the child before the read failure surfaces.
#[test]
fn unreadable_child_makes_the_real_walk_incomplete() {
  use std::os::unix::fs::{MetadataExt, PermissionsExt};

  let root = std::env::temp_dir().join(format!(
    "tributary-fs-walk-incomplete-{}",
    std::process::id()
  ));
  let child = root.join("blocked");
  let _ = std::fs::remove_dir_all(&root);
  std::fs::create_dir_all(&child).expect("create the child dir");
  let Ok(meta) = std::fs::metadata(&root) else {
    let _ = std::fs::remove_dir_all(&root);
    return;
  };
  let root_dev = meta.dev();

  if std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o000)).is_err() {
    let _ = std::fs::remove_dir_all(&root);
    return;
  }
  if std::fs::read_dir(&child).is_ok() {
    // Root/DAC_OVERRIDE reads it anyway — the walk would complete here.
    let _ = std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o755));
    let _ = std::fs::remove_dir_all(&root);
    eprintln!(
      "SKIP unreadable_child_makes_the_real_walk_incomplete: the 000 child is readable \
       (root/CAP_DAC_OVERRIDE)"
    );
    return;
  }

  // Hand the walk the root's REAL FID so its reopen-verification passes and the
  // descent reaches the unreadable child (a wrong expected FID would fail RootGone
  // at the root, never exercising the child path this cell is about).
  let Some(expected) = real_dir_fid(&root, [0u8; 8]) else {
    let _ = std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o755));
    let _ = std::fs::remove_dir_all(&root);
    eprintln!(
      "SKIP unreadable_child_makes_the_real_walk_incomplete: the temp root exports no handle"
    );
    return;
  };
  let result = seed_walk(
    &root,
    [0u8; 8],
    root_dev,
    &expected,
    &[],
    None,
    MAX_WALK_DECLINES,
  );
  // Restore permissions BEFORE asserting so cleanup always succeeds.
  let _ = std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o755));
  let _ = std::fs::remove_dir_all(&root);
  match result {
    Err(WalkError::Incomplete(_)) => {}
    // A filesystem whose root cannot export a handle fails earlier as RootGone —
    // then this environment cannot exercise the descendant path, so skip.
    Err(WalkError::RootGone(_)) => {
      eprintln!(
        "SKIP unreadable_child_makes_the_real_walk_incomplete: the temp root exports no handle"
      );
    }
    Ok(_) => panic!("an unreadable in-root child directory must make the walk Incomplete"),
  }
}

/// The real subtree walk over a populated directory (a stand-in for a directory
/// MOVED IN from outside the root) produces a [`SeedEntry`] per DESCENDANT
/// directory, each linked to its parent, and does NOT re-emit the subtree root
/// itself (the caller already learned it). The `fsid`/`root_dev` are read from the
/// real temp tree so the single-device descent stays inside it.
#[test]
fn subtree_walk_maps_descendants_not_the_root() {
  use std::os::unix::fs::MetadataExt;

  let subtree =
    std::env::temp_dir().join(format!("tributary-fs-subtree-walk-{}", std::process::id()));
  // subtree/{child/{grand/}, leaf.txt} — two descendant DIRECTORIES and a file.
  let grand = subtree.join("child/grand");
  let _ = std::fs::remove_dir_all(&subtree);
  std::fs::create_dir_all(&grand).expect("create the descendant dirs");
  std::fs::write(subtree.join("leaf.txt"), b"x").expect("create a file");
  let Ok(meta) = std::fs::metadata(&subtree) else {
    let _ = std::fs::remove_dir_all(&subtree);
    return;
  };
  let root_dev = meta.dev();
  // The moved dir's learned FID must be its REAL handle now — the subtree walk
  // verifies the reopened directory against it before descending, so a
  // stand-in FID would be rejected as a same-superblock replacement. Encode it the
  // way the reader would have when it learned the move-in.
  let Some(subtree_fid) = real_dir_fid(&subtree, [0u8; 8]) else {
    let _ = std::fs::remove_dir_all(&subtree);
    eprintln!("SKIP subtree_walk_maps_descendants_not_the_root: temp fs exports no handles");
    return;
  };

  let result = subtree_walk(
    &subtree,
    &subtree_fid,
    [0u8; 8],
    root_dev,
    &[],
    None,
    MAX_WALK_DECLINES,
  );
  let _ = std::fs::remove_dir_all(&subtree);
  let entries = match result {
    Ok(seed) => seed.entries,
    // A temp filesystem that cannot export handles fails as Incomplete on the
    // first descendant — then this environment cannot exercise the mapping, skip.
    Err(WalkError::Incomplete(_)) => {
      eprintln!("SKIP subtree_walk_maps_descendants_not_the_root: temp fs exports no handles");
      return;
    }
    Err(WalkError::RootGone(_)) => unreachable!("subtree_walk never reports RootGone"),
  };
  // Two descendant directories (child, grand); the file and the subtree root are
  // NOT entries.
  assert_eq!(
    entries.len(),
    2,
    "exactly the two descendant directories are mapped, not the root or the file"
  );
  // The top descendant links to the subtree root FID (the moved directory).
  assert!(
    entries
      .iter()
      .any(|e| e.name == std::ffi::OsStr::new("child") && e.parent.as_ref() == Some(&subtree_fid)),
    "the top descendant hangs off the moved directory's FID"
  );
  // Every entry is a child (none is a root anchor).
  assert!(
    entries.iter().all(|e| e.parent.is_some()),
    "no entry is a root anchor — the moved directory itself is not re-emitted"
  );
}

/// An unreadable descendant inside a moved-in subtree makes the subtree walk
/// INCOMPLETE, the same completeness rule the seed walk enforces — a foreign
/// populated directory with a blind sub-subtree cannot be admitted half-mapped.
/// Self-probing exactly like `unreadable_child_makes_the_real_walk_incomplete`.
#[test]
fn subtree_walk_unreadable_descendant_is_incomplete() {
  use std::os::unix::fs::{MetadataExt, PermissionsExt};

  let subtree = std::env::temp_dir().join(format!(
    "tributary-fs-subtree-walk-blocked-{}",
    std::process::id()
  ));
  let blocked = subtree.join("blocked");
  let _ = std::fs::remove_dir_all(&subtree);
  std::fs::create_dir_all(&blocked).expect("create the descendant dir");
  let Ok(meta) = std::fs::metadata(&subtree) else {
    let _ = std::fs::remove_dir_all(&subtree);
    return;
  };
  let root_dev = meta.dev();
  // The moved dir's learned FID must be the top's REAL handle so the subtree walk's
  // reopen-verification passes and the descent reaches the unreadable
  // `blocked` child — the intended incompleteness (a stand-in FID would fail the
  // top-level gate instead, a different failure than this cell asserts). The top is
  // readable, so it encodes even while `blocked` is 000.
  let Some(subtree_fid) = real_dir_fid(&subtree, [0u8; 8]) else {
    let _ = std::fs::remove_dir_all(&subtree);
    eprintln!("SKIP subtree_walk_unreadable_descendant_is_incomplete: temp fs exports no handles");
    return;
  };

  if std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000)).is_err() {
    let _ = std::fs::remove_dir_all(&subtree);
    return;
  }
  if std::fs::read_dir(&blocked).is_ok() {
    let _ = std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o755));
    let _ = std::fs::remove_dir_all(&subtree);
    eprintln!(
      "SKIP subtree_walk_unreadable_descendant_is_incomplete: the 000 dir is readable \
       (root/CAP_DAC_OVERRIDE)"
    );
    return;
  }

  let result = subtree_walk(
    &subtree,
    &subtree_fid,
    [0u8; 8],
    root_dev,
    &[],
    None,
    MAX_WALK_DECLINES,
  );
  let _ = std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o755));
  let _ = std::fs::remove_dir_all(&subtree);
  match result {
    Err(WalkError::Incomplete(_)) => {}
    Err(WalkError::RootGone(_)) => unreachable!("subtree_walk never reports RootGone"),
    Ok(_) => panic!("an unreadable descendant in a moved-in subtree must make the walk Incomplete"),
  }
}

/// `subtree_walk` on a MISSING path is `Incomplete`, NOT a benign empty walk. The
/// reader resolves the moved dir's current path through the map and only calls this
/// while the node is still in-map and `pending_walk` — so a `NotFound` means no
/// rename-out was processed (the single-threaded reader would have forgotten it
/// first) and the directory should be present. Swallowing it as an empty subtree is
/// exactly the burst hole that would leave a re-moved populated dir's descendants
/// blind forever. It folds to the reader's retry-once-then-blind→fatal.
#[test]
fn subtree_walk_on_missing_path_is_incomplete_not_empty() {
  let missing = std::env::temp_dir().join(format!(
    "tributary-fs-subtree-walk-missing-{}",
    std::process::id()
  ));
  let _ = std::fs::remove_dir_all(&missing);
  let subtree_fid = Fid::new([7; 8], Box::from(&[7u8][..]));
  match subtree_walk(
    &missing,
    &subtree_fid,
    [0u8; 8],
    0,
    &[],
    None,
    MAX_WALK_DECLINES,
  ) {
    Err(WalkError::Incomplete(err)) => {
      assert_eq!(
        err.kind(),
        io::ErrorKind::NotFound,
        "the incompleteness carries the NotFound that opening the missing dir raised"
      );
    }
    Err(WalkError::RootGone(_)) => unreachable!("subtree_walk never reports RootGone"),
    Ok(seed) => panic!(
      "a missing moved-in subtree path must be Incomplete, not an empty walk (got {} entries)",
      seed.entries.len()
    ),
  }
}

/// The directory cap (design §4.9) on a real tree: a `seed_walk` whose cap is
/// SMALLER than the tree's directory count aborts as [`WalkError::Incomplete`]
/// (the fanotify-not-viable class the spawn folds to `NotViable` and the reseed to
/// fatal — never a multi-gigabyte map built blind), while a generous cap seeds the
/// whole tree. The cap is fenced during the descent, so the oversized inventory is
/// never materialized.
#[test]
fn seed_walk_over_the_directory_cap_is_incomplete() {
  use std::os::unix::fs::MetadataExt;

  let root = std::env::temp_dir().join(format!("tributary-fs-cap-walk-{}", std::process::id()));
  let _ = std::fs::remove_dir_all(&root);
  // Root + three subdirectories = four directories total.
  std::fs::create_dir_all(root.join("a")).expect("create a walkable root");
  std::fs::create_dir_all(root.join("b")).expect("subdir b");
  std::fs::create_dir_all(root.join("c")).expect("subdir c");
  let Ok(meta) = std::fs::metadata(&root) else {
    let _ = std::fs::remove_dir_all(&root);
    return;
  };
  let root_dev = meta.dev();
  let Some(expected) = real_dir_fid(&root, [0u8; 8]) else {
    let _ = std::fs::remove_dir_all(&root);
    eprintln!("SKIP seed_walk_over_the_directory_cap_is_incomplete: temp root exports no handle");
    return;
  };

  // A cap of two cannot hold four directories: the walk aborts as Incomplete.
  let capped = seed_walk(
    &root,
    [0u8; 8],
    root_dev,
    &expected,
    &[],
    Some(2),
    MAX_WALK_DECLINES,
  );
  assert!(
    matches!(capped, Err(WalkError::Incomplete(_))),
    "a tree exceeding the directory cap is Incomplete (fanotify not viable), not a partial seed"
  );

  // A generous cap seeds the whole tree.
  let ok = seed_walk(
    &root,
    [0u8; 8],
    root_dev,
    &expected,
    &[],
    Some(1000),
    MAX_WALK_DECLINES,
  );
  let _ = std::fs::remove_dir_all(&root);
  let entries = ok.expect("a generous cap seeds the whole tree").entries;
  assert_eq!(
    entries.len(),
    4,
    "root + three subdirectories seed under a cap that comfortably holds them"
  );
}

/// The walk's TWO budgets, held apart — the MAP budget (`max_map_directories`,
/// the public option) bounds only what would become map nodes, and the
/// WALK-OUTPUT budget ([`MAX_WALK_DECLINES`]) bounds the boundaries the walk
/// reports.
///
/// Both halves have been wrong in turn, in opposite directions, so both are held
/// here on ONE staging:
///
/// - the entry fence once read `seed.entries.len()` alone while both decline
///   pushes ran above it, so a FLAT tree of boundary directories — the
///   btrfs-subvolume layout this design exists to support, and a container host's
///   mount farm — grew `WalkSeed::declined` without limit while `entries` never
///   moved past the anchor. That is the leg that caps the declines.
/// - charging BOTH vectors to `max_map_directories` then made a legal
///   configuration illegal. The option's documented meaning is the map's size, and
///   a declined boundary never becomes a map node — so a cap of ONE rejected a
///   root whose map would have held exactly one directory, and any tree that fit
///   before but had declined anything failed at spawn (and, on recovery, failed
///   twice and killed a live scope). That is the leg that admits the tree.
///
/// The staging is deliberately a tree the ENTRY fence can never catch: every child
/// is declined, so `entries` stays at exactly ONE (the root anchor) for the whole
/// walk. A cell that let some children through would pass with the decline fence
/// deleted, because the entry fence would catch the same tree — the false green
/// this branch has already produced once.
///
/// Boundaries without a privileged mount: `seed_from_fd` takes the fence frame as
/// a PARAMETER, so handing it a frame no child can match makes the mount fence
/// decline every one of them (the same seam
/// `seed_from_fd_fences_on_the_handed_mount_frame_not_a_stale_one` uses).
#[test]
fn the_map_budget_and_the_walk_output_budget_bound_different_vectors() {
  use std::os::{fd::AsFd, unix::fs::MetadataExt};

  let root = std::env::temp_dir().join(format!(
    "tributary-fs-decline-budget-{}",
    std::process::id()
  ));
  let _ = std::fs::remove_dir_all(&root);
  std::fs::create_dir_all(&root).expect("create a walkable root");
  for n in 0..6 {
    std::fs::create_dir_all(root.join(format!("b{n}"))).expect("create a flat boundary child");
  }
  let Ok(meta) = std::fs::metadata(&root) else {
    let _ = std::fs::remove_dir_all(&root);
    return;
  };
  let root_dev = meta.dev();
  let Some(root_fd) = open_dir_fd(&root) else {
    let _ = std::fs::remove_dir_all(&root);
    eprintln!(
      "SKIP the_map_budget_and_the_walk_output_budget_bound_different_vectors: cannot open root"
    );
    return;
  };
  // A frame no child can match makes EVERY child a mount-fence decline. Needs the
  // host to answer mount ids at all: an `Ok(None)` degrades to the device belt, and
  // then nothing here declines.
  let Ok(Some(fresh)) = crate::os::linux::root_mount_id(root_fd.as_fd()) else {
    let _ = std::fs::remove_dir_all(&root);
    eprintln!(
      "SKIP the_map_budget_and_the_walk_output_budget_bound_different_vectors: no mount id reported"
    );
    return;
  };
  let unmatchable = fresh.wrapping_add(1);

  // Uncapped: the shape is confirmed before anything is asserted about the fence —
  // one entry (the anchor) and six declines. `entries.len()` is 1 the whole way, so
  // the entry fence cannot be what aborts the capped walk below.
  let uncapped = seed_from_fd(
    open_dir_fd(&root).expect("re-open root for the uncapped walk"),
    &root,
    &WalkFrame {
      fsid: [0u8; 8],
      root_dev,
      fence_mnt_id: Some(unmatchable),
      exclusions: &[],
      budget: None,
      decline_budget: MAX_WALK_DECLINES,
    },
  )
  .expect("an all-boundary root still seeds its anchor");
  assert_eq!(
    uncapped.entries.len(),
    1,
    "staging: only the root anchor is ever an ENTRY — every child declines"
  );
  assert_eq!(
    uncapped.declined.len(),
    6,
    "staging: all six flat boundaries are declined: {:?}",
    uncapped.declined
  );

  // A WALK-OUTPUT budget of four cannot hold six declines. Only the decline fence
  // can trip here: `entries.len()` never exceeds 1, and the map budget is
  // uncapped.
  let over_output = seed_from_fd(
    open_dir_fd(&root).expect("re-open root for the decline-budget walk"),
    &root,
    &WalkFrame {
      fsid: [0u8; 8],
      root_dev,
      fence_mnt_id: Some(unmatchable),
      exclusions: &[],
      budget: None,
      decline_budget: 4,
    },
  );
  assert!(
    matches!(over_output, Err(WalkError::Incomplete(_))),
    "the walk's REPORT is bounded: an all-boundary tree past the walk-output \
     limit is Incomplete (fanotify not viable), never an unbounded decline list \
     — got {:?}",
    over_output.map(|seed| (seed.entries.len(), seed.declined.len()))
  );

  // And the other direction: a MAP budget of ONE holds exactly one directory —
  // the anchor — which is all this tree ever asks the map for. Charging the six
  // declines against it is what made this legal configuration fail at spawn.
  let one_directory = seed_from_fd(
    root_fd,
    &root,
    &WalkFrame {
      fsid: [0u8; 8],
      root_dev,
      fence_mnt_id: Some(unmatchable),
      exclusions: &[],
      budget: Some(1),
      decline_budget: MAX_WALK_DECLINES,
    },
  );
  let _ = std::fs::remove_dir_all(&root);
  let one_directory =
    one_directory.expect("a map cap of one admits a root whose map holds one directory");
  assert_eq!(
    one_directory.entries.len(),
    1,
    "the map really does hold exactly one directory under the cap of one"
  );
  assert_eq!(
    one_directory.declined.len(),
    6,
    "and every boundary is still reported: the declines are bounded elsewhere, \
     not silently truncated: {:?}",
    one_directory.declined
  );
}

/// The two fences held directly against ONE inventory, which is the only
/// order-independent way to hold them.
///
/// The end-to-end cell above walks a real tree, and `readdir` yields that tree's
/// children in whatever order the filesystem likes — so a staging that mixes
/// entries and declines proves "the map budget counts entries ONLY" on some
/// orderings and not others. The two predicates are pure functions of one
/// `WalkSeed`, so asking them directly is exact: the same inventory, one budget
/// at a time, each held at both sides of its own threshold.
///
/// This is the cell that fails if the two counts are ever folded back together —
/// a fence reading `entries.len() + declined.len()` answers `Err` at the first
/// assertion below, where a map with room for two directories holds one.
#[test]
fn the_two_walk_budgets_each_count_only_their_own_vector() {
  let seed = WalkSeed {
    entries: vec![SeedEntry::root(some_fid(1), std::path::Path::new("/r"))],
    declined: vec![
      crate::os::DeclinedBoundary {
        location: std::path::PathBuf::from("/r/a"),
        dev: 99,
        mnt_id: Some(7),
      },
      crate::os::DeclinedBoundary {
        location: std::path::PathBuf::from("/r/b"),
        dev: 99,
        mnt_id: Some(8),
      },
      crate::os::DeclinedBoundary {
        location: std::path::PathBuf::from("/r/c"),
        dev: 99,
        mnt_id: Some(9),
      },
    ],
    // Neither fence reads the walked frame; it is here because the two vectors
    // and the frame come out of one walk.
    fence_mnt_id: Some(42),
  };

  // The MAP budget sees one directory, never four. `max_map_directories` is a
  // public option whose documented meaning is the admission map's size, and a
  // declined boundary never becomes a map node.
  assert!(
    fence_entries(Some(2), &seed).is_ok(),
    "a map budget of two has room for the one directory this inventory would map"
  );
  assert!(
    fence_entries(None, &seed).is_ok(),
    "and an uncapped map budget fences nothing at all"
  );
  assert!(
    matches!(fence_entries(Some(1), &seed), Err(WalkError::Incomplete(_))),
    "it does still bind: one directory held under a budget of one leaves no room \
     for the next"
  );

  // The WALK-OUTPUT budget sees three declines, never four, and never the map's
  // number.
  assert!(
    fence_declines(4, &seed).is_ok(),
    "a walk-output budget of four has room past the three boundaries reported"
  );
  assert!(
    matches!(fence_declines(3, &seed), Err(WalkError::Incomplete(_))),
    "and it binds at its own threshold — the declines stay bounded, just not out \
     of the map's budget"
  );
}

/// A `Some(0)` cap fences the ANCHOR itself, not just the descent's children: an
/// EMPTY root (no descendants to trip the child fence) is still `Incomplete`, since
/// a zero cap means the map may never hold even the root anchor. This is the
/// fanotify-unviable class the spawn folds to `NotViable` (Auto → inotify, forced →
/// typed error) — never a live one-node map whose first event trips `over_capacity`.
#[test]
fn a_zero_cap_is_incomplete_even_for_an_empty_root() {
  use std::os::unix::fs::MetadataExt;

  let root = std::env::temp_dir().join(format!("tributary-fs-zero-cap-{}", std::process::id()));
  let _ = std::fs::remove_dir_all(&root);
  // An empty root: no children exist, so ONLY the anchor fence can make this
  // Incomplete — exactly the hole the child-only fence left open.
  std::fs::create_dir_all(&root).expect("create an empty walkable root");
  let Ok(meta) = std::fs::metadata(&root) else {
    let _ = std::fs::remove_dir_all(&root);
    return;
  };
  let root_dev = meta.dev();
  let Some(expected) = real_dir_fid(&root, [0u8; 8]) else {
    let _ = std::fs::remove_dir_all(&root);
    eprintln!("SKIP a_zero_cap_is_incomplete_even_for_an_empty_root: temp root exports no handle");
    return;
  };

  let capped = seed_walk(
    &root,
    [0u8; 8],
    root_dev,
    &expected,
    &[],
    Some(0),
    MAX_WALK_DECLINES,
  );
  let _ = std::fs::remove_dir_all(&root);
  assert!(
    matches!(capped, Err(WalkError::Incomplete(_))),
    "a zero cap admits no map at all — Incomplete (fanotify not viable) even for an empty root, \
     never a live one-node anchor map: {capped:?}"
  );
}

/// A `Some(1)` cap seeds EXACTLY the root anchor and lives: the anchor fits (one
/// directory), and an empty root has no children to overflow it. This pins the
/// boundary opposite [`a_zero_cap_is_incomplete_even_for_an_empty_root`] — the cap
/// bounds the map INCLUSIVELY at its ceiling, so a cap equal to the anchor count is
/// a viable one-node seed, not a rejection.
#[test]
fn a_cap_of_one_seeds_exactly_the_anchor_for_an_empty_root() {
  use std::os::unix::fs::MetadataExt;

  let root = std::env::temp_dir().join(format!("tributary-fs-cap-one-{}", std::process::id()));
  let _ = std::fs::remove_dir_all(&root);
  std::fs::create_dir_all(&root).expect("create an empty walkable root");
  let Ok(meta) = std::fs::metadata(&root) else {
    let _ = std::fs::remove_dir_all(&root);
    return;
  };
  let root_dev = meta.dev();
  let Some(expected) = real_dir_fid(&root, [0u8; 8]) else {
    let _ = std::fs::remove_dir_all(&root);
    eprintln!(
      "SKIP a_cap_of_one_seeds_exactly_the_anchor_for_an_empty_root: temp root exports no \
               handle"
    );
    return;
  };

  let ok = seed_walk(
    &root,
    [0u8; 8],
    root_dev,
    &expected,
    &[],
    Some(1),
    MAX_WALK_DECLINES,
  );
  let _ = std::fs::remove_dir_all(&root);
  let entries = ok
    .expect("a cap of one holds the sole root anchor of an empty root")
    .entries;
  assert_eq!(
    entries.len(),
    1,
    "exactly the root anchor seeds under a cap of one"
  );
  assert!(
    entries[0].parent.is_none(),
    "the single seeded entry is the root anchor (no parent)"
  );
}

/// The descent fences children against the mount frame it is HANDED, and the live
/// path-reopen walks hand it the frame they re-read from the reopened root fd — so
/// a same-object re-mount fences descendants on the NEW frame, not a stale one.
/// Exercised at the `seed_from_fd` seam: fed the root fd's OWN fresh mount id, a
/// same-mount child is descended; fed a STALE frame (a spawn-captured id after the
/// root moved mounts), the identical child reads as a boundary and is skipped. This
/// is the re-mount shape without a privileged bind — the container `remount` cell
/// proves the reopen-recompute end to end.
#[test]
fn seed_from_fd_fences_on_the_handed_mount_frame_not_a_stale_one() {
  use std::os::{fd::AsFd, unix::fs::MetadataExt};

  let root = std::env::temp_dir().join(format!("tributary-fs-fence-frame-{}", std::process::id()));
  let _ = std::fs::remove_dir_all(&root);
  std::fs::create_dir_all(root.join("child")).expect("create a walkable root + child");
  let Ok(meta) = std::fs::metadata(&root) else {
    let _ = std::fs::remove_dir_all(&root);
    return;
  };
  let root_dev = meta.dev();
  let Some(root_fd) = open_dir_fd(&root) else {
    let _ = std::fs::remove_dir_all(&root);
    eprintln!(
      "SKIP seed_from_fd_fences_on_the_handed_mount_frame_not_a_stale_one: cannot open root"
    );
    return;
  };
  // The root fd's TRUE current frame — what the reopen recompute reads and hands
  // the descent. A filesystem that reports no mount id (a successful `Ok(None)`
  // mask-absent read) degrades to the device belt (no frame to make stale), so this
  // cell cannot exercise the fence: skip loudly. A statx read error is likewise not
  // exercisable here.
  let Ok(Some(fresh)) = crate::os::linux::root_mount_id(root_fd.as_fd()) else {
    let _ = std::fs::remove_dir_all(&root);
    eprintln!(
      "SKIP seed_from_fd_fences_on_the_handed_mount_frame_not_a_stale_one: no mount id reported"
    );
    return;
  };

  // Handed the FRESH frame the reopen reads from the fd, the same-mount child is
  // descended: root anchor + the child.
  let with_fresh = seed_from_fd(
    open_dir_fd(&root).expect("re-open root for the fresh-frame walk"),
    &root,
    &WalkFrame {
      fsid: [0u8; 8],
      root_dev,
      fence_mnt_id: Some(fresh),
      exclusions: &[],
      budget: None,
      decline_budget: MAX_WALK_DECLINES,
    },
  );
  let with_fresh = match with_fresh {
    Ok(seed) => seed,
    // A temp fs that cannot export handles fails on the child — then this
    // environment cannot exercise the descent, so skip.
    Err(_) => {
      let _ = std::fs::remove_dir_all(&root);
      eprintln!(
        "SKIP seed_from_fd_fences_on_the_handed_mount_frame_not_a_stale_one: temp fs exports no \
         handle"
      );
      return;
    }
  };
  assert!(
    with_fresh
      .entries
      .iter()
      .any(|e| e.name == std::ffi::OsStr::new("child") && e.parent.is_some()),
    "the fresh reopen frame descends the same-mount child"
  );
  // SEAM 2's control leg: a walk that fences nothing declines nothing, so the
  // recorded set stays empty and the assertion below is about the FENCE rather
  // than about the walk emitting a decline for every child it sees.
  assert!(
    with_fresh.declined.is_empty(),
    "a walk that descends every child declines no boundary: {:?}",
    with_fresh.declined
  );

  // Handed a STALE frame (a spawn-captured id from before the root moved mounts), the
  // identical child now differs from the fence and is skipped — the silent blindness
  // the reopen-recompute avoids by reading the frame from the current fd.
  let stale = fresh.wrapping_add(1);
  let with_stale = seed_from_fd(
    root_fd,
    &root,
    &WalkFrame {
      fsid: [0u8; 8],
      root_dev,
      fence_mnt_id: Some(stale),
      exclusions: &[],
      budget: None,
      decline_budget: MAX_WALK_DECLINES,
    },
  )
  .expect("the stale-frame walk still seeds the root anchor, just skips the child");
  let _ = std::fs::remove_dir_all(&root);
  assert!(
    !with_stale
      .entries
      .iter()
      .any(|e| e.name == std::ffi::OsStr::new("child")),
    "a STALE fence frame marks the same-mount child a boundary and skips it — which is \
     why the reopen-recompute reads the frame from the current fd"
  );
  assert!(
    with_stale.entries.iter().any(|e| e.parent.is_none()),
    "the root anchor is still seeded under either frame"
  );
  // SEAM 2, at the MOUNT-FENCE decline site, on real fds. The same skip that keeps
  // the child out of the map now carries the child OUT of the walk as a boundary:
  // the triple is the one the fence actually read from the pinned fd — the child's
  // own device and its own mount id — not the fence value it was compared against,
  // and not anything a later path re-resolution could reproduce.
  assert_eq!(
    with_stale
      .declined
      .iter()
      .map(|b| (b.location.clone(), b.dev, b.mnt_id))
      .collect::<Vec<_>>(),
    vec![(root.join("child"), root_dev, Some(fresh))],
    "the declined child is surfaced with the identity the fence read, not discarded"
  );
}

/// SEAM 2 at the OTHER decline site: the cheap DEVICE BELT, which must surface a
/// boundary carrying the child's OWN MOUNT ID — read from the pinned fd, exactly
/// as the mount fence's decline does.
///
/// This is the regression the belt once was. The `statx` sat BELOW the belt, so a
/// foreign-device decline was recorded with `mnt_id: None` — and an id-less
/// record is what `MountRecord::condemnable` reads as DEVICE-ONLY, i.e.
/// permanently exempt from every condemnation mechanism. That minted an exempt
/// record from an observation that could not tell a real vfsmount from a
/// same-mount subvolume. The failure it produced was reachable: a genuine mount
/// arriving after the spawn baseline, first observed by a LIVE walk, and departing
/// before any refresh confirmed a row at its location was condemned by nothing —
/// no cover, no admission reseed, and a revealed subtree never seeded into the FID
/// map. The core half of that sequence is
/// `core::tests::linux_fanotify::a_mount_seen_only_by_a_live_walk_is_still_condemnable`.
///
/// A `None` here is now reserved for its one honest meaning: the host answers no
/// mount ids at all. This cell skips loudly rather than passing vacuously on such
/// a host, because `None == None` would hold under the very bug it guards.
///
/// Staged the same way the sibling stages a stale mount frame: `root_dev` is a
/// walk PARAMETER (the spawn captures it from the pin, the reseed carries it), so
/// handing the descent a device its children cannot match puts every child on the
/// far side of the belt with no privilege and no second filesystem.
#[test]
fn seed_from_fd_surfaces_a_device_belt_decline_with_the_childs_mount_id() {
  use std::os::{fd::AsFd, unix::fs::MetadataExt};

  let root = std::env::temp_dir().join(format!("tributary-fs-fence-belt-{}", std::process::id()));
  let _ = std::fs::remove_dir_all(&root);
  std::fs::create_dir_all(root.join("child")).expect("create a walkable root + child");
  let Ok(meta) = std::fs::metadata(&root) else {
    let _ = std::fs::remove_dir_all(&root);
    return;
  };
  let root_dev = meta.dev();
  let Some(root_fd) = open_dir_fd(&root) else {
    let _ = std::fs::remove_dir_all(&root);
    eprintln!(
      "SKIP seed_from_fd_surfaces_a_device_belt_decline_with_the_childs_mount_id: cannot open root"
    );
    return;
  };
  // The child's TRUE mount id, read the way the walk reads it. A host that answers
  // none cannot tell the fixed walk from the broken one, so it skips loudly.
  let Some(child_fd) = open_dir_fd(&root.join("child")) else {
    let _ = std::fs::remove_dir_all(&root);
    eprintln!(
      "SKIP seed_from_fd_surfaces_a_device_belt_decline_with_the_childs_mount_id: cannot open child"
    );
    return;
  };
  let Ok(Some(child_mnt)) = crate::os::linux::root_mount_id(child_fd.as_fd()) else {
    let _ = std::fs::remove_dir_all(&root);
    eprintln!(
      "SKIP seed_from_fd_surfaces_a_device_belt_decline_with_the_childs_mount_id: no mount id \
       reported"
    );
    return;
  };
  drop(child_fd);

  // The belt is handed a device NO child can be on, so the child trips the belt
  // rather than the mount fence — the exact branch that used to skip the read.
  // `fence_mnt_id` is `None` on purpose: the id must be read for the RECORD, not
  // merely for a comparison the fence happens to want.
  let foreign = root_dev.wrapping_add(1);
  let seeded = match seed_from_fd(
    root_fd,
    &root,
    &WalkFrame {
      fsid: [0u8; 8],
      root_dev: foreign,
      fence_mnt_id: None,
      exclusions: &[],
      budget: None,
      decline_budget: MAX_WALK_DECLINES,
    },
  ) {
    Ok(seed) => seed,
    // A temp fs that cannot export handles fails on the ROOT anchor; then this
    // environment cannot exercise the descent at all.
    Err(_) => {
      let _ = std::fs::remove_dir_all(&root);
      eprintln!(
        "SKIP seed_from_fd_surfaces_a_device_belt_decline_with_the_childs_mount_id: temp fs \
         exports no handle"
      );
      return;
    }
  };
  let _ = std::fs::remove_dir_all(&root);

  assert!(
    !seeded
      .entries
      .iter()
      .any(|e| e.name == std::ffi::OsStr::new("child")),
    "staging: the belt skipped the child — a different device is always a boundary"
  );
  assert_eq!(
    seeded
      .declined
      .iter()
      .map(|b| (b.location.clone(), b.dev, b.mnt_id))
      .collect::<Vec<_>>(),
    vec![(root.join("child"), root_dev, Some(child_mnt))],
    "the belt's decline carries the child's own device AND the mount id read from \
     the fd the walk pinned — never a `None` the partition would read as \
     permanently exempt"
  );
}

/// The move-in subtree walk fences on the REMAINING budget the reader threads, not
/// the full cap: a `budget` smaller than the subtree's descendant count aborts
/// `Incomplete` (folding to the reader's retry-then-fatal) rather than mapping past
/// it, while a generous/`None` budget maps every descendant. This is the additive
/// half of the cap taxonomy — a near-cap map hands the walk `cap - len`, so a
/// populated move-in never allocates a whole extra cap before the reader's fatal.
#[test]
fn subtree_walk_fences_on_the_remaining_budget() {
  use std::os::unix::fs::MetadataExt;

  let subtree = std::env::temp_dir().join(format!(
    "tributary-fs-subtree-budget-{}",
    std::process::id()
  ));
  // subtree/{a, b, c} — three descendant directories.
  let _ = std::fs::remove_dir_all(&subtree);
  std::fs::create_dir_all(subtree.join("a")).expect("create descendant a");
  std::fs::create_dir_all(subtree.join("b")).expect("descendant b");
  std::fs::create_dir_all(subtree.join("c")).expect("descendant c");
  let Ok(meta) = std::fs::metadata(&subtree) else {
    let _ = std::fs::remove_dir_all(&subtree);
    return;
  };
  let root_dev = meta.dev();
  let Some(subtree_fid) = real_dir_fid(&subtree, [0u8; 8]) else {
    let _ = std::fs::remove_dir_all(&subtree);
    eprintln!("SKIP subtree_walk_fences_on_the_remaining_budget: temp fs exports no handle");
    return;
  };

  // A budget of one cannot hold three descendants: the additive walk aborts before
  // mapping past the room left — never a partial over-budget seed.
  let capped = subtree_walk(
    &subtree,
    &subtree_fid,
    [0u8; 8],
    root_dev,
    &[],
    Some(1),
    MAX_WALK_DECLINES,
  );
  assert!(
    matches!(capped, Err(WalkError::Incomplete(_))),
    "a subtree exceeding the remaining budget is Incomplete (blind → fatal), not a partial seed"
  );

  // A generous budget maps all three descendants (the moved dir itself is not
  // re-emitted, so exactly the three children).
  let ok = subtree_walk(
    &subtree,
    &subtree_fid,
    [0u8; 8],
    root_dev,
    &[],
    Some(1000),
    MAX_WALK_DECLINES,
  );
  let _ = std::fs::remove_dir_all(&subtree);
  let entries = ok.expect("a generous budget maps every descendant").entries;
  assert_eq!(
    entries.len(),
    3,
    "all three descendant directories map under a budget that comfortably holds them"
  );
}

/// Builds a temp tree `<base>/vol/inner` and returns `(base, vol, dev)`, the
/// shape an admission reseed walks: `vol` is the revealed mountpoint directory
/// (its parent `base` stands in for the mapped tree), `inner` is the ground under
/// it that the seed walk never saw. `None` when the temp filesystem cannot be
/// read at all (the caller skips loudly).
fn revealed_tree(tag: &str) -> Option<(std::path::PathBuf, std::path::PathBuf, u64)> {
  use std::os::unix::fs::MetadataExt;

  let base = std::env::temp_dir().join(format!(
    "tributary-fs-revealed-{tag}-{}",
    std::process::id()
  ));
  let vol = base.join("vol");
  let _ = std::fs::remove_dir_all(&base);
  std::fs::create_dir_all(vol.join("inner")).expect("create the revealed tree");
  std::fs::write(vol.join("leaf.txt"), b"x").expect("create a file");
  let dev = std::fs::metadata(&base).ok()?.dev();
  Some((base, vol, dev))
}

/// The frame of a LIVE path, read exactly as the admission reseed reads its own:
/// `fstat` for the device and `statx(STATX_MNT_ID)` for the mount, both off a
/// pinned no-symlink fd. `None` when the path cannot be opened or stat'd (the
/// caller skips loudly).
///
/// It is read rather than invented because [`revealed_walk`] now compares the
/// frame it is HANDED against the one it reads from the live root, and refuses a
/// request whose frame the root no longer has. A hand-built frame is exactly the
/// superseded request that refusal is for, so staging "the location is across the
/// frame" by lying about the ROOT no longer stages anything — the crossing has to
/// be real, and `a_revealed_walk_refuses_a_location_across_the_frame` makes it so.
fn live_frame(path: &std::path::Path) -> Option<ScopeFrame> {
  use std::os::fd::AsFd as _;
  let fd = open_dir_fd(path)?;
  let stat = rustix::fs::fstat(&fd).ok()?;
  let mnt_id = crate::os::linux::root_mount_id(fd.as_fd()).ok()?;
  Some(ScopeFrame {
    root_dev: Some(stat.st_dev),
    root_mnt_id: mnt_id,
  })
}

/// The ordinary admission reseed: the revealed location enters as a CHILD of its
/// own parent — never a root anchor, which would re-root the whole map — and its
/// descendants come with it. The returned parent FID is what the reader checks
/// against the map before seeding any of it.
#[test]
fn a_revealed_walk_maps_the_location_under_its_real_parent() {
  let Some((base, vol, dev)) = revealed_tree("map") else {
    return;
  };
  let Some(parent_fid) = real_dir_fid(&base, [0u8; 8]) else {
    let _ = std::fs::remove_dir_all(&base);
    eprintln!("SKIP a_revealed_walk_maps_the_location_under_its_real_parent: no handles");
    return;
  };

  let Some(frame) = live_frame(&base) else {
    let _ = std::fs::remove_dir_all(&base);
    eprintln!("SKIP a_revealed_walk_maps_the_location_under_its_real_parent: no frame");
    return;
  };
  let walked = revealed_walk(&vol, &base, frame, [0u8; 8], dev, &[], None);
  let _ = std::fs::remove_dir_all(&base);
  let AdmitWalk::Revealed { parent, seed } = (match walked {
    Ok(walked) => walked,
    Err(_) => {
      eprintln!("SKIP a_revealed_walk_maps_the_location_under_its_real_parent: no handles");
      return;
    }
  }) else {
    panic!("a location on the scope's own frame is revealed, never refused");
  };
  assert_eq!(
    parent, parent_fid,
    "the parent FID comes from the fd the child was opened RELATIVE to, so the \
     parent/child link is the kernel's answer rather than a second path lookup"
  );
  assert_eq!(
    seed.entries.len(),
    2,
    "the revealed location itself plus its one descendant directory (the file is \
     not a map node): {:?}",
    seed.entries
  );
  assert!(
    seed
      .entries
      .iter()
      .any(|e| e.name == std::ffi::OsStr::new("vol") && e.parent.as_ref() == Some(&parent_fid)),
    "the location hangs under its parent as a CHILD: a root anchor here would \
     re-root the live map: {:?}",
    seed.entries
  );
  assert!(
    seed.entries.iter().all(|e| e.parent.is_some()),
    "and nothing in an additive walk is ever a root anchor"
  );
}

/// A live `(root, location)` pair where `location` is a directory directly under
/// `root` sitting on its OWN mount, together with both frames — the only way to
/// drive the admission walk's fence over a real mount boundary without
/// privileges to make one.
///
/// The candidates are the pseudo-filesystems every Linux kernel mounts itself, so
/// at least one pair exists on any host that can run fanotify at all. `root` must
/// also export a FILE HANDLE, because the cells below need the walk to be able to
/// reach its descent: a root that exports none stops at the parent-handle read
/// (overlayfs, which is the root of most containers) and every verdict past the
/// fence would read the same.
fn crossing_pair() -> Option<(
  &'static std::path::Path,
  &'static std::path::Path,
  ScopeFrame,
  ScopeFrame,
)> {
  const CANDIDATES: [(&str, &str); 8] = [
    ("/dev", "/dev/shm"),
    ("/dev", "/dev/mqueue"),
    ("/dev", "/dev/pts"),
    ("/", "/proc"),
    ("/", "/sys"),
    ("/", "/dev"),
    ("/", "/run"),
    ("/", "/tmp"),
  ];
  CANDIDATES.into_iter().find_map(|(root, location)| {
    let root = std::path::Path::new(root);
    let location = std::path::Path::new(location);
    let root_frame = live_frame(root)?;
    let location_frame = live_frame(location)?;
    let crosses = root_frame.root_dev != location_frame.root_dev
      || root_frame.root_mnt_id != location_frame.root_mnt_id;
    (crosses && real_dir_fid(root, [0u8; 8]).is_some()).then_some((
      root,
      location,
      root_frame,
      location_frame,
    ))
  })
}

/// The design's precondition, from the pinned fd. A location that is STILL
/// COVERED sits across the scope's frame, and the walk refuses it without
/// descending a single directory.
///
/// **The crossing is REAL, not staged by a hand-built frame.** It used to be
/// staged: the walk was handed a root device the location could not be on, and
/// `crossed_by` fired on the device half. That staging died with R10 F2 — the
/// walk now reads the root's frame itself and refuses a request whose frame the
/// root does not have ([`AdmitWalk::Stale`]), so a lie about the root is answered
/// as a superseded request rather than as a covered location. [`crossing_pair`]
/// supplies a real one instead: a live pseudo-filesystem mounted directly under a
/// root that is itself a live mount, which needs no privilege at all.
///
/// Walking it instead is the breach: `descend` would fence the descent on the
/// BIND's own frame, and every directory under the alias would seed into the
/// admission map as in-root, which is exactly what the walk's mount fence exists
/// to prevent.
#[test]
fn a_revealed_walk_refuses_a_location_across_the_frame() {
  let Some((root, location, root_frame, location_frame)) = crossing_pair() else {
    eprintln!("SKIP a_revealed_walk_refuses_a_location_across_the_frame: no crossing pair");
    return;
  };
  let walked = revealed_walk(
    location,
    root,
    root_frame,
    [0u8; 8],
    root_frame.root_dev.expect("the live root answers a device"),
    &[],
    None,
  );
  assert!(
    matches!(
      walked,
      Ok(AdmitWalk::StillCovered { dev, mnt_id })
        if dev == location_frame.root_dev && mnt_id == location_frame.root_mnt_id
    ),
    "a location across the scope frame is refused, never walked — and the refusal \
     carries the identity it actually found there ({location:?}, expected \
     {location_frame:?}): {walked:?}"
  );
}

/// **R10 F2.** The admission request captures the root's frame when the core PARKS
/// the departure, and the walk runs on this thread arbitrarily later. Legacy mount
/// ids are allocated LOWEST-FREE and freed on umount, so across that interval a
/// departure can free the child's id while a same-object re-mount of the ROOT
/// takes it, and a same-device bind at the departed location can take the id the
/// root just gave up. The captured frame then reads `(D, R)` against a bind that
/// reads `(D, R)`, `crossed_by` sees no boundary, and the descent seeds the BIND's
/// subtree into the admission map — after which every mutation on that bind's real
/// path OUTSIDE the root resolves and delivers under its in-root alias.
///
/// **The collision is staged by construction, not raced.** The request is handed
/// the frame of the mount that is actually STANDING at the location, which is
/// exactly the state a recycled id leaves behind and needs no privilege to build:
/// what the captured frame names is a mount that is not the root's. The location
/// is a real submount and the root really does export handles, so the pre-fix code
/// has everything it needs to walk straight into it — which is the breach, and
/// which the companion cell above proves is refused when the frame is the ROOT's.
///
/// The fix is that the frame is read at EXECUTION time, from a root fd held open
/// across both mount-id reads (a mount id is unique among LIVE mounts and an fd
/// pins its vfsmount, so two ids read from two simultaneously-held fds are equal
/// iff they name the same mount), and a request whose captured frame the live root
/// no longer has is refused rather than executed.
///
/// MUTATION WITNESS (fence on the captured frame): delete the `live != frame`
/// refusal and fence with `frame.crossed_by(..)` in place of `live.crossed_by(..)`
/// — the pre-fix code — and this FAILS at `a request issued against a frame the
/// root no longer has is REFUSED` with `Ok(Revealed { parent: Fid { .. }, seed:
/// WalkSeed { .. } })`: the walk descends into a mount that is not the root's and
/// hands back its inventory, which is the seeding half of the breach.
/// MUTATION WITNESS (staleness read as a covered location): answer
/// `AdmitWalk::StillCovered { dev: None, mnt_id: None }` in place of `Stale` and
/// this FAILS at the same site with `Ok(StillCovered { dev: None, mnt_id: None })`
/// — nothing is seeded, but a `StillCovered` makes the core put the condemned
/// record back and release the located cover over ground nothing admitted, instead
/// of escalating to the whole-root recovery that is on the current frame by
/// construction.
#[test]
fn a_revealed_walk_refuses_a_request_whose_frame_the_root_no_longer_has() {
  let Some((root, location, root_frame, location_frame)) = crossing_pair() else {
    eprintln!(
      "SKIP a_revealed_walk_refuses_a_request_whose_frame_the_root_no_longer_has: no crossing pair"
    );
    return;
  };
  assert_ne!(
    location_frame, root_frame,
    "staging: the captured frame names a mount that is NOT the root's, which is \
     what a re-mounted root plus a recycled bind leaves behind"
  );
  let walked = revealed_walk(
    location,
    root,
    // The superseded frame: the identity of whatever is standing at the
    // location. `crossed_by` against it finds no boundary at all.
    location_frame,
    [0u8; 8],
    root_frame.root_dev.expect("the live root answers a device"),
    &[],
    None,
  );
  assert!(
    matches!(walked, Ok(AdmitWalk::Stale)),
    "a request issued against a frame the root no longer has is REFUSED, and \
     refused as SUPERSEDED — executing it fences the descent on the very mount \
     the fence exists to stop, and seeds it ({location:?} under {root:?}): \
     {walked:?}"
  );
}

/// A mountpoint removed after its unmount owes nothing: the location no longer
/// resolves to a directory, so there is no ground to admit and the round trip
/// still answers. Not a failure — driving an ordinary `rmdir` down the loss
/// ladder would reseed the whole map and cover the entire root for it.
#[test]
fn a_revealed_walk_of_a_vanished_location_is_nothing() {
  let Some((base, vol, dev)) = revealed_tree("vanished") else {
    return;
  };
  std::fs::remove_dir_all(&vol).expect("remove the revealed location");
  let Some(frame) = live_frame(&base) else {
    let _ = std::fs::remove_dir_all(&base);
    eprintln!("SKIP a_revealed_walk_of_a_vanished_location_is_nothing: no frame");
    return;
  };
  let walked = revealed_walk(&vol, &base, frame, [0u8; 8], dev, &[], None);
  let _ = std::fs::remove_dir_all(&base);
  assert!(
    matches!(walked, Ok(AdmitWalk::Nothing)),
    "a location that is no longer a directory owes no admission: {walked:?}"
  );
}

/// The exclusion fence, applied BEFORE any open. On a kernel-recursive mark the
/// only way to honour an exclusion is to keep the subtree out of the admission
/// map, so a reseed that walked excluded ground would admit exactly what the
/// caller asked never to hear about — and would keep admitting it forever after.
#[test]
fn a_revealed_walk_of_an_excluded_location_admits_nothing() {
  let Some((base, vol, dev)) = revealed_tree("excluded") else {
    return;
  };
  let Some(frame) = live_frame(&base) else {
    let _ = std::fs::remove_dir_all(&base);
    eprintln!("SKIP a_revealed_walk_of_an_excluded_location_admits_nothing: no frame");
    return;
  };
  let walked = revealed_walk(
    &vol,
    &base,
    frame,
    [0u8; 8],
    dev,
    std::slice::from_ref(&vol),
    None,
  );
  let _ = std::fs::remove_dir_all(&base);
  assert!(
    matches!(walked, Ok(AdmitWalk::Nothing)),
    "excluded ground never enters the map: {walked:?}"
  );
}

/// The additive cap, fencing the revealed LOCATION and not merely its
/// descendants. The reader hands this walk the room the map has LEFT (`cap -
/// len`), so a map with none cannot take even the one node — and a walk that
/// pushed it anyway would hand `map.seed` a vec that overflows the cap, tripping
/// its debug assertion in tests and the live `over_capacity` fatal in production.
///
/// The EMPTY location is the case that makes the fence non-redundant, which is
/// why this cell builds one. A POPULATED location is caught by [`descend`]'s own
/// budget check the moment it would push a child, so a cell that only tried that
/// shape would pass with the fence deleted.
#[test]
fn a_revealed_walk_with_no_room_left_is_incomplete() {
  let Some((base, vol, dev)) = revealed_tree("budget") else {
    return;
  };
  let empty = base.join("empty");
  std::fs::create_dir(&empty).expect("create an empty revealed location");

  let Some(frame) = live_frame(&base) else {
    let _ = std::fs::remove_dir_all(&base);
    eprintln!("SKIP a_revealed_walk_with_no_room_left_is_incomplete: no frame");
    return;
  };
  let empty_none_left = revealed_walk(&empty, &base, frame, [0u8; 8], dev, &[], Some(0));
  let none_left = revealed_walk(&vol, &base, frame, [0u8; 8], dev, &[], Some(0));
  let one_only = revealed_walk(&vol, &base, frame, [0u8; 8], dev, &[], Some(1));
  let roomy = revealed_walk(&vol, &base, frame, [0u8; 8], dev, &[], Some(2));
  let _ = std::fs::remove_dir_all(&base);
  assert!(
    matches!(empty_none_left, Err(WalkError::Incomplete(_))),
    "an EMPTY location with no room left is Incomplete: nothing under it would \
     ever reach the descent's own budget check, so only the fence on the \
     location itself can catch it: {empty_none_left:?}"
  );
  assert!(
    matches!(none_left, Err(WalkError::Incomplete(_))),
    "no room left is Incomplete (→ the loss barrier), never a partial seed: {none_left:?}"
  );
  match one_only {
    // Room for the location itself but not its descendant: the descent aborts
    // rather than mapping past the room actually left.
    Err(WalkError::Incomplete(_)) => {}
    Ok(other) => panic!("a budget of one cannot hold the location AND its descendant: {other:?}"),
    Err(WalkError::RootGone(err)) => {
      panic!("the admission walk never reports RootGone: {err}")
    }
  }
  match roomy {
    Ok(AdmitWalk::Revealed { seed, .. }) => assert_eq!(
      seed.entries.len(),
      2,
      "a budget that holds the location AND its descendant maps both"
    ),
    other => panic!("room for both admits both: {other:?}"),
  }
}

/// The pure `FAN_*` constants and info-record tags restate the kernel ABI; this
/// pins them to libc so they can never drift.
mod libc_cross_assert {
  use super::super::super::{FAN_INIT_FLAGS, FAN_MARK_MASK, fid};

  #[test]
  fn fanotify_constants_match_libc() {
    assert_eq!(fid::FAN_MODIFY, libc::FAN_MODIFY);
    assert_eq!(fid::FAN_ATTRIB, libc::FAN_ATTRIB);
    assert_eq!(fid::FAN_CREATE, libc::FAN_CREATE);
    assert_eq!(fid::FAN_DELETE, libc::FAN_DELETE);
    assert_eq!(fid::FAN_DELETE_SELF, libc::FAN_DELETE_SELF);
    assert_eq!(fid::FAN_MOVE_SELF, libc::FAN_MOVE_SELF);
    assert_eq!(fid::FAN_RENAME, libc::FAN_RENAME);
    assert_eq!(fid::FAN_Q_OVERFLOW, libc::FAN_Q_OVERFLOW);
    assert_eq!(fid::FAN_ONDIR, libc::FAN_ONDIR);
  }

  #[test]
  fn eoverflow_matches_libc() {
    assert_eq!(
      fid::EOVERFLOW,
      libc::EOVERFLOW,
      "the locally-restated EOVERFLOW must track libc so the handle-sizing retry \
       fires on the real errno"
    );
  }

  #[test]
  fn metadata_version_matches_libc() {
    assert_eq!(
      fid::FANOTIFY_METADATA_VERSION,
      libc::FANOTIFY_METADATA_VERSION,
      "decode refuses every event whose `vers` differs from this, so a constant \
       that drifted from the headers would refuse the entire live stream"
    );
  }

  #[test]
  fn info_record_tags_match_libc() {
    assert_eq!(fid::FAN_EVENT_INFO_TYPE_FID, libc::FAN_EVENT_INFO_TYPE_FID);
    assert_eq!(
      fid::FAN_EVENT_INFO_TYPE_DFID_NAME,
      libc::FAN_EVENT_INFO_TYPE_DFID_NAME
    );
    assert_eq!(
      fid::FAN_EVENT_INFO_TYPE_DFID,
      libc::FAN_EVENT_INFO_TYPE_DFID
    );
    assert_eq!(
      fid::FAN_EVENT_INFO_TYPE_OLD_DFID_NAME,
      libc::FAN_EVENT_INFO_TYPE_OLD_DFID_NAME
    );
    assert_eq!(
      fid::FAN_EVENT_INFO_TYPE_NEW_DFID_NAME,
      libc::FAN_EVENT_INFO_TYPE_NEW_DFID_NAME
    );
  }

  #[test]
  fn init_and_mark_flag_sets_match_the_composite() {
    assert_eq!(
      FAN_INIT_FLAGS,
      libc::FAN_CLASS_NOTIF
        | libc::FAN_REPORT_FID
        | libc::FAN_REPORT_DFID_NAME
        | libc::FAN_REPORT_TARGET_FID
    );
    assert_eq!(
      FAN_MARK_MASK,
      libc::FAN_CREATE
        | libc::FAN_DELETE
        | libc::FAN_MODIFY
        | libc::FAN_ATTRIB
        | libc::FAN_RENAME
        | libc::FAN_DELETE_SELF
        | libc::FAN_MOVE_SELF
        | libc::FAN_ONDIR
    );
  }
}
