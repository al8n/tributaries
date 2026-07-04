use std::io;

use rustix::io::Errno;

use super::{
  WalkError, WalkSkip, classify_walk_skip, handle_fid_at, handles_match, seed_from_fd, seed_walk,
  subtree_walk,
};
use crate::os::linux::fanotify::fid::Fid;

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
  let result = seed_walk(missing, [0u8; 8], 0, &some_fid(1), None);
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
  let result = seed_walk(&root, [0u8; 8], root_dev, &wrong, None);
  let _ = std::fs::remove_dir_all(&root);
  assert!(
    matches!(result, Err(WalkError::RootGone(_))),
    "a reopened root whose handle does not equal the expected anchor is RootGone (replaced at \
     path), never a seed of the replacement tree"
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
  let result = seed_walk(&root, [0u8; 8], root_dev, &expected, None);
  let _ = std::fs::remove_dir_all(&root);
  let entries = result.expect("the genuine root passes the FID gate and seeds");
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
  let result = subtree_walk(&subtree, &wrong, [0u8; 8], root_dev, None);
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
  let result = subtree_walk(&subtree, &subtree_fid, [0u8; 8], root_dev, None);
  let _ = std::fs::remove_dir_all(&subtree);
  let entries = result.expect(
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
  let result = seed_walk(&root, [0u8; 8], root_dev, &expected, None);
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

  let result = subtree_walk(&subtree, &subtree_fid, [0u8; 8], root_dev, None);
  let _ = std::fs::remove_dir_all(&subtree);
  let entries = match result {
    Ok(entries) => entries,
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

  let result = subtree_walk(&subtree, &subtree_fid, [0u8; 8], root_dev, None);
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
  match subtree_walk(&missing, &subtree_fid, [0u8; 8], 0, None) {
    Err(WalkError::Incomplete(err)) => {
      assert_eq!(
        err.kind(),
        io::ErrorKind::NotFound,
        "the incompleteness carries the NotFound that opening the missing dir raised"
      );
    }
    Err(WalkError::RootGone(_)) => unreachable!("subtree_walk never reports RootGone"),
    Ok(entries) => panic!(
      "a missing moved-in subtree path must be Incomplete, not an empty walk (got {} entries)",
      entries.len()
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
  let capped = seed_walk(&root, [0u8; 8], root_dev, &expected, Some(2));
  assert!(
    matches!(capped, Err(WalkError::Incomplete(_))),
    "a tree exceeding the directory cap is Incomplete (fanotify not viable), not a partial seed"
  );

  // A generous cap seeds the whole tree.
  let ok = seed_walk(&root, [0u8; 8], root_dev, &expected, Some(1000));
  let _ = std::fs::remove_dir_all(&root);
  let entries = ok.expect("a generous cap seeds the whole tree");
  assert_eq!(
    entries.len(),
    4,
    "root + three subdirectories seed under a cap that comfortably holds them"
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
  // the descent. A filesystem that reports no mount id degrades to the device belt
  // (no frame to make stale), so this cell cannot exercise the fence: skip loudly.
  let Some(fresh) = crate::os::linux::root_mount_id(root_fd.as_fd()) else {
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
    [0u8; 8],
    root_dev,
    Some(fresh),
    None,
  );
  let fresh_entries = match with_fresh {
    Ok(entries) => entries,
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
    fresh_entries
      .iter()
      .any(|e| e.name == std::ffi::OsStr::new("child") && e.parent.is_some()),
    "the fresh reopen frame descends the same-mount child"
  );

  // Handed a STALE frame (a spawn-captured id from before the root moved mounts), the
  // identical child now differs from the fence and is skipped — the silent blindness
  // the reopen-recompute avoids by reading the frame from the current fd.
  let stale = fresh.wrapping_add(1);
  let with_stale = seed_from_fd(root_fd, &root, [0u8; 8], root_dev, Some(stale), None)
    .expect("the stale-frame walk still seeds the root anchor, just skips the child");
  let _ = std::fs::remove_dir_all(&root);
  assert!(
    !with_stale
      .iter()
      .any(|e| e.name == std::ffi::OsStr::new("child")),
    "a STALE fence frame marks the same-mount child a boundary and skips it — which is \
     why the reopen-recompute reads the frame from the current fd"
  );
  assert!(
    with_stale.iter().any(|e| e.parent.is_none()),
    "the root anchor is still seeded under either frame"
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
  let capped = subtree_walk(&subtree, &subtree_fid, [0u8; 8], root_dev, Some(1));
  assert!(
    matches!(capped, Err(WalkError::Incomplete(_))),
    "a subtree exceeding the remaining budget is Incomplete (blind → fatal), not a partial seed"
  );

  // A generous budget maps all three descendants (the moved dir itself is not
  // re-emitted, so exactly the three children).
  let ok = subtree_walk(&subtree, &subtree_fid, [0u8; 8], root_dev, Some(1000));
  let _ = std::fs::remove_dir_all(&subtree);
  let entries = ok.expect("a generous budget maps every descendant");
  assert_eq!(
    entries.len(),
    3,
    "all three descendant directories map under a budget that comfortably holds them"
  );
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
