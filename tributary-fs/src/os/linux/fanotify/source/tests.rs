use std::io;

use rustix::io::Errno;

use super::{WalkError, WalkSkip, classify_walk_skip, seed_walk, subtree_walk};
use crate::os::linux::fanotify::fid::Fid;

/// A root that cannot export a file handle is a FATAL seed/reseed failure, never
/// an empty successful seed: the root anchor is the base every admitted path
/// resolves against, so without it the map admits nothing. A nonexistent path
/// stands in for `name_to_handle_at` failing on the root — the walk must return
/// [`WalkError::RootGone`] (a race the spawn reports as root-unavailable and the
/// reseed escalates), not a live-but-blind source.
#[test]
fn root_without_a_handle_is_a_fatal_seed_failure() {
  let missing = std::path::Path::new("/tributary-fs-nonexistent-root-for-seed-walk");
  let result = seed_walk(missing, [0u8; 8], 0);
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

  let result = seed_walk(&root, [0u8; 8], root_dev);
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
  // A stand-in FID for the already-learned moved directory; its bytes are
  // irrelevant to the descent (only the seed entries' parent links are checked).
  let subtree_fid = Fid::new([7; 8], Box::from(&[7u8][..]));

  let result = subtree_walk(&subtree, &subtree_fid, [0u8; 8], root_dev);
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
  let subtree_fid = Fid::new([7; 8], Box::from(&[7u8][..]));

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

  let result = subtree_walk(&subtree, &subtree_fid, [0u8; 8], root_dev);
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
  match subtree_walk(&missing, &subtree_fid, [0u8; 8], 0) {
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
