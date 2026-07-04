use std::io;

use super::{WalkError, WalkSkip, classify_walk_skip, seed_walk};

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

/// The walk-skip classifier is the completeness decision, extracted pure so the
/// two classes are row-tested without a live filesystem: ONLY `NotFound`
/// (`ENOENT`) is a benign vanished-race skip; every other failure — permission,
/// I/O, unsupported — is an in-root coverage hole that makes the tree
/// `Incomplete` (fanotify not viable).
#[test]
fn classify_walk_skip_only_notfound_is_a_race() {
  assert_eq!(
    classify_walk_skip(&io::Error::from(io::ErrorKind::NotFound)),
    WalkSkip::VanishedRace,
    "a vanished entry is a benign race the walk skips"
  );
  for kind in [
    io::ErrorKind::PermissionDenied,
    io::ErrorKind::Unsupported,
    io::ErrorKind::Other,
    io::ErrorKind::InvalidInput,
  ] {
    assert_eq!(
      classify_walk_skip(&io::Error::from(kind)),
      WalkSkip::Incomplete,
      "{kind:?} on an existing in-root directory is an incompleteness, not a race"
    );
  }
  // A raw errno (EACCES) — the exact chmod-000-subdirectory case — surfaces as
  // PermissionDenied and is classified Incomplete: under Auto the spawn falls
  // back to inotify, under forced Fanotify it is a typed viability error.
  assert_eq!(
    classify_walk_skip(&io::Error::from_raw_os_error(libc::EACCES)),
    WalkSkip::Incomplete,
    "an EACCES child directory makes the walk incomplete (the container fallback case)"
  );
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
