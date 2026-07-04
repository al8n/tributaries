use super::handle_support_proven;

/// A successful `name_to_handle_at` (`rc == 0`) proves the filesystem exports
/// handles regardless of `errno`.
#[test]
fn success_proves_support() {
  assert!(handle_support_proven(0, None));
}

/// EOVERFLOW is the only failure errno that still proves support (the handle
/// exists, the buffer was merely too small).
#[test]
fn eoverflow_proves_support() {
  assert!(handle_support_proven(-1, Some(libc::EOVERFLOW)));
}

/// Every OTHER failure errno fails the row — a transient or permission error is
/// NOT evidence the fs can encode handles, and admitting on it produces a live
/// source that drops everything as outside-root.
#[test]
fn other_errnos_fail_the_row() {
  for errno in [
    libc::EOPNOTSUPP,
    libc::EACCES,
    libc::ESTALE,
    libc::ENOENT,
    libc::EINVAL,
    libc::ENOMEM,
    libc::EPERM,
  ] {
    assert!(
      !handle_support_proven(-1, Some(errno)),
      "errno {errno} must not prove handle support"
    );
  }
  // A failure with no decodable errno also fails the row.
  assert!(!handle_support_proven(-1, None));
}
