//! The two Windows decisions the cookie directory still takes, compiled on
//! every host exactly like the RDCW decode.
//!
//! Both are here rather than beside their Win32 calls for one reason: a rule
//! that can only be exercised where a Windows kernel runs is a rule whose
//! inversion is invisible to the suite. [`ffi`](super::ffi) owns the calls and
//! lowers their answers into plain integers; the decisions taken on those
//! answers live here, where every host's `cargo test` runs them.
//!
//! What is NOT here is as deliberate. This module used to hold a whole
//! access-control vocabulary — sids, entries, labels, and a verdict on whether
//! a directory already standing at the cookie name could be TRUSTED — and,
//! after that, a reparse refusal read off a handle opened on a name this crate
//! had just created. The Windows arm asks neither question now. Its create and
//! its open are ONE call (`ffi::create_directory_at`), whose `FILE_CREATE`
//! disposition fails outright if the name exists at all, so there is no
//! interval in which a stranger's object could come to stand where this crate
//! is about to write — nothing to adjudicate, and no vocabulary to keep in step
//! with Microsoft's.

/// Moves a minted token off `u32::MAX`, the ONE value in the space that
/// `is_sync_cookie_dir_name`'s qualifier arm refuses (it is `(uid_t)-1`, which
/// no Unix minter can render either).
///
/// Without this remap a draw landing there would name a directory the
/// classifier calls a USER directory — so that directory's own create, and
/// every cookie inside it, would surface on consumer streams, silently.
/// `u32::MAX - 1` is the nearest admissible value and is picked
/// deterministically; it costs exactly one extra collision pair in a space of
/// 2^32, and a collision costs one retry rather than a wrong answer (see
/// `driver::bind_fresh_cookie_dir`).
pub(crate) const fn admissible_token(hash: u32) -> u32 {
  if hash == u32::MAX { u32::MAX - 1 } else { hash }
}

/// The `NTSTATUS` values the cookie directory's create decides on BY NAME,
/// spelled as literals where every host compiles them.
///
/// They are pinned against the vendored bindings by the status assertion in
/// [`ffi`](super::ffi) — the notify-filter discipline, applied to the one call
/// whose status codes this crate reads rather than forwards.
pub(crate) mod nt_status {
  /// `STATUS_OBJECT_NAME_COLLISION`: the name is already bound. This is what
  /// `FILE_CREATE` answers instead of opening whatever it found, and lowering
  /// it to `AlreadyExists` is what makes the mint loop a loop.
  pub(crate) const OBJECT_NAME_COLLISION: i32 = 0xC000_0035_u32 as i32;
  /// `STATUS_OBJECT_NAME_EXISTS`: INFORMATIONAL severity — a success by NT's
  /// rule — and still "the name was already bound". The dispositions that adopt
  /// an existing object report it beside a valid handle; `FILE_CREATE` is not
  /// one of them, so it should never surface here. It is decided anyway, and
  /// decided as a collision, because the only other reading is "adopt whatever
  /// answered".
  pub(crate) const OBJECT_NAME_EXISTS: i32 = 0x4000_0000_u32 as i32;
  /// `STATUS_ACCESS_DENIED`: the create was refused outright.
  pub(crate) const ACCESS_DENIED: i32 = 0xC000_0022_u32 as i32;
}

/// What one `NtCreateFile` status means to the cookie-directory mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NtCreate {
  /// The create bound the name: the handle it returned refers to a directory
  /// this call made, and never to something that was standing there already.
  Bound,
  /// The name was already bound. NOTHING was created, so nothing behind that
  /// name is this call's to enter or to remove — the candidate is discarded and
  /// another minted (`driver::mint_step` retries exactly `AlreadyExists`).
  Collided,
  /// The create was denied. `PermissionDenied` is spelled by this crate rather
  /// than left to the status conversion, because it is the one failure kind the
  /// mint's decision table distinguishes from the rest.
  Denied,
  /// Anything else: the status carries the whole story and is converted
  /// faithfully by the caller.
  Failed,
}

/// Reads one `NtCreateFile` status for the mint.
///
/// Success is NT's own test — a non-negative status — and not "a handle came
/// back", because [`nt_status::OBJECT_NAME_EXISTS`] is a success that hands back
/// a handle to an object this call did not make. Naming the two collision
/// statuses BEFORE the severity rule is what keeps that one on the discard path.
pub(crate) fn nt_create(status: i32) -> NtCreate {
  match status {
    nt_status::OBJECT_NAME_COLLISION | nt_status::OBJECT_NAME_EXISTS => NtCreate::Collided,
    nt_status::ACCESS_DENIED => NtCreate::Denied,
    _ if status >= 0 => NtCreate::Bound,
    _ => NtCreate::Failed,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// A token landing on `u32::MAX` is moved, because the classifier refuses
  /// exactly that value.
  ///
  /// FAIL-ON-REVERT (drop [`admissible_token`] from the mint): that draw names
  /// `.tributaries-sync-cookies-4294967295`, which `is_sync_cookie_dir_name`
  /// calls a USER directory — so the directory's own create and every cookie
  /// inside it reach consumer streams.
  #[test]
  fn a_token_never_lands_on_the_one_value_the_classifier_refuses() {
    assert_eq!(admissible_token(u32::MAX), u32::MAX - 1);
    // Every other value passes through untouched: the remap is a single
    // point, not a mangling of the space.
    assert_eq!(admissible_token(0), 0);
    assert_eq!(admissible_token(1), 1);
    assert_eq!(admissible_token(u32::MAX - 1), u32::MAX - 1);
  }

  /// The mint's reading of an `NtCreateFile` status, as a table — the rule that
  /// decides, without a Windows kernel, whether an occupied candidate costs one
  /// retry or fails the whole write.
  ///
  /// FAIL-ON-REVERT in three directions. Drop the collision row and
  /// `driver::mint_step` never sees `AlreadyExists`, so a name a peer got to
  /// first aborts the sync instead of being discarded — the mint loop stops
  /// being a loop. Drop the [`nt_status::OBJECT_NAME_EXISTS`] row and a
  /// success-severity "that name was already there" is read as this call's own
  /// creation, which is precisely the adoption this architecture deleted. Decide
  /// success by "a handle came back" instead of by NT's severity rule and both
  /// follow at once.
  #[test]
  fn a_create_status_is_read_by_severity_and_by_name() {
    assert_eq!(nt_create(0), NtCreate::Bound, "STATUS_SUCCESS");
    assert_eq!(
      nt_create(nt_status::OBJECT_NAME_COLLISION),
      NtCreate::Collided,
      "an occupied name must reach the mint loop as AlreadyExists"
    );
    assert_eq!(
      nt_create(nt_status::OBJECT_NAME_EXISTS),
      NtCreate::Collided,
      "a success-severity name status is still somebody else's object"
    );
    assert_eq!(nt_create(nt_status::ACCESS_DENIED), NtCreate::Denied);

    // The severity rule itself, at its boundaries.
    assert_eq!(nt_create(i32::MAX), NtCreate::Bound);
    assert_eq!(nt_create(-1), NtCreate::Failed);
    assert_eq!(nt_create(i32::MIN), NtCreate::Failed);

    /// `STATUS_BUFFER_OVERFLOW` — WARNING severity, which NT does NOT count as
    /// success, so neither does this.
    const BUFFER_OVERFLOW: i32 = 0x8000_0005_u32 as i32;
    /// `STATUS_OBJECT_PATH_NOT_FOUND` — the PARENT is gone, so another
    /// candidate name would fail identically.
    const OBJECT_PATH_NOT_FOUND: i32 = 0xC000_003A_u32 as i32;
    /// `STATUS_DISK_FULL`, likewise nothing a fresh name would fix.
    const DISK_FULL: i32 = 0xC000_007F_u32 as i32;

    assert_eq!(nt_create(BUFFER_OVERFLOW), NtCreate::Failed);
    assert_eq!(nt_create(OBJECT_PATH_NOT_FOUND), NtCreate::Failed);
    assert_eq!(nt_create(DISK_FULL), NtCreate::Failed);
  }
}
