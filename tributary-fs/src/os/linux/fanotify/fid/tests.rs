use super::{
  DecodeOutcome, EOVERFLOW, FAN_ATTRIB, FAN_CREATE, FAN_DELETE, FAN_DELETE_SELF,
  FAN_EVENT_INFO_TYPE_DFID, FAN_EVENT_INFO_TYPE_DFID_NAME, FAN_EVENT_INFO_TYPE_FID,
  FAN_EVENT_INFO_TYPE_NEW_DFID_NAME, FAN_EVENT_INFO_TYPE_OLD_DFID_NAME, FAN_MODIFY, FAN_MOVE_SELF,
  FAN_ONDIR, FAN_Q_OVERFLOW, FAN_RENAME, Fid, HandleAttempt, classify_handle_attempt,
  decode_events,
};

/// One `struct file_handle`: `handle_bytes` (u32), `handle_type` (i32), then
/// the opaque bytes.
fn file_handle(handle_type: i32, opaque: &[u8]) -> Vec<u8> {
  let mut out = Vec::new();
  out.extend_from_slice(&(opaque.len() as u32).to_ne_bytes());
  out.extend_from_slice(&handle_type.to_ne_bytes());
  out.extend_from_slice(opaque);
  out
}

/// One info record: header (`info_type` u8, `pad` u8, `len` u16) + payload,
/// where the whole record length is placed in `len`.
fn info_record(info_type: u8, payload: &[u8]) -> Vec<u8> {
  let len = (4 + payload.len()) as u16;
  let mut out = Vec::new();
  out.push(info_type);
  out.push(0);
  out.extend_from_slice(&len.to_ne_bytes());
  out.extend_from_slice(payload);
  out
}

/// A FID payload: `fsid` (8 bytes) + a `file_handle`, plus an optional
/// NUL-terminated name (the `*_NAME` record types).
fn fid_payload(fsid: [u8; 8], handle_type: i32, opaque: &[u8], name: Option<&[u8]>) -> Vec<u8> {
  let mut out = Vec::new();
  out.extend_from_slice(&fsid);
  out.extend_from_slice(&file_handle(handle_type, opaque));
  if let Some(name) = name {
    out.extend_from_slice(name);
    out.push(0);
  }
  out
}

/// One `fanotify_event_metadata` (24 bytes) followed by its info records.
/// `event_len` is set to the total.
fn event(mask: u64, info: &[u8]) -> Vec<u8> {
  let event_len = (24 + info.len()) as u32;
  let mut out = Vec::new();
  out.extend_from_slice(&event_len.to_ne_bytes()); // event_len
  out.push(3); // vers
  out.push(0); // reserved
  out.extend_from_slice(&24u16.to_ne_bytes()); // metadata_len
  out.extend_from_slice(&mask.to_ne_bytes()); // mask
  out.extend_from_slice(&(-1i32).to_ne_bytes()); // fd = FAN_NOFD
  out.extend_from_slice(&0i32.to_ne_bytes()); // pid
  out.extend_from_slice(info);
  out
}

const FSID_A: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const FSID_B: [u8; 8] = [9, 9, 9, 9, 0, 0, 0, 0];

/// A `DFID_NAME` FID payload whose `file_handle.handle_bytes` field is forced
/// to `u32::MAX` while the opaque bytes present are far shorter — a decode is
/// impossible on any width, and `FILE_HANDLE_PREFIX + handle_bytes` overflows
/// `usize` on a 32-bit target.
fn fid_payload_with_absurd_handle_bytes() -> Vec<u8> {
  let mut payload = fid_payload(FSID_A, 1, b"x", Some(b"child"));
  // `handle_bytes` is the u32 at the start of the `file_handle`, right after the
  // 8-byte fsid.
  payload[8..12].copy_from_slice(&u32::MAX.to_ne_bytes());
  payload
}

/// A create with `DFID_NAME` (the parent + child name) and a `FID` (the
/// child's own handle, from `FAN_REPORT_TARGET_FID`) decodes both, with the
/// name trimmed and both FIDs exact.
#[test]
fn single_create_decodes_dir_fid_name_and_target_fid() {
  let dir = info_record(
    FAN_EVENT_INFO_TYPE_DFID_NAME,
    &fid_payload(FSID_A, 1, b"parent-handle", Some(b"child.txt")),
  );
  let target = info_record(
    FAN_EVENT_INFO_TYPE_FID,
    &fid_payload(FSID_A, 1, b"child-handle", None),
  );
  let mut info = dir;
  info.extend(target);
  let buf = event(FAN_CREATE | FAN_ONDIR, &info);

  let DecodeOutcome { events, lossy } = decode_events(&buf);
  assert!(!lossy);
  assert_eq!(events.len(), 1);
  let ev = &events[0];
  assert!(ev.mask.created());
  assert!(ev.mask.ondir());
  assert_eq!(ev.name.as_deref(), Some(b"child.txt".as_slice()));

  let dir_fid = ev.dir_fid.as_ref().expect("dir fid present");
  assert_eq!(dir_fid.fsid(), FSID_A);
  // The stored handle is the type word (native-endian i32) followed by the
  // opaque bytes.
  let mut expected = 1i32.to_ne_bytes().to_vec();
  expected.extend_from_slice(b"parent-handle");
  assert_eq!(dir_fid.handle(), expected.as_slice());

  let target_fid = ev.target_fid.as_ref().expect("target fid present");
  let mut expected_child = 1i32.to_ne_bytes().to_vec();
  expected_child.extend_from_slice(b"child-handle");
  assert_eq!(target_fid.handle(), expected_child.as_slice());
  assert_ne!(dir_fid, target_fid, "parent and child are distinct FIDs");
}

/// A delete carries only the directory FID and the child name (no
/// `TARGET_FID` — the object is gone).
#[test]
fn delete_decodes_dir_fid_name_without_target() {
  let info = info_record(
    FAN_EVENT_INFO_TYPE_DFID_NAME,
    &fid_payload(FSID_A, 1, b"dir", Some(b"gone")),
  );
  let buf = event(FAN_DELETE, &info);
  let DecodeOutcome { events, lossy } = decode_events(&buf);
  assert!(!lossy);
  assert_eq!(events.len(), 1);
  assert!(events[0].mask.removed());
  assert!(events[0].dir_fid.is_some());
  assert!(events[0].target_fid.is_none());
  assert_eq!(events[0].name.as_deref(), Some(b"gone".as_slice()));
}

/// A `FAN_RENAME` carries `OLD_DFID_NAME` + `NEW_DFID_NAME` in one event; both
/// halves parse with their own directory FID and name. A directory rename
/// (`FAN_ONDIR`) also carries the moved object's own `FID` (`target_fid`) — the
/// field the child-FID structural rule requires for a tree-mutating rename.
#[test]
fn rename_decodes_both_halves_in_one_event() {
  let old = info_record(
    FAN_EVENT_INFO_TYPE_OLD_DFID_NAME,
    &fid_payload(FSID_A, 1, b"srcdir", Some(b"old.txt")),
  );
  let new = info_record(
    FAN_EVENT_INFO_TYPE_NEW_DFID_NAME,
    &fid_payload(FSID_B, 2, b"dstdir", Some(b"new.txt")),
  );
  let target = info_record(
    FAN_EVENT_INFO_TYPE_FID,
    &fid_payload(FSID_A, 1, b"moved-handle", None),
  );
  let mut info = old;
  info.extend(new);
  info.extend(target);
  let buf = event(FAN_RENAME | FAN_ONDIR, &info);

  let DecodeOutcome { events, lossy } = decode_events(&buf);
  assert!(!lossy);
  assert_eq!(events.len(), 1);
  let rename = events[0].rename.as_ref().expect("rename info present");
  assert_eq!(rename.old_name, b"old.txt");
  assert_eq!(rename.new_name, b"new.txt");
  assert_eq!(rename.old_dir.fsid(), FSID_A);
  assert_eq!(rename.new_dir.fsid(), FSID_B);
  assert_ne!(rename.old_dir, rename.new_dir);
  assert!(events[0].mask.rename());
  assert!(
    events[0].target_fid.is_some(),
    "a dir rename carries the moved object's own FID"
  );
}

/// A `FAN_RENAME` with only one half is malformed and refused (marks the batch
/// lossy) — a pair that cannot be paired is never half-emitted.
#[test]
fn rename_with_one_half_is_lossy() {
  let old = info_record(
    FAN_EVENT_INFO_TYPE_OLD_DFID_NAME,
    &fid_payload(FSID_A, 1, b"srcdir", Some(b"old.txt")),
  );
  let buf = event(FAN_RENAME, &old);
  let DecodeOutcome { events, lossy } = decode_events(&buf);
  assert!(lossy);
  assert!(events.is_empty());
}

/// A `FAN_RENAME` whose mask is set but which carries NEITHER half is refused
/// (lossy), not silently dropped with `rename = None`: an unpairable rename must
/// take the ordered `Overflow` barrier, never fall through as a well-formed event.
#[test]
fn rename_with_zero_halves_is_lossy() {
  let buf = event(FAN_RENAME, &[]);
  let DecodeOutcome { events, lossy } = decode_events(&buf);
  assert!(
    lossy,
    "a rename with no halves is malformed, not a clean event"
  );
  assert!(events.is_empty());
}

/// A `FAN_RENAME` half whose name decodes empty (a bare NUL) is refused: an empty
/// name would lower to an empty path component, so a present-but-nameless half is
/// as malformed as a missing one and takes the loss barrier rather than the
/// `unwrap_or_default()` empty-component drop.
#[test]
fn rename_with_an_empty_name_half_is_lossy() {
  let old = info_record(
    FAN_EVENT_INFO_TYPE_OLD_DFID_NAME,
    &fid_payload(FSID_A, 1, b"srcdir", Some(b"old.txt")),
  );
  // A NEW half whose name field is a lone NUL: `decode_fid_record` trims it to
  // `None`, so the pair cannot be completed.
  let new = info_record(
    FAN_EVENT_INFO_TYPE_NEW_DFID_NAME,
    &fid_payload(FSID_B, 2, b"dstdir", Some(b"")),
  );
  let mut info = old;
  info.extend(new);
  let buf = event(FAN_RENAME, &info);
  let DecodeOutcome { events, lossy } = decode_events(&buf);
  assert!(lossy, "a rename half with an empty name is malformed");
  assert!(events.is_empty());
}

/// A truncated trailing event (a header cut short, or an `event_len` past the
/// buffer) stops the walk and marks the batch lossy, never panicking. The
/// intact leading event is kept.
#[test]
fn truncated_tail_is_lossy_and_keeps_intact_prefix() {
  let good = event(
    FAN_ATTRIB,
    &info_record(
      FAN_EVENT_INFO_TYPE_DFID_NAME,
      &fid_payload(FSID_A, 1, b"d", Some(b"f")),
    ),
  );
  let mut buf = good.clone();
  // Half a metadata header — structurally impossible to parse.
  buf.extend_from_slice(&[0u8; 12]);
  let DecodeOutcome { events, lossy } = decode_events(&buf);
  assert!(lossy);
  assert_eq!(events.len(), 1, "the intact leading event survives");
  assert!(events[0].mask.attrib());
}

/// An `event_len` that claims more than the buffer holds is refused before any
/// info bytes are read — never an out-of-bounds slice.
#[test]
fn overlong_event_len_is_lossy() {
  let mut buf = event(FAN_CREATE, &[]);
  // Rewrite event_len to claim 4 KiB while the buffer is 24 bytes.
  buf[0..4].copy_from_slice(&4096u32.to_ne_bytes());
  let DecodeOutcome { events, lossy } = decode_events(&buf);
  assert!(lossy);
  assert!(events.is_empty());
}

/// A `handle_bytes` of `u32::MAX` on a short payload: `FILE_HANDLE_PREFIX +
/// handle_bytes` overflows `usize` on a 32-bit target (i686), which would panic
/// on the add before the slice bound is tested. `decode_fid_record` resolves it
/// to a malformed FID — the batch is `lossy` with no events, never a panic.
#[test]
fn absurd_handle_bytes_alone_is_lossy_not_a_panic() {
  let info = info_record(
    FAN_EVENT_INFO_TYPE_DFID_NAME,
    &fid_payload_with_absurd_handle_bytes(),
  );
  let buf = event(FAN_CREATE, &info);
  let DecodeOutcome { events, lossy } = decode_events(&buf);
  assert!(lossy, "a handle length that overflows usize is lossy");
  assert!(events.is_empty(), "the overflowing FID yields no event");
}

/// A valid event followed by one whose `handle_bytes` overflows `usize`: the
/// intact leading event decodes, then the absurd handle stops the walk lossy —
/// the mid-buffer form of the 32-bit overflow guard.
#[test]
fn absurd_handle_bytes_after_valid_event_is_lossy() {
  let good = event(
    FAN_CREATE,
    &info_record(
      FAN_EVENT_INFO_TYPE_DFID_NAME,
      &fid_payload(FSID_A, 1, b"d", Some(b"f")),
    ),
  );
  let bad = event(
    FAN_DELETE,
    &info_record(
      FAN_EVENT_INFO_TYPE_DFID_NAME,
      &fid_payload_with_absurd_handle_bytes(),
    ),
  );
  let mut buf = good;
  buf.extend(bad);
  let DecodeOutcome { events, lossy } = decode_events(&buf);
  assert!(lossy);
  assert_eq!(events.len(), 1, "the intact leading event survives");
  assert!(events[0].mask.created());
}

/// An unknown info-record type (a PIDFD, a future tag) is skipped by its own
/// length; the walk stays synchronized and the known records still decode.
#[test]
fn unknown_info_record_is_skipped() {
  // A type-4 (PIDFD) record with arbitrary payload, between two known records.
  let pidfd = info_record(4, &[0xAA; 8]);
  let dir = info_record(
    FAN_EVENT_INFO_TYPE_DFID_NAME,
    &fid_payload(FSID_A, 1, b"d", Some(b"child")),
  );
  let mut info = pidfd;
  info.extend(dir);
  let buf = event(FAN_CREATE, &info);

  let DecodeOutcome { events, lossy } = decode_events(&buf);
  assert!(!lossy, "an unknown type is skipped, not a loss");
  assert_eq!(events.len(), 1);
  assert_eq!(events[0].name.as_deref(), Some(b"child".as_slice()));
  assert!(events[0].dir_fid.is_some());
}

/// A `FAN_Q_OVERFLOW` marker carries no FID and marks the batch lossy while
/// still advancing past its (info-less) event. DECODE keeps any post-marker event
/// in `events` — that is decode's contract, NOT delivery: the reader treats a
/// lossy decode as an ordering barrier and drops the whole buffer's events behind
/// the `Overflow` (see the reader's `process_decoded`), so a post-marker event is
/// decoded here but never forwarded.
#[test]
fn overflow_marker_is_lossy_and_skipped() {
  let overflow = event(FAN_Q_OVERFLOW, &[]);
  let good = event(
    FAN_CREATE,
    &info_record(
      FAN_EVENT_INFO_TYPE_DFID_NAME,
      &fid_payload(FSID_A, 1, b"d", Some(b"f")),
    ),
  );
  let mut buf = overflow;
  buf.extend(good);
  let DecodeOutcome { events, lossy } = decode_events(&buf);
  assert!(lossy, "overflow is a loss signal");
  assert_eq!(
    events.len(),
    1,
    "the following intact event still DECODES (the reader drops it behind the barrier)"
  );
  assert!(events[0].mask.created());
}

/// FIDs sharing an fsid but differing in handle bytes are distinct objects;
/// FIDs differing only in fsid are distinct too. Exact byte equality — never a
/// hash, never an fsid-only comparison.
#[test]
fn fid_equality_is_byte_exact() {
  let a = Fid::new(FSID_A, Box::from(&b"handle-1"[..]));
  let b = Fid::new(FSID_A, Box::from(&b"handle-2"[..]));
  let c = Fid::new(FSID_B, Box::from(&b"handle-1"[..]));
  let a2 = Fid::new(FSID_A, Box::from(&b"handle-1"[..]));
  assert_ne!(a, b, "same fsid, different handle = different object");
  assert_ne!(a, c, "different fsid = different object");
  assert_eq!(a, a2, "identical bytes = same object");
}

/// The `name_to_handle_at` dynamic-sizing decision table (the sole errno logic
/// behind both the `Backend::Auto` probe's row 5 and the seed/reseed walk's
/// handle read). `rc == 0` is the encoded handle; the FIRST `EOVERFLOW` proves a
/// handle exists and asks to grow; every other errno is unsupported.
#[test]
fn handle_attempt_decision_table() {
  // Success at the first try — encoded, regardless of a stale errno.
  assert_eq!(
    classify_handle_attempt(0, None, false),
    HandleAttempt::Encoded
  );
  assert_eq!(
    classify_handle_attempt(0, Some(EOVERFLOW), false),
    HandleAttempt::Encoded,
    "rc == 0 is success even if last_os_error still reads a stale EOVERFLOW"
  );

  // First EOVERFLOW: the buffer was too small but a handle exists — grow once.
  assert_eq!(
    classify_handle_attempt(-1, Some(EOVERFLOW), false),
    HandleAttempt::Grow
  );

  // Success AT the retry (rc == 0 after having grown) still encodes.
  assert_eq!(
    classify_handle_attempt(0, None, true),
    HandleAttempt::Encoded,
    "the grown retry succeeding is a normal encode"
  );

  // A SECOND EOVERFLOW (already grown to the kernel's own reported size): a
  // lying kernel — fail rather than loop forever.
  assert_eq!(
    classify_handle_attempt(-1, Some(EOVERFLOW), true),
    HandleAttempt::Unsupported,
    "a double EOVERFLOW is a broken kernel, never a second grow"
  );

  // Every other errno fails the row, grown or not — a non-exporting filesystem
  // (EOPNOTSUPP) or a transient/permission failure is NOT handle support, so it
  // must never admit a root the FID map cannot seed.
  for errno in [
    libc::EOPNOTSUPP,
    libc::EACCES,
    libc::ESTALE,
    libc::ENOENT,
    libc::EINVAL,
    libc::ENOMEM,
    libc::EPERM,
  ] {
    assert_eq!(
      classify_handle_attempt(-1, Some(errno), false),
      HandleAttempt::Unsupported,
      "errno {errno} must not prove handle support"
    );
    assert_eq!(
      classify_handle_attempt(-1, Some(errno), true),
      HandleAttempt::Unsupported,
      "errno {errno} after a grow is still unsupported"
    );
  }

  // A failure with no decodable errno also fails the row.
  assert_eq!(
    classify_handle_attempt(-1, None, false),
    HandleAttempt::Unsupported
  );
}

/// The decode-layer validation suite (`decode_info`): every vocabulary the composite
/// emits must carry the fields its admission path consumes, else the buffer is
/// `lossy` (→ ordered `Overflow` + reseed) rather than a clean event admission would
/// silently mishandle. Two orthogonal rules are exercised, each with its malformed
/// side (`lossy`, no event) and its well-formed counterpart (decodes intact), so the
/// whole class is closed, not just the reported instance:
///
/// - the NAME / drop-gate (`required_fields_present`): a named dirent needs its name;
/// - the CHILD-FID structural rule (`mutates_child_tree`): ANY directory-tree
///   mutation on a CHILD node — a dir create/delete/move dirent OR a dir rename —
///   needs the child's own `target_fid`; a self-event (root death), a file event, and
///   a non-structural dir modify/attrib are exempt (the rule must not over-fire).
mod required_field_matrix {
  use super::*;

  /// A single-event buffer: one `DFID_NAME` record (parent FID + `name`, where an
  /// empty `name` is a lone NUL that decodes to `None`) and, when `target` is set,
  /// the child's `FID` record — the exact record shape the composite emits.
  fn dirent(mask: u64, name: Option<&[u8]>, target: Option<&[u8]>) -> Vec<u8> {
    let mut info = info_record(
      FAN_EVENT_INFO_TYPE_DFID_NAME,
      &fid_payload(FSID_A, 1, b"dir-handle", name),
    );
    if let Some(target) = target {
      info.extend(info_record(
        FAN_EVENT_INFO_TYPE_FID,
        &fid_payload(FSID_A, 1, target, None),
      ));
    }
    event(mask, &info)
  }

  /// A `FAN_RENAME` buffer: the `OLD_DFID_NAME` + `NEW_DFID_NAME` halves (each a
  /// directory FID + a non-empty name, so the both-halves rule always passes) and,
  /// when `target` is set, the moved object's own `FID` record
  /// (`FAN_REPORT_TARGET_FID`). `ondir` toggles `FAN_ONDIR` — the flag that makes a
  /// rename a directory-tree mutation the child-FID rule guards. The two dir handles
  /// are parameters so a row can label the in-root / move-out / move-in shapes.
  fn rename_event(
    old_handle: &[u8],
    new_handle: &[u8],
    ondir: bool,
    target: Option<&[u8]>,
  ) -> Vec<u8> {
    let mut info = info_record(
      FAN_EVENT_INFO_TYPE_OLD_DFID_NAME,
      &fid_payload(FSID_A, 1, old_handle, Some(b"old")),
    );
    info.extend(info_record(
      FAN_EVENT_INFO_TYPE_NEW_DFID_NAME,
      &fid_payload(FSID_A, 1, new_handle, Some(b"new")),
    ));
    if let Some(target) = target {
      info.extend(info_record(
        FAN_EVENT_INFO_TYPE_FID,
        &fid_payload(FSID_A, 1, target, None),
      ));
    }
    let mask = if ondir {
      FAN_RENAME | FAN_ONDIR
    } else {
      FAN_RENAME
    };
    event(mask, &info)
  }

  /// A self-event buffer: a bare `DFID` record (the object's own FID, no name) —
  /// the well-formed name-less shape a `DELETE_SELF`/`MOVE_SELF` carries.
  fn self_event(mask: u64) -> Vec<u8> {
    event(
      mask,
      &info_record(
        FAN_EVENT_INFO_TYPE_DFID,
        &fid_payload(FSID_A, 1, b"self-handle", None),
      ),
    )
  }

  fn decode_one(buf: &[u8]) -> DecodeOutcome {
    decode_events(buf)
  }

  /// An empty name (a lone NUL) on a FILE create leaves the event pathless —
  /// admission would resolve no `<dir>/<name>` — so it is refused (lossy).
  #[test]
  fn empty_name_file_create_is_lossy() {
    let DecodeOutcome { events, lossy } =
      decode_one(&dirent(FAN_CREATE, Some(b""), Some(b"child")));
    assert!(lossy, "an empty-name create carries no path");
    assert!(events.is_empty());
  }

  /// An empty name on a DIRECTORY create is doubly malformed (no path AND `learn`
  /// could not place it); refused (lossy) rather than admitted unlearned.
  #[test]
  fn empty_name_dir_create_is_lossy() {
    let DecodeOutcome { events, lossy } =
      decode_one(&dirent(FAN_CREATE | FAN_ONDIR, Some(b""), Some(b"child")));
    assert!(lossy);
    assert!(events.is_empty());
  }

  /// An empty name on a delete leaves no path to resolve — lossy.
  #[test]
  fn empty_name_delete_is_lossy() {
    let DecodeOutcome { events, lossy } = decode_one(&dirent(FAN_DELETE, Some(b""), None));
    assert!(lossy);
    assert!(events.is_empty());
  }

  /// An empty name on a modify — lossy.
  #[test]
  fn empty_name_modify_is_lossy() {
    let DecodeOutcome { events, lossy } = decode_one(&dirent(FAN_MODIFY, Some(b""), None));
    assert!(lossy);
    assert!(events.is_empty());
  }

  /// An empty name on an attrib — lossy.
  #[test]
  fn empty_name_attrib_is_lossy() {
    let DecodeOutcome { events, lossy } = decode_one(&dirent(FAN_ATTRIB, Some(b""), None));
    assert!(lossy);
    assert!(events.is_empty());
  }

  /// A DIRECTORY create missing its `TARGET_FID` (no `FID` record) cannot be
  /// `learn`ed into the map, so its subtree would go blind — refused (lossy), the
  /// exact silent-loss-until-reseed edge this matrix closes.
  #[test]
  fn dir_create_without_target_fid_is_lossy() {
    let DecodeOutcome { events, lossy } =
      decode_one(&dirent(FAN_CREATE | FAN_ONDIR, Some(b"newdir"), None));
    assert!(
      lossy,
      "a directory create with no child FID cannot be learned"
    );
    assert!(events.is_empty());
  }

  /// The kernel's object-event shape (a `DELETE_SELF`/`ATTRIB` on an object) reports
  /// the object's OWN handle as a bare `FID` record — no `DFID`, so `dir_fid` is
  /// `None`. This is NOT malformed: admission drops a FID-less event (the firehose
  /// filter), and a drop is not coverage loss. Decode must leave it CLEAN, else the
  /// superblock's constant self/attrib traffic would spuriously reseed (and, co-
  /// batched with a real event, drop it behind the barrier — the regression this
  /// row guards). Masks `0x404` (ATTRIB|DELETE_SELF) etc. arrive exactly this way.
  #[test]
  fn object_event_with_only_own_fid_is_not_lossy() {
    for mask in [
      FAN_DELETE_SELF | FAN_ATTRIB,
      FAN_MOVE_SELF,
      FAN_ATTRIB,
      FAN_DELETE_SELF | FAN_MOVE_SELF | FAN_ATTRIB,
    ] {
      let buf = event(
        mask,
        &info_record(
          FAN_EVENT_INFO_TYPE_FID,
          &fid_payload(FSID_A, 1, b"self-handle", None),
        ),
      );
      let DecodeOutcome { events, lossy } = decode_one(&buf);
      assert!(
        !lossy,
        "a FID-less object event {mask:#x} is dropped, not lossy"
      );
      assert_eq!(events.len(), 1);
      assert!(
        events[0].dir_fid.is_none(),
        "no DFID — admission will drop it"
      );
      assert!(
        events[0].target_fid.is_some(),
        "the object's own FID is present"
      );
    }
  }

  /// An event with no FIDs at all (an empty info region) is likewise not lossy: with
  /// no directory FID it is unaddressable and admission drops it — a drop, never a
  /// decode loss that would reseed.
  #[test]
  fn event_with_no_fids_is_not_lossy() {
    let DecodeOutcome { events, lossy } = decode_one(&event(FAN_DELETE_SELF, &[]));
    assert!(
      !lossy,
      "a FID-less event is dropped by admission, not lossy"
    );
    assert_eq!(events.len(), 1);
    assert!(events[0].dir_fid.is_none());
  }

  /// The well-formed FILE create (dir FID + name, target present but not required
  /// for a file) decodes intact.
  #[test]
  fn well_formed_file_create_decodes() {
    let DecodeOutcome { events, lossy } =
      decode_one(&dirent(FAN_CREATE, Some(b"file.txt"), Some(b"child")));
    assert!(!lossy);
    assert_eq!(events.len(), 1);
    assert!(events[0].mask.created());
    assert_eq!(events[0].name.as_deref(), Some(b"file.txt".as_slice()));
  }

  /// The well-formed DIRECTORY create (dir FID + name + target) decodes intact,
  /// carrying the child FID `learn` needs.
  #[test]
  fn well_formed_dir_create_decodes() {
    let DecodeOutcome { events, lossy } = decode_one(&dirent(
      FAN_CREATE | FAN_ONDIR,
      Some(b"newdir"),
      Some(b"child"),
    ));
    assert!(!lossy);
    assert_eq!(events.len(), 1);
    assert!(events[0].mask.ondir());
    assert!(events[0].target_fid.is_some(), "the child FID is present");
  }

  /// The well-formed delete/modify/attrib (dir FID + name, no target needed) each
  /// decode intact.
  #[test]
  fn well_formed_named_events_decode() {
    for mask in [FAN_DELETE, FAN_MODIFY, FAN_ATTRIB] {
      let DecodeOutcome { events, lossy } = decode_one(&dirent(mask, Some(b"entry"), None));
      assert!(!lossy, "a named {mask:#x} event is well-formed");
      assert_eq!(events.len(), 1);
      assert_eq!(events[0].name.as_deref(), Some(b"entry".as_slice()));
    }
  }

  /// A well-formed self-event (`DELETE_SELF`/`MOVE_SELF` with a bare `DFID`, no
  /// name) decodes intact — the one legitimately name-less class.
  #[test]
  fn well_formed_self_events_decode() {
    for mask in [FAN_DELETE_SELF | FAN_ONDIR, FAN_MOVE_SELF | FAN_ONDIR] {
      let DecodeOutcome { events, lossy } = decode_one(&self_event(mask));
      assert!(!lossy, "a name-less self-event is well-formed");
      assert_eq!(events.len(), 1);
      assert!(events[0].dir_fid.is_some());
      assert!(events[0].name.is_none(), "a self-event carries no name");
    }
  }

  /// A DIRECTORY delete (`DELETE|ONDIR`) missing its child `target_fid` is lossy:
  /// `admit`'s `forget(target_fid)` would silently no-op, leaving the deleted
  /// directory in the map (its parent link still resolves, and a deleted subtree
  /// yields no further events for the lazy orphan eviction to catch) — a stale-path
  /// / directory-count hole with no loss signal. Refused → the ordered `Overflow`
  /// + reseed prunes it honestly.
  #[test]
  fn dir_delete_without_target_fid_is_lossy() {
    let DecodeOutcome { events, lossy } =
      decode_one(&dirent(FAN_DELETE | FAN_ONDIR, Some(b"sub"), None));
    assert!(
      lossy,
      "a directory delete with no child FID cannot prune its subtree"
    );
    assert!(events.is_empty());
  }

  /// The well-formed DIRECTORY delete (`DELETE|ONDIR` + name + child `target_fid`)
  /// decodes intact, carrying the FID `forget` prunes the departed subtree by.
  #[test]
  fn well_formed_dir_delete_with_target_decodes() {
    let DecodeOutcome { events, lossy } = decode_one(&dirent(
      FAN_DELETE | FAN_ONDIR,
      Some(b"sub"),
      Some(b"child"),
    ));
    assert!(!lossy);
    assert_eq!(events.len(), 1);
    assert!(events[0].mask.removed() && events[0].mask.ondir());
    assert!(events[0].target_fid.is_some(), "the child FID is present");
  }

  /// A FILE delete (`DELETE`, no `ONDIR`) mutates no directory tree — files never
  /// enter the map — so a missing `target_fid` is not a hole: it stays a clean
  /// event. The child-FID rule fires on directory deletes, never file deletes (it
  /// must not over-fire on the firehose's file traffic).
  #[test]
  fn file_delete_without_target_is_not_lossy() {
    let DecodeOutcome { events, lossy } = decode_one(&dirent(FAN_DELETE, Some(b"gone"), None));
    assert!(!lossy, "a file delete needs no child FID");
    assert_eq!(events.len(), 1);
    assert!(events[0].mask.removed() && !events[0].mask.ondir());
  }

  /// A directory `FAN_RENAME|ONDIR` missing its moved-object `target_fid` is lossy
  /// for EVERY move shape — in-root re-parent, move-out, and move-in — because decode
  /// gates BEFORE the map is consulted: it cannot know which end is in-root, so it
  /// refuses any targetless ondir rename uniformly, and none of the three shapes can
  /// reach `admit_rename`'s target-keyed re-parent / forget / walk. The well-formed
  /// counterparts (WITH target) mutate the map correctly at the admit layer.
  #[test]
  fn dir_rename_without_target_fid_is_lossy_for_every_shape() {
    for (old_handle, new_handle, shape) in [
      (b"in".as_slice(), b"in2".as_slice(), "in-root re-parent"),
      (b"in".as_slice(), b"out".as_slice(), "move-out"),
      (b"out".as_slice(), b"in".as_slice(), "move-in"),
    ] {
      let DecodeOutcome { events, lossy } =
        decode_one(&rename_event(old_handle, new_handle, true, None));
      assert!(lossy, "a targetless ondir rename ({shape}) is lossy");
      assert!(events.is_empty(), "no event escapes the gate for {shape}");
    }
  }

  /// The well-formed directory rename (`ONDIR` + both halves + the moved object's
  /// `target_fid`) decodes intact, carrying the FID `admit_rename` re-parents /
  /// forgets / walks the moved subtree by.
  #[test]
  fn well_formed_dir_rename_with_target_decodes() {
    let DecodeOutcome { events, lossy } =
      decode_one(&rename_event(b"src", b"dst", true, Some(b"moved")));
    assert!(!lossy);
    assert_eq!(events.len(), 1);
    assert!(events[0].mask.rename() && events[0].mask.ondir());
    assert!(
      events[0].target_fid.is_some(),
      "the moved object FID is present"
    );
  }

  /// A FILE rename (no `ONDIR`) mutates no directory tree, so it needs no
  /// `target_fid`: a targetless one stays a clean event, proving the child-FID rule
  /// does not over-fire on files.
  #[test]
  fn file_rename_without_target_is_not_lossy() {
    let DecodeOutcome { events, lossy } = decode_one(&rename_event(b"src", b"dst", false, None));
    assert!(
      !lossy,
      "a file rename carries no subtree, so no target is required"
    );
    assert_eq!(events.len(), 1);
    assert!(events[0].mask.rename() && !events[0].mask.ondir());
  }

  /// A directory MODIFY/ATTRIB (`ONDIR` but not a structural verb) changes content
  /// or metadata, not the tree, so it needs no `target_fid` — a high-frequency dir
  /// event the child-FID rule must NOT reseed-storm on.
  #[test]
  fn dir_modify_and_attrib_without_target_are_not_lossy() {
    for mask in [FAN_MODIFY | FAN_ONDIR, FAN_ATTRIB | FAN_ONDIR] {
      let DecodeOutcome { events, lossy } = decode_one(&dirent(mask, Some(b"d"), None));
      assert!(
        !lossy,
        "a non-structural ondir {mask:#x} event needs no child FID"
      );
      assert_eq!(events.len(), 1);
      assert!(events[0].mask.ondir());
    }
  }

  /// The root-death edge (do NOT regress): the WATCHED ROOT's own `DELETE_SELF`/
  /// `MOVE_SELF` is a SELF-event, not a child tree mutation, so the child-FID rule
  /// must never lossy nor gate it. Both report shapes stay clean:
  ///  - a bare `DFID` (the object's own directory FID, no name) → admitted, lowered
  ///    to the death lifecycle;
  ///  - a bare `FID` (`dir_fid = None`, only the object's own handle) → dropped by
  ///    admission, caught by the liveness probe.
  ///
  /// Neither carries — nor needs — a child `target_fid`.
  #[test]
  fn root_self_event_stays_clean_under_the_child_fid_rule() {
    for mask in [FAN_DELETE_SELF | FAN_ONDIR, FAN_MOVE_SELF | FAN_ONDIR] {
      // Shape 1: the root's own DFID, no name — admission resolves the root path.
      let DecodeOutcome { events, lossy } = decode_one(&self_event(mask));
      assert!(!lossy, "a name-less root self-event {mask:#x} is not lossy");
      assert_eq!(events.len(), 1);
      assert!(events[0].dir_fid.is_some() && events[0].name.is_none());

      // Shape 2: only the object's own FID (no DFID) — admission drops it.
      let buf = event(
        mask,
        &info_record(
          FAN_EVENT_INFO_TYPE_FID,
          &fid_payload(FSID_A, 1, b"root-handle", None),
        ),
      );
      let DecodeOutcome { events, lossy } = decode_one(&buf);
      assert!(!lossy, "a FID-only root self-event {mask:#x} is not lossy");
      assert_eq!(events.len(), 1);
      assert!(
        events[0].dir_fid.is_none(),
        "dropped, not lossy — the liveness probe covers it"
      );
    }
  }
}
