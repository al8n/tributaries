use super::{
  DecodeOutcome, EOVERFLOW, FAN_ATTRIB, FAN_CREATE, FAN_DELETE, FAN_EVENT_INFO_TYPE_DFID_NAME,
  FAN_EVENT_INFO_TYPE_FID, FAN_EVENT_INFO_TYPE_NEW_DFID_NAME, FAN_EVENT_INFO_TYPE_OLD_DFID_NAME,
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
/// halves parse with their own directory FID and name.
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
  let mut info = old;
  info.extend(new);
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
