use super::{
  AbiMismatch, DecodeOutcome, FAN_ATTRIB, FAN_CREATE, FAN_DELETE, FAN_DELETE_SELF,
  FAN_EVENT_INFO_TYPE_DFID, FAN_EVENT_INFO_TYPE_DFID_NAME, FAN_EVENT_INFO_TYPE_FID,
  FAN_EVENT_INFO_TYPE_NEW_DFID_NAME, FAN_EVENT_INFO_TYPE_OLD_DFID_NAME, FAN_MODIFY, FAN_MOVE_SELF,
  FAN_ONDIR, FAN_Q_OVERFLOW, FAN_RENAME, FANOTIFY_METADATA_VERSION, Fid, METADATA_LEN,
  decode_events,
};
// Used only by `handle_attempt_decision_table`, itself unix-gated (libc errnos).
#[cfg(unix)]
use super::{EOVERFLOW, HandleAttempt, classify_handle_attempt};

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

/// One `fanotify_event_metadata` with every header field spelled out, so a
/// test can plant a `vers`, a `metadata_len`, or an `event_len` the ABI
/// forbids. `header_slack` is inserted between the fixed struct and `info`,
/// which is how a header longer than the fixed struct is spelled on the wire.
fn event_with_header(
  vers: u8,
  metadata_len: u16,
  event_len: u32,
  mask: u64,
  header_slack: &[u8],
  info: &[u8],
) -> Vec<u8> {
  let mut out = Vec::new();
  out.extend_from_slice(&event_len.to_ne_bytes()); // event_len
  out.push(vers); // vers
  out.push(0); // reserved
  out.extend_from_slice(&metadata_len.to_ne_bytes()); // metadata_len
  out.extend_from_slice(&mask.to_ne_bytes()); // mask
  out.extend_from_slice(&(-1i32).to_ne_bytes()); // fd = FAN_NOFD
  out.extend_from_slice(&0i32.to_ne_bytes()); // pid
  out.extend_from_slice(header_slack);
  out.extend_from_slice(info);
  out
}

/// One `fanotify_event_metadata` (24 bytes) followed by its info records.
/// `event_len` is set to the total.
fn event(mask: u64, info: &[u8]) -> Vec<u8> {
  event_with_header(
    FANOTIFY_METADATA_VERSION,
    METADATA_LEN as u16,
    (METADATA_LEN + info.len()) as u32,
    mask,
    &[],
    info,
  )
}

/// [`decode_events`] for every cell whose buffer is well-formed or plants a
/// RECOVERABLE malformation. Only a foreign `vers` leaves by the terminal, so
/// unwrapping here is itself an assertion: a guard that over-applied the ABI
/// verdict to a malformed LENGTH or record would fail each of these cells rather
/// than quietly promote one event's corruption into a dead source.
fn decode_recoverable(buf: &[u8]) -> DecodeOutcome {
  decode_events(buf).expect("only a foreign metadata version abandons the fd")
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

  let DecodeOutcome { events, lossy } = decode_recoverable(&buf);
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
  let DecodeOutcome { events, lossy } = decode_recoverable(&buf);
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

  let DecodeOutcome { events, lossy } = decode_recoverable(&buf);
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
  let DecodeOutcome { events, lossy } = decode_recoverable(&buf);
  assert!(lossy);
  assert!(events.is_empty());
}

/// A `FAN_RENAME` whose mask is set but which carries NEITHER half is refused
/// (lossy), not silently dropped with `rename = None`: an unpairable rename must
/// take the ordered `Overflow` barrier, never fall through as a well-formed event.
#[test]
fn rename_with_zero_halves_is_lossy() {
  let buf = event(FAN_RENAME, &[]);
  let DecodeOutcome { events, lossy } = decode_recoverable(&buf);
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
  let DecodeOutcome { events, lossy } = decode_recoverable(&buf);
  assert!(lossy, "a rename half with an empty name is malformed");
  assert!(events.is_empty());
}

/// A `FAN_RENAME` half whose name is the self-name "." is refused (lossy), exactly
/// as an empty-name half is. "." is a directory's OWN self-reference, never a real
/// moved child, so a rename half carrying it is anomalous: decode folds "." to
/// `None` (see `decode_fid_record`), the pair cannot be completed, and the batch
/// takes the loss barrier rather than lowering a stray "." path component.
#[test]
fn rename_with_a_dot_name_half_is_lossy() {
  let old = info_record(
    FAN_EVENT_INFO_TYPE_OLD_DFID_NAME,
    &fid_payload(FSID_A, 1, b"srcdir", Some(b"old.txt")),
  );
  // A NEW half whose name is the self-name ".": `decode_fid_record` folds it to
  // `None`, so the pair cannot be completed.
  let new = info_record(
    FAN_EVENT_INFO_TYPE_NEW_DFID_NAME,
    &fid_payload(FSID_B, 2, b"dstdir", Some(b".")),
  );
  let mut info = old;
  info.extend(new);
  let buf = event(FAN_RENAME, &info);
  let DecodeOutcome { events, lossy } = decode_recoverable(&buf);
  assert!(lossy, "a rename half named '.' is malformed");
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
  let DecodeOutcome { events, lossy } = decode_recoverable(&buf);
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
  let DecodeOutcome { events, lossy } = decode_recoverable(&buf);
  assert!(lossy);
  assert!(events.is_empty());
}

/// One well-formed create's info region, reused by the header-contract suite
/// below: only the metadata header ever varies there.
fn one_create_info() -> Vec<u8> {
  info_record(
    FAN_EVENT_INFO_TYPE_DFID_NAME,
    &fid_payload(FSID_A, 1, b"dir-handle", Some(b"child.txt")),
  )
}

/// `vers` is the wire ABI version of `fanotify_event_metadata` itself, and
/// fanotify(7) instructs a reader that sees a foreign one to abandon the
/// stream: with the struct redefined, every offset the decode loads names a
/// different field, so `mask`, `event_len` and the info region are all read out
/// of the wrong bytes and reported as a valid event.
///
/// It leaves as [`AbiMismatch`], NOT as a `lossy` outcome, and the distinction is
/// the whole cell: the version is a property of the DESCRIPTOR, so the recoverable
/// answer (reseed the map, emit a covering `Overflow`, read on) buys a stream that
/// re-earns the same refusal on its very next buffer — forever, decoding nothing,
/// re-enumerating the tree each time and never saying the source is unusable. The
/// error carries the version seen, which is what tells a newer kernel from a
/// stream that is not fanotify at all.
///
/// MUTATION WITNESS: route `vers` back through the `lossy` header condition and
/// this FAILS at `a foreign metadata version abandons the fd, never the loss
/// barrier` — the fd's own verdict comes back as one buffer's recoverable loss.
#[test]
fn a_foreign_metadata_version_is_terminal_not_lossy() {
  let info = one_create_info();
  let buf = event_with_header(
    FANOTIFY_METADATA_VERSION + 1,
    METADATA_LEN as u16,
    (METADATA_LEN + info.len()) as u32,
    FAN_CREATE,
    &[],
    &info,
  );
  assert_eq!(
    decode_events(&buf),
    Err(AbiMismatch {
      found: FANOTIFY_METADATA_VERSION + 1
    }),
    "a foreign metadata version abandons the fd, never the loss barrier"
  );
}

/// The version gate is checked at EVERY header, not latched off the first one.
/// A latched check would be sound against the ABI alone (the kernel stamps one
/// version per fd) but not against the decode's own control flow: a malformed
/// length stops the walk mid-buffer, so the events after it are never examined
/// at all, and "already checked once" is not the same claim as "checked this
/// header". A foreign version reachable only on the SECOND event still abandons
/// the fd, and the clean event ahead of it goes with the buffer — the terminal
/// owes the consumer a covering rescan for everything the source could have
/// said, so a prefix batch off an unparseable stream buys nothing.
///
/// MUTATION WITNESS: latch the gate to the first header (`if at == 0 && vers !=
/// ...`) and this FAILS at `a foreign version on a later event still abandons
/// the fd` — the buffer decodes clean and the source reads on.
#[test]
fn a_foreign_metadata_version_on_a_later_event_is_terminal() {
  let info = one_create_info();
  let mut buf = event(FAN_CREATE, &info);
  buf.extend_from_slice(&event_with_header(
    FANOTIFY_METADATA_VERSION + 1,
    METADATA_LEN as u16,
    (METADATA_LEN + info.len()) as u32,
    FAN_CREATE,
    &[],
    &info,
  ));
  // The first event alone decodes clean, so nothing but the second header's
  // version can be what refuses the buffer.
  assert_eq!(
    decode_recoverable(&event(FAN_CREATE, &info)).events.len(),
    1,
    "the leading event is well-formed on its own"
  );
  assert_eq!(
    decode_events(&buf),
    Err(AbiMismatch {
      found: FANOTIFY_METADATA_VERSION + 1
    }),
    "a foreign version on a later event still abandons the fd"
  );
}

/// `metadata_len` is the header's own size, so a value below the fixed struct
/// claims the event ends inside words the decode has already loaded — the info
/// region would start in the middle of the header and parse its `fd`/`pid` as
/// an info record.
///
/// MUTATION WITNESS: drop `metadata_len < METADATA_LEN` and this FAILS on
/// `lossy`.
#[test]
fn a_metadata_len_below_the_fixed_struct_is_lossy() {
  let info = one_create_info();
  let buf = event_with_header(
    FANOTIFY_METADATA_VERSION,
    (METADATA_LEN - 8) as u16,
    (METADATA_LEN + info.len()) as u32,
    FAN_CREATE,
    &[],
    &info,
  );
  let DecodeOutcome { events, lossy } = decode_recoverable(&buf);
  assert!(lossy);
  assert!(events.is_empty());
}

/// A `metadata_len` past the event — and so past what the buffer holds — leaves
/// the info region with no start the record can contain.
///
/// MUTATION WITNESS: drop `event_len < metadata_len` and this FAILS on
/// `lossy`.
#[test]
fn a_metadata_len_past_the_event_is_lossy() {
  let info = one_create_info();
  let event_len = (METADATA_LEN + info.len()) as u32;
  let buf = event_with_header(
    FANOTIFY_METADATA_VERSION,
    (event_len + 8) as u16,
    event_len,
    FAN_CREATE,
    &[],
    &info,
  );
  let DecodeOutcome { events, lossy } = decode_recoverable(&buf);
  assert!(lossy);
  assert!(events.is_empty());
}

/// The point of `metadata_len`: the info records begin where the HEADER ends,
/// not at a fixed 24. A header carrying the optional per-event-type bytes the
/// field exists to allow still yields its info records intact — reading them
/// from a hardcoded offset would parse the header's own tail as a record and
/// desynchronize the walk.
///
/// MUTATION WITNESS: take the info region from a fixed `at + METADATA_LEN` and
/// this FAILS at `a grown header is not a malformed event` — the header's own
/// tail is read as an info record whose `len` escapes the event.
#[test]
fn info_records_start_where_metadata_len_says() {
  let info = one_create_info();
  // Eight bytes of header past the fixed struct, shaped so that mistaking them
  // for an info record cannot be silent: `len` = 0xFFFF escapes the event.
  let slack = [0xFFu8; 8];
  let buf = event_with_header(
    FANOTIFY_METADATA_VERSION,
    (METADATA_LEN + slack.len()) as u16,
    (METADATA_LEN + slack.len() + info.len()) as u32,
    FAN_CREATE,
    &slack,
    &info,
  );
  let DecodeOutcome { events, lossy } = decode_recoverable(&buf);
  assert!(!lossy, "a grown header is not a malformed event");
  assert_eq!(events.len(), 1);
  assert_eq!(events[0].name.as_deref(), Some(b"child.txt".as_slice()));
  assert!(events[0].dir_fid.is_some());
}

/// An info record whose `len` reaches past the event's own region is refused:
/// the walk advances by that `len`, so believing it would step into the NEXT
/// event's header (or off the buffer) and decode it as this event's payload.
///
/// MUTATION WITNESS: widen the bound to `record_len > info.len() + 16` and
/// this FAILS with `range end index 48 out of range for slice of length 40`.
#[test]
fn an_info_record_escaping_the_event_is_lossy() {
  let mut info = one_create_info();
  // The record's `len` is the u16 at offset 2 of its header.
  let escaping = (info.len() + 8) as u16;
  info[2..4].copy_from_slice(&escaping.to_ne_bytes());
  let buf = event(FAN_CREATE, &info);
  let DecodeOutcome { events, lossy } = decode_recoverable(&buf);
  assert!(lossy);
  assert!(events.is_empty());
}

/// An info record whose `len` is below its own header cannot advance the walk;
/// believing a zero would spin on the same four bytes forever. Refused.
///
/// MUTATION WITNESS: loosen the bound to `record_len < 3` and this FAILS with
/// `slice index starts at 4 but ends at 3`.
#[test]
fn an_info_record_shorter_than_its_header_is_lossy() {
  for short in [0u16, 1, 3] {
    let mut info = one_create_info();
    info[2..4].copy_from_slice(&short.to_ne_bytes());
    let buf = event(FAN_CREATE, &info);
    let DecodeOutcome { events, lossy } = decode_recoverable(&buf);
    assert!(lossy, "len={short} must refuse");
    assert!(events.is_empty());
  }
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
  let DecodeOutcome { events, lossy } = decode_recoverable(&buf);
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
  let DecodeOutcome { events, lossy } = decode_recoverable(&buf);
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

  let DecodeOutcome { events, lossy } = decode_recoverable(&buf);
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
  let DecodeOutcome { events, lossy } = decode_recoverable(&buf);
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
// The errno rows are keyed by `libc` constants (a unix-only dependency), so this
// pure-logic table is exercised on unix only; Windows still compiles the stub.
#[cfg(unix)]
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

/// Decode is PURELY STRUCTURAL after the admission-by-action inversion: it carries
/// through whatever fields the wire held and judges NO semantic required-field rule
/// (the decode-side required-field matrix is gone — the admission classifier now
/// selects an action whose own field requirements are the validation, so decode and
/// admission cannot disagree). This suite pins that
/// contract: the shapes the pre-inversion decode made lossy for a MISSING SEMANTIC
/// FIELD now decode CLEAN, carrying the omission through as `None` for the classifier
/// to judge — while the WIRE-structural refusals (a one-sided rename, a truncation, a
/// `handle_bytes` overflow) stay lossy in the dedicated tests above. The relocated
/// semantic verdicts (which of these become `Admission::Lossy` / `ForeignDrop` /
/// forward) are proven in the classifier's totality table (the `fanotify` suite).
mod structural_decode {
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
  /// directory FID + a non-empty name, so the both-halves WIRE rule always passes)
  /// and, when `target` is set, the moved object's own `FID` record. `ondir` toggles
  /// `FAN_ONDIR`.
  fn rename_event(ondir: bool, target: Option<&[u8]>) -> Vec<u8> {
    let mut info = info_record(
      FAN_EVENT_INFO_TYPE_OLD_DFID_NAME,
      &fid_payload(FSID_A, 1, b"srcdir", Some(b"old")),
    );
    info.extend(info_record(
      FAN_EVENT_INFO_TYPE_NEW_DFID_NAME,
      &fid_payload(FSID_A, 1, b"dstdir", Some(b"new")),
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
  /// the name-less shape a `DELETE_SELF`/`MOVE_SELF` carries.
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
    super::decode_recoverable(buf)
  }

  /// An empty name (a lone NUL) on any dirent no longer makes decode lossy: decode
  /// folds it to `None` and emits the event clean. The classifier catches the
  /// missing name at the action (a named dirent needs its name → `Lossy`); decode
  /// does not pre-judge it.
  #[test]
  fn empty_name_dirent_decodes_clean_with_no_name() {
    for mask in [
      FAN_CREATE,
      FAN_CREATE | FAN_ONDIR,
      FAN_DELETE,
      FAN_MODIFY,
      FAN_ATTRIB,
    ] {
      let DecodeOutcome { events, lossy } = decode_one(&dirent(mask, Some(b""), Some(b"child")));
      assert!(!lossy, "an empty-name {mask:#x} is not a WIRE loss");
      assert_eq!(events.len(), 1);
      assert!(
        events[0].name.is_none(),
        "the empty name folded to None for the classifier to judge"
      );
    }
  }

  /// A DIRECTORY create/delete missing its `TARGET_FID` no longer makes decode
  /// lossy: decode emits it with `target_fid = None` and the classifier decides
  /// (an in-root dir mutation with no child FID → `Lossy`; out-of-root →
  /// `ForeignDrop`). Decode itself no longer runs any semantic child-FID matrix.
  #[test]
  fn dir_mutation_without_target_decodes_clean() {
    for mask in [FAN_CREATE | FAN_ONDIR, FAN_DELETE | FAN_ONDIR] {
      let DecodeOutcome { events, lossy } = decode_one(&dirent(mask, Some(b"sub"), None));
      assert!(
        !lossy,
        "a targetless dir mutation {mask:#x} is not a WIRE loss"
      );
      assert_eq!(events.len(), 1);
      assert!(
        events[0].target_fid.is_none(),
        "the absent child FID is carried through for the classifier"
      );
      assert!(events[0].dir_fid.is_some() && events[0].name.is_some());
    }
  }

  /// A directory `FAN_RENAME|ONDIR` missing its moved-object `target_fid` decodes
  /// CLEAN (both halves are present — the WIRE rule passes) and carries
  /// `target_fid = None`. The old decode made this lossy via its child-FID matrix;
  /// now the classifier makes a targetless ONDIR rename `Lossy` per move shape,
  /// against the map (see the `fanotify` totality table).
  #[test]
  fn dir_rename_without_target_decodes_clean() {
    let DecodeOutcome { events, lossy } = decode_one(&rename_event(true, None));
    assert!(!lossy, "both halves present ⇒ no WIRE loss");
    assert_eq!(events.len(), 1);
    assert!(events[0].rename.is_some() && events[0].mask.ondir());
    assert!(
      events[0].target_fid.is_none(),
      "the absent moved FID is the classifier's to judge, not decode's"
    );
  }

  /// A FILE rename (no `ONDIR`) with no target decodes clean — unchanged; there was
  /// never a WIRE reason to refuse it.
  #[test]
  fn file_rename_without_target_decodes_clean() {
    let DecodeOutcome { events, lossy } = decode_one(&rename_event(false, None));
    assert!(!lossy);
    assert_eq!(events.len(), 1);
    assert!(events[0].rename.is_some() && !events[0].mask.ondir());
  }

  /// The kernel's object-event shape (a `DELETE_SELF`/`ATTRIB` on an object) reports
  /// the object's OWN handle as a bare `FID` record — no `DFID`, so `dir_fid` is
  /// `None`, `target_fid` present. Always a clean decode (the classifier routes it:
  /// a root self-FID → `RootDeath`, else `ForeignDrop`). Masks `0x404`
  /// (ATTRIB|DELETE_SELF) etc. arrive exactly this way.
  #[test]
  fn object_event_with_only_own_fid_decodes_clean() {
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
        "a FID-only object event {mask:#x} is not a WIRE loss"
      );
      assert_eq!(events.len(), 1);
      assert!(events[0].dir_fid.is_none(), "no DFID — the FID-only shape");
      assert!(
        events[0].target_fid.is_some(),
        "the object's own FID is present"
      );
    }
  }

  /// An event with no FIDs at all (an empty info region) decodes clean too: the
  /// classifier drops it (unaddressable firehose noise), never a decode loss.
  #[test]
  fn event_with_no_fids_decodes_clean() {
    let DecodeOutcome { events, lossy } = decode_one(&event(FAN_DELETE_SELF, &[]));
    assert!(!lossy);
    assert_eq!(events.len(), 1);
    assert!(events[0].dir_fid.is_none() && events[0].target_fid.is_none());
  }

  /// The well-formed shapes still decode intact, carrying every field the classifier
  /// consumes: a file/dir create with its name (+ child FID), a named
  /// delete/modify/attrib, a name-less self-event, a targeted directory rename.
  #[test]
  fn well_formed_shapes_decode_intact() {
    let DecodeOutcome { events, lossy } = decode_one(&dirent(
      FAN_CREATE | FAN_ONDIR,
      Some(b"newdir"),
      Some(b"child"),
    ));
    assert!(!lossy);
    assert!(events[0].mask.ondir() && events[0].target_fid.is_some());

    for mask in [FAN_DELETE, FAN_MODIFY, FAN_ATTRIB] {
      let DecodeOutcome { events, lossy } = decode_one(&dirent(mask, Some(b"entry"), None));
      assert!(!lossy, "a named {mask:#x} event decodes");
      assert_eq!(events[0].name.as_deref(), Some(b"entry".as_slice()));
    }

    for mask in [FAN_DELETE_SELF | FAN_ONDIR, FAN_MOVE_SELF | FAN_ONDIR] {
      let DecodeOutcome { events, lossy } = decode_one(&self_event(mask));
      assert!(!lossy, "a name-less self-event decodes");
      assert!(events[0].dir_fid.is_some() && events[0].name.is_none());
    }

    let DecodeOutcome { events, lossy } = decode_one(&rename_event(true, Some(b"moved")));
    assert!(!lossy);
    assert!(events[0].mask.rename() && events[0].target_fid.is_some());
  }

  /// A `DFID_NAME` whose name is the self-name "." is the kernel's encoding for an
  /// event on the directory OBJECT ITSELF (man 7 fanotify). Decode folds it to the
  /// name-less SELF shape — `name = None`, `dir_fid` = the directory's own FID —
  /// identical to the empty-name bare-`DFID_NAME` form, so the classifier routes it
  /// to its self path (a root's `RootDeath`, a subdir self-forget, a bare
  /// modify/attrib on the object's own path) instead of a bogus `<dir>/.` child.
  #[test]
  fn dfid_name_dot_folds_to_the_self_shape() {
    for mask in [
      FAN_DELETE_SELF | FAN_ONDIR,
      FAN_MOVE_SELF | FAN_ONDIR,
      FAN_ATTRIB | FAN_ONDIR,
      FAN_MODIFY | FAN_ONDIR,
    ] {
      let DecodeOutcome { events, lossy } = decode_one(&dirent(mask, Some(b"."), None));
      assert!(!lossy, "a '.' self-event {mask:#x} is not a WIRE loss");
      assert_eq!(events.len(), 1);
      assert!(
        events[0].name.is_none(),
        "the '.' self-name folded to None (the name-less self shape)"
      );
      let dir_fid = events[0]
        .dir_fid
        .as_ref()
        .expect("the DFID is preserved as the self-addressing object");
      // The stored handle is the type word (native-endian i32) then the opaque
      // bytes — the `dirent` helper's `fid_payload(FSID_A, 1, b"dir-handle", ..)`.
      let mut expected = 1i32.to_ne_bytes().to_vec();
      expected.extend_from_slice(b"dir-handle");
      assert_eq!(dir_fid.handle(), expected.as_slice());
      assert!(events[0].target_fid.is_none());
    }
  }

  /// ONLY exactly "." folds. A real child name — including one that merely CONTAINS
  /// a dot ("a.txt"), BEGINS with one (".hidden"), or is the parent link ("..") — is
  /// carried through UNCHANGED, so decode never mistakes a legitimate dirent for the
  /// self-encoding.
  #[test]
  fn only_exact_dot_folds_real_child_names_pass_through() {
    for name in [b".." as &[u8], b".hidden", b"a.txt", b"...", b".a", b"a."] {
      let DecodeOutcome { events, lossy } = decode_one(&dirent(FAN_CREATE, Some(name), Some(b"c")));
      assert!(!lossy);
      assert_eq!(events.len(), 1);
      assert_eq!(
        events[0].name.as_deref(),
        Some(name),
        "a real child name is unchanged; only exactly '.' folds to the self shape"
      );
    }
  }
}
