use std::{cell::Cell, io, path::Path};

use super::{ReseedOutcome, SeedOutcome, process_decoded, reseed_map, seed_moved_in_subtree};
use crate::os::{
  BackendStatsShared, SourceMessage,
  linux::fanotify::{
    fid::{
      DecodeOutcome, FAN_CREATE, FAN_DELETE, FAN_DELETE_SELF, FAN_EVENT_INFO_TYPE_DFID_NAME,
      FAN_MODIFY, FAN_MOVE_SELF, FAN_ONDIR, FAN_RENAME, FanMask, Fid, RawFanotifyEvent, RenameInfo,
      decode_events,
    },
    map::{FidMap, SeedEntry},
  },
  transport::TransportState,
};

fn fid(tag: u8) -> Fid {
  Fid::new([tag; 8], Box::from(&[tag][..]))
}

/// The exact `Fid` `decode_events` yields from a wire FID (handle = `handle_type`
/// native-endian i32 followed by `opaque`), so a map seeded with it matches the
/// decoded event's FID — the map keys on the handle bytes.
fn wire_fid(fsid: [u8; 8], handle_type: i32, opaque: &[u8]) -> Fid {
  let mut handle = handle_type.to_ne_bytes().to_vec();
  handle.extend_from_slice(opaque);
  Fid::new(fsid, handle.into_boxed_slice())
}

/// A one-record fanotify buffer: a single `DFID_NAME` info record (fsid + file
/// handle + a NUL-terminated `name`) in an event of `mask` — the packed wire shape
/// the kernel delivers a directory self-event in when it uses the "." self-name.
fn dfid_name_event(
  mask: u64,
  fsid: [u8; 8],
  handle_type: i32,
  opaque: &[u8],
  name: &[u8],
) -> Vec<u8> {
  let mut fh = (opaque.len() as u32).to_ne_bytes().to_vec();
  fh.extend_from_slice(&handle_type.to_ne_bytes());
  fh.extend_from_slice(opaque);
  let mut payload = fsid.to_vec();
  payload.extend_from_slice(&fh);
  payload.extend_from_slice(name);
  payload.push(0);
  let record_len = (4 + payload.len()) as u16;
  let mut info = vec![FAN_EVENT_INFO_TYPE_DFID_NAME, 0];
  info.extend_from_slice(&record_len.to_ne_bytes());
  info.extend_from_slice(&payload);
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

/// A `FAN_MODIFY` event on child `name` under directory `dir_fid` — the simplest
/// admissible shape: if `dir_fid` is in the map it resolves to `<dir>/<name>` and
/// would forward as a Batch entry, so it is the suffix event the barrier must drop.
fn modify_under(dir_fid: Fid, name: &[u8]) -> RawFanotifyEvent {
  RawFanotifyEvent {
    mask: FanMask::new(FAN_MODIFY),
    dir_fid: Some(dir_fid),
    target_fid: None,
    name: Some(name.to_vec()),
    rename: None,
  }
}

/// The kind of each message a `process_decoded` call put on the queue, captured
/// in order — enough to assert the barrier (no `Batch` ahead of the `Overflow`).
#[derive(Debug, PartialEq, Eq)]
enum Sent {
  Batch(usize),
  Overflow,
  Fatal,
}

/// Runs `process_decoded` over `decoded` against `map`, capturing what it forwards
/// (in order) and how many times each walk closure ran. The reseed walk returns
/// `reseed`; a `None` reseed models a walk that fails every attempt (→ blind).
fn run_process(
  map: &mut FidMap,
  decoded: DecodeOutcome,
  reseed: Option<Vec<SeedEntry>>,
) -> (Vec<Sent>, bool, u32) {
  let stats = BackendStatsShared::default();
  let transport = TransportState::new(8);
  let sent = std::cell::RefCell::new(Vec::new());
  let reseeds = Cell::new(0u32);
  let alive = process_decoded(
    decoded,
    map,
    &stats,
    &transport,
    &[],
    || {
      reseeds.set(reseeds.get() + 1);
      match &reseed {
        Some(entries) => Ok(entries.clone()),
        None => Err(io::Error::other("reseed walk fails")),
      }
    },
    |_, _, _| Ok(Vec::new()),
    |msg| {
      sent.borrow_mut().push(match msg {
        SourceMessage::Batch(payload) => Sent::Batch(payload.events.len()),
        SourceMessage::Overflow(_) => Sent::Overflow,
        SourceMessage::Fatal(_) => Sent::Fatal,
      });
      true
    },
  );
  (sent.into_inner(), alive, reseeds.get())
}

/// [`run_process`] with an exclusion set — the admission fence, which covers the two
/// shapes the walk fence structurally cannot: an event about the excluded directory
/// ITSELF (its parent is mapped, so it would admit) and a rename with one end inside
/// it. Returns the events actually forwarded.
fn run_process_with_exclusions(
  map: &mut FidMap,
  decoded: DecodeOutcome,
  exclusions: &[std::path::PathBuf],
) -> Vec<crate::os::linux::AdmittedEvent> {
  let stats = BackendStatsShared::default();
  let transport = TransportState::new(8);
  let forwarded = std::cell::RefCell::new(Vec::new());
  let alive = process_decoded(
    decoded,
    map,
    &stats,
    &transport,
    exclusions,
    || Ok(one_entry_walk()),
    |_, _, _| Ok(Vec::new()),
    |msg| {
      if let SourceMessage::Batch(payload) = msg {
        for ev in payload.events {
          if let crate::os::SourceEvent::Linux(crate::os::linux::RawLinuxEvent::Fanotify(a)) = ev {
            forwarded.borrow_mut().push(a);
          }
        }
      }
      true
    },
  );
  assert!(
    alive,
    "an exclusion suppresses events, it never kills the stream"
  );
  forwarded.into_inner()
}

/// [`run_process`] with the moved-in subtree walk under the caller's control:
/// `subtree` is what every attempt returns, so `None` models a walk that fails
/// every time — the stale-path shape an in-batch move burst produces.
fn run_process_with_subtree(
  map: &mut FidMap,
  decoded: DecodeOutcome,
  reseed: Option<Vec<SeedEntry>>,
  subtree: Option<Vec<SeedEntry>>,
) -> (Vec<Sent>, bool, u32, u32) {
  let stats = BackendStatsShared::default();
  let transport = TransportState::new(8);
  let sent = std::cell::RefCell::new(Vec::new());
  let reseeds = Cell::new(0u32);
  let walks = Cell::new(0u32);
  let alive = process_decoded(
    decoded,
    map,
    &stats,
    &transport,
    &[],
    || {
      reseeds.set(reseeds.get() + 1);
      match &reseed {
        Some(entries) => Ok(entries.clone()),
        None => Err(io::Error::other("reseed walk fails")),
      }
    },
    |_, _, _| {
      walks.set(walks.get() + 1);
      match &subtree {
        Some(entries) => Ok(entries.clone()),
        None => Err(io::Error::from(io::ErrorKind::NotFound)),
      }
    },
    |msg| {
      sent.borrow_mut().push(match msg {
        SourceMessage::Batch(payload) => Sent::Batch(payload.events.len()),
        SourceMessage::Overflow(_) => Sent::Overflow,
        SourceMessage::Fatal(_) => Sent::Fatal,
      });
      true
    },
  );
  (sent.into_inner(), alive, reseeds.get(), walks.get())
}

/// A populated directory (`fid 5`) moved INTO `/root/sub` from outside the root —
/// the shape that owes a descendant walk, so its walk failing is what the burst
/// trace turns on.
fn move_in_under_sub() -> RawFanotifyEvent {
  RawFanotifyEvent {
    mask: FanMask::new(FAN_RENAME | FAN_ONDIR),
    dir_fid: None,
    target_fid: Some(fid(5)),
    name: None,
    rename: Some(RenameInfo {
      old_dir: fid(9),
      old_name: b"X".to_vec(),
      new_dir: fid(2),
      new_name: b"X".to_vec(),
    }),
  }
}

fn one_entry_walk() -> Vec<SeedEntry> {
  vec![SeedEntry::root(fid(1), Path::new("/root"))]
}

/// A seeded map with `/root` and its child `/root/sub` (fid 2), the parent a
/// moved-in directory's descendants would hang off of.
fn seeded_with_sub() -> FidMap {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), std::ffi::OsString::from("sub")),
  ]);
  map
}

/// A walk that succeeds on the FIRST try reseeds the map and reports
/// `Reseeded` — the common path.
#[test]
fn first_walk_success_reseeds() {
  let mut map = FidMap::new();
  let outcome = reseed_map(&mut map, || Ok(one_entry_walk()));
  assert_eq!(outcome, ReseedOutcome::Reseeded);
  assert_eq!(map.dir_count(), 1, "the map was rebuilt from the walk");
}

/// A transient failure is absorbed by the single immediate retry: fail once,
/// succeed on the retry, and the map is still restored (no scope death for a
/// momentary hiccup).
#[test]
fn retry_absorbs_a_transient_failure() {
  let mut map = FidMap::new();
  let calls = Cell::new(0u32);
  let outcome = reseed_map(&mut map, || {
    calls.set(calls.get() + 1);
    if calls.get() == 1 {
      Err(io::Error::other("transient"))
    } else {
      Ok(one_entry_walk())
    }
  });
  assert_eq!(outcome, ReseedOutcome::Reseeded);
  assert_eq!(calls.get(), 2, "the retry ran exactly once");
  assert_eq!(map.dir_count(), 1);
}

/// A walk that fails TWICE concedes blindness: the policy returns `Blind`, the
/// signal the reader escalates to a terminal `Fatal` (a stale-but-running source
/// is the silent-loss shape the whole stack prevents). The map is left untouched
/// rather than half-rebuilt.
#[test]
fn double_failure_is_blind() {
  let mut map = FidMap::new();
  let calls = Cell::new(0u32);
  let outcome = reseed_map(&mut map, || {
    calls.set(calls.get() + 1);
    Err::<Vec<SeedEntry>, io::Error>(io::Error::other("still failing"))
  });
  assert_eq!(outcome, ReseedOutcome::Blind);
  assert_eq!(
    calls.get(),
    2,
    "the walk was attempted twice, then conceded"
  );
  assert_eq!(
    map.dir_count(),
    0,
    "a failed reseed leaves the map untouched"
  );
}

/// A moved-in subtree walk that succeeds on the FIRST try ADDS its descendant
/// directories to the map (never clears it — the moved dir and everything else
/// already present stay), clears the moved dir's `pending_walk`, and reports
/// `Seeded` — the completeness-restoring path at the boundary-move site. The walk
/// closure receives the moved dir's CURRENT resolved path (not a captured one).
#[test]
fn subtree_walk_success_adds_descendants() {
  let mut map = seeded_with_sub();
  // The moved directory `arrived` (fid 5) was learned under /root/sub as a
  // pending-walk top; the walk discovers its pre-existing descendant `deep`
  // (fid 6).
  map.learn_moved_in(&fid(2), b"arrived", &fid(5));
  let before = map.dir_count();
  let seen_path = Cell::new(None);
  let outcome = seed_moved_in_subtree(&mut map, &fid(5), |subtree, _| {
    seen_path.set(Some(subtree.to_path_buf()));
    Ok(vec![SeedEntry::child(
      fid(6),
      fid(5),
      std::ffi::OsString::from("deep"),
    )])
  });
  assert_eq!(outcome, SeedOutcome::Seeded);
  assert_eq!(
    seen_path.take(),
    Some(std::path::PathBuf::from("/root/sub/arrived")),
    "the walk ran from the moved dir's current resolved path"
  );
  assert_eq!(
    map.dir_count(),
    before + 1,
    "the descendant was ADDED, the rest of the map untouched"
  );
  assert_eq!(
    map.admit(&fid(6)),
    Some(std::path::PathBuf::from("/root/sub/arrived/deep")),
    "the walked descendant now admits under the moved directory"
  );
  assert_eq!(
    map.pending_walk_target(&fid(5)).map(|(_, p)| p),
    Some(false),
    "the pending_walk flag is cleared once the walk completes"
  );
}

/// A transient walk failure is absorbed by the single immediate retry (mirroring
/// `reseed_map`): fail once, succeed on the retry, and the descendants are still
/// mapped — no scope death for a momentary hiccup mid-walk.
#[test]
fn subtree_walk_retry_absorbs_a_transient_failure() {
  let mut map = seeded_with_sub();
  map.learn_moved_in(&fid(2), b"arrived", &fid(5));
  let calls = Cell::new(0u32);
  let outcome = seed_moved_in_subtree(&mut map, &fid(5), |_, _| {
    calls.set(calls.get() + 1);
    if calls.get() == 1 {
      Err(io::Error::other("transient"))
    } else {
      Ok(vec![SeedEntry::child(
        fid(6),
        fid(5),
        std::ffi::OsString::from("deep"),
      )])
    }
  });
  assert_eq!(outcome, SeedOutcome::Seeded);
  assert_eq!(calls.get(), 2, "the retry ran exactly once");
  assert!(
    map.admit(&fid(6)).is_some(),
    "the descendant was mapped on retry"
  );
}

/// A moved-in subtree walk that fails TWICE concedes `Blind` — the signal the
/// reader escalates to a terminal `Fatal` (a foreign populated directory whose
/// descendants cannot be mapped is the silent-loss shape). The map keeps whatever
/// was already present (the moved dir stays learned); only the unreachable
/// descendants are missing, which is exactly why the source must die rather than
/// run on blind.
#[test]
fn subtree_walk_double_failure_is_blind() {
  let mut map = seeded_with_sub();
  map.learn_moved_in(&fid(2), b"arrived", &fid(5));
  let calls = Cell::new(0u32);
  let outcome = seed_moved_in_subtree(&mut map, &fid(5), |_, _| {
    calls.set(calls.get() + 1);
    Err::<Vec<SeedEntry>, io::Error>(io::Error::other("still failing"))
  });
  assert_eq!(outcome, SeedOutcome::Blind);
  assert_eq!(
    calls.get(),
    2,
    "the walk was attempted twice, then conceded"
  );
  assert!(
    map.contains(&fid(5)),
    "the moved directory itself stays learned — only its subtree is missing"
  );
  assert_eq!(
    map.pending_walk_target(&fid(5)).map(|(_, p)| p),
    Some(true),
    "a blinding walk leaves the flag set — the obligation was never discharged"
  );
}

/// If the moved-in top is FORGOTTEN (rename-out / delete by an intervening event)
/// before its deferred walk runs, the walk is CANCELLED: `pending_walk_target`
/// returns `None`, so `seed_moved_in_subtree` reports `Seeded` WITHOUT calling the
/// walk closure — a departed subtree owes nothing.
#[test]
fn walk_is_cancelled_when_the_moved_dir_was_forgotten() {
  let mut map = seeded_with_sub();
  map.learn_moved_in(&fid(2), b"arrived", &fid(5));
  // An intervening event forgot the moved dir before the walk ran.
  map.forget(&fid(5));
  let calls = Cell::new(0u32);
  let outcome = seed_moved_in_subtree(&mut map, &fid(5), |_, _| {
    calls.set(calls.get() + 1);
    Ok(Vec::new())
  });
  assert_eq!(
    outcome,
    SeedOutcome::Seeded,
    "a cancelled walk is not blind"
  );
  assert_eq!(calls.get(), 0, "the walk closure never ran");
}

/// If an intervening event already CLEARED the moved dir's `pending_walk` (the
/// obligation was discharged elsewhere), the deferred walk is a no-op: `Seeded`
/// with no closure call. The dedup-by-node guard against a redundant re-walk.
#[test]
fn walk_is_skipped_when_no_longer_pending() {
  let mut map = seeded_with_sub();
  map.learn_moved_in(&fid(2), b"arrived", &fid(5));
  map.clear_pending_walk(&fid(5));
  let calls = Cell::new(0u32);
  let outcome = seed_moved_in_subtree(&mut map, &fid(5), |_, _| {
    calls.set(calls.get() + 1);
    Ok(Vec::new())
  });
  assert_eq!(outcome, SeedOutcome::Seeded);
  assert_eq!(calls.get(), 0, "an already-discharged walk does not re-run");
}

/// The burst scenario at the READER layer: a populated dir moved in to
/// /root/sub/arrived (learned pending) then re-parented in-root to /root/other in
/// the SAME batch, BEFORE the deferred walk runs. The walk must resolve the
/// CURRENT path (/root/other/arrived) through the map — not the stale
/// admission-time /root/sub/arrived — and map the descendant there. A stale
/// captured path would `read_dir` a nonexistent location.
#[test]
fn deferred_walk_resolves_current_path_after_reparent() {
  let mut map = seeded_with_sub();
  // A second in-root parent /root/other for the re-parent destination.
  map.learn(&fid(1), b"other", Some(&fid(3)));
  // Event 1: populated dir (fid 5) moved in under /root/sub, learned pending.
  map.learn_moved_in(&fid(2), b"arrived", &fid(5));
  // Event 2 (same batch): re-parented in-root to /root/other/arrived.
  map.learn(&fid(3), b"arrived", Some(&fid(5)));
  // The deferred walk resolves the moved dir where it ACTUALLY is now.
  let seen_path = Cell::new(None);
  let outcome = seed_moved_in_subtree(&mut map, &fid(5), |subtree, _| {
    seen_path.set(Some(subtree.to_path_buf()));
    Ok(vec![SeedEntry::child(
      fid(6),
      fid(5),
      std::ffi::OsString::from("deep"),
    )])
  });
  assert_eq!(outcome, SeedOutcome::Seeded);
  assert_eq!(
    seen_path.take(),
    Some(std::path::PathBuf::from("/root/other/arrived")),
    "the walk followed the in-root re-parent to the current path"
  );
  assert_eq!(
    map.admit(&fid(6)),
    Some(std::path::PathBuf::from("/root/other/arrived/deep")),
    "the descendant is mapped under the moved dir's CURRENT location"
  );
}

/// The reviewer's exact regression, at the seam: a LOSSY buffer whose suffix is an
/// event under an in-root FID (which would resolve to a path and forward as a Batch
/// entry) must forward NO Batch — only the `Overflow` — and must reseed first. The
/// suffix path could be STALE (a rename lost in the window), so delivering it ahead
/// of the covering rescan is the wrong-path hole this barrier closes. Decode keeps
/// the post-marker event in `.events` (its own contract); the reader drops it here.
#[test]
fn lossy_buffer_forwards_only_the_overflow_after_reseeding() {
  let mut map = seeded_with_sub();
  // A suffix event under /root/sub (fid 2, in-map): it WOULD admit to /root/sub/f.
  let decoded = DecodeOutcome {
    events: vec![modify_under(fid(2), b"f")],
    lossy: true,
  };
  let (sent, alive, reseeds) = run_process(&mut map, decoded, Some(one_entry_walk()));
  assert!(alive, "a reseeded loss keeps the stream live");
  assert_eq!(reseeds, 1, "the loss reseeded the map before signaling");
  assert_eq!(
    sent,
    vec![Sent::Overflow],
    "the barrier: no Batch precedes the Overflow — the suffix event is dropped"
  );
}

/// A MERGED multi-structural event (a create+delete of the same dirent — man 7
/// fanotify merges consecutive events for one object, and the mask is a bitmask) is
/// SEMANTICALLY ambiguous, not wire-lossy: decode produces it intact (`lossy: false`),
/// and classify routes it to `Admission::Lossy`, so the reader takes the SAME
/// per-buffer barrier a wire loss takes. This drives the merged event end to end
/// (decode outcome → classify → barrier): a would-forward event co-batched AHEAD of it
/// is dropped (only the `Overflow` is forwarded, no Batch), the map is reseeded rather
/// than one-sided-mutated (the merged create never learns the deleted child), and the
/// stream stays live. The deterministic container-reality complement to the hermetic
/// oracle — the kernel MAY merge, and however it does, the seam refuses the ambiguity.
#[test]
fn merged_multi_structural_event_takes_the_barrier_and_reseeds() {
  let mut map = seeded_with_sub();
  let merged = RawFanotifyEvent {
    mask: FanMask::new(FAN_CREATE | FAN_DELETE | FAN_ONDIR),
    dir_fid: Some(fid(2)),
    target_fid: Some(fid(7)),
    name: Some(b"merged".to_vec()),
    rename: None,
  };
  // A would-forward modify AHEAD of the merged event: the barrier must drop it too.
  let decoded = DecodeOutcome {
    events: vec![modify_under(fid(2), b"before"), merged],
    lossy: false,
  };
  let (sent, alive, reseeds) = run_process(&mut map, decoded, Some(one_entry_walk()));
  assert!(
    alive,
    "the ambiguous merge reseeds and keeps the stream live"
  );
  assert_eq!(
    reseeds, 1,
    "classify's Lossy took the barrier and reseeded once"
  );
  assert_eq!(
    sent,
    vec![Sent::Overflow],
    "the barrier: only the Overflow — the merged event AND the co-batched suffix drop"
  );
  assert!(
    !map.contains_dir(&fid(7)),
    "the merged create never learned the child its co-merged delete removed"
  );
}

/// The rename half of the same class, driven end to end: a directory renamed AND
/// deleted in ONE kernel-merged event (`FAN_RENAME|FAN_DELETE`, both rename halves
/// present) is decoded intact (`lossy: false`), but classify now counts `FAN_RENAME`
/// as a structural verb — so the merged mask is multi-structural and the universal gate
/// routes it to `Admission::Lossy`, taking the SAME per-buffer barrier a wire loss does.
/// A would-forward modify co-batched AHEAD of it is dropped (only the `Overflow`, no
/// Batch), the map is reseeded rather than one-sided re-parented (fid(2) is NOT moved to
/// /root/moved), and the stream stays live. The reader-level complement to the classify
/// oracle for the rename-before-guard class the fix closes.
#[test]
fn merged_rename_delete_takes_the_barrier_and_reseeds() {
  let mut map = seeded_with_sub();
  let merged = RawFanotifyEvent {
    mask: FanMask::new(FAN_RENAME | FAN_DELETE | FAN_ONDIR),
    dir_fid: None,
    target_fid: Some(fid(2)),
    name: None,
    rename: Some(RenameInfo {
      old_dir: fid(1),
      old_name: b"sub".to_vec(),
      new_dir: fid(1),
      new_name: b"moved".to_vec(),
    }),
  };
  // A would-forward modify AHEAD of the merged rename: the barrier must drop it too.
  let decoded = DecodeOutcome {
    events: vec![modify_under(fid(2), b"before"), merged],
    lossy: false,
  };
  let (sent, alive, reseeds) = run_process(&mut map, decoded, Some(one_entry_walk()));
  assert!(
    alive,
    "the ambiguous rename+delete reseeds and keeps the stream live"
  );
  assert_eq!(
    reseeds, 1,
    "classify's Lossy took the barrier and reseeded once"
  );
  assert_eq!(
    sent,
    vec![Sent::Overflow],
    "the barrier: only the Overflow — the merged rename AND the co-batched suffix drop"
  );
  assert_eq!(
    map.admit(&fid(2)),
    None,
    "no one-sided re-parent survived: the reseed rebuilt from the walk, not a half-applied rename"
  );
}

/// The rename-only-admittance class, driven end to end at the reader: a directory renamed
/// AND self-moved in ONE kernel-merged event (`FAN_RENAME|FAN_MOVE_SELF|ONDIR`, both rename
/// halves present) whose rename PARENTS are both foreign but whose moved `target_fid` IS the
/// watched ROOT. The rename-only admittance saw only the foreign parents and `ForeignDrop`ped
/// it — silently losing an in-root root-death event and leaving the root UN-reseeded; the
/// action-aware gate sees the in-root `target_fid` and routes the ambiguity to
/// `Admission::Lossy`, so the reader takes the SAME per-buffer barrier a wire loss does. A
/// would-forward modify co-batched AHEAD of it is dropped (only the `Overflow`, no Batch), the
/// map is RESEEDED (the root is not left un-reseeded), and the stream stays live. The
/// reader-level complement to the classify oracle for the class the action-aware admittance
/// closes.
#[test]
fn merged_rename_self_hidden_in_root_target_takes_the_barrier_and_reseeds() {
  let mut map = seeded_with_sub();
  let merged = RawFanotifyEvent {
    mask: FanMask::new(FAN_RENAME | FAN_MOVE_SELF | FAN_ONDIR),
    dir_fid: None,
    target_fid: Some(fid(1)), // the ROOT — the in-root object the foreign parents hid
    name: None,
    rename: Some(RenameInfo {
      old_dir: fid(90),
      old_name: b"root".to_vec(),
      new_dir: fid(91),
      new_name: b"root".to_vec(),
    }),
  };
  // A would-forward modify AHEAD of the merged event: the barrier must drop it too.
  let decoded = DecodeOutcome {
    events: vec![modify_under(fid(2), b"before"), merged],
    lossy: false,
  };
  let (sent, alive, reseeds) = run_process(&mut map, decoded, Some(one_entry_walk()));
  assert!(
    alive,
    "the ambiguous merge reseeds and keeps the stream live"
  );
  assert_eq!(
    reseeds, 1,
    "the in-root target_fid is seen, so the merge takes the barrier and reseeds — the root is not left un-reseeded"
  );
  assert_eq!(
    sent,
    vec![Sent::Overflow],
    "the barrier: only the Overflow — the merged event AND the co-batched suffix drop"
  );
}

/// The downstream half of the missing-target directory-delete class: once decode
/// makes a targetless `FAN_DELETE|ONDIR` lossy (the decode gate is
/// exercised in the `fid` suite), the reader reseeds — and the reseed must PRUNE the
/// stale subtree the old lazy-only path would have left admitting forever (a deleted
/// directory yields no further events for the lazy orphan eviction to catch). A
/// targetless dir-delete decodes to an EMPTY, lossy buffer (`decode_info` returns
/// `None` and stops), so this drives that exact shape and asserts the map returns to
/// the post-delete baseline — the deleted directory and its descendant are gone, not
/// stale.
#[test]
fn lossy_dir_delete_reseed_prunes_the_stale_subtree() {
  let mut map = FidMap::new();
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), std::ffi::OsString::from("sub")),
    SeedEntry::child(fid(3), fid(2), std::ffi::OsString::from("child")),
  ]);
  assert_eq!(map.dir_count(), 3);
  // The lossy buffer a targetless dir-delete produces: no events, only the loss. The
  // fresh walk observes the tree AFTER /root/sub was removed — just the root remains.
  let decoded = DecodeOutcome {
    events: Vec::new(),
    lossy: true,
  };
  let (sent, alive, reseeds) = run_process(&mut map, decoded, Some(one_entry_walk()));
  assert!(alive, "a reseeded loss keeps the stream live");
  assert_eq!(reseeds, 1, "the loss reseeded the map");
  assert_eq!(
    sent,
    vec![Sent::Overflow],
    "only the Overflow barrier is forwarded"
  );
  assert_eq!(
    map.dir_count(),
    1,
    "the reseed pruned the deleted subtree — no stale directories left admitting"
  );
  assert_eq!(map.admit(&fid(2)), None, "the deleted directory is gone");
  assert_eq!(map.admit(&fid(3)), None, "and its descendant with it");
}

/// A CLEAN buffer forwards its admitted events as one Batch and NO Overflow, and
/// never reseeds — the barrier branch is not on the happy path.
#[test]
fn clean_buffer_forwards_the_batch_and_never_reseeds() {
  let mut map = seeded_with_sub();
  let decoded = DecodeOutcome {
    events: vec![modify_under(fid(2), b"f"), modify_under(fid(1), b"g")],
    lossy: false,
  };
  let (sent, alive, reseeds) = run_process(&mut map, decoded, Some(one_entry_walk()));
  assert!(alive);
  assert_eq!(reseeds, 0, "a clean buffer never triggers a reseed");
  assert_eq!(
    sent,
    vec![Sent::Batch(2)],
    "both admitted events ride one Batch, no Overflow"
  );
}

/// A CLEAN buffer (`decoded.lossy == false`) whose events include a CLASSIFIED
/// `Admission::Lossy` — a targetless in-root directory create the action cannot
/// learn — takes the SAME per-buffer barrier a wire loss does: reseed, then forward
/// ONLY the `Overflow`, dropping the whole buffer (the clean modify ahead of it
/// included). This is the inversion's key property — a missing required field is a
/// loss decided AT the action, not by a decode matrix, yet it holds the identical
/// barrier.
#[test]
fn classified_lossy_event_takes_the_barrier_and_reseeds() {
  let mut map = seeded_with_sub();
  let dir_create_no_target = RawFanotifyEvent {
    mask: FanMask::new(FAN_CREATE | FAN_ONDIR),
    dir_fid: Some(fid(2)),
    target_fid: None,
    name: Some(b"newdir".to_vec()),
    rename: None,
  };
  // A clean decode: an admissible modify FIRST, then the classified-Lossy dir-create.
  let decoded = DecodeOutcome {
    events: vec![modify_under(fid(2), b"f"), dir_create_no_target],
    lossy: false,
  };
  let (sent, alive, reseeds) = run_process(&mut map, decoded, Some(one_entry_walk()));
  assert!(alive, "a reseeded classified loss keeps the stream live");
  assert_eq!(
    reseeds, 1,
    "the classified loss reseeded the map before signaling"
  );
  assert_eq!(
    sent,
    vec![Sent::Overflow],
    "the barrier: no Batch precedes the Overflow — the whole buffer is dropped"
  );
}

/// A CLEAN buffer whose events include a `ForeignDrop` (an out-of-root FID) forwards
/// only the admitted events as one Batch and NEVER reseeds — the firehose filter is a
/// silent drop, distinct from a loss.
#[test]
fn foreign_event_is_dropped_from_a_clean_batch() {
  let mut map = seeded_with_sub();
  let decoded = DecodeOutcome {
    events: vec![
      modify_under(fid(2), b"f"),
      modify_under(fid(99), b"elsewhere"),
    ],
    lossy: false,
  };
  let (sent, alive, reseeds) = run_process(&mut map, decoded, Some(one_entry_walk()));
  assert!(alive);
  assert_eq!(reseeds, 0, "a dropped foreign event is not a loss");
  assert_eq!(
    sent,
    vec![Sent::Batch(1)],
    "only the in-root event rides the Batch; the foreign one is dropped silently"
  );
}

/// A lossy buffer whose reseed walk fails every attempt escalates to the terminal
/// `Fatal` (blind → fatal) and forwards NEITHER a Batch nor an Overflow — a
/// stale-but-running source is the silent-loss shape the whole stack refuses.
#[test]
fn lossy_buffer_with_a_blinding_reseed_is_fatal_only() {
  let mut map = seeded_with_sub();
  let decoded = DecodeOutcome {
    events: vec![modify_under(fid(2), b"f")],
    lossy: true,
  };
  let (sent, alive, reseeds) = run_process(&mut map, decoded, None);
  assert!(!alive, "a blind reseed kills the stream");
  assert_eq!(reseeds, 2, "the reseed retried once, then conceded blind");
  assert_eq!(
    sent,
    vec![Sent::Fatal],
    "no Batch and no Overflow — the terminal Fatal is the only signal"
  );
}

/// The admission fence, at the two boundaries the walk fence cannot reach.
///
/// The walk keeps the excluded subtree out of the map, so events from INSIDE it
/// never resolve at all. But the excluded directory's own dirent lives under a
/// MAPPED parent, so an event naming it admits and would be reported — the caller
/// asked not to hear about that directory, and its own modification is exactly
/// that. Unrelated siblings must be untouched, or a stray exclusion would silence
/// the tree.
#[test]
fn an_event_on_the_excluded_directory_itself_is_suppressed() {
  let mut map = seeded_with_sub();
  let exclusions = vec![std::path::PathBuf::from("/root/sub")];
  let decoded = DecodeOutcome {
    events: vec![
      // Under /root: the excluded directory's own dirent, and an unrelated sibling.
      modify_under(fid(1), b"sub"),
      modify_under(fid(1), b"other"),
    ],
    lossy: false,
  };
  let forwarded = run_process_with_exclusions(&mut map, decoded, &exclusions);
  let paths: Vec<_> = forwarded.iter().filter_map(|e| e.path.clone()).collect();
  assert_eq!(
    paths,
    vec![std::path::PathBuf::from("/root/other")],
    "the excluded directory's own event is suppressed; its sibling is reported"
  );
}

/// A rename is suppressed exactly when NEITHER of its ends is REPORTED, and this asserts
/// it on what the reader actually FORWARDS — the last thing the source hands the driver
/// before a record is minted from it.
///
/// An end is reported when its parent directory resolves in-root AND no exclusion covers
/// the joined path. It fails to be reported two ways, and the distinction is the whole
/// cell: the path is excluded, or there IS no path because the parent resolves nothing
/// (off the root, or under an exclusion the walk fence never mapped). Testing "are both
/// ends excluded" conflates the second with "reportable" — a rename arriving from off the
/// root onto an excluded name then survives, and the lowering, seeing one end outside the
/// root and one inside it, emits a located rescan naming the excluded path. The rows with
/// an `Outside` end beside an `Excluded` one are that leak, in both directions.
///
/// The forwarded rows are the guard the fix must not break: an unresolvable end is not
/// evidence of an exclusion, so every crossing with ONE reported end still goes out.
/// Dropping those would make an arriving file simply never exist.
#[test]
fn a_rename_is_forwarded_exactly_when_one_of_its_ends_is_reported() {
  // fid 2 is mapped at the excluded `/root/sub`; fid 1 is the reported root; fid 9 is in
  // no map at all — the three endpoint states, one FID each.
  let exclusions = vec![std::path::PathBuf::from("/root/sub")];
  let rename = |old_dir: Fid, old: &[u8], new_dir: Fid, new: &[u8]| RawFanotifyEvent {
    mask: FanMask::new(FAN_RENAME),
    dir_fid: None,
    target_fid: None,
    name: None,
    rename: Some(RenameInfo {
      old_dir,
      old_name: old.to_vec(),
      new_dir,
      new_name: new.to_vec(),
    }),
  };

  let rows: [(&str, RawFanotifyEvent, bool); 7] = [
    (
      "excluded → excluded",
      rename(fid(2), b"a", fid(2), b"b"),
      false,
    ),
    (
      "outside → excluded",
      rename(fid(9), b"x", fid(1), b"sub"),
      false,
    ),
    (
      "excluded → outside",
      rename(fid(1), b"sub", fid(9), b"x"),
      false,
    ),
    (
      "excluded → reported",
      rename(fid(2), b"a", fid(1), b"a"),
      true,
    ),
    (
      "reported → excluded",
      rename(fid(1), b"a", fid(2), b"a"),
      true,
    ),
    (
      "outside → reported",
      rename(fid(9), b"x", fid(1), b"a"),
      true,
    ),
    (
      "reported → outside",
      rename(fid(1), b"a", fid(9), b"x"),
      true,
    ),
  ];

  for (label, event, forwarded) in rows {
    let mut map = seeded_with_sub();
    let out = run_process_with_exclusions(
      &mut map,
      DecodeOutcome {
        events: vec![event],
        lossy: false,
      },
      &exclusions,
    );
    assert_eq!(
      out.len(),
      usize::from(forwarded),
      "{label}: expected forwarded={forwarded}, got {out:?}"
    );
  }
}

/// The reported trace: an ordinary same-buffer move burst must not kill the
/// source.
///
/// Move a populated `X` into `/root/sub/X`, then straight on to somewhere else
/// before the reader consumes the buffer. The reader processes records IN ORDER, so
/// the walk owed by the FIRST record runs while the map still says `/root/sub/X` and
/// the disk no longer does — every attempt is `ENOENT`. That is the map lagging the
/// disk by one unread record, not blindness: the very next record would have
/// re-parented the node.
///
/// So the buffer takes the loss barrier — reseed, then `Overflow` alone — and the
/// stream stays LIVE. Killing it would strand every unrelated subscription on the
/// scope over churn any consumer produces, and would do it without even an ordered
/// loss signal for the co-batched delivery it discards.
#[test]
fn a_move_in_walk_that_cannot_find_its_subtree_is_loss_not_death() {
  let mut map = seeded_with_sub();
  // A would-forward event co-batched AHEAD of the move-in: the barrier drops it,
  // but the `Overflow` covers it — under the terminal it vanished uncovered.
  let decoded = DecodeOutcome {
    events: vec![modify_under(fid(2), b"f"), move_in_under_sub()],
    lossy: false,
  };
  let (sent, alive, reseeds, walks) =
    run_process_with_subtree(&mut map, decoded, Some(one_entry_walk()), None);

  assert!(
    alive,
    "an in-batch move burst is ordinary churn; the stream survives it"
  );
  assert!(walks >= 1, "the move-in walk was actually attempted");
  assert_eq!(
    reseeds, 1,
    "the failed subtree walk escalates to the FULL recovery, which repairs the map \
     wherever the burst left the directory"
  );
  assert_eq!(
    sent,
    vec![Sent::Overflow],
    "loss barrier: no Batch precedes the Overflow, and no Fatal is signaled"
  );
}

/// `Fatal` is reserved for the failure of the FULL recovery. Same burst, same
/// failing subtree walk — but now the reseed cannot rebuild the map either, so
/// there is nothing left to repair the source with and the terminal is honest.
///
/// This is the boundary the previous behavior collapsed: it spent the terminal on
/// the first failure, before the recovery that almost always succeeds had been
/// tried at all.
#[test]
fn a_move_in_burst_is_only_fatal_once_the_full_recovery_also_fails() {
  let mut map = seeded_with_sub();
  let decoded = DecodeOutcome {
    events: vec![modify_under(fid(2), b"f"), move_in_under_sub()],
    lossy: false,
  };
  let (sent, alive, reseeds, _) = run_process_with_subtree(&mut map, decoded, None, None);

  assert!(!alive, "a reseed that cannot rebuild the map is terminal");
  assert_eq!(
    reseeds, 2,
    "the reseed policy retried once before conceding"
  );
  assert_eq!(
    sent,
    vec![Sent::Fatal],
    "the terminal is signaled alone, and only after recovery failed"
  );
}

/// The kernel encodes a directory self-event as a `DFID_NAME` record whose name is
/// the self-name ".". Driven END TO END at the reader — a REAL "." buffer decoded and
/// pushed through `process_decoded` — a root `DELETE_SELF` reaches terminal
/// root-death: the reader forwards the root's OWN path (`/root`, which compile
/// lowers to the death lifecycle), NEVER the `<root>/.` child that treating the
/// "." as a literal name would produce (a located rescan of "root/."). At the
/// reader the FORWARDED PATH is the
/// verdict — `/root` is the root death, `/root/.` would be the child rescan — so the
/// buffer forwards one clean Batch on `/root` and never reseeds.
#[test]
fn dfid_name_dot_root_delete_reaches_root_death_at_the_reader() {
  const FSID: [u8; 8] = [7; 8];
  let root = wire_fid(FSID, 1, b"root-handle");
  let mut map = FidMap::new();
  map.seed([SeedEntry::root(root, Path::new("/root"))]);

  let buf = dfid_name_event(FAN_DELETE_SELF | FAN_ONDIR, FSID, 1, b"root-handle", b".");
  let decoded = decode_events(&buf);
  assert!(
    !decoded.lossy && decoded.events.len() == 1 && decoded.events[0].name.is_none(),
    "decode folded the '.' self-name to the name-less self shape"
  );

  let stats = BackendStatsShared::default();
  let transport = TransportState::new(8);
  let paths = std::cell::RefCell::new(Vec::new());
  let alive = process_decoded(
    decoded,
    &mut map,
    &stats,
    &transport,
    &[],
    || Ok(one_entry_walk()),
    |_, _, _| Ok(Vec::new()),
    |msg| {
      if let SourceMessage::Batch(payload) = msg {
        for ev in payload.events {
          if let crate::os::SourceEvent::Linux(crate::os::linux::RawLinuxEvent::Fanotify(a)) = ev {
            paths.borrow_mut().push(a.path);
          }
        }
      }
      true
    },
  );
  assert!(alive, "a root self-event is a clean forward, not a loss");
  assert_eq!(
    paths.into_inner(),
    vec![Some(std::path::PathBuf::from("/root"))],
    "the root DELETE_SELF '.' reaches terminal root-death on /root, never a located rescan of /root/."
  );
}

/// The exclusion fence measured where it actually bites: the SIZE OF THE ADMISSION
/// MAP.
///
/// Suppressing an excluded event at delivery is not enough, and the difference is not
/// cosmetic. Classification is what learns, re-parents, forgets, and hands the reader a
/// subtree to walk, so an exclusion tested AFTER it lets live creates and populated
/// move-ins under an excluded path grow the map for a subtree the caller asked not to
/// hear about. The map is capped, and an over-cap map is the terminal `Fatal` — so
/// sustained excluded churn could kill the source and drop coverage for every
/// subscription that had nothing to do with the exclusion. These rows therefore assert
/// the DIRECTORY COUNT (and, where it is the point, that no subtree walk ran at all), a
/// property a delivery-only fence cannot satisfy.
mod exclusion_fence {
  use super::*;
  use crate::os::linux::fanotify::fid::{FAN_ATTRIB, FAN_MOVE_SELF};

  /// Everything the fence is judged on for one buffer: what reached the queue, in
  /// order; the events actually forwarded; whether the stream survived; and how many
  /// move-in subtree walks ran.
  struct Fenced {
    forwarded: Vec<crate::os::linux::AdmittedEvent>,
    sent: Vec<Sent>,
    alive: bool,
    walks: u32,
  }

  /// Drives one buffer through `process_decoded` under `exclusions`. The subtree walk
  /// returns one descendant of whatever it was asked to walk, so a walk that DOES run
  /// is visible both in `walks` and as growth in the map — the two ways this suite
  /// catches a fence that acts too late.
  fn run(map: &mut FidMap, decoded: DecodeOutcome, exclusions: &[std::path::PathBuf]) -> Fenced {
    let stats = BackendStatsShared::default();
    let transport = TransportState::new(8);
    let forwarded = std::cell::RefCell::new(Vec::new());
    let sent = std::cell::RefCell::new(Vec::new());
    let walks = Cell::new(0u32);
    let alive = process_decoded(
      decoded,
      map,
      &stats,
      &transport,
      exclusions,
      || Ok(one_entry_walk()),
      |_, subtree_fid, _| {
        walks.set(walks.get() + 1);
        Ok(vec![SeedEntry::child(
          fid(6),
          subtree_fid.clone(),
          std::ffi::OsString::from("deep"),
        )])
      },
      |msg| {
        sent.borrow_mut().push(match &msg {
          SourceMessage::Batch(payload) => Sent::Batch(payload.events.len()),
          SourceMessage::Overflow(_) => Sent::Overflow,
          SourceMessage::Fatal(_) => Sent::Fatal,
        });
        if let SourceMessage::Batch(payload) = msg {
          for ev in payload.events {
            if let crate::os::SourceEvent::Linux(crate::os::linux::RawLinuxEvent::Fanotify(a)) = ev
            {
              forwarded.borrow_mut().push(a);
            }
          }
        }
        true
      },
    );
    Fenced {
      forwarded: forwarded.into_inner(),
      sent: sent.into_inner(),
      alive,
      walks: walks.get(),
    }
  }

  /// The exclusion set every row here uses: one directory directly under the root, so
  /// its PARENT is mapped and its own dirent therefore resolves — the boundary shape.
  fn cache_excluded() -> Vec<std::path::PathBuf> {
    vec![std::path::PathBuf::from("/root/cache")]
  }

  /// A map holding only the root anchor.
  fn root_only() -> FidMap {
    let mut map = FidMap::new();
    map.seed([SeedEntry::root(fid(1), Path::new("/root"))]);
    map
  }

  fn dir_create(parent: Fid, name: &[u8], child: Fid) -> RawFanotifyEvent {
    RawFanotifyEvent {
      mask: FanMask::new(FAN_CREATE | FAN_ONDIR),
      dir_fid: Some(parent),
      target_fid: Some(child),
      name: Some(name.to_vec()),
      rename: None,
    }
  }

  fn dir_rename(
    old_dir: Fid,
    old_name: &[u8],
    new_dir: Fid,
    new_name: &[u8],
    moved: Fid,
  ) -> RawFanotifyEvent {
    RawFanotifyEvent {
      mask: FanMask::new(FAN_RENAME | FAN_ONDIR),
      dir_fid: None,
      target_fid: Some(moved),
      name: None,
      rename: Some(RenameInfo {
        old_dir,
        old_name: old_name.to_vec(),
        new_dir,
        new_name: new_name.to_vec(),
      }),
    }
  }

  /// A LIVE `mkdir` of the excluded directory itself. Its parent is the root, which is
  /// mapped, so the create resolves and would be learned — putting the excluded
  /// directory INTO the admission map, from where every later create under it resolves
  /// and grows the map too. The fence must refuse it before the learn, leaving the map
  /// exactly as it was, while an unrelated sibling create in the same buffer is learned
  /// and reported.
  #[test]
  fn a_live_create_of_the_excluded_directory_never_enters_the_map() {
    let mut map = root_only();
    let before = map.dir_count();
    let decoded = DecodeOutcome {
      events: vec![
        dir_create(fid(1), b"cache", fid(10)),
        dir_create(fid(1), b"keep", fid(11)),
      ],
      lossy: false,
    };
    let out = run(&mut map, decoded, &cache_excluded());
    assert!(out.alive);
    assert_eq!(
      map.dir_count(),
      before + 1,
      "only the reported sibling was learned — the excluded directory never entered the map"
    );
    assert!(
      !map.contains(&fid(10)),
      "the excluded directory is absent, so nothing under it can ever resolve"
    );
    assert_eq!(
      out
        .forwarded
        .iter()
        .filter_map(|e| e.path.clone())
        .collect::<Vec<_>>(),
      vec![std::path::PathBuf::from("/root/keep")],
      "the excluded create is not reported; the sibling is"
    );
  }

  /// The severity, reproduced: sustained create traffic under an excluded path must not
  /// be able to consume the directory cap and kill the source.
  ///
  /// The map is capped at two directories and holds only the root. The buffer creates
  /// the excluded directory and then a run of children under it — the shape a build
  /// cache or a package manager produces continuously. Learning any of them would run
  /// the map past its cap, and an over-cap map is the terminal `Fatal`: the source dies
  /// and every subscription on the scope loses coverage, over activity in a subtree the
  /// caller explicitly excluded. With the fence ahead of the learn the map never moves,
  /// so the cap is untouchable from an excluded subtree no matter how long the churn
  /// runs.
  #[test]
  fn sustained_creates_under_an_excluded_subtree_cannot_consume_the_map_cap() {
    let mut map = FidMap::with_capacity(Some(2));
    map.seed([SeedEntry::root(fid(1), Path::new("/root"))]);
    let mut events = vec![dir_create(fid(1), b"cache", fid(10))];
    // Children of the excluded directory, addressed through it — the growth that
    // followed the leaked learn.
    events.extend((11..=40).map(|tag| dir_create(fid(10), b"d", fid(tag))));
    let decoded = DecodeOutcome {
      events,
      lossy: false,
    };
    let out = run(&mut map, decoded, &cache_excluded());
    assert!(
      out.alive,
      "excluded churn must never reach the cap, let alone the terminal it triggers"
    );
    assert!(
      !out.sent.contains(&Sent::Fatal),
      "no Fatal: the cap cannot be consumed by a subtree the caller excluded"
    );
    assert_eq!(
      map.dir_count(),
      1,
      "the map is exactly the root it started as — 31 excluded creates cost it nothing"
    );
  }

  /// A POPULATED directory moved in from outside the root, landing on the excluded
  /// path. Learning it would also owe a descendant walk, so a late fence pays twice:
  /// the map grows AND the reader walks a whole foreign subtree for a destination the
  /// caller asked not to hear about.
  ///
  /// Nothing about this move is reportable, in either end: the source lies off the
  /// watched root and the destination is excluded. It is NOT a boundary crossing — a
  /// crossing has a half the consumer can see, and this has none — so the pair is not
  /// forwarded either. Forwarding it lowered to a located rescan on the one end that was
  /// in-root, which is the EXCLUDED one, handing the consumer an obligation to
  /// re-enumerate the very path it asked never to hear about.
  #[test]
  fn a_populated_move_in_to_an_excluded_destination_is_refused_whole() {
    let mut map = root_only();
    let before = map.dir_count();
    let decoded = DecodeOutcome {
      events: vec![dir_rename(fid(9), b"X", fid(1), b"cache", fid(5))],
      lossy: false,
    };
    let out = run(&mut map, decoded, &cache_excluded());
    assert!(out.alive);
    assert_eq!(
      out.walks, 0,
      "no subtree walk ran: an excluded destination owes no descendants"
    );
    assert_eq!(
      map.dir_count(),
      before,
      "neither the moved directory nor any descendant entered the map"
    );
    assert!(!map.contains(&fid(5)), "the moved-in top was not learned");
    assert!(
      out.forwarded.is_empty(),
      "neither end is in the reported tree, so nothing may be forwarded: {:?}",
      out.forwarded
    );
  }

  /// The row above with ONE thing changed — the moved object is a directory the map
  /// already holds — and the outcome must change with it. Nothing this rename NAMES is
  /// reportable (its source parent is off the watched root, its destination is the
  /// excluded name), but what it MOVES is `/root/keep`, a live mapped subtree in the
  /// reported tree.
  ///
  /// Dropping it as excluded churn is what the endpoint-only fence did, and the damage is
  /// entirely in the map: the subtree is gone from the reported tree while the map still
  /// resolves it, so every later event under it is delivered at a path the object no
  /// longer occupies, and its nodes keep holding admission capacity forever — nothing
  /// re-walks a subtree nobody knows departed. This asserts the repair END TO END: the
  /// buffer takes the ordered barrier, the map is reseeded, and a follow-up event under
  /// the departed subtree is dropped as foreign instead of misdelivered.
  ///
  /// The delivery assertions alone would pass a fence that dropped it — the rename has no
  /// reportable half either way — so the discriminating assertions are the map's.
  #[test]
  fn a_fenced_rename_of_a_mapped_subtree_barriers_instead_of_stranding_it() {
    let mut map = FidMap::new();
    map.seed([
      SeedEntry::root(fid(1), Path::new("/root")),
      SeedEntry::child(fid(2), fid(1), std::ffi::OsString::from("keep")),
      SeedEntry::child(fid(3), fid(2), std::ffi::OsString::from("deep")),
    ]);
    let decoded = DecodeOutcome {
      events: vec![dir_rename(fid(9), b"keep", fid(1), b"cache", fid(2))],
      lossy: false,
    };
    let out = run(&mut map, decoded, &cache_excluded());
    assert!(out.alive, "a loss barrier is never a death");
    // The MAP first — it is the assertion that discriminates. A fence that dropped this
    // event leaves the departed subtree resolving at /root/keep and /root/keep/deep.
    assert_eq!(
      map.resolve_path(&fid(2)),
      None,
      "the departed subtree must stop resolving: the barrier's reseed replaced the stale \
       picture the drop would have kept"
    );
    assert_eq!(
      map.resolve_path(&fid(3)),
      None,
      "nor may anything beneath it resolve — a clean drop leaves this at /root/keep/deep"
    );
    assert_eq!(map.dir_count(), 1, "the reseed walk's map is what remains");
    // Then the delivery half: the barrier is ordered and covering.
    assert_eq!(
      out.sent,
      vec![Sent::Overflow],
      "the buffer takes the ordered barrier: a covering Overflow, and no Batch ahead of it"
    );
    assert!(
      out.forwarded.is_empty(),
      "nothing is forwarded — neither end of the pair is in the reported tree: {:?}",
      out.forwarded
    );
    assert_eq!(
      out.walks, 0,
      "and no descendant walk was owed for an excluded destination"
    );

    // The misdelivery the stranded nodes would have produced, driven directly: an event
    // under the departed subtree must now be refused as foreign, not reported at a path
    // the object left.
    let later = DecodeOutcome {
      events: vec![modify_under(fid(3), b"f")],
      lossy: false,
    };
    let after = run(&mut map, later, &cache_excluded());
    assert!(after.alive);
    assert!(
      after.forwarded.is_empty(),
      "a later event under the departed subtree resolves nothing — without the barrier it \
       arrives as /root/keep/deep/f, a path that no longer exists: {:?}",
      after.forwarded
    );
  }

  /// A MAPPED subtree renamed onto the excluded path. The moved directory is already
  /// known, so the map's own maintenance is a re-parent — which would park a live
  /// subtree, descendants and all, inside the exclusion, where every later create under
  /// it resolves through the re-parented node and grows the map again.
  ///
  /// The reported tree is the root MINUS the exclusions, so this move is a DEPARTURE
  /// from it and takes the move-out arm: forget the subtree, report the pair. The
  /// discriminator is the descendant — it must stop resolving entirely, not resolve to
  /// a path inside the exclusion.
  #[test]
  fn renaming_a_mapped_subtree_onto_an_excluded_path_forgets_it() {
    let mut map = FidMap::new();
    map.seed([
      SeedEntry::root(fid(1), Path::new("/root")),
      SeedEntry::child(fid(2), fid(1), std::ffi::OsString::from("keep")),
      SeedEntry::child(fid(3), fid(2), std::ffi::OsString::from("deep")),
    ]);
    let decoded = DecodeOutcome {
      events: vec![dir_rename(fid(1), b"keep", fid(1), b"cache", fid(2))],
      lossy: false,
    };
    let out = run(&mut map, decoded, &cache_excluded());
    assert!(out.alive);
    assert_eq!(
      map.dir_count(),
      1,
      "the departed subtree was pruned, not re-parented into the exclusion"
    );
    assert_eq!(
      map.resolve_path(&fid(3)),
      None,
      "the descendant no longer resolves at all — it must NOT sit at /root/cache/deep, \
       admitting and growing the map under an excluded path"
    );
    let rename = out
      .forwarded
      .first()
      .and_then(|e| e.rename.clone())
      .expect("a crossing rename is reported");
    assert_eq!(
      (rename.old_path, rename.new_path),
      (
        std::path::PathBuf::from("/root/keep"),
        std::path::PathBuf::from("/root/cache")
      ),
      "the pair names both ends: the caller sees the object leave the reported tree"
    );
    map.assert_adjacency();
  }

  /// The OTHER direction across the same boundary: an object moving OUT of the excluded
  /// subtree into the reported tree. It is arriving as far as the caller is concerned,
  /// so it must be reported AND mapped — its descendants walked in, exactly as any
  /// move-in from outside the root. Suppressing this half would make an arriving
  /// directory simply never exist, and skipping its walk would leave it silently blind.
  #[test]
  fn a_move_out_of_the_excluded_subtree_is_reported_and_walked_in() {
    let mut map = root_only();
    let decoded = DecodeOutcome {
      // The source parent is the excluded directory itself: the walk fence kept it out
      // of the map, so it does not resolve — the shape a real move out of an exclusion
      // arrives in.
      events: vec![dir_rename(fid(20), b"X", fid(1), b"X", fid(5))],
      lossy: false,
    };
    let out = run(&mut map, decoded, &cache_excluded());
    assert!(out.alive);
    assert_eq!(out.forwarded.len(), 1, "the arriving half is reported");
    assert_eq!(
      out.walks, 1,
      "its pre-existing descendants are walked in — an arrival owes completeness"
    );
    assert!(
      map.contains(&fid(5)) && map.contains(&fid(6)),
      "the moved directory and its walked descendant are now admitted"
    );
  }

  /// Renaming an exclusion's ANCESTOR moves the boundary across the subtree without any
  /// event ever naming the descendants it uncovers. With `/root/a/cache` excluded the
  /// walk fence never mapped it; renaming `/root/a` to `/root/b` makes `cache`
  /// reportable, and if the rename is a bare re-parent the directory simply stays absent
  /// — every event beneath it then drops as foreign, permanently, because nothing later
  /// re-walks it.
  ///
  /// The reader is where that is observable end to end: the classifier must hand it a
  /// subtree to walk, and the walk must land in the map. So this asserts BOTH the walk
  /// count and the resulting map contents — a delivery-only assertion sees nothing here,
  /// since the rename record itself is forwarded either way.
  #[test]
  fn renaming_an_exclusions_ancestor_walks_the_newly_visible_subtree_in() {
    let mut map = FidMap::new();
    map.seed([
      SeedEntry::root(fid(1), Path::new("/root")),
      SeedEntry::child(fid(2), fid(1), std::ffi::OsString::from("a")),
    ]);
    let under_a = vec![std::path::PathBuf::from("/root/a/cache")];
    let decoded = DecodeOutcome {
      events: vec![dir_rename(fid(1), b"a", fid(1), b"b", fid(2))],
      lossy: false,
    };
    let out = run(&mut map, decoded, &under_a);
    assert!(
      out.alive,
      "a re-walk is ordinary maintenance, never a death"
    );
    assert!(
      !out.sent.contains(&Sent::Overflow),
      "and never a loss barrier: the subtree is walked in, not reseeded around"
    );
    assert_eq!(
      out.walks, 1,
      "the moved subtree is walked under the destination's exclusion geometry"
    );
    assert_eq!(
      map.resolve_path(&fid(6)),
      Some(std::path::PathBuf::from("/root/b/deep")),
      "the walk's descendants are admitted at the new path — without this every event \
       under the newly-visible subtree drops as foreign forever"
    );
    assert_eq!(
      out.forwarded.len(),
      1,
      "the rename itself is still reported"
    );
    map.assert_adjacency();
  }

  /// The same boundary crossed the other way: the rename carries a MAPPED subtree UNDER
  /// an exclusion. `/root/b/cache` is excluded and `/root/a/cache` is mapped, so a bare
  /// re-parent would leave the map holding — and resolving paths through — directories
  /// the fence says are outside the reported tree, on capacity the exclusion exists to
  /// shed. The discriminator is the descendant's resolution, not the delivery.
  #[test]
  fn renaming_a_subtree_under_an_exclusion_drops_what_the_fence_now_covers() {
    let mut map = FidMap::new();
    map.seed([
      SeedEntry::root(fid(1), Path::new("/root")),
      SeedEntry::child(fid(2), fid(1), std::ffi::OsString::from("a")),
      SeedEntry::child(fid(3), fid(2), std::ffi::OsString::from("cache")),
      SeedEntry::child(fid(4), fid(3), std::ffi::OsString::from("deep")),
    ]);
    let under_b = vec![std::path::PathBuf::from("/root/b/cache")];
    let decoded = DecodeOutcome {
      events: vec![dir_rename(fid(1), b"a", fid(1), b"b", fid(2))],
      lossy: false,
    };
    let out = run(&mut map, decoded, &under_b);
    assert!(out.alive);
    assert_eq!(
      out.walks, 1,
      "the destination's geometry is rebuilt, not inherited"
    );
    assert_eq!(
      map.resolve_path(&fid(3)),
      None,
      "the newly-excluded directory must NOT resolve at /root/b/cache"
    );
    assert_eq!(map.resolve_path(&fid(4)), None, "nor anything beneath it");
    assert_eq!(
      map.resolve_path(&fid(2)),
      Some(std::path::PathBuf::from("/root/b")),
      "while the moved top itself is exactly where the rename put it"
    );
    map.assert_adjacency();
  }

  /// The cap guard beside the two crossings: the re-walk must not be a way for a rename
  /// to run a capped map over its ceiling. It cannot, and the shape is why — the stale
  /// subtree is discarded BEFORE the walk, so the walk's own budget is the room that
  /// frees plus whatever was already left, and it re-maps only what the fence reports.
  /// This drives it at the cap exactly: four directories in a four-directory map, one of
  /// them moving under an exclusion.
  ///
  /// A guard rather than a witness — a bare re-parent maps nothing and passes it too —
  /// kept because it is the invariant the fence was won on, and the arm added here is
  /// the only one that can grow the map on a rename of an ALREADY-KNOWN directory.
  #[test]
  fn a_geometry_rewalk_cannot_run_a_capped_map_over_its_ceiling() {
    let mut map = FidMap::with_capacity(Some(4));
    map.seed([
      SeedEntry::root(fid(1), Path::new("/root")),
      SeedEntry::child(fid(2), fid(1), std::ffi::OsString::from("a")),
      SeedEntry::child(fid(3), fid(2), std::ffi::OsString::from("cache")),
      SeedEntry::child(fid(4), fid(3), std::ffi::OsString::from("deep")),
    ]);
    let under_b = vec![std::path::PathBuf::from("/root/b/cache")];
    let decoded = DecodeOutcome {
      events: vec![dir_rename(fid(1), b"a", fid(1), b"b", fid(2))],
      lossy: false,
    };
    let out = run(&mut map, decoded, &under_b);
    assert!(out.alive, "the re-walk did not kill the source");
    assert!(
      !out.sent.contains(&Sent::Fatal),
      "no cap Fatal: the crossing frees more than the walk re-maps"
    );
    assert!(
      !map.over_capacity(),
      "and the map is still inside its ceiling"
    );
  }

  /// `RootDeath` is never suppressed, whatever the caller excluded — including an
  /// exclusion covering the watched root itself, which would otherwise silence the one
  /// record that says the watch is over. Driven for each shape the death can be
  /// reported in: the `DFID` self-event, the `FID`-only self-event, and the dirent from
  /// the root's own foreign parent.
  #[test]
  fn the_roots_own_death_is_reported_under_an_exclusion_covering_the_root() {
    let whole_root = vec![std::path::PathBuf::from("/root")];
    let shapes: [(&str, RawFanotifyEvent); 3] = [
      (
        "DFID self-event",
        RawFanotifyEvent {
          mask: FanMask::new(FAN_DELETE_SELF | FAN_ONDIR),
          dir_fid: Some(fid(1)),
          target_fid: None,
          name: None,
          rename: None,
        },
      ),
      (
        "FID-only self-event",
        RawFanotifyEvent {
          mask: FanMask::new(FAN_MOVE_SELF | FAN_ONDIR),
          dir_fid: None,
          target_fid: Some(fid(1)),
          name: None,
          rename: None,
        },
      ),
      (
        "dirent from the root's foreign parent",
        RawFanotifyEvent {
          mask: FanMask::new(FAN_DELETE | FAN_ONDIR),
          dir_fid: Some(fid(99)),
          target_fid: Some(fid(1)),
          name: Some(b"root".to_vec()),
          rename: None,
        },
      ),
    ];
    for (label, event) in shapes {
      let mut map = root_only();
      let out = run(
        &mut map,
        DecodeOutcome {
          events: vec![event],
          lossy: false,
        },
        &whole_root,
      );
      assert_eq!(
        out
          .forwarded
          .iter()
          .filter_map(|e| e.path.clone())
          .collect::<Vec<_>>(),
        vec![std::path::PathBuf::from("/root")],
        "{label}: the root's own death outranks every exclusion"
      );
    }
  }

  /// An ambiguous kernel-merged mask on the excluded directory must not barrier the
  /// buffer. The loss barrier exists because an ambiguous event can stale the map its
  /// buffer-mates resolve through — but the fence refuses this one before any shape
  /// acts, so it stales nothing and there is nothing for a reseed to repair. Charging
  /// the whole read buffer (and a scope-wide `Overflow`) for churn inside an exclusion
  /// would be the same harm as the cap: excluded activity damaging unrelated
  /// subscriptions.
  #[test]
  fn an_ambiguous_merge_on_the_excluded_directory_does_not_barrier_the_buffer() {
    let mut map = root_only();
    let merged = RawFanotifyEvent {
      mask: FanMask::new(FAN_CREATE | FAN_DELETE | FAN_ONDIR),
      dir_fid: Some(fid(1)),
      target_fid: Some(fid(10)),
      name: Some(b"cache".to_vec()),
      rename: None,
    };
    let decoded = DecodeOutcome {
      events: vec![modify_under(fid(1), b"f"), merged],
      lossy: false,
    };
    let out = run(&mut map, decoded, &cache_excluded());
    assert!(out.alive);
    assert_eq!(
      out.sent,
      vec![Sent::Batch(1)],
      "the co-batched delivery survives: no Overflow, no dropped buffer"
    );
    assert_eq!(
      map.dir_count(),
      1,
      "and the map is untouched — neither learned nor reseeded"
    );
  }

  /// The fence reads paths, so it must not fire on an event whose addressing FID does
  /// not resolve: an unmapped parent names no in-root path, and an event under it is
  /// the ordinary firehose drop rather than an exclusion decision. Pinned because the
  /// fence runs ahead of every membership gate — a fence that guessed here would
  /// suppress on a path it never actually resolved.
  #[test]
  fn an_unresolvable_addressing_fid_is_a_firehose_drop_not_an_exclusion() {
    let mut map = root_only();
    let decoded = DecodeOutcome {
      events: vec![
        modify_under(fid(77), b"elsewhere"),
        RawFanotifyEvent {
          mask: FanMask::new(FAN_ATTRIB),
          dir_fid: Some(fid(77)),
          target_fid: None,
          name: None,
          rename: None,
        },
        modify_under(fid(1), b"f"),
      ],
      lossy: false,
    };
    let out = run(&mut map, decoded, &cache_excluded());
    assert!(out.alive);
    assert_eq!(
      out.sent,
      vec![Sent::Batch(1)],
      "the foreign events drop silently and the in-root one is delivered"
    );
    assert_eq!(map.dir_count(), 1);
  }
}

/// Reader-teardown fairness: the drain loop observes a pending shutdown between
/// reads, so a source that stays readable can never wedge teardown. A real fd is
/// needed (`/dev/zero`), so this is Linux-only and off under miri; the mid-drain
/// arrival under a live producer is covered by the container smoke.
#[cfg(all(target_os = "linux", not(miri)))]
mod liveness {
  use std::{sync::mpsc, time::Duration};

  use super::super::{Control, DrainExit, ReaderShared, ReseedContext, drain_events};
  use crate::os::{BackendStatsShared, linux::fanotify::map::FidMap, transport::TransportState};

  /// An always-readable fd that never returns `EAGAIN`, standing in for a source
  /// under sustained traffic: `drain_events` reads it forever unless it observes a
  /// control message between reads.
  fn never_eagain_fd() -> std::os::fd::OwnedFd {
    std::fs::File::open("/dev/zero")
      .expect("/dev/zero opens on linux")
      .into()
  }

  fn reader_shared() -> (
    ReaderShared,
    async_channel::Receiver<crate::os::SourceMessage>,
  ) {
    let (tx, rx) = async_channel::unbounded();
    let shared = ReaderShared {
      queue: tx,
      transport: TransportState::new(8),
      buffer_bytes: 64 * 1024,
      stats: std::sync::Arc::new(BackendStatsShared::default()),
    };
    (shared, rx)
  }

  /// A pending `Shutdown` stops the drain at the TOP of the loop, before the next
  /// read/decode — so even against a never-`EAGAIN` fd the reader observes teardown
  /// immediately instead of draining forever. This pins the control check AHEAD of
  /// the read: a check placed after `process_decoded` would first read `/dev/zero`,
  /// decode it lossy, and drive a (failing) reseed, returning `Died` — never
  /// `Shutdown`. A watchdog bounds the assertion so a regressed check that spins
  /// forever fails as a timeout rather than hanging the suite.
  #[test]
  fn pending_shutdown_stops_the_drain_before_reading() {
    let fd = never_eagain_fd();
    let (tx, rx) = mpsc::channel();
    tx.send(Control::Shutdown).expect("enqueue shutdown");
    let (shared, _queue_rx) = reader_shared();
    let reseed = ReseedContext::for_test(std::path::PathBuf::from("/nonexistent"));
    let mut map = FidMap::new();
    let mut buf = vec![0u8; 64 * 1024];

    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
      let exit = drain_events(&fd, &mut buf, &mut map, &reseed, &rx, &shared);
      let _ = done_tx.send(exit);
    });
    let exit = done_rx
      .recv_timeout(Duration::from_secs(5))
      .expect("the drain must observe the pending shutdown, not spin on /dev/zero");
    assert_eq!(exit, DrainExit::Shutdown);
    worker.join().expect("worker joins");
  }
}
