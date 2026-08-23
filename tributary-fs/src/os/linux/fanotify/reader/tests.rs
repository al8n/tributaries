use std::{cell::Cell, io, path::Path};

use super::{
  ADMIT_QUOTA_PER_PASS, AdmitVerdict, AdmitWalk, BufferContext, Control, ControlExit, ControlPost,
  MAX_QUEUED_ADMITS, MAX_WALK_DECLINES, ReportContext, ReportCredit, ReseedGeneration,
  ReseedOutcome, SeedOutcome, StepExit, WalkSeed, admit_revealed, control_mailbox, process_decoded,
  reseed_map, reserve_report_credit, seed_moved_in_subtree, service_control, service_control_with,
};
use crate::os::{
  AdmitOutcome, AdmitRequest, AdmitTicket, BackendStatsShared, DeclinedBoundary, ScopeFrame,
  SourceMessage,
  linux::{
    fanotify::{
      fid::{
        DecodeOutcome, FAN_CREATE, FAN_DELETE, FAN_DELETE_SELF, FAN_EVENT_INFO_TYPE_DFID_NAME,
        FAN_MODIFY, FAN_MOVE_SELF, FAN_ONDIR, FAN_RENAME, FanMask, Fid, RawFanotifyEvent,
        RenameInfo, decode_events,
      },
      map::{FidMap, SeedEntry},
    },
    wake::WakeState,
  },
  transport::TransportState,
};

fn fid(tag: u8) -> Fid {
  Fid::new([tag; 8], Box::from(&[tag][..]))
}

/// The boundary-report slot [`process_decoded`] now takes RESERVED, exactly as
/// `drain_events` reserves it before the read — a buffer never leaves the kernel
/// without the credit to report its walk on. Every cell that drives a buffer claims
/// from the transport under test, so residency accounting reads the same as it does
/// in production.
fn report_credit(transport: &TransportState) -> crate::os::transport::BudgetPermit {
  crate::os::transport::BudgetPermit::acquire_boundaries(transport)
    .expect("the buffer's report slot is free")
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
  /// SEAM 2 on the wire: the boundaries a walk this buffer drove declined,
  /// captured whole so a cell can assert the exact triple that crossed — the
  /// point of the seam is that the core takes what the walk read, not a shape the
  /// core could have re-derived.
  ///
  /// The whole [`WalkBoundaries`], not just its declines, because WHICH walk
  /// produced them is now part of the message: a complete whole-root walk is a
  /// GENERATION the core retires device-only records against, and a partial one
  /// may only ever add. A cell that captured the declines alone could not tell
  /// the two apart.
  Boundaries(crate::os::WalkBoundaries),
  Overflow,
  /// An admission round trip's reply. No walk this suite's `process_decoded`
  /// cells drive answers one, so seeing it here at all would mean a buffer had
  /// started answering the core's parked covers.
  Admitted(crate::os::AdmitReport),
  /// ONE whole-root recovery on the wire: the reseed's complete generation, the
  /// cutoff it discharges and the loss it implies, indivisible. Captured whole
  /// because the point of the message is that the three cannot be separated —
  /// a cell that saw only "a report went out" could not tell this from the
  /// three-message shape it replaced.
  RootRecovered(crate::os::RootRecovery),
  Fatal,
}

/// Runs `process_decoded` over `decoded` against `map`, capturing what it forwards
/// (in order) and how many times each walk closure ran. The reseed walk returns
/// `reseed`; a `None` reseed models a walk that fails every attempt (→ blind).
/// The `bool` these buffer helpers report, out of the step's three-way exit. They
/// stage no teardown — their predicate is constant `false` — so `Abandoned` is
/// structurally unreachable here and asserted rather than folded into `alive`,
/// which would let a regression that abandons for the WRONG reason read as a
/// living stream.
fn alive_of(exit: StepExit) -> bool {
  match exit {
    StepExit::Done => true,
    StepExit::Died => false,
    StepExit::Abandoned => {
      unreachable!("no teardown is staged in this rig: the shutdown predicate is constant false")
    }
  }
}

fn run_process(
  map: &mut FidMap,
  decoded: DecodeOutcome,
  reseed: Option<WalkSeed>,
) -> (Vec<Sent>, bool, u32) {
  let stats = BackendStatsShared::default();
  let transport = TransportState::new(8);
  let sent = std::cell::RefCell::new(Vec::new());
  let reseeds = Cell::new(0u32);
  let exit = process_decoded(
    decoded,
    map,
    &BufferContext {
      report: ReportContext {
        stats: &stats,
        transport: &transport,
      },
      exclusions: &[],
      frame_epoch: HEARD_EPOCH,
    },
    report_credit(&transport),
    || {
      reseeds.set(reseeds.get() + 1);
      match &reseed {
        Some(seed) => Ok(seed.clone()),
        None => Err(io::Error::other("reseed walk fails")),
      }
    },
    |_, _, _, _| Ok(WalkSeed::default()),
    |msg| {
      sent.borrow_mut().push(match msg {
        SourceMessage::Batch(payload) => Sent::Batch(payload.events.len()),
        SourceMessage::Boundaries(boundaries, _) => Sent::Boundaries(boundaries),
        SourceMessage::Admitted(report) => Sent::Admitted(report),
        SourceMessage::RootRecovered(recovery, _) => Sent::RootRecovered(recovery),
        SourceMessage::Overflow(_) => Sent::Overflow,
        SourceMessage::Fatal(_) => Sent::Fatal,
      });
      true
    },
    &|| false,
  );
  (sent.into_inner(), alive_of(exit), reseeds.get())
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
  let exit = process_decoded(
    decoded,
    map,
    &BufferContext {
      report: ReportContext {
        stats: &stats,
        transport: &transport,
      },
      exclusions,
      frame_epoch: HEARD_EPOCH,
    },
    report_credit(&transport),
    || Ok(one_entry_walk()),
    |_, _, _, _| Ok(WalkSeed::default()),
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
    &|| false,
  );
  assert!(
    alive_of(exit),
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
  reseed: Option<WalkSeed>,
  subtree: Option<WalkSeed>,
) -> (Vec<Sent>, bool, u32, u32) {
  let stats = BackendStatsShared::default();
  let transport = TransportState::new(8);
  let sent = std::cell::RefCell::new(Vec::new());
  let reseeds = Cell::new(0u32);
  let walks = Cell::new(0u32);
  let exit = process_decoded(
    decoded,
    map,
    &BufferContext {
      report: ReportContext {
        stats: &stats,
        transport: &transport,
      },
      exclusions: &[],
      frame_epoch: HEARD_EPOCH,
    },
    report_credit(&transport),
    || {
      reseeds.set(reseeds.get() + 1);
      match &reseed {
        Some(seed) => Ok(seed.clone()),
        None => Err(io::Error::other("reseed walk fails")),
      }
    },
    |_, _, _, _| {
      walks.set(walks.get() + 1);
      match &subtree {
        Some(seed) => Ok(seed.clone()),
        None => Err(io::Error::from(io::ErrorKind::NotFound)),
      }
    },
    |msg| {
      sent.borrow_mut().push(match msg {
        SourceMessage::Batch(payload) => Sent::Batch(payload.events.len()),
        SourceMessage::Boundaries(boundaries, _) => Sent::Boundaries(boundaries),
        SourceMessage::Admitted(report) => Sent::Admitted(report),
        SourceMessage::RootRecovered(recovery, _) => Sent::RootRecovered(recovery),
        SourceMessage::Overflow(_) => Sent::Overflow,
        SourceMessage::Fatal(_) => Sent::Fatal,
      });
      true
    },
    &|| false,
  );
  (
    sent.into_inner(),
    alive_of(exit),
    reseeds.get(),
    walks.get(),
  )
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

/// The mount id every whole-root stub walk in this suite reports as the frame it
/// fenced against — the root's own, and the value the recovery reply must carry
/// out untouched.
const WALKED_ROOT_MNT_ID: Option<u64> = Some(42);

/// The core's frame epoch as the harness's source has been told it — the value a
/// buffer samples out of the control mailbox and stamps onto an autonomous
/// whole-root generation.
///
/// Deliberately NOT zero: zero is what a mailbox that was never published to
/// holds, so a stamp hardcoded to it would pass every assertion here.
const HEARD_EPOCH: u64 = 9;

/// The frame a stub walk that does NOT start at the root fences against: a
/// revealed location, or a moved-in subtree. Deliberately not the root's, so a
/// recovery that reported one of these instead would be visible.
const WALKED_SUBTREE_MNT_ID: Option<u64> = Some(51);

fn one_entry_walk() -> WalkSeed {
  WalkSeed {
    entries: vec![SeedEntry::root(fid(1), Path::new("/root"))],
    declined: Vec::new(),
    fence_mnt_id: WALKED_ROOT_MNT_ID,
  }
}

/// The same one-entry walk, plus the boundaries the descent declined on the way —
/// the only difference between a walk that fences nothing and one that fences a
/// submount. Both triples are here because the two decline sites answer different
/// amounts: the device belt runs BEFORE the mount id is read (`mnt_id: None`,
/// device-only and exempt), the mount fence runs after (`mnt_id: Some`, and
/// condemnable without waiting for a row).
fn walk_declining(declined: Vec<DeclinedBoundary>) -> WalkSeed {
  WalkSeed {
    entries: vec![SeedEntry::root(fid(1), Path::new("/root"))],
    declined,
    fence_mnt_id: WALKED_ROOT_MNT_ID,
  }
}

/// The mount fence's decline: a `mount --bind` of a same-superblock directory, so
/// the device belt cannot see it and only the differing mount id marks it.
fn bind_boundary(location: &str) -> DeclinedBoundary {
  DeclinedBoundary {
    location: std::path::PathBuf::from(location),
    dev: 1,
    mnt_id: Some(77),
  }
}

/// The device belt's decline: a btrfs subvolume, on a foreign device but on the
/// walk root's OWN mount, and with no mountinfo row EVER.
///
/// The id is read for every decline now, both fences alike — the belt no longer
/// skips the `statx` — so a subvolume is modelled by the ROOT's own mount id
/// rather than by an absent one. An absent id would model a host that answers no
/// mount ids at all, which is a different case entirely, and conflating the two
/// is what let a genuine mount be recorded permanently exempt.
fn subvolume_boundary(location: &str) -> DeclinedBoundary {
  DeclinedBoundary {
    location: std::path::PathBuf::from(location),
    dev: 9,
    mnt_id: Some(42),
  }
}

/// One PARTIAL boundary report: a moved-in subtree walk or an admission reseed,
/// which saw one subtree and proves nothing about the rest of the root.
fn partial(declined: Vec<DeclinedBoundary>) -> crate::os::WalkBoundaries {
  crate::os::WalkBoundaries {
    declined,
    reach: crate::os::WalkReach::Partial,
  }
}

/// One WHOLE-ROOT boundary report: a map reseed that ran to completion, and
/// therefore the COMPLETE boundary set under the root — the generation the core
/// retires its device-only records against.
fn whole_root(declined: Vec<DeclinedBoundary>) -> crate::os::WalkBoundaries {
  crate::os::WalkBoundaries {
    declined,
    reach: crate::os::WalkReach::WholeRoot {
      root_mnt_id: WALKED_ROOT_MNT_ID,
      epoch: HEARD_EPOCH,
    },
  }
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

/// Posts one control message and asserts the reader's end is still live — the
/// `tx.send(..).unwrap()` of the channel this mailbox replaced.
fn post(tx: &ControlPost, message: Control) {
  assert!(tx.send(message), "the reader's inbox is live");
}

/// The admission reseed's request: admit the ground revealed at `location`,
/// fenced against a scope frame whose device is 1 and whose mount is 42.
fn admit_request(location: &str) -> AdmitRequest {
  ticketed_admit(7, location)
}

/// The same request under a caller-chosen ticket, for the cells that queue a
/// BACKLOG and have to say which of them was answered.
fn ticketed_admit(ticket: u64, location: &str) -> AdmitRequest {
  epoched_admit(ticket, 0, location)
}

/// The same request again, under a caller-chosen frame EPOCH — the stamp a
/// recovery that COLLAPSES this request carries back to the core, so the cells
/// that fold a burst can say which of its epochs the one reply must report.
fn epoched_admit(ticket: u64, epoch: u64, location: &str) -> AdmitRequest {
  AdmitRequest {
    ticket: AdmitTicket::new(ticket),
    location: std::path::PathBuf::from(location),
    frame: ScopeFrame {
      root_dev: Some(1),
      root_mnt_id: Some(42),
    },
    epoch,
  }
}

/// One whole-root recovery request at `ticket`, issued in frame epoch `epoch`.
fn recovery_request(ticket: u64, epoch: u64) -> crate::os::RecoveryRequest {
  crate::os::RecoveryRequest {
    ticket: AdmitTicket::new(ticket),
    epoch,
  }
}

/// What a successful admission walk of `/root/sub`'s revealed ground answers: the
/// parent it hangs under (`/root`, fid 1 — already in the map), one directory
/// discovered inside it, and whatever the descent declined on the way.
fn revealed_under_root(declined: Vec<DeclinedBoundary>) -> AdmitWalk {
  AdmitWalk::Revealed {
    parent: fid(1),
    seed: WalkSeed {
      entries: vec![SeedEntry::child(
        fid(3),
        fid(1),
        std::ffi::OsString::from("vol"),
      )],
      declined,
      // The LOCATION's own frame, which is not the root's: a revealed subtree is
      // walked from the object that was uncovered there.
      fence_mnt_id: WALKED_SUBTREE_MNT_ID,
    },
  }
}

/// The ordinary admission: the revealed ground enters the map ADDITIVELY (the
/// live map is extended, never cleared — this is not a loss), and the descent's
/// own declines ride out with it so the core records where the revealed subtree
/// itself ends.
#[test]
fn an_admission_seeds_the_revealed_ground_and_carries_its_declines() {
  let mut map = seeded_with_sub();
  let before = map.dir_count();
  let mut declined = Vec::new();
  let verdict = admit_revealed(
    &mut map,
    &admit_request("/root/vol"),
    &mut declined,
    |_, _, _| Ok(revealed_under_root(vec![bind_boundary("/root/vol/inner")])),
    &|| false,
  );
  assert_eq!(verdict, AdmitVerdict::Admitted);
  assert_eq!(
    map.dir_count(),
    before + 1,
    "the revealed ground was ADDED, not reseeded over: the live map's \
     event-learned handles must survive an admission"
  );
  assert!(
    map.contains_dir(&fid(3)),
    "and the revealed directory now admits"
  );
  assert_eq!(
    declined,
    vec![bind_boundary("/root/vol/inner")],
    "a submount inside the revealed ground is a boundary the core must record: \
     nothing else on this profile will ever see it"
  );
}

/// The design's precondition, and the reason the walk reads a frame at all: a
/// location that is STILL COVERED — the refresh raced a live mount, or a remount
/// re-covered it since — is REFUSED, and refused ONCE.
///
/// Two things this pins beyond the verdict. The map is untouched: walking a
/// covered location would fence the descent on the BIND's frame and seed an
/// out-of-root alias subtree into the admission map, which is the exact breach
/// the walk's mount fence exists to prevent. And the walk runs a single time: a
/// refusal is a definite answer about a live boundary, so folding it into the
/// failure count would drive every raced mount down the loss ladder.
#[test]
fn a_still_covered_location_refuses_the_admission_without_walking() {
  let mut map = seeded_with_sub();
  let before = map.dir_count();
  let attempts = Cell::new(0u32);
  let mut declined = Vec::new();
  let verdict = admit_revealed(
    &mut map,
    &admit_request("/root/vol"),
    &mut declined,
    |_, _, _| {
      attempts.set(attempts.get() + 1);
      Ok(AdmitWalk::StillCovered {
        dev: Some(9),
        mnt_id: Some(42),
      })
    },
    &|| false,
  );
  assert_eq!(
    verdict,
    AdmitVerdict::StillCovered {
      dev: Some(9),
      mnt_id: Some(42),
    },
    "the identity the walk read travels with the refusal — the core cannot tell \
     a live mount from the boundary a departure uncovered without it"
  );
  assert_eq!(attempts.get(), 1, "a refusal is not retried");
  assert_eq!(map.dir_count(), before, "and nothing was admitted");
  assert!(declined.is_empty());
}

/// Nothing to admit: the mountpoint was removed after the unmount, or its name
/// now holds a symlink or a file, or the caller EXCLUDES it. The round trip still
/// answers — the core is holding a cover on it — and it answers success, because
/// there is no ground left for the map to be blind to.
#[test]
fn an_admission_with_nothing_to_walk_still_answers_admitted() {
  let mut map = seeded_with_sub();
  let before = map.dir_count();
  let mut declined = Vec::new();
  let verdict = admit_revealed(
    &mut map,
    &admit_request("/root/vol"),
    &mut declined,
    |_, _, _| Ok(AdmitWalk::Nothing),
    &|| false,
  );
  assert_eq!(verdict, AdmitVerdict::Admitted);
  assert_eq!(map.dir_count(), before);
}

/// Ground the map cannot REACH is owed nothing. The walk hands back the parent
/// the inventory would hang under; if the map cannot resolve that parent to a
/// path — it is excluded, orphaned, or outside the reported tree — then every
/// node seeded beneath it would resolve to `None` on its first admission and be
/// evicted as an orphan, having counted against the directory cap in the
/// meantime.
#[test]
fn an_admission_under_an_unreachable_parent_seeds_nothing() {
  let mut map = seeded_with_sub();
  let before = map.dir_count();
  let mut declined = Vec::new();
  let verdict = admit_revealed(
    &mut map,
    &admit_request("/root/vol"),
    &mut declined,
    |_, _, _| {
      Ok(AdmitWalk::Revealed {
        // fid 8 was never seeded: the map holds no such directory.
        parent: fid(8),
        seed: WalkSeed {
          entries: vec![SeedEntry::child(
            fid(3),
            fid(8),
            std::ffi::OsString::from("vol"),
          )],
          declined: vec![bind_boundary("/root/vol/inner")],
          fence_mnt_id: WALKED_SUBTREE_MNT_ID,
        },
      })
    },
    &|| false,
  );
  assert_eq!(verdict, AdmitVerdict::Admitted);
  assert_eq!(map.dir_count(), before, "no dead nodes entered the map");
  assert!(
    declined.is_empty(),
    "and nothing about ground the map cannot reach is recorded"
  );
}

/// The retry, mirroring the reseed's and the move-in walk's: a directory
/// momentarily unreadable mid-walk is absorbed rather than escalated.
#[test]
fn an_admission_retry_absorbs_a_transient_failure() {
  let mut map = seeded_with_sub();
  let attempts = Cell::new(0u32);
  let mut declined = Vec::new();
  let verdict = admit_revealed(
    &mut map,
    &admit_request("/root/vol"),
    &mut declined,
    |_, _, _| {
      attempts.set(attempts.get() + 1);
      if attempts.get() == 1 {
        return Err(io::Error::other("transient"));
      }
      Ok(revealed_under_root(Vec::new()))
    },
    &|| false,
  );
  assert_eq!(verdict, AdmitVerdict::Admitted);
  assert_eq!(attempts.get(), 2);
  assert!(map.contains_dir(&fid(3)));
}

/// Two failures concede blindness — the rung the caller answers with the LOSS
/// BARRIER, never with a half-admitted subtree and a cover already spent.
#[test]
fn an_admission_that_fails_twice_is_blind() {
  let mut map = seeded_with_sub();
  let before = map.dir_count();
  let attempts = Cell::new(0u32);
  let mut declined = Vec::new();
  let verdict = admit_revealed(
    &mut map,
    &admit_request("/root/vol"),
    &mut declined,
    |_, _, _| {
      attempts.set(attempts.get() + 1);
      Err(io::Error::other("unreadable"))
    },
    &|| false,
  );
  assert_eq!(verdict, AdmitVerdict::Blind);
  assert_eq!(attempts.get(), 2, "once, then one retry");
  assert_eq!(map.dir_count(), before, "a failed walk contributes nothing");
}

/// Runs ONE queued admission end to end — the [`service_control_with`] pass, not
/// [`run_admission`] alone — over a real map with stub walks, capturing what it
/// forwarded IN ORDER and whether the source survived. The same shape
/// [`run_process`] gives `process_decoded`. `admit` answers the scoped walk;
/// `reseed` answers the whole-root recovery the ladder's bottom rung escalates to
/// (`None` = a walk that fails every attempt, i.e. blind).
///
/// The pass and not the step, because the escalation is no longer the step's: a
/// request the located walk cannot answer folds into the mailbox's recovery slot,
/// and the ONE recovery that discharges it runs here. A helper that drove
/// `run_admission` alone could no longer see the ladder's bottom at all.
fn run_admit(
  map: &mut FidMap,
  admit: impl FnMut(&std::path::Path, ScopeFrame, Option<usize>) -> io::Result<AdmitWalk>,
  reseed: Option<WalkSeed>,
) -> (Vec<Sent>, bool) {
  let stats = BackendStatsShared::default();
  let transport = TransportState::new(8);
  let sent = std::cell::RefCell::new(Vec::new());
  let (tx, mut inbox) = control_mailbox();
  post(&tx, Control::Admit(admit_request("/root/vol")));
  let exit = service_control_with(
    &mut inbox,
    map,
    ReportContext {
      stats: &stats,
      transport: &transport,
    },
    admit,
    || match &reseed {
      Some(seed) => Ok(seed.clone()),
      None => Err(io::Error::other("reseed walk fails")),
    },
    |msg| {
      sent.borrow_mut().push(match msg {
        SourceMessage::Batch(payload) => Sent::Batch(payload.events.len()),
        SourceMessage::Boundaries(boundaries, _) => Sent::Boundaries(boundaries),
        SourceMessage::Admitted(report) => Sent::Admitted(report),
        SourceMessage::RootRecovered(recovery, _) => Sent::RootRecovered(recovery),
        SourceMessage::Overflow(_) => Sent::Overflow,
        SourceMessage::Fatal(_) => Sent::Fatal,
      });
      true
    },
    &|| false,
  );
  (sent.into_inner(), control_alive_of(exit))
}

/// [`alive_of`] for a whole control pass. `Shutdown` is asserted rather than
/// folded into a verdict for the same reason: no teardown is staged in this rig,
/// so a pass that answered one would be a regression reading as a living stream.
fn control_alive_of(exit: ControlExit) -> bool {
  match exit {
    ControlExit::Continue | ControlExit::Deferred | ControlExit::Blocked => true,
    ControlExit::Died => false,
    ControlExit::Shutdown => {
      unreachable!("no teardown is staged in this rig: the shutdown predicate is constant false")
    }
  }
}

/// The successful round trip's WIRE ORDER, which is the whole contract: the
/// walk's own declines first (a boundary inside the revealed ground is in the
/// coverage set before anything sends the consumer to re-read it), then the reply
/// that releases the parked cover — and nothing else at all. No batch, no loss.
#[test]
fn a_successful_admission_sends_its_declines_then_its_reply() {
  let mut map = seeded_with_sub();
  let (sent, alive) = run_admit(
    &mut map,
    |_, _, _| Ok(revealed_under_root(vec![bind_boundary("/root/vol/inner")])),
    Some(one_entry_walk()),
  );
  assert!(alive);
  assert_eq!(
    sent,
    vec![
      Sent::Boundaries(partial(vec![bind_boundary("/root/vol/inner")])),
      Sent::Admitted(crate::os::AdmitReport {
        ticket: AdmitTicket::new(7),
        outcome: AdmitOutcome::Admitted,
      }),
    ],
    "declines ahead of the reply, and no ordinary traffic in between"
  );
  assert!(
    map.contains_dir(&fid(3)),
    "and the ground really is admitted"
  );
}

/// **R14 F2.** A full boundary-report counter is not a dead consumer, and the
/// event path must WAIT on it rather than answer the terminal.
///
/// The counter's exhaustion used to be read as proof that the driver had stopped
/// consuming this source's queue. It proves that
/// [`MAX_BOUNDARY_REPORTS_IN_FLIGHT`] reports await ingestion at this instant —
/// a value re-read at a cadence — while [`drain_events`] reads to `EAGAIN` with
/// no pacing against that credit and can produce one report per buffer, and
/// permits come back only when the driver's task is next polled. Nine
/// boundary-bearing buffers while that task is merely descheduled therefore
/// killed a source with nothing wrong with it. Splitting the deferrable and
/// undeferrable counters (R13 F3) stopped one producer occupying the other's
/// headroom; it did not turn a backlog into evidence of death.
///
/// The wait is only honest because of WHERE it is taken: before the read, while
/// the events are still in the kernel's own queue. That is the answer to "this
/// producer cannot defer" — true of every point after the read, and false of the
/// one point before it.
///
/// Four legs, and the third is the one a wait cannot be correct without: credit
/// available is claimed without blocking at all; an exhausted counter blocks
/// instead of dying; the park is ARMED before the block, so a slot released in
/// that window cannot have its wake elided; and a release landing between the two
/// claims is taken on the spot rather than slept through.
///
/// MUTATION WITNESS (die instead of waiting): answer `ReportCredit::Closed` from
/// the exhausted-counter path and this FAILS at `an exhausted counter is a WAIT`
/// with a trailing `: Closed` — the R14 F2 defect exactly, one function further up
/// than it used to live.
/// MUTATION WITNESS (block without arming the park): delete the `wake.arm_park()`
/// ahead of the re-check and this FAILS at `the park is ARMED before the block` —
/// the release that ends the wait elides its wake against a reader that has not
/// announced it is blocking, and the wait becomes a hang.
/// MUTATION WITNESS (no re-check under the park): delete the second
/// `acquire_boundaries` and this FAILS at `a slot freed under the armed park is
/// taken on the spot` with a trailing `: Woken` — the same lost wakeup from the
/// other side.
#[test]
fn a_full_report_budget_makes_the_reader_wait_rather_than_die() {
  let transport = TransportState::with_report_budget(8, 1, None);
  let wake = WakeState::new().expect("an eventfd for the credit wait");
  let blocked = Cell::new(0usize);
  let parked_in_block = Cell::new(false);

  // Leg one: credit is free, so nothing blocks and nothing parks.
  let first = reserve_report_credit(&transport, &wake, &|| false, || {
    blocked.set(blocked.get() + 1);
    Ok(())
  });
  assert!(
    matches!(first, ReportCredit::Claimed(_)),
    "staging: a free slot is claimed outright"
  );
  assert_eq!(blocked.get(), 0, "staging: and nothing blocked for it");
  assert!(
    !wake.is_parked(),
    "staging: nor did anything announce a block that never happened"
  );

  // Leg two: the counter is now full — the driver holds the only report. This is
  // the ninth boundary-bearing buffer, and it must not be the source's last.
  let held = first;
  let waited = reserve_report_credit(&transport, &wake, &|| false, || {
    blocked.set(blocked.get() + 1);
    parked_in_block.set(wake.is_parked());
    Ok(())
  });
  assert!(
    matches!(waited, ReportCredit::Woken),
    "an exhausted counter is a WAIT, not a verdict about the consumer: the slots \
     come back on the driver's thread whenever its task is next polled, and \
     nothing here has observed that it will not be: {waited:?}"
  );
  assert_eq!(blocked.get(), 1, "and it really did block");
  assert!(
    parked_in_block.get(),
    "the park is ARMED before the block: `boundary_released` elides its wake \
     against a reader that has not announced it is blocking, so an unarmed wait \
     is a hang"
  );
  assert!(
    !wake.is_parked(),
    "and the park is cleared on the way out, on every exit this has"
  );

  // Leg three: a slot released in the window between the failed claim and the
  // block is taken on the spot. `receiver_closed` is called exactly there, which
  // is what makes it the hook for staging that release.
  let release = std::cell::RefCell::new(Some(held));
  let raced = reserve_report_credit(
    &transport,
    &wake,
    &|| {
      release.borrow_mut().take();
      false
    },
    || {
      blocked.set(blocked.get() + 1);
      Ok(())
    },
  );
  assert!(
    matches!(raced, ReportCredit::Claimed(_)),
    "a slot freed under the armed park is taken on the spot: the re-check is what \
     keeps a release that lands in that window from being slept through: {raced:?}"
  );
  assert_eq!(
    blocked.get(),
    1,
    "and it never blocked at all: {blocked:?} blocks in total"
  );
  assert_eq!(
    transport.boundaries_in_flight(),
    1,
    "the claim is the reserved slot itself — one buffer's worth, held until its \
     report is queued or the buffer produces none"
  );
}

/// The two things that END a credit wait instead of extending it, because a wait
/// with neither is a hang rather than back-pressure.
///
/// A CLOSED receiver is the liveness proof the terminal was always reaching for
/// and never had: with no consumer the permits behind the queued reports may
/// never be released at all, so waiting on them is not back-pressure, and no
/// report could be delivered if a slot did come back. That — not a full counter —
/// is what "the driver has stopped consuming this source's queue" actually looks
/// like, and it is now the only report condition that answers `Fatal`.
///
/// A SHUTDOWN is the reader-teardown contract: teardown outranks every long op
/// here, and a wait for credit is a long op like any other.
///
/// Both are checked BEFORE the block, which is the whole of it: checked after,
/// each is a wait nothing ends.
///
/// MUTATION WITNESS (wait for a consumer that is gone): delete the
/// `receiver_closed()` check and this FAILS at `a closed receiver is not waited
/// on` with a trailing `: Woken` — the reader blocking on an edge that can no
/// longer be produced.
/// MUTATION WITNESS (teardown queues behind the wait): delete the
/// `wake.shutdown_requested()` check and this FAILS at `a shutdown is not waited
/// out either` with a trailing `: Woken` — `SourceHandle::shutdown` JOINS this
/// thread, so a reader parked on credit no driver is left to return wedges the
/// teardown.
#[test]
fn a_closed_receiver_and_a_shutdown_both_end_the_credit_wait() {
  let transport = TransportState::with_report_budget(8, 1, None);
  let wake = WakeState::new().expect("an eventfd for the credit wait");
  let _held = crate::os::transport::BudgetPermit::acquire_boundaries(&transport)
    .expect("staging: the one slot is taken, so every claim below fails");
  let blocked = Cell::new(0usize);

  let gone = reserve_report_credit(&transport, &wake, &|| true, || {
    blocked.set(blocked.get() + 1);
    Ok(())
  });
  assert!(
    matches!(gone, ReportCredit::Closed),
    "a closed receiver is not waited on: it is the one condition that proves the \
     slots will never come back, which is what the terminal is for: {gone:?}"
  );
  assert_eq!(
    blocked.get(),
    0,
    "and the proof is taken BEFORE the block, or it is a wait nothing ends"
  );
  assert!(!wake.is_parked(), "with no park left armed behind it");

  wake.request_shutdown();
  let torn = reserve_report_credit(&transport, &wake, &|| false, || {
    blocked.set(blocked.get() + 1);
    Ok(())
  });
  assert!(
    matches!(torn, ReportCredit::Shutdown),
    "a shutdown is not waited out either: teardown JOINS this thread, so a reader \
     parked on credit would wedge it: {torn:?}"
  );
  assert_eq!(blocked.get(), 0, "and it, too, is checked before the block");
  assert!(!wake.is_parked(), "and clears the park it armed");
}

/// A buffer reports on the slot its READER reserved, and that is what makes a full
/// counter survivable at all: by the time the report exists the events are decoded
/// and the map is reseeded, so a claim that fails there has nowhere to go but the
/// terminal. The claim happens one step earlier, where the events are still in the
/// kernel.
///
/// Staged at the counter's floor with the whole allowance already spent by the
/// caller's own reservation, which is exactly the state the old code called a dead
/// consumer: the report goes out, nothing is fatal, and the residency is the one
/// slot that was reserved for it.
///
/// MUTATION WITNESS (claim at the report instead): give the report site back its
/// own `acquire_boundaries`-or-die while the reader's reservation stands, and this
/// FAILS at `an occupied counter is not a source failure` — the credit decided at
/// the one place a full counter cannot be waited on, which kills a healthy source
/// with its own reserved slot.
#[test]
fn a_buffer_reports_on_the_slot_its_reader_reserved() {
  let stats = BackendStatsShared::default();
  // ONE report slot, with a healthy BATCH budget beside it: the floor this cell
  // drives is the report budget's own, and the two are different numbers for
  // different concerns.
  let transport = TransportState::with_report_budget(8, 1, None);
  let mut map = seeded_with_sub();
  // The reader's reservation, taken before the read — and with it the counter is
  // FULL. Nothing else may claim, which is the whole staging.
  let reserved = report_credit(&transport);
  assert!(
    crate::os::transport::BudgetPermit::acquire_boundaries(&transport).is_none(),
    "staging: the counter is exhausted for anything that claims at the report"
  );

  // A LOSSY buffer: the reseed runs, its whole-root generation is the report, and
  // the `Overflow` rides behind it. This is the producer with nowhere to defer to.
  let held = std::cell::RefCell::new(Vec::new());
  let sent = std::cell::RefCell::new(Vec::new());
  let exit = process_decoded(
    DecodeOutcome {
      events: Vec::new(),
      lossy: true,
    },
    &mut map,
    &BufferContext {
      report: ReportContext {
        stats: &stats,
        transport: &transport,
      },
      exclusions: &[],
      frame_epoch: HEARD_EPOCH,
    },
    reserved,
    || Ok(one_entry_walk()),
    |_, _, _, _| Ok(WalkSeed::default()),
    |msg| {
      sent.borrow_mut().push(match msg {
        SourceMessage::Batch(payload) => Sent::Batch(payload.events.len()),
        SourceMessage::Boundaries(boundaries, permit) => {
          held.borrow_mut().push(permit);
          Sent::Boundaries(boundaries)
        }
        SourceMessage::Admitted(report) => Sent::Admitted(report),
        SourceMessage::RootRecovered(recovery, permit) => {
          held.borrow_mut().push(permit);
          Sent::RootRecovered(recovery)
        }
        SourceMessage::Overflow(_) => Sent::Overflow,
        SourceMessage::Fatal(_) => Sent::Fatal,
      });
      true
    },
    &|| false,
  );
  let sent = sent.into_inner();
  assert!(
    alive_of(exit),
    "an occupied counter is not a source failure"
  );
  assert!(
    matches!(sent.first(), Some(Sent::Boundaries(_))),
    "a buffer reports on the slot its reader reserved: the generation goes out \
     ahead of the loss it implies, on a counter with nothing left to claim: \
     {sent:?}"
  );
  assert!(
    !sent.iter().any(|s| matches!(s, Sent::Fatal)),
    "and nothing is terminal: a full counter is a driver that has not been polled \
     yet, which this producer has already paid for by waiting before the read: \
     {sent:?}"
  );
  assert_eq!(
    transport.boundaries_in_flight(),
    1,
    "the reserved slot became the report's slot — reserving and reporting are one \
     permit, never two"
  );
  assert_eq!(
    transport.in_flight(),
    0,
    "and it is NOT a batch slot: a boundary observation exerts no batch \
     back-pressure"
  );

  // Ingest releases it, and the bound is residency rather than a latch.
  held.borrow_mut().clear();
  assert_eq!(
    transport.boundaries_in_flight(),
    0,
    "dropping the permit returns the slot"
  );
}
/// A refusal answers [`AdmitOutcome::StillCovered`] and touches nothing else.
/// The core lapses to the replaced handling on it — cover, and put the record
/// back — so the reply is the whole of what this owes.
#[test]
fn a_refused_admission_answers_still_covered_and_nothing_else() {
  let mut map = seeded_with_sub();
  let before = map.dir_count();
  let (sent, alive) = run_admit(
    &mut map,
    |_, _, _| {
      Ok(AdmitWalk::StillCovered {
        dev: Some(9),
        mnt_id: Some(42),
      })
    },
    None,
  );
  assert!(alive, "a refusal is not a death: the map was never touched");
  assert_eq!(
    sent,
    vec![Sent::Admitted(crate::os::AdmitReport {
      ticket: AdmitTicket::new(7),
      // Carried through the ladder UNCHANGED: what the walk read off the fd it
      // pinned is what the core decides the put-back on.
      outcome: AdmitOutcome::StillCovered {
        dev: Some(9),
        mnt_id: Some(42),
      },
    })]
  );
  assert_eq!(map.dir_count(), before);
}

/// The LADDER, and the reason a half-admitted subtree with the cover already
/// spent is not an acceptable terminal: a scoped walk that fails twice falls back
/// to the whole-map reseed, which re-walks from the ROOT — where the revealed
/// ground now lives, since the mount is gone — and answers with the ONE
/// indivisible recovery message.
///
/// **The message is the assertion.** This rung used to send three — the
/// whole-root generation, the loss, and a `Covered` reply — and the three could
/// be separated. The reply told the core to discard the record its departure
/// verdict had taken; the generation was what re-recorded the mounts the reseed
/// found still there. Drop the generation (a boundary permit refused, which is a
/// live path) and those mounts are recorded NOWHERE: their next departure is
/// derived by nothing, their revealed ground is never admitted, and events on it
/// are rejected as outside the map with no signal. So the three facts now travel
/// as one `RootRecovery`, and a cell that could see them apart would be a cell
/// asserting the defect.
///
/// It also pins the STAMPS the reply carries out: the epoch the collapsed request
/// was issued at, echoed untouched, and the root mount id the reseed walk actually
/// fenced against. Neither is derivable at the other end, and the core installs
/// nothing from a recovery whose stamps are not its own.
///
/// MUTATION WITNESS: split the rung back into `forward_boundaries` +
/// `forward_batch(lossy)` + an `Admitted` reply and this FAILS at `one
/// indivisible message` with a three-element left against the one-element right.
/// MUTATION WITNESS (the frame goes missing): report `root_mnt_id: None` from
/// `run_root_recovery` instead of the walk's own `generation.root_mnt_id` and it
/// FAILS at the same site with `root_mnt_id: None` against `Some(42)` — a
/// recovery that cannot say which root it walked is one the core can only apply
/// on trust.
#[test]
fn an_admission_whose_walk_fails_recovers_the_root_in_one_message() {
  let mut map = seeded_with_sub();
  let (sent, alive) = run_admit(
    &mut map,
    |_, _, _| Err(io::Error::other("unreadable")),
    Some(walk_declining(vec![subvolume_boundary("/root/subvol")])),
  );
  assert!(
    alive,
    "the fallback recovered sight, so the source lives on"
  );
  assert_eq!(
    sent,
    vec![Sent::RootRecovered(crate::os::RootRecovery {
      declined: vec![subvolume_boundary("/root/subvol")],
      cutoff: AdmitTicket::new(7),
      epoch: 0,
      root_mnt_id: WALKED_ROOT_MNT_ID,
    })],
    "one indivisible message: the reseed's COMPLETE generation, the cutoff that \
     discharges this round trip, and the two stamps that say which world it was \
     walked in — never a generation that can go missing while the reply still \
     retires the record"
  );
  assert_eq!(
    map.dir_count(),
    1,
    "and the map was REBUILT from the root walk, not extended"
  );
}

/// **R10 F2, the disposition.** A request the walk refused as SUPERSEDED
/// ([`AdmitWalk::Stale`] — the live root no longer has the frame the core
/// captured when it parked the departure) is answered by the WHOLE-ROOT recovery,
/// never by a located reply.
///
/// Both halves of that matter, and each rules out a plausible cheaper answer:
///
/// - **not `Admitted`.** Nothing was walked and nothing entered the map, so
///   releasing the parked cover would send the consumer to re-read ground the
///   source is still blind to — the exact ordering admission-before-cover exists
///   to enforce.
/// - **not `StillCovered`.** That verdict makes the core put the condemned record
///   back and emit the located cover, on the strength of an identity no walk read.
///
/// The recovery is what converges: its reseed walks from the ROOT and reads its
/// fence off the fd it reopens, so it is on the CURRENT frame whatever the parked
/// request carried; its cutoff discharges this ticket and every earlier one, so a
/// burst superseded by the same root re-mount folds into one reseed rather than
/// one per request.
///
/// MUTATION WITNESS (disposed of as a reply): map `AdmitVerdict::Stale` to
/// `AdmitOutcome::Admitted` beside `StillCovered` in `run_admission` and this
/// FAILS at `the whole-root recovery, and only it` with `left:
/// [Admitted(AdmitReport { ticket: AdmitTicket(7), outcome: Admitted })]` — a
/// cover released over ground nothing admitted.
/// MUTATION WITNESS (retried instead of definite): fold `Stale` into the failure
/// count (`Ok(AdmitWalk::Stale) => {}` in `admit_revealed`'s match) and this FAILS
/// at `the refusal is DEFINITE and runs once` with `left: 2, right: 1` — two
/// opens and two `statx` pairs to re-read a frame that cannot have become current
/// again, before landing on the same rung anyway.
#[test]
fn a_superseded_admission_recovers_the_root_instead_of_replying() {
  let mut map = seeded_with_sub();
  let before = map.dir_count();
  let attempts = Cell::new(0u32);
  let (sent, alive) = run_admit(
    &mut map,
    |_, _, _| {
      attempts.set(attempts.get() + 1);
      Ok(AdmitWalk::Stale)
    },
    Some(walk_declining(vec![subvolume_boundary("/root/subvol")])),
  );
  assert_eq!(
    attempts.get(),
    1,
    "the refusal is DEFINITE and runs once: the captured frame cannot become \
     current again on a second attempt"
  );
  assert!(alive, "a superseded request is not a death");
  assert_eq!(
    sent,
    vec![Sent::RootRecovered(crate::os::RootRecovery {
      declined: vec![subvolume_boundary("/root/subvol")],
      cutoff: AdmitTicket::new(7),
      epoch: 0,
      root_mnt_id: WALKED_ROOT_MNT_ID,
    })],
    "the whole-root recovery, and only it — no located reply releases a cover \
     over ground this request never walked"
  );
  assert_ne!(
    map.dir_count(),
    before + 1,
    "and the superseded walk seeded NOTHING of its own: the map is whatever the \
     reseed rebuilt, never the refused request's ground"
  );
}

/// The bottom of the ladder. The scoped walk failed and so did the whole-map
/// reseed that is its only fallback, so the source is blind and the terminal is
/// the honest answer — a stale-but-running source is the silent-loss shape this
/// stack exists to prevent.
///
/// NO reply is sent, and nothing is stranded by that: the `Fatal` kills the
/// scope, and the parked cover dies with its state.
#[test]
fn an_admission_whose_recovery_also_fails_is_fatal_with_no_reply() {
  let mut map = seeded_with_sub();
  let (sent, alive) = run_admit(
    &mut map,
    |_, _, _| Err(io::Error::other("unreadable")),
    None,
  );
  assert!(!alive, "a blind recovery is the terminal");
  assert_eq!(
    sent,
    vec![Sent::Fatal],
    "the terminal is the only thing the consumer sees — no Overflow that would \
     promise a recovery that did not happen, and no reply"
  );
}

/// THE HAZARD. Every place this reader observes control used to read
/// `matches!(control.try_recv(), Ok(Control::Shutdown))` — an expression that
/// RECEIVES a message and then evaluates to `false` for anything that is not a
/// shutdown, i.e. consumes and discards it with no diagnostic anywhere. With one
/// variant that was harmless; with a second it silently swallows an admission and
/// leaves the core holding a parked cover for a reply that will never come.
///
/// The shared mailbox cannot have that shape: there is no receive at all, only
/// reads of an outstanding obligation that is cleared by DISCHARGING it. Both
/// directions are pinned here — an admission alone survives the observation, and
/// an admission that arrives BESIDE a shutdown is still held rather than eaten by
/// the shutdown check that overtakes it.
#[test]
fn a_control_message_that_is_not_a_shutdown_is_never_discarded() {
  let (tx, mut inbox) = control_mailbox();

  post(&tx, Control::Admit(admit_request("/root/a")));
  post(&tx, Control::Admit(admit_request("/root/b")));
  assert!(!inbox.shutting_down(), "no shutdown was sent");
  assert_eq!(
    inbox.next_admit().map(|r| r.location),
    Some(std::path::PathBuf::from("/root/a")),
    "the first admission survived the observation, in arrival order"
  );
  assert_eq!(
    inbox.next_admit().map(|r| r.location),
    Some(std::path::PathBuf::from("/root/b")),
    "and so did the second: a single peek-and-discard would have eaten both"
  );
  assert!(inbox.next_admit().is_none());

  // And beside a shutdown: the shutdown is observed, and the admission is still
  // HELD rather than consumed-and-thrown-away by the check that outranks it.
  post(&tx, Control::Admit(admit_request("/root/c")));
  post(&tx, Control::Shutdown);
  post(&tx, Control::Admit(admit_request("/root/d")));
  assert!(inbox.shutting_down(), "the shutdown was observed");
  assert_eq!(
    inbox.next_admit().map(|r| r.location),
    Some(std::path::PathBuf::from("/root/c"))
  );
  assert_eq!(
    inbox.next_admit().map(|r| r.location),
    Some(std::path::PathBuf::from("/root/d")),
    "a message BEHIND the shutdown is not lost to it either"
  );
}

/// The reader shell one `service_control` needs: a capturing queue, a live
/// transport, and the stats the walk timings land in.
struct ControlRig {
  shared: super::ReaderShared,
  rx: async_channel::Receiver<SourceMessage>,
  reseed: super::ReseedContext,
}

fn control_rig() -> ControlRig {
  let (queue, rx) = async_channel::bounded(8);
  ControlRig {
    shared: super::ReaderShared {
      queue,
      transport: TransportState::new(8),
      buffer_bytes: 4096,
      stats: std::sync::Arc::new(BackendStatsShared::default()),
    },
    rx,
    reseed: super::ReseedContext::for_test(std::path::PathBuf::from("/root")),
  }
}

/// The three observation sites are ONE body, and this drives it: a queued
/// admission is drained, RUN, and answered on the source's ordered queue — which
/// is what releases the core's parked cover.
///
/// The location names a path that does not exist, so the walk's very first step
/// (opening the location's parent, no-symlink) fails `ENOENT` — the benign
/// vanish, a mountpoint removed after its unmount — and the walk answers
/// "nothing to admit". That keeps the cell hermetic while still exercising the
/// whole path: drain → run the real walk → answer the ticket.
#[test]
fn service_control_runs_a_queued_admission_and_answers_its_ticket() {
  let rig = control_rig();
  let mut map = FidMap::new();
  let (tx, mut inbox) = control_mailbox();
  post(
    &tx,
    Control::Admit(admit_request("/tributaries-no-such-root/vol")),
  );

  let exit = service_control(&mut inbox, &mut map, &rig.reseed, &rig.shared, &|| false);
  assert_eq!(exit, ControlExit::Continue);
  match rig.rx.try_recv() {
    Ok(SourceMessage::Admitted(report)) => {
      assert_eq!(report.ticket, AdmitTicket::new(7), "the ticket echoes back");
      assert_eq!(report.outcome, AdmitOutcome::Admitted);
    }
    other => panic!("the admission answers on the source's queue: {other:?}"),
  }
  assert!(
    rig.rx.try_recv().is_err(),
    "and says nothing else: no batch, no loss, no boundary"
  );
}

/// Teardown outranks every long op here, and this is the reader half of "a scope
/// torn down with a parked cover outstanding": the shutdown wins, the queued
/// admission is abandoned unrun, and NO reply is sent.
///
/// Nothing is stranded by that. The scope whose cover was parked on the request
/// is ending — its coverage obligation ends with its own terminal record, and the
/// core drops the parked state with the scope.
#[test]
fn a_shutdown_supersedes_a_queued_admission_and_answers_nothing() {
  let rig = control_rig();
  let mut map = FidMap::new();
  let (tx, mut inbox) = control_mailbox();
  post(
    &tx,
    Control::Admit(admit_request("/tributaries-no-such-root/vol")),
  );
  post(&tx, Control::Shutdown);

  let exit = service_control(&mut inbox, &mut map, &rig.reseed, &rig.shared, &|| false);
  assert_eq!(exit, ControlExit::Shutdown);
  assert!(
    rig.rx.try_recv().is_err(),
    "an abandoned round trip is answered by nothing at all"
  );
}

/// Everything a capturing `service_control_with` pass needs that is not the
/// inbox or the map: the stats the walk timings land in, the transport the
/// barrier and the budgets are read off, and the messages the pass produced.
struct PassRig {
  stats: BackendStatsShared,
  transport: TransportState,
}

fn pass_rig() -> PassRig {
  PassRig {
    stats: BackendStatsShared::default(),
    transport: TransportState::new(256),
  }
}

/// The tickets a captured run of messages answered, in order.
fn answered(sent: &[SourceMessage]) -> Vec<(AdmitTicket, AdmitOutcome)> {
  sent
    .iter()
    .filter_map(|msg| match msg {
      SourceMessage::Admitted(report) => Some((report.ticket, report.outcome)),
      _ => None,
    })
    .collect()
}

/// **R5 F3**, the teardown half: a shutdown that lands WHILE a backlog is being
/// serviced preempts the remainder instead of queueing behind every walk in it.
///
/// `service_control` used to drain the channel, check shutdown ONCE, and then run
/// the whole snapshot. One mount refresh can condemn every mount under the root,
/// and each admission drives up to two revealed walks plus two whole-root reseeds
/// on failure — so `SourceHandle::shutdown`, which JOINS this thread, waited out
/// admission-count x walk-size before it could return.
///
/// The shutdown is enqueued from inside the first walk, which is what the reader
/// really races: the check that catches it is the fresh drain BETWEEN admissions,
/// and only the walk already in flight is waited on (a half-built map is the one
/// thing worse than a slow teardown).
#[test]
fn a_shutdown_landing_between_admissions_preempts_the_rest_of_the_backlog() {
  let rig = pass_rig();
  let mut map = FidMap::new();
  let (tx, mut inbox) = control_mailbox();
  for ticket in 1..=3u64 {
    post(&tx, Control::Admit(ticketed_admit(ticket, "/root/vol")));
  }

  let walks = Cell::new(0u32);
  let mut sent: Vec<SourceMessage> = Vec::new();
  let exit = service_control_with(
    &mut inbox,
    &mut map,
    ReportContext {
      stats: &rig.stats,
      transport: &rig.transport,
    },
    |_, _, _| {
      walks.set(walks.get() + 1);
      // Teardown lands while this first walk is running.
      if walks.get() == 1 {
        post(&tx, Control::Shutdown);
      }
      Ok(AdmitWalk::Nothing)
    },
    || Ok(one_entry_walk()),
    |msg| {
      sent.push(msg);
      true
    },
    &|| false,
  );

  assert_eq!(exit, ControlExit::Shutdown, "teardown outranks the backlog");
  assert_eq!(
    walks.get(),
    1,
    "only the admission already in flight ran: the other two were preempted, \
     not deferred behind them"
  );
  assert_eq!(
    answered(&sent),
    vec![(AdmitTicket::new(1), AdmitOutcome::Admitted)],
    "the one that ran is answered; the abandoned two are answered by nothing at \
     all, which is the teardown-priority rule: {sent:?}"
  );
}

/// **R5 F3**, the reader-fairness half: one pass runs a BOUNDED quota and hands
/// the rest back, so the event drain is never held off for the length of a whole
/// backlog.
///
/// Teardown is not the only thing an unbounded pass defers. This reader spends
/// nearly all its life blocked in `poll`, and while a pass runs it reads no
/// events at all — a kernel queue that fills meanwhile is a `FAN_Q_OVERFLOW`, a
/// real loss, not mere latency. `Deferred` is what tells the caller about to
/// BLOCK to keep a wake pending; the caller about to read treats it as `Continue`.
#[test]
fn one_pass_runs_a_bounded_quota_and_defers_the_rest() {
  let rig = pass_rig();
  let mut map = FidMap::new();
  let (tx, mut inbox) = control_mailbox();
  let queued = ADMIT_QUOTA_PER_PASS as u64 + 1;
  for ticket in 1..=queued {
    post(&tx, Control::Admit(ticketed_admit(ticket, "/root/vol")));
  }

  let mut sent: Vec<SourceMessage> = Vec::new();
  let exit = service_control_with(
    &mut inbox,
    &mut map,
    ReportContext {
      stats: &rig.stats,
      transport: &rig.transport,
    },
    |_, _, _| Ok(AdmitWalk::Nothing),
    || Ok(one_entry_walk()),
    |msg| {
      sent.push(msg);
      true
    },
    &|| false,
  );
  assert_eq!(
    answered(&sent).len(),
    ADMIT_QUOTA_PER_PASS,
    "exactly the quota ran — servicing every queued admission is the shape that \
     starves the event drain: {sent:?}"
  );
  assert_eq!(
    exit,
    ControlExit::Deferred,
    "and the pass SAYS it stopped on its quota with work still queued: the \
     caller about to block on `poll` keeps a wake pending on this answer alone"
  );

  // The rest is not lost: the very next pass takes it, and says so.
  sent.clear();
  let exit = service_control_with(
    &mut inbox,
    &mut map,
    ReportContext {
      stats: &rig.stats,
      transport: &rig.transport,
    },
    |_, _, _| Ok(AdmitWalk::Nothing),
    || Ok(one_entry_walk()),
    |msg| {
      sent.push(msg);
      true
    },
    &|| false,
  );
  assert_eq!(
    exit,
    ControlExit::Continue,
    "and the inbox is empty afterwards, so nothing is left pending"
  );
  assert_eq!(
    answered(&sent),
    vec![(AdmitTicket::new(queued), AdmitOutcome::Admitted)],
    "the deferred admission ran on the next pass, in arrival order: {sent:?}"
  );
}

/// **R7 F3**, the burst half: ONE queued burst of recoveries costs ONE reseed,
/// however large the burst is.
///
/// The control traffic used to ride an unbounded channel drained a bounded number
/// of messages per pass, and the pass then executed and CLEARED the accumulated
/// recovery cutoff while the rest of the burst was still unreceived — so an
/// N-message burst already sitting in the channel paid `ceil(N / budget)`
/// whole-tree reseeds for what the cutoff rule says is ONE obligation. The
/// coalescing now happens where a message is POSTED, so there is no slice of the
/// burst for a pass to execute against.
///
/// A FIXED count, deliberately not one derived from any constant: a count that
/// scaled with the bound under test would report the same verdict for every value
/// of it.
///
/// MUTATION WITNESS (coalescing): fold first-wins
/// (`self.recovery = self.recovery.or(Some(ticket))`) and this FAILS at `the
/// cutoff names the HIGHEST ticket of the whole burst` with `left:
/// AdmitTicket(1), right: AdmitTicket(300)` — the core left holding 299 covers no
/// reply will ever release.
/// MUTATION WITNESS (discharge): leave the slot set in `take_recovery`
/// (read it instead of taking it) and it FAILS at `the burst is DISCHARGED by the
/// one recovery` with `left: Deferred, right: Continue`, and the second pass then
/// reseeds again — the repeated full-root recovery for one obligation, which is
/// the finding's own shape.
#[test]
fn one_queued_burst_of_recoveries_costs_exactly_one_reseed() {
  let rig = pass_rig();
  let mut map = FidMap::new();
  let (tx, mut inbox) = control_mailbox();
  // Recoveries rather than admissions: each is one word in the mailbox, so what
  // this cell reads is the COALESCING and not the backlog cap.
  const QUEUED: u64 = 300;
  const {
    assert!(
      QUEUED > MAX_QUEUED_ADMITS as u64,
      "the burst must be larger than any per-pass retention this reader has, or \
       the cell asserts nothing"
    );
  }
  for ticket in 1..=QUEUED {
    post(&tx, Control::Recover(recovery_request(ticket, 0)));
  }
  assert_eq!(
    tx.outstanding(),
    (0, true),
    "staging: the whole burst is ONE outstanding obligation, not a queue of them"
  );

  let reseeds = Cell::new(0u32);
  let mut sent: Vec<SourceMessage> = Vec::new();
  let exit = service_control_with(
    &mut inbox,
    &mut map,
    ReportContext {
      stats: &rig.stats,
      transport: &rig.transport,
    },
    |_, _, _| panic!("no located walk is owed"),
    || {
      reseeds.set(reseeds.get() + 1);
      Ok(one_entry_walk())
    },
    |msg| {
      sent.push(msg);
      true
    },
    &|| false,
  );
  assert_eq!(
    reseeds.get(),
    1,
    "ONE whole-tree reseed for the whole burst: {sent:?}"
  );
  assert_eq!(
    exit,
    ControlExit::Continue,
    "the burst is DISCHARGED by the one recovery, so the pass leaves nothing \
     pending and the reader goes back to reading events: {sent:?}"
  );
  assert_eq!(sent.len(), 1, "and ONE message answers it: {sent:?}");
  let SourceMessage::RootRecovered(recovery, _) = &sent[0] else {
    panic!("the burst is answered by the indivisible recovery: {sent:?}");
  };
  assert_eq!(
    recovery.cutoff,
    AdmitTicket::new(QUEUED),
    "the cutoff names the HIGHEST ticket of the whole burst, so every cover the \
     core parked below it is discharged"
  );

  // Nothing is left resident: a second pass has no work at all.
  let exit = service_control_with(
    &mut inbox,
    &mut map,
    ReportContext {
      stats: &rig.stats,
      transport: &rig.transport,
    },
    |_, _, _| panic!("nothing is left to walk"),
    || panic!("nothing is left to reseed"),
    |_| panic!("nothing is left to send"),
    &|| false,
  );
  assert_eq!(exit, ControlExit::Continue);
}

/// **R12 F2.** A BURST of admissions the located walk cannot answer costs ONE
/// whole-root reseed and ONE report — not one of each per request.
///
/// The core permits 64 outstanding admissions before it collapses them, and a
/// single root re-mount supersedes every one of that burst at once: each is
/// refused by the executor as [`AdmitWalk::Stale`], and each used to reseed the
/// entire root inline and report a cutoff naming only ITSELF, while the rest of
/// the burst sat queued behind it. That is 64 complete root walks — the largest
/// op this reader has, run back to back with no event read in between, which is
/// how a `FAN_Q_OVERFLOW` gets manufactured out of a recovery.
///
/// **And the second report is a source death, not merely a cost.** The boundary
/// budget is an independent, small counter, and a recovery may not be dropped when
/// it cannot claim a permit — the producer signals the terminal `Fatal` instead.
/// So the rig runs at a budget of ONE: with the routing in place exactly one
/// report is produced and the source lives; without it the second walk's report is
/// refused a permit and kills a stream that had nothing wrong with it.
///
/// The burst size is a FIXED literal and deliberately smaller than
/// [`MAX_QUEUED_ADMITS`], so every request is resident as a BODY and what this
/// reads is the reader's own escalation folding — never the mailbox's backlog cap,
/// which is a different mechanism with its own cell.
///
/// The last request carries a LATER frame epoch, which is what a burst spanning
/// the frame change actually looks like, and pins the pairing: the reply's cutoff
/// and its epoch must come from the SAME request — the newest — or the core
/// judges a current-frame recovery against a stamp from the world before it.
///
/// MUTATION WITNESS (routing): put the reseed back inline in the `Blind | Stale`
/// arm (`reseed_after_loss` + `forward_root_recovery` cut off at
/// `request.ticket`) and this FAILS at `ONE whole-root reseed answers the whole
/// burst` with `left: 2, right: 1` — the pass stops at two only because the
/// second report cannot claim a permit and kills the source, which the surviving
/// legs then also catch.
/// MUTATION WITNESS (discharge): drop the cutoff-raising in `take_recovery` (drain
/// the queued bodies but never fold their tickets:
/// `for _ in mailbox.admits.drain(..) {}`) and it FAILS at `the cutoff names the
/// HIGHEST ticket in the burst` with `left: AdmitTicket(1), right:
/// AdmitTicket(41)` — the core left holding forty covers no reply will ever
/// release, which is the very leak the one-message recovery exists to close.
#[test]
fn a_burst_of_superseded_admissions_costs_one_reseed_and_one_report() {
  let stats = BackendStatsShared::default();
  // ONE boundary-report slot, with a healthy BATCH budget beside it: a second
  // report in the same pass cannot be sent at all.
  let transport = TransportState::with_report_budget(8, 1, None);
  let mut map = FidMap::new();
  let (tx, mut inbox) = control_mailbox();

  const BURST: u64 = 40;
  const LATE_EPOCH: u64 = 7;
  const {
    // `BURST` requests plus the one from the later epoch, all resident as bodies.
    assert!(
      (BURST as usize) < MAX_QUEUED_ADMITS,
      "the burst must fit the mailbox as BODIES, or this cell reads the backlog \
       cap's fold instead of the ladder's"
    );
    assert!(
      BURST as usize > ADMIT_QUOTA_PER_PASS,
      "and it must exceed one pass's admission quota, or a single pass could \
       answer it request-by-request and still look bounded"
    );
  }
  for ticket in 1..=BURST {
    post(&tx, Control::Admit(epoched_admit(ticket, 0, "/root/vol")));
  }
  // The one posted AFTER the frame moved: same burst, newer world.
  post(
    &tx,
    Control::Admit(epoched_admit(BURST + 1, LATE_EPOCH, "/root/vol")),
  );

  let walks = Cell::new(0u32);
  let mut sent: Vec<SourceMessage> = Vec::new();
  let exit = service_control_with(
    &mut inbox,
    &mut map,
    ReportContext {
      stats: &stats,
      transport: &transport,
    },
    // One root re-mount supersedes the whole burst; the executor refuses each.
    |_, _, _| Ok(AdmitWalk::Stale),
    || {
      walks.set(walks.get() + 1);
      Ok(one_entry_walk())
    },
    |msg| {
      sent.push(msg);
      true
    },
    &|| false,
  );

  assert_eq!(
    walks.get(),
    1,
    "ONE whole-root reseed answers the whole burst: {sent:?}"
  );
  assert_eq!(
    sent.len(),
    1,
    "and ONE message reports it — a report per superseded request is what the \
     budget of one below cannot even carry: {sent:?}"
  );
  let SourceMessage::RootRecovered(recovery, _) = &sent[0] else {
    panic!("the burst is answered by the indivisible recovery: {sent:?}");
  };
  assert_eq!(
    recovery.cutoff,
    AdmitTicket::new(BURST + 1),
    "the cutoff names the HIGHEST ticket in the burst, so every cover the core \
     parked below it is discharged by this one reply"
  );
  assert_eq!(
    recovery.epoch, LATE_EPOCH,
    "and the epoch is that same request's — cutoff and stamp come from ONE \
     obligation, or the core judges this walk against a world it was not asked in"
  );
  assert_eq!(
    recovery.root_mnt_id, WALKED_ROOT_MNT_ID,
    "beside the root frame the reseed actually fenced against"
  );
  assert_eq!(
    exit,
    ControlExit::Continue,
    "every ticket is discharged: nothing is left queued, so the reader goes \
     straight back to reading events: {sent:?}"
  );
  assert!(
    !inbox.has_work(),
    "and the mailbox really is empty — no follow-up is owed for requests that \
     were all posted BEFORE the walk"
  );
  assert_eq!(
    transport.boundaries_in_flight(),
    1,
    "one permit, held by the one report: a second would have had none to claim, \
     and a recovery that cannot claim one kills the source"
  );
}

/// **R7 F3**, the sustained half: recoveries that keep ARRIVING while a slow
/// reseed runs stay bounded — one walk in flight plus one follow-up, never one
/// walk per arrival and never a growing queue.
///
/// This is the half the unbounded channel could not give. A scope that fails
/// closed asks for a recovery on every authoritative refresh, so while a
/// million-directory reseed ran the queue grew without bound and each pass turned
/// another budget's worth of it into another whole-tree walk — the reader could
/// stop reading events indefinitely while the kernel queue filled behind it.
///
/// The verdict is CONSTANT-INDEPENDENT: the walk count is linear in the number of
/// WALKS that had arrivals during them, never in the number of messages. Three
/// producing walks and fifty arrivals each answer `4`, not `151`.
///
/// The admission bodies posted alongside pin the memory bound with a FIXED
/// literal rather than the cap itself, so raising the cap cannot make the cell
/// pass vacuously.
///
/// MUTATION WITNESS (bounded walks): leave the slot set in
/// `take_recovery` and this FAILS at `the recoveries CONVERGE` — the run
/// never stops reseeding, which is the starvation the coalescing exists to
/// prevent.
/// MUTATION WITNESS (bounded memory): drop the `self.admits.len() <
/// MAX_QUEUED_ADMITS` guard in `Mailbox::post` and it FAILS at `the mailbox never
/// holds more admission bodies than its cap` with `left: 400, right: 128` — the
/// unbounded retention the cap exists to prevent.
#[test]
fn sustained_arrivals_during_an_in_flight_reseed_stay_bounded() {
  let rig = pass_rig();
  let mut map = FidMap::new();
  let (tx, mut inbox) = control_mailbox();

  // Fixed literals, none of them derived from a constant under test.
  const PRODUCING_WALKS: u32 = 3;
  const ARRIVALS_PER_WALK: u64 = 50;
  const ADMITS_PER_WALK: u64 = 400;
  const RESIDENT_CEILING: usize = 128;
  const {
    assert!(
      MAX_QUEUED_ADMITS <= RESIDENT_CEILING && (ADMITS_PER_WALK as usize) > RESIDENT_CEILING,
      "the ceiling must sit above the cap and below the burst, or the residency \
       assertion is vacuous"
    );
  }

  post(&tx, Control::Recover(recovery_request(1, 0)));
  let reseeds = Cell::new(0u32);
  let next_ticket = Cell::new(1u64);
  let peak_resident = Cell::new(0usize);
  let peak_recoveries = Cell::new(0usize);

  let mut passes = 0u32;
  loop {
    passes += 1;
    assert!(
      passes <= PRODUCING_WALKS + 4,
      "the recoveries CONVERGE: a bounded producer must stop costing walks once \
       it stops producing, or the reader never returns to reading events \
       (reseeds so far: {})",
      reseeds.get()
    );
    let mut sent: Vec<SourceMessage> = Vec::new();
    let exit = service_control_with(
      &mut inbox,
      &mut map,
      ReportContext {
        stats: &rig.stats,
        transport: &rig.transport,
      },
      |_, _, _| Ok(AdmitWalk::Nothing),
      || {
        // The producer, running WHILE the walk does: the driver's refresh keeps
        // ticking, and each tick asks for another recovery and parks another
        // departure's admission.
        reseeds.set(reseeds.get() + 1);
        if reseeds.get() <= PRODUCING_WALKS {
          for _ in 0..ARRIVALS_PER_WALK {
            next_ticket.set(next_ticket.get() + 1);
            post(
              &tx,
              Control::Recover(recovery_request(next_ticket.get(), 0)),
            );
          }
          for _ in 0..ADMITS_PER_WALK {
            next_ticket.set(next_ticket.get() + 1);
            post(
              &tx,
              Control::Admit(ticketed_admit(next_ticket.get(), "/root/vol")),
            );
          }
        }
        let (resident, recovering) = tx.outstanding();
        peak_resident.set(peak_resident.get().max(resident));
        peak_recoveries.set(peak_recoveries.get().max(usize::from(recovering)));
        Ok(one_entry_walk())
      },
      |msg| {
        sent.push(msg);
        true
      },
      &|| false,
    );
    if exit == ControlExit::Continue && !inbox.has_work() {
      break;
    }
    assert_ne!(exit, ControlExit::Shutdown);
    assert_ne!(exit, ControlExit::Died);
  }

  assert_eq!(
    reseeds.get(),
    PRODUCING_WALKS + 1,
    "one walk per producing walk plus the ONE follow-up its arrivals earned — \
     never one per message, which is what {} arrivals would have cost",
    PRODUCING_WALKS as u64 * ARRIVALS_PER_WALK
  );
  assert_eq!(
    peak_recoveries.get(),
    1,
    "at most ONE recovery obligation is ever outstanding: the current walk's \
     cutoff is out of the mailbox, and everything arriving behind it folds into \
     the single follow-up"
  );
  assert!(
    peak_resident.get() <= RESIDENT_CEILING,
    "the mailbox never holds more admission bodies than its cap, however long \
     the producer runs: {} resident",
    peak_resident.get()
  );
}

/// **R6 F4**, the teardown half of the bounded drain: shutdown reaches the reader
/// OUT OF BAND, so a bounded pass can never defer teardown behind a full channel.
///
/// The two halves are a pair. A drain that stops at its budget can leave a
/// `Control::Shutdown` sitting in the channel unseen, which would trade the event
/// starvation it fixes for a teardown latency it does not — `SourceHandle::shutdown`
/// JOINS this thread. `WakeState::request_shutdown` is raised BEFORE the terminal
/// message is enqueued and is read without touching the channel at all, so the
/// preemption is independent of how much traffic is queued in front of it.
///
/// Staged with the flag alone and NO `Control::Shutdown` in the channel, which is
/// the only staging that can tell the out-of-band path from the in-band one.
///
/// MUTATION WITNESS: read only the drained message (drop the `shutdown_requested`
/// disjunct) and this FAILS at `a shutdown outranks every long op here, the
/// reseed included` — the reader runs the whole recovery instead of preempting,
/// which is precisely the teardown latency the bounded drain would otherwise buy.
#[test]
fn an_out_of_band_shutdown_preempts_a_full_control_channel() {
  let rig = pass_rig();
  let mut map = FidMap::new();
  let (tx, mut inbox) = control_mailbox();
  for ticket in 1..=300u64 {
    post(&tx, Control::Recover(recovery_request(ticket, 0)));
  }

  let mut sent: Vec<SourceMessage> = Vec::new();
  let exit = service_control_with(
    &mut inbox,
    &mut map,
    ReportContext {
      stats: &rig.stats,
      transport: &rig.transport,
    },
    |_, _, _| panic!("no located walk is owed"),
    || panic!("a shutdown outranks every long op here, the reseed included"),
    |msg| {
      sent.push(msg);
      true
    },
    // The flag teardown raises before it enqueues anything.
    &|| true,
  );
  assert_eq!(
    exit,
    ControlExit::Shutdown,
    "the out-of-band flag preempts, whatever is queued in front of it"
  );
  assert!(
    sent.is_empty(),
    "and the scope being torn down is owed nothing: no recovery ran, no ticket \
     was answered: {sent:?}"
  );
}

/// **R6 F4**, the backlog half: past `MAX_QUEUED_ADMITS` the whole outstanding set
/// collapses into ONE root-wide recovery answered by ONE message, instead of
/// growing without bound and replying per ticket.
///
/// A mass unmount is one refresh condemning every departed record at once, so the
/// queue's natural burst is the namespace's. The collapse is not a new degrade:
/// it is the rung `AdmitVerdict::Blind` already falls to — a whole-map reseed
/// whose declines are a complete generation, and a root cover that DOMINATES
/// every located cover it stands in for. Every ticket is still discharged,
/// because the core parked a cover on each and an unanswered one is parked
/// forever — but by a CUTOFF rather than a reply each, so neither the message
/// count nor the core's retirement is linear in the burst.
///
/// MUTATION WITNESS (shape): answer per ticket again — a `SourceMessage::Admitted`
/// loop over the discharged run — and this FAILS at `and not one per-ticket
/// reply`, which is the site that names the quadratic retirement it restores.
/// MUTATION WITNESS (cutoff): fold with `min` instead of `max` and it FAILS at
/// `the cutoff names the HIGHEST ticket` with `left: AdmitTicket(1), right:
/// AdmitTicket(67)` — a cutoff below the run leaves the core holding covers no
/// reply will ever release.
#[test]
fn a_backlog_past_the_cap_collapses_into_one_root_wide_recovery() {
  let rig = pass_rig();
  let mut map = FidMap::new();
  let (tx, mut inbox) = control_mailbox();
  let queued = MAX_QUEUED_ADMITS as u64 + 3;
  for ticket in 1..=queued {
    post(&tx, Control::Admit(ticketed_admit(ticket, "/root/vol")));
  }

  let admit_walks = Cell::new(0u32);
  let reseeds = Cell::new(0u32);
  let mut sent: Vec<SourceMessage> = Vec::new();
  let exit = service_control_with(
    &mut inbox,
    &mut map,
    ReportContext {
      stats: &rig.stats,
      transport: &rig.transport,
    },
    |_, _, _| {
      admit_walks.set(admit_walks.get() + 1);
      Ok(AdmitWalk::Nothing)
    },
    || {
      reseeds.set(reseeds.get() + 1);
      Ok(one_entry_walk())
    },
    |msg| {
      sent.push(msg);
      true
    },
    &|| false,
  );

  assert_eq!(
    reseeds.get(),
    1,
    "ONE root-wide recovery for the whole run, not one walk per entry"
  );
  assert_eq!(
    admit_walks.get(),
    0,
    "and no located walk ran at all: the reseed re-walks from the root, which \
     subsumes every one of them"
  );
  assert_eq!(
    exit,
    ControlExit::Continue,
    "so the whole backlog is discharged in ONE pass — an uncollapsed one would \
     still be deferring walks"
  );
  assert!(
    answered(&sent).is_empty(),
    "and not one per-ticket reply: the core retired those by SEARCHING its \
     parked vector, which is quadratic in exactly the burst this collapse \
     absorbs: {sent:?}"
  );
  assert_eq!(
    sent.len(),
    1,
    "ONE message discharges the whole run: {sent:?}"
  );
  let SourceMessage::RootRecovered(recovery, _) = &sent[0] else {
    panic!("the collapse answers with the indivisible recovery: {sent:?}");
  };
  assert_eq!(
    recovery.cutoff,
    AdmitTicket::new(queued),
    "the cutoff names the HIGHEST ticket in the run, so the core discharges the \
     whole contiguous prefix in one linear pass — a lower one would leave covers \
     parked with no reply left to release them"
  );
  assert_eq!(
    recovery.declined,
    one_entry_walk().declined,
    "and it carries the reseed's COMPLETE generation in the same message, so the \
     evidence and the discharge cannot be separated"
  );

  // Nothing is left resident: a second pass has no work at all.
  sent.clear();
  let exit = service_control_with(
    &mut inbox,
    &mut map,
    ReportContext {
      stats: &rig.stats,
      transport: &rig.transport,
    },
    |_, _, _| panic!("nothing is left to walk"),
    || panic!("nothing is left to reseed"),
    |msg| {
      sent.push(msg);
      true
    },
    &|| false,
  );
  assert_eq!(exit, ControlExit::Continue);
  assert!(
    sent.is_empty(),
    "the collapsed backlog left no residue: {sent:?}"
  );
}

/// **R7 F4**, the located ladder: a teardown that lands WHILE the first walk runs
/// preempts the retry, and never interrupts the walk in flight.
///
/// The out-of-band flag was checked once, before `run_admission`, and the
/// synchronous ladder then ran two revealed-subtree attempts followed by two
/// whole-root reseed attempts with no further check — so a shutdown arriving
/// during the first failing walk waited out up to three more potentially
/// million-directory walks, with `SourceHandle::shutdown` joining this thread
/// throughout.
///
/// Both halves of the rule are here, because they pull in opposite directions:
/// the RETRY is a fresh walk and a teardown outranks it, while the walk ALREADY
/// RUNNING must finish (a half-built map is the silent-blindness shape the whole
/// stack prevents).
///
/// MUTATION WITNESS (preemption): drop the `attempt > 0 && shutdown_requested()`
/// check in `admit_revealed` and this FAILS at `the retry never ran` with
/// `left: 2, right: 1` — the teardown waiting out a second whole walk.
/// MUTATION WITNESS (must-complete): move that check ahead of the FIRST attempt
/// (`shutdown_requested()` alone) and it FAILS at `the walk already in flight
/// always completes` with `left: 0, right: 1` — a teardown abandoning an
/// admission that would have succeeded.
#[test]
fn a_teardown_during_the_first_located_walk_preempts_only_its_retry() {
  let mut map = seeded_with_sub();
  let attempts = Cell::new(0u32);
  let tearing_down = Cell::new(false);
  let mut declined = Vec::new();
  let verdict = admit_revealed(
    &mut map,
    &admit_request("/root/vol"),
    &mut declined,
    |_, _, _| {
      attempts.set(attempts.get() + 1);
      // `SourceHandle::teardown` raises the flag while this walk is running.
      tearing_down.set(true);
      Err(io::Error::other("unreadable"))
    },
    &|| tearing_down.get(),
  );
  assert_eq!(
    attempts.get(),
    1,
    "the retry never ran: a teardown outranks a walk that has not started"
  );
  assert_eq!(
    verdict,
    AdmitVerdict::Abandoned,
    "and the verdict says ABANDONED, not Blind — nothing was proven about the \
     source's sight, so the caller must not escalate"
  );

  // The other half: a teardown already pending does NOT interrupt the one walk
  // this ladder starts.
  let mut map = seeded_with_sub();
  let attempts = Cell::new(0u32);
  let mut declined = Vec::new();
  let verdict = admit_revealed(
    &mut map,
    &admit_request("/root/vol"),
    &mut declined,
    |_, _, _| {
      attempts.set(attempts.get() + 1);
      Ok(revealed_under_root(Vec::new()))
    },
    &|| true,
  );
  assert_eq!(
    attempts.get(),
    1,
    "the walk already in flight always completes: the map is whole or it is \
     nothing"
  );
  assert_eq!(verdict, AdmitVerdict::Admitted);
}

/// **R7 F4**, the escalation: a located ladder that exhausted itself while a
/// teardown was landing must NOT trade its two failed walks for a walk of the
/// entire root.
///
/// This is the single largest op the reader has, and it sat behind the ladder
/// with no check in front of it at all.
///
/// The rung no longer walks: it folds the exhausted request into the mailbox's
/// recovery slot, and the ONE recovery that discharges it runs a statement later,
/// in the pass. So the teardown gate lives there too — the check BETWEEN
/// admissions, which is now what stands between an escalation and the whole-root
/// walk it buys. Folding on the way out costs nothing and loses nothing: the
/// cutoff stays in the mailbox unanswered, exactly as `run_root_recovery`'s own
/// abandoned exit leaves the one it had already taken, because the scope whose
/// cover was parked on it is ending.
///
/// MUTATION WITNESS (escalation): drop the `inbox.shutting_down() ||
/// shutdown_requested()` check between admissions in `service_control_with` and
/// this PANICS at `a teardown outranks the whole-root escalation` — the reader
/// walking the whole tree on its way out.
/// MUTATION WITNESS (silence): send an `AdmitReport` from the escalation arm
/// before folding and it FAILS at `an abandoned admission answers NOTHING` with
/// `[Admitted(AdmitReport { ticket: AdmitTicket(7), outcome: StillCovered })]` —
/// the teardown rule says the request dies unrun and unanswered with the scope.
#[test]
fn a_teardown_in_the_located_ladder_never_buys_the_whole_root_escalation() {
  let stats = BackendStatsShared::default();
  let transport = TransportState::new(8);
  let mut map = seeded_with_sub();
  let attempts = Cell::new(0u32);
  let tearing_down = Cell::new(false);
  let mut sent: Vec<SourceMessage> = Vec::new();
  let (tx, mut inbox) = control_mailbox();
  post(&tx, Control::Admit(admit_request("/root/vol")));

  let exit = service_control_with(
    &mut inbox,
    &mut map,
    ReportContext {
      stats: &stats,
      transport: &transport,
    },
    |_, _, _| {
      attempts.set(attempts.get() + 1);
      // The teardown lands during the SECOND walk, so the located ladder runs to
      // its own exhaustion and it is the ESCALATION that must be refused.
      if attempts.get() == 2 {
        tearing_down.set(true);
      }
      Err(io::Error::other("unreadable"))
    },
    || panic!("a teardown outranks the whole-root escalation"),
    |msg| {
      sent.push(msg);
      true
    },
    &|| tearing_down.get(),
  );

  assert_eq!(
    attempts.get(),
    2,
    "staging: the located ladder really did exhaust itself, so this cell reads \
     the escalation and not the retry"
  );
  assert_eq!(
    exit,
    ControlExit::Shutdown,
    "the request is abandoned rather than escalated"
  );
  assert!(
    sent.is_empty(),
    "an abandoned admission answers NOTHING — no reply, no loss, no terminal: \
     the scope whose cover was parked on it is ending: {sent:?}"
  );
}

/// **R7 F4**, the reseed ladder: a teardown between the whole-root walk's two
/// attempts abandons it, and abandonment is NOT blindness.
///
/// The distinction is the whole point. `Blind` means the source was PROVEN unable
/// to see and is escalated to the terminal `Fatal`; a ladder cut short by
/// teardown proved nothing at all, and reporting a `Fatal` on the way out would
/// turn an orderly shutdown into a scope death the consumer has to interpret.
///
/// MUTATION WITNESS (preemption): drop the `attempt > 0 && shutdown_requested()`
/// check in `reseed_map` and this FAILS at `the retry never ran` with
/// `left: 2, right: 1`.
/// MUTATION WITNESS (not-a-terminal): answer `ReseedOutcome::Blind` on the
/// abandoned path and it FAILS at `abandonment is not blindness` — the teardown
/// escalated into a terminal `Fatal`.
#[test]
fn a_teardown_between_the_reseeds_attempts_abandons_rather_than_conceding_blind() {
  let mut map = FidMap::new();
  let calls = Cell::new(0u32);
  let tearing_down = Cell::new(false);
  let mut generation = ReseedGeneration::default();
  let outcome = reseed_map(
    &mut map,
    &mut generation,
    || {
      calls.set(calls.get() + 1);
      tearing_down.set(true);
      Err::<WalkSeed, io::Error>(io::Error::other("still failing"))
    },
    &|| tearing_down.get(),
  );
  assert_eq!(calls.get(), 1, "the retry never ran");
  assert_eq!(
    outcome,
    ReseedOutcome::Abandoned,
    "abandonment is not blindness: nothing was proven about the source's sight"
  );
  assert_eq!(map.dir_count(), 0, "and the map is untouched");
}

/// **R7 F4**, the same rule on the move-in walk — the third of the reader's
/// two-attempt ladders, and the one whose failure rung is a whole-root reseed
/// behind a loss barrier.
///
/// MUTATION WITNESS: drop the `attempt > 0 && shutdown_requested()` check in
/// `seed_moved_in_subtree` and this FAILS at `the retry never ran` with
/// `left: 2, right: 1` — a teardown waiting out a second subtree walk on its way
/// to a loss barrier it will never deliver.
#[test]
fn a_teardown_between_the_move_in_walks_attempts_abandons_it() {
  let mut map = seeded_with_sub();
  map.learn_moved_in(&fid(2), b"arrived", &fid(5));
  let calls = Cell::new(0u32);
  let tearing_down = Cell::new(false);
  let mut declined = Vec::new();
  let outcome = seed_moved_in_subtree(
    &mut map,
    &fid(5),
    &mut declined,
    |_, _| {
      calls.set(calls.get() + 1);
      tearing_down.set(true);
      Err::<WalkSeed, io::Error>(io::Error::from(io::ErrorKind::NotFound))
    },
    &|| tearing_down.get(),
  );
  assert_eq!(calls.get(), 1, "the retry never ran");
  assert_eq!(
    outcome,
    SeedOutcome::Abandoned,
    "and the buffer is abandoned rather than sent down the loss ladder, whose \
     own recovery is a walk of the entire root"
  );
}

/// **R7 F4**, the control-path plumbing: an abandonment inside a whole-root
/// recovery reaches the reader as `Shutdown`, not as a death.
///
/// The pass owns the cutoff it took out of the mailbox, so the shape this pins is
/// what the reader DOES with a ladder that gave up: it quiesces, and the ticket
/// dies with the scope rather than being answered by a `Fatal` the consumer would
/// read as a stream failure.
///
/// MUTATION WITNESS (exit): map `StepExit::Abandoned` to `ControlExit::Died` in
/// `service_control_with`'s recovery arm and this FAILS at `a teardown ends the
/// reader by SHUTDOWN` with `left: Died, right: Shutdown` — a clean teardown
/// reported as a dead source.
/// MUTATION WITNESS (terminal): drop the between-attempt check in `reseed_map`
/// and it FAILS at `the reseed's retry never ran` with `left: 2, right: 1` — and
/// that second failing walk is what would then escalate an orderly shutdown into
/// the terminal `Fatal` the `sent.is_empty()` leg forbids.
#[test]
fn a_teardown_inside_a_root_recovery_quiesces_instead_of_dying() {
  let rig = pass_rig();
  let mut map = FidMap::new();
  let (tx, mut inbox) = control_mailbox();
  post(&tx, Control::Recover(recovery_request(9, 0)));

  let walks = Cell::new(0u32);
  let tearing_down = Cell::new(false);
  let mut sent: Vec<SourceMessage> = Vec::new();
  let exit = service_control_with(
    &mut inbox,
    &mut map,
    ReportContext {
      stats: &rig.stats,
      transport: &rig.transport,
    },
    |_, _, _| panic!("no located walk is owed"),
    || {
      walks.set(walks.get() + 1);
      tearing_down.set(true);
      Err(io::Error::other("unreadable"))
    },
    |msg| {
      sent.push(msg);
      true
    },
    &|| tearing_down.get(),
  );
  assert_eq!(walks.get(), 1, "the reseed's retry never ran");
  assert_eq!(
    exit,
    ControlExit::Shutdown,
    "a teardown ends the reader by SHUTDOWN, not by death"
  );
  assert!(
    sent.is_empty(),
    "nothing at all is sent: no recovery, no terminal, no reply: {sent:?}"
  );
}

/// **R13 F3.** A pass boundary is not a transport-credit boundary: two ORDINARY
/// whole-root recoveries at a boundary budget of one must not kill the source, and
/// the second must WAIT for the first report's slot.
///
/// The seal used to be "at most one recovery per pass": a recovery yields the pass,
/// and the caller re-enters. But re-entering is instant — the caller self-wakes on
/// `Deferred` and the `poll` returns at once — while the first `RootRecovered` still
/// holds its permit until the DRIVER consumes it, on another thread, whenever it
/// gets there. So the second pass met an exhausted counter and signalled the
/// terminal `Fatal` for nothing worse than consumer scheduling latency, at the
/// supported floor of `os_batch_capacity = 1`.
///
/// The fix is a credit boundary rather than a pass boundary. The slot is claimed
/// BEFORE the obligation leaves the mailbox, so a pass with no credit walks nothing,
/// consumes nothing, and answers [`ControlExit::Blocked`] — which the reader treats
/// as "block until a slot comes back" rather than "spin", the release itself being
/// the wake. Deferring costs a round trip; dying costs the scope.
///
/// The three legs are the three claims: the first recovery is answered and holds
/// the only slot; the second is BLOCKED — not answered, not dropped, and above all
/// not fatal, with the obligation still in the mailbox; and the released slot lets
/// exactly that obligation through.
///
/// MUTATION WITNESS (claim inside the send): give `forward_root_recovery` back its
/// own `acquire_boundaries`/`signal_fatal_boundaries` and drop the pre-claim, and
/// this FAILS at `an unconsumed queue is NOT a source failure` — the second pass
/// sends `Fatal` for two ordinary bursts.
/// MUTATION WITNESS (defer instead of block): return `pass_end(inbox)` in place of
/// `ControlExit::Blocked` and this FAILS at `the pass reports itself BLOCKED` with
/// `left: Deferred, right: Blocked` — the caller keeps a wake pending, re-enters
/// immediately, fails the identical claim, and spins on a reader whose whole job is
/// to be reading events.
#[test]
fn a_credit_less_control_pass_waits_instead_of_dying() {
  let stats = BackendStatsShared::default();
  // The REPORT budget's own floor: one boundary report in flight, with a healthy
  // batch budget beside it. The credit boundary is what serializes, whatever the
  // number is; `os_batch_capacity` is a different concern and is held clear of it.
  let transport = TransportState::with_report_budget(8, 1, None);
  let mut map = FidMap::new();
  let (tx, mut inbox) = control_mailbox();

  // The permits the driver would release at ingest, HELD instead.
  let held = std::cell::RefCell::new(Vec::new());
  let pass = |inbox: &mut super::ControlInbox, map: &mut FidMap| {
    let mut sent: Vec<SourceMessage> = Vec::new();
    let exit = service_control_with(
      inbox,
      map,
      ReportContext {
        stats: &stats,
        transport: &transport,
      },
      |_, _, _| panic!("no located walk is owed"),
      || Ok(one_entry_walk()),
      |msg| {
        if let SourceMessage::RootRecovered(recovery, permit) = msg {
          held.borrow_mut().push(permit);
          sent.push(SourceMessage::RootRecovered(
            recovery,
            crate::os::transport::BudgetPermit::detached(),
          ));
        } else {
          sent.push(msg);
        }
        true
      },
      &|| false,
    );
    (sent, exit)
  };

  // Burst one.
  post(&tx, Control::Recover(recovery_request(1, 0)));
  let (first, exit) = pass(&mut inbox, &mut map);
  assert_eq!(
    exit,
    ControlExit::Continue,
    "staging: the first recovery is answered and nothing is left owed: {first:?}"
  );
  assert!(
    matches!(first.as_slice(), [SourceMessage::RootRecovered(..)]),
    "staging: it answered with exactly its one indivisible report: {first:?}"
  );
  assert_eq!(
    transport.boundaries_in_flight(),
    1,
    "staging: and that report is holding the only slot until the driver ingests it"
  );

  // Burst two — a separate, ordinary obligation, arriving while the first report
  // is still queued.
  post(&tx, Control::Recover(recovery_request(2, 0)));
  let (second, exit) = pass(&mut inbox, &mut map);
  assert!(
    second.is_empty(),
    "an unconsumed queue is NOT a source failure: nothing is sent, and above all \
     no terminal Fatal for two ordinary bursts: {second:?}"
  );
  assert_eq!(
    exit,
    ControlExit::Blocked,
    "the pass reports itself BLOCKED rather than deferred: a deferral keeps a wake \
     pending and re-runs the identical failed claim"
  );
  assert!(
    inbox.recovering(),
    "and the obligation is still in the mailbox — the claim happens BEFORE the \
     take, so a pass that cannot report walks nothing and consumes nothing"
  );

  // The driver ingests. The slot comes back, and the waiting obligation goes.
  held.borrow_mut().clear();
  assert_eq!(
    transport.boundaries_in_flight(),
    0,
    "staging: ingest returned the slot"
  );
  let (third, exit) = pass(&mut inbox, &mut map);
  assert_eq!(
    exit,
    ControlExit::Continue,
    "the released slot is what ends the wait: {third:?}"
  );
  assert_eq!(
    third
      .iter()
      .filter_map(|msg| match msg {
        SourceMessage::RootRecovered(recovery, _) => Some(recovery.cutoff),
        _ => None,
      })
      .collect::<Vec<_>>(),
    vec![AdmitTicket::new(2)],
    "and it is the very obligation the blocked pass left standing: {third:?}"
  );
}

/// **R13 F3, the residual.** A control-pass recovery in flight plus an event-path
/// whole-root reseed, at `os_batch_capacity = 1`, must not kill the source.
///
/// This is the case the first credit fix left open, and it is the batch/boundary
/// conflation rather than the pass/credit one: the event path claims a boundary
/// slot it cannot defer, so at the supported floor of ONE the recovery report
/// already sitting on the queue took the only slot and the very next lossy buffer
/// signalled the terminal. Two ordinary, unrelated events — a mount departure and
/// a kernel-queue overflow, which in practice arrive together — killing a source
/// with nothing wrong with it.
///
/// Two numbers close it, and both legs are asserted because either alone would
/// leave a hole:
///
/// - the report budget is [`MAX_BOUNDARY_REPORTS_IN_FLIGHT`], never
///   `os_batch_capacity`. A batch is up to `os_buffer_bytes` of decoded events and
///   its exhaustion degrades to the ordered loss; a report is a walk's declines and
///   its exhaustion is the terminal. One number cannot be the verdict for both.
/// - the two producers hold SEPARATE report counters, because their verdicts are
///   opposite. Sized alone, a control backlog running while the driver is merely
///   slow still occupies the headroom the terminal is read out of — and a mass
///   unmount is exactly when a departure burst and a queue overflow happen at once.
///
/// The verdict is deliberately NOT parameterized by either constant: this stages
/// one recovery and one reseed at `os_batch_capacity = 1` and asserts both went out
/// and nothing died, which is the property, not the arithmetic.
///
/// MUTATION WITNESS (tie the report budget back to the batch budget): claim against
/// `transport.budget` instead of `transport.reports_budget` in `acquire_boundaries`
/// and this FAILS at `nor is a SECOND overflow` — at `os_batch_capacity = 1` the
/// event path's whole allowance is one report, so a source that saw two overflows
/// before the driver's task was polled once signals the terminal.
/// MUTATION WITNESS (one report counter for both producers): claim against
/// `reports_in_flight` in `acquire_deferred_boundaries` and this FAILS at `the
/// deferrable producer holds its OWN counter` with `left: 0, right: 1` — the
/// control pass spending headroom the event path's death sentence is read out of,
/// which is the same defect one producer deeper.
///
/// Neither mutation is masked by the other's fix, which is why both legs are here:
/// the counter split alone still dies on two consecutive overflows at the floor,
/// and the sizing alone still dies behind a control backlog.
#[test]
fn a_recovery_in_flight_does_not_kill_the_event_path_at_a_batch_capacity_of_one() {
  let stats = BackendStatsShared::default();
  // `os_batch_capacity` at its supported floor, and NOTHING else configured: the
  // report budget is the transport's own default, which is the whole point.
  let transport = TransportState::new(1);
  let mut map = seeded_with_sub();
  let (tx, mut inbox) = control_mailbox();

  // The permits the driver would release at ingest, HELD — so the recovery report
  // really is still resident when the event path asks for its own slot.
  let held = std::cell::RefCell::new(Vec::new());
  let capture = |held: &std::cell::RefCell<Vec<_>>, sent: &mut Vec<Sent>, msg| match msg {
    SourceMessage::Batch(payload) => sent.push(Sent::Batch(payload.events.len())),
    SourceMessage::Boundaries(boundaries, permit) => {
      held.borrow_mut().push(permit);
      sent.push(Sent::Boundaries(boundaries));
    }
    SourceMessage::Admitted(report) => sent.push(Sent::Admitted(report)),
    SourceMessage::RootRecovered(recovery, permit) => {
      held.borrow_mut().push(permit);
      sent.push(Sent::RootRecovered(recovery));
    }
    SourceMessage::Overflow(_) => sent.push(Sent::Overflow),
    SourceMessage::Fatal(_) => sent.push(Sent::Fatal),
  };

  // Event one: the core asks for a whole-root recovery, and the control pass
  // answers it. Its report is now queued and holding a slot.
  post(&tx, Control::Recover(recovery_request(1, 0)));
  let mut first: Vec<Sent> = Vec::new();
  let exit = service_control_with(
    &mut inbox,
    &mut map,
    ReportContext {
      stats: &stats,
      transport: &transport,
    },
    |_, _, _| panic!("no located walk is owed"),
    || Ok(one_entry_walk()),
    |msg| {
      capture(&held, &mut first, msg);
      true
    },
    &|| false,
  );
  assert_eq!(
    exit,
    ControlExit::Continue,
    "staging: the recovery was answered: {first:?}"
  );
  assert!(
    matches!(first.as_slice(), [Sent::RootRecovered(_)]),
    "staging: with its one indivisible report: {first:?}"
  );
  assert_eq!(
    transport.deferred_boundaries_in_flight(),
    1,
    "the deferrable producer holds its OWN counter: a control report may not spend \
     the headroom the event path's terminal is read out of"
  );

  // Event two, unrelated: a lossy buffer. The reseed runs and its whole-root
  // generation must go out — this producer cannot defer, its events are already
  // out of the kernel and its map is already rebuilt.
  let lossy = |map: &mut FidMap| {
    let mut sent: Vec<Sent> = Vec::new();
    let exit = process_decoded(
      DecodeOutcome {
        events: Vec::new(),
        lossy: true,
      },
      map,
      &BufferContext {
        report: ReportContext {
          stats: &stats,
          transport: &transport,
        },
        exclusions: &[],
        frame_epoch: HEARD_EPOCH,
      },
      report_credit(&transport),
      || Ok(one_entry_walk()),
      |_, _, _, _| Ok(WalkSeed::default()),
      |msg| {
        capture(&held, &mut sent, msg);
        true
      },
      &|| false,
    );
    (sent, exit)
  };

  let (second, exit) = lossy(&mut map);
  assert_eq!(
    exit,
    StepExit::Done,
    "two ordinary events are not a source failure: {second:?}"
  );
  assert!(
    !second.iter().any(|s| matches!(s, Sent::Fatal)),
    "two ordinary events are not a source failure — a mount departure and a queue \
     overflow arrive together, and neither is a statement about the consumer: \
     {second:?}"
  );
  assert!(
    matches!(second.first(), Some(Sent::Boundaries(_))),
    "the reseed's generation goes out ahead of the loss it implies, exactly as it \
     does on a source with no recovery in flight at all: {second:?}"
  );
  assert_eq!(
    transport.deferred_boundaries_in_flight(),
    1,
    "the control report is STILL on its own counter — the event path spent none of \
     the deferrable producer's credit, and vice versa"
  );

  // A SECOND lossy buffer, still unconsumed. This is the leg the SIZING decides:
  // one event-path report may not be the whole allowance, or a source that saw two
  // overflows before the driver's task was polled once dies for it.
  let (third, exit) = lossy(&mut map);
  assert_eq!(
    exit,
    StepExit::Done,
    "nor is a SECOND overflow: the report budget is sized against the burst a \
     producer reaches before the driver gets a turn, and one is not a burst: \
     {third:?}"
  );
  assert!(
    !third.iter().any(|s| matches!(s, Sent::Fatal)),
    "an event path whose whole allowance was one report would signal the terminal \
     here — which is exactly what tying it to `os_batch_capacity` did at the \
     floor: {third:?}"
  );
  assert_eq!(
    transport.boundaries_in_flight(),
    3,
    "all three reports are resident at once, which is the thing a shared number \
     could not express"
  );
  assert_eq!(
    transport.in_flight(),
    0,
    "on no batch slots whatever: `os_batch_capacity` bounds decoded events and \
     says nothing about boundary evidence"
  );
}

/// The edge that ends a [`ControlExit::Blocked`] wait: releasing a BOUNDARY slot
/// notifies the producer, and releasing a batch slot does not.
///
/// Without this, `Blocked` is a deadlock rather than a wait. The reader blocks in
/// `poll` over its fanotify fd and its eventfd; the driver that consumes the report
/// runs on another thread and posts no control message for having done so, so on a
/// quiet tree — with the root-liveness interval at the supported zero — nothing
/// would ever wake the reader to retry its claim, and the core would sit holding a
/// parked cover for a reply that is never produced.
///
/// The batch half is not symmetry: a batch producer never waits on credit (it
/// degrades to the ordered loss instead), so waking a reader on every batch ingest
/// would be a syscall per batch bought for nothing.
///
/// MUTATION WITNESS (never notified): drop the `credit.boundary_released()` call
/// from `BudgetPermit::drop` and this FAILS at `a returned boundary slot notifies`
/// with `left: 0, right: 1`.
/// MUTATION WITNESS (notify on every slot): pass the credit to `acquire` as well as
/// `acquire_boundaries` and it FAILS at `a returned BATCH slot notifies nothing`
/// with `left: 2, right: 1` — a wake syscall per ingested batch.
#[test]
fn a_returned_boundary_slot_notifies_the_producer() {
  #[derive(Debug, Default)]
  struct Counting(std::sync::atomic::AtomicUsize);
  impl crate::os::transport::BoundaryCredit for Counting {
    fn boundary_released(&self) {
      self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
  }

  let credit = std::sync::Arc::new(Counting::default());
  let transport = TransportState::with_boundary_credit(
    4,
    Some(std::sync::Arc::clone(&credit) as std::sync::Arc<dyn crate::os::transport::BoundaryCredit>),
  );

  let permit =
    crate::os::transport::BudgetPermit::acquire_boundaries(&transport).expect("a slot is free");
  assert_eq!(
    credit.0.load(std::sync::atomic::Ordering::Relaxed),
    0,
    "staging: claiming notifies nothing — only the RELEASE is an edge"
  );
  drop(permit);
  assert_eq!(
    credit.0.load(std::sync::atomic::Ordering::Relaxed),
    1,
    "a returned boundary slot notifies the producer, which is the only thing that \
     can end a wait for credit"
  );

  // A batch slot is a different counter and a different contract. One real event,
  // because an EMPTY batch claims no slot at all and would prove nothing.
  crate::os::transport::forward_batch(
    &transport,
    vec![crate::os::linux::RawLinuxEvent::Fanotify(
      crate::os::linux::AdmittedEvent {
        mask: crate::os::linux::fanotify::FanMask::new(0),
        path: None,
        rename: None,
      },
    )],
    false,
    |msg| {
      assert!(
        matches!(
          msg,
          crate::os::transport::SourceMessage::<crate::os::linux::RawLinuxEvent>::Batch(_)
        ),
        "staging: the batch claimed a slot and went out"
      );
      true
    },
  );
  assert_eq!(
    credit.0.load(std::sync::atomic::Ordering::Relaxed),
    1,
    "a returned BATCH slot notifies nothing: a batch producer never waits on \
     credit, so the wake would be bought for nothing"
  );
}

/// A walk that succeeds on the FIRST try reseeds the map and reports
/// `Reseeded` — the common path.
#[test]
fn first_walk_success_reseeds() {
  let mut map = FidMap::new();
  let mut generation = ReseedGeneration::default();
  let outcome = reseed_map(&mut map, &mut generation, || Ok(one_entry_walk()), &|| {
    false
  });
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
  let mut generation = ReseedGeneration::default();
  let outcome = reseed_map(
    &mut map,
    &mut generation,
    || {
      calls.set(calls.get() + 1);
      if calls.get() == 1 {
        Err(io::Error::other("transient"))
      } else {
        Ok(one_entry_walk())
      }
    },
    &|| false,
  );
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
  let mut generation = ReseedGeneration::default();
  let outcome = reseed_map(
    &mut map,
    &mut generation,
    || {
      calls.set(calls.get() + 1);
      Err::<WalkSeed, io::Error>(io::Error::other("still failing"))
    },
    &|| false,
  );
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
  let mut declined = Vec::new();
  let outcome = seed_moved_in_subtree(
    &mut map,
    &fid(5),
    &mut declined,
    |subtree, _| {
      seen_path.set(Some(subtree.to_path_buf()));
      Ok(WalkSeed {
        entries: vec![SeedEntry::child(
          fid(6),
          fid(5),
          std::ffi::OsString::from("deep"),
        )],
        declined: Vec::new(),
        fence_mnt_id: WALKED_SUBTREE_MNT_ID,
      })
    },
    &|| false,
  );
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
  let mut declined = Vec::new();
  let outcome = seed_moved_in_subtree(
    &mut map,
    &fid(5),
    &mut declined,
    |_, _| {
      calls.set(calls.get() + 1);
      if calls.get() == 1 {
        Err(io::Error::other("transient"))
      } else {
        Ok(WalkSeed {
          entries: vec![SeedEntry::child(
            fid(6),
            fid(5),
            std::ffi::OsString::from("deep"),
          )],
          declined: Vec::new(),
          fence_mnt_id: WALKED_SUBTREE_MNT_ID,
        })
      }
    },
    &|| false,
  );
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
  let mut declined = Vec::new();
  let outcome = seed_moved_in_subtree(
    &mut map,
    &fid(5),
    &mut declined,
    |_, _| {
      calls.set(calls.get() + 1);
      Err::<WalkSeed, io::Error>(io::Error::other("still failing"))
    },
    &|| false,
  );
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
  let mut declined = Vec::new();
  let outcome = seed_moved_in_subtree(
    &mut map,
    &fid(5),
    &mut declined,
    |_, _| {
      calls.set(calls.get() + 1);
      Ok(WalkSeed::default())
    },
    &|| false,
  );
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
  let mut declined = Vec::new();
  let outcome = seed_moved_in_subtree(
    &mut map,
    &fid(5),
    &mut declined,
    |_, _| {
      calls.set(calls.get() + 1);
      Ok(WalkSeed::default())
    },
    &|| false,
  );
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
  let mut declined = Vec::new();
  let outcome = seed_moved_in_subtree(
    &mut map,
    &fid(5),
    &mut declined,
    |subtree, _| {
      seen_path.set(Some(subtree.to_path_buf()));
      Ok(WalkSeed {
        entries: vec![SeedEntry::child(
          fid(6),
          fid(5),
          std::ffi::OsString::from("deep"),
        )],
        declined: Vec::new(),
        fence_mnt_id: WALKED_SUBTREE_MNT_ID,
      })
    },
    &|| false,
  );
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
/// **R12 F1, the producer half.** The generation a lossy buffer's reseed sends
/// carries the ROOT MOUNT ID that walk fenced against — the fact the core judges
/// the whole report by, and one nothing at the other end can re-derive.
///
/// The stub reports a frame no other cell in this suite uses. A producer that
/// hardcoded the ordinary one, or dropped the field for `None`, would agree with
/// every other fixture here by coincidence and is visible only against this one.
///
/// MUTATION WITNESS (dropped): send `root_mnt_id: None` from `process_decoded`'s
/// barrier and this FAILS at `the generation names the root it walked` with
/// `root_mnt_id: None` against `Some(4242)` — a generation that cannot say which
/// root it describes is one the core can only install on trust.
/// MUTATION WITNESS (reach downgraded): send the barrier's report as
/// `WalkReach::Partial` and it FAILS at the same site with `left: [Overflow]` —
/// the report vanishing entirely, since an empty PARTIAL one is not worth a
/// message. A barrier that stopped claiming the whole root would stop retiring
/// the core's device-only records at all, which is the growth the generation
/// exists to bound.
#[test]
fn the_loss_barriers_generation_names_the_root_its_walk_fenced_against() {
  let mut map = seeded_with_sub();
  // Deliberately not `WALKED_ROOT_MNT_ID`: this cell is the one that would catch a
  // producer agreeing with the fixture rather than reporting the walk.
  const WALKED: Option<u64> = Some(4242);
  let seed = WalkSeed {
    fence_mnt_id: WALKED,
    ..one_entry_walk()
  };
  let decoded = DecodeOutcome {
    events: Vec::new(),
    lossy: true,
  };
  let (sent, alive, reseeds) = run_process(&mut map, decoded, Some(seed));
  assert!(alive, "a reseeded loss keeps the stream live");
  assert_eq!(reseeds, 1, "staging: the loss really did reseed");
  assert_eq!(
    sent,
    vec![
      Sent::Boundaries(crate::os::WalkBoundaries {
        declined: Vec::new(),
        reach: crate::os::WalkReach::WholeRoot {
          root_mnt_id: WALKED,
          epoch: HEARD_EPOCH,
        },
      }),
      Sent::Overflow,
    ],
    "the generation names the root it walked, and claims the WHOLE of it — the \
     two facts the core needs to decide whether this generation is its own"
  );
}

/// **R12 F1, the producing half.** The stamp on an autonomous whole-root
/// generation is the CORE'S frame epoch as the mailbox last heard it — folded in
/// as a MAXIMUM over everything the core has ever sent, and read before the walk
/// that will carry it.
///
/// The walked mount id cannot carry the check alone: Linux allocates mount ids
/// lowest-free, so a root that went A → B → A is back on the id the core holds
/// while a generation still queued from the first A describes a mount that is
/// gone. The epoch counts WORLDS core-side and is never recycled, so no reading of
/// an id can forge it.
///
/// Two things are pinned here, and the second is why the fold is a maximum rather
/// than a store: the mailbox is posted into from the driver's effect drain, and a
/// stamp that could go BACKWARDS on a late-arriving older message would refuse
/// generations from the world the core actually holds.
///
/// MUTATION WITNESS (the stamp is not the core's value): put `epoch: 0` on the
/// `WalkReach::WholeRoot` the lossy branch of `process_decoded` builds — the
/// unstamped report this replaces — and this FAILS at `the report carries the
/// epoch the core published` with `left: 0, right: 12`, leaving the recycled-id
/// case open exactly as it was.
/// MUTATION WITNESS (the fold is a store): make `Mailbox::observe_epoch`
/// `self.frame_epoch = epoch` and it FAILS at `and it is the NEWEST world the core
/// has named` with `left: 4, right: 12` — an older request landing behind a newer
/// publication dragging the source back into a world the core has left, so every
/// sound generation after it is refused.
#[test]
fn an_autonomous_generation_carries_the_newest_frame_epoch_the_core_published() {
  const PUBLISHED: u64 = 12;
  const OLDER: u64 = 4;
  const {
    assert!(
      OLDER < PUBLISHED && PUBLISHED != 0,
      "the older message must be strictly older, and neither may be the value an \
       unpublished mailbox already holds"
    );
  }
  let (tx, mut inbox) = control_mailbox();
  post(&tx, Control::Frame(PUBLISHED));
  // A request minted BEFORE that publication, delivered after it — the ordinary
  // shape of an effect drain, and the one a plain store would take at face value.
  post(&tx, Control::Recover(recovery_request(1, OLDER)));
  assert_eq!(
    inbox.frame_epoch(),
    PUBLISHED,
    "and it is the NEWEST world the core has named: a stamp that walked backwards \
     would refuse generations from the world the core actually holds"
  );

  // The recovery the request above owes, run out of the way first, so the buffer
  // below is the reader's OWN decision to reseed and not an answer to anything.
  let rig = pass_rig();
  let mut map = seeded_with_sub();
  let mut answered: Vec<SourceMessage> = Vec::new();
  let exit = service_control_with(
    &mut inbox,
    &mut map,
    ReportContext {
      stats: &rig.stats,
      transport: &rig.transport,
    },
    |_, _, _| panic!("no located walk is owed"),
    || Ok(one_entry_walk()),
    |msg| {
      answered.push(msg);
      true
    },
    &|| false,
  );
  assert_eq!(
    exit,
    ControlExit::Continue,
    "staging: the requested recovery is discharged: {answered:?}"
  );

  // The autonomous reseed: a lossy buffer, no request behind it.
  let stats = BackendStatsShared::default();
  let transport = TransportState::new(8);
  let sent = std::cell::RefCell::new(Vec::new());
  let exit = process_decoded(
    DecodeOutcome {
      events: Vec::new(),
      lossy: true,
    },
    &mut map,
    &BufferContext {
      report: ReportContext {
        stats: &stats,
        transport: &transport,
      },
      exclusions: &[],
      // Sampled from the live mailbox, exactly as `drain_events` samples it —
      // reading the constant instead would be a cell asserting its own fixture.
      frame_epoch: inbox.frame_epoch(),
    },
    report_credit(&transport),
    || Ok(one_entry_walk()),
    |_, _, _, _| Ok(WalkSeed::default()),
    |msg| {
      sent.borrow_mut().push(match msg {
        SourceMessage::Boundaries(boundaries, _) => Sent::Boundaries(boundaries),
        SourceMessage::Overflow(_) => Sent::Overflow,
        SourceMessage::Fatal(_) => Sent::Fatal,
        other => panic!("a lossy buffer sends only its generation and the loss: {other:?}"),
      });
      true
    },
    &|| false,
  );
  assert_eq!(
    exit,
    StepExit::Done,
    "staging: the reseed kept the stream live"
  );
  assert_eq!(
    sent.into_inner(),
    vec![
      Sent::Boundaries(crate::os::WalkBoundaries {
        declined: Vec::new(),
        reach: crate::os::WalkReach::WholeRoot {
          root_mnt_id: WALKED_ROOT_MNT_ID,
          epoch: PUBLISHED,
        },
      }),
      Sent::Overflow,
    ],
    "the report carries the epoch the core published, beside the root the walk \
     actually fenced against — two stamps, because the id one alone is forgeable \
     by a kernel that recycles ids"
  );
}

/// **R12 F4.** An obligation that arrives WHILE a whole-root walk is running does
/// not buy a second recovery report inside the same pass.
///
/// The recovery's [`RootRecovery`](crate::os::RootRecovery) is indivisible and
/// therefore NOT droppable: a permit it cannot claim kills the source. The
/// boundary budget's supported floor is ONE permit, and a permit is held until the
/// DRIVER consumes the message — so a pass that produced two reports back to back,
/// never returning to the event loop between them, killed a source with nothing
/// wrong with it. The reader used to do exactly that: it took the first snapshot,
/// walked, and then carried straight on through the quota loop into the request
/// that had landed meanwhile.
///
/// A recovery therefore YIELDS the pass. Nothing is discarded by that — the
/// obligation stays in the mailbox slot that coalesces it, and
/// [`ControlExit::Deferred`] is precisely the signal that has the caller re-enter
/// at once.
///
/// The rig runs at a budget of ONE so the failure is a source death and not merely
/// a cost, and the second pass runs with the first report DROPPED, which is what
/// the driver consuming it does.
///
/// MUTATION WITNESS (no yield): put `StepExit::Done => {}` back in
/// `service_control_with`'s in-loop recovery arm and this FAILS at `ONE walk in
/// the pass` with `left: 2, right: 1` — and the surviving legs then also catch it,
/// because the second report has no permit to claim and signals the terminal
/// `Fatal`.
/// MUTATION WITNESS (yield without deferring): make `pass_end` answer
/// `ControlExit::Continue` unconditionally and it FAILS at `the pass DEFERS what
/// it did not run` — a caller about to block on `poll` would leave the follow-up
/// waiting on unrelated traffic, which for a quiet tree is forever.
#[test]
fn a_request_arriving_during_a_recovery_walk_costs_no_second_report_in_the_pass() {
  let stats = BackendStatsShared::default();
  // ONE boundary-report slot, with a healthy BATCH budget beside it: a second
  // report in the same pass cannot be sent at all.
  let transport = TransportState::with_report_budget(8, 1, None);
  let mut map = FidMap::new();
  let (tx, mut inbox) = control_mailbox();

  // The prefix of the burst the reader wakes on.
  post(&tx, Control::Admit(epoched_admit(1, 0, "/root/vol")));

  let walks = Cell::new(0u32);
  let mut sent: Vec<SourceMessage> = Vec::new();
  let exit = service_control_with(
    &mut inbox,
    &mut map,
    ReportContext {
      stats: &stats,
      transport: &transport,
    },
    // The root re-mounted, so the executor refuses the located walk and the
    // request folds into the recovery slot.
    |_, _, _| Ok(AdmitWalk::Stale),
    || {
      walks.set(walks.get() + 1);
      // THE REST OF THE BURST, landing across the reader's wake — posted from
      // inside the walk, which is the only moment the race is expressible.
      if walks.get() == 1 {
        post(&tx, Control::Admit(epoched_admit(2, 0, "/root/vol2")));
      }
      Ok(one_entry_walk())
    },
    |msg| {
      sent.push(msg);
      true
    },
    &|| false,
  );

  assert_eq!(walks.get(), 1, "ONE walk in the pass: {sent:?}");
  assert_eq!(
    sent.len(),
    1,
    "and ONE report — a second could not claim the only boundary permit, and a \
     recovery that cannot claim one kills the source: {sent:?}"
  );
  let SourceMessage::RootRecovered(recovery, _) = &sent[0] else {
    panic!("the folded request is answered by the indivisible recovery: {sent:?}");
  };
  assert_eq!(
    recovery.cutoff,
    AdmitTicket::new(1),
    "whose cutoff names only what was posted BEFORE the walk began — a ticket \
     minted during it names ground the walk may not have reached"
  );
  assert!(
    !sent
      .iter()
      .any(|msg| matches!(msg, SourceMessage::Fatal(_))),
    "the source is alive: nothing here is a reason to kill it: {sent:?}"
  );
  assert_eq!(
    exit,
    ControlExit::Deferred,
    "the pass DEFERS what it did not run, so a caller about to block arms a wake \
     rather than leaving the follow-up on unrelated traffic: {sent:?}"
  );
  assert!(
    inbox.has_work(),
    "and the follow-up really is still owed — deferring is not discarding"
  );

  // The driver consumes the report, which releases the permit; the next pass
  // answers the follow-up.
  drop(sent);
  assert_eq!(
    transport.boundaries_in_flight(),
    0,
    "staging: the permit is back"
  );
  let mut again: Vec<SourceMessage> = Vec::new();
  let exit = service_control_with(
    &mut inbox,
    &mut map,
    ReportContext {
      stats: &stats,
      transport: &transport,
    },
    |_, _, _| Ok(AdmitWalk::Stale),
    || {
      walks.set(walks.get() + 1);
      Ok(one_entry_walk())
    },
    |msg| {
      again.push(msg);
      true
    },
    &|| false,
  );
  assert_eq!(
    walks.get(),
    2,
    "the follow-up costs its own walk, and only one"
  );
  assert_eq!(
    again.len(),
    1,
    "answered by one more indivisible recovery: {again:?}"
  );
  assert_eq!(
    exit,
    ControlExit::Continue,
    "with nothing left owed: {again:?}"
  );
  assert!(
    !inbox.has_work(),
    "the mailbox really is empty — every ticket was answered or folded into one \
     that was"
  );
}

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
    vec![Sent::Boundaries(whole_root(Vec::new())), Sent::Overflow],
    "the barrier: no Batch precedes the Overflow — the suffix event is dropped. \
     The reseed's own report rides ahead of it as always, and it is WHOLE-ROOT \
     even when it declined nothing: an empty complete walk is the generation \
     that retires the core's last stale device-only record"
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
    vec![Sent::Boundaries(whole_root(Vec::new())), Sent::Overflow],
    "the barrier: no Batch — the merged event AND the co-batched suffix drop, \
     behind the reseed's own whole-root report"
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
    vec![Sent::Boundaries(whole_root(Vec::new())), Sent::Overflow],
    "the barrier: no Batch — the merged rename AND the co-batched suffix drop, \
     behind the reseed's own whole-root report"
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
    vec![Sent::Boundaries(whole_root(Vec::new())), Sent::Overflow],
    "the barrier: no Batch — the merged event AND the co-batched suffix drop, \
     behind the reseed's own whole-root report"
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
    vec![Sent::Boundaries(whole_root(Vec::new())), Sent::Overflow],
    "the reseed's whole-root report, then the Overflow barrier — and no Batch"
  );
  assert_eq!(
    map.dir_count(),
    1,
    "the reseed pruned the deleted subtree — no stale directories left admitting"
  );
  assert_eq!(map.admit(&fid(2)), None, "the deleted directory is gone");
  assert_eq!(map.admit(&fid(3)), None, "and its descendant with it");
}

/// SEAM 2, the POST-LOSS RESEED driver: the boundaries the reseed walk declined
/// leave the reader on the source's ordered lane, as their own message, AHEAD of
/// the `Overflow` that covers the same ground.
///
/// The order is the point. The loss is about to make the consumer re-read this
/// tree; the coverage set should already know where that tree ends when it does.
/// It also cannot ride the barrier itself — `forward_batch` with a non-empty
/// event list would enqueue a `Batch` before the `Overflow`, which is exactly the
/// barrier this branch exists to hold — so it goes as a separate message that
/// carries no record and touches no dedup position.
#[test]
fn a_reseed_walks_declines_ride_the_lane_ahead_of_the_overflow() {
  let mut map = seeded_with_sub();
  let decoded = DecodeOutcome {
    events: vec![modify_under(fid(2), b"f")],
    lossy: true,
  };
  let declined = vec![
    bind_boundary("/root/bound"),
    subvolume_boundary("/root/vol"),
  ];
  let (sent, alive, reseeds) =
    run_process(&mut map, decoded, Some(walk_declining(declined.clone())));
  assert!(alive, "a reseeded loss keeps the stream live");
  assert_eq!(reseeds, 1, "the loss reseeded the map before signaling");
  assert_eq!(
    sent,
    vec![Sent::Boundaries(whole_root(declined)), Sent::Overflow],
    "the reseed's declines cross as their own message, before the Overflow — and \
     still no Batch precedes it"
  );
}

/// A LOSSY buffer sends the RESEED's generation and nothing else: the declines its
/// pre-barrier walks produced are DISCARDED, not merged in.
///
/// Merging them would be worse than redundant. The whole-root report is a
/// generation the core sweeps its device-only records against, so a stale
/// location carried over from a walk that ran BEFORE the barrier would be
/// re-recorded immediately after the sweep that exists to drop it — the
/// reconciliation would quietly undo itself on exactly the buffers it matters
/// most on. Everything still there is re-declined by the reseed anyway, since it
/// walks the whole root.
#[test]
fn a_lossy_buffer_sends_the_reseeds_generation_not_the_pre_barrier_declines() {
  let mut map = seeded_with_sub();
  // A move-in (whose walk declines) followed by a classified-Lossy dir-create
  // (which takes the barrier): the walk's declines exist BEFORE the reseed runs.
  let dir_create_no_target = RawFanotifyEvent {
    mask: FanMask::new(FAN_CREATE | FAN_ONDIR),
    dir_fid: Some(fid(2)),
    target_fid: None,
    name: Some(b"newdir".to_vec()),
    rename: None,
  };
  let decoded = DecodeOutcome {
    events: vec![move_in_under_sub(), dir_create_no_target],
    lossy: false,
  };
  let (sent, alive, reseeds, walks) = run_process_with_subtree(
    &mut map,
    decoded,
    Some(walk_declining(vec![bind_boundary("/root/bound")])),
    Some(walk_declining(vec![subvolume_boundary(
      "/root/sub/arrived/vol",
    )])),
  );
  assert!(alive, "a reseeded loss keeps the stream live");
  assert_eq!(walks, 1, "staging: the move-in walk ran and declined");
  assert_eq!(reseeds, 1, "staging: the classified loss took the barrier");
  assert_eq!(
    sent,
    vec![
      Sent::Boundaries(whole_root(vec![bind_boundary("/root/bound")])),
      Sent::Overflow,
    ],
    "the reseed's set alone, flagged whole-root — the move-in walk's own decline \
     is not carried into a generation it was not part of"
  );
}

/// SEAM 2, the MOVED-IN SUBTREE driver: a directory moved in from OUTSIDE the
/// root brings its own boundaries with it, and this walk is the only thing that
/// will ever look at them.
///
/// The declines go out AHEAD of the buffer's own events, so a boundary is in the
/// coverage set before any event under the moved-in subtree is delivered.
#[test]
fn a_moved_in_subtree_walks_declines_ride_the_lane_ahead_of_the_batch() {
  let mut map = seeded_with_sub();
  let decoded = DecodeOutcome {
    events: vec![move_in_under_sub()],
    lossy: false,
  };
  let declined = vec![subvolume_boundary("/root/sub/arrived/vol")];
  let (sent, alive, reseeds, walks) = run_process_with_subtree(
    &mut map,
    decoded,
    Some(one_entry_walk()),
    Some(walk_declining(declined.clone())),
  );
  assert!(alive);
  assert_eq!(reseeds, 0, "a clean move-in never triggers a reseed");
  assert_eq!(walks, 1, "the moved-in subtree was walked exactly once");
  assert_eq!(
    sent,
    vec![Sent::Boundaries(partial(declined)), Sent::Batch(1)],
    "the move-in walk's declines precede the rename this buffer forwards"
  );
}

/// A CLEAN buffer whose walks declined NOTHING puts nothing on the lane — the
/// control leg, and the reason every other clean cell in this suite still reads a
/// bare `[Sent::Batch(..)]`.
///
/// Clean is the operative word. This buffer's report is PARTIAL (a moved-in
/// subtree walk saw one subtree), and an empty partial report carries no
/// information at all, so it is suppressed. A LOSSY buffer's report is
/// whole-root, and an empty one of those is a real statement — "no boundary
/// anywhere under this root" — so it is always sent (see
/// `lossy_buffer_forwards_only_the_overflow_after_reseeding`).
#[test]
fn a_buffer_whose_walks_decline_nothing_sends_no_boundary_message() {
  let mut map = seeded_with_sub();
  let decoded = DecodeOutcome {
    events: vec![move_in_under_sub()],
    lossy: false,
  };
  let (sent, _alive, _reseeds, walks) = run_process_with_subtree(
    &mut map,
    decoded,
    Some(one_entry_walk()),
    Some(one_entry_walk()),
  );
  assert_eq!(walks, 1, "staging: the subtree walk did run");
  assert_eq!(
    sent,
    vec![Sent::Batch(1)],
    "no declines, no message — the seam costs an empty buffer nothing: {sent:?}"
  );
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
    vec![Sent::Boundaries(whole_root(Vec::new())), Sent::Overflow],
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
    vec![Sent::Boundaries(whole_root(Vec::new())), Sent::Overflow],
    "loss barrier: no Batch precedes the Overflow, and no Fatal is signaled"
  );
}

/// **F2**: a buffer's accumulated DECLINES do not shrink the map budget the next
/// move-in walk in that buffer is handed. Two budgets, two numbers, and neither is
/// ever subtracted from the other.
///
/// `max_map_directories` is a PUBLIC option whose documented meaning is the size
/// of the admission map. A walk's declines cost `PathBuf`s in a report vector and
/// seed no map node at all, so charging them against that option makes a legal
/// configuration behave illegally: a move-in burst hands each later walk less room
/// than the map actually has, and a subtree that fits the cap perfectly well fails
/// its fence, fails its retry, and drops the whole buffer through the loss/reseed
/// ladder. The accumulator IS bounded — by its own allowance, asserted below —
/// just never by spending the map's.
#[test]
fn a_buffers_declines_never_shrink_the_next_walks_map_budget() {
  let mut map = FidMap::with_capacity(Some(64));
  map.seed([
    SeedEntry::root(fid(1), Path::new("/root")),
    SeedEntry::child(fid(2), fid(1), std::ffi::OsString::from("sub")),
  ]);
  // Two DISTINCT directories moved in under `/root/sub` in one buffer: each is
  // learned and each owes its own descendant walk.
  let decoded = DecodeOutcome {
    events: vec![
      move_in_named(fid(2), fid(5), b"X"),
      move_in_named(fid(2), fid(6), b"Y"),
    ],
    lossy: false,
  };

  let stats = BackendStatsShared::default();
  let transport = TransportState::new(8);
  let handed = std::cell::RefCell::new(Vec::new());
  let exit = process_decoded(
    decoded,
    &mut map,
    &BufferContext {
      report: ReportContext {
        stats: &stats,
        transport: &transport,
      },
      exclusions: &[],
      frame_epoch: HEARD_EPOCH,
    },
    report_credit(&transport),
    || Ok(one_entry_walk()),
    |_, _, budget, declines| {
      handed.borrow_mut().push((budget, declines));
      // Three boundaries and no admitted directory: the map does not grow across
      // the walk itself, so the ONLY thing that can move the second walk's map
      // budget is the directory the second move-in learned.
      Ok(WalkSeed {
        entries: Vec::new(),
        declined: vec![
          bind_boundary("/root/sub/X/a"),
          bind_boundary("/root/sub/X/b"),
          bind_boundary("/root/sub/X/c"),
        ],
        fence_mnt_id: WALKED_SUBTREE_MNT_ID,
      })
    },
    |_| true,
    &|| false,
  );
  assert!(
    alive_of(exit),
    "two ordinary move-ins do not kill the stream"
  );

  let handed = handed.into_inner();
  assert_eq!(handed.len(), 2, "both move-ins drove a walk: {handed:?}");
  let (first_budget, first_declines) = handed[0];
  let first_budget = first_budget.expect("a capped map hands the walk a budget");
  // The MAP budget moves by exactly one: the directory the second move-in itself
  // learned. Not by four — the three declines the first walk reported are not map
  // nodes and may not be charged here.
  assert_eq!(
    handed[1].0,
    Some(first_budget - 1),
    "the second walk is handed the room the MAP actually has left; charging the \
     first walk's three declines against it would hand it {:?}",
    Some(first_budget - 1 - 3)
  );
  // The DECLINE allowance is where those three are charged, and it is the one
  // that bounds the buffer-wide accumulator: without a share of it, the vector
  // every walk in the buffer appends to would be bounded only by
  // `renames-in-buffer x MAX_WALK_DECLINES`.
  assert_eq!(
    first_declines, MAX_WALK_DECLINES,
    "the first walk in a buffer has the whole allowance"
  );
  assert_eq!(
    handed[1].1,
    MAX_WALK_DECLINES - 3,
    "and the second is handed what the first left of it"
  );
}

/// **F2's own arithmetic**, from the finding: cap 10, a map three directories
/// long, three declines already accumulated in this buffer, and a five-directory
/// subtree moved in. Seven map slots are genuinely free and five are needed, so
/// this must SUCCEED — under the coupling the walk saw four and the buffer died
/// through the loss ladder for nothing.
///
/// The stub walk applies `fence_entries`' own rule (`entries.len() >= budget`,
/// checked before each push, so an `n`-entry walk aborts exactly when
/// `budget < n`) rather than a shape of its own, because the whole cell is about
/// which NUMBER reaches that rule.
#[test]
fn a_five_directory_move_in_fits_the_room_the_map_has_left() {
  // One seeded directory, so the SECOND move-in's learn puts the map at exactly
  // three — the finding's map length.
  let mut map = FidMap::with_capacity(Some(10));
  map.seed([SeedEntry::root(fid(1), Path::new("/root"))]);
  let decoded = DecodeOutcome {
    events: vec![
      move_in_named(fid(1), fid(5), b"X"),
      move_in_named(fid(1), fid(6), b"Y"),
    ],
    lossy: false,
  };

  let stats = BackendStatsShared::default();
  let transport = TransportState::new(8);
  let sent = std::cell::RefCell::new(Vec::new());
  let budgets = std::cell::RefCell::new(Vec::new());
  let walks = Cell::new(0u32);
  let reseeds = Cell::new(0u32);
  let exit = process_decoded(
    decoded,
    &mut map,
    &BufferContext {
      report: ReportContext {
        stats: &stats,
        transport: &transport,
      },
      exclusions: &[],
      frame_epoch: HEARD_EPOCH,
    },
    report_credit(&transport),
    || {
      reseeds.set(reseeds.get() + 1);
      Ok(one_entry_walk())
    },
    |_, subtree_fid, budget, _| {
      walks.set(walks.get() + 1);
      // The FIRST move-in is the one that accumulates the three declines; it
      // admits nothing.
      if walks.get() == 1 {
        return Ok(WalkSeed {
          entries: Vec::new(),
          declined: vec![
            bind_boundary("/root/X/a"),
            bind_boundary("/root/X/b"),
            bind_boundary("/root/X/c"),
          ],
          fence_mnt_id: WALKED_SUBTREE_MNT_ID,
        });
      }
      budgets.borrow_mut().push(budget);
      let entries: Vec<SeedEntry> = (0..5u8)
        .map(|n| {
          SeedEntry::child(
            fid(10 + n),
            subtree_fid.clone(),
            std::ffi::OsString::from(format!("d{n}")),
          )
        })
        .collect();
      // `fence_entries`, verbatim: it runs before each push, so a walk producing
      // `entries.len()` of them aborts exactly when the budget is smaller.
      if budget.is_some_and(|budget| budget < entries.len()) {
        return Err(io::Error::other("the walk exceeded the directory budget"));
      }
      Ok(WalkSeed {
        entries,
        declined: Vec::new(),
        fence_mnt_id: WALKED_SUBTREE_MNT_ID,
      })
    },
    |msg| {
      sent.borrow_mut().push(match msg {
        SourceMessage::Batch(payload) => Sent::Batch(payload.events.len()),
        SourceMessage::Boundaries(boundaries, _) => Sent::Boundaries(boundaries),
        SourceMessage::Admitted(report) => Sent::Admitted(report),
        SourceMessage::RootRecovered(recovery, _) => Sent::RootRecovered(recovery),
        SourceMessage::Overflow(_) => Sent::Overflow,
        SourceMessage::Fatal(_) => Sent::Fatal,
      });
      true
    },
    &|| false,
  );

  assert!(
    alive_of(exit),
    "a subtree that fits the cap is not a terminal"
  );
  // The HARM first, because it is what the coupling actually cost: the walk that
  // fit was refused, refused again on its retry, and the whole buffer went down
  // the loss ladder — a dropped batch, a full whole-map reseed, and an `Overflow`
  // sending the consumer to re-read the entire root, all avoidable.
  let sent = sent.into_inner();
  assert_eq!(
    (reseeds.get(), walks.get()),
    (0, 2),
    "no loss ladder: one walk per move-in, no retry, and no whole-map reseed"
  );
  assert_eq!(
    sent,
    vec![
      Sent::Boundaries(partial(vec![
        bind_boundary("/root/X/a"),
        bind_boundary("/root/X/b"),
        bind_boundary("/root/X/c"),
      ])),
      Sent::Batch(2),
    ],
    "both move-ins are delivered behind the boundaries the first walk declined, \
     and NOTHING is covered — an Overflow here is the avoidable one"
  );
  // And the arithmetic that produced it.
  assert_eq!(
    budgets.into_inner(),
    vec![Some(7)],
    "map length 3 against a cap of 10 leaves SEVEN, and this buffer's three \
     declines take none of them"
  );
}

/// A populated directory moved IN under `parent` under a caller-chosen FID and
/// name, so one buffer can carry two distinct move-ins.
fn move_in_named(parent: Fid, target: Fid, name: &[u8]) -> RawFanotifyEvent {
  RawFanotifyEvent {
    mask: FanMask::new(FAN_RENAME | FAN_ONDIR),
    dir_fid: None,
    target_fid: Some(target),
    name: None,
    rename: Some(RenameInfo {
      old_dir: fid(9),
      old_name: name.to_vec(),
      new_dir: parent,
      new_name: name.to_vec(),
    }),
  }
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
  let decoded = decode_events(&buf).expect("the buffer carries this build's metadata version");
  assert!(
    !decoded.lossy && decoded.events.len() == 1 && decoded.events[0].name.is_none(),
    "decode folded the '.' self-name to the name-less self shape"
  );

  let stats = BackendStatsShared::default();
  let transport = TransportState::new(8);
  let paths = std::cell::RefCell::new(Vec::new());
  let exit = process_decoded(
    decoded,
    &mut map,
    &BufferContext {
      report: ReportContext {
        stats: &stats,
        transport: &transport,
      },
      exclusions: &[],
      frame_epoch: HEARD_EPOCH,
    },
    report_credit(&transport),
    || Ok(one_entry_walk()),
    |_, _, _, _| Ok(WalkSeed::default()),
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
    &|| false,
  );
  assert!(
    alive_of(exit),
    "a root self-event is a clean forward, not a loss"
  );
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
    let exit = process_decoded(
      decoded,
      map,
      &BufferContext {
        report: ReportContext {
          stats: &stats,
          transport: &transport,
        },
        exclusions,
        frame_epoch: HEARD_EPOCH,
      },
      report_credit(&transport),
      || Ok(one_entry_walk()),
      |_, subtree_fid, _, _| {
        walks.set(walks.get() + 1);
        Ok(WalkSeed {
          entries: vec![SeedEntry::child(
            fid(6),
            subtree_fid.clone(),
            std::ffi::OsString::from("deep"),
          )],
          declined: Vec::new(),
          fence_mnt_id: WALKED_SUBTREE_MNT_ID,
        })
      },
      |msg| {
        sent.borrow_mut().push(match &msg {
          SourceMessage::Batch(payload) => Sent::Batch(payload.events.len()),
          SourceMessage::Boundaries(boundaries, _) => Sent::Boundaries(boundaries.clone()),
          SourceMessage::Admitted(report) => Sent::Admitted(*report),
          SourceMessage::RootRecovered(recovery, _) => Sent::RootRecovered(recovery.clone()),
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
      &|| false,
    );
    Fenced {
      forwarded: forwarded.into_inner(),
      sent: sent.into_inner(),
      alive: alive_of(exit),
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
      vec![Sent::Boundaries(whole_root(Vec::new())), Sent::Overflow],
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
/// reads, so a source that stays readable can never wedge teardown — and the
/// sibling property, that a source whose event ABI this build cannot decode is
/// abandoned rather than read forever. A real fd is needed (`/dev/zero`), so this
/// is Linux-only and off under miri; the mid-drain arrival under a live producer
/// is covered by the container smoke.
#[cfg(all(target_os = "linux", not(miri)))]
mod liveness {
  use std::{sync::mpsc, time::Duration};

  use super::super::{
    Control, DrainExit, ReaderShared, ReseedContext, control_mailbox, drain_events,
  };
  use crate::os::{
    BackendStatsShared, SourceMessage,
    linux::{fanotify::map::FidMap, wake::WakeState},
    transport::TransportState,
  };

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
    reader_shared_with(TransportState::new(8))
  }

  fn reader_shared_with(
    transport: TransportState,
  ) -> (
    ReaderShared,
    async_channel::Receiver<crate::os::SourceMessage>,
  ) {
    let (tx, rx) = async_channel::unbounded();
    let shared = ReaderShared {
      queue: tx,
      transport,
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
    let (tx, mut inbox) = control_mailbox();
    assert!(tx.send(Control::Shutdown), "the reader's inbox is live");
    let (shared, _queue_rx) = reader_shared();
    let reseed = ReseedContext::for_test(std::path::PathBuf::from("/nonexistent"));
    let mut map = FidMap::new();
    let mut buf = vec![0u8; 64 * 1024];

    let wake = WakeState::new().expect("an eventfd for the drain's shutdown check");
    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
      let exit = drain_events(&fd, &mut buf, &mut map, &reseed, &mut inbox, &shared, &wake);
      let _ = done_tx.send(exit);
    });
    let exit = done_rx
      .recv_timeout(Duration::from_secs(5))
      .expect("the drain must observe the pending shutdown, not spin on /dev/zero");
    assert_eq!(exit, DrainExit::Shutdown);
    worker.join().expect("worker joins");
  }

  /// A foreign `fanotify_event_metadata.vers` is the DESCRIPTOR's verdict, not one
  /// buffer's, and the drain must terminate on it. `/dev/zero` is exactly such a
  /// source: every 24-byte "header" it yields carries `vers = 0`, and it never
  /// returns `EAGAIN`. Routed through the loss barrier the reader would reseed the
  /// map, emit a covering `Overflow`, and read the same undecodable fd again — a
  /// cycle that re-enumerates the tree on every buffer, forever, without one
  /// notification ever being decoded and without ever saying the source is
  /// unusable. So this asserts the three halves of the terminal together: the
  /// drain DIES, the consumer's queue carries the `Fatal` and nothing else (no
  /// `Overflow` ahead of it, no `Batch`), and NO recovery walk was attempted.
  ///
  /// The reseed root is deliberately unwalkable, which is what makes the exit
  /// codes alone insufficient evidence: a regressed reader reaches the terminal
  /// too, by the long way round (loss → reseed twice → blind → `Fatal`). The
  /// reseed COUNT is what separates the two. A watchdog bounds the wait so a
  /// regression that instead spins on a walkable root fails as a timeout rather
  /// than hanging the suite.
  ///
  /// MUTATION WITNESS: hand the verdict to the loss path instead of the terminal
  /// (a `lossy` outcome out of the `Err` arm) and this FAILS at `a foreign ABI
  /// version never reseeds` with `left: 1, right: 0` — the drain still ends up
  /// dead, but by the long way round, through the recovery this cell forbids.
  #[test]
  fn a_foreign_metadata_version_terminates_the_drain() {
    let fd = never_eagain_fd();
    // No control message: only the ABI verdict can end this drain.
    let (_tx, mut inbox) = control_mailbox();
    let (shared, queue_rx) = reader_shared();
    let stats = std::sync::Arc::clone(&shared.stats);
    let reseed = ReseedContext::for_test(std::path::PathBuf::from("/nonexistent"));
    let mut map = FidMap::new();
    let mut buf = vec![0u8; 64 * 1024];

    let wake = WakeState::new().expect("an eventfd for the drain's shutdown check");
    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
      let exit = drain_events(&fd, &mut buf, &mut map, &reseed, &mut inbox, &shared, &wake);
      let _ = done_tx.send(exit);
    });
    let exit = done_rx
      .recv_timeout(Duration::from_secs(5))
      .expect("a foreign metadata version must abandon the fd, not read it forever");
    assert_eq!(exit, DrainExit::Died);
    worker.join().expect("worker joins");

    assert_eq!(
      stats.snapshot().reseeds(),
      0,
      "a foreign ABI version never reseeds — there is no map to repair, only an fd to abandon"
    );
    assert!(
      matches!(queue_rx.try_recv(), Ok(SourceMessage::Fatal(_))),
      "the terminal is the FIRST thing the consumer sees — no recoverable Overflow precedes it"
    );
    assert!(
      queue_rx.try_recv().is_err(),
      "and the only thing: the source is done, not covered and continuing"
    );
  }

  /// **R14 F2, through the real drain.** The credit the event path reserves is
  /// claimed BEFORE the read, which is the whole of what makes waiting for it
  /// honest: the events are still in the kernel's own queue, so a producer that
  /// "cannot defer" has somewhere to leave them after all.
  ///
  /// The fd is `/dev/zero` — always readable, never `EAGAIN`, and undecodable. A
  /// reader that reached the read would die on the ABI verdict; a reader that
  /// answered the terminal for a full counter would die on that. This one PARKS,
  /// having read nothing, and a shutdown still preempts the park — teardown JOINS
  /// this thread, so a wait that outranked it would wedge the join.
  ///
  /// The shutdown is raised only once the reader is observably parked, so the cell
  /// tests the wait rather than racing it: a drain that dies instead of parking, or
  /// reads instead of reserving, never reaches the park at all and fails on the
  /// spot with its own exit rather than on a clock.
  ///
  /// MUTATION WITNESS (die for a full counter): answer `ReportCredit::Closed` from
  /// the exhausted-counter path and this FAILS at `the drain PARKS on credit rather
  /// than dying for it` with `Died` — the R14 F2 defect, reached through the real
  /// reader.
  /// MUTATION WITNESS (read first, reserve later): move the reservation below the
  /// `read` and this FAILS at the same assertion with `Died` — the ABI verdict,
  /// which can only fire once a buffer has been taken out of the kernel with no
  /// slot to report its walk on.
  #[test]
  fn a_credit_less_drain_parks_before_the_read_and_a_shutdown_preempts_it() {
    let fd = never_eagain_fd();
    // No control message: only the credit wait and the shutdown decide this drain.
    let (_tx, mut inbox) = control_mailbox();
    // ONE report slot on the event path's counter, and it is spent below.
    let (shared, queue_rx) = reader_shared_with(TransportState::with_report_budget(8, 1, None));
    let stats = std::sync::Arc::clone(&shared.stats);
    let reserved = crate::os::transport::BudgetPermit::acquire_boundaries(&shared.transport)
      .expect("staging: the one report slot is free, and is now spent");

    let reseed = ReseedContext::for_test(std::path::PathBuf::from("/nonexistent"));
    let mut map = FidMap::new();
    let mut buf = vec![0u8; 64 * 1024];
    let wake = WakeState::new().expect("an eventfd for the drain's credit wait");

    std::thread::scope(|scope| {
      let (done_tx, done_rx) = mpsc::channel();
      let waker = &wake;
      scope.spawn(move || {
        let exit = drain_events(&fd, &mut buf, &mut map, &reseed, &mut inbox, &shared, waker);
        let _ = done_tx.send(exit);
      });

      // Wait for the PARK, not for a duration: a drain that died or read instead
      // never reaches it, and says so with its own exit.
      let deadline = std::time::Instant::now() + Duration::from_secs(5);
      while !wake.is_parked() {
        if let Ok(exit) = done_rx.try_recv() {
          panic!(
            "the drain PARKS on credit rather than dying for it — a full counter \
             is a driver that has not been polled yet, and the events this one \
             would report on are still in the kernel: {exit:?}"
          );
        }
        assert!(
          std::time::Instant::now() < deadline,
          "the drain must reach the credit wait"
        );
        std::thread::yield_now();
      }

      // Teardown outranks the wait, exactly as it outranks every long op here.
      wake.request_shutdown();
      wake.wake();
      let exit = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("a shutdown must preempt the credit wait, or `shutdown` wedges on the join");
      assert_eq!(
        exit,
        DrainExit::Shutdown,
        "and it leaves by the shutdown, not by a terminal"
      );
    });
    drop(reserved);

    assert!(
      queue_rx.try_recv().is_err(),
      "the consumer sees NOTHING: no terminal for a counter that was merely full, \
       and no loss standing in for evidence that was never produced"
    );
    assert_eq!(
      stats.snapshot().reseeds(),
      0,
      "and nothing was read: this fd would have driven the ABI verdict on its \
       first buffer, which is only reachable past the reservation"
    );
  }

  /// The one report condition that IS still terminal: a closed receiver.
  ///
  /// With no consumer the permits behind the queued reports may never be released
  /// at all, and no report could be delivered if a slot did come back — so the wait
  /// has no edge left and parking on it is a hang rather than back-pressure. That
  /// is a fact about the consumer, and it is what the old rung was reaching for
  /// when it read a full counter as one.
  ///
  /// A watchdog bounds the wait so the failure this forbids — a park on an edge
  /// nothing can produce — fails as a timeout instead of hanging the suite.
  ///
  /// MUTATION WITNESS (wait for a consumer that is gone): delete the
  /// `receiver_closed()` check in `reserve_report_credit` and this FAILS at `the
  /// drain must not park on credit no consumer will return: Timeout`.
  #[test]
  fn a_credit_less_drain_with_no_consumer_takes_the_terminal() {
    let fd = never_eagain_fd();
    let (_tx, mut inbox) = control_mailbox();
    let (shared, queue_rx) = reader_shared_with(TransportState::with_report_budget(8, 1, None));
    let reserved = crate::os::transport::BudgetPermit::acquire_boundaries(&shared.transport)
      .expect("staging: the one report slot is free, and is now spent");
    // Closed, not dropped: the buffered messages — and the permits inside them —
    // stay exactly where they are, which is the state a wait could never leave.
    queue_rx.close();

    let reseed = ReseedContext::for_test(std::path::PathBuf::from("/nonexistent"));
    let mut map = FidMap::new();
    let mut buf = vec![0u8; 64 * 1024];
    let wake = WakeState::new().expect("an eventfd for the drain's credit wait");
    let (done_tx, done_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
      let exit = drain_events(&fd, &mut buf, &mut map, &reseed, &mut inbox, &shared, &wake);
      let _ = done_tx.send(exit);
    });
    let exit = done_rx
      .recv_timeout(Duration::from_secs(5))
      .expect("the drain must not park on credit no consumer will return");
    assert_eq!(
      exit,
      DrainExit::Died,
      "a consumer that is gone ends the source: there is no edge left to wait on \
       and nothing to deliver if there were"
    );
    worker.join().expect("worker joins");
    drop(reserved);
  }
}
