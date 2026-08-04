//! The USN journal source: the per-volume probe, the seed walk, and a pump
//! whose reads ride the durable journal.
//!
//! The journal reshapes the pump in one way: the next read's cursor comes
//! from the CURRENT buffer's header, so reissue-before-parse is impossible —
//! and unnecessary. Records wait in the journal between reads (durability is
//! the buffer), so the pump runs parse → advance cursor → reissue on one
//! pinned buffer, and a reseed walk running on the pump thread pauses
//! delivery without losing anything. Every journal-side truncation (wrap,
//! purge, ID change) funnels into one spine: in-band loss → fresh walk →
//! cursor re-anchor at the live edge, with the covering rescan owning the
//! walk window.

use std::{
  io,
  os::windows::io::{AsHandle, AsRawHandle, OwnedHandle},
  path::{Component, Path, PathBuf},
  sync::{Arc, atomic::AtomicBool},
};

use windows_sys::Win32::{
  Foundation::HANDLE,
  Storage::FileSystem::GetVolumeInformationByHandleW,
  System::{IO::OVERLAPPED, Ioctl::READ_USN_JOURNAL_DATA_V1},
};

use super::{
  super::{
    EventReceiver, ProbeStage, Quiesce, ResumeToken, RootMeta, SourceConfig, SourceError,
    SourceEvent, SpawnFailed,
    transport::{self, TransportState},
  },
  DRAIN_LIMIT_MS, DRAIN_PACKET_BUDGET, DrainStep, RawWindowsEvent, contained_pump,
  drain_to_pin_end, ffi,
  source::{KEY_CONTROL, KEY_READ, PumpShared, SourceHandle},
  usn::{RenameSemantics, UsnAdmission, UsnAdmitted, UsnFence, map::FrnMap},
};

/// The session-table cap (a noise filter; eviction re-reports, never loses).
const SESSION_CAP: usize = 1024;

/// The drive letter of a canonical root, if a disk prefix names one.
fn drive_of(root: &Path) -> Option<char> {
  for component in root.components() {
    if let Component::Prefix(prefix) = component {
      use std::path::Prefix;
      return match prefix.kind() {
        Prefix::VerbatimDisk(letter) | Prefix::Disk(letter) => Some(letter as char),
        _ => None,
      };
    }
  }
  None
}

/// Whether the volume behind `root` is the filesystem the journal's rename
/// accounting was MEASURED on — the fact that scopes the repeat-rename
/// retirement to the evidence licensing it.
///
/// The journal probe above admits any volume with an active journal speaking
/// record version 2 or 3, and that is a wider set than the measurement covers:
/// ReFS emits V3 and has never been observed here. The measurement (see
/// [`usn`](super::usn)) renamed one file twice through one held handle on NTFS
/// and watched the two rename bits ALTERNATE; a filesystem whose bits instead
/// ACCUMULATE would write a second move's word and have the delta discard it,
/// which is silence. So the arm asks WHICH filesystem before it spends the
/// retirement.
///
/// `GetVolumeInformationByHandleW` answers it from the ROOT'S OWN OPEN HANDLE —
/// the one already bracketed, identity-verified, and proven a directory on a
/// disk device. No path is re-resolved and no second object can be swapped in
/// behind the answer, which is the same rule every other fact this barrier
/// establishes is read under. It is asked of the handle rather than of the
/// `\\.\X:` device because the documented contract is a handle to a FILE OR
/// DIRECTORY, and the root is one.
///
/// EVERY FAILURE IS [`Unmeasured`](RenameSemantics::Unmeasured), and none of
/// them is a spawn failure. An old build, a filesystem that will not answer, a
/// name longer than the buffer: each leaves the volume unproven, which costs the
/// old cover rate and nothing else. Refusing the arm over an unanswered query
/// would trade a working source for a question that has a conservative answer.
fn rename_semantics_of(root: &OwnedHandle) -> RenameSemantics {
  // Long enough for every filesystem name Windows ships and its terminator;
  // a name that does not fit fails the call, which is already conservative.
  let mut name = [0u16; 32];
  // SAFETY: the handle is live and borrowed for the call; `name` is a writable
  // buffer whose element count is passed as the size; every optional output the
  // call is not asked for is null, which the API documents as "not wanted".
  let answered = unsafe {
    GetVolumeInformationByHandleW(
      root.as_raw_handle() as HANDLE,
      std::ptr::null_mut(),
      0,
      std::ptr::null_mut(),
      std::ptr::null_mut(),
      std::ptr::null_mut(),
      name.as_mut_ptr(),
      name.len() as u32,
    )
  };
  if answered == 0 {
    return RenameSemantics::Unmeasured;
  }
  let len = name
    .iter()
    .position(|unit| *unit == 0)
    .unwrap_or(name.len());
  if String::from_utf16_lossy(&name[..len]).eq_ignore_ascii_case("NTFS") {
    RenameSemantics::Measured
  } else {
    RenameSemantics::Unmeasured
  }
}

/// Why a walk stalled.
enum WalkStall {
  /// The walked world moved underneath the walk (a vanished or replaced
  /// object, an identity mismatch, the anchor dying): the seed walk
  /// restarts its whole attempt, a live walk escalates to the reseed
  /// spine. There is deliberately NO benign-skip outcome.
  Vanished,
  /// An indeterminate or refusing outcome (a lossy enumeration page, an
  /// unnameable directory, the cap): the walk fails closed.
  Broken,
}

/// Walks the subtree under `canonical`, building the directory-FRN map by
/// HANDLE-BOUND enumeration: children are listed through each directory's
/// retained handle (`FileIdExtdDirectoryInfo` — names, attributes, and
/// 128-bit ids come from the enumeration itself), and the only per-child
/// open is immediately verified against the enumerated FRN. No path is
/// ever re-opened to LIST anything, so a replacement directory installed
/// at a walked path can never be enumerated in the original's place; a
/// verify mismatch is a [`WalkStall::Vanished`]. The tree mutating under
/// the walk restarts the whole attempt — no local repair is complete.
///
/// `fence` is the caller's exclusions: an excluded directory is never learned
/// and never descended, so a preexisting excluded subtree consumes none of the
/// directory cap — the same guarantee the live stream's fence gives.
fn seed_walk(
  canonical: &Path,
  root_identity: ffi::HandleIdentity,
  max_directories: Option<usize>,
  fence: &UsnFence,
) -> Result<FrnMap, ProbeStage> {
  const ATTEMPTS: usize = 3;
  for _ in 0..ATTEMPTS {
    let root = match ffi::open_directory(canonical) {
      Ok(root) => root,
      Err(_) => return Err(ProbeStage::Walk),
    };
    // The FULL identity — file ids are unique only within a volume, so an
    // FRN-alone match could bless a same-numbered object elsewhere.
    match ffi::identity_of(root.as_handle()) {
      Ok(identity) if identity == root_identity => {}
      _ => return Err(ProbeStage::Walk),
    }
    let mut map = FrnMap::new(root_identity.file_id, max_directories);
    match walk_under(
      &mut map,
      canonical.to_path_buf(),
      root,
      root_identity,
      fence,
    ) {
      Ok(()) => return Ok(map),
      Err(WalkStall::Vanished) => continue,
      Err(WalkStall::Broken) => return Err(ProbeStage::Walk),
    }
  }
  Err(ProbeStage::Walk)
}

/// The shared handle-bound walk core: enumerates `anchor` (already
/// identity-verified by the caller) and every mapped descendant through
/// their retained handles, learning each directory child by its enumerated
/// FRN before its own (verified) open.
fn walk_under(
  map: &mut FrnMap,
  anchor_path: PathBuf,
  anchor: OwnedHandle,
  anchor_identity: ffi::HandleIdentity,
  fence: &UsnFence,
) -> Result<(), WalkStall> {
  let volume_serial = anchor_identity.volume_serial;
  let mut page = vec![0u8; 64 * 1024];
  let mut queue: Vec<(PathBuf, OwnedHandle, u128)> =
    vec![(anchor_path, anchor, anchor_identity.file_id)];
  while let Some((dir_path, handle, dir_frn)) = queue.pop() {
    let mut restart = true;
    loop {
      let filled = match ffi::read_directory_page(handle.as_handle(), &mut page, restart) {
        Ok(Some(len)) => len,
        Ok(None) => break,
        // The handle is live by construction, so an enumeration failure is
        // the object dying underneath it (dismount, delete-pended): the
        // world moved.
        Err(_) => return Err(WalkStall::Vanished),
      };
      restart = false;
      let decoded = super::dirscan::decode_page(&page[..filled]);
      if decoded.lossy {
        return Err(WalkStall::Broken);
      }
      for child in decoded.children {
        if !child.is_dir() {
          continue;
        }
        if child.is_reparse() {
          // A containment boundary: never descended, never mapped.
          continue;
        }
        let Some(name) = child.name else {
          // A directory whose name has no Unicode spelling can never
          // anchor resolvable children: fail closed.
          return Err(WalkStall::Broken);
        };
        let child_path = dir_path.join(&name);
        // THE EXCLUSION FENCE, ahead of the learn AND of the per-child open:
        // an excluded directory is not in the reported tree, so it costs no
        // map entry, no handle and no descent, and the churn inside it can
        // never consume the cap the rest of the tree competes for.
        if fence.excludes_path(&child_path) {
          continue;
        }
        match map.learn(child.frn, dir_frn, name.clone()) {
          super::usn::map::LearnOutcome::Learned => {}
          _ => return Err(WalkStall::Broken),
        }
        // The one per-child open: NO-FOLLOW (a reparse point that raced
        // in must be seen as itself, never resolved to a foreign target)
        // and verified against the ENUMERATED id on the WATCHED volume —
        // an impostor at the joined path mismatches on either coordinate.
        let opened = match ffi::open_directory_no_follow(&child_path) {
          Ok(opened) => opened,
          Err(_) => return Err(WalkStall::Vanished),
        };
        // A reparse point that appeared since the enumeration is a
        // containment boundary the enumeration missed: the world moved.
        match ffi::is_reparse_point(opened.as_handle()) {
          Ok(false) => {}
          Ok(true) | Err(_) => return Err(WalkStall::Vanished),
        }
        match ffi::identity_of(opened.as_handle()) {
          Ok(identity)
            if identity.file_id == child.frn && identity.volume_serial == volume_serial => {}
          _ => return Err(WalkStall::Vanished),
        }
        queue.push((child_path, opened, child.frn));
      }
    }
  }
  Ok(())
}

/// Walks one moved-in (or revealed) subtree into the live map: the anchor's
/// identity is verified against the requested FRN, then the shared
/// handle-bound core walks below it. Any stall — vanished paths, identity
/// mismatches, lossy pages — escalates to the caller, whose one answer is
/// the full reseed spine.
fn walk_into(
  map: &mut FrnMap,
  dir: &Path,
  frn: u128,
  volume_serial: u64,
  fence: &UsnFence,
) -> Result<(), ()> {
  // No-follow: a moved-in reparse point must be seen as itself — its
  // TARGET (possibly another volume, possibly a same-numbered FRN there)
  // is never walked.
  let anchor = ffi::open_directory_no_follow(dir).map_err(|_| ())?;
  match ffi::is_reparse_point(anchor.as_handle()) {
    Ok(false) => {}
    Ok(true) | Err(_) => return Err(()),
  }
  let anchor_identity = ffi::identity_of(anchor.as_handle()).map_err(|_| ())?;
  if anchor_identity.file_id != frn || anchor_identity.volume_serial != volume_serial {
    return Err(());
  }
  walk_under(map, dir.to_path_buf(), anchor, anchor_identity, fence).map_err(|_| ())
}

/// What the journal pump owns: the pinned I/O state of one volume stream.
struct JournalIo {
  volume: OwnedHandle,
  /// A SECOND volume handle, never associated with the port: every
  /// re-query runs on it, so no query completion can ever be dequeued as
  /// (or ahead of) the one outstanding read's packet.
  query: OwnedHandle,
  port: OwnedHandle,
  journal_id: u64,
  cursor: i64,
  /// The volume the journal belongs to — half of the scope a resume cursor is
  /// only ever honored under (a file id is unique only within a volume, and so
  /// is a USN).
  volume_serial: u64,
  /// The startup identity of the watched root: every reseed re-open must
  /// still name THIS object, or the scope would silently rebind to a
  /// replacement tree while the original root's death goes unreported.
  root_identity: ffi::HandleIdentity,
  /// The configured directory cap, preserved across reseeds.
  max_directories: Option<usize>,
  /// The caller's exclusions, resolved against the root — consulted by every
  /// walk this pump runs (the reseed's fresh one and every moved-in subtree),
  /// exactly as the admission consults its own copy on the live stream.
  fence: UsnFence,
  read: Box<READ_USN_JOURNAL_DATA_V1>,
  buffer: Box<[u8]>,
  overlapped: Box<OVERLAPPED>,
}

// SAFETY: the embedded raw pointers are owned by the enclosed boxes; the
// struct is moved ONCE into the pump thread and never shared; the kernel
// writes through them strictly between an issue and the dequeued completion
// the pump alone observes.
unsafe impl Send for JournalIo {}

impl JournalIo {
  /// Issues the next journal read from the cursor (P2: the previous read's
  /// completion was dequeued, or nothing was ever issued).
  fn issue(&mut self) -> io::Result<()> {
    *self.read = READ_USN_JOURNAL_DATA_V1 {
      StartUsn: self.cursor,
      ReasonMask: u32::MAX,
      ReturnOnlyOnClose: 0,
      Timeout: 0,
      BytesToWaitFor: 1,
      UsnJournalID: self.journal_id,
      MinMajorVersion: 2,
      MaxMajorVersion: 3,
    };
    *self.overlapped = unsafe { std::mem::zeroed() };
    // SAFETY: request/buffer/OVERLAPPED are boxed fields of self, address
    // stable and untouched until this issue's completion is dequeued (the
    // P1 pin); one read outstanding per volume (the caller's proof).
    unsafe {
      ffi::issue_journal_read(
        self.volume.as_handle(),
        &raw mut *self.read,
        &mut self.buffer,
        &raw mut *self.overlapped,
      )
    }
  }
}

/// Starts the journal arm for an already-bracketed root.
///
/// `Err(stage)` = a probe precondition failed (Auto falls back; a forced
/// journal surfaces it typed). `Ok(Err(_))` = the probe held but the spawn
/// failed hard — surfaced on every selection path, and carrying the live pump
/// back when the failure came after the stream started.
#[allow(clippy::type_complexity)]
pub(super) fn spawn(
  config: &SourceConfig,
  canonical: PathBuf,
  root_handle: &OwnedHandle,
  identity: ffi::HandleIdentity,
) -> Result<Result<(SourceHandle, EventReceiver, RootMeta), SpawnFailed<SourceHandle>>, ProbeStage>
{
  let Some(drive) = drive_of(&canonical) else {
    return Err(ProbeStage::VolumeAccess);
  };
  let volume = ffi::open_volume(drive).map_err(|_| ProbeStage::VolumeAccess)?;
  // The query twin: never port-associated, so its completions can never be
  // dequeued as the outstanding read's packet.
  let query = ffi::open_volume(drive).map_err(|_| ProbeStage::VolumeAccess)?;
  let facts = ffi::query_journal(query.as_handle()).map_err(|_| ProbeStage::JournalActive)?;
  if facts.min_major > 3 || facts.max_major < 2 {
    return Err(ProbeStage::JournalActive);
  }
  // Read at the barrier, off the same handle that proved the root's kind and
  // identity, because this is the point where the retirement is granted or
  // withheld and the only point that can see the volume at all.
  let renames = rename_semantics_of(root_handle);
  let fence = UsnFence::new(canonical.clone(), config.exclusions.clone());
  let map = seed_walk(&canonical, identity, config.max_map_directories, &fence)?;

  // The probe held: everything past here is a hard spawn outcome.
  let probed = ProbedVolume {
    volume,
    query,
    facts,
    renames,
  };
  Ok(start(
    config,
    canonical,
    root_handle,
    identity,
    probed,
    map,
    fence,
  ))
}

/// What the probe hands the starter: the two volume handles, the journal facts
/// they were probed with, and whether this volume's filesystem is the one the
/// rename measurement was taken on.
struct ProbedVolume {
  volume: OwnedHandle,
  query: OwnedHandle,
  facts: ffi::JournalFacts,
  renames: RenameSemantics,
}

fn start(
  config: &SourceConfig,
  canonical: PathBuf,
  root_handle: &OwnedHandle,
  identity: ffi::HandleIdentity,
  probed: ProbedVolume,
  map: FrnMap,
  fence: UsnFence,
) -> Result<(SourceHandle, EventReceiver, RootMeta), SpawnFailed<SourceHandle>> {
  let ProbedVolume {
    volume,
    query,
    facts,
    renames,
  } = probed;
  let port = ffi::iocp_new().map_err(|_| SourceError::CreateFailed)?;
  ffi::iocp_associate(port.as_handle(), volume.as_handle(), KEY_READ)
    .map_err(|_| SourceError::CreateFailed)?;

  let buffer_len = config.os_buffer_bytes.get() as usize;
  // A retiring stream's cursor, honored only against the SAME journal instance
  // on the SAME volume: a deleted-and-recreated journal gets a fresh id, and a
  // cursor below `first_usn` names history the journal already purged (the read
  // would refuse it), above `next_usn` names records that do not exist. Anything
  // unhonorable falls back to the live edge — history is the consumer's crawl,
  // exactly like FSEvents' SinceNow default — and the commit `Rescan` covers the
  // window either way.
  //
  // An honored cursor is deliberately BELOW the live edge, so the first reads
  // replay history against a map the seed walk built from the tree as it stands
  // NOW. That is not a consistent cut and cannot be made into one: no walk is
  // atomic against a live volume. Replayed structural records may therefore
  // contradict the map — a historical create whose parent has since moved
  // beneath its own child is the sharp case — and the reconciliation is
  // `LearnOutcome::Inconsistent` → `UsnAdmitted::MapInconsistent` → the reseed
  // spine, which answers with an ordered loss, a fresh walk, and a re-anchor at
  // the live edge. Applying such a link instead knotted the parent chain and
  // hung the pump.
  let cursor = config
    .since
    .and_then(|token| token.usn_cursor(facts.journal_id, identity.volume_serial))
    .filter(|usn| (facts.first_usn..=facts.next_usn).contains(usn))
    .unwrap_or(facts.next_usn);
  let io_state = JournalIo {
    volume,
    query,
    port,
    journal_id: facts.journal_id,
    cursor,
    volume_serial: identity.volume_serial,
    root_identity: identity,
    max_directories: config.max_map_directories,
    fence: fence.clone(),
    read: Box::new(unsafe { std::mem::zeroed() }),
    buffer: vec![0u8; buffer_len].into_boxed_slice(),
    overlapped: Box::new(unsafe { std::mem::zeroed() }),
  };

  let (queue_tx, queue_rx) = async_channel::unbounded();
  let shared = Arc::new(PumpShared {
    queue: queue_tx,
    transport: TransportState::new(config.channel_capacity.get()),
    stopped: AtomicBool::new(false),
    resume: Arc::default(),
  });
  let control_port = io_state
    .port
    .try_clone()
    .map_err(|_| SourceError::CreateFailed)?;
  // The retirement applies where its premise was proven, and this is the only
  // caller that can say whether it was.
  let admission = UsnAdmission::new(map, SESSION_CAP)
    .with_fence(fence)
    .with_rename_semantics(renames);
  // The startup handshake: the pump reports its first issue before spawn
  // can commit, so a refused journal read is a SPAWN failure, never a
  // successful-but-dead source.
  let (started_tx, started_rx) = std::sync::mpsc::sync_channel::<bool>(1);
  let pump = spawn_pump(
    io_state,
    admission,
    canonical.clone(),
    Arc::clone(&shared),
    started_tx,
  )?;
  if !started_rx.recv().unwrap_or(false) {
    // A join hands back the pump's panic payload exactly as `catch_unwind`
    // does, and discarding it with `let _ =` DROPS it — running the
    // panicking code's own destructor here rather than inside a boundary.
    if let Err(payload) = pump.join() {
      let _ = tributary_proto::unwind::dispose_panic_payload(payload);
    }
    return Err(SourceError::StartFailed.into());
  }
  let source_handle = SourceHandle::assemble(pump, control_port, shared);

  // The post-live re-proof: the pinned handle's object cannot change, so
  // the check re-opens the PATH — bytes now reaching a different object
  // than the delivering stream watches must not be committed.
  //
  // From here the stream is LIVE, and no failure below tears it down here.
  // This pump's journal read is overlapped exactly like the RDCW pump's, so a
  // rollback drain that cannot prove the read's completion was dequeued RETAINS
  // the pinned request, buffer and `OVERLAPPED` rather than freeing what the
  // kernel may still write, and answers `Unproven`. Discarding that answer
  // reported the retention as nothing: no `TeardownFailed` reached the driver,
  // so nothing counted the retained state, bounded admission over it, or kept
  // `close` from claiming quiescence. The running stream therefore rides back
  // out with the error (see [`SpawnFailed`](super::super::SpawnFailed)) into
  // the driver's counted teardown submission.
  match ffi::open_directory(&canonical).and_then(|live| ffi::identity_of(live.as_handle())) {
    Ok(live_identity) if live_identity == identity => {}
    Ok(_) => {
      return Err(SpawnFailed::rolled_back(
        SourceError::RootReplaced { root: canonical },
        source_handle,
      ));
    }
    Err(source) => {
      return Err(SpawnFailed::rolled_back(
        SourceError::RootUnavailable {
          root: canonical,
          source,
        },
        source_handle,
      ));
    }
  }

  let mut ancestors = Vec::new();
  for ancestor in canonical.ancestors().skip(1) {
    if ancestor.as_os_str().is_empty() {
      break;
    }
    match ffi::open_directory(ancestor).and_then(|opened| ffi::identity_of(opened.as_handle())) {
      Ok(ancestor_identity) => ancestors.push(super::super::RootIdentity::new(
        ancestor_identity.volume_serial,
        ancestor_identity.file_id,
      )),
      Err(source) => {
        return Err(SpawnFailed::rolled_back(
          SourceError::RootUnavailable {
            root: ancestor.to_path_buf(),
            source,
          },
          source_handle,
        ));
      }
    }
  }

  let _ = root_handle;
  let meta = RootMeta {
    root: canonical,
    root_dev: identity.volume_serial,
    root_mnt_id: None,
    mounts: Vec::new(),
    identity: super::super::RootIdentity::new(identity.volume_serial, identity.file_id),
    ancestors,
    backend: super::super::BackendKind::UsnJournal,
  };
  Ok((source_handle, queue_rx, meta))
}

/// Starts the journal pump thread. The thread's value is its quiescence
/// verdict, which the shared `SourceHandle` reads out of the join.
fn spawn_pump(
  io_state: JournalIo,
  admission: UsnAdmission,
  root: PathBuf,
  shared: Arc<PumpShared>,
  started: std::sync::mpsc::SyncSender<bool>,
) -> Result<std::thread::JoinHandle<Quiesce>, SourceError> {
  std::thread::Builder::new()
    .name("tributary-fs.usn".into())
    .spawn(move || {
      let mut io_state = io_state;
      let mut admission = admission;
      // The FIRST issue happens here, after every fallible setup step: no
      // pinned read can exist for a spawn that fails to start its pump.
      // The handshake makes the outcome part of the spawn barrier.
      if io_state.issue().is_err() {
        let _ = started.send(false);
        // A refused issue queues no I/O, so no pin was ever taken and this
        // drop frees nothing the kernel holds.
        return Quiesce::Proven;
      }
      let _ = started.send(true);
      contained_pump(
        io_state,
        |io_state| run(io_state, &mut admission, &root, &shared),
        || shared.fatal(SourceError::CallbackPanic),
      )
    })
    .map_err(|_| SourceError::StartFailed)
}

/// Forwards one admitted batch, staging `reached` — the cursor the journal has
/// been read up TO — as the batch's resume candidate. The candidate becomes the
/// stream's resume point only when the driver ingests this batch, so a batch the
/// budget dropped or the queue still holds leaves a successor re-reading that
/// span. A batch that admitted nothing enqueues nothing and therefore publishes
/// nothing: the successor replays a wider, duplicate-only window rather than a
/// position no ingest ever proved.
fn forward(
  shared: &PumpShared,
  events: Vec<UsnAdmitted>,
  lossy: bool,
  reached: Option<ResumeToken>,
) {
  let events: Vec<SourceEvent> = events
    .into_iter()
    .map(|event| SourceEvent::Windows(RawWindowsEvent::Usn(event)))
    .collect();
  transport::forward_batch_resuming(
    &shared.transport,
    events,
    lossy,
    reached.map(|token| (&shared.resume, token)),
    |msg| shared.send(msg),
  );
}

/// The map's cap died on a live learn: the fanotify cap-death shape.
fn cap_exceeded_error() -> io::Error {
  io::Error::other(
    "the USN directory map exceeded its cap on a live create/move-in; the source cannot keep learning",
  )
}

/// The pump loop: parse → advance → reissue on the durable journal.
///
/// Returns whether the exit PROVED the outstanding read's pin ended. Every arm
/// but the two drains reaches its `return` having just dequeued that read's
/// own completion with no reissue behind it, so the pin is provably closed and
/// the I/O state may drop; the drains answer for themselves.
fn run(
  io_state: &mut JournalIo,
  admission: &mut UsnAdmission,
  root: &Path,
  shared: &PumpShared,
) -> Quiesce {
  loop {
    let completion = match ffi::iocp_wait(io_state.port.as_handle(), u32::MAX) {
      Ok(completion) => completion,
      Err(err) => {
        // A wait failure dequeued NOTHING: the outstanding read's pin is
        // unproven, so the teardown drain (cancel → drain-to-exact →
        // leak-on-failure) must run before the I/O state can drop.
        shared.fatal(SourceError::ReadFailed { source: err });
        return teardown_drain(io_state);
      }
    };
    match completion {
      ffi::Completion::TimedOut => continue,
      ffi::Completion::Packet {
        key: KEY_CONTROL, ..
      } => {
        return teardown_drain(io_state);
      }
      ffi::Completion::Packet {
        bytes,
        error,
        overlapped,
        ..
      } => {
        if overlapped != (&raw mut *io_state.overlapped).cast() {
          // Not the outstanding read's packet: a stray completion must
          // never be decoded as (or advance the cursor of) the read.
          debug_assert!(false, "a stray packet reached the journal pump");
          continue;
        }
        if let Some(code) = error {
          if shared.stopped() {
            // This IS the outstanding read's own failed completion (the
            // overlapped check above proved it), so dequeuing it is the same
            // proof the drain goes looking for.
            return Quiesce::Proven;
          }
          // Journal-side truncation (wrap, purge, ID change) funnels into
          // the reseed spine (which widows the carry and resets sessions
          // first); a journal that cannot be re-anchored is terminal.
          if !reseed(io_state, admission, root, shared) {
            shared.fatal(SourceError::ReadFailed {
              source: io::Error::from_raw_os_error(code),
            });
            return Quiesce::Proven;
          }
          if io_state.issue().is_err() {
            shared.fatal(SourceError::StartFailed);
            return Quiesce::Proven;
          }
          continue;
        }

        let decoded = super::usn::decode::decode_journal(&io_state.buffer[..bytes as usize]);
        let mut admitted = Vec::new();
        // Admission STOPS at the first verdict that ends the batch's trust —
        // the map contradicted, the map overfull, or the root dead — and
        // discards the rest of the buffer. Every one of those lowers to a
        // cover the consumer re-reads at; records admitted AFTER it would be
        // resolved through the very topology it disowns, and a consumer that
        // re-read at the cover and then applied them diverged again on the
        // spot. The verdict is the batch's last word instead.
        let verdict = admission.admit_batch(decoded.records, &mut admitted);
        if decoded.lossy {
          // The carry's partner may sit in the refused remainder: widow it
          // ahead of the loss signal `forward` is about to raise. A stopped
          // batch already widowed its carry ahead of the cover, so this is a
          // no-op there — never a widow landing behind the cover.
          admission.flush(&mut admitted);
        }
        // Moved-in subtrees demand their walks BEFORE later records are
        // read: journal order resumes against a map that knows them. The
        // walk anchors at the FRN's CURRENT map location (a later record in
        // the same buffer may have reparented it — the event's captured
        // target is the RESCAN's location, never the walk's), and a
        // directory the map no longer knows was moved out again: nothing
        // left to walk.
        //
        // A stopped batch skips them outright: this map is about to be
        // replaced wholesale (or abandoned with the source), so walking into
        // it buys nothing and its stalls would only manufacture loss the
        // in-band cover already carries.
        let mut walk_failed = false;
        if verdict.is_none() {
          for event in &admitted {
            if let UsnAdmitted::MovedInSubtree { frn, .. } = event {
              let Some(components) = admission.map_mut().resolve_dir(*frn) else {
                continue;
              };
              let mut path = root.to_path_buf();
              for component in &components {
                path.push(component);
              }
              if walk_into(
                admission.map_mut(),
                &path,
                *frn,
                io_state.root_identity.volume_serial,
                &io_state.fence,
              )
              .is_err()
              {
                walk_failed = true;
              }
            }
          }
        }
        let map_died = admitted
          .iter()
          .any(|event| matches!(event, UsnAdmitted::MapOverflow));
        // A record that contradicted the map is NOT the cap's death: the map
        // is stale, and the reseed spine is what repairs a stale map. It takes
        // the same treatment as a failed walk — the root cover was already
        // planned in-band, the span is not a place to resume from, and the
        // fresh walk re-anchors everything after it.
        let map_stale = admitted
          .iter()
          .any(|event| matches!(event, UsnAdmitted::MapInconsistent));
        let root_died = admitted
          .iter()
          .any(|event| matches!(event, UsnAdmitted::RootDeath));
        // The position this read reached. A walk that failed (or a map that
        // contradicted itself) leaves the map wrong for everything after it,
        // so its span is not a place to come back to; `forward` itself
        // discards the candidate on a lossy read.
        let reached =
          (!walk_failed && !map_stale && decoded.next_usn > io_state.cursor).then(|| {
            ResumeToken::usn(
              io_state.journal_id,
              decoded.next_usn,
              io_state.volume_serial,
            )
          });
        forward(shared, admitted, decoded.lossy, reached);
        if map_died {
          shared.fatal(SourceError::ReadFailed {
            source: cap_exceeded_error(),
          });
          return Quiesce::Proven;
        }
        if root_died {
          // The in-band terminal was delivered; the stream ends silently
          // (the core's death lifecycle owns the rest).
          return Quiesce::Proven;
        }
        if decoded.lossy || walk_failed || map_stale {
          if !reseed(io_state, admission, root, shared) {
            shared.fatal(SourceError::StartFailed);
            return Quiesce::Proven;
          }
        } else if decoded.next_usn > io_state.cursor {
          io_state.cursor = decoded.next_usn;
        }
        if io_state.issue().is_err() {
          // The completed read's packet was dequeued and its successor was
          // refused, so nothing is pinned.
          shared.fatal(SourceError::StartFailed);
          return Quiesce::Proven;
        }
      }
    }
  }
}

/// The loss spine: in-band loss first, then a fresh walk and a cursor
/// re-anchor at the live edge (the covering rescan owns the walk window —
/// delivery pauses on the durable journal, nothing is lost). `false` = the
/// journal itself is gone; the caller goes fatal.
fn reseed(
  io_state: &mut JournalIo,
  admission: &mut UsnAdmission,
  root: &Path,
  shared: &PumpShared,
) -> bool {
  // The pairing carry predates the gap: widow it in-band FIRST, and drop
  // the cumulative-reason history whose CLOSEs may sit inside the gap.
  let mut widowed = Vec::new();
  admission.flush(&mut widowed);
  // The widowed carry predates the gap: it belongs to the OLD cursor, so it
  // stages nothing. The re-anchor below is published only by the batches read
  // after it.
  forward(shared, widowed, false, None);
  admission.reset_sessions();
  transport::signal_loss::<SourceEvent, _>(&shared.transport, |msg| shared.send(msg));
  let Ok(facts) = ffi::query_journal(io_state.query.as_handle()) else {
    return false;
  };
  {
    let Ok(handle) = ffi::open_directory(root) else {
      return false;
    };
    match ffi::identity_of(handle.as_handle()) {
      // The re-opened path must still name the STARTUP object: a
      // replacement here is the original root's death, never a rebind.
      Ok(identity) if identity == io_state.root_identity => {}
      _ => return false,
    }
  }
  let Ok(map) = seed_walk(
    root,
    io_state.root_identity,
    io_state.max_directories,
    &io_state.fence,
  ) else {
    return false;
  };
  io_state.journal_id = facts.journal_id;
  io_state.cursor = facts.next_usn;
  *admission.map_mut() = map;
  true
}

/// The teardown drain: cancel the outstanding read, then consume its final
/// completion so the pin provably ends before the handles close. A drain
/// that cannot prove the end LEAKS the pinned boxes — the kernel may still
/// write through them, so freeing would be the bug.
///
/// The leak is granular on purpose: only the request, the buffer and the
/// `OVERLAPPED` are retained, while the two volume handles and the port still
/// close with the I/O state. Closing a handle with a pending overlapped
/// operation cancels it and lets the kernel complete it into the retained
/// `OVERLAPPED`, which is exactly what the retention is for.
///
/// `Unproven` is the verdict on every path that reaches that leak — a
/// cancellation whose completion never arrived within the bound, a wait that
/// failed, and a budget spent on strays are indistinguishable from outside,
/// and all three end with kernel-owned memory retained. Reporting them as a
/// completed teardown is what let repeated failures leak without ever being
/// counted.
fn teardown_drain(io_state: &mut JournalIo) -> Quiesce {
  ffi::cancel_io(io_state.volume.as_handle());
  // Bound the pin's identity BEFORE the drain borrows the port: the
  // OVERLAPPED cannot move (it is boxed) and the pump issues nothing more.
  let pinned: *mut OVERLAPPED = &raw mut *io_state.overlapped;
  let port = io_state.port.as_handle();
  let verdict = drain_to_pin_end(DRAIN_PACKET_BUDGET, || {
    match ffi::iocp_wait(port, DRAIN_LIMIT_MS) {
      Ok(ffi::Completion::Packet { overlapped, .. }) if overlapped == pinned.cast() => {
        DrainStep::PinEnded
      }
      Ok(ffi::Completion::Packet { .. }) => DrainStep::Stray,
      Ok(ffi::Completion::TimedOut) | Err(_) => DrainStep::Exhausted,
    }
  });
  if verdict == Quiesce::Proven {
    return verdict;
  }
  let buffer = std::mem::replace(&mut io_state.buffer, Vec::new().into_boxed_slice());
  Box::leak(buffer);
  let read = std::mem::replace(&mut io_state.read, Box::new(unsafe { std::mem::zeroed() }));
  Box::leak(read);
  let overlapped = std::mem::replace(
    &mut io_state.overlapped,
    Box::new(unsafe { std::mem::zeroed() }),
  );
  Box::leak(overlapped);
  verdict
}
