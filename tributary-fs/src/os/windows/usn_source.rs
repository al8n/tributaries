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
  os::windows::io::{AsHandle, OwnedHandle},
  path::{Component, Path, PathBuf},
  sync::{Arc, atomic::AtomicBool},
};

use windows_sys::Win32::System::{IO::OVERLAPPED, Ioctl::READ_USN_JOURNAL_DATA_V1};

use super::{
  super::{
    EventReceiver, ProbeStage, RootMeta, SourceConfig, SourceError, SourceEvent,
    transport::{self, TransportState},
  },
  RawWindowsEvent, ffi,
  source::{KEY_CONTROL, KEY_READ, PumpShared, SourceHandle},
  usn::{UsnAdmission, UsnAdmitted, map::FrnMap},
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

/// Walks the subtree under `canonical`, building the directory-FRN map.
/// One open per directory (the batched id-enumeration is a recorded
/// deferral); a directory that vanishes mid-walk is a benign race, an
/// unreadable EXISTING one refuses completeness.
fn seed_walk(
  canonical: &Path,
  root_frn: u128,
  max_directories: Option<usize>,
) -> Result<FrnMap, ProbeStage> {
  // A queued directory whose path stops opening mid-walk means the tree
  // mutated under the walk — and not necessarily AT that directory: an
  // ANCESTOR rename strands every queued descendant's stale path while the
  // ancestor itself stays mapped, so replay would reparent it with no walk
  // owed. No local repair is complete; the walk restarts against the tree
  // as it now is, and refuses if the churn outruns it.
  const ATTEMPTS: usize = 3;
  'attempt: for _ in 0..ATTEMPTS {
    let mut map = FrnMap::new(root_frn, max_directories);
    let mut queue = vec![(canonical.to_path_buf(), root_frn)];
    while let Some((dir_path, dir_frn)) = queue.pop() {
      let entries = match std::fs::read_dir(&dir_path) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound && dir_frn != root_frn => {
          continue 'attempt;
        }
        Err(_) => return Err(ProbeStage::Walk),
      };
      for entry in entries {
        let entry = entry.map_err(|_| ProbeStage::Walk)?;
        admit_walk_entry(&mut map, &mut queue, &entry, dir_frn).map_err(|_| ProbeStage::Walk)?;
      }
    }
    return Ok(map);
  }
  Err(ProbeStage::Walk)
}

/// Walks one moved-in subtree into the live map (the seed walk's shape,
/// anchored at the moved directory). The anchor's identity is verified
/// against the requested FRN — a missing or replaced anchor, like every
/// indeterminate metadata failure below it, is an error: the caller
/// escalates to the full reseed spine rather than run blind.
fn walk_into(map: &mut FrnMap, dir: &Path, frn: u128) -> Result<(), ()> {
  let anchor = ffi::open_directory(dir).map_err(|_| ())?;
  let anchor_identity = ffi::identity_of(anchor.as_handle()).map_err(|_| ())?;
  if anchor_identity.file_id != frn {
    return Err(());
  }
  drop(anchor);
  let mut queue = vec![(dir.to_path_buf(), frn)];
  while let Some((dir_path, dir_frn)) = queue.pop() {
    let entries = match std::fs::read_dir(&dir_path) {
      Ok(entries) => entries,
      // A verified (or already-mapped) directory whose path no longer
      // opens was renamed between verification and enumeration: its
      // descendants would stay unmapped while the map carries the top —
      // a blind subtree. The walk refuses; the reseed spine re-walks the
      // world as it now is. (The probe-time seed walk may skip a vanished
      // directory — nothing depends on its map yet and the cursor
      // pre-dates the walk — but a LIVE walk may not.)
      Err(_) => return Err(()),
    };
    for entry in entries {
      match admit_walk_entry(map, &mut queue, &entry.map_err(|_| ())?, dir_frn) {
        Ok(()) => {}
        Err(()) => return Err(()),
      }
    }
  }
  Ok(())
}

/// One walk entry's admission, shared by the seed walk and the live subtree
/// walk: directories admit (or the walk refuses), files skip, and every
/// indeterminate metadata outcome is a refusal — an unreadable EXISTING
/// directory must never become a silently unmapped subtree.
fn admit_walk_entry(
  map: &mut FrnMap,
  queue: &mut Vec<(PathBuf, u128)>,
  entry: &std::fs::DirEntry,
  dir_frn: u128,
) -> Result<(), ()> {
  let kind = entry.file_type().map_err(|_| ())?;
  if !kind.is_dir() || kind.is_symlink() {
    return Ok(());
  }
  let child_path = entry.path();
  let child = match ffi::open_directory(&child_path) {
    Ok(child) => child,
    Err(_) => {
      // Only a PROVEN disappearance is a benign race; an access-denied or
      // indeterminate probe is a completeness refusal.
      return match child_path.try_exists() {
        Ok(false) => Ok(()),
        Ok(true) | Err(_) => Err(()),
      };
    }
  };
  // A reparse point (junction/mount) is a containment boundary: never
  // descended, never mapped. An indeterminate query refuses.
  if ffi::is_reparse_point(child.as_handle()).map_err(|_| ())? {
    return Ok(());
  }
  let child_identity = ffi::identity_of(child.as_handle()).map_err(|_| ())?;
  let name = entry.file_name();
  let Some(name) = name.to_str() else {
    return Err(());
  };
  match map.learn(child_identity.file_id, dir_frn, name.to_owned()) {
    super::usn::map::LearnOutcome::Learned => {}
    _ => return Err(()),
  }
  queue.push((child_path, child_identity.file_id));
  Ok(())
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
  /// The startup identity of the watched root: every reseed re-open must
  /// still name THIS object, or the scope would silently rebind to a
  /// replacement tree while the original root's death goes unreported.
  root_identity: ffi::HandleIdentity,
  /// The configured directory cap, preserved across reseeds.
  max_directories: Option<usize>,
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
/// failed hard — surfaced on every selection path.
#[allow(clippy::type_complexity)]
pub(super) fn spawn(
  config: &SourceConfig,
  canonical: PathBuf,
  root_handle: &OwnedHandle,
  identity: ffi::HandleIdentity,
) -> Result<Result<(SourceHandle, EventReceiver, RootMeta), SourceError>, ProbeStage> {
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
  let map = seed_walk(&canonical, identity.file_id, config.max_map_directories)?;

  // The probe held: everything past here is a hard spawn outcome.
  let probed = ProbedVolume {
    volume,
    query,
    facts,
  };
  Ok(start(config, canonical, root_handle, identity, probed, map))
}

/// What the probe hands the starter: the two volume handles and the
/// journal facts they were probed with.
struct ProbedVolume {
  volume: OwnedHandle,
  query: OwnedHandle,
  facts: ffi::JournalFacts,
}

fn start(
  config: &SourceConfig,
  canonical: PathBuf,
  root_handle: &OwnedHandle,
  identity: ffi::HandleIdentity,
  probed: ProbedVolume,
  map: FrnMap,
) -> Result<(SourceHandle, EventReceiver, RootMeta), SourceError> {
  let ProbedVolume {
    volume,
    query,
    facts,
  } = probed;
  let port = ffi::iocp_new().map_err(|_| SourceError::CreateFailed)?;
  ffi::iocp_associate(port.as_handle(), volume.as_handle(), KEY_READ)
    .map_err(|_| SourceError::CreateFailed)?;

  let buffer_len = (config.channel_capacity.get().max(1) * 1024).clamp(4 * 1024, 64 * 1024);
  let io_state = JournalIo {
    volume,
    query,
    port,
    journal_id: facts.journal_id,
    // Live-only: history is the consumer's crawl, exactly like FSEvents'
    // SinceNow default.
    cursor: facts.next_usn,
    root_identity: identity,
    max_directories: config.max_map_directories,
    read: Box::new(unsafe { std::mem::zeroed() }),
    buffer: vec![0u8; buffer_len].into_boxed_slice(),
    overlapped: Box::new(unsafe { std::mem::zeroed() }),
  };

  let (queue_tx, queue_rx) = async_channel::unbounded();
  let shared = Arc::new(PumpShared {
    queue: queue_tx,
    transport: TransportState::new(config.channel_capacity.get()),
    stopped: AtomicBool::new(false),
  });
  let control_port = io_state
    .port
    .try_clone()
    .map_err(|_| SourceError::CreateFailed)?;
  let admission = UsnAdmission::new(map, SESSION_CAP);
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
    let _ = pump.join();
    return Err(SourceError::StartFailed);
  }
  let source_handle = SourceHandle::assemble(pump, control_port, shared);

  // The post-live re-proof: the pinned handle's object cannot change, so
  // the check re-opens the PATH — bytes now reaching a different object
  // than the delivering stream watches must not be committed.
  match ffi::open_directory(&canonical).and_then(|live| ffi::identity_of(live.as_handle())) {
    Ok(live_identity) if live_identity == identity => {}
    Ok(_) => {
      source_handle.shutdown();
      return Err(SourceError::RootReplaced { root: canonical });
    }
    Err(source) => {
      source_handle.shutdown();
      return Err(SourceError::RootUnavailable {
        root: canonical,
        source,
      });
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
        source_handle.shutdown();
        return Err(SourceError::RootUnavailable {
          root: ancestor.to_path_buf(),
          source,
        });
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

fn spawn_pump(
  io_state: JournalIo,
  admission: UsnAdmission,
  root: PathBuf,
  shared: Arc<PumpShared>,
  started: std::sync::mpsc::SyncSender<bool>,
) -> Result<std::thread::JoinHandle<()>, SourceError> {
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
        return;
      }
      let _ = started.send(true);
      let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run(&mut io_state, &mut admission, &root, &shared);
      }));
      if outcome.is_err() {
        // A panicked pump cannot prove its read's pin ended: leak the I/O
        // state rather than drop memory the kernel may still write.
        std::mem::forget(io_state);
        shared.fatal(SourceError::CallbackPanic);
      }
    })
    .map_err(|_| SourceError::StartFailed)
}

fn forward(shared: &PumpShared, events: Vec<UsnAdmitted>, lossy: bool) {
  let events: Vec<SourceEvent> = events
    .into_iter()
    .map(|event| SourceEvent::Windows(RawWindowsEvent::Usn(event)))
    .collect();
  transport::forward_batch(&shared.transport, events, lossy, |msg| shared.send(msg));
}

/// The map's cap died on a live learn: the fanotify cap-death shape.
fn cap_exceeded_error() -> io::Error {
  io::Error::other(
    "the USN directory map exceeded its cap on a live create/move-in; the source cannot keep learning",
  )
}

/// The pump loop: parse → advance → reissue on the durable journal.
fn run(io_state: &mut JournalIo, admission: &mut UsnAdmission, root: &Path, shared: &PumpShared) {
  loop {
    let completion = match ffi::iocp_wait(io_state.port.as_handle(), u32::MAX) {
      Ok(completion) => completion,
      Err(err) => {
        // A wait failure dequeued NOTHING: the outstanding read's pin is
        // unproven, so the teardown drain (cancel → drain-to-exact →
        // leak-on-failure) must run before the I/O state can drop.
        shared.fatal(SourceError::ReadFailed { source: err });
        teardown_drain(io_state);
        return;
      }
    };
    match completion {
      ffi::Completion::TimedOut => continue,
      ffi::Completion::Packet {
        key: KEY_CONTROL, ..
      } => {
        teardown_drain(io_state);
        return;
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
            return;
          }
          // Journal-side truncation (wrap, purge, ID change) funnels into
          // the reseed spine (which widows the carry and resets sessions
          // first); a journal that cannot be re-anchored is terminal.
          if !reseed(io_state, admission, root, shared) {
            shared.fatal(SourceError::ReadFailed {
              source: io::Error::from_raw_os_error(code),
            });
            return;
          }
          if io_state.issue().is_err() {
            shared.fatal(SourceError::StartFailed);
            return;
          }
          continue;
        }

        let decoded = super::usn::decode::decode_journal(&io_state.buffer[..bytes as usize]);
        let mut admitted = Vec::new();
        for record in decoded.records {
          admission.admit(record, &mut admitted);
        }
        if decoded.lossy {
          // The carry's partner may sit in the refused remainder: widow it
          // ahead of the loss signal `forward` is about to raise.
          admission.flush(&mut admitted);
        }
        // Moved-in subtrees demand their walks BEFORE later records are
        // read: journal order resumes against a map that knows them. The
        // walk anchors at the FRN's CURRENT map location (a later record in
        // the same buffer may have reparented it — the event's captured
        // target is the RESCAN's location, never the walk's), and a
        // directory the map no longer knows was moved out again: nothing
        // left to walk.
        let mut walk_failed = false;
        for event in &admitted {
          if let UsnAdmitted::MovedInSubtree { frn, .. } = event {
            let Some(components) = admission.map_mut().resolve_dir(*frn) else {
              continue;
            };
            let mut path = root.to_path_buf();
            for component in &components {
              path.push(component);
            }
            if walk_into(admission.map_mut(), &path, *frn).is_err() {
              walk_failed = true;
            }
          }
        }
        let map_died = admitted
          .iter()
          .any(|event| matches!(event, UsnAdmitted::MapOverflow));
        let root_died = admitted
          .iter()
          .any(|event| matches!(event, UsnAdmitted::RootDeath));
        forward(shared, admitted, decoded.lossy);
        if map_died {
          shared.fatal(SourceError::ReadFailed {
            source: cap_exceeded_error(),
          });
          return;
        }
        if root_died {
          // The in-band terminal was delivered; the stream ends silently
          // (the core's death lifecycle owns the rest).
          return;
        }
        if decoded.lossy || walk_failed {
          if !reseed(io_state, admission, root, shared) {
            shared.fatal(SourceError::StartFailed);
            return;
          }
        } else if decoded.next_usn > io_state.cursor {
          io_state.cursor = decoded.next_usn;
        }
        if io_state.issue().is_err() {
          shared.fatal(SourceError::StartFailed);
          return;
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
  forward(shared, widowed, false);
  admission.reset_sessions();
  transport::signal_loss::<SourceEvent, _>(&shared.transport, |msg| shared.send(msg));
  let Ok(facts) = ffi::query_journal(io_state.query.as_handle()) else {
    return false;
  };
  let root_frn = {
    let Ok(handle) = ffi::open_directory(root) else {
      return false;
    };
    match ffi::identity_of(handle.as_handle()) {
      // The re-opened path must still name the STARTUP object: a
      // replacement here is the original root's death, never a rebind.
      Ok(identity) if identity == io_state.root_identity => identity.file_id,
      _ => return false,
    }
  };
  let Ok(map) = seed_walk(root, root_frn, io_state.max_directories) else {
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
fn teardown_drain(io_state: &mut JournalIo) {
  ffi::cancel_io(io_state.volume.as_handle());
  for _ in 0..16 {
    match ffi::iocp_wait(io_state.port.as_handle(), 5_000) {
      Ok(ffi::Completion::Packet { overlapped, .. })
        if overlapped == (&raw mut *io_state.overlapped).cast() =>
      {
        return;
      }
      Ok(ffi::Completion::Packet { .. }) => {}
      Ok(ffi::Completion::TimedOut) | Err(_) => break,
    }
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
}
