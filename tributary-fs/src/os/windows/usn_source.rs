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
fn seed_walk(
  canonical: &Path,
  root_frn: u128,
  max_directories: Option<usize>,
) -> Result<FrnMap, ProbeStage> {
  const ATTEMPTS: usize = 3;
  for _ in 0..ATTEMPTS {
    let root = match ffi::open_directory(canonical) {
      Ok(root) => root,
      Err(_) => return Err(ProbeStage::Walk),
    };
    match ffi::identity_of(root.as_handle()) {
      Ok(identity) if identity.file_id == root_frn => {}
      _ => return Err(ProbeStage::Walk),
    }
    let mut map = FrnMap::new(root_frn, max_directories);
    match walk_under(&mut map, canonical.to_path_buf(), root, root_frn) {
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
  anchor_frn: u128,
) -> Result<(), WalkStall> {
  let mut page = vec![0u8; 64 * 1024];
  let mut queue: Vec<(PathBuf, OwnedHandle, u128)> = vec![(anchor_path, anchor, anchor_frn)];
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
        match map.learn(child.frn, dir_frn, name.clone()) {
          super::usn::map::LearnOutcome::Learned => {}
          _ => return Err(WalkStall::Broken),
        }
        // The one per-child open, immediately verified against the
        // ENUMERATED id: an impostor at the joined path mismatches.
        let child_path = dir_path.join(&name);
        let opened = match ffi::open_directory(&child_path) {
          Ok(opened) => opened,
          Err(_) => return Err(WalkStall::Vanished),
        };
        match ffi::identity_of(opened.as_handle()) {
          Ok(identity) if identity.file_id == child.frn => {}
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
fn walk_into(map: &mut FrnMap, dir: &Path, frn: u128) -> Result<(), ()> {
  let anchor = ffi::open_directory(dir).map_err(|_| ())?;
  let anchor_identity = ffi::identity_of(anchor.as_handle()).map_err(|_| ())?;
  if anchor_identity.file_id != frn {
    return Err(());
  }
  walk_under(map, dir.to_path_buf(), anchor, frn).map_err(|_| ())
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
