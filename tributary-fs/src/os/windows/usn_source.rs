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
  let mut map = FrnMap::new(root_frn, max_directories);
  let mut queue = vec![(canonical.to_path_buf(), root_frn)];
  while let Some((dir_path, dir_frn)) = queue.pop() {
    let entries = match std::fs::read_dir(&dir_path) {
      Ok(entries) => entries,
      Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
      Err(_) => return Err(ProbeStage::Walk),
    };
    for entry in entries {
      let Ok(entry) = entry else {
        return Err(ProbeStage::Walk);
      };
      let Ok(kind) = entry.file_type() else {
        continue;
      };
      if !kind.is_dir() || kind.is_symlink() {
        continue;
      }
      let child_path = entry.path();
      let Ok(child) = ffi::open_directory(&child_path) else {
        if child_path.exists() {
          return Err(ProbeStage::Walk);
        }
        continue;
      };
      // A reparse point (junction/mount) is a containment boundary: never
      // descended, never mapped.
      if ffi::is_reparse_point(child.as_handle()).unwrap_or(true) {
        continue;
      }
      let Ok(child_identity) = ffi::identity_of(child.as_handle()) else {
        return Err(ProbeStage::Walk);
      };
      let name = entry.file_name();
      let Some(name) = name.to_str() else {
        // A directory whose name has no Unicode spelling cannot anchor
        // resolvable children: completeness refuses, the probe falls.
        return Err(ProbeStage::Walk);
      };
      map.seed([(child_identity.file_id, dir_frn, name.to_owned())]);
      queue.push((child_path, child_identity.file_id));
    }
  }
  Ok(map)
}

/// What the journal pump owns: the pinned I/O state of one volume stream.
struct JournalIo {
  volume: OwnedHandle,
  port: OwnedHandle,
  journal_id: u64,
  cursor: i64,
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
  let facts = ffi::query_journal(volume.as_handle()).map_err(|_| ProbeStage::JournalActive)?;
  if facts.min_major > 3 || facts.max_major < 2 {
    return Err(ProbeStage::JournalActive);
  }
  let map = seed_walk(&canonical, identity.file_id, config.max_map_directories)?;

  // The probe held: everything past here is a hard spawn outcome.
  Ok(start(
    config,
    canonical,
    root_handle,
    identity,
    volume,
    facts,
    map,
  ))
}

fn start(
  config: &SourceConfig,
  canonical: PathBuf,
  root_handle: &OwnedHandle,
  identity: ffi::HandleIdentity,
  volume: OwnedHandle,
  facts: ffi::JournalFacts,
  map: FrnMap,
) -> Result<(SourceHandle, EventReceiver, RootMeta), SourceError> {
  let port = ffi::iocp_new().map_err(|_| SourceError::CreateFailed)?;
  ffi::iocp_associate(port.as_handle(), volume.as_handle(), KEY_READ)
    .map_err(|_| SourceError::CreateFailed)?;

  let buffer_len = (config.channel_capacity.get().max(1) * 1024).clamp(4 * 1024, 64 * 1024);
  let mut io_state = JournalIo {
    volume,
    port,
    journal_id: facts.journal_id,
    // Live-only: history is the consumer's crawl, exactly like FSEvents'
    // SinceNow default.
    cursor: facts.next_usn,
    read: Box::new(unsafe { std::mem::zeroed() }),
    buffer: vec![0u8; buffer_len].into_boxed_slice(),
    overlapped: Box::new(unsafe { std::mem::zeroed() }),
  };
  io_state.issue().map_err(|_| SourceError::StartFailed)?;

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
  let pump = spawn_pump(io_state, admission, canonical.clone(), Arc::clone(&shared))?;
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
) -> Result<std::thread::JoinHandle<()>, SourceError> {
  std::thread::Builder::new()
    .name("tributary-fs.usn".into())
    .spawn(move || {
      let mut io_state = io_state;
      let mut admission = admission;
      let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run(&mut io_state, &mut admission, &root, &shared);
      }));
      if outcome.is_err() {
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
        shared.fatal(SourceError::ReadFailed { source: err });
        return;
      }
    };
    match completion {
      ffi::Completion::TimedOut => continue,
      ffi::Completion::Packet {
        key: KEY_CONTROL, ..
      } => {
        // Stop-belt → cancel → drain the read's final completion → drop.
        ffi::cancel_io(io_state.volume.as_handle());
        let _ = ffi::iocp_wait(io_state.port.as_handle(), 5_000);
        return;
      }
      ffi::Completion::Packet { bytes, error, .. } => {
        if let Some(code) = error {
          if shared.stopped() {
            return;
          }
          // Journal-side truncation (wrap, purge, ID change) funnels into
          // the reseed spine; a journal that cannot be re-anchored (deleted,
          // inactive) is terminal.
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
        if decoded.lossy {
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
  transport::signal_loss::<SourceEvent, _>(&shared.transport, |msg| shared.send(msg));
  let Ok(facts) = ffi::query_journal(io_state.volume.as_handle()) else {
    return false;
  };
  let root_frn = {
    let Ok(handle) = ffi::open_directory(root) else {
      return false;
    };
    match ffi::identity_of(handle.as_handle()) {
      Ok(identity) => identity.file_id,
      Err(_) => return false,
    }
  };
  let Ok(map) = seed_walk(root, root_frn, None) else {
    return false;
  };
  io_state.journal_id = facts.journal_id;
  io_state.cursor = facts.next_usn;
  *admission.map_mut() = map;
  true
}
