//! The RDCW source: the spawn barrier and the per-source pump thread.
//!
//! One directory handle per root, one completion port per source, one pump
//! thread that owns the whole OVERLAPPED lifecycle — issue, completion,
//! cancellation, drain — behind the transport channel. Control reaches the
//! pump exclusively as posted packets on its own port, so control and I/O are
//! one totally ordered lane and no parked/wake handshake exists to get wrong;
//! the packet IS the wakeup.
//!
//! The pump invariants this module is audited against:
//! - **Buffer pin**: from a successful issue until its completion (or its
//!   failed-completion packet) is dequeued, the kernel owns the buffer and
//!   OVERLAPPED — both are boxed and never touched in between, and a drain
//!   that cannot prove the pin's end LEAKS them rather than freeing under a
//!   pending write.
//! - **Single outstanding read, reissue-before-parse**: exactly one read is
//!   pending per handle; the alternate buffer's read is issued before the
//!   completed buffer is decoded, so the lost window between completion and
//!   reissue is one decode, not one decode plus one forward.
//! - **Loss is ordered and in-band**: overflow (zero-byte completion or
//!   `ERROR_NOTIFY_ENUM_DIR`), decode refusal, and widowed rename halves are
//!   forwarded at their queue position through the transport's
//!   `forward_batch`/`signal_loss`; a held OLD widows BEFORE the loss signal
//!   that postdates it.
//! - **The stream never goes quiet without a message**: every terminal path
//!   emits exactly one in-band `Fatal` — except the driver's own shutdown,
//!   the one silent exit.
//! - **Cancellation is never death**: `ERROR_OPERATION_ABORTED` packets are
//!   consumed by the teardown drain, never lowered to `Fatal`.

use std::{
  io,
  os::windows::io::{AsHandle, OwnedHandle},
  sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
  },
  thread::JoinHandle,
};

use windows_sys::Win32::{Foundation::ERROR_NOTIFY_ENUM_DIR, System::IO::OVERLAPPED};

use super::{
  super::{
    EventReceiver, MAX_EXCLUSIONS, ResumeToken, RootMeta, ScopePort, SourceConfig, SourceError,
    SourceEvent, SourceMessage,
    transport::{self, TransportState},
  },
  RdcwPairer, ffi, is_unc_remote, lower_rdcw_buffer,
};

/// The completion key of the one directory (or volume) read.
pub(super) const KEY_READ: usize = 1;
/// The completion key of a posted control (shutdown) packet.
pub(super) const KEY_CONTROL: usize = 2;

/// How long a held rename OLD half waits for its NEW before widowing — the
/// pump-side pairing window. Bounded and small: adjacency is the documented
/// delivery shape, so a cross-buffer partner arrives with the very next
/// completion or not at all.
const PAIRING_WINDOW_MS: u32 = 20;

/// How long the teardown drain waits for the cancelled read's final
/// completion before declaring the pin unprovable and leaking the buffers.
const DRAIN_LIMIT_MS: u32 = 5_000;

/// What the pump thread owns: the pinned I/O state of one directory stream.
struct PumpIo {
  /// The watched directory, OVERLAPPED-opened.
  handle: OwnedHandle,
  /// The completion port every completion and control packet arrives on.
  port: OwnedHandle,
  /// The two read buffers (P1: boxed, address-stable).
  buffers: [Box<[u8]>; 2],
  /// Each buffer's OVERLAPPED, zeroed between uses (P1: boxed).
  overlapped: [Box<OVERLAPPED>; 2],
  /// Which buffer the outstanding read targets.
  active: usize,
  /// Whether reads use the extended (identity-carrying) record layout.
  extended: bool,
}

// SAFETY: `OVERLAPPED` embeds raw pointers, which strips the auto-impl, but
// every pointer in this struct is either null or owned by the enclosed boxes;
// the whole struct is moved ONCE into the pump thread and never shared, and
// the kernel's writes through the OVERLAPPED happen strictly between an issue
// and the dequeued completion the pump alone observes.
unsafe impl Send for PumpIo {}

impl PumpIo {
  /// Issues the next read into `buffers[active]` (P2: the caller has proven
  /// no read is outstanding — the previous completion was dequeued, or
  /// nothing was ever issued).
  fn issue(&mut self) -> io::Result<()> {
    *self.overlapped[self.active] = unsafe { std::mem::zeroed() };
    let overlapped: *mut OVERLAPPED = &raw mut *self.overlapped[self.active];
    // SAFETY: the buffer and OVERLAPPED are boxed fields of self, address
    // stable and untouched until the completion for this issue is dequeued
    // (the P1 pin); at most one read is outstanding (the caller's proof).
    unsafe {
      ffi::issue_read(
        self.handle.as_handle(),
        &mut self.buffers[self.active],
        self.extended,
        overlapped,
      )
    }
  }
}

/// The state the spawn shares with the pump thread and the handle.
pub(super) struct PumpShared {
  pub(super) queue: async_channel::Sender<SourceMessage>,
  pub(super) transport: TransportState,
  /// The stop belt: raised by `shutdown` before the control post, so a pump
  /// that dequeues ANY packet after it knows the source is closing.
  pub(super) stopped: AtomicBool,
}

impl PumpShared {
  pub(super) fn send(&self, msg: SourceMessage) -> bool {
    self.queue.try_send(msg).is_ok()
  }

  pub(super) fn fatal(&self, err: SourceError) {
    transport::signal_fatal_once(&self.transport, err, |msg| self.send(msg));
  }

  /// Whether the stop belt is raised (teardown is in progress).
  pub(super) fn stopped(&self) -> bool {
    self.stopped.load(Ordering::Acquire)
  }
}

/// The spawn entry point of the RDCW backend.
pub(crate) struct Source;

impl Source {
  /// Starts one RDCW stream per the barrier: canonicalize → locality →
  /// pinned open → object bracket → first issue (the extended-vs-basic
  /// probe) → pump → post-live re-proof.
  pub(crate) fn spawn(
    config: SourceConfig,
  ) -> Result<(SourceHandle, EventReceiver, RootMeta), SourceError> {
    if config.roots.is_empty() {
      return Err(SourceError::NoRoots);
    }
    if config.exclusions.len() > MAX_EXCLUSIONS {
      return Err(SourceError::TooManyExclusions {
        supplied: config.exclusions.len(),
      });
    }

    let supplied = config.roots[0].clone();
    let canonical =
      std::fs::canonicalize(&supplied).map_err(|source| SourceError::RootUnavailable {
        root: supplied.clone(),
        source,
      })?;
    // Both Windows backends are blind (or silently lossy) on SMB: refuse a
    // remote root at the barrier, never degrade into a stream that cannot
    // keep its delivery contract.
    if is_unc_remote(&canonical) {
      return Err(SourceError::RootUnavailable {
        root: canonical,
        source: io::Error::new(
          io::ErrorKind::Unsupported,
          "network filesystems deliver no reliable events",
        ),
      });
    }

    let handle =
      ffi::open_directory(&canonical).map_err(|source| SourceError::RootUnavailable {
        root: canonical.clone(),
        source,
      })?;
    if !ffi::is_disk_object(handle.as_handle()) {
      return Err(SourceError::RootUnavailable {
        root: canonical,
        source: io::Error::new(
          io::ErrorKind::Unsupported,
          "the root is not a disk-backed object",
        ),
      });
    }
    match ffi::is_directory(handle.as_handle()) {
      Ok(true) => {}
      Ok(false) => {
        return Err(SourceError::NotADirectory { root: canonical });
      }
      Err(source) => {
        return Err(SourceError::RootUnavailable {
          root: canonical,
          source,
        });
      }
    }
    let identity =
      ffi::identity_of(handle.as_handle()).map_err(|source| SourceError::RootUnavailable {
        root: canonical.clone(),
        source,
      })?;

    // The per-root backend dispatch: the journal arm is preferred under
    // Auto (privileged, per volume) and falls to RDCW at its first failing
    // probe stage; forcing it surfaces that stage typed instead.
    match config.backend {
      super::super::Backend::UsnJournal => {
        return super::usn_source::spawn(&config, canonical, &handle, identity)
          .map_err(|stage| SourceError::BackendProbeFailed { stage })?;
      }
      super::super::Backend::Auto => {
        if let Ok(spawned) = super::usn_source::spawn(&config, canonical.clone(), &handle, identity)
        {
          return spawned;
        }
      }
      _ => {}
    }

    let port = ffi::iocp_new().map_err(|_| SourceError::CreateFailed)?;
    ffi::iocp_associate(port.as_handle(), handle.as_handle(), KEY_READ)
      .map_err(|_| SourceError::CreateFailed)?;

    let buffer_len = config.channel_capacity.get().max(1) * 1024;
    let buffer_len = buffer_len.clamp(4 * 1024, 64 * 1024);
    let io_state = PumpIo {
      handle,
      port,
      buffers: [
        vec![0u8; buffer_len].into_boxed_slice(),
        vec![0u8; buffer_len].into_boxed_slice(),
      ],
      overlapped: [
        Box::new(unsafe { std::mem::zeroed() }),
        Box::new(unsafe { std::mem::zeroed() }),
      ],
      active: 0,
      extended: true,
    };

    let (queue_tx, queue_rx) = async_channel::unbounded();
    let shared = Arc::new(PumpShared {
      queue: queue_tx,
      transport: TransportState::new(config.channel_capacity.get()),
      stopped: AtomicBool::new(false),
    });
    let control = ControlPost {
      port: io_state
        .port
        .try_clone()
        .map_err(|_| SourceError::CreateFailed)?,
    };
    // The startup handshake: the pump reports its first issue before spawn
    // can commit, so a refused stream is a SPAWN failure, never a
    // successful-but-dead source.
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel::<bool>(1);
    let pump = spawn_pump(io_state, Arc::clone(&shared), started_tx)?;
    if !started_rx.recv().unwrap_or(false) {
      let _ = pump.join();
      return Err(SourceError::StartFailed);
    }

    // From here the stream is live; failures tear it down through the one
    // proven teardown path (the handle) before rejecting.
    let source_handle = SourceHandle {
      pump: Some(pump),
      control,
      shared,
    };

    // The post-live half of the identity bracket: the pinned handle's object
    // cannot change, so the re-proof re-opens the PATH — if its bytes now
    // reach a different object than the delivering stream watches, the
    // stream anchors coverage to the wrong tree and must not be committed.
    let live = match ffi::open_directory(&canonical) {
      Ok(live) => live,
      Err(source) => {
        source_handle.shutdown();
        return Err(SourceError::RootUnavailable {
          root: canonical,
          source,
        });
      }
    };
    match ffi::identity_of(live.as_handle()) {
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
    drop(live);

    // Ancestor identities feed root-disjointness containment, read strictly
    // after the stream is live so the chain reflects the delivering stream's
    // world (the macOS bracket, byte for byte).
    let mut ancestors = Vec::new();
    for ancestor in canonical.ancestors().skip(1) {
      if ancestor.as_os_str().is_empty() {
        break;
      }
      let opened = match ffi::open_directory(ancestor) {
        Ok(opened) => opened,
        Err(source) => {
          source_handle.shutdown();
          return Err(SourceError::RootUnavailable {
            root: ancestor.to_path_buf(),
            source,
          });
        }
      };
      match ffi::identity_of(opened.as_handle()) {
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

    let meta = RootMeta {
      root: canonical,
      root_dev: identity.volume_serial,
      // Windows has no mount-id notion; the core's descent fence falls back
      // to the device (volume-serial) check on this backend.
      root_mnt_id: None,
      // No pre-start mount seed either: junction containment is enforced by
      // the reparse refusal at descent, and event-side trust stays closed
      // until the driver's post-live refresh regardless.
      mounts: Vec::new(),
      identity: super::super::RootIdentity::new(identity.volume_serial, identity.file_id),
      ancestors,
      backend: super::super::BackendKind::Rdcw,
    };
    Ok((source_handle, queue_rx, meta))
  }
}

/// The port alias `shutdown` posts its control packet through. A duplicated
/// handle, so posting races nothing the pump owns.
struct ControlPost {
  port: OwnedHandle,
}

/// A live RDCW stream. Dropping it tears the stream down; prefer
/// [`shutdown`](Self::shutdown) at an orderly exit.
pub(crate) struct SourceHandle {
  /// `None` once torn down — teardown runs exactly once.
  pump: Option<JoinHandle<()>>,
  control: ControlPost,
  shared: Arc<PumpShared>,
}

impl SourceHandle {
  /// Assembles a handle around a running pump — the journal arm builds the
  /// same teardown shape over its own thread and port.
  pub(super) fn assemble(
    pump: JoinHandle<()>,
    control_port: OwnedHandle,
    shared: Arc<PumpShared>,
  ) -> Self {
    Self {
      pump: Some(pump),
      control: ControlPost { port: control_port },
      shared,
    }
  }

  /// The resume point minted so far. RDCW has no journal to resume from.
  // Journal resume is deferred surface, mirrored across every backend.
  #[allow(dead_code)]
  pub(crate) fn resume_token(&self) -> Option<ResumeToken> {
    None
  }

  /// The clonable arm/disarm port: kernel-recursive, so no arm traffic.
  // The driver's SourceControl default already answers Inert; kept so the
  // handle surface matches its siblings.
  #[allow(dead_code)]
  pub(crate) fn scope_port(&self) -> ScopePort {
    ScopePort::Inert
  }

  /// Quiesces and destroys the stream. Blocks for at most one in-flight
  /// completion plus the bounded teardown drain.
  pub(crate) fn shutdown(mut self) {
    self.teardown();
  }

  fn teardown(&mut self) {
    let Some(pump) = self.pump.take() else {
      return;
    };
    self.shared.stopped.store(true, Ordering::Release);
    // A failed post means the port is gone — the pump is already exiting.
    let _ = ffi::iocp_post(self.control.port.as_handle(), KEY_CONTROL);
    let _ = pump.join();
  }
}

impl Drop for SourceHandle {
  fn drop(&mut self) {
    self.teardown();
  }
}

/// Starts the pump thread.
fn spawn_pump(
  io_state: PumpIo,
  shared: Arc<PumpShared>,
  started: std::sync::mpsc::SyncSender<bool>,
) -> Result<JoinHandle<()>, SourceError> {
  std::thread::Builder::new()
    .name("tributary-fs.rdcw".into())
    .spawn(move || {
      let mut io_state = io_state;
      // The FIRST issue happens here, after every fallible setup step: no
      // pinned read can exist for a spawn that fails to start its pump. It
      // doubles as the record-layout probe — a kernel or filesystem without
      // the extended class refuses the issue itself, and the stream falls
      // back to the basic layout once, before anything is delivered. The
      // handshake makes the outcome part of the spawn barrier.
      if io_state.issue().is_err() {
        io_state.extended = false;
        if io_state.issue().is_err() {
          let _ = started.send(false);
          return;
        }
      }
      let _ = started.send(true);
      let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run(&mut io_state, &shared);
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

/// The pump loop. One read outstanding at all times; completions, control
/// posts, and the pairing-window timeout are the only wakeups.
fn run(io_state: &mut PumpIo, shared: &PumpShared) {
  let mut pairer = RdcwPairer::new();
  loop {
    // A held rename OLD bounds the wait: its partner arrives with the next
    // completion or the window widows it.
    let timeout = if pairer.holds_old() {
      PAIRING_WINDOW_MS
    } else {
      u32::MAX
    };
    let completion = match ffi::iocp_wait(io_state.port.as_handle(), timeout) {
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
      ffi::Completion::TimedOut => {
        // The pairing window elapsed: widow the carry, in order.
        let mut widowed = Vec::new();
        pairer.flush(&mut widowed);
        let events = widowed
          .into_iter()
          .map(|event| SourceEvent::Windows(super::RawWindowsEvent::Rdcw(event)))
          .collect::<Vec<_>>();
        transport::forward_batch(&shared.transport, events, false, |msg| shared.send(msg));
      }
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
        debug_assert_eq!(
          overlapped,
          (&raw mut *io_state.overlapped[io_state.active]).cast(),
          "the one outstanding read completes on the active OVERLAPPED"
        );
        if let Some(code) = error {
          if code as u32 == ERROR_NOTIFY_ENUM_DIR {
            // The kernel's own overflow verdict: events were dropped and the
            // buffer holds nothing usable. Widow the carry (it predates the
            // loss), signal the loss, and keep the stream alive.
            let mut widowed = Vec::new();
            pairer.flush(&mut widowed);
            let events = widowed
              .into_iter()
              .map(|event| SourceEvent::Windows(super::RawWindowsEvent::Rdcw(event)))
              .collect::<Vec<_>>();
            transport::forward_batch(&shared.transport, events, true, |msg| shared.send(msg));
            if io_state.issue().is_err() {
              shared.fatal(SourceError::StartFailed);
              return;
            }
            continue;
          }
          if shared.stopped.load(Ordering::Acquire) {
            // A cancellation packet raced the control post: consume it and
            // exit on the control packet still in the queue — or now.
            return;
          }
          shared.fatal(SourceError::ReadFailed {
            source: io::Error::from_raw_os_error(code),
          });
          return;
        }

        // Success for the active buffer: swap and reissue BEFORE parsing.
        let completed = io_state.active;
        io_state.active ^= 1;
        if io_state.issue().is_err() {
          // The stream cannot continue; deliver what the completed buffer
          // holds, then die loudly.
          let (events, lossy) = lower_rdcw_buffer(
            &mut pairer,
            &io_state.buffers[completed][..bytes as usize],
            io_state.extended,
          );
          transport::forward_batch(&shared.transport, events, lossy, |msg| shared.send(msg));
          shared.fatal(SourceError::StartFailed);
          return;
        }

        if bytes == 0 {
          // The zero-byte success completion is the other overflow shape.
          let mut widowed = Vec::new();
          pairer.flush(&mut widowed);
          let events = widowed
            .into_iter()
            .map(|event| SourceEvent::Windows(super::RawWindowsEvent::Rdcw(event)))
            .collect::<Vec<_>>();
          transport::forward_batch(&shared.transport, events, true, |msg| shared.send(msg));
        } else {
          let (events, lossy) = lower_rdcw_buffer(
            &mut pairer,
            &io_state.buffers[completed][..bytes as usize],
            io_state.extended,
          );
          transport::forward_batch(&shared.transport, events, lossy, |msg| shared.send(msg));
        }
      }
    }
  }
}

/// The teardown drain: cancel the outstanding read, then consume its final
/// completion so the buffer pin provably ends before the handles close. A
/// drain that cannot prove the end within its bound LEAKS the pinned boxes —
/// the kernel may still write through them, so freeing would be the bug.
fn teardown_drain(io_state: &mut PumpIo) {
  ffi::cancel_io(io_state.handle.as_handle());
  let deadline_packets = 16;
  for _ in 0..deadline_packets {
    match ffi::iocp_wait(io_state.port.as_handle(), DRAIN_LIMIT_MS) {
      Ok(ffi::Completion::Packet { overlapped, .. })
        if overlapped == (&raw mut *io_state.overlapped[io_state.active]).cast() =>
      {
        // The pin ended: the read's completion (aborted or success) was
        // dequeued. Handles and buffers now close through Drop.
        return;
      }
      // Stray control posts or older packets: keep draining.
      Ok(ffi::Completion::Packet { .. }) => {}
      Ok(ffi::Completion::TimedOut) | Err(_) => break,
    }
  }
  // The pin's end was not observed: leak the I/O state rather than free
  // memory the kernel may still write.
  let leaked = std::mem::replace(
    &mut io_state.buffers,
    [Vec::new().into_boxed_slice(), Vec::new().into_boxed_slice()],
  );
  let [a, b] = leaked;
  Box::leak(a);
  Box::leak(b);
  let overlapped = std::mem::replace(
    &mut io_state.overlapped,
    [
      Box::new(unsafe { std::mem::zeroed() }),
      Box::new(unsafe { std::mem::zeroed() }),
    ],
  );
  let [a, b] = overlapped;
  Box::leak(a);
  Box::leak(b);
}
