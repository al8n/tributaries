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
//! - **A retained pin is REPORTED**: every exit answers
//!   [`Quiesce`](super::super::Quiesce), and the paths that retain — the
//!   panic-forget and a drain that never dequeued the read's completion —
//!   answer `Unproven`, so the driver retires the stream as `TeardownFailed`
//!   rather than counting a leak as a clean teardown. A spawn that fails AFTER
//!   the pump is live never performs that teardown itself: it hands the running
//!   stream back inside [`SpawnFailed`](super::super::SpawnFailed) so the same
//!   counted submission reads the verdict.
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
    EventReceiver, MAX_EXCLUSIONS, Quiesce, ResumeToken, RootMeta, ScopePort, SourceConfig,
    SourceError, SourceEvent, SourceMessage, SpawnFailed,
    transport::{self, TransportState},
  },
  DRAIN_LIMIT_MS, DRAIN_PACKET_BUDGET, DrainStep, RdcwPairer, contained_pump, drain_to_pin_end,
  ffi, is_unc_remote, joined_verdict, lower_rdcw_buffer,
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
  /// The resume point the driver has ACKNOWLEDGED. The RDCW pump stages
  /// nothing into it (its notifications have no durable position), so an RDCW
  /// source reports `None` by construction rather than by a special case; the
  /// journal pump stages a cursor with every batch.
  pub(super) resume: Arc<transport::ResumeShared>,
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
  ) -> Result<(SourceHandle, EventReceiver, RootMeta), SpawnFailed<SourceHandle>> {
    if config.roots.is_empty() {
      return Err(SourceError::NoRoots.into());
    }
    if config.exclusions.len() > MAX_EXCLUSIONS {
      return Err(
        SourceError::TooManyExclusions {
          supplied: config.exclusions.len(),
        }
        .into(),
      );
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
      return Err(
        SourceError::RootUnavailable {
          root: canonical,
          source: io::Error::new(
            io::ErrorKind::Unsupported,
            "network filesystems deliver no reliable events",
          ),
        }
        .into(),
      );
    }

    let handle =
      ffi::open_directory(&canonical).map_err(|source| SourceError::RootUnavailable {
        root: canonical.clone(),
        source,
      })?;
    if !ffi::is_disk_object(handle.as_handle()) {
      return Err(
        SourceError::RootUnavailable {
          root: canonical,
          source: io::Error::new(
            io::ErrorKind::Unsupported,
            "the root is not a disk-backed object",
          ),
        }
        .into(),
      );
    }
    match ffi::is_directory(handle.as_handle()) {
      Ok(true) => {}
      Ok(false) => {
        return Err(SourceError::NotADirectory { root: canonical }.into());
      }
      Err(source) => {
        return Err(
          SourceError::RootUnavailable {
            root: canonical,
            source,
          }
          .into(),
        );
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
          .map_err(|stage| SpawnFailed::refused(SourceError::BackendProbeFailed { stage }))?;
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

    // The native buffer is its OWN option, in bytes: deriving it from the batch
    // budget multiplied a caller-supplied count into a length, which wraps (or
    // panics) on a 32-bit `usize` long before it means anything.
    let buffer_len = config.os_buffer_bytes.get() as usize;
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
      resume: Arc::default(),
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
      // A join hands back the pump's panic payload exactly as `catch_unwind`
      // does, and discarding it with `let _ =` DROPS it — running the
      // panicking code's own destructor here rather than inside a boundary.
      if let Err(payload) = pump.join() {
        let _ = tributary_proto::unwind::dispose_panic_payload(payload);
      }
      return Err(SourceError::StartFailed.into());
    }

    // From here the stream is LIVE, and every failure below hands it back
    // running rather than tearing it down here.
    //
    // Rolling back inline was the earlier shape, and it discarded the
    // `shutdown`'s verdict on the reasoning that a failing spawn owns no scope
    // and owes no counted obligation. But this pump's reads are overlapped: a
    // cancellation drain that cannot prove the read's completion was dequeued
    // RETAINS the pinned buffer, its `OVERLAPPED` and this handle rather than
    // freeing memory the kernel may still write through — the memory-safe
    // choice — and answers `Unproven`. Discarded here, that retention was
    // reported as nothing at all: no `TeardownFailed` reached the driver, so
    // the backlog never bounded admission over it and `close` still claimed
    // quiescence. The scope not existing never made the retained state stop
    // existing.
    //
    // So the rollback rides out with the error (see
    // [`SpawnFailed`](super::super::SpawnFailed)) and the driver retires it
    // through the same counted submission a committed stream uses, where the
    // verdict chooses the terminal.
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
        return Err(SpawnFailed::rolled_back(
          SourceError::RootUnavailable {
            root: canonical,
            source,
          },
          source_handle,
        ));
      }
    };
    match ffi::identity_of(live.as_handle()) {
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
          return Err(SpawnFailed::rolled_back(
            SourceError::RootUnavailable {
              root: ancestor.to_path_buf(),
              source,
            },
            source_handle,
          ));
        }
      };
      match ffi::identity_of(opened.as_handle()) {
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
  /// `None` once torn down — teardown runs exactly once. The thread's value
  /// IS its quiescence verdict: a pump that had to retain kernel-owned state
  /// reports it here rather than exiting silently.
  pump: Option<JoinHandle<Quiesce>>,
  control: ControlPost,
  shared: Arc<PumpShared>,
}

impl SourceHandle {
  /// Assembles a handle around a running pump — the journal arm builds the
  /// same teardown shape over its own thread and port.
  pub(super) fn assemble(
    pump: JoinHandle<Quiesce>,
    control_port: OwnedHandle,
    shared: Arc<PumpShared>,
  ) -> Self {
    Self {
      pump: Some(pump),
      control: ControlPost { port: control_port },
      shared,
    }
  }

  /// The resume point the driver has ACKNOWLEDGED — a journal cursor on the USN
  /// arm, and `None` on RDCW, which stages none because a change notification
  /// names no durable position to come back to.
  pub(crate) fn resume_token(&self) -> Option<ResumeToken> {
    self.shared.resume.published()
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
  ///
  /// The answer is the PUMP'S — this handle only posts the control packet and
  /// joins. A pump that had to retain its pinned buffers (it panicked, or its
  /// cancellation drain never dequeued the read's completion) reports
  /// [`Quiesce::Unproven`], and the driver turns that into a failed teardown
  /// rather than a clean one.
  pub(crate) fn shutdown(mut self) -> Quiesce {
    self.teardown()
  }

  fn teardown(&mut self) -> Quiesce {
    let Some(pump) = self.pump.take() else {
      // Teardown already ran and already reported its own verdict; answering
      // again here would count one stream twice.
      return Quiesce::Proven;
    };
    self.shared.stopped.store(true, Ordering::Release);
    // A failed post means the port is gone — the pump is already exiting.
    let _ = ffi::iocp_post(self.control.port.as_handle(), KEY_CONTROL);
    // The join carries the pump's own verdict, and a thread that unwound
    // carries none — including the payload discipline, which the shared reader
    // owns so no site can reintroduce a bare drop of it.
    joined_verdict(pump.join())
  }
}

impl Drop for SourceHandle {
  /// The backstop for a handle released without an orderly `shutdown`.
  ///
  /// The verdict is discarded, and this is the one place where that stays
  /// right. A `Drop` reached here is a handle no driver frame is accounting for
  /// any more: the driver's escrow and reservoir guards hand every stream they
  /// still hold to the reaper sink, and they run precisely on the exits — an
  /// unwind, a cancelled task, a shut-down runtime — where the frame that owns
  /// the backlog counter, the unproven latch and the close reply is itself
  /// gone. There is no admission left to slow and no close reply left to make
  /// honest, so a verdict here has no reader rather than a reader being denied
  /// one. A spawn rollback is a different case entirely and is NOT this one: a
  /// live driver is still there to hear it, which is why the barrier hands its
  /// stream back rather than dropping it here.
  fn drop(&mut self) {
    let _ = self.teardown();
  }
}

/// Starts the pump thread. The thread's value is its quiescence verdict, which
/// [`SourceHandle::teardown`] reads out of the join.
fn spawn_pump(
  io_state: PumpIo,
  shared: Arc<PumpShared>,
  started: std::sync::mpsc::SyncSender<bool>,
) -> Result<JoinHandle<Quiesce>, SourceError> {
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
          // A refused issue queues no I/O, so no pin was ever taken and this
          // drop frees nothing the kernel holds.
          return Quiesce::Proven;
        }
      }
      let _ = started.send(true);
      contained_pump(
        io_state,
        |io_state| run(io_state, &shared),
        || shared.fatal(SourceError::CallbackPanic),
      )
    })
    .map_err(|_| SourceError::StartFailed)
}

/// The pump loop. One read outstanding at all times; completions, control
/// posts, and the pairing-window timeout are the only wakeups.
///
/// Returns whether the exit PROVED the outstanding read's pin ended. Every
/// arm but the two drains reaches its `return` having just dequeued that
/// read's own completion with no reissue behind it, so the pin is provably
/// closed and the I/O state may drop; the drains answer for themselves.
fn run(io_state: &mut PumpIo, shared: &PumpShared) -> Quiesce {
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
        return teardown_drain(io_state);
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
        return teardown_drain(io_state);
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
              // The completion was dequeued and the reissue queued nothing:
              // no read is outstanding.
              shared.fatal(SourceError::StartFailed);
              return Quiesce::Proven;
            }
            continue;
          }
          if shared.stopped.load(Ordering::Acquire) {
            // A cancellation packet raced the control post: consume it and
            // exit on the control packet still in the queue — or now. This IS
            // the outstanding read's own failed completion, so dequeuing it is
            // the same proof the drain goes looking for.
            return Quiesce::Proven;
          }
          shared.fatal(SourceError::ReadFailed {
            source: io::Error::from_raw_os_error(code),
          });
          return Quiesce::Proven;
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
          // The completed read's packet was dequeued and its successor was
          // refused, so nothing is pinned.
          shared.fatal(SourceError::StartFailed);
          return Quiesce::Proven;
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
///
/// The leak is granular on purpose: only the buffer and the `OVERLAPPED` are
/// retained, while the directory handle and the port still close with the I/O
/// state. Closing a handle with a pending overlapped operation cancels it and
/// lets the kernel complete it into the retained `OVERLAPPED`, which is
/// exactly what the retention is for.
///
/// `Unproven` is the verdict on every path that reaches that leak — a
/// cancellation whose completion never arrived within the bound, a wait that
/// failed, and a budget spent on strays are indistinguishable from outside,
/// and all three end with kernel-owned memory retained. Reporting them as a
/// completed teardown is what let repeated failures leak without ever being
/// counted.
fn teardown_drain(io_state: &mut PumpIo) -> Quiesce {
  ffi::cancel_io(io_state.handle.as_handle());
  // Bound the pin's identity BEFORE the drain borrows the port: the active
  // OVERLAPPED cannot move (it is boxed) and the pump issues nothing more.
  let pinned: *mut OVERLAPPED = &raw mut *io_state.overlapped[io_state.active];
  let port = io_state.port.as_handle();
  let verdict = drain_to_pin_end(DRAIN_PACKET_BUDGET, || {
    match ffi::iocp_wait(port, DRAIN_LIMIT_MS) {
      // The pin ended: the read's completion (aborted or success) was
      // dequeued. Handles and buffers now close through Drop.
      Ok(ffi::Completion::Packet { overlapped, .. }) if overlapped == pinned.cast() => {
        DrainStep::PinEnded
      }
      // Stray control posts or older packets: keep draining.
      Ok(ffi::Completion::Packet { .. }) => DrainStep::Stray,
      Ok(ffi::Completion::TimedOut) | Err(_) => DrainStep::Exhausted,
    }
  });
  if verdict == Quiesce::Proven {
    return verdict;
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
  verdict
}
