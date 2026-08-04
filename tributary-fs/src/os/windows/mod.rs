//! The Windows backends: `ReadDirectoryChangesW` (unprivileged) and, later,
//! the USN change journal (privileged-preferred), selected per volume by
//! `Backend::Auto`.
//!
//! Pure machinery (the record decode, the payload vocabulary) compiles
//! everywhere tests run, mirroring the transport/fsevent/linux precedent; the
//! FFI layer (directory handles, OVERLAPPED reads, the per-source IOCP pump
//! thread) is `cfg(all(target_os = "windows", not(miri)))` and reduces every
//! completion to these types as early as possible.

// The windows walks are the production consumers; on every other host only
// the twins reach the decoder.
#[cfg_attr(not(all(target_os = "windows", not(miri))), allow(dead_code))]
pub(crate) mod dirscan;
#[cfg(all(target_os = "windows", not(miri)))]
pub(crate) mod ffi;
pub(crate) mod rdcw;
#[cfg(all(target_os = "windows", not(miri)))]
pub(crate) mod source;
#[cfg(all(target_os = "windows", not(miri)))]
pub(crate) mod usn_source;
// The journal source consumes this next; the twins pin its contracts first.
#[allow(dead_code)]
pub(crate) mod usn;
#[cfg(all(target_os = "windows", not(miri)))]
pub(crate) use source::{Source, SourceHandle};

/// Windows reads no mount table in v1: `None` keeps event-side trust closed
/// until the driver's post-live refresh (the seam's unknown-boundary
/// semantic), and junction containment is enforced by the reparse refusal at
/// descent rather than by a seed.
#[cfg(all(target_os = "windows", not(miri)))]
pub(crate) fn mounts_under(root: &std::path::Path) -> Option<Vec<std::path::PathBuf>> {
  let _ = root;
  None
}

pub(crate) use rdcw::{
  decode::{RdcwAction, RdcwName, RdcwRecord},
  pairing::{RdcwEvent, RdcwPairer},
};

use super::Quiesce;

/// How many packets a teardown drain will consume while looking for the
/// outstanding read's own completion. Strays (a duplicate control post, a
/// completion the pump no longer tracks) are skipped, but not endlessly: a
/// port a foreign producer keeps feeding must not hold the pump forever.
// The windows pumps are the production callers; on every other host only the
// twins reach the drain.
#[cfg_attr(not(all(target_os = "windows", not(miri))), allow(dead_code))]
const DRAIN_PACKET_BUDGET: usize = 16;

/// How long each drain step waits for a packet before declaring the pin
/// unprovable. Bounded and generous: the cancellation's completion is queued
/// by the kernel, so on a live volume it is already there.
#[cfg_attr(not(all(target_os = "windows", not(miri))), allow(dead_code))]
const DRAIN_LIMIT_MS: u32 = 5_000;

/// What one step of a teardown drain observed on the completion port.
#[cfg_attr(not(all(target_os = "windows", not(miri))), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DrainStep {
  /// The outstanding read's OWN completion — success, failure, or the
  /// `ERROR_OPERATION_ABORTED` a cancellation produces. Dequeuing it is
  /// exactly what ends the kernel's ownership of the pinned buffer and
  /// `OVERLAPPED`, so it is the only observation that proves anything.
  PinEnded,
  /// Some other packet: a stray control post, or a completion from an
  /// operation this pump no longer tracks. Proves nothing; keep draining.
  Stray,
  /// Nothing more will be dequeued — the bounded wait elapsed, or the wait
  /// itself failed. The drain has run out of evidence.
  Exhausted,
}

/// Drives a teardown drain to its verdict.
///
/// `Proven` requires a step to have ACTUALLY observed the pin end. A drain
/// that times out, whose wait fails, or that spends its whole budget on
/// strays answers `Unproven` — the case the caller then handles by retaining
/// the pinned allocation rather than freeing memory the kernel may still be
/// writing into.
///
/// Both Windows pumps drive this one function because the failure they share
/// is the one that matters: a drain that cannot finish looks, from the
/// outside, exactly like a drain that did. Deciding that in one place is what
/// keeps the two pumps from disagreeing about what counts as proof.
// The windows pumps are the production callers; on every other host only the
// twins reach it.
#[cfg_attr(not(all(target_os = "windows", not(miri))), allow(dead_code))]
pub(crate) fn drain_to_pin_end(budget: usize, mut step: impl FnMut() -> DrainStep) -> Quiesce {
  for _ in 0..budget {
    match step() {
      DrainStep::PinEnded => return Quiesce::Proven,
      DrainStep::Stray => {}
      DrainStep::Exhausted => break,
    }
  }
  Quiesce::Unproven
}

/// Runs one pump body under its own unwind containment and reports the
/// verdict its thread exits with.
///
/// The body borrows the pump's pinned I/O state and answers whether it proved
/// that state's kernel-side lifetime over. This function owns the state so it
/// can decide what happens to it:
///
/// - The body RETURNED: its verdict stands, and the state drops normally. A
///   drain that already leaked its pinned boxes hands back a shell whose
///   handles are safe to close, so `Unproven` here still drops.
/// - The body UNWOUND: the state is FORGOTTEN, never dropped. A panic can
///   land anywhere, including between a successful issue and its completion,
///   so the pump cannot prove the kernel is done with the buffer or the
///   `OVERLAPPED`; freeing them would be a use-after-free the panic made
///   silent. Retaining them is the memory-safe answer and is deliberate.
///
/// The unwind arm therefore answers `Unproven` unconditionally, and that is
/// the whole point of routing the panic through here: the leak is correct, but
/// a thread that returns normally after leaking would otherwise be joined as a
/// success and the retained handles, buffers and `OVERLAPPED`s would never be
/// counted anywhere.
// The windows pumps are the production callers; on every other host only the
// twins reach it.
#[cfg_attr(not(all(target_os = "windows", not(miri))), allow(dead_code))]
pub(crate) fn contained_pump<S>(
  mut state: S,
  body: impl FnOnce(&mut S) -> Quiesce,
  fatal: impl FnOnce(),
) -> Quiesce {
  match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(&mut state))) {
    Ok(verdict) => verdict,
    Err(payload) => {
      // Retired inside its own boundary rather than dropped as this function
      // returns, where a payload whose own `Drop` panics would unwind past the
      // leak and the fatal signal below.
      let _ = tributary_proto::unwind::dispose_panic_payload(payload);
      std::mem::forget(state);
      fatal();
      Quiesce::Unproven
    }
  }
}

/// The verdict a JOINED pump reports to its handle.
///
/// A pump that returned answers for itself. A pump whose thread UNWOUND
/// reached none of the arms that decide a verdict — it left through its panic
/// hook, its handshake send, or the retirement of its own payload — so there
/// is nothing to trust: the read's pin may be open and the I/O state was
/// neither dropped nor deliberately retained. That is `Unproven`.
///
/// Reading the join alone was the original defect's mechanism, in the other
/// direction: the pump caught its own panic, leaked the pinned state and
/// returned, so the join SUCCEEDED and the handle reported a clean teardown.
/// The verdict now rides the thread's value, and this is where it is read.
///
/// The payload is retired inside its own boundary rather than dropped as this
/// function returns, where a payload whose `Drop` panics would unwind on the
/// teardown worker — or in a handle's `Drop`, on whatever thread released it.
// The windows handle is the production caller; on every other host only the
// twins reach it.
#[cfg_attr(not(all(target_os = "windows", not(miri))), allow(dead_code))]
pub(crate) fn joined_verdict(joined: std::thread::Result<Quiesce>) -> Quiesce {
  match joined {
    Ok(verdict) => verdict,
    Err(payload) => {
      let _ = tributary_proto::unwind::dispose_panic_payload(payload);
      Quiesce::Unproven
    }
  }
}

/// Whether a canonical root's byte form names a REMOTE object by prefix
/// alone: a UNC path (`\\server\share`, or `\\?\UNC\server\share`) that no
/// local drive letter mediates. RDCW and the USN journal are both blind (or
/// silently lossy) on SMB, so a remote root is refused at the spawn barrier;
/// a drive-lettered mapping is caught separately by the handle-side drive
/// probe. Pure string logic so every host's twins pin it.
// The windows spawn barrier is the production caller; on every other host
// only the twins reach it.
#[cfg_attr(not(all(target_os = "windows", not(miri))), allow(dead_code))]
pub(crate) fn is_unc_remote(path: &std::path::Path) -> bool {
  let Some(text) = path.to_str() else {
    // A root that cannot even spell as UTF-8 is refused elsewhere; the
    // prefix classifier only answers the remote question.
    return false;
  };
  let verbatim_unc = text
    .get(..8)
    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(r"\\?\UNC\"));
  if verbatim_unc {
    return true;
  }
  if let Some(rest) = text.strip_prefix(r"\\") {
    // `\\?\C:\...` and `\\.\pipe\...` are verbatim/device forms, not UNC.
    return !rest.starts_with("?\\") && !rest.starts_with(".\\");
  }
  false
}

/// One decoded, pump-paired Windows source event as it crosses the
/// pump→driver queue.
///
/// The USN arm arrives with the journal backend; the enum exists from the
/// start so the seam payload, the driver lowering, and the hermetic twins
/// name one Windows shape throughout the campaign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RawWindowsEvent {
  /// One `ReadDirectoryChangesW` event after rename pairing.
  Rdcw(RdcwEvent),
  /// One admitted USN journal event.
  // The journal source (windows-only) is the production constructor; on
  // every other host the core suites construct it directly.
  #[cfg_attr(not(all(target_os = "windows", not(miri))), allow(dead_code))]
  Usn(usn::UsnAdmitted),
}

/// One completion buffer's full pure pipeline — decode, pair, and wrap into
/// the seam payload, in kernel order. Returns the events plus whether the
/// chain refused part-way (decode loss the pump signals AFTER forwarding the
/// events, so the loss covers exactly what follows them).
///
/// A lossy chain also widows the pairer's held OLD first: its NEW half may
/// sit in the refused remainder, and the widow must precede the loss signal
/// it predates — the pump-side loss-ordering invariant.
// The windows pump drives this per completion; on every other host only
// the twins reach it.
#[cfg_attr(not(all(target_os = "windows", not(miri))), allow(dead_code))]
pub(crate) fn lower_rdcw_buffer(
  pairer: &mut RdcwPairer,
  buf: &[u8],
  extended: bool,
) -> (Vec<super::SourceEvent>, bool) {
  let decoded = rdcw::decode::decode_records(buf, extended);
  let mut paired = Vec::with_capacity(decoded.records.len());
  for record in decoded.records {
    pairer.push(record, &mut paired);
  }
  if decoded.lossy {
    pairer.flush(&mut paired);
  }
  let events = paired
    .into_iter()
    .map(|event| super::SourceEvent::Windows(RawWindowsEvent::Rdcw(event)))
    .collect();
  (events, decoded.lossy)
}

#[cfg(test)]
mod tests {
  use std::{
    cell::Cell,
    rc::Rc,
    sync::atomic::{AtomicUsize, Ordering},
  };

  use super::{
    DrainStep, Quiesce, RawWindowsEvent, RdcwEvent, RdcwPairer, contained_pump, drain_to_pin_end,
    joined_verdict, lower_rdcw_buffer, rdcw::decode::RdcwAction,
  };
  use crate::os::SourceEvent;

  fn record_bytes(next: u32, action: u32, name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&next.to_le_bytes());
    buf.extend_from_slice(&action.to_le_bytes());
    let units: Vec<u8> = name
      .encode_utf16()
      .flat_map(|unit| unit.to_le_bytes())
      .collect();
    buf.extend_from_slice(&(units.len() as u32).to_le_bytes());
    buf.extend_from_slice(&units);
    buf
  }

  #[test]
  fn a_pair_split_across_buffers_survives_the_seam() {
    let mut pairer = RdcwPairer::new();
    let (events, lossy) = lower_rdcw_buffer(&mut pairer, &record_bytes(0, 4, "old"), false);
    assert!(!lossy);
    assert!(events.is_empty(), "the OLD parks across the boundary");

    let (events, lossy) = lower_rdcw_buffer(&mut pairer, &record_bytes(0, 5, "new"), false);
    assert!(!lossy);
    assert_eq!(events.len(), 1);
    assert!(matches!(
      &events[0],
      SourceEvent::Windows(RawWindowsEvent::Rdcw(RdcwEvent::Renamed { .. }))
    ));
  }

  #[test]
  fn a_lossy_chain_widows_the_carry_before_the_loss() {
    let mut pairer = RdcwPairer::new();
    let mut buf = record_bytes(0, 4, "old");
    // Retro-link to a truncated second record: the chain refuses there.
    let second_at = buf.len().next_multiple_of(4);
    buf.resize(second_at, 0);
    buf[0..4].copy_from_slice(&(second_at as u32).to_le_bytes());
    buf.extend_from_slice(&[0u8; 6]);

    let (events, lossy) = lower_rdcw_buffer(&mut pairer, &buf, false);
    assert!(lossy);
    assert_eq!(events.len(), 1, "the held OLD widows ahead of the loss");
    assert!(matches!(
      &events[0],
      SourceEvent::Windows(RawWindowsEvent::Rdcw(RdcwEvent::WidowOld(rec)))
        if rec.action == RdcwAction::RenamedOld
    ));
    assert!(!pairer.holds_old());
  }

  #[test]
  fn unc_remote_prefixes_classify() {
    use std::path::Path;

    use super::is_unc_remote;

    assert!(is_unc_remote(Path::new(r"\\server\share\dir")));
    assert!(is_unc_remote(Path::new(r"\\?\UNC\server\share")));
    assert!(is_unc_remote(Path::new(r"\\?\unc\server\share")));
    assert!(!is_unc_remote(Path::new(r"\\?\C:\local\dir")));
    assert!(!is_unc_remote(Path::new(r"\\.\pipe\name")));
    assert!(!is_unc_remote(Path::new(r"C:\local\dir")));
    assert!(!is_unc_remote(Path::new("/posix/style")));
  }

  /// The drain proves the pin ended only by OBSERVING it, and stops looking the
  /// moment it does.
  #[test]
  fn a_drain_that_dequeues_the_read_proves_the_pin_ended() {
    let steps = Cell::new(0usize);
    let verdict = drain_to_pin_end(16, || {
      steps.set(steps.get() + 1);
      DrainStep::PinEnded
    });
    assert_eq!(
      verdict,
      Quiesce::Proven,
      "the read's own completion IS the proof"
    );
    assert_eq!(steps.get(), 1, "and the drain stops at it");
  }

  /// Strays cost budget, not truth: the pin's own completion behind them still
  /// proves the pin ended.
  #[test]
  fn strays_ahead_of_the_read_do_not_cost_the_proof() {
    let remaining = Cell::new(3usize);
    let verdict = drain_to_pin_end(16, || {
      if remaining.get() > 0 {
        remaining.set(remaining.get() - 1);
        DrainStep::Stray
      } else {
        DrainStep::PinEnded
      }
    });
    assert_eq!(verdict, Quiesce::Proven);
  }

  /// A cancellation drain that TIMES OUT reports the pin unproven.
  ///
  /// This is the non-panic half of the class. The pump cancels its read and
  /// waits for the completion that ends the kernel's ownership of the buffer;
  /// when that completion never arrives the buffer and its `OVERLAPPED` are
  /// retained on purpose — freeing them would be a use-after-free. Answering
  /// `Proven` here reported that retention as a clean teardown.
  ///
  /// FAIL-ON-REVERT: return `Quiesce::Proven` from the fallthrough of
  /// `drain_to_pin_end` and this cell (and the two below) flip.
  #[test]
  fn a_drain_that_times_out_leaves_the_pin_unproven() {
    let steps = Cell::new(0usize);
    let verdict = drain_to_pin_end(16, || {
      steps.set(steps.get() + 1);
      DrainStep::Exhausted
    });
    assert_eq!(
      verdict,
      Quiesce::Unproven,
      "the cancellation's completion never arrived, so the buffer's pin is still open"
    );
    assert_eq!(
      steps.get(),
      1,
      "and an exhausted port is not re-waited on for the rest of the budget"
    );
  }

  /// A port a foreign producer keeps feeding cannot hold the pump forever — and
  /// the budget it exhausts buys no proof.
  #[test]
  fn a_budget_spent_on_strays_leaves_the_pin_unproven() {
    let steps = Cell::new(0usize);
    let verdict = drain_to_pin_end(4, || {
      steps.set(steps.get() + 1);
      DrainStep::Stray
    });
    assert_eq!(verdict, Quiesce::Unproven);
    assert_eq!(
      steps.get(),
      4,
      "the budget is a bound, and it is spent exactly"
    );
  }

  /// One I/O state, with a `Drop` that records whether it ran — the whole
  /// instrument for the panic-forget arm.
  struct PinnedState {
    dropped: Rc<Cell<bool>>,
  }

  impl Drop for PinnedState {
    fn drop(&mut self) {
      self.dropped.set(true);
    }
  }

  /// A pump body that RETURNS hands back its own verdict, and its I/O state
  /// drops normally — including when the verdict is `Unproven`, because a drain
  /// that could not prove the pin has already retained the pinned boxes itself
  /// and left a shell whose handles are safe to close.
  #[test]
  fn a_returning_pump_reports_its_own_verdict_and_releases_its_state() {
    for reported in [Quiesce::Proven, Quiesce::Unproven] {
      let dropped = Rc::new(Cell::new(false));
      let fatals = AtomicUsize::new(0);
      let verdict = contained_pump(
        PinnedState {
          dropped: Rc::clone(&dropped),
        },
        |_| reported,
        || {
          fatals.fetch_add(1, Ordering::SeqCst);
        },
      );
      assert_eq!(verdict, reported);
      assert!(
        dropped.get(),
        "a body that returned decided the state's fate"
      );
      assert_eq!(
        fatals.load(Ordering::SeqCst),
        0,
        "no terminal is signalled for a body that did not unwind"
      );
    }
  }

  /// A pump body that UNWINDS retains its I/O state — and says so.
  ///
  /// Both halves are the point. The state is FORGOTTEN because a panic can land
  /// between a successful issue and its completion, where the kernel still owns
  /// the buffer and the `OVERLAPPED`; dropping them there would be a
  /// use-after-free the panic made silent, so the leak is correct and stays.
  /// What was wrong is that the thread then returned normally, its join
  /// succeeded, and the driver classified the leak as a completed teardown.
  ///
  /// FAIL-ON-REVERT: answer `Quiesce::Proven` in `contained_pump`'s unwind arm
  /// and the verdict assertion fails while the leak assertion still passes —
  /// which is exactly the defect: the leak was never the bug, reporting it as
  /// success was.
  #[test]
  fn a_panicking_pump_retains_its_state_and_reports_the_pin_unproven() {
    let dropped = Rc::new(Cell::new(false));
    let fatals = AtomicUsize::new(0);
    let verdict = contained_pump(
      PinnedState {
        dropped: Rc::clone(&dropped),
      },
      |_| panic!("the pump unwinds mid-loop, with a read outstanding"),
      || {
        fatals.fetch_add(1, Ordering::SeqCst);
      },
    );
    assert_eq!(
      verdict,
      Quiesce::Unproven,
      "a panicked pump proved nothing about the kernel's buffer"
    );
    assert!(
      !dropped.get(),
      "and it retained the pinned state rather than free memory the kernel may still write"
    );
    assert_eq!(
      fatals.load(Ordering::SeqCst),
      1,
      "the stream still goes loud in band exactly once"
    );
  }

  /// A panic payload whose own disposal unwinds must not carry the pump past
  /// the leak: the retention and the in-band terminal both still happen.
  #[test]
  fn a_pump_payload_whose_drop_panics_still_retains_and_reports() {
    struct PanicsOnDrop;

    impl Drop for PanicsOnDrop {
      fn drop(&mut self) {
        panic!("a pump's panic payload panics as it is disposed of");
      }
    }

    let dropped = Rc::new(Cell::new(false));
    let fatals = AtomicUsize::new(0);
    let verdict = contained_pump(
      PinnedState {
        dropped: Rc::clone(&dropped),
      },
      |_| std::panic::panic_any(PanicsOnDrop),
      || {
        fatals.fetch_add(1, Ordering::SeqCst);
      },
    );
    assert_eq!(verdict, Quiesce::Unproven);
    assert!(!dropped.get(), "the pinned state is still retained");
    assert_eq!(
      fatals.load(Ordering::SeqCst),
      1,
      "and the in-band terminal is still signalled"
    );
  }

  /// A pump whose THREAD unwound proves nothing, and a successful join proves
  /// only what the pump itself put in it.
  ///
  /// The finding's own mechanism was here: the pump caught its panic, leaked
  /// the pinned state to stay memory-safe, and returned — so the join succeeded
  /// and the handle read success out of it. The verdict now rides the thread's
  /// value, which is why the `Ok` arm forwards rather than assumes.
  ///
  /// FAIL-ON-REVERT: answer `Quiesce::Proven` in the `Err` arm, or ignore the
  /// `Ok` payload and answer `Proven` unconditionally, and the matching
  /// assertion below fails.
  #[test]
  fn a_joined_pump_reports_its_own_verdict_and_an_unwound_thread_reports_none() {
    assert_eq!(joined_verdict(Ok(Quiesce::Proven)), Quiesce::Proven);
    assert_eq!(
      joined_verdict(Ok(Quiesce::Unproven)),
      Quiesce::Unproven,
      "a successful join carries the pump's answer, it does not overwrite it"
    );

    let unwound = std::panic::catch_unwind(|| panic!("the pump thread left outside its own arms"))
      .map(|()| Quiesce::Proven);
    assert_eq!(
      joined_verdict(unwound),
      Quiesce::Unproven,
      "a thread that unwound reached no arm that decides anything"
    );
  }
}
