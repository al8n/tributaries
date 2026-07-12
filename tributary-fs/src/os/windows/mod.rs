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
  use super::{
    RawWindowsEvent, RdcwEvent, RdcwPairer, lower_rdcw_buffer, rdcw::decode::RdcwAction,
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
}
