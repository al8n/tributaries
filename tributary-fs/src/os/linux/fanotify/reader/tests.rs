use std::{cell::Cell, io, path::Path};

use super::{ReseedOutcome, SeedOutcome, process_decoded, reseed_map, seed_moved_in_subtree};
use crate::os::{
  BackendStatsShared, SourceMessage,
  linux::fanotify::{
    fid::{
      DecodeOutcome, FAN_CREATE, FAN_DELETE, FAN_MODIFY, FAN_ONDIR, FanMask, Fid, RawFanotifyEvent,
    },
    map::{FidMap, SeedEntry},
  },
  transport::TransportState,
};

fn fid(tag: u8) -> Fid {
  Fid::new([tag; 8], Box::from(&[tag][..]))
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
