use std::{cell::Cell, io, path::Path};

use super::{ReseedOutcome, SeedOutcome, reseed_map, seed_moved_in_subtree};
use crate::os::linux::fanotify::{
  fid::Fid,
  map::{FidMap, SeedEntry},
};

fn fid(tag: u8) -> Fid {
  Fid::new([tag; 8], Box::from(&[tag][..]))
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
