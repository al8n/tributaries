//! End-to-end integration through the public API against real
//! `ReadDirectoryChangesW`.
//!
//! Real-kernel timing is nondeterministic, so every assertion is
//! convergence-style: wait (bounded) until the expected fact is observed;
//! extra events — coalesced kinds, additional `Rescan`s — are always legal.
//!
//! The zoo cells (`TRIBUTARY_ZOO_NTFS`/`TRIBUTARY_ZOO_FAT32`, built by
//! `ci/windows/zoo.ps1`) self-probe and skip loudly when the environment
//! variables are absent, so the suite also runs on a bare developer box.
//!
//! ALWAYS run this binary with `--test-threads=1` (CI does): the overflow
//! cell floods the kernel buffer, which would perturb any event-flow test
//! running concurrently.
//!
//! The suite doubles as the campaign's [verify] ledger executor: the
//! root-delete, root-rename, and overflow cells pin the documented-by-practice
//! Windows behaviors the pump design rests on, and it hosts the MEASUREMENT
//! cells — cells that print a kernel behaviour the documentation does not
//! state, so a decision resting on that behaviour is made from a CI log rather
//! than from a guess.
//!
//! A measurement whose answer has since been BUILT ON stops being a measurement
//! and becomes a GATE. It is marked `[gate]` rather than `[measure]`, it asserts
//! the property the code now relies on, and it fails the job when the kernel
//! stops providing it — because a check that cannot fail licenses nothing, and
//! the deletion it licensed is still in the tree.

// not(miri): drives real Win32 I/O and a tokio runtime — none of which miri
// can execute. The sans-I/O logic is covered by the lib unit tests.
#![cfg(all(target_os = "windows", feature = "tokio", not(miri)))]

use std::{
  path::{Path, PathBuf},
  sync::atomic::{AtomicU32, Ordering},
  time::Duration,
};

use tributary_fs::{Backend, Event, EventKind, Interest, TokioWatcher, WatcherOptions};

mod common;

use common::{covers, delivered};

/// Generous ceiling for one expected observation; CI runners are slow.
const DEADLINE: Duration = Duration::from_secs(20);

/// A fresh scratch root, canonicalized so event paths and expectations share
/// one byte form (`\\?\`-prefixed on Windows).
fn scratch_root(tag: &str) -> PathBuf {
  static COUNTER: AtomicU32 = AtomicU32::new(0);
  let dir = std::env::temp_dir()
    .canonicalize()
    .expect("canonicalize temp dir")
    .join(format!(
      "tributary-fs-it-{}-{}-{}",
      tag,
      std::process::id(),
      COUNTER.fetch_add(1, Ordering::Relaxed),
    ));
  std::fs::create_dir_all(&dir).expect("create scratch root");
  dir.canonicalize().expect("canonicalize scratch root")
}

/// The constructor for every cell whose SUBJECT is a `ReadDirectoryChangesW`
/// behaviour.
///
/// Pinned rather than left to `Auto`, which prefers the journal wherever one is
/// enabled: an Auto-selected USN source would let such a cell pass while proving
/// nothing about the backend it is written for.
fn rdcw_watcher() -> TokioWatcher {
  TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Rdcw)).expect("build watcher")
}

/// The constructor for the cells whose subject IS the selection.
///
/// Deliberately NOT [`rdcw_watcher`]: a selection cell built on a pinned backend
/// asserts about a choice its own constructor already made, which makes the
/// assertion true by construction and the cell worthless. Nothing here may
/// name a backend.
fn auto_watcher() -> TokioWatcher {
  TokioWatcher::new(WatcherOptions::new()).expect("build watcher")
}

/// Waits until an event satisfying `pred` arrives, or the deadline lapses.
async fn wait_for(
  watcher: &mut TokioWatcher,
  mut pred: impl FnMut(&Event) -> bool,
) -> Option<Event> {
  loop {
    let event = tokio::time::timeout(DEADLINE, watcher.next())
      .await
      .ok()??;
    if pred(&event) {
      return Some(event);
    }
  }
}

/// A FORCED RDCW selection reports itself — the unprivileged arm stays
/// selectable and honest even where Auto would prefer the journal.
#[tokio::test]
async fn forced_rdcw_reports_itself() {
  let root = scratch_root("select");
  let w = rdcw_watcher();
  let handle = w.watch(&root, Interest::all()).await.expect("watch");
  assert_eq!(w.backend_of(handle).expect("live root").as_str(), "rdcw");
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// Create → modify → remove under a nested tree: each verb is delivered.
///
/// The three `FILE_ACTION_*` words lower to `Created`/`Modified`/`Removed` with
/// no probe in between, so each step names both the exact path and the verb it
/// expects. A `Rescan` is not a weaker version of that answer — it is the pump's
/// reply when it lost the records it would have decoded — so the whole cell
/// would say nothing at all if one were admitted.
#[tokio::test]
async fn verbs_flow_end_to_end() {
  let root = scratch_root("verbs");
  std::fs::create_dir_all(root.join("deep")).expect("mkdir");
  let mut w = rdcw_watcher();
  let _handle = w.watch(&root, Interest::all()).await.expect("watch");

  let file = root.join("deep").join("probe.txt");
  std::fs::write(&file, b"one").expect("create");
  assert!(
    wait_for(&mut w, |e| delivered(e, &file) && e.kind().is_created())
      .await
      .is_some(),
    "the create is delivered as Created"
  );

  std::fs::write(&file, b"two").expect("modify");
  assert!(
    wait_for(&mut w, |e| delivered(e, &file) && e.kind().is_modified())
      .await
      .is_some(),
    "the modify is delivered as Modified"
  );

  std::fs::remove_file(&file).expect("remove");
  assert!(
    wait_for(&mut w, |e| delivered(e, &file) && e.kind().is_removed())
      .await
      .is_some(),
    "the remove is delivered as Removed"
  );

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// A same-tree rename accounts for BOTH ends: one paired `Moved` naming the
/// destination and carrying the source, or the documented degradation into a
/// `Removed` on the source AND a `Created` on the destination.
///
/// Either end alone is a lost half, so neither alone settles this. Both proofs
/// are [`delivered`] rather than `covers`: a `Rescan` at or above the root
/// satisfies coverage of both paths at once without pairing anything, which
/// would let a backend that decodes no rename at all pass the cell named for
/// rename decoding.
#[tokio::test]
async fn renames_deliver_both_ends() {
  let root = scratch_root("rename");
  let from = root.join("old.txt");
  std::fs::write(&from, b"x").expect("seed");
  let mut w = rdcw_watcher();
  let _handle = w.watch(&root, Interest::all()).await.expect("watch");

  let to = root.join("new.txt");
  std::fs::rename(&from, &to).expect("rename");

  // Accumulated across the drain rather than matched on one event: the
  // degraded form spends its two halves on two separate events, so no single
  // event can carry that proof.
  let (mut paired, mut source_half, mut destination_half) = (false, false, false);
  let settled = wait_for(&mut w, |e| {
    match e.kind() {
      EventKind::Moved(moved) if delivered(e, &to) && moved.from() == from.as_path() => {
        paired = true;
      }
      EventKind::Removed if delivered(e, &from) => source_half = true,
      EventKind::Created if delivered(e, &to) => destination_half = true,
      _ => {}
    }
    paired || (source_half && destination_half)
  })
  .await;
  assert!(
    settled.is_some(),
    "a rename accounts for both ends: paired={paired} removed_source={source_half} \
     created_destination={destination_half}"
  );

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// The watch-relative spelling of an event's path, for assertions about what
/// a location may contain. The root itself is `\\?\C:\…`, so a naive scan for
/// `:` would trip on the drive letter.
fn under_root(event: &Event, root: &Path) -> Option<String> {
  event
    .path()
    .strip_prefix(root)
    .ok()
    .map(|rest| rest.to_string_lossy().into_owned())
}

/// NTFS alternate data streams: mutating `file.txt:ads` is a mutation of
/// `file.txt`, and that is what the consumer must be told.
///
/// The subscription omitted the three `FILE_NOTIFY_CHANGE_STREAM_*` bits, so
/// the filesystem was never obliged to report any of this — the stream could
/// be created, written and deleted while the stream stayed silent and
/// "healthy". Two things are asserted: the owner's own path is reached, and no
/// location ever carries a `:` — the proto path vocabulary has no spelling for
/// a stream suffix, so publishing one would put a segment in the consumer's
/// index that names nothing it can enumerate.
#[tokio::test]
async fn ads_mutations_reach_their_owner() {
  let root = scratch_root("ads");
  let file = root.join("owner.txt");
  std::fs::write(&file, b"base").expect("seed the owner");
  let mut w = rdcw_watcher();
  let _handle = w.watch(&root, Interest::all()).await.expect("watch");

  // `path:stream` is the NTFS spelling; `std::fs` opens it like any other
  // name, so no FFI is needed to produce the mutation.
  let stream = root.join("owner.txt:ads");
  std::fs::write(&stream, b"stream payload").expect("write the alternate data stream");

  let mut colon_free = true;
  let observed = wait_for(&mut w, |e| {
    if let Some(rest) = under_root(e, &root)
      && rest.contains(':')
    {
      colon_free = false;
    }
    covers(e, &file)
  })
  .await;
  assert!(
    observed.is_some(),
    "an alternate-data-stream write must reach its owner file"
  );
  assert!(
    colon_free,
    "a stream suffix must never enter a published location"
  );

  // Removing the stream is likewise the owner's business.
  std::fs::remove_file(&stream).expect("remove the alternate data stream");
  assert!(
    wait_for(&mut w, |e| covers(e, &file)).await.is_some(),
    "the stream's removal must reach its owner file"
  );

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// 8.3 short-name aliases: both notify layouts may return either spelling for
/// an object that has both, and which one arrives is unspecified.
///
/// A short alias is not a location a consumer indexes by — its crawl holds
/// `Long File Name.txt` — so publishing `LONGFI~1.TXT` as the event's stable
/// path silently and permanently diverges the two, with no later event that
/// repairs it. The requirement is therefore a disjunction plus a prohibition:
/// the canonical path is reached (directly, or through a `Rescan` at or above
/// it, which sends the consumer back to the filesystem — the only authority on
/// the canonical name), and NO delivered event may name the alias.
///
/// `fsutil file setshortname` installs the alias explicitly, so the cell does
/// not depend on the volume's 8.3 CREATION policy — only on the privilege to
/// set one, whose absence is a loud skip.
#[tokio::test]
async fn a_short_name_alias_is_never_published_as_a_location() {
  let root = scratch_root("shortname");
  let long = root.join("Long File Name.txt");
  std::fs::write(&long, b"one").expect("seed the long-named file");

  let installed = std::process::Command::new("fsutil")
    .args(["file", "setshortname"])
    .arg(&long)
    .arg("LONGFI~1.TXT")
    .status();
  match installed {
    Ok(status) if status.success() => {}
    _ => {
      common::skip_notice(format_args!(
        "a_short_name_alias_is_never_published_as_a_location: \
         `fsutil file setshortname` refused (it needs the restore privilege)"
      ));
      let _ = std::fs::remove_dir_all(&root);
      return;
    }
  }
  let alias = root.join("LONGFI~1.TXT");

  let mut w = rdcw_watcher();
  let _handle = w.watch(&root, Interest::all()).await.expect("watch");

  // Mutate THROUGH the alias: the notification carries whichever spelling the
  // mutating open used, which is precisely the unspecified behaviour.
  std::fs::write(&alias, b"two").expect("write through the short alias");

  let mut published_alias: Option<String> = None;
  let observed = wait_for(&mut w, |e| {
    if delivered(e, &alias) {
      published_alias = Some(format!("{e:?}"));
    }
    covers(e, &long)
  })
  .await;
  assert!(
    observed.is_some(),
    "a mutation through the short alias must reach the canonical path, or be \
     covered by a rescan at or above it"
  );
  assert!(
    published_alias.is_none(),
    "the short alias was published as an authoritative location: {published_alias:?}"
  );

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// Unwatch/rewatch cycles reclaim cleanly — the registry never leaks a root.
#[tokio::test]
async fn watch_unwatch_cycles_reclaim() {
  let root = scratch_root("cycles");
  let w = rdcw_watcher();
  for _ in 0..8 {
    let handle = w.watch(&root, Interest::all()).await.expect("watch");
    w.unwatch(handle).await.expect("unwatch");
  }
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// [verify] root delete under a live watch: the scope dies loudly (a terminal
/// Rescan/root-gone shape), never silently.
#[tokio::test]
async fn root_delete_is_loud() {
  let parent = scratch_root("rootdel");
  let root = parent.join("victim");
  std::fs::create_dir_all(&root).expect("mkdir");
  let root = root.canonicalize().expect("canonicalize");
  let mut w = rdcw_watcher();
  let _handle = w.watch(&root, Interest::all()).await.expect("watch");

  std::fs::remove_dir_all(&root).expect("delete the watched root");
  assert!(
    wait_for(&mut w, |e| matches!(e.kind(), EventKind::Rescan)
      || e.path().starts_with(&root))
    .await
    .is_some(),
    "the watched root's deletion surfaces in-band"
  );

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&parent);
}

/// [verify] overflow: a burst far past the kernel buffer forces the loss
/// path, which must surface as a Rescan — never silence, never a wedge.
#[tokio::test]
async fn overflow_degrades_to_rescan() {
  let root = scratch_root("overflow");
  let mut w = rdcw_watcher();
  let _handle = w.watch(&root, Interest::all()).await.expect("watch");

  // A dense burst of tiny creates+removes: far more record bytes than one
  // 64 KiB kernel buffer holds while the pump is between reads.
  for round in 0..64 {
    for i in 0..256 {
      let f = root.join(format!("burst-{round}-{i}.tmp"));
      std::fs::write(&f, b"x").ok();
      std::fs::remove_file(&f).ok();
    }
  }
  assert!(
    wait_for(&mut w, |e| matches!(e.kind(), EventKind::Rescan)
      || e.path().starts_with(&root))
    .await
    .is_some(),
    "the burst surfaces events or the loss rescan"
  );

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// A UNC root is refused at the barrier with a typed error, never a silent
/// dead watch.
#[tokio::test]
async fn unc_root_is_refused() {
  let w = rdcw_watcher();
  let err = w
    .watch(Path::new(r"\\localhost\c$\Windows"), Interest::all())
    .await
    .expect_err("a UNC root cannot start");
  let text = format!("{err}");
  assert!(!text.is_empty());
  w.close().await.expect("close");
}

/// Forcing the foreign fanotify backend fails typed on Windows.
#[tokio::test]
async fn foreign_backend_is_typed() {
  let root = scratch_root("foreign");
  let w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Fanotify)).expect("build");
  let err = w
    .watch(&root, Interest::all())
    .await
    .expect_err("fanotify does not exist on Windows");
  assert!(
    matches!(
      &err,
      tributary_fs::WatchRootError::Source(tributary_fs::SourceError::ForeignBackend {
        requested: Backend::Fanotify,
      })
    ),
    "{err:?}"
  );
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// The zoo cells: the verb flow on the identity-bearing volume, and the
/// typed refusal on the identity-less one — FAT32 reports no stable file
/// ids (`FileIdInfo` refuses), so the identity bracket cannot hold and the
/// barrier refuses the watch rather than run without `RootReplaced`
/// detection or registry disjointness. A recorded v1 boundary.
#[tokio::test]
async fn zoo_volumes_flow() {
  if let Some(base) = std::env::var_os("TRIBUTARY_ZOO_NTFS") {
    let root = PathBuf::from(&base).join(format!("watch-{}", std::process::id()));
    std::fs::create_dir_all(&root).expect("zoo scratch");
    let root = root.canonicalize().expect("canonicalize zoo root");
    let mut w = rdcw_watcher();
    let _handle = w.watch(&root, Interest::all()).await.expect("watch");
    let file = root.join("zoo.txt");
    std::fs::write(&file, b"x").expect("create");
    assert!(
      wait_for(&mut w, |e| covers(e, &file)).await.is_some(),
      "ntfs zoo: the create is delivered"
    );
    w.close().await.expect("close");
    let _ = std::fs::remove_dir_all(&root);
  } else {
    common::skip_notice(format_args!(
      "zoo_volumes_flow: TRIBUTARY_ZOO_NTFS is unset (no zoo)"
    ));
  }

  if let Some(base) = std::env::var_os("TRIBUTARY_ZOO_FAT32") {
    let root = PathBuf::from(&base).join(format!("watch-{}", std::process::id()));
    std::fs::create_dir_all(&root).expect("zoo scratch");
    let root = root.canonicalize().expect("canonicalize zoo root");
    let w = rdcw_watcher();
    let err = w
      .watch(&root, Interest::all())
      .await
      .expect_err("an identity-less filesystem cannot hold the bracket");
    assert!(
      matches!(
        &err,
        tributary_fs::WatchRootError::Source(tributary_fs::SourceError::RootUnavailable { .. })
      ),
      "{err:?}"
    );
    w.close().await.expect("close");
    let _ = std::fs::remove_dir_all(&root);
  } else {
    common::skip_notice(format_args!(
      "zoo_volumes_flow: TRIBUTARY_ZOO_FAT32 is unset (no zoo)"
    ));
  }
}

/// The journal arm: on an elevated runner the NTFS zoo volume (or the
/// workspace volume) selects the USN backend under Auto; unprivileged hosts
/// legally fall back to RDCW — both selections must flow events.
///
/// The one cell in this suite that must NOT pin a backend: it is the ladder
/// itself under test, so it builds with [`auto_watcher`].
#[tokio::test]
async fn auto_selection_flows_on_either_arm() {
  let root = scratch_root("auto-arm");
  let mut w = auto_watcher();
  let handle = w.watch(&root, Interest::all()).await.expect("watch");
  let backend = w.backend_of(handle).expect("live root");
  assert!(
    matches!(backend.as_str(), "rdcw" | "usn-journal"),
    "the windows Auto arm selects a windows primitive: {backend}"
  );

  let file = root.join("auto.txt");
  std::fs::write(&file, b"x").expect("create");
  assert!(
    wait_for(&mut w, |e| covers(e, &file)).await.is_some(),
    "{backend}: the create is delivered"
  );
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// Reads a volume's current USN journal identifier through `fsutil`.
///
/// The identifier is the FIRST hexadecimal field `fsutil usn queryjournal`
/// prints, which is the one part of that output whose position does not move
/// with the runner's display language. `None` means the volume has no journal
/// (or the tool refused), which callers turn into a loud failure rather than a
/// silent pass — the whole point of the cells that read it is to prove which
/// discontinuity they produced.
fn journal_id(drive: &str) -> Option<String> {
  let out = std::process::Command::new("fsutil")
    .args(["usn", "queryjournal", drive])
    .output()
    .ok()?;
  if !out.status.success() {
    return None;
  }
  String::from_utf8_lossy(&out.stdout)
    .split_whitespace()
    .find(|token| token.starts_with("0x") || token.starts_with("0X"))
    .map(str::to_owned)
}

/// [verify] journal-ID CHANGE: deleting and recreating the journal under a
/// live watch invalidates the reader's journal identifier, and the stream must
/// surface the loss as a Rescan and keep delivering afterwards — never
/// silence, never a wedge.
///
/// This cell is deliberately NOT named for a wrap, and its precondition is
/// asserted rather than assumed. A wrap (same journal, `FirstUsn` advanced
/// past a live cursor, `ERROR_JOURNAL_ENTRY_DELETED`) and a journal-ID change
/// are different kernel discontinuities that merely happen to share this
/// crate's downstream reseed spine; a cell exercising one proves nothing about
/// the other, and while it CLAIMED to be the wrap cell it made the wrap row
/// look covered. Reaching the same helper is not the same as reaching it the
/// same way.
///
/// The same-journal truncation row is still open. It cannot be produced by
/// churn from outside the process — a live pump rides the journal's edge and
/// simply keeps up — so it needs a Windows-only seam that holds the reader
/// between reads while a volume-wide churn advances `FirstUsn` past its
/// captured cursor. That seam does not exist yet, and substituting a different
/// discontinuity for it is exactly what this cell used to do.
#[tokio::test]
async fn journal_id_change_degrades_to_rescan() {
  let Some(base) = std::env::var_os("TRIBUTARY_ZOO_WRAP") else {
    common::skip_notice(format_args!(
      "journal_id_change_degrades_to_rescan: TRIBUTARY_ZOO_WRAP is unset"
    ));
    return;
  };
  let root = PathBuf::from(&base).join(format!("wrap-{}", std::process::id()));
  std::fs::create_dir_all(&root).expect("wrap scratch");
  let root = root.canonicalize().expect("canonicalize wrap root");
  // The wrap volume EXISTS to exercise the journal: force the selection so
  // a probe, seed, or startup regression fails the cell instead of quietly
  // riding the RDCW fallback while CI stays green. Capacities exceed the
  // WHOLE churn, so neither the consumer channel nor the transport budget
  // can overflow — the awaited Rescan can only be journal truncation.
  let mut w = TokioWatcher::new(
    WatcherOptions::new()
      .with_backend(Backend::UsnJournal)
      .with_event_capacity(std::num::NonZeroUsize::new(65_536).unwrap())
      .with_os_batch_capacity(std::num::NonZeroUsize::new(4_096).unwrap()),
  )
  .expect("build");
  let handle = w
    .watch(&root, Interest::all())
    .await
    .expect("the prepared wrap volume must start the forced journal");
  assert_eq!(w.backend_of(handle).expect("live").as_str(), "usn-journal");

  // Delete and recreate the journal under the live watch: the next read's
  // journal-identifier mismatch takes the loss → reseed → covering-rescan
  // spine. (The runner is Administrator; fsutil owns the volume state.)
  let drive = base
    .to_str()
    .and_then(|s| s.get(..2))
    .expect("the zoo exports a drive-lettered root")
    .to_owned();
  let before = journal_id(&drive).expect("the prepared wrap volume has a live journal");
  let delete = std::process::Command::new("fsutil")
    .args(["usn", "deletejournal", "/d", &drive])
    .status()
    .expect("fsutil runs");
  assert!(delete.success(), "deleting the sacrificial journal");
  let recreate = std::process::Command::new("fsutil")
    .args(["usn", "createjournal", "m=1048576", "a=262144", &drive])
    .status()
    .expect("fsutil runs");
  assert!(recreate.success(), "recreating the sacrificial journal");
  // The precondition this cell is named for, PROVEN rather than assumed: a
  // recreate that reused the identifier would leave the reader's cursor valid
  // and the Rescan below would then be some other discontinuity's.
  let after = journal_id(&drive).expect("the recreated journal is queryable");
  assert_ne!(
    before, after,
    "recreating the journal must change its identifier, or this cell is \
     exercising a discontinuity it did not produce"
  );
  // Post-loss activity gives the (re-anchored) stream something to read.
  std::fs::write(root.join("post-loss.txt"), b"x").expect("post-loss create");
  assert!(
    wait_for(&mut w, |e| matches!(e.kind(), EventKind::Rescan))
      .await
      .is_some(),
    "the journal loss surfaces its covering rescan"
  );

  // Journal deletion races the pump's reseed: the re-query lands either
  // AFTER the recreate (reseed re-anchors onto the new journal — the scope
  // survives) or INSIDE the deleted window (reseed fails — the ratified
  // terminal-fatal, and a REWATCH re-probes). Both are designed outcomes;
  // silence or a wedge is the only failure. Either way, delivery must
  // resume with a CONCRETE event no queued or terminal Rescan can fake.
  let mut w = if w.backend_of(handle).is_some() {
    w
  } else {
    // The terminal path: the dead scope was reported (the Rescan above);
    // the rewatch must start cleanly against the recreated journal.
    w.close().await.expect("close the dead-scope watcher");
    let fresh =
      TokioWatcher::new(WatcherOptions::new().with_backend(Backend::UsnJournal)).expect("build");
    let handle = fresh
      .watch(&root, Interest::all())
      .await
      .expect("the rewatch re-probes onto the recreated journal");
    assert_eq!(
      fresh.backend_of(handle).expect("live").as_str(),
      "usn-journal"
    );
    fresh
  };
  let probe = root.join("alive.txt");
  std::fs::write(&probe, b"x").expect("post-loss create");
  assert!(
    wait_for(&mut w, |e| delivered(e, &probe)).await.is_some(),
    "a concrete post-loss event flows"
  );
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// The birth refresh must AGREE with the spawn barrier's identity: a healthy
/// root survives it registered, delivers no unsolicited terminal Rescan, and
/// still flows a CONCRETE (non-Rescan) event afterwards. Pins the
/// stat-versus-handle identity representation staying in one system.
async fn birth_refresh_survives(backend: Backend, tag: &str) {
  // On a zoo host the journal leg runs on the journal-enabled NTFS volume
  // and a forced-USN startup failure is a FAILURE — the elevated runners
  // are exactly where this arm must prove itself.
  let zoo = std::env::var_os("TRIBUTARY_ZOO_NTFS");
  let root = match (&zoo, backend.is_usn_journal()) {
    (Some(base), true) => {
      let dir = PathBuf::from(base).join(format!("birth-{}", std::process::id()));
      std::fs::create_dir_all(&dir).expect("zoo scratch");
      dir.canonicalize().expect("canonicalize zoo root")
    }
    _ => scratch_root(tag),
  };
  let mut w = TokioWatcher::new(WatcherOptions::new().with_backend(backend)).expect("build");
  let handle = match w.watch(&root, Interest::all()).await {
    Ok(handle) => handle,
    // ONLY the typed probe refusal is a legitimate skip, and only with no
    // prepared elevated environment: every other error — CreateFailed,
    // StartFailed, the identity bracket — is a real USN regression.
    Err(tributary_fs::WatchRootError::Source(err))
      if backend.is_usn_journal()
        && zoo.is_none()
        && matches!(err, tributary_fs::SourceError::BackendProbeFailed { .. }) =>
    {
      common::skip_notice(format_args!(
        "birth_refresh({tag}): the forced journal's probe refused ({err})"
      ));
      return;
    }
    Err(err) => panic!("watch({tag}): {err}"),
  };

  // Give the post-spawn refresh (and any misclassified death it would
  // cause) time to land, while asserting nothing terminal arrives.
  let quiet = tokio::time::timeout(Duration::from_secs(3), w.next()).await;
  if let Ok(Some(event)) = &quiet {
    assert!(
      !matches!(event.kind(), EventKind::Rescan),
      "an unsolicited root Rescan right after registration is the birth \
       refresh misclassifying a healthy root: {event:?}"
    );
  }
  assert!(
    w.backend_of(handle).is_some(),
    "the scope must survive its birth refresh registered"
  );

  // And the stream still delivers CONCRETE events — a covering Rescan is
  // not accepted here, so a terminal-then-rescan death cannot fake this.
  let file = root.join("post-refresh.txt");
  std::fs::write(&file, b"x").expect("create");
  assert!(
    wait_for(&mut w, |e| delivered(e, &file)).await.is_some(),
    "a concrete post-refresh event flows"
  );

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn a_healthy_rdcw_root_survives_its_birth_refresh() {
  birth_refresh_survives(Backend::Rdcw, "birth-rdcw").await;
}

#[tokio::test]
async fn a_healthy_usn_root_survives_its_birth_refresh() {
  birth_refresh_survives(Backend::UsnJournal, "birth-usn").await;
}

/// A forced-journal root, on the zoo's journal-enabled NTFS volume where one is
/// prepared. Canonicalized, because the source canonicalizes the supplied root
/// and the exclusion set is matched on the paths AS SUPPLIED — an exclusion
/// spelled from an uncanonicalized root could not match an event path.
fn usn_root(tag: &str) -> PathBuf {
  match std::env::var_os("TRIBUTARY_ZOO_NTFS") {
    Some(base) => {
      let dir = PathBuf::from(base).join(format!("{tag}-{}", std::process::id()));
      std::fs::create_dir_all(&dir).expect("zoo scratch");
      dir.canonicalize().expect("canonicalize zoo root")
    }
    None => scratch_root(tag),
  }
}

/// Watches `root` with a forced journal, or skips loudly when no journal is
/// available AND no elevated zoo was prepared. On a zoo host every failure is a
/// real regression, exactly as [`birth_refresh_survives`] treats it.
async fn forced_usn_watch(
  cell: &str,
  root: &Path,
  options: WatcherOptions,
) -> Option<(TokioWatcher, tributary_fs::RootHandle)> {
  let zoo = std::env::var_os("TRIBUTARY_ZOO_NTFS");
  let w = TokioWatcher::new(options.with_backend(Backend::UsnJournal)).expect("build");
  match w.watch(root, Interest::all()).await {
    Ok(handle) => Some((w, handle)),
    Err(tributary_fs::WatchRootError::Source(err))
      if zoo.is_none() && matches!(err, tributary_fs::SourceError::BackendProbeFailed { .. }) =>
    {
      common::skip_notice(format_args!(
        "{cell}: the forced journal's probe refused ({err})"
      ));
      None
    }
    Err(err) => panic!("{cell}: watch: {err}"),
  }
}

/// THE COLD half of the exclusion guarantee, on a real journal: a PREEXISTING
/// excluded subtree consumes none of the directory cap.
///
/// The seed walk is where the journal arm learns the tree, and a cap it cannot
/// fit inside is not a degrade — it fails the walk, which fails the forced
/// backend's probe outright. With forty directories parked under the exclusion
/// and a cap of four, the watch succeeds only if the walk declined them before
/// learning them.
#[tokio::test]
async fn a_preexisting_excluded_subtree_never_consumes_the_seed_cap() {
  let root = usn_root("usn-excl-cold");
  std::fs::create_dir_all(root.join("keep")).expect("mkdir keep");
  for n in 0..40 {
    std::fs::create_dir_all(root.join("cache").join(format!("d{n}"))).expect("mkdir cache child");
  }

  let options = WatcherOptions::new()
    .with_exclusions(vec![root.join("cache")])
    .with_max_map_directories(Some(4));
  let Some((mut w, handle)) = forced_usn_watch(
    "a_preexisting_excluded_subtree_never_consumes_the_seed_cap",
    &root,
    options,
  )
  .await
  else {
    let _ = std::fs::remove_dir_all(&root);
    return;
  };
  assert_eq!(
    w.backend_of(handle).expect("live root").as_str(),
    "usn-journal"
  );

  // The reported tree still flows CONCRETE events — a rescan-only survivor
  // would prove nothing about the walk having mapped anything.
  let file = root.join("keep").join("probe.txt");
  std::fs::write(&file, b"x").expect("create in the reported tree");
  assert!(
    wait_for(&mut w, |e| delivered(e, &file)).await.is_some(),
    "the reported tree delivers after a fenced seed walk"
  );

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// THE LIVE half, on a real journal: churn on an excluded name consumes none of
/// the cap either, so it can never reach the map-overflow terminal that would
/// end the whole source.
///
/// Create/delete of one excluded directory is the shape a build cache makes, and
/// each incarnation is a fresh file reference — so every create is map GROWTH.
/// Growing past the cap answers `MapOverflow`, which is not a dropped event but
/// the source's death, taking the unrelated subscriptions on the same root with
/// it. The scope surviving fifty rounds under a cap of two IS the assertion.
#[tokio::test]
async fn live_excluded_churn_never_reaches_the_map_overflow_terminal() {
  let root = usn_root("usn-excl-live");
  std::fs::create_dir_all(root.join("keep")).expect("mkdir keep");

  let options = WatcherOptions::new()
    .with_exclusions(vec![root.join("cache")])
    .with_max_map_directories(Some(2));
  let Some((mut w, handle)) = forced_usn_watch(
    "live_excluded_churn_never_reaches_the_map_overflow_terminal",
    &root,
    options,
  )
  .await
  else {
    let _ = std::fs::remove_dir_all(&root);
    return;
  };

  let cache = root.join("cache");
  for _ in 0..50 {
    std::fs::create_dir(&cache).expect("create the excluded directory");
    std::fs::remove_dir(&cache).expect("remove the excluded directory");
  }

  assert!(
    w.backend_of(handle).is_some(),
    "excluded churn must never end the scope: the map cap belongs to the \
     reported tree"
  );
  let file = root.join("keep").join("after.txt");
  std::fs::write(&file, b"x").expect("create in the reported tree");
  assert!(
    wait_for(&mut w, |e| delivered(e, &file)).await.is_some(),
    "and the reported tree still delivers concrete events afterwards"
  );

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// Drains until the stream stays silent for `quiet`, and reports what it saw.
///
/// A cell that must attribute an observation to a LATER mutation cannot simply
/// wait for a predicate: an earlier mutation's event may still be in flight and
/// would satisfy it. Draining to silence first makes the next observation the
/// consequence of what happens next.
async fn quiesce(watcher: &mut TokioWatcher, quiet: Duration) -> usize {
  let mut seen = 0;
  while (tokio::time::timeout(quiet, watcher.next()).await).is_ok_and(|e| e.is_some()) {
    seen += 1;
  }
  seen
}

/// [verify] the journal names LINKS, not objects, and the close names the LAST
/// handle's link.
///
/// A file hard-linked as `<root>/in.txt` and `<outside>/out.txt` is written
/// through the watched link, written again — which NTFS records nothing for,
/// the kind already being in the session's mask — and then closed with the
/// OUTSIDE handle last. The close summary is the only convergence the journal
/// offers for the unrecorded write, and it carries the closing handle's
/// `Open.Link.Name`: a name under a parent the watched map does not know.
/// Routed there it was dropped as out-of-root and the consumer that read at the
/// first notice held half-written contents with nothing left to correct them.
///
/// The cell is a CONVERGENCE claim, deliberately: it drains to silence before
/// the last close so the observation it then waits for is attributable to that
/// close, and it asks [`covers`] rather than `delivered` because the honest
/// repair for a link the record does not name is a cover, not a verb. What it
/// cannot pin on a live kernel is WHICH record produced the repair; the routing
/// decision itself is pinned deterministically by the admission unit cells.
#[tokio::test]
async fn a_close_through_an_outside_hard_link_still_converges_the_watched_one() {
  // Hard links cannot cross volumes, so the outside link is a SIBLING of the
  // watched root on the same volume — the zoo journal volume where one is
  // prepared, the temp volume otherwise.
  let zoo = std::env::var_os("TRIBUTARY_ZOO_NTFS");
  let (root, outside) = match &zoo {
    Some(base) => {
      let stem = PathBuf::from(base).join(format!("hardlink-{}", std::process::id()));
      let root = stem.join("watched");
      let outside = stem.join("elsewhere");
      std::fs::create_dir_all(&root).expect("zoo scratch");
      std::fs::create_dir_all(&outside).expect("zoo scratch");
      (
        root.canonicalize().expect("canonicalize"),
        outside.canonicalize().expect("canonicalize"),
      )
    }
    None => {
      let root = scratch_root("hardlink-watched");
      let outside = scratch_root("hardlink-elsewhere");
      (root, outside)
    }
  };
  let watched = root.join("in.txt");
  let unwatched = outside.join("out.txt");
  // Both links exist BEFORE the watch, so nothing the cell waits for can be
  // the creation's own traffic.
  std::fs::write(&watched, b"0").expect("create the watched link");
  std::fs::hard_link(&watched, &unwatched).expect("the outside hard link");

  let mut w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::UsnJournal))
    .expect("build watcher");
  let handle = match w.watch(&root, Interest::all()).await {
    Ok(handle) => handle,
    Err(tributary_fs::WatchRootError::Source(err))
      if zoo.is_none() && matches!(err, tributary_fs::SourceError::BackendProbeFailed { .. }) =>
    {
      common::skip_notice(format_args!(
        "a_close_through_an_outside_hard_link_still_converges_the_watched_one: the forced \
         journal's probe refused ({err})"
      ));
      return;
    }
    Err(err) => panic!("watch: {err}"),
  };
  assert_eq!(w.backend_of(handle).expect("live").as_str(), "usn-journal");

  // Both handles open at once: the session spans them, and only the LAST close
  // writes the summary record.
  let mut inside_handle = std::fs::OpenOptions::new()
    .write(true)
    .open(&watched)
    .expect("open the watched link");
  let outside_handle = std::fs::OpenOptions::new()
    .write(true)
    .open(&unwatched)
    .expect("open the outside link");

  use std::io::{Seek, SeekFrom, Write};
  inside_handle.write_all(b"1").expect("first write");
  inside_handle.flush().expect("flush");
  assert!(
    wait_for(&mut w, |e| covers(e, &watched)).await.is_some(),
    "the first write is noticed at the watched link"
  );

  // The repeat NTFS writes no record for: same kind, already in the mask.
  inside_handle.seek(SeekFrom::Start(0)).expect("rewind");
  inside_handle.write_all(b"2").expect("second write");
  inside_handle.flush().expect("flush");
  drop(inside_handle);
  // Everything in flight is consumed here, so what follows belongs to the last
  // close.
  quiesce(&mut w, Duration::from_secs(3)).await;

  drop(outside_handle);
  assert!(
    wait_for(&mut w, |e| covers(e, &watched)).await.is_some(),
    "the close through the OUTSIDE link must still repair the watched one"
  );

  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
  let _ = std::fs::remove_dir_all(&outside);
}

/// Drains until the stream stays silent for `quiet`, folding everything seen
/// into the reference consumer.
///
/// A convergence claim about a COVER cannot be asked as a predicate wait: the
/// question is not whether some rescan arrived but whether what arrived is
/// enough to put the consumer's own index back in step with the tree, and only
/// a consumer can answer that.
async fn drain_into(
  watcher: &mut TokioWatcher,
  inventory: &mut common::Inventory,
  quiet: Duration,
) -> usize {
  let mut seen = 0;
  while let Ok(Some(event)) = tokio::time::timeout(quiet, watcher.next()).await {
    inventory.apply(&event);
    seen += 1;
  }
  seen
}

/// [verify] A SILENT REPEAT RENAME OF A WATCHED HARD LINK still puts the
/// consumer back in step.
///
/// A journal session is keyed by FILE REFERENCE and one reference carries many
/// hard links, of which only some are inside the watched root. NTFS records a
/// change only when its kind is not already in that reference's accumulated
/// mask, so once ANY rename bit stands, a further rename of ANY of its links
/// writes no record at all. The sequence that turns those two facts into a
/// permanently wrong consumer is exactly this one:
///
/// 1. `<root>/in.txt` and `<outside>/out.txt` are two links of one file, and
///    the consumer's index holds `in.txt`;
/// 2. one handle is opened on the OUTSIDE link and held, so the session spans
///    everything below;
/// 3. the OUTSIDE link is renamed. Both of its endpoints are links this scope
///    does not report, so the source is told nothing it can act on — but the
///    rename bits now stand for the whole reference;
/// 4. the WATCHED link is renamed. The kind is already in the mask, so this
///    writes NO RECORD: a rename inside the watched tree, invisible;
/// 5. the last handle closes, through the OUTSIDE link, so even the close
///    summary names a link the map cannot resolve.
///
/// Every record the source can possibly see in that sequence has an unreported
/// end. A source that books its unproven-location debt from those endpoints
/// alone books nothing, emits nothing, and leaves the consumer holding
/// `in.txt` for as long as it lives, with nothing later in the stream to
/// correct it.
///
/// The claim is therefore made on the CONSUMER rather than on an event: a
/// [`common::Inventory`] seeded from the tree applies concrete verbs and
/// discharges rescans by re-reading, so it converges whether the repair arrives
/// as a verb or as a cover, and stays diverged if nothing arrives at all. What
/// this cell cannot pin on a live kernel is WHICH record produced the repair;
/// the accounting decision itself is pinned deterministically by the admission
/// unit cells.
///
/// CI-ONLY. It needs a real journal-armed NTFS volume and two links of one file
/// on it, so it cannot run on a non-Windows host at all.
#[tokio::test]
async fn a_silently_renamed_watched_hard_link_still_converges_the_consumer() {
  // Hard links cannot cross volumes, so the outside link is a SIBLING of the
  // watched root on the same volume.
  let zoo = std::env::var_os("TRIBUTARY_ZOO_NTFS");
  let (root, outside) = match &zoo {
    Some(base) => {
      let stem = PathBuf::from(base).join(format!("silentlink-{}", std::process::id()));
      let root = stem.join("watched");
      let outside = stem.join("elsewhere");
      std::fs::create_dir_all(&root).expect("zoo scratch");
      std::fs::create_dir_all(&outside).expect("zoo scratch");
      (
        root.canonicalize().expect("canonicalize"),
        outside.canonicalize().expect("canonicalize"),
      )
    }
    None => (
      scratch_root("silentlink-watched"),
      scratch_root("silentlink-elsewhere"),
    ),
  };
  let watched = root.join("in.txt");
  let watched_moved = root.join("in-moved.txt");
  let unwatched = outside.join("out.txt");
  let unwatched_moved = outside.join("out-moved.txt");
  // Both links exist BEFORE the watch, so nothing observed afterwards can be
  // the creation's own traffic.
  std::fs::write(&watched, b"0").expect("create the watched link");
  std::fs::hard_link(&watched, &unwatched).expect("the outside hard link");

  let mut w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::UsnJournal))
    .expect("build watcher");
  let handle = match w.watch(&root, Interest::all()).await {
    Ok(handle) => handle,
    Err(tributary_fs::WatchRootError::Source(err))
      if zoo.is_none() && matches!(err, tributary_fs::SourceError::BackendProbeFailed { .. }) =>
    {
      common::skip_notice(format_args!(
        "a_silently_renamed_watched_hard_link_still_converges_the_consumer: the forced \
         journal's probe refused ({err})"
      ));
      return;
    }
    Err(err) => panic!("watch: {err}"),
  };
  assert_eq!(w.backend_of(handle).expect("live").as_str(), "usn-journal");

  // The consumer's index, exactly as a real one takes it when the watch opens.
  let mut inventory = common::Inventory::seeded(&root);
  assert!(
    inventory.disagreement().is_empty(),
    "the premise: the consumer starts in step: {:?}",
    inventory.disagreement()
  );

  // The session that spans both renames, opened through the OUTSIDE link and
  // closed last. Rust's `OpenOptions` shares delete, so both renames proceed
  // while it is held.
  let outside_handle = std::fs::OpenOptions::new()
    .write(true)
    .open(&unwatched)
    .expect("open the outside link");

  std::fs::rename(&unwatched, &unwatched_moved).expect("rename the OUTSIDE link first");
  // Everything the outside rename could produce is consumed here, so what
  // remains is attributable to the watched link's move and to the close.
  drain_into(&mut w, &mut inventory, Duration::from_secs(3)).await;

  // The rename the journal writes no record for: the bits already stand.
  std::fs::rename(&watched, &watched_moved).expect("rename the WATCHED link in silence");
  drain_into(&mut w, &mut inventory, Duration::from_secs(3)).await;

  drop(outside_handle);
  drain_into(&mut w, &mut inventory, Duration::from_secs(5)).await;

  let disagreement = inventory.disagreement();
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
  let _ = std::fs::remove_dir_all(&outside);
  assert!(
    disagreement.is_empty(),
    "a rename of a link inside the watched tree must not be able to hide behind \
     an earlier rename of a link outside it: {disagreement:?}"
  );
}

/// A same-volume replace keeps the backend: widening the root re-runs the
/// spawn (and under a FORCED RDCW selection resolves RDCW again), the
/// covering `Rescan` bridges the swap, and newly covered ground is live
/// under the fresh subtree stream.
#[tokio::test]
async fn replace_root_same_volume_keeps_the_backend() {
  let root = scratch_root("replace");
  let sub = root.join("y");
  std::fs::create_dir_all(&sub).expect("mkdir");
  let mut w = rdcw_watcher();
  let handle = w.watch(&sub, Interest::all()).await.expect("watch");
  assert_eq!(w.backend_of(handle).expect("live").as_str(), "rdcw");

  w.replace_root(handle, &root)
    .await
    .expect("the swap commits");
  assert_eq!(w.root_path(handle), Some(root.clone()), "the view re-roots");
  assert_eq!(
    w.backend_of(handle).expect("live").as_str(),
    "rdcw",
    "a same-volume swap keeps the backend"
  );
  let covering = wait_for(&mut w, |e| e.is_rescan() && e.path() == root).await;
  assert!(covering.is_some(), "the covering Rescan arrives");

  let outside = root.join("outside.txt");
  std::fs::write(&outside, b"x").expect("write outside");
  assert!(
    wait_for(&mut w, |e| covers(e, &outside)).await.is_some(),
    "newly covered ground is live"
  );
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// [verify] cross-volume replace under Auto: the selection ladder re-runs
/// per spawn, so the backend may legitimately flip rdcw ↔ usn-journal with
/// runner elevation. Pinned is only the KR contract — the swap commits, the
/// covering `Rescan` arrives, the resolved backend is one of the two KR
/// arms, and the new volume is live. Zoo-gated like the other volume cells.
#[tokio::test]
async fn replace_root_cross_volume_reruns_the_ladder() {
  let Some(base) = std::env::var_os("TRIBUTARY_ZOO_NTFS") else {
    common::skip_notice(format_args!(
      "replace_root_cross_volume_reruns_the_ladder: TRIBUTARY_ZOO_NTFS is unset"
    ));
    return;
  };
  let old_root = scratch_root("replace-xvol");
  let new_root = PathBuf::from(&base).join(format!("replace-{}", std::process::id()));
  std::fs::create_dir_all(&new_root).expect("zoo scratch");
  let new_root = new_root.canonicalize().expect("canonicalize zoo root");
  let mut w = auto_watcher();
  let handle = w.watch(&old_root, Interest::all()).await.expect("watch");
  let before = w.backend_of(handle).expect("live").as_str().to_owned();

  w.replace_root(handle, &new_root)
    .await
    .expect("the swap commits");
  assert_eq!(w.root_path(handle), Some(new_root.clone()));
  let after = w.backend_of(handle).expect("live").as_str().to_owned();
  assert!(
    matches!(after.as_str(), "rdcw" | "usn-journal"),
    "a KR arm resolves: {after}"
  );
  eprintln!("cross-volume ladder: {before} -> {after} (elevation-dependent)");
  let covering = wait_for(&mut w, |e| e.is_rescan() && e.path() == new_root).await;
  assert!(covering.is_some(), "the covering Rescan arrives");

  let probe = new_root.join("xvol.txt");
  std::fs::write(&probe, b"x").expect("create");
  assert!(
    wait_for(&mut w, |e| covers(e, &probe)).await.is_some(),
    "the new volume is live"
  );
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&new_root);
  let _ = std::fs::remove_dir_all(&old_root);
}

/// The prefix every line of the close-name measurement carries, so one `grep`
/// over a CI log recovers the whole answer.
const CLOSE_NAME_PROBE: &str = "TRIBUTARY-USN-CLOSE-NAME-PROBE";

/// Writes one line straight to the process's own stderr.
///
/// `eprintln!` routes through libtest's per-cell output capture, which is
/// printed only when the cell FAILS or when `--nocapture` is passed — and the
/// integration job passes neither. A cell whose entire product is a
/// measurement must land that measurement in the log while PASSING, so it
/// writes to the inherited handle, which the capture does not intercept.
fn probe_log(args: std::fmt::Arguments<'_>) {
  use std::io::Write;
  let mut err = std::io::stderr().lock();
  let _ = writeln!(err, "{args}");
  let _ = err.flush();
}

/// The change-journal ABI the close-name probe reads through.
///
/// Declared here rather than borrowed: `windows-sys` is a runtime dependency
/// of `tributary-fs` and not a dev-dependency, so an integration test cannot
/// name its types, and the backend's own bindings are crate-private. Every
/// layout below is the documented stable journal ABI and every size is pinned
/// at compile time, so a mistyped field is a build failure rather than a
/// plausible-looking wrong answer — which, for a cell that exists to settle a
/// question, is the only failure mode that matters.
mod journal_abi {
  use core::ffi::c_void;

  pub type Handle = *mut c_void;

  pub const GENERIC_READ: u32 = 0x8000_0000;
  pub const FILE_SHARE_READ: u32 = 0x1;
  pub const FILE_SHARE_WRITE: u32 = 0x2;
  pub const FILE_SHARE_DELETE: u32 = 0x4;
  pub const OPEN_EXISTING: u32 = 3;
  /// `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 61, METHOD_BUFFERED, FILE_ANY_ACCESS)`.
  pub const FSCTL_QUERY_USN_JOURNAL: u32 = 0x0009_00f4;
  /// `CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 46, METHOD_NEITHER, FILE_ANY_ACCESS)`.
  pub const FSCTL_READ_USN_JOURNAL: u32 = 0x0009_00bb;
  pub const USN_REASON_RENAME_OLD_NAME: u32 = 0x0000_1000;
  pub const USN_REASON_RENAME_NEW_NAME: u32 = 0x0000_2000;
  pub const USN_REASON_CLOSE: u32 = 0x8000_0000;

  pub fn invalid_handle() -> Handle {
    core::ptr::without_provenance_mut(usize::MAX)
  }

  #[repr(C)]
  #[derive(Default)]
  pub struct ByHandleFileInformation {
    pub file_attributes: u32,
    pub creation_time: [u32; 2],
    pub last_access_time: [u32; 2],
    pub last_write_time: [u32; 2],
    pub volume_serial_number: u32,
    pub file_size_high: u32,
    pub file_size_low: u32,
    pub number_of_links: u32,
    pub file_index_high: u32,
    pub file_index_low: u32,
  }

  /// `USN_JOURNAL_DATA_V0` — the smallest form, which the driver fills when
  /// the output buffer is exactly its size.
  #[repr(C)]
  #[derive(Default)]
  pub struct UsnJournalDataV0 {
    pub usn_journal_id: u64,
    pub first_usn: i64,
    pub next_usn: i64,
    pub lowest_valid_usn: i64,
    pub max_usn: i64,
    pub maximum_size: u64,
    pub allocation_delta: u64,
  }

  /// `READ_USN_JOURNAL_DATA_V0` — `V2` records only, which is what the NTFS
  /// zoo volume emits and all this measurement needs.
  #[repr(C)]
  pub struct ReadUsnJournalDataV0 {
    pub start_usn: i64,
    pub reason_mask: u32,
    pub return_only_on_close: u32,
    pub timeout: u64,
    pub bytes_to_wait_for: u64,
    pub usn_journal_id: u64,
  }

  const _: () = assert!(size_of::<ByHandleFileInformation>() == 52);
  const _: () = assert!(size_of::<UsnJournalDataV0>() == 56);
  const _: () = assert!(size_of::<ReadUsnJournalDataV0>() == 40);

  // `raw-dylib` rather than an import library: rustc synthesizes the imports
  // itself, so the probe needs nothing on the linker's search path. It is the
  // same mechanism the crate's own `windows-sys` bindings already link through
  // in this job, so it is proven on these runners rather than assumed.
  #[link(name = "kernel32", kind = "raw-dylib")]
  unsafe extern "system" {
    pub fn CreateFileW(
      file_name: *const u16,
      desired_access: u32,
      share_mode: u32,
      security_attributes: *const c_void,
      creation_disposition: u32,
      flags_and_attributes: u32,
      template_file: Handle,
    ) -> Handle;
    pub fn CloseHandle(handle: Handle) -> i32;
    pub fn DeviceIoControl(
      device: Handle,
      control_code: u32,
      in_buffer: *const c_void,
      in_buffer_size: u32,
      out_buffer: *mut c_void,
      out_buffer_size: u32,
      bytes_returned: *mut u32,
      overlapped: *mut c_void,
    ) -> i32;
    pub fn GetFileInformationByHandle(handle: Handle, info: *mut ByHandleFileInformation) -> i32;
    pub fn CreateHardLinkW(
      new_file_name: *const u16,
      existing_file_name: *const u16,
      security_attributes: *const c_void,
    ) -> i32;
  }
}

use journal_abi::{
  ByHandleFileInformation, CloseHandle, CreateFileW, CreateHardLinkW, DeviceIoControl,
  FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FSCTL_QUERY_USN_JOURNAL,
  FSCTL_READ_USN_JOURNAL, GENERIC_READ, GetFileInformationByHandle, Handle, OPEN_EXISTING,
  ReadUsnJournalDataV0, USN_REASON_CLOSE, USN_REASON_RENAME_NEW_NAME, USN_REASON_RENAME_OLD_NAME,
  UsnJournalDataV0, invalid_handle,
};

/// Creates `link` as a second name for the file `existing` already names.
fn create_hard_link(link: &Path, existing: &Path) -> Result<(), String> {
  let wide = |path: &Path| -> Vec<u16> {
    path
      .to_string_lossy()
      .encode_utf16()
      .chain([0])
      .collect::<Vec<u16>>()
  };
  let (link, existing) = (wide(link), wide(existing));
  // SAFETY: both strings are NUL-terminated and outlive the call; a null
  // security descriptor is the documented "default".
  let ok = unsafe { CreateHardLinkW(link.as_ptr(), existing.as_ptr(), std::ptr::null()) };
  if ok == 0 {
    return Err(format!(
      "creating a hard link failed ({}) — the volume may not be NTFS",
      std::io::Error::last_os_error()
    ));
  }
  Ok(())
}

/// A volume device handle, closed once on drop so every early return is clean.
struct VolumeHandle(Handle);

impl Drop for VolumeHandle {
  fn drop(&mut self) {
    // SAFETY: the handle came from a successful `CreateFileW`, is owned solely
    // by this value, and is closed exactly once.
    unsafe { CloseHandle(self.0) };
  }
}

/// Opens `\\.\X:` for journal reads. Effectively requires elevation, which is
/// what makes an unprivileged developer box a legitimate skip.
fn open_volume(drive: char) -> Result<VolumeHandle, String> {
  let device: Vec<u16> = format!(r"\\.\{drive}:").encode_utf16().chain([0]).collect();
  // SAFETY: `device` is NUL-terminated and outlives the call; a null security
  // descriptor and a null template are the documented "none".
  let raw = unsafe {
    CreateFileW(
      device.as_ptr(),
      GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      std::ptr::null(),
      OPEN_EXISTING,
      0,
      std::ptr::null_mut(),
    )
  };
  if raw == invalid_handle() {
    return Err(format!(
      "opening the volume device \\\\.\\{drive}: failed ({}) — journal reads need elevation",
      std::io::Error::last_os_error()
    ));
  }
  Ok(VolumeHandle(raw))
}

/// The volume's live journal identity and its next-to-be-minted USN.
fn query_journal(volume: &VolumeHandle) -> Result<(u64, i64), String> {
  let mut data = UsnJournalDataV0::default();
  let mut returned = 0u32;
  // SAFETY: the handle is live and opened without FILE_FLAG_OVERLAPPED, so a
  // null OVERLAPPED makes the call synchronous; `data` is a writable,
  // correctly-sized output buffer for the control code.
  let ok = unsafe {
    DeviceIoControl(
      volume.0,
      FSCTL_QUERY_USN_JOURNAL,
      std::ptr::null(),
      0,
      (&raw mut data).cast(),
      u32::try_from(size_of::<UsnJournalDataV0>()).unwrap_or(u32::MAX),
      &raw mut returned,
      std::ptr::null_mut(),
    )
  };
  if ok == 0 {
    return Err(format!(
      "querying the volume journal failed ({}) — the volume may have none",
      std::io::Error::last_os_error()
    ));
  }
  Ok((data.usn_journal_id, data.next_usn))
}

/// One journal record, reduced to the three fields the measurement turns on.
struct ProbeRecord {
  usn: i64,
  frn: u128,
  reason: u32,
  name: String,
}

/// Decodes one `FSCTL_READ_USN_JOURNAL` output: the leading next-USN cursor
/// followed by `RecordLength`-strided `USN_RECORD_V2`/`V3` records.
///
/// Deliberately a separate, defensive walk rather than a reach into the
/// backend's decoder: a probe that shares the decoder it is meant to inform
/// would report that decoder's beliefs back to itself.
fn decode_journal(buf: &[u8]) -> (i64, Vec<ProbeRecord>) {
  if buf.len() < 8 {
    return (0, Vec::new());
  }
  let next_usn = i64::from_le_bytes(buf[..8].try_into().expect("8 bytes"));
  let mut records = Vec::new();
  let mut at = 8usize;
  while at + 8 <= buf.len() {
    let stride = u32::from_le_bytes(buf[at..at + 4].try_into().expect("4 bytes")) as usize;
    let major = u16::from_le_bytes(buf[at + 4..at + 6].try_into().expect("2 bytes"));
    let Some(end) = at.checked_add(stride).filter(|end| *end <= buf.len()) else {
      break;
    };
    if stride == 0 {
      break;
    }
    // V2 carries 64-bit references, V3 the 128-bit form; both share the tail
    // layout that follows them.
    let (header, tail) = match major {
      2 => (60usize, at + 24),
      3 => (76usize, at + 40),
      _ => {
        at = end;
        continue;
      }
    };
    if stride < header || tail + 36 > buf.len() {
      break;
    }
    let frn = if major == 2 {
      u128::from(u64::from_le_bytes(
        buf[at + 8..at + 16].try_into().expect("8 bytes"),
      ))
    } else {
      u128::from_le_bytes(buf[at + 8..at + 24].try_into().expect("16 bytes"))
    };
    let usn = i64::from_le_bytes(buf[tail..tail + 8].try_into().expect("8 bytes"));
    let reason = u32::from_le_bytes(buf[tail + 16..tail + 20].try_into().expect("4 bytes"));
    let name_len =
      u16::from_le_bytes(buf[tail + 32..tail + 34].try_into().expect("2 bytes")) as usize;
    let name_off =
      u16::from_le_bytes(buf[tail + 34..tail + 36].try_into().expect("2 bytes")) as usize;
    let name = match at
      .checked_add(name_off)
      .and_then(|start| start.checked_add(name_len).map(|stop| (start, stop)))
      .filter(|(_, stop)| *stop <= end && name_len.is_multiple_of(2) && name_off >= header)
    {
      Some((start, stop)) => {
        let units: Vec<u16> = buf[start..stop]
          .as_chunks::<2>()
          .0
          .iter()
          .copied()
          .map(u16::from_le_bytes)
          .collect();
        String::from_utf16_lossy(&units)
      }
      None => "<unnameable>".to_owned(),
    };
    records.push(ProbeRecord {
      usn,
      frn,
      reason,
      name,
    });
    at = end;
  }
  (next_usn, records)
}

/// Drains the journal from `cursor`, appending EVERY record it decodes — the
/// whole volume's stream, in journal order. Returns the cursor the next drain
/// resumes from.
///
/// IT DELIBERATELY FILTERS NOTHING, and that is load-bearing rather than
/// incidental. The backend reads this same volume-wide stream, and one of its
/// pairing rules is about the interleaving: a parked rename half is drained
/// before any record that takes its session entry, which is every record of
/// another file reference. A drain that kept only one subject's records would
/// hand `moves_are_recorded_afresh` a stream in which that rule can never fire,
/// so `OLD, someone else's record, NEW` would arrive as an adjacent pair and be
/// certified as one the source joins — while the source widows both halves. A
/// caller that wants one subject's records for a MEASUREMENT filters what comes
/// back; the GATE must not.
fn drain_journal(
  volume: &VolumeHandle,
  journal_id: u64,
  cursor: i64,
  into: &mut Vec<ProbeRecord>,
) -> Result<i64, String> {
  // The prepared zoo volume is otherwise idle, so this terminates in a couple
  // of rounds; the ceiling only bounds a busy fallback volume.
  const ROUNDS: usize = 512;
  let mut cursor = cursor;
  let mut buffer = vec![0u8; 64 * 1024];
  for _ in 0..ROUNDS {
    let request = ReadUsnJournalDataV0 {
      start_usn: cursor,
      reason_mask: u32::MAX,
      return_only_on_close: 0,
      timeout: 0,
      // Zero means "return whatever is there now" — the probe must never
      // block waiting for a volume that has gone quiet.
      bytes_to_wait_for: 0,
      usn_journal_id: journal_id,
    };
    let mut returned = 0u32;
    // SAFETY: the handle is live and synchronous; the request and the output
    // buffer are live, correctly sized, and exclusively borrowed for the
    // duration of this synchronous call.
    let ok = unsafe {
      DeviceIoControl(
        volume.0,
        FSCTL_READ_USN_JOURNAL,
        (&raw const request).cast(),
        u32::try_from(size_of::<ReadUsnJournalDataV0>()).unwrap_or(u32::MAX),
        buffer.as_mut_ptr().cast(),
        u32::try_from(buffer.len()).unwrap_or(u32::MAX),
        &raw mut returned,
        std::ptr::null_mut(),
      )
    };
    if ok == 0 {
      return Err(format!(
        "reading the journal from usn {cursor} failed ({})",
        std::io::Error::last_os_error()
      ));
    }
    let (next, records) = decode_journal(&buffer[..returned as usize]);
    into.extend(records);
    if next == cursor {
      return Ok(cursor);
    }
    cursor = next;
  }
  Ok(cursor)
}

/// The drive letter a path is rooted at, through the `\\?\` prefix the scratch
/// roots canonicalize to.
fn drive_letter(path: &Path) -> Option<char> {
  let text = path.to_string_lossy().into_owned();
  let rest = text.strip_prefix(r"\\?\").unwrap_or(&text);
  let mut chars = rest.chars();
  let letter = chars.next()?;
  (letter.is_ascii_alphabetic() && chars.next() == Some(':')).then(|| letter.to_ascii_uppercase())
}

/// The file reference number behind an open handle.
fn file_reference(handle: Handle) -> Result<u128, String> {
  let mut info = ByHandleFileInformation::default();
  // SAFETY: `handle` is a live file handle borrowed for this call, and `info`
  // is a writable, correctly-sized output buffer.
  let ok = unsafe { GetFileInformationByHandle(handle, &raw mut info) };
  if ok == 0 {
    return Err(format!(
      "reading the file reference failed ({})",
      std::io::Error::last_os_error()
    ));
  }
  Ok(u128::from(
    (u64::from(info.file_index_high) << 32) | u64::from(info.file_index_low),
  ))
}

/// [measure] which NAME a `USN_REASON_CLOSE` record carries: the one its
/// session was OPENED under, or the subject's name at the moment of the close.
///
/// The question is not academic and has no documented answer. NTFS records a
/// change only when its kind is not already in the session's accumulated mask,
/// so a subject renamed TWICE on one open handle writes a record for the first
/// move and NOTHING for the second — the FID map keeps the first destination,
/// and for a directory every path resolved beneath it is silently wrong for as
/// long as the map lives. The close summary carries the subject's final parent
/// and name and is the one place that divergence is provable, but ONLY if a
/// close record's `FileName` is the current name. If it is instead the opening
/// name, comparing it against the map says nothing at all. Microsoft's
/// change-journal documentation does not say which it is, and it cannot be
/// observed on a non-Windows host.
///
/// THE GAP IS ALREADY CLOSED, CONSERVATIVELY: admission treats a close that
/// re-asserts its own session's rename bits as an unproven location and pays a
/// root cover (plus a reseed for a directory). That is correct and expensive —
/// ordinary single renames close with their rename bits recorded too, so every
/// in-root rename whose close is observed pays one. This measurement is what
/// makes a cheaper answer possible: if the close names the CURRENT link, the
/// summary becomes comparable against the map and the cover fires only on a
/// genuine disagreement; if it names the OPENING one, the blanket cover is the
/// floor and stays.
///
/// So this cell measures rather than decides. It renames ONCE (the second
/// rename is the defect, not the question), asserts only what is already
/// certain — that a close record exists at all — and prints every record the
/// session produced so the log interprets itself. The narrower comparison is
/// deliberately NOT written here: it becomes a separate change once the answer
/// is in a CI log.
///
/// Skipping is the failure mode this cell most has to avoid, since a skip
/// reads exactly like a pass. It therefore announces itself before it can
/// decide anything, writes past libtest's capture so a PASSING run still
/// carries the measurement, and treats an unmeasurable host as a hard failure
/// whenever the environment was prepared to measure (a zoo volume, or CI at
/// all) — a silent skip is only legal on a bare unprivileged developer box.
#[test]
fn usn_close_record_carries_which_name() {
  probe_log(format_args!(
    "{CLOSE_NAME_PROBE} start: measuring the FileName on a USN_REASON_CLOSE record"
  ));
  let zoo = std::env::var_os("TRIBUTARY_ZOO_NTFS");
  let must_measure = zoo.is_some() || std::env::var_os("CI").is_some();
  match measure_close_record_name(zoo.as_deref()) {
    Ok(()) => {}
    Err(why) if must_measure => panic!(
      "{CLOSE_NAME_PROBE} the measurement could not be taken on a host that was prepared \
       to take it (zoo present or CI set): {why}"
    ),
    Err(why) => probe_log(format_args!(
      "{CLOSE_NAME_PROBE} skip: {why} (legal only on an unprepared developer box)"
    )),
  }
}

fn measure_close_record_name(zoo: Option<&std::ffi::OsStr>) -> Result<(), String> {
  use std::io::Write;

  // The volume is opened and the cursor captured BEFORE anything is created,
  // so a host that cannot measure leaves no scratch behind — and so the cursor
  // provably predates every record this session writes.
  let base = match zoo {
    Some(base) => PathBuf::from(base),
    None => std::env::temp_dir()
      .canonicalize()
      .map_err(|e| format!("canonicalize temp dir: {e}"))?,
  };
  let drive =
    drive_letter(&base).ok_or_else(|| format!("{} is not on a lettered volume", base.display()))?;
  let volume = open_volume(drive)?;
  let (journal_id, start) = query_journal(&volume)?;

  let root = match zoo {
    Some(_) => {
      let dir = base.join(format!("usnclose-{}", std::process::id()));
      std::fs::create_dir_all(&dir).map_err(|e| format!("zoo scratch: {e}"))?;
      dir
        .canonicalize()
        .map_err(|e| format!("canonicalize zoo scratch: {e}"))?
    }
    None => scratch_root("usn-close-name"),
  };

  let before = root.join("close-name-before.txt");
  let after = root.join("close-name-after.txt");
  let (before_name, after_name) = (
    before
      .file_name()
      .expect("leaf")
      .to_string_lossy()
      .into_owned(),
    after
      .file_name()
      .expect("leaf")
      .to_string_lossy()
      .into_owned(),
  );

  // The session: one open, one write through it, ONE rename while it is still
  // open, then the close that writes the summary.
  let mut handle = std::fs::OpenOptions::new()
    .create(true)
    .truncate(true)
    .write(true)
    .open(&before)
    .map_err(|e| format!("open {}: {e}", before.display()))?;
  handle
    .write_all(b"close-record name probe")
    .and_then(|()| handle.flush())
    .map_err(|e| format!("write: {e}"))?;
  let frn = {
    use std::os::windows::io::AsRawHandle;
    file_reference(handle.as_raw_handle().cast())?
  };
  std::fs::rename(&before, &after).map_err(|e| format!("rename under the open handle: {e}"))?;
  drop(handle);

  probe_log(format_args!(
    "{CLOSE_NAME_PROBE} volume={drive}: root={} journal=0x{journal_id:016x} \
     frn=0x{frn:032x} start_usn={start}",
    root.display()
  ));
  probe_log(format_args!(
    "{CLOSE_NAME_PROBE} name the session was OPENED under: {before_name}"
  ));
  probe_log(format_args!(
    "{CLOSE_NAME_PROBE} name the subject had at CLOSE:      {after_name}"
  ));

  // The close record is written on the cleanup path, which the drop above does
  // not synchronize with; poll rather than sleep a fixed guess.
  let mut records = Vec::new();
  let mut cursor = start;
  for _ in 0..50 {
    // A MEASUREMENT, not a gate: the question is which name one subject's own
    // close record carries, so the volume's other traffic is noise and is
    // dropped here rather than in the drain. The gate below keeps it.
    cursor = drain_journal(&volume, journal_id, cursor, &mut records)?;
    records.retain(|record| record.frn == frn);
    if records
      .iter()
      .any(|record| record.reason & USN_REASON_CLOSE != 0)
    {
      break;
    }
    std::thread::sleep(Duration::from_millis(200));
  }

  for record in &records {
    probe_log(format_args!(
      "{CLOSE_NAME_PROBE} record usn={} reason=0x{:08x}{} name={}",
      record.usn,
      record.reason,
      if record.reason & USN_REASON_CLOSE != 0 {
        " CLOSE"
      } else {
        ""
      },
      record.name
    ));
  }

  let closes: Vec<&ProbeRecord> = records
    .iter()
    .filter(|record| record.reason & USN_REASON_CLOSE != 0)
    .collect();
  match closes.last() {
    Some(close) => {
      let verdict = if close.name == after_name {
        "CURRENT NAME — a close summary can be compared against the map"
      } else if close.name == before_name {
        "OPENING NAME — the map comparison would fire on every ordinary rename"
      } else {
        "NEITHER — the close named a third thing; do not build on it"
      };
      probe_log(format_args!(
        "{CLOSE_NAME_PROBE} ANSWER close FileName={} => {verdict}",
        close.name
      ));
    }
    None => probe_log(format_args!(
      "{CLOSE_NAME_PROBE} ANSWER none: no CLOSE record for this subject was observed"
    )),
  }
  probe_log(format_args!(
    "{CLOSE_NAME_PROBE} end: {} record(s) for this subject, {} of them CLOSE",
    records.len(),
    closes.len()
  ));

  let _ = std::fs::remove_dir_all(&root);
  // The ONE thing already certain, and the only thing asserted: the session
  // produced a close summary. Which name it carried is reported, never judged,
  // so the cell passes whichever way the kernel answers.
  assert!(
    !closes.is_empty(),
    "{CLOSE_NAME_PROBE}: a closed write session must produce a USN_REASON_CLOSE record"
  );
  Ok(())
}

/// The prefix every line of the repeat-rename measurement carries, so one
/// `grep` over a CI log recovers the whole answer.
const REPEAT_RENAME_PROBE: &str = "TRIBUTARY-USN-REPEAT-RENAME-PROBE";

/// [measure] WHETHER A SECOND RENAME ON ONE OPEN HANDLE WRITES ANY RECORD.
///
/// This is the single load-bearing assumption under every repeat-rename cover
/// the journal backend pays, and it is INFERRED rather than measured. Microsoft
/// documents the journal's repeat rule for writes — "several write operations
/// with no intervening close and reopen operations result in only one change
/// record" — and says nothing about renames. The backend applies the rule to
/// renames anyway, which is the conservative reading, and the whole cost
/// follows from it:
///
/// * a close that re-asserts its session's rename bits pays one root cover
///   (plus a reseed for a mapped directory), so every in-root rename whose
///   close is observed pays one;
/// * and a FILE whose observed rename endpoints were all OUTSIDE the reported
///   tree retains a latent debt its close pays, because a reference carries
///   many hard links and a silent second move may name a watched one. The
///   journal is volume-wide, so that is a cover per file rename ON THE VOLUME.
///
/// If NTFS in fact writes the second move — which is not unreasonable, since
/// both rename halves carry NAMES that a summary cannot reconstruct — then
/// nothing is silent, every one of those covers is unnecessary, and the whole
/// class collapses. One measurement decides it, and it cannot be taken off
/// Windows.
///
/// So this cell measures rather than decides: it renames TWICE through one held
/// handle, prints every record the session wrote, and asserts only what is
/// already certain — that the session produced a close summary. It passes
/// whichever way the kernel answers, and the narrower backend is written from
/// the log, not guessed from here.
///
/// Skipping is the failure mode it most has to avoid, since a skip reads
/// exactly like a pass, so it announces itself before it can decide anything,
/// writes past libtest's capture, and treats an unmeasurable host as a hard
/// failure whenever the environment was prepared to measure.
#[test]
fn usn_repeat_rename_on_one_handle_writes_which_records() {
  probe_log(format_args!(
    "{REPEAT_RENAME_PROBE} start: measuring whether a SECOND rename on one open handle \
     writes any USN record"
  ));
  let zoo = std::env::var_os("TRIBUTARY_ZOO_NTFS");
  let must_measure = zoo.is_some() || std::env::var_os("CI").is_some();
  match measure_repeat_rename(zoo.as_deref()) {
    Ok(()) => {}
    Err(why) if must_measure => panic!(
      "{REPEAT_RENAME_PROBE} the measurement could not be taken on a host that was prepared \
       to take it (zoo present or CI set): {why}"
    ),
    Err(why) => probe_log(format_args!(
      "{REPEAT_RENAME_PROBE} skip: {why} (legal only on an unprepared developer box)"
    )),
  }
}

fn measure_repeat_rename(zoo: Option<&std::ffi::OsStr>) -> Result<(), String> {
  // The volume is opened and the cursor captured BEFORE anything is created, so
  // a host that cannot measure leaves no scratch behind — and so the cursor
  // provably predates every record this session writes.
  let base = match zoo {
    Some(base) => PathBuf::from(base),
    None => std::env::temp_dir()
      .canonicalize()
      .map_err(|e| format!("canonicalize temp dir: {e}"))?,
  };
  let drive =
    drive_letter(&base).ok_or_else(|| format!("{} is not on a lettered volume", base.display()))?;
  let volume = open_volume(drive)?;
  let (journal_id, start) = query_journal(&volume)?;

  let root = match zoo {
    Some(_) => {
      let dir = base.join(format!("usnrepeat-{}", std::process::id()));
      std::fs::create_dir_all(&dir).map_err(|e| format!("zoo scratch: {e}"))?;
      dir
        .canonicalize()
        .map_err(|e| format!("canonicalize zoo scratch: {e}"))?
    }
    None => scratch_root("usn-repeat-rename"),
  };

  let first = root.join("repeat-first.txt");
  let second = root.join("repeat-second.txt");
  let third = root.join("repeat-third.txt");

  // ONE session: the handle is held across both renames, so no close intervenes
  // and the second move meets the rename bits already standing.
  let handle = std::fs::OpenOptions::new()
    .create(true)
    .truncate(true)
    .write(true)
    .open(&first)
    .map_err(|e| format!("open {}: {e}", first.display()))?;
  let frn = {
    use std::os::windows::io::AsRawHandle;
    file_reference(handle.as_raw_handle().cast())?
  };
  std::fs::rename(&first, &second).map_err(|e| format!("first rename: {e}"))?;
  std::fs::rename(&second, &third).map_err(|e| format!("second rename: {e}"))?;
  drop(handle);

  probe_log(format_args!(
    "{REPEAT_RENAME_PROBE} volume={drive}: root={} journal=0x{journal_id:016x} \
     frn=0x{frn:032x} start_usn={start}",
    root.display()
  ));
  probe_log(format_args!(
    "{REPEAT_RENAME_PROBE} moves: repeat-first.txt -> repeat-second.txt -> repeat-third.txt, \
     one handle held across both"
  ));

  // The close record is written on the cleanup path, which the drop above does
  // not synchronize with; poll rather than sleep a fixed guess.
  let mut records = Vec::new();
  let mut cursor = start;
  for _ in 0..50 {
    // A MEASUREMENT, not a gate: the question is how many records ONE subject's
    // two moves wrote, so the volume's other traffic is noise and is dropped
    // here rather than in the drain. The gate below keeps it.
    cursor = drain_journal(&volume, journal_id, cursor, &mut records)?;
    records.retain(|record| record.frn == frn);
    if records
      .iter()
      .any(|record| record.reason & USN_REASON_CLOSE != 0)
    {
      break;
    }
    std::thread::sleep(Duration::from_millis(200));
  }

  for record in &records {
    probe_log(format_args!(
      "{REPEAT_RENAME_PROBE} record usn={} reason=0x{:08x}{} name={}",
      record.usn,
      record.reason,
      if record.reason & USN_REASON_CLOSE != 0 {
        " CLOSE"
      } else {
        ""
      },
      record.name
    ));
  }

  // The arriving halves BEFORE the close are what the question turns on: one
  // means the second move was silent, two or more means it was not. The close
  // summary carries the same bits cumulatively and is excluded, since it proves
  // nothing about how many moves produced them.
  let arrivals: Vec<&ProbeRecord> = records
    .iter()
    .filter(|record| {
      record.reason & USN_REASON_CLOSE == 0 && record.reason & USN_REASON_RENAME_NEW_NAME != 0
    })
    .collect();
  let departures = records
    .iter()
    .filter(|record| {
      record.reason & USN_REASON_CLOSE == 0 && record.reason & USN_REASON_RENAME_OLD_NAME != 0
    })
    .count();
  let verdict = match arrivals.len() {
    0 => "NO ARRIVING HALF AT ALL — the probe did not observe the session; do not build on it",
    1 => {
      "SILENT — the second move wrote no record, so the repeat-rename covers are the floor \
       and the latent debt is required"
    }
    _ => {
      "RECORDED — the second move DID write, so a rename is not subject to the repeat rule \
       and the whole repeat-rename cover class can be retired"
    }
  };
  probe_log(format_args!(
    "{REPEAT_RENAME_PROBE} ANSWER arriving halves before the close={} (departing={departures}) \
     => {verdict}",
    arrivals.len()
  ));
  probe_log(format_args!(
    "{REPEAT_RENAME_PROBE} end: {} record(s) for this subject",
    records.len()
  ));

  let _ = std::fs::remove_dir_all(&root);
  // The ONE thing already certain, and the only thing asserted. How many moves
  // the journal recorded is reported, never judged, so the cell passes
  // whichever way the kernel answers.
  assert!(
    records
      .iter()
      .any(|record| record.reason & USN_REASON_CLOSE != 0),
    "{REPEAT_RENAME_PROBE}: a closed session must produce a USN_REASON_CLOSE record"
  );
  Ok(())
}

/// The prefix every line of the hard-link rename measurement carries, so one
/// `grep` over a CI log recovers the whole answer.
const HARD_LINK_RENAME_PROBE: &str = "TRIBUTARY-USN-HARDLINK-RENAME-PROBE";

/// [gate] RENAMING A SECOND HARD LINK OF AN ALREADY-RENAMED FILE MUST WRITE ITS
/// OWN TWO RECORDS, FRESH — the one step of the repeat-rename retirement that
/// would otherwise rest on inference.
///
/// The sibling cell `usn_repeat_rename_on_one_handle_writes_which_records`
/// measured the same file's link being moved twice through one held handle and
/// found BOTH moves recorded, with the two rename bits alternating
/// (`0x1100`, `0x2100`, `0x1100`, `0x2100`) rather than accumulating. That
/// retired the journal backend's whole repeat-rename cover class, including the
/// LATENT debt a file used to carry for links this module cannot enumerate.
///
/// The latent debt's own shape is one step further out, and this cell is that
/// step: a file reference with TWO links, a handle held on the first, the FIRST
/// link renamed, then the SECOND. The retirement's reasoning is that the
/// accumulated reason word belongs to the open FILE rather than to a link, and
/// that the rename path clears the opposite half as it sets its own — so link
/// B's departing half is fresh whatever link A did, and the move writes its two
/// records like any other.
///
/// # THIS ONE IS A GATE, NOT A MEASUREMENT, AND THE DIFFERENCE IS THE POINT
///
/// Its two siblings measured UNKNOWNS, so they report and pass either way: a
/// measurement that fails CI teaches nothing the log did not already carry. This
/// cell is different in kind, because a deletion has already been made on the
/// strength of what it reports. A gate that cannot fail is not a gate, so it
/// fails — on a silent second move, on records that name the wrong link, on
/// halves that arrive inverted or that the source never joins, on a session that
/// closes with a move still owed, and on a close that never comes.
///
/// AND IT FAILS UNDER PRODUCTION'S OWN DELTA AND PRODUCTION'S OWN PAIRING. A raw
/// bit count would pass a stream whose second move the source discards, because
/// the source forwards a record's FRESH bits and drops any rename half already
/// standing in the session's mask — which is exactly the world an accumulating
/// filesystem would produce. A freshness test ALONE would pass a stream whose
/// halves are all present and all fresh and which the source still reports as
/// widows, because pairing is a second decision with a second answer: a delta
/// carrying both halves is read as an arrival, a carried departure survives only
/// to the adjacent record, and this subject's own `CLOSE` drains the carry
/// rather than completing it. So the verdict comes from
/// `tributary_fs::moves_are_recorded_afresh`, which replays the records through
/// the session table AND the pairer the source itself uses, in the order the
/// admission sequences them. The cell and the retirement therefore cannot drift
/// apart: there is one delta rule and one pairing rule, and both read both.
///
/// AND IT REPLAYS THE STREAM THE SOURCE READS, WHICH IS THE WHOLE VOLUME'S.
/// Reusing the source's machines proves nothing if they are fed an input the
/// source never receives, and one of the pairing rules is ABOUT the volume's
/// interleaving: a parked departing half is drained ahead of any record that
/// takes its session entry, which is every record of another file reference. A
/// probe that kept only this subject's records would delete exactly the records
/// that make the source widow — `OLD, someone else's record, NEW` would arrive
/// adjacent, be joined, and certify a pairing the source reports as two widows.
/// So the drain keeps everything and the subject is NAMED to the predicate
/// instead, which matches the expected sequence against this file reference's
/// own halves and lets every other record do what it does in the source.
///
/// THE CONSEQUENCE IS STATED RATHER THAN HIDDEN: if another file's record really
/// does land between link B's two halves, this cell REFUSES — and the refusal is
/// true, because the source reports no ordered move for that stream either. NTFS
/// writes a rename's two records in the transaction that performs the rename, so
/// nothing of this volume's own traffic is expected between them; a run that
/// refuses this way has found something worth reading rather than a flake to
/// retry, and the log prints every stranger's record adjacent to a subject's so
/// the refusal names itself.
///
/// WHAT IT DOES NOT COVER, and cannot: the volume is NTFS, and NTFS is all any
/// of the three cells has ever run on. The source scopes the retirement to that
/// evidence — see `RenameSemantics` — so a filesystem this gate does not speak
/// for keeps the conservative debt rather than inheriting a proof it was never
/// given.
///
/// CI-only, like its siblings: a journal read needs the volume device, which
/// effectively needs elevation. It announces itself before it can decide
/// anything, writes past libtest's capture so a PASSING run still carries the
/// measurement, and treats an unmeasurable host as a hard failure whenever the
/// environment was prepared to measure (a zoo volume, or CI at all).
#[test]
fn usn_repeat_rename_across_two_hard_links_writes_which_records() {
  probe_log(format_args!(
    "{HARD_LINK_RENAME_PROBE} start: measuring whether renaming a SECOND hard link of an \
     already-renamed file writes any USN record"
  ));
  let zoo = std::env::var_os("TRIBUTARY_ZOO_NTFS");
  let must_measure = zoo.is_some() || std::env::var_os("CI").is_some();
  match measure_hard_link_rename(zoo.as_deref()) {
    Ok(()) => {}
    Err(why) if must_measure => panic!(
      "{HARD_LINK_RENAME_PROBE} the measurement could not be taken on a host that was prepared \
       to take it (zoo present or CI set): {why}"
    ),
    Err(why) => probe_log(format_args!(
      "{HARD_LINK_RENAME_PROBE} skip: {why} (legal only on an unprepared developer box)"
    )),
  }
}

fn measure_hard_link_rename(zoo: Option<&std::ffi::OsStr>) -> Result<(), String> {
  // The volume is opened and the cursor captured BEFORE anything is created, so
  // a host that cannot measure leaves no scratch behind — and so the cursor
  // provably predates every record this session writes.
  let base = match zoo {
    Some(base) => PathBuf::from(base),
    None => std::env::temp_dir()
      .canonicalize()
      .map_err(|e| format!("canonicalize temp dir: {e}"))?,
  };
  let drive =
    drive_letter(&base).ok_or_else(|| format!("{} is not on a lettered volume", base.display()))?;
  let volume = open_volume(drive)?;
  let (journal_id, start) = query_journal(&volume)?;

  let root = match zoo {
    Some(_) => {
      let dir = base.join(format!("usnhardlink-{}", std::process::id()));
      std::fs::create_dir_all(&dir).map_err(|e| format!("zoo scratch: {e}"))?;
      dir
        .canonicalize()
        .map_err(|e| format!("canonicalize zoo scratch: {e}"))?
    }
    None => scratch_root("usn-hardlink-rename"),
  };

  let link_a = root.join("hardlink-a.txt");
  let link_a2 = root.join("hardlink-a2.txt");
  let link_b = root.join("hardlink-b.txt");
  let link_b2 = root.join("hardlink-b2.txt");

  // Two names for ONE file reference, then ONE session held across both moves.
  std::fs::write(&link_a, b"hard link rename probe")
    .map_err(|e| format!("create {}: {e}", link_a.display()))?;
  create_hard_link(&link_b, &link_a)?;

  let handle = std::fs::OpenOptions::new()
    .write(true)
    .open(&link_a)
    .map_err(|e| format!("open {}: {e}", link_a.display()))?;
  let frn = {
    use std::os::windows::io::AsRawHandle;
    file_reference(handle.as_raw_handle().cast())?
  };
  std::fs::rename(&link_a, &link_a2).map_err(|e| format!("rename of link A: {e}"))?;
  std::fs::rename(&link_b, &link_b2).map_err(|e| format!("rename of link B: {e}"))?;
  drop(handle);

  probe_log(format_args!(
    "{HARD_LINK_RENAME_PROBE} volume={drive}: root={} journal=0x{journal_id:016x} \
     frn=0x{frn:032x} start_usn={start}",
    root.display()
  ));
  probe_log(format_args!(
    "{HARD_LINK_RENAME_PROBE} moves: link A hardlink-a.txt -> hardlink-a2.txt, then link B \
     hardlink-b.txt -> hardlink-b2.txt, one handle held on link A across both"
  ));

  // WHAT THE POLL WAITS FOR IS THE WHOLE VERDICT, not "a close". The write that
  // created link A, and the link creation itself, each open and close a session
  // of their own on this same file reference, so a `CLOSE` record is already in
  // the journal before the held handle is even opened — waiting for one would
  // have stopped polling before the session under test had said anything. The
  // premise is the loop's own condition, so the wait ends exactly when the
  // question is answered and never before.
  let moves = [
    tributary_fs::ExpectedMove {
      from: "hardlink-a.txt",
      to: "hardlink-a2.txt",
    },
    tributary_fs::ExpectedMove {
      from: "hardlink-b.txt",
      to: "hardlink-b2.txt",
    },
  ];
  // THE VERDICT IS TAKEN OVER THE WHOLE VOLUME STREAM, unfiltered, because that
  // is the stream the backend reads. Which records the expected sequence is
  // about is stated by `frn` instead — the predicate matches only that subject's
  // halves and lets every other subject's record do exactly what it does in the
  // source, which for a parked half is to drain it. Filtering the stream to
  // `frn` here would delete precisely the records that make the source widow,
  // and the gate would certify a pairing over an input the source never sees.
  let verdict_of = |records: &[ProbeRecord]| {
    let seen: Vec<tributary_fs::PremiseRecord<'_>> = records
      .iter()
      .map(|record| tributary_fs::PremiseRecord {
        frn: record.frn,
        reason: record.reason,
        name: record.name.as_str(),
      })
      .collect();
    tributary_fs::moves_are_recorded_afresh(&seen, frn, &moves)
  };
  let mut records = Vec::new();
  let mut cursor = start;
  // The answer before anything was drained, so the verdict a failure reports is
  // always one the predicate produced rather than a placeholder chosen here.
  let mut verdict = verdict_of(&records);
  for _ in 0..50 {
    cursor = drain_journal(&volume, journal_id, cursor, &mut records)?;
    verdict = verdict_of(&records);
    if verdict.holds() {
      break;
    }
    std::thread::sleep(Duration::from_millis(200));
  }

  // The log carries the subject's records in full, plus every stranger's record
  // that IMMEDIATELY FOLLOWS one of them. That second set is not padding: a
  // stranger can only change the verdict by draining a half the subject just
  // parked, which requires it to sit directly behind a subject record — so this
  // is exactly the foreign traffic a refusal could be about, and the rest is a
  // count. Indices are the predicate's own, so a verdict's `at` reads straight
  // off these lines.
  let mut logged = 0usize;
  for (at, record) in records.iter().enumerate() {
    let follows_subject = at
      .checked_sub(1)
      .is_some_and(|prior| records[prior].frn == frn);
    if record.frn != frn && !follows_subject {
      continue;
    }
    logged += 1;
    probe_log(format_args!(
      "{HARD_LINK_RENAME_PROBE} record[{at}] {} usn={} reason=0x{:08x}{} name={}",
      if record.frn == frn {
        "subject"
      } else {
        "stranger"
      },
      record.usn,
      record.reason,
      if record.reason & USN_REASON_CLOSE != 0 {
        " CLOSE"
      } else {
        ""
      },
      record.name
    ));
  }
  let mine = records.iter().filter(|record| record.frn == frn).count();
  probe_log(format_args!(
    "{HARD_LINK_RENAME_PROBE} stream: {} record(s) on the volume, {mine} of them this \
     subject's, {logged} printed",
    records.len()
  ));

  // The raw counts stay in the log because a failing verdict is worth reading
  // beside them — but they decide nothing. Counting bits cannot tell a fresh
  // half from a re-asserted one, and the source keeps only the fresh ones. They
  // are counted over the SUBJECT's records alone: the volume's other renames are
  // other files being renamed, which is neither evidence for nor against this
  // one's second move.
  let departures = records
    .iter()
    .filter(|record| {
      record.frn == frn
        && record.reason & USN_REASON_CLOSE == 0
        && record.reason & USN_REASON_RENAME_OLD_NAME != 0
    })
    .count();
  let arrivals = records
    .iter()
    .filter(|record| {
      record.frn == frn
        && record.reason & USN_REASON_CLOSE == 0
        && record.reason & USN_REASON_RENAME_NEW_NAME != 0
    })
    .count();
  probe_log(format_args!(
    "{HARD_LINK_RENAME_PROBE} ANSWER raw halves before the close: departing={departures} \
     arriving={arrivals}; verdict under the source's own delta => {verdict:?}"
  ));
  probe_log(format_args!(
    "{HARD_LINK_RENAME_PROBE} end: {mine} record(s) for this subject"
  ));

  let _ = std::fs::remove_dir_all(&root);
  // THE GATE. Anything but `Holds` means the retirement's premise is false on
  // this volume, and the debt the retirement removed is owed after all — a
  // silent second move, a move recorded under a link that is not B's, halves
  // arriving inverted, halves the source's delta would discard, one delta
  // carrying both halves at once, a pair the source's pairer widows rather than
  // joins (including one another subject's record fell between), a session that
  // closes with a move still owed, or a stream that never closes. Each of those
  // is a different way to be wrong and every one of them fails here.
  assert!(
    verdict.holds(),
    "{HARD_LINK_RENAME_PROBE}: renaming the SECOND hard link of an already-renamed file must \
     write its own ordered, correctly named pair of FRESH halves that the source itself joins, \
     followed by a close — the journal answered {verdict:?} instead, so the repeat-rename cover \
     class this volume's backend retired is required after all"
  );
  Ok(())
}
