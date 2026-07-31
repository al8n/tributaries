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
//! Windows behaviors the pump design rests on.

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
    eprintln!("SKIP zoo_volumes_flow: TRIBUTARY_ZOO_NTFS is unset (no zoo)");
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
    eprintln!("SKIP zoo_volumes_flow: TRIBUTARY_ZOO_FAT32 is unset (no zoo)");
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

/// [verify] journal wrap: churn on the sacrificial tiny-journal volume until
/// it truncates; the stream must surface the loss as a Rescan and keep
/// delivering afterwards — never silence, never a wedge.
#[tokio::test]
async fn journal_wrap_degrades_to_rescan() {
  let Some(base) = std::env::var_os("TRIBUTARY_ZOO_WRAP") else {
    eprintln!("SKIP journal_wrap_degrades_to_rescan: TRIBUTARY_ZOO_WRAP is unset");
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

  // A live pump's cursor rides the journal's edge, so churn alone cannot
  // reliably wrap PAST the reader (truncation behind the cursor is
  // harmless — the first executor run proved the pump keeps up). The
  // deterministic loss trigger is the journal ID CHANGE: delete and
  // recreate the journal under the live watch; the next read's ID
  // mismatch takes the same loss → reseed → covering-rescan spine a wrap
  // does. (The runner is Administrator; fsutil owns the volume state.)
  let drive = base
    .to_str()
    .and_then(|s| s.get(..2))
    .expect("the zoo exports a drive-lettered root")
    .to_owned();
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
      eprintln!("SKIP birth_refresh({tag}): the forced journal's probe refused ({err})");
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
    eprintln!("SKIP replace_root_cross_volume_reruns_the_ladder: TRIBUTARY_ZOO_NTFS is unset");
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
