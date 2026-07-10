use super::*;
use agnostic_lite::tokio::TokioRuntime;

/// Locks in `Watcher<R>: Sync`: the umbrella's single-owner actor awaits the
/// `&self` `watch`/`unwatch` futures inside a `Send` spawned owner, which
/// holds only if `&Watcher` is `Send` — i.e. `Watcher: Sync`. Reintroducing a
/// `!Sync` field (e.g. re-boxing `events` without `+ Sync`) fails to compile
/// here. Never invoked; the bound is checked when the generic body compiles.
#[allow(dead_code)]
fn _assert_watcher_sync<R: RuntimeLite>() {
  fn is_sync<T: Sync>() {}
  is_sync::<Watcher<R>>();
}

/// A watcher wired to a command channel the test controls (no driver task, no
/// platform), so registration protocols are observable in isolation.
fn manual_watcher() -> (Watcher<TokioRuntime>, async_channel::Receiver<Command>) {
  let (command_tx, command_rx) = async_channel::bounded(16);
  let (_event_tx, event_rx) = async_channel::bounded::<(ScopeId, Arc<PathBuf>, Change)>(4);
  (
    Watcher {
      instance: WATCHER_INSTANCES.fetch_add(1, Ordering::Relaxed),
      commands: command_tx,
      events: Box::pin(event_rx),
      roots: Arc::new(RwLock::new(RootSet::default())),
      _runtime: PhantomData,
    },
    command_rx,
  )
}

fn pending_of(watcher: &Watcher<TokioRuntime>) -> Vec<PathBuf> {
  watcher
    .roots
    .read()
    .unwrap_or_else(PoisonError::into_inner)
    .pending
    .iter()
    .map(|reserved| reserved.path.clone())
    .collect()
}

/// A real directory to canonicalize against (watch() stats its root before
/// anything else).
fn scratch_dir(tag: &str) -> PathBuf {
  let dir = std::env::temp_dir().join(format!("tributary-fs-watcher-{}-{tag}", std::process::id()));
  std::fs::create_dir_all(&dir).expect("scratch dir");
  dir
}

/// Close cannot claim quiescence it never observed: a close command that
/// cannot even be delivered means the driver stopped — with whatever
/// spawn/teardown work it held unobserved — so the caller gets `Stopped`,
/// never `Ok`.
#[tokio::test]
async fn close_reports_stopped_when_the_driver_is_gone() {
  let (watcher, command_rx) = manual_watcher();
  drop(command_rx);
  let err = watcher
    .close()
    .await
    .expect_err("an unacknowledged close is not quiescence");
  assert!(err.is_stopped(), "{err:?}");
}

#[tokio::test]
async fn cancelled_watch_releases_its_reservation() {
  let (watcher, commands) = manual_watcher();
  let dir = scratch_dir("cancel");

  {
    let mut fut = Box::pin(watcher.watch(&dir, Interest::all()));
    // One poll carries the future past the command send (the channel has
    // room), leaving it parked on the never-answered reply.
    assert!(futures_util::poll!(fut.as_mut()).is_pending());
    assert_eq!(pending_of(&watcher).len(), 1, "the root is reserved");
    // The future drops here — a cancellation mid-await.
  }
  assert!(
    pending_of(&watcher).is_empty(),
    "a cancelled watch releases its reservation"
  );
  // The command reached the driver side with its reply receiver gone — the
  // shape the driver resolves by tearing the orphan stream down.
  let cmd = commands.recv().await.expect("the command was sent");
  match cmd {
    Command::Watch { reply, root, .. } => {
      assert_eq!(root, std::fs::canonicalize(&dir).unwrap());
      let (unwind_tx, unwind_rx) = async_channel::unbounded();
      let scope = ScopeId::new(1.try_into().unwrap());
      assert!(
        reply
          .send(Ok(crate::driver::WatchGrant::new(scope, root, unwind_tx)))
          .is_err(),
        "the cancelled caller cannot receive the reply"
      );
      // The failed send dropped the still-armed grant, which unwinds its
      // scope back to the driver.
      assert_eq!(
        unwind_rx.try_recv().ok(),
        Some(scope),
        "an undeliverable grant unwinds its scope"
      );
    }
    _ => panic!("expected the watch command"),
  }

  // The path is free again: a fresh watch passes the overlap check and gets
  // as far as awaiting its own reply.
  let mut fut = Box::pin(watcher.watch(&dir, Interest::all()));
  assert!(futures_util::poll!(fut.as_mut()).is_pending());
  assert_eq!(pending_of(&watcher).len(), 1, "the fresh watch reserved it");
  drop(fut);

  let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn dropped_before_first_poll_reserves_nothing() {
  let (watcher, _commands) = manual_watcher();
  let dir = scratch_dir("unpolled");
  drop(watcher.watch(&dir, Interest::all()));
  assert!(pending_of(&watcher).is_empty());
  let _ = std::fs::remove_dir_all(&dir);
}

/// A handle is a capability scoped to its issuing watcher: a foreign handle
/// is rejected outright — before any command is sent — so it can never tear
/// down the victim watcher's unrelated root that shares the scope number.
#[tokio::test]
async fn foreign_handle_is_rejected_without_touching_the_victim() {
  let (victim, commands) = manual_watcher();
  let foreign = RootHandle::new(
    victim.instance + 1,
    ScopeId::new(core::num::NonZeroU64::new(1).unwrap()),
  );

  assert!(matches!(
    victim.unwatch(foreign).await,
    Err(UnwatchError::UnknownRoot)
  ));
  assert!(
    commands.try_recv().is_err(),
    "a foreign handle must not reach the victim's driver"
  );
  assert_eq!(victim.root_path(foreign), None);
}

/// Reservation-time identity: two spellings of one object collide at `take`
/// (the first reserver wins deterministically), a live entry blocks an
/// aliased reservation the same way, and an unknown identity still passes
/// disjoint bytes — the driver's final check is the authority then.
#[test]
fn reservations_collide_on_object_identity() {
  use crate::os::RootIdentity;
  let roots = Arc::new(RwLock::new(RootSet::default()));
  let id = RootIdentity::new(1, 42);
  let first =
    Reservation::take(&roots, PathBuf::from("/spelling/One"), Some(id)).expect("first spelling");
  let err = Reservation::take(&roots, PathBuf::from("/spelling/one"), Some(id))
    .expect_err("one object, two spellings");
  assert!(
    matches!(err, WatchRootError::Overlaps { existing, .. } if existing.as_path() == Path::new("/spelling/One"))
  );
  drop(first);

  roots
    .write()
    .unwrap_or_else(PoisonError::into_inner)
    .entries
    .insert(
      ScopeId::new(1.try_into().unwrap()),
      RootEntry {
        path: Arc::new(PathBuf::from("/live/Root")),
        identity: id,
        ancestors: Vec::new().into(),
        backend: BackendKind::FsEvents,
        stats: None,
      },
    );
  let err = Reservation::take(&roots, PathBuf::from("/live/root"), Some(id))
    .expect_err("aliases a live root");
  assert!(
    matches!(err, WatchRootError::Overlaps { existing, .. } if existing.as_path() == Path::new("/live/Root"))
  );
  assert!(Reservation::take(&roots, PathBuf::from("/elsewhere"), None).is_ok());
}

/// Same-watcher handles for scopes the registry does not know answer `None`
/// without erroring elsewhere — the negative control for the brand check.
#[tokio::test]
async fn unknown_scope_of_own_instance_has_no_path() {
  let (watcher, _commands) = manual_watcher();
  let handle = RootHandle::new(
    watcher.instance,
    ScopeId::new(core::num::NonZeroU64::new(7).unwrap()),
  );
  assert_eq!(watcher.root_path(handle), None);
}

/// `backend_stats` is gated exactly like `backend_of` and populated only for a
/// fanotify root: a non-fanotify (FSEvents) live root has no admission map and
/// reports `None`; a fanotify root reports a snapshot of its live counters; and a
/// handle that names no live root of this watcher (unknown, or foreign) reports
/// `None`.
#[tokio::test]
async fn backend_stats_is_fanotify_only_and_gated() {
  let (watcher, _commands) = manual_watcher();
  let id = RootIdentity::new(1, 1);

  // A live FSEvents root (scope 1): no admission map, so no stats.
  let fsevents = ScopeId::new(core::num::NonZeroU64::new(1).unwrap());
  // A live fanotify root (scope 2): a shared stats handle the reader would write.
  let fanotify = ScopeId::new(core::num::NonZeroU64::new(2).unwrap());
  let shared = std::sync::Arc::new(crate::os::BackendStatsShared::default());
  {
    let mut set = watcher
      .roots
      .write()
      .unwrap_or_else(PoisonError::into_inner);
    set.entries.insert(
      fsevents,
      RootEntry {
        path: Arc::new(PathBuf::from("/fse")),
        identity: id,
        ancestors: Vec::new().into(),
        backend: BackendKind::FsEvents,
        stats: None,
      },
    );
    set.entries.insert(
      fanotify,
      RootEntry {
        path: Arc::new(PathBuf::from("/fan")),
        identity: RootIdentity::new(2, 2),
        ancestors: Vec::new().into(),
        backend: BackendKind::Fanotify,
        stats: Some(Arc::clone(&shared)),
      },
    );
  }

  let fse_handle = RootHandle::new(watcher.instance, fsevents);
  let fan_handle = RootHandle::new(watcher.instance, fanotify);
  assert_eq!(
    watcher.backend_stats(fse_handle),
    None,
    "an FSEvents root keeps no admission map — no stats"
  );

  // Simulate the reader publishing some counters, then snapshot.
  shared.set_map(42, 7);
  shared.add_memo(9, 3);
  shared.record_reseed();
  shared.record_walk(1234);
  let stats = watcher
    .backend_stats(fan_handle)
    .expect("a fanotify root exposes stats");
  assert_eq!(stats.directories(), 42);
  assert_eq!(stats.memo_generation(), 7);
  assert_eq!(stats.memo_hits(), 9);
  assert_eq!(stats.memo_misses(), 3);
  assert_eq!(stats.reseeds(), 1);
  assert_eq!(stats.seed_walk_last_micros(), 1234);
  assert_eq!(stats.seed_walk_count(), 1);
  // The snapshot is a copy, not a live view: a later write does not mutate it.
  shared.set_map(100, 8);
  assert_eq!(stats.directories(), 42, "the snapshot froze the counters");

  // An unknown scope of this watcher, and a foreign-branded handle, both report
  // `None` — the same gating as `backend_of`.
  let unknown = RootHandle::new(
    watcher.instance,
    ScopeId::new(core::num::NonZeroU64::new(99).unwrap()),
  );
  assert_eq!(watcher.backend_stats(unknown), None);
  let foreign = RootHandle::new(watcher.instance.wrapping_add(1), fanotify);
  assert_eq!(
    watcher.backend_stats(foreign),
    None,
    "a foreign-branded handle never reads this watcher's stats"
  );
}

/// The registry holds exactly the LIVE roots: every unwatch reclaims its
/// entry (the driver's scope-dead signal), so repeated cycles cannot grow it.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn registry_reclaims_on_unwatch_cycles() {
  let watcher = Watcher::<TokioRuntime>::new(WatcherOptions::new()).expect("build");
  let dir = scratch_dir("reclaim");
  for _ in 0..8 {
    let handle = watcher
      .watch(&dir, tributary_proto::Interest::all())
      .await
      .expect("watch");
    assert_eq!(watcher.registry_len(), 1);
    watcher.unwatch(handle).await.expect("unwatch");
    assert_eq!(watcher.registry_len(), 0, "unwatch reclaims the entry");
    assert_eq!(
      watcher.root_path(handle),
      None,
      "a reclaimed handle no longer names a root"
    );
  }
  watcher.close().await.expect("close");
}

/// `request_set_cover` is the non-blocking, REPLY-LESS prompt path: it `try_send`s a
/// reply-less `SetCover` and reports whether the control channel accepted it — `true` with room,
/// `false` when full or closed (or foreign), never blocking or panicking.
#[tokio::test]
async fn request_set_cover_is_reply_less_and_reports_channel_capacity() {
  let (watcher, commands) = manual_watcher();
  let handle = RootHandle::new(watcher.instance, ScopeId::new(1.try_into().unwrap()));

  // A foreign handle is refused without touching the channel.
  let foreign = RootHandle::new(
    watcher.instance.wrapping_add(1),
    ScopeId::new(1.try_into().unwrap()),
  );
  assert!(
    !watcher.request_set_cover(foreign, vec![PathBuf::from("/r/a")]),
    "a foreign handle is refused"
  );

  // With room, the prompt request enqueues a REPLY-LESS SetCover and reports success.
  assert!(
    watcher.request_set_cover(handle, vec![PathBuf::from("/r/a")]),
    "the channel has room"
  );
  match commands.try_recv().expect("a command was enqueued") {
    Command::SetCover {
      scope,
      retained,
      reply,
    } => {
      assert_eq!(scope, handle.scope());
      assert_eq!(retained, vec![PathBuf::from("/r/a")]);
      assert!(
        reply.is_none(),
        "the prompt request carries no reply (fire-and-forget)"
      );
    }
    _ => panic!("expected a SetCover command"),
  }

  // Saturate the bounded(16) channel: further prompts are refused (false), never blocking.
  for _ in 0..16 {
    assert!(watcher.request_set_cover(handle, vec![PathBuf::from("/r/full")]));
  }
  assert!(
    !watcher.request_set_cover(handle, vec![PathBuf::from("/r/overflow")]),
    "a full channel refuses the prompt"
  );

  // A closed channel is likewise refused, never a panic.
  drop(commands);
  assert!(
    !watcher.request_set_cover(handle, vec![PathBuf::from("/r/closed")]),
    "a closed channel refuses the prompt"
  );
}

/// `request_unwatch` is the non-blocking, REPLY-LESS teardown twin of the awaited `unwatch` (
/// ): it `try_send`s a reply-less `Unwatch` and reports whether the control channel accepted it —
/// `true` with room, `false` when full or closed (or foreign) — never blocking or panicking. The
/// enqueued command carries `reply: None`, marking it fire-and-forget for the driver.
#[tokio::test]
async fn request_unwatch_is_reply_less_and_reports_channel_capacity() {
  let (watcher, commands) = manual_watcher();
  let handle = RootHandle::new(watcher.instance, ScopeId::new(1.try_into().unwrap()));

  // A foreign handle is refused without touching the channel.
  let foreign = RootHandle::new(
    watcher.instance.wrapping_add(1),
    ScopeId::new(1.try_into().unwrap()),
  );
  assert!(
    !watcher.request_unwatch(foreign),
    "a foreign handle is refused"
  );

  // With room, the request enqueues a REPLY-LESS Unwatch and reports success.
  assert!(watcher.request_unwatch(handle), "the channel has room");
  match commands.try_recv().expect("a command was enqueued") {
    Command::Unwatch { scope, reply } => {
      assert_eq!(scope, handle.scope());
      assert!(
        reply.is_none(),
        "the reply-less request carries no reply (fire-and-forget)"
      );
    }
    _ => panic!("expected an Unwatch command"),
  }

  // Saturate the bounded(16) channel: further requests are refused (false), never blocking.
  for _ in 0..16 {
    assert!(watcher.request_unwatch(handle));
  }
  assert!(
    !watcher.request_unwatch(handle),
    "a full channel refuses the request"
  );

  // A closed channel is likewise refused, never a panic.
  drop(commands);
  assert!(
    !watcher.request_unwatch(handle),
    "a closed channel refuses the request"
  );
}

/// The awaited `set_cover` sends a SetCover carrying a reply to ack (the acked twin of the
/// reply-less `request_set_cover`).
#[tokio::test]
async fn set_cover_sends_an_acked_command() {
  let (watcher, commands) = manual_watcher();
  let handle = RootHandle::new(watcher.instance, ScopeId::new(1.try_into().unwrap()));
  let mut fut = Box::pin(watcher.set_cover(handle, vec![PathBuf::from("/r/a")]));
  // One poll carries it past the send, parking on the never-answered reply.
  assert!(futures_util::poll!(fut.as_mut()).is_pending());
  match commands.try_recv().expect("the command was sent") {
    Command::SetCover {
      scope,
      retained,
      reply,
    } => {
      assert_eq!(scope, handle.scope());
      assert_eq!(retained, vec![PathBuf::from("/r/a")]);
      assert!(
        reply.is_some(),
        "the awaited set_cover carries a reply to ack"
      );
    }
    _ => panic!("expected a SetCover command"),
  }
  drop(fut);
}

mod lifecycle {
  use super::*;
  use crate::driver::testing::FakeFs;
  use agnostic_lite::tokio::TokioRuntime;
  use std::time::Duration;
  use tributary_proto::FileKind;

  fn scratch(tag: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
      "tributary-fs-lifecycle-{}-{tag}",
      std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let canonical = std::fs::canonicalize(&dir).expect("canonicalize");
    (dir, canonical)
  }

  /// Gives the driver and blocking pool scheduler slices under paused time.
  async fn settle(mut done: impl FnMut() -> bool) {
    for _ in 0..200 {
      if done() {
        return;
      }
      tokio::task::yield_now().await;
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
  }

  /// End to end: the source dies after the grant was delivered but before
  /// `watch()` polls it out. The single-writer registry saw live-then-dead in
  /// driver order; the late commit yields a dead-on-arrival handle, and the
  /// path is immediately re-watchable.
  #[tokio::test(start_paused = true)]
  async fn death_before_the_grant_poll_yields_a_dead_on_arrival_handle() {
    let (dir, canonical) = scratch("doa");
    let fs = FakeFs::new(1);
    fs.put(&canonical, FileKind::Dir, 1);
    let watcher =
      Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");

    let mut fut = Box::pin(watcher.watch(&dir, Interest::all()));
    assert!(futures_util::poll!(fut.as_mut()).is_pending());
    // The driver spawned the stream and recorded the scope live BEFORE the
    // grant could reach this future.
    settle(|| watcher.registry_len() == 1).await;
    assert_eq!(watcher.registry_len(), 1);

    // The source dies while the grant sits undelivered in the oneshot.
    fs.disconnect(&canonical);
    settle(|| watcher.registry_len() == 0 && fs.shutdowns() == 1).await;
    assert_eq!(watcher.registry_len(), 0, "the driver reclaimed the entry");

    // The late poll still commits — into a dead-on-arrival handle.
    let handle = loop {
      match futures_util::poll!(fut.as_mut()) {
        std::task::Poll::Ready(res) => break res.expect("the grant commits"),
        std::task::Poll::Pending => {
          tokio::task::yield_now().await;
          tokio::time::sleep(Duration::from_millis(10)).await;
        }
      }
    };
    drop(fut);
    assert_eq!(watcher.root_path(handle), None);
    assert!(matches!(
      watcher.unwatch(handle).await,
      Err(UnwatchError::UnknownRoot)
    ));

    // No overlap blocker survives: the same path watches afresh.
    let fresh = watcher
      .watch(&dir, Interest::all())
      .await
      .expect("re-watch succeeds");
    assert_eq!(
      watcher.root_path(fresh).as_deref(),
      Some(canonical.as_path())
    );
    watcher.close().await.expect("close");
    let _ = std::fs::remove_dir_all(&dir);
  }

  /// The public close contract is honest: `Ok` proves quiescence, so a
  /// teardown wedged past the grace — whose handle already moved into the
  /// blocking call, beyond any Drop backstop — surfaces as `NotQuiesced`
  /// rather than a false confirmation.
  #[tokio::test]
  async fn close_is_honest_about_a_wedged_teardown() {
    let (dir, canonical) = scratch("wedged-close");
    let fs = FakeFs::new(1);
    fs.put(&canonical, FileKind::Dir, 1);
    let watcher =
      Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");
    let _handle = watcher
      .watch(&dir, Interest::all())
      .await
      .expect("watch goes live");

    let gate = fs.hold_teardowns();
    let err = watcher
      .close()
      .await
      .expect_err("quiescence was not proven");
    assert!(
      err.is_not_quiesced(),
      "a wedged teardown must not read as quiescent: {err:?}"
    );

    gate.release();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while fs.shutdowns() == 0 && std::time::Instant::now() < deadline {
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(fs.shutdowns(), 1, "the wedged call completes once released");
    let _ = std::fs::remove_dir_all(&dir);
  }

  /// Cancellation at each await boundary of `watch()` — before the grant
  /// exists and with it delivered-but-unpolled — leaves no reservation, no
  /// orphan stream, and no registry entry, and the path watches afresh.
  #[tokio::test(start_paused = true)]
  async fn cancellation_at_every_await_point_leaves_consistent_state() {
    for wait_for_grant in [false, true] {
      let (dir, canonical) = scratch(if wait_for_grant {
        "cancel-late"
      } else {
        "cancel-early"
      });
      let fs = FakeFs::new(1);
      fs.put(&canonical, FileKind::Dir, 1);
      let watcher =
        Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");

      {
        let mut fut = Box::pin(watcher.watch(&dir, Interest::all()));
        assert!(futures_util::poll!(fut.as_mut()).is_pending());
        if wait_for_grant {
          settle(|| watcher.registry_len() == 1).await;
        }
        // The future drops here — cancellation mid-await.
      }
      // Wait for the cancelled pipeline to have RUN, not merely for balanced
      // counters: `spawns == shutdowns` is vacuously true at 0 == 0 before
      // the driver even receives the command, and a fresh watch admitted that
      // early races the cancelled scope's spawn of the same root.
      settle(|| fs.spawns() == 1 && fs.shutdowns() == 1 && watcher.registry_len() == 0).await;
      assert_eq!(fs.spawns(), 1, "the cancelled watch's stream spawned");
      assert_eq!(
        fs.shutdowns(),
        1,
        "no orphan stream survives a cancelled watch (wait_for_grant={wait_for_grant})"
      );
      assert_eq!(watcher.registry_len(), 0);

      let handle = watcher
        .watch(&dir, Interest::all())
        .await
        .expect("a fresh watch succeeds");
      watcher.unwatch(handle).await.expect("unwatch");
      watcher.close().await.expect("close");
      let _ = std::fs::remove_dir_all(&dir);
    }
  }

  /// The backend re-canonicalizes at spawn: a root retargeted onto an
  /// already-watched tree between the reservation and the spawn must be
  /// rejected by the driver's final-root check — the fresh stream torn down,
  /// the existing watch untouched.
  #[tokio::test(start_paused = true)]
  async fn retargeted_root_overlapping_an_existing_watch_is_rejected() {
    let (dir_a, canon_a) = scratch("retarget-victim");
    let (dir_b, canon_b) = scratch("retarget-mover");
    let fs = FakeFs::new(1);
    fs.put(&canon_a, FileKind::Dir, 1);
    fs.put(&canon_b, FileKind::Dir, 2);
    let watcher =
      Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");

    let victim = watcher.watch(&dir_a, Interest::all()).await.expect("watch");
    let spawned_before = fs.spawns();

    // Between B's reservation and its spawn, the path retargets INTO A's
    // watched tree (the fake mirrors the backend's re-canonicalization).
    fs.remap_spawn_root(&canon_b, canon_a.join("sub"));
    let err = watcher
      .watch(&dir_b, Interest::all())
      .await
      .expect_err("the final root overlaps");
    match err {
      WatchRootError::Overlaps { path, existing } => {
        assert_eq!(path, canon_a.join("sub"), "the FINAL root is reported");
        assert_eq!(existing, canon_a);
      }
      other => panic!("expected Overlaps, got {other:?}"),
    }
    // The rejected stream never went live and was torn down inside the
    // driver's accounting; the victim is untouched.
    settle(|| fs.shutdowns() == fs.spawns() - 1).await;
    assert_eq!(fs.spawns(), spawned_before + 1);
    assert_eq!(fs.shutdowns(), fs.spawns() - 1, "only the victim survives");
    assert_eq!(watcher.registry_len(), 1);
    assert_eq!(
      watcher.root_path(victim).as_deref(),
      Some(canon_a.as_path())
    );

    watcher.close().await.expect("close");
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
  }

  /// Two spellings of ONE object (the fake gives two paths one `(dev, ino)`,
  /// exactly a case alias on an insensitive volume): every byte comparison
  /// passes, and the driver's identity check still collides them — the
  /// rejected stream is torn down and the victim is untouched.
  #[tokio::test(start_paused = true)]
  async fn aliased_final_roots_collide_by_identity() {
    let (dir_a, canon_a) = scratch("alias-victim");
    let (dir_b, canon_b) = scratch("alias-imposter");
    let fs = FakeFs::new(1);
    fs.put(&canon_a, FileKind::Dir, 10);
    fs.put(&canon_b, FileKind::Dir, 10);
    let watcher =
      Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");

    let victim = watcher.watch(&dir_a, Interest::all()).await.expect("watch");
    let err = watcher
      .watch(&dir_b, Interest::all())
      .await
      .expect_err("one object, two spellings");
    match err {
      WatchRootError::Overlaps { existing, .. } => assert_eq!(existing, canon_a),
      other => panic!("expected Overlaps, got {other:?}"),
    }
    settle(|| fs.shutdowns() == fs.spawns() - 1).await;
    assert_eq!(watcher.registry_len(), 1);
    assert_eq!(
      watcher.root_path(victim).as_deref(),
      Some(canon_a.as_path())
    );

    watcher.close().await.expect("close");
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
  }

  /// New-inside-existing across spellings: the new root's ancestor chain
  /// carries the live root's identity (its parent IS the live root, however
  /// spelled), so containment collides where bytes cannot.
  #[tokio::test(start_paused = true)]
  async fn aliased_ancestor_makes_the_new_root_nested() {
    let (dir_a, canon_a) = scratch("contain-victim");
    let (base, canon_base) = scratch("contain-base");
    let sub = base.join("sub");
    std::fs::create_dir_all(&sub).expect("create nested dir");
    let canon_sub = std::fs::canonicalize(&sub).expect("canonicalize");
    let fs = FakeFs::new(1);
    fs.put(&canon_a, FileKind::Dir, 20);
    fs.put(&canon_sub, FileKind::Dir, 21);
    // The nested root's parent shares the live root's identity — an alias.
    fs.put(&canon_base, FileKind::Dir, 20);
    let watcher =
      Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");

    let _victim = watcher.watch(&dir_a, Interest::all()).await.expect("watch");
    let err = watcher
      .watch(&sub, Interest::all())
      .await
      .expect_err("nested under an alias of the live root");
    match err {
      WatchRootError::Overlaps { existing, .. } => assert_eq!(existing, canon_a),
      other => panic!("expected Overlaps, got {other:?}"),
    }
    assert_eq!(watcher.registry_len(), 1);

    watcher.close().await.expect("close");
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&base);
  }

  /// Existing-inside-new across spellings: the new root's identity appears in
  /// a live root's ancestor chain — the new root CONTAINS the live one under
  /// a different spelling.
  #[tokio::test(start_paused = true)]
  async fn aliased_new_root_contains_a_live_root() {
    let (base, canon_base) = scratch("outer-base");
    let sub = base.join("sub");
    std::fs::create_dir_all(&sub).expect("create nested dir");
    let canon_sub = std::fs::canonicalize(&sub).expect("canonicalize");
    let (dir_x, canon_x) = scratch("outer-imposter");
    let fs = FakeFs::new(1);
    fs.put(&canon_base, FileKind::Dir, 30);
    fs.put(&canon_sub, FileKind::Dir, 31);
    // The newcomer shares the live root's PARENT identity — it contains it.
    fs.put(&canon_x, FileKind::Dir, 30);
    let watcher =
      Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");

    let _victim = watcher.watch(&sub, Interest::all()).await.expect("watch");
    let err = watcher
      .watch(&dir_x, Interest::all())
      .await
      .expect_err("contains the live root under an alias");
    match err {
      WatchRootError::Overlaps { existing, .. } => assert_eq!(existing, canon_sub),
      other => panic!("expected Overlaps, got {other:?}"),
    }
    assert_eq!(watcher.registry_len(), 1);

    watcher.close().await.expect("close");
    let _ = std::fs::remove_dir_all(&base);
    let _ = std::fs::remove_dir_all(&dir_x);
  }

  /// Distinct identities under disjoint bytes stay admitted — the negative
  /// control for every identity cell above.
  #[tokio::test(start_paused = true)]
  async fn distinct_identities_stay_disjoint() {
    let (dir_a, canon_a) = scratch("distinct-a");
    let (dir_b, canon_b) = scratch("distinct-b");
    let fs = FakeFs::new(1);
    fs.put(&canon_a, FileKind::Dir, 40);
    fs.put(&canon_b, FileKind::Dir, 41);
    let watcher =
      Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");

    let _a = watcher
      .watch(&dir_a, Interest::all())
      .await
      .expect("watch a");
    let _b = watcher
      .watch(&dir_b, Interest::all())
      .await
      .expect("watch b");
    assert_eq!(watcher.registry_len(), 2);

    watcher.close().await.expect("close");
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
  }

  /// A root retargeted from a directory to a regular FILE between the
  /// reservation and the spawn is a typed pre-live rejection: no stream ever
  /// exists, no event ever surfaces, and other watches are untouched.
  #[tokio::test(start_paused = true)]
  async fn retargeted_root_to_file_is_rejected_before_live() {
    let (dir, canonical) = scratch("retarget-to-file");
    let fs = FakeFs::new(1);
    fs.put(&canonical, FileKind::Dir, 1);
    let plain = PathBuf::from("/retargeted-plain-file");
    fs.put(&plain, FileKind::File, 2);
    fs.remap_spawn_root(&canonical, &plain);
    let mut watcher =
      Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");

    let err = watcher
      .watch(&dir, Interest::all())
      .await
      .expect_err("a file root is rejected");
    match err {
      WatchRootError::NotADirectory { path } => {
        assert_eq!(path, plain, "the FINAL root is reported");
      }
      other => panic!("expected NotADirectory, got {other:?}"),
    }
    assert_eq!(fs.spawns(), 0, "no stream ever went live");
    assert_eq!(watcher.registry_len(), 0);
    assert!(
      tokio::time::timeout(Duration::from_secs(2), watcher.next())
        .await
        .is_err(),
      "a never-live scope produces no events"
    );

    watcher.close().await.expect("close");
    let _ = std::fs::remove_dir_all(&dir);
  }

  /// The identity bracket: a root whose OBJECT is swapped between the
  /// metadata capture and the stream going live — same bytes, different
  /// `(dev, ino)` — is rejected post-live, the just-started stream torn
  /// down, and nothing goes live to the caller. The new object itself
  /// remains watchable: the bracket rejected a race, not the root.
  #[tokio::test(start_paused = true)]
  async fn replaced_root_between_seal_and_live_is_rejected() {
    let (dir, canonical) = scratch("replaced-at-live");
    let fs = FakeFs::new(1);
    fs.put(&canonical, FileKind::Dir, 1);
    fs.replace_at_live(&canonical, FileKind::Dir, 99);
    let mut watcher =
      Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");

    let err = watcher
      .watch(&dir, Interest::all())
      .await
      .expect_err("the swapped object is rejected");
    match err {
      WatchRootError::Source(crate::SourceError::RootReplaced { root }) => {
        assert_eq!(root, canonical, "the FINAL root is reported");
      }
      other => panic!("expected RootReplaced, got {other:?}"),
    }
    assert_eq!(fs.spawns(), 1, "the stream went live before the bracket");
    assert_eq!(fs.shutdowns(), 1, "the just-live stream was torn down");
    assert_eq!(watcher.registry_len(), 0);
    assert!(
      tokio::time::timeout(Duration::from_secs(2), watcher.next())
        .await
        .is_err(),
      "a never-live scope produces no events"
    );

    let handle = watcher
      .watch(&dir, Interest::all())
      .await
      .expect("the new object registers cleanly");
    assert_eq!(
      watcher.root_path(handle).as_deref(),
      Some(canonical.as_path())
    );

    watcher.close().await.expect("close");
    let _ = std::fs::remove_dir_all(&dir);
  }

  /// A plain spawn failure is equally event-silent end to end: the caller
  /// gets Err, and the Monitor's internal failure rescan for the never-live
  /// root is fenced at the core — nothing reaches the stream, not even
  /// through the dying retry.
  #[tokio::test(start_paused = true)]
  async fn failed_watch_produces_no_events() {
    let (dir, _canonical) = scratch("spawn-fails");
    let fs = FakeFs::new(1);
    // The canonical root is never registered as a fake node: the spawn fails
    // with RootUnavailable (the fake's pre-start half of the lifecycle).
    let mut watcher =
      Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");

    let err = watcher
      .watch(&dir, Interest::all())
      .await
      .expect_err("the spawn fails");
    assert!(matches!(err, WatchRootError::Source(_)), "{err:?}");
    assert_eq!(watcher.registry_len(), 0);
    assert!(
      tokio::time::timeout(Duration::from_secs(2), watcher.next())
        .await
        .is_err(),
      "a failed watch delivers nothing"
    );

    watcher.close().await.expect("close");
    let _ = std::fs::remove_dir_all(&dir);
  }

  /// A retargeted-but-disjoint final root goes live under the FINAL path:
  /// the registry, the handle, and event assembly all carry what is actually
  /// watched.
  #[tokio::test(start_paused = true)]
  async fn retargeted_root_disjoint_goes_live_under_the_final_root() {
    let (dir, canonical) = scratch("retarget-disjoint");
    let fs = FakeFs::new(1);
    fs.put(&canonical, FileKind::Dir, 1);
    let final_root = PathBuf::from("/retargeted-final");
    fs.put(&final_root, FileKind::Dir, 2);
    fs.remap_spawn_root(&canonical, &final_root);
    let mut watcher =
      Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");

    let handle = watcher.watch(&dir, Interest::all()).await.expect("watch");
    assert_eq!(
      watcher.root_path(handle).as_deref(),
      Some(final_root.as_path()),
      "the registry holds the final root"
    );

    // Wire paths mirror what a backend delivers: '/'-separated bytes on every
    // host. PathBuf::join would use the HOST separator, and on Windows (where
    // only the hermetic suites run) the byte-level root-prefix lowering would
    // classify the event as outside the root.
    let file = PathBuf::from("/retargeted-final/a.txt");
    fs.put(&file, FileKind::File, 9);
    fs.send_batch(
      &final_root,
      vec![crate::os::RawOsEvent {
        path: file.clone(),
        flags: crate::os::FsEventFlags::new(
          crate::os::FsEventFlags::ITEM_CREATED.bits()
            | crate::os::FsEventFlags::ITEM_IS_FILE.bits(),
        ),
        event_id: 1,
        file_id: std::num::NonZeroU64::new(9),
      }],
    );
    let event = tokio::time::timeout(Duration::from_secs(5), watcher.next())
      .await
      .expect("an event arrives")
      .expect("the stream is open");
    assert_eq!(event.path(), file.as_path(), "assembly uses the final root");

    watcher.close().await.expect("close");
    let _ = std::fs::remove_dir_all(&dir);
  }

  /// The hermetic twin of the real-FS registry-cycles test: entries exist
  /// exactly while their root is live, on every platform.
  #[tokio::test(start_paused = true)]
  async fn registry_reclaims_on_unwatch_cycles_hermetic() {
    let (dir, canonical) = scratch("cycles");
    let fs = FakeFs::new(1);
    fs.put(&canonical, FileKind::Dir, 1);
    let watcher =
      Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");
    for _ in 0..8 {
      let handle = watcher.watch(&dir, Interest::all()).await.expect("watch");
      assert_eq!(watcher.registry_len(), 1);
      watcher.unwatch(handle).await.expect("unwatch");
      settle(|| watcher.registry_len() == 0).await;
      assert_eq!(watcher.registry_len(), 0, "unwatch reclaims the entry");
      assert_eq!(watcher.root_path(handle), None);
    }
    watcher.close().await.expect("close");
    let _ = std::fs::remove_dir_all(&dir);
  }
}
