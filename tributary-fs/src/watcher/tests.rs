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
  // No driver task holds the other half; these protocol tests never reap a cookie.
  let (cleanup, _cookie_wake) = crate::driver::cookie_ingress();
  let (_event_tx, event_rx) = async_channel::bounded::<(ScopeId, Arc<PathBuf>, Change)>(4);
  (
    Watcher {
      instance: WATCHER_INSTANCES.fetch_add(1, Ordering::Relaxed),
      commands: command_tx,
      cleanup,
      sync_tickets: Arc::new(AtomicU64::new(0)),
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
  let first = Reservation::take(&roots, PathBuf::from("/spelling/One"), Some(id), None)
    .expect("first spelling");
  let err = Reservation::take(&roots, PathBuf::from("/spelling/one"), Some(id), None)
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
  let err = Reservation::take(&roots, PathBuf::from("/live/root"), Some(id), None)
    .expect_err("aliases a live root");
  assert!(
    matches!(err, WatchRootError::Overlaps { existing, .. } if existing.as_path() == Path::new("/live/Root"))
  );
  assert!(Reservation::take(&roots, PathBuf::from("/elsewhere"), None, None).is_ok());
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
/// not(miri): the one unit test that spawns the REAL backend (`Watcher::new`
/// → FSEvents), and under miri the os seam is deliberately the unsupported
/// stub, so the watch itself would honestly refuse. The hermetic twin below
/// (`registry_reclaims_on_unwatch_cycles_hermetic`) keeps the reclaim logic
/// under miri via the fake seam.
#[cfg(all(target_os = "macos", not(miri)))]
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
/// reply-less `SetCover` and reports the tri-state [`RequestOutcome`] — `Enqueued` with room,
/// `Busy` when the channel is momentarily full (the caller retries), and `Rejected` when it can
/// NEVER be enqueued (a foreign brand or a closed watcher — the caller drops the intent).
/// Distinguishing `Busy` from `Rejected` is what lets a caller retry genuine backpressure while
/// dropping never-valid work; collapsing them (the retired `bool`) was the growth vector.
/// Never blocks or panics.
#[tokio::test]
async fn request_set_cover_is_reply_less_and_reports_channel_capacity() {
  let (watcher, commands) = manual_watcher();
  let handle = RootHandle::new(watcher.instance, ScopeId::new(1.try_into().unwrap()));

  // A foreign handle is REJECTED (never retryable) without touching the channel.
  let foreign = RootHandle::new(
    watcher.instance.wrapping_add(1),
    ScopeId::new(1.try_into().unwrap()),
  );
  assert_eq!(
    watcher.request_set_cover(foreign, vec![PathBuf::from("/r/a")]),
    RequestOutcome::Rejected,
    "a foreign handle is rejected — never retryable"
  );

  // With room, the prompt request ENQUEUES a REPLY-LESS SetCover.
  assert_eq!(
    watcher.request_set_cover(handle, vec![PathBuf::from("/r/a")]),
    RequestOutcome::Enqueued,
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

  // Saturate the bounded(16) channel: a full channel is BUSY (transient — the caller retries, it
  // does NOT drop the request), never blocking.
  for _ in 0..16 {
    assert_eq!(
      watcher.request_set_cover(handle, vec![PathBuf::from("/r/full")]),
      RequestOutcome::Enqueued
    );
  }
  assert_eq!(
    watcher.request_set_cover(handle, vec![PathBuf::from("/r/overflow")]),
    RequestOutcome::Busy,
    "a full channel is Busy — a genuine caller retries, never dropped"
  );

  // A closed channel is REJECTED (the driver is gone — never retryable), never a panic.
  drop(commands);
  assert_eq!(
    watcher.request_set_cover(handle, vec![PathBuf::from("/r/closed")]),
    RequestOutcome::Rejected,
    "a closed channel is rejected — retrying can never succeed"
  );
}

/// A [`SyncAdmission`] minted by a DIFFERENT watcher is refused by `sync_root` synchronously —
/// before any command is sent — in the foreign-handle door idiom: a foreign admission's sequence is
/// unrelated to this watcher's numbering, so honoring it could alias one of this watcher's
/// incarnations. The admission-brand check precedes any root lookup, so a synthetic live-branded
/// handle reaches it. Both door refusals are pre-birth, so each hands the admission back
/// ([`SyncRootDenied::admission`] is `Some`) for a same-sequence retry.
#[tokio::test]
async fn sync_root_refuses_a_foreign_ticket_at_the_door() {
  let (watcher, commands) = manual_watcher();
  let (other, _other_commands) = manual_watcher();
  let handle = RootHandle::new(watcher.instance, ScopeId::new(1.try_into().unwrap()));

  // An admission minted by the OTHER watcher — a foreign brand — is refused ForeignTicket, and the
  // pre-birth refusal hands the admission back.
  let (foreign, _foreign_ticket) = other.mint_sync_ticket();
  assert!(
    matches!(
      watcher
        .sync_root(handle, "/r", ".tributaries-sync-foreign", foreign)
        .await,
      Err(SyncRootDenied {
        error: SyncRootError::ForeignTicket,
        admission: Some(_)
      })
    ),
    "a foreign-brand admission is refused ForeignTicket and handed back for retry"
  );
  assert!(
    commands.try_recv().is_err(),
    "the foreign admission sent no command — the refusal is synchronous, at the door"
  );

  // This watcher's OWN admission clears the admission door: it then falls through to the root lookup
  // (which this manual watcher has no live root for), so the answer is UnknownRoot, never
  // ForeignTicket — the brand, not all admissions, is what ForeignTicket refuses. UnknownRoot is
  // pre-birth too, so its admission also comes back.
  let (own, _own_ticket) = watcher.mint_sync_ticket();
  assert!(
    matches!(
      watcher
        .sync_root(handle, "/r", ".tributaries-sync-own", own)
        .await,
      Err(SyncRootDenied {
        error: SyncRootError::UnknownRoot,
        admission: Some(_)
      })
    ),
    "this watcher's own admission clears the foreign-ticket door"
  );
}

/// The pre/post-birth Some/None classification, pinned per variant at the single audit point
/// (`SyncRootDenied::classify`). A refusal raised BEFORE the sync is admitted (the synchronous door
/// errors and the reply-borne refusals) hands the admission back — `Some`, and it is the SAME
/// admission (its sequence is preserved), so a retry keeps the sequence and its paired cancel
/// ticket. A post-birth or ambiguous outcome — `Write` (admitted then retired), `Retired`, `Closed`,
/// and, by the `_ => None` default, any future variant — consumes it (`None`), the fail-safe
/// direction that forces a re-mint rather than re-presenting a spent sequence.
///
/// Fail-on-old: move any pre-birth variant into the default arm (or `Write`/`Retired`/`Closed` into
/// the returned set) and its assertion flips immediately — this match is the only place the
/// classification can drift.
#[tokio::test]
async fn sync_root_denied_classifies_each_variant_pre_or_post_birth() {
  let (watcher, _commands) = manual_watcher();

  // Every refusal that fires before admission returns the SAME admission (sequence preserved) for a
  // same-sequence retry.
  let pre_birth = [
    SyncRootError::UnknownRoot,
    SyncRootError::ForeignTicket,
    SyncRootError::BadCookieName { name: "x".into() },
    SyncRootError::DirOutsideRoot {
      dir: PathBuf::from("/d"),
      root: PathBuf::from("/r"),
    },
    SyncRootError::WriteInFlight,
    SyncRootError::NameInUse { name: "x".into() },
    SyncRootError::TicketInUse {},
    SyncRootError::CleanupBacklog,
  ];
  for error in pre_birth {
    let (admission, ticket) = watcher.mint_sync_ticket();
    let seq = ticket.seq();
    let denied = SyncRootDenied::classify(error, admission);
    let returned = denied.admission.unwrap_or_else(|| {
      panic!(
        "{:?} is pre-birth and must return the admission",
        denied.error
      )
    });
    assert_eq!(
      returned.seq(),
      seq,
      "the returned admission keeps the original sequence for a same-sequence retry: {:?}",
      denied.error
    );
  }

  // Post-birth or ambiguous: the sequence is spent (or its fate unknown), so the admission is
  // consumed and a retry must re-mint. `Write` retires its record before replying (the sequence is
  // burned), `Retired` is a post-admission terminal, and `Closed` is fail-safe.
  let post_birth = [
    SyncRootError::Write {
      path: PathBuf::from("/r/.tributaries-sync-x"),
      source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    },
    SyncRootError::Retired,
    SyncRootError::Closed,
  ];
  for error in post_birth {
    let (admission, _ticket) = watcher.mint_sync_ticket();
    let denied = SyncRootDenied::classify(error, admission);
    assert!(
      denied.admission.is_none(),
      "{:?} is post-birth/ambiguous and must consume the admission",
      denied.error
    );
  }
}

/// [`SyncAdmission`] is plain `Send + Sync` data (two `u64`s), so it holds across `sync_root`'s await
/// without perturbing the future's `Send` — the seam the umbrella's owner-send asserts depend on.
#[allow(dead_code)]
fn _assert_sync_admission_is_send_sync() {
  fn is_send_sync<T: Send + Sync>() {}
  is_send_sync::<SyncAdmission>();
  is_send_sync::<SyncRootDenied>();
}

/// `request_unwatch` is the non-blocking, REPLY-LESS teardown twin of the awaited `unwatch`: it
/// `try_send`s a reply-less `Unwatch` and reports the tri-state [`RequestOutcome`] — `Enqueued`
/// with room, `Busy` when the channel is momentarily full (the caller retries), and `Rejected`
/// when it can NEVER be enqueued (a foreign brand or a closed watcher — the caller drops the
/// intent). Distinguishing `Busy` from `Rejected` is what lets a caller retry genuine backpressure
/// while dropping never-valid work; collapsing them (the retired `bool`) was the growth vector.
/// The enqueued command carries `reply: None`, marking it fire-and-forget for the driver.
#[tokio::test]
async fn request_unwatch_is_reply_less_and_reports_channel_capacity() {
  let (watcher, commands) = manual_watcher();
  let handle = RootHandle::new(watcher.instance, ScopeId::new(1.try_into().unwrap()));

  // A foreign handle is REJECTED (never retryable) without touching the channel.
  let foreign = RootHandle::new(
    watcher.instance.wrapping_add(1),
    ScopeId::new(1.try_into().unwrap()),
  );
  assert_eq!(
    watcher.request_unwatch(foreign),
    RequestOutcome::Rejected,
    "a foreign handle is rejected — never retryable"
  );

  // With room, the request ENQUEUES a REPLY-LESS Unwatch.
  assert_eq!(
    watcher.request_unwatch(handle),
    RequestOutcome::Enqueued,
    "the channel has room"
  );
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

  // Saturate the bounded(16) channel: a full channel is BUSY (transient — the caller retries, it
  // does NOT drop the request), never blocking.
  for _ in 0..16 {
    assert_eq!(watcher.request_unwatch(handle), RequestOutcome::Enqueued);
  }
  assert_eq!(
    watcher.request_unwatch(handle),
    RequestOutcome::Busy,
    "a full channel is Busy — a genuine caller retries, never dropped"
  );

  // A closed channel is REJECTED (the driver is gone — never retryable), never a panic.
  drop(commands);
  assert_eq!(
    watcher.request_unwatch(handle),
    RequestOutcome::Rejected,
    "a closed channel is rejected — retrying can never succeed"
  );
}

/// The awaited `set_cover` sends a SetCover carrying a reply to ack (the acked twin of the
/// reply-less `request_set_cover`), and the driver's answered outcome reaches the caller
/// verbatim.
#[tokio::test]
async fn set_cover_sends_an_acked_command() {
  let (watcher, commands) = manual_watcher();
  let handle = RootHandle::new(watcher.instance, ScopeId::new(1.try_into().unwrap()));
  let mut fut = Box::pin(watcher.set_cover(handle, vec![PathBuf::from("/r/a")]));
  // One poll carries it past the send, parking on the not-yet-answered reply.
  assert!(futures_util::poll!(fut.as_mut()).is_pending());
  match commands.try_recv().expect("the command was sent") {
    Command::SetCover {
      scope,
      retained,
      reply,
    } => {
      assert_eq!(scope, handle.scope());
      assert_eq!(retained, vec![PathBuf::from("/r/a")]);
      let reply = reply.expect("the awaited set_cover carries a reply to ack");
      reply
        .send(CoverOutcome::Degraded)
        .expect("the caller is awaiting");
    }
    _ => panic!("expected a SetCover command"),
  }
  let outcome = fut.await.expect("an answered ack resolves Ok");
  assert_eq!(
    outcome,
    CoverOutcome::Degraded,
    "the driver's outcome reaches the caller verbatim"
  );
}

/// A reply dropped mid-fence — the driver died, or close-mid-fence under the ratified
/// drop-the-replies semantics — surfaces as [`UnwatchError::Closed`]: never a hang, never a
/// fabricated outcome. A foreign handle is still rejected before anything is sent.
#[tokio::test]
async fn set_cover_maps_a_dropped_reply_to_closed() {
  let (watcher, commands) = manual_watcher();
  let handle = RootHandle::new(watcher.instance, ScopeId::new(1.try_into().unwrap()));

  let foreign = RootHandle::new(
    watcher.instance.wrapping_add(1),
    ScopeId::new(1.try_into().unwrap()),
  );
  assert!(matches!(
    watcher
      .set_cover(foreign, vec![PathBuf::from("/r/a")])
      .await,
    Err(UnwatchError::UnknownRoot)
  ));
  assert!(
    commands.try_recv().is_err(),
    "a foreign handle never reaches the driver"
  );

  let mut fut = Box::pin(watcher.set_cover(handle, vec![PathBuf::from("/r/a")]));
  assert!(futures_util::poll!(fut.as_mut()).is_pending());
  match commands.try_recv().expect("the command was sent") {
    Command::SetCover { reply, .. } => drop(reply),
    _ => panic!("expected a SetCover command"),
  }
  let err = fut.await.expect_err("a dropped reply is Closed");
  assert!(err.is_closed(), "{err:?}");
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

  /// How much REAL time one settle round hands to the threads the runtime does
  /// not schedule, before [`timing_scale`] is applied. Sized for the slowest
  /// step such a thread can owe a predicate: the driver creates a reaper thread
  /// on demand, so the first teardown of a run must fit an OS thread spawn, its
  /// first scheduling onto a CPU, and the teardown itself — and on an
  /// oversubscribed machine the scheduling latency alone is a scheduler
  /// quantum, hundreds of microseconds to low milliseconds.
  const SETTLE_ROUND_SLICE: Duration = Duration::from_millis(2);

  /// Scales the real-clock slice, sharing the workspace's timing knob with the
  /// real-kernel suites. Instrumented builds (the sanitizer lanes set this) slow
  /// a thread's spawn and its teardown work several fold while a fixed
  /// wall-clock slice does not stretch to match. Unset it is 1.
  fn timing_scale() -> u32 {
    std::env::var("TRIBUTARY_FS_TIMING_SCALE")
      .ok()
      .and_then(|v| v.parse().ok())
      .filter(|n| *n > 0)
      .unwrap_or(1)
  }

  fn settle_round_slice() -> Duration {
    static SLICE: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();
    *SLICE.get_or_init(|| SETTLE_ROUND_SLICE * timing_scale())
  }

  /// Gives the driver, the blocking pool and the driver's teardown reaper
  /// scheduler slices under paused time — 200 rounds, so a fully expired budget
  /// is 200 × [`SETTLE_ROUND_SLICE`].
  ///
  /// # Why a round costs REAL time under a paused clock
  ///
  /// These cells run on a current-thread runtime with `start_paused = true`, so
  /// the driver task and the test share one thread and the virtual sleep below
  /// hands the driver its next timer at no wall-clock cost. That covers
  /// everything the runtime schedules — and stops exactly there. A stream
  /// teardown runs on the driver's teardown reaper, an ordinary OS thread no
  /// runtime clock governs, and while this task is inside an `await` the
  /// runtime, not that thread, is on the CPU. A round therefore splits in two:
  /// the awaits let the driver reach the point where it hands work off, and
  /// [`SETTLE_ROUND_SLICE`] of real sleep is the window in which the thread it
  /// handed to can run. More rounds cannot substitute for a wider window — the
  /// loop returns as soon as `done` holds, so an observable published a beat
  /// after the one this predicate names has only the CURRENT round's slice to
  /// land in.
  ///
  /// This used to be implicit: while teardowns ran on the blocking pool, an
  /// outstanding `spawn_blocking` inhibited the paused clock's auto-advance, so
  /// the virtual sleep could not return until the pool went quiet. Off the pool
  /// the runtime sees itself idle, auto-advances, and the budget collapses to
  /// nothing unless the slice is spent deliberately.
  async fn settle(mut done: impl FnMut() -> bool) {
    for _ in 0..200 {
      if done() {
        return;
      }
      tokio::task::yield_now().await;
      tokio::time::sleep(Duration::from_millis(10)).await;
      std::thread::sleep(settle_round_slice());
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

  /// A `RootHandle` is `Copy`, so a caller can await two unwatches of the
  /// same root. Both resolve honestly (the first tears it down, the duplicate
  /// is `UnknownRoot`) and — the load-bearing part — neither is dropped: a
  /// dropped reply reads as driver death, which would wrongly CLEAR the whole
  /// registry and erase an UNRELATED live root's overlap fence.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_duplicate_unwatch_never_clears_an_unrelated_root() {
    let (dir_a, canon_a) = scratch("dup-a");
    let (dir_b, canon_b) = scratch("dup-b");
    let fs = FakeFs::new(1);
    fs.put(&canon_a, FileKind::Dir, 1);
    fs.put(&canon_b, FileKind::Dir, 2);
    let watcher =
      Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");
    let handle_a = watcher
      .watch(&dir_a, Interest::all())
      .await
      .expect("watch A");
    let handle_b = watcher
      .watch(&dir_b, Interest::all())
      .await
      .expect("watch B");

    // Hold the teardown so A stays non-quiescent across both unwatches.
    let gate = fs.hold_teardowns();
    let mut u1 = Box::pin(watcher.unwatch(handle_a));
    assert!(futures_util::poll!(u1.as_mut()).is_pending());
    // Let the first unwatch remove the handle and dispatch the held teardown
    // before the duplicate lands in the outstanding-obligation branch.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut u2 = Box::pin(watcher.unwatch(handle_a));
    assert!(futures_util::poll!(u2.as_mut()).is_pending());
    tokio::time::sleep(Duration::from_millis(100)).await;

    gate.release();
    u1.await.expect("the first unwatch succeeds");
    assert!(
      matches!(u2.await, Err(UnwatchError::UnknownRoot)),
      "the duplicate is UnknownRoot, never a Closed that reads as driver death"
    );

    // The unrelated root B survived: its entry is intact AND its overlap
    // fence still rejects a colliding watch — proof the registry was never
    // cleared.
    assert_eq!(
      watcher.root_path(handle_b).as_deref(),
      Some(canon_b.as_path())
    );
    let err = watcher
      .watch(&dir_b, Interest::all())
      .await
      .expect_err("B is still registered, so a re-watch overlaps");
    assert!(matches!(err, WatchRootError::Overlaps { .. }), "{err:?}");

    watcher.close().await.expect("close");
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
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

  /// The public set-cover ack over a live KERNEL-RECURSIVE root (the hermetic
  /// suites pin FSEvents): answered `Recursive` immediately — one
  /// whole-subtree stream IS the coverage, which never narrowed, so there is
  /// no reconcile to fence — and an unknown scope of this watcher is the
  /// driver-side `Skipped(UnknownRoot)`, not an error (the handle plane
  /// cannot distinguish never-watched from just-died).
  #[tokio::test(start_paused = true)]
  async fn set_cover_on_a_kernel_recursive_root_answers_recursive() {
    let (dir, canonical) = scratch("kr-cover");
    let fs = FakeFs::new(1);
    fs.put(&canonical, FileKind::Dir, 1);
    let watcher =
      Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");
    let handle = watcher.watch(&dir, Interest::all()).await.expect("watch");

    let outcome = watcher
      .set_cover(handle, vec![canonical.join("keep")])
      .await
      .expect("the driver answers");
    assert_eq!(
      outcome,
      CoverOutcome::Recursive,
      "kernel-recursive coverage never narrowed — reported, never fenced"
    );

    let dead = RootHandle::new(watcher.instance, ScopeId::new(9.try_into().unwrap()));
    let outcome = watcher
      .set_cover(dead, vec![canonical.join("keep")])
      .await
      .expect("the driver answers");
    assert_eq!(outcome, CoverOutcome::Skipped(SkipReason::UnknownRoot));

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

  /// The public swap contract end to end: the handle survives, the registry
  /// view flips old → new, the old path is immediately re-watchable, and the
  /// same handle still unwatches afterwards.
  #[tokio::test(start_paused = true)]
  async fn replace_root_swaps_the_registry_view() {
    let (dir_a, canon_a) = scratch("replace-old");
    let (dir_b, canon_b) = scratch("replace-new");
    let fs = FakeFs::new(1);
    fs.put(&canon_a, FileKind::Dir, 1);
    fs.put(&canon_b, FileKind::Dir, 2);
    let watcher =
      Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");

    let handle = watcher.watch(&dir_a, Interest::all()).await.expect("watch");
    let backend = watcher.backend_of(handle).expect("a live backend");

    watcher
      .replace_root(handle, &dir_b)
      .await
      .expect("the swap commits");
    settle(|| fs.shutdowns() == 1).await;
    assert_eq!(watcher.registry_len(), 1, "one scope throughout");
    assert_eq!(
      watcher.root_path(handle).as_deref(),
      Some(canon_b.as_path()),
      "the view re-roots"
    );
    assert_eq!(watcher.backend_of(handle), Some(backend));

    // The old coverage is released: the old path watches afresh.
    let fresh = watcher
      .watch(&dir_a, Interest::all())
      .await
      .expect("the old root is free again");
    watcher.unwatch(fresh).await.expect("unwatch the fresh");

    watcher.unwatch(handle).await.expect("the handle survives");
    settle(|| watcher.registry_len() == 0).await;
    watcher.close().await.expect("close");
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
  }

  /// The awaited error contract: each refusal shape surfaces typed, with the
  /// watch untouched.
  #[tokio::test(start_paused = true)]
  async fn replace_root_refusals_are_typed_and_atomic() {
    let (dir_a, canon_a) = scratch("refuse-old");
    let (dir_v, canon_v) = scratch("refuse-victim");
    let file = dir_a.join("plain.txt");
    std::fs::write(&file, b"x").expect("a plain file");
    let fs = FakeFs::new(1);
    fs.put(&canon_a, FileKind::Dir, 1);
    fs.put(&canon_v, FileKind::Dir, 2);
    let watcher =
      Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");
    let handle = watcher.watch(&dir_a, Interest::all()).await.expect("watch");
    let _victim = watcher.watch(&dir_v, Interest::all()).await.expect("watch");

    // A new root that does not exist.
    let missing = dir_a.join("nope");
    assert!(matches!(
      watcher.replace_root(handle, &missing).await,
      Err(ReplaceRootError::NotFound { .. })
    ));
    // A new root that is not a directory.
    assert!(matches!(
      watcher.replace_root(handle, &file).await,
      Err(ReplaceRootError::NotADirectory { .. })
    ));
    // A handle from another watcher instance.
    let other_fs = FakeFs::new(1);
    other_fs.put(&canon_v, FileKind::Dir, 2);
    let other =
      Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), other_fs.clone()).expect("build");
    let foreign = other.watch(&dir_v, Interest::all()).await.expect("watch");
    assert!(matches!(
      watcher.replace_root(foreign, &dir_v).await,
      Err(ReplaceRootError::UnknownRoot)
    ));
    other.close().await.expect("close other");
    // A new root that overlaps ANOTHER live watch — refused at reservation
    // time, exemption notwithstanding.
    match watcher.replace_root(handle, &dir_v).await {
      Err(ReplaceRootError::Overlaps { path, existing }) => {
        assert_eq!(path, canon_v);
        assert_eq!(existing, canon_v);
      }
      other => panic!("expected Overlaps, got {other:?}"),
    }

    // Every refusal left the watch untouched.
    assert_eq!(watcher.registry_len(), 2);
    assert_eq!(
      watcher.root_path(handle).as_deref(),
      Some(canon_a.as_path())
    );
    watcher.close().await.expect("close");
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_v);
  }

  /// Cancellation at each await boundary of `replace_root`, crossed with the
  /// spawn fates. Once the command is sent the driver owns the swap — a
  /// dropped future abandons only the NOTIFICATION: a viable swap still
  /// commits, a failed one still unwinds. In every arm the reservation is
  /// released, `registry_len` holds at 1, and `root_path` reports the old
  /// root or the new one — never neither.
  #[tokio::test(start_paused = true)]
  async fn replace_cancellation_at_every_await_point_leaves_consistent_state() {
    // Dropped before the first poll: nothing was reserved, nothing was sent.
    {
      let (dir_a, canon_a) = scratch("rc-unpolled-old");
      let (dir_b, _canon_b) = scratch("rc-unpolled-new");
      let fs = FakeFs::new(1);
      fs.put(&canon_a, FileKind::Dir, 1);
      fs.put(std::fs::canonicalize(&dir_b).unwrap(), FileKind::Dir, 2);
      let watcher =
        Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");
      let handle = watcher.watch(&dir_a, Interest::all()).await.expect("watch");

      drop(watcher.replace_root(handle, &dir_b));
      assert_eq!(
        watcher.root_path(handle).as_deref(),
        Some(canon_a.as_path())
      );
      let fresh = watcher
        .watch(&dir_b, Interest::all())
        .await
        .expect("no reservation lingers");
      watcher.unwatch(fresh).await.expect("unwatch");
      watcher.close().await.expect("close");
      let _ = std::fs::remove_dir_all(&dir_a);
      let _ = std::fs::remove_dir_all(&dir_b);
    }

    // Dropped post-send while the spawn is HELD: the driver still commits.
    // Mid-window the view reports the OLD root — never neither.
    for drop_after_settle in [false, true] {
      let (dir_a, canon_a) = scratch(if drop_after_settle {
        "rc-unpolled-reply-old"
      } else {
        "rc-held-old"
      });
      let (dir_b, canon_b) = scratch(if drop_after_settle {
        "rc-unpolled-reply-new"
      } else {
        "rc-held-new"
      });
      let fs = FakeFs::new(1);
      fs.put(&canon_a, FileKind::Dir, 1);
      fs.put(&canon_b, FileKind::Dir, 2);
      let watcher =
        Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");
      let handle = watcher.watch(&dir_a, Interest::all()).await.expect("watch");

      let gate = (!drop_after_settle).then(|| fs.hold_spawns());
      {
        let mut fut = Box::pin(watcher.replace_root(handle, &dir_b));
        assert!(futures_util::poll!(fut.as_mut()).is_pending());
        if drop_after_settle {
          // The reply is delivered but never polled out.
          settle(|| fs.shutdowns() == 1).await;
        } else {
          assert_eq!(
            watcher.root_path(handle).as_deref(),
            Some(canon_a.as_path()),
            "mid-swap the view is the OLD root, never neither"
          );
        }
        // The future drops here — the notification is abandoned.
      }
      if let Some(gate) = &gate {
        gate.release();
      }
      settle(|| fs.shutdowns() == 1 && watcher.root_path(handle).as_deref() == Some(&canon_b))
        .await;
      assert_eq!(watcher.registry_len(), 1);
      assert_eq!(
        watcher.root_path(handle).as_deref(),
        Some(canon_b.as_path()),
        "the abandoned swap still committed (drop_after_settle={drop_after_settle})"
      );
      let fresh = watcher
        .watch(&dir_a, Interest::all())
        .await
        .expect("the old coverage was released");
      watcher.unwatch(fresh).await.expect("unwatch");
      watcher.close().await.expect("close");
      let _ = std::fs::remove_dir_all(&dir_a);
      let _ = std::fs::remove_dir_all(&dir_b);
    }

    // Dropped post-send and the spawn FAILS: the driver unwinds — the old
    // watch is untouched and the reservation is released.
    {
      let (dir_a, canon_a) = scratch("rc-fail-old");
      let (dir_b, canon_b) = scratch("rc-fail-new");
      let fs = FakeFs::new(1);
      fs.put(&canon_a, FileKind::Dir, 1);
      // canon_b exists on the REAL fs but not in the fake: the spawn fails.
      let watcher =
        Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");
      let handle = watcher.watch(&dir_a, Interest::all()).await.expect("watch");

      {
        let mut fut = Box::pin(watcher.replace_root(handle, &dir_b));
        assert!(futures_util::poll!(fut.as_mut()).is_pending());
      }
      // The release is observable as the error KIND flipping: `Overlaps`
      // names the still-held reservation, while a fresh Source failure can
      // only come from an attempt that RESERVED canon_b itself.
      let mut released = false;
      for _ in 0..500 {
        match watcher.watch(&dir_b, Interest::all()).await {
          Err(WatchRootError::Overlaps { .. }) => {
            tokio::time::sleep(Duration::from_millis(10)).await;
          }
          Err(_) => {
            released = true;
            break;
          }
          Ok(_) => panic!("canon_b is not in the fake tree yet"),
        }
      }
      assert!(released, "the failed replace releases its reservation");
      assert_eq!(
        watcher.root_path(handle).as_deref(),
        Some(canon_a.as_path()),
        "the failed swap left the old root"
      );
      // And the path is genuinely re-watchable once the root exists.
      fs.put(&canon_b, FileKind::Dir, 2);
      let fresh = watcher
        .watch(&dir_b, Interest::all())
        .await
        .expect("re-watchable after the unwind");
      watcher.unwatch(fresh).await.expect("unwatch");
      watcher.close().await.expect("close");
      let _ = std::fs::remove_dir_all(&dir_a);
      let _ = std::fs::remove_dir_all(&dir_b);
    }

    // Dropped post-send and the FINAL check conflicts (the backend
    // re-canonicalizes onto a bystander's tree): the driver unwinds, both
    // watches untouched, the refused stream torn down.
    {
      let (dir_a, canon_a) = scratch("rc-conflict-old");
      let (dir_b, canon_b) = scratch("rc-conflict-new");
      let (dir_v, canon_v) = scratch("rc-conflict-victim");
      let fs = FakeFs::new(1);
      fs.put(&canon_a, FileKind::Dir, 1);
      fs.put(&canon_b, FileKind::Dir, 2);
      fs.put(&canon_v, FileKind::Dir, 3);
      fs.put(canon_v.join("sub"), FileKind::Dir, 4);
      let watcher =
        Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");
      let handle = watcher.watch(&dir_a, Interest::all()).await.expect("watch");
      let victim = watcher.watch(&dir_v, Interest::all()).await.expect("watch");
      let spawned_before = fs.spawns();

      fs.remap_spawn_root(&canon_b, canon_v.join("sub"));
      {
        let mut fut = Box::pin(watcher.replace_root(handle, &dir_b));
        assert!(futures_util::poll!(fut.as_mut()).is_pending());
      }
      settle(|| fs.spawns() == spawned_before + 1 && fs.shutdowns() == 1).await;
      assert_eq!(fs.shutdowns(), 1, "the refused replacement is torn down");
      assert_eq!(watcher.registry_len(), 2, "both watches survive");
      assert_eq!(
        watcher.root_path(handle).as_deref(),
        Some(canon_a.as_path())
      );
      assert_eq!(
        watcher.root_path(victim).as_deref(),
        Some(canon_v.as_path())
      );
      // The canon_b reservation was released: a fresh watch of dir_b gets
      // all the way to the FINAL check (the remap still redirects it into
      // the victim), not a reservation-time refusal against canon_b itself.
      match watcher.watch(&dir_b, Interest::all()).await {
        Err(WatchRootError::Overlaps { path, existing }) => {
          assert_eq!(path, canon_v.join("sub"), "the FINAL root is reported");
          assert_eq!(existing, canon_v);
        }
        other => panic!("expected the final-check Overlaps, got {other:?}"),
      }
      watcher.close().await.expect("close");
      let _ = std::fs::remove_dir_all(&dir_a);
      let _ = std::fs::remove_dir_all(&dir_b);
      let _ = std::fs::remove_dir_all(&dir_v);
    }
  }

  /// A hostile flood of the PUBLIC cleanup requests retains NOTHING — the whole
  /// point of the cleanup ingress being a mark on a counted obligation rather than
  /// a queue.
  ///
  /// The cell is deliberately the WORST case for a queue: a current-thread runtime
  /// on which the driver task, though spawned, is NEVER SCHEDULED — the flooding
  /// caller holds the only thread and awaits nothing — so no drain can rescue the
  /// bound. Against the old design (an unbounded lane fed by zero-validation
  /// `try_send`s, with dedup only after dequeue) this is precisely the reported
  /// growth vector: every one of these calls would allocate and retain one
  /// caller-sized message.
  ///
  /// The assertions are the STRUCTURAL quantities rather than process memory
  /// (which is not deterministic): the ledger is the only place a cleanup request
  /// can live, and the wake is the only channel the ingress touches.
  ///
  /// Fail-on-old: with the door removed and the wake unbounded (the old lane's
  /// shape — enqueue anything, resolve later), the wake grows to one entry per
  /// call and the `<= 1` assertion fails on the very first check.
  #[tokio::test(flavor = "current_thread")]
  async fn a_hostile_cleanup_flood_retains_nothing_with_the_driver_unscheduled() {
    let fs = FakeFs::new(1);
    let watcher =
      Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");

    // Nothing is awaited from here on: on a current-thread runtime the driver task
    // cannot run at all, so every bound below is proven WITHOUT a drain.
    //
    // One reused ticket is the duplicate-target half of the vector: the old lane
    // queued each duplicate, because it deduplicated only after dequeue.
    let (_, dup) = watcher.mint_sync_ticket();
    for i in 0..100_000u64 {
      watcher.request_remove_cookie(PathBuf::from(format!("/r/.tributaries-sync-{i}")));
      // A freshly minted, never-admitted ticket resolves nothing — it addresses no
      // record this watcher ever admitted, so the flood retains nothing through it.
      watcher.request_cancel_sync(watcher.mint_sync_ticket().1);
      watcher.request_remove_cookie(PathBuf::from("/r/.tributaries-sync-dup"));
      watcher.request_cancel_sync(dup);
    }

    assert_eq!(
      watcher.cleanup.ledger_len(),
      0,
      "no request created an obligation: the flood addressed nothing this watcher \
       ever admitted, so it had nowhere to be stored"
    );
    assert!(
      watcher.cleanup.wake_len() <= 1,
      "the wake is capacity-1 and carries no request, so 400k calls cannot grow it \
       past one token: {}",
      watcher.cleanup.wake_len()
    );

    // The driver is still perfectly healthy: the flood cost it nothing to ignore,
    // and a genuine sync still admits (its refusals were never consumed).
    let watched = watcher.registry_len();
    assert_eq!(watched, 0, "no root was ever watched");
    watcher.close().await.expect("close");
  }

  /// The returned-admission retry contract, end to end over the real driver: a pre-birth refusal
  /// hands the admission back, and re-presenting it retries under the SAME sequence — a refusal
  /// burns nothing. A admits under `name`; a second sync under the same `name` with a FRESH
  /// admission is refused `NameInUse` (A's write already completed, so it is the name gate, not
  /// single-flight) and that refusal returns the admission; once A is reaped and the name frees,
  /// the returned admission admits under its original sequence.
  ///
  /// Fail-on-old: neuter `SyncRootDenied::classify` to always-`None` and the `expect` on the
  /// returned admission fails FAST — there is nothing to retry with, and the move-only admission
  /// cannot be reconstructed.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_pre_birth_refusal_returns_the_admission_for_a_same_sequence_retry() {
    let (dir, canonical) = scratch("admission-retry");
    let fs = FakeFs::new(1);
    fs.put(&canonical, FileKind::Dir, 1);
    let watcher =
      Watcher::<TokioRuntime>::new_with(WatcherOptions::new(), fs.clone()).expect("build");
    let handle = watcher
      .watch(&dir, Interest::all())
      .await
      .expect("watch the root");

    let name = ".tributaries-sync-admission-retry";

    // A admits under `name` and writes its cookie (the reply resolves at write-complete).
    let (a1, _t1) = watcher.mint_sync_ticket();
    let path_a = watcher
      .sync_root(handle, &canonical, name, a1)
      .await
      .expect("A admits and writes its cookie");

    // A second sync under the SAME name, with a FRESH admission, is refused NameInUse — a pre-birth
    // refusal that hands the admission back for a same-sequence retry.
    let (a2, t2) = watcher.mint_sync_ticket();
    let seq2 = t2.seq();
    let denied = watcher
      .sync_root(handle, &canonical, name, a2)
      .await
      .expect_err("a second sync under a live name is refused");
    assert!(
      matches!(denied.error, SyncRootError::NameInUse { .. }),
      "the second same-name sync is refused NameInUse, got {:?}",
      denied.error
    );
    let mut admission = denied
      .admission
      .expect("a pre-birth NameInUse refusal returns the admission for a same-sequence retry");
    assert_eq!(
      admission.seq(),
      seq2,
      "the returned admission keeps its original sequence"
    );

    // Reap A to free the name, then RETRY with the returned admission. Each NameInUse hands it back
    // (the contract), so the SAME sequence is re-presented without a re-mint until A retires and the
    // name frees — then it admits under seq2. Bounded so a wedged reap fails the cell, never hangs.
    watcher.request_remove_cookie(path_a.clone());
    let mut attempts = 0;
    let path_b = loop {
      attempts += 1;
      assert!(attempts <= 500, "A did not retire within the retry budget");
      match watcher.sync_root(handle, &canonical, name, admission).await {
        Ok(path) => break path,
        Err(denied) => {
          assert!(
            matches!(denied.error, SyncRootError::NameInUse { .. }),
            "while A drains the only expected refusal is NameInUse, got {:?}",
            denied.error
          );
          admission = denied
            .admission
            .expect("every NameInUse hands the admission back for retry");
          assert_eq!(
            admission.seq(),
            seq2,
            "the sequence is preserved across every retry"
          );
          tokio::time::sleep(Duration::from_millis(10)).await;
        }
      }
    };
    assert_eq!(
      path_b, path_a,
      "the retry admits under the same name — the returned admission burned nothing"
    );

    // Close proves every cookie this watcher wrote (A's, then the retry's incarnation under seq2)
    // was confirmed removed.
    watcher.close().await.expect("close removes every cookie");
    let _ = std::fs::remove_dir_all(&dir);
  }
}

/// Forcing another platform's primitive fails the watch with the typed
/// [`SourceError::ForeignBackend`](crate::SourceError::ForeignBackend) — never
/// a silent ignore and never a fallback. The real seam rejects the selection
/// before any platform spawn (or its FFI) runs, so the refusal is identical on
/// every host.
#[cfg(not(miri))]
#[tokio::test]
async fn foreign_backend_is_a_typed_spawn_error() {
  let foreign = if cfg!(target_os = "linux") {
    crate::Backend::Rdcw
  } else {
    crate::Backend::Inotify
  };
  let dir = scratch_dir("foreign-backend");
  let watcher =
    Watcher::<TokioRuntime>::new(WatcherOptions::new().with_backend(foreign)).expect("build");

  let err = watcher
    .watch(&dir, Interest::all())
    .await
    .expect_err("a foreign selection can never start");
  assert!(
    matches!(
      err,
      WatchRootError::Source(crate::SourceError::ForeignBackend { requested }) if requested == foreign
    ),
    "{err:?}"
  );
  watcher.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&dir);
}

/// The replace exemption: a reservation (and the live-set check under it)
/// excludes exactly ONE scope — the root being replaced — so widening onto
/// an ancestor of ONLY that root reserves cleanly, while any OTHER live
/// root's coverage still conflicts.
#[test]
fn reservation_exemption_excludes_exactly_the_replaced_scope() {
  let roots = Arc::new(RwLock::new(RootSet::default()));
  let replaced = ScopeId::new(core::num::NonZeroU64::new(7).unwrap());
  let bystander = ScopeId::new(core::num::NonZeroU64::new(9).unwrap());
  {
    let mut set = roots.write().unwrap();
    set.entries.insert(
      replaced,
      RootEntry {
        path: Arc::new(PathBuf::from("/a/b")),
        identity: RootIdentity::new(1, 10),
        ancestors: vec![RootIdentity::new(1, 1)].into(),
        backend: crate::os::BackendKind::FsEvents,
        stats: None,
      },
    );
    set.entries.insert(
      bystander,
      RootEntry {
        path: Arc::new(PathBuf::from("/c/d")),
        identity: RootIdentity::new(1, 20),
        ancestors: vec![RootIdentity::new(1, 2)].into(),
        backend: crate::os::BackendKind::FsEvents,
        stats: None,
      },
    );
  }

  // Widening /a/b -> /a: overlaps ONLY the replaced scope — exempt passes.
  let widened = Reservation::take(&roots, PathBuf::from("/a"), None, Some(replaced))
    .expect("the replaced scope's own coverage never conflicts");
  drop(widened);

  // Without the exemption the same take conflicts (today's watch behavior).
  let err = Reservation::take(&roots, PathBuf::from("/a"), None, None)
    .expect_err("un-exempted overlap still conflicts");
  assert!(matches!(err, WatchRootError::Overlaps { .. }));

  // The exemption is NOT a blank check: /c (the bystander's ancestor)
  // still conflicts even with the replaced scope exempted.
  let err = Reservation::take(&roots, PathBuf::from("/c"), None, Some(replaced))
    .expect_err("another live root's coverage still conflicts");
  assert!(matches!(err, WatchRootError::Overlaps { .. }));

  // Identity aliasing is exempted the same way: a candidate that IS the
  // replaced root's object (same identity, different spelling) passes...
  let aliased = Reservation::take(
    &roots,
    PathBuf::from("/A/B"),
    Some(RootIdentity::new(1, 10)),
    Some(replaced),
  )
  .expect("the replaced object under another spelling is exempt");
  drop(aliased);
  // ...while the bystander's object never does.
  let err = Reservation::take(
    &roots,
    PathBuf::from("/elsewhere"),
    Some(RootIdentity::new(1, 20)),
    Some(replaced),
  )
  .expect_err("a bystander's object identity still conflicts");
  assert!(matches!(err, WatchRootError::Overlaps { .. }));
}

/// The final-root gate honors the same exemption on the single-writer side:
/// ancestor-identity containment against the replaced scope is exempt,
/// against anyone else it conflicts.
#[test]
fn final_root_conflict_exemption_mirrors_the_reservation() {
  let roots = Arc::new(RwLock::new(RootSet::default()));
  let replaced = ScopeId::new(core::num::NonZeroU64::new(7).unwrap());
  {
    let mut set = roots.write().unwrap();
    set.entries.insert(
      replaced,
      RootEntry {
        path: Arc::new(PathBuf::from("/a/b")),
        identity: RootIdentity::new(1, 10),
        ancestors: vec![RootIdentity::new(1, 1)].into(),
        backend: crate::os::BackendKind::FsEvents,
        stats: None,
      },
    );
  }
  let writer = RegistryWriter {
    roots: Arc::clone(&roots),
  };
  // /a contains /a/b (and /a IS the replaced root's recorded ancestor
  // identity): exempted, no conflict.
  assert_eq!(
    writer.final_root_conflict(
      Path::new("/a"),
      RootIdentity::new(1, 1),
      &[],
      None,
      Some(replaced),
    ),
    None
  );
  // Un-exempted, the same check conflicts.
  assert!(
    writer
      .final_root_conflict(Path::new("/a"), RootIdentity::new(1, 1), &[], None, None)
      .is_some()
  );
}
