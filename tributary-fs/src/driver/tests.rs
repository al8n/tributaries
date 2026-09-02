use super::{testing::*, *};
use std::{
  collections::BTreeSet,
  num::{NonZeroU64, NonZeroUsize},
  sync::Arc,
  time::Duration,
};

use agnostic_lite::tokio::TokioRuntime;
use tributary_proto::{Epoch, FileKind, Location, Segment};

use crate::os::{FsEventFlags, RawOsEvent};

struct Rig {
  fs: FakeFs,
  commands: async_channel::Sender<Command>,
  /// The watcher handle's half of the cookie-cleanup ingress: the suites drive
  /// the PUBLIC reap and cancel through exactly what `Watcher` calls, on the very
  /// ledger this rig's driver admits into.
  cleanup: CookieIngress,
  events: async_channel::Receiver<(ScopeId, Arc<PathBuf>, Change)>,
}

fn config() -> DriverConfig {
  DriverConfig {
    latency: Duration::from_millis(10),
    move_window: Duration::from_millis(100),
    os_batch_capacity: NonZeroUsize::new(8).unwrap(),
    // Inert for the fake spawns (no native read buffer); a real spawn threads
    // this into its SourceConfig.
    os_buffer_bytes: std::num::NonZeroU32::new(64 * 1024).unwrap(),
    exclusions: Vec::new(),
    profile: BackendKind::FsEvents,
    backend: Backend::Auto,
    // DISABLED here (`ZERO`), not merely dormant. Since #74 the tick arms for
    // BOTH Linux profiles (`DriverCore::liveness_ticked`), so every descending
    // rig below would inherit a LIVE cadence from this shared config — and a
    // production-sized interval buys the shared suite nothing, because no cell
    // here runs for 30 s, so the tick never fires natively at all.
    //
    // Under an INTERPRETER it does fire, and there it starves the loop. A driver
    // iteration costs on the order of a second under Miri (measured: 182
    // iterations in 272 s), while N ticking scopes demand N mount refreshes per
    // interval — so past a couple of dozen live scopes the demand exceeds the
    // service rate, each refresh completion lands on `op_rx`, and `op_rx` is the
    // FIRST `select_biased!` arm: once it stops emptying, the command mailbox
    // behind it is never polled again and the run makes no further progress.
    // That is what took `retention`'s
    // `held_root_arms_cannot_burst_past_the_teardown_backlog_bound` (64 live
    // scopes) from a pass to a permanent stall at 48 of them, on every Miri
    // shard.
    //
    // A cell that is ABOUT the cadence sets its own interval — see
    // `descending::tick`.
    root_liveness_interval: Duration::ZERO,
    // Inert for the fake spawns (no fanotify admission map); a real fanotify
    // spawn threads this into its SourceConfig.
    max_map_directories: None,
    cookie_retry_base: Duration::from_millis(100),
    cookie_retry_cap: Duration::from_secs(5),
    cookie_retry_budget: 8,
    cookie_backlog_cap: 8,
    cookie_global_cap: 128,
  }
}

/// The cookie-retry cells' config: a fast backoff, a small attempt budget, and a low
/// per-scope backlog cap, so the driver-owned retry, budget-park, and backlog-refusal
/// paths run in real (multi-thread) time within a `settle` window.
fn tuned_config() -> DriverConfig {
  DriverConfig {
    cookie_retry_base: Duration::from_millis(5),
    cookie_retry_cap: Duration::from_millis(20),
    cookie_retry_budget: 3,
    cookie_backlog_cap: 3,
    cookie_global_cap: 64,
    ..config()
  }
}

fn rig_with_capacity(event_capacity: usize) -> Rig {
  rig_with(event_capacity, NullRegistry)
}

/// A rig whose driver runs with an explicit [`DriverConfig`] — the cookie-retry cells override
/// the backoff/budget/backlog knobs so their timings are fast and deterministic.
fn rig_with_config(event_capacity: usize, config: DriverConfig) -> Rig {
  let fs = FakeFs::new(1);
  fs.put("/r", FileKind::Dir, 1);
  let (cmd_tx, cmd_rx) = async_channel::bounded(16);
  let (cleanup, cookie_wake) = cookie_ingress();
  let (ev_tx, ev_rx) = async_channel::bounded(event_capacity);
  tokio::spawn(run::<TokioRuntime, FakeFs>(
    config,
    fs.clone(),
    cmd_rx,
    cookie_wake,
    ev_tx,
    NullRegistry,
  ));
  Rig {
    fs,
    commands: cmd_tx,
    cleanup,
    events: ev_rx,
  }
}

fn rig_with(event_capacity: usize, registry: impl ScopeRegistry) -> Rig {
  let fs = FakeFs::new(1);
  fs.put("/r", FileKind::Dir, 1);
  let (cmd_tx, cmd_rx) = async_channel::bounded(16);
  let (cleanup, cookie_wake) = cookie_ingress();
  let (ev_tx, ev_rx) = async_channel::bounded(event_capacity);
  tokio::spawn(run::<TokioRuntime, FakeFs>(
    config(),
    fs.clone(),
    cmd_rx,
    cookie_wake,
    ev_tx,
    registry,
  ));
  Rig {
    fs,
    commands: cmd_tx,
    cleanup,
    events: ev_rx,
  }
}

async fn watch(rig: &Rig, root: &str) -> ScopeId {
  let before = rig.fs.refreshes();
  let (reply, on_reply) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Watch {
      root: PathBuf::from(root),
      interest: tributary_proto::Interest::all(),
      reply,
    })
    .await
    .unwrap();
  let grant = on_reply.await.unwrap().expect("watch succeeds");
  let scope = grant.scope();
  grant.defuse();
  // A scope is born trust-closed; its birth refresh runs on the real-thread
  // blocking pool. Wait it out so every test starts from installed trust —
  // once the result is queued, the biased select consumes it before any
  // batch a test injects afterwards. Real-clock bound: the pool runs outside
  // the paused runtime.
  let deadline = std::time::Instant::now() + Duration::from_secs(10);
  while rig.fs.refreshes() <= before && std::time::Instant::now() < deadline {
    tokio::task::yield_now().await;
  }
  assert!(rig.fs.refreshes() > before, "the birth refresh ran");
  // The counter increments inside the pool thread an instant before its
  // result is queued; a few yields let that send land.
  for _ in 0..8 {
    tokio::task::yield_now().await;
  }
  scope
}

fn ev(path: &str, flags: FsEventFlags, event_id: u64, file_id: u64) -> RawOsEvent {
  RawOsEvent {
    path: PathBuf::from(path),
    flags,
    event_id,
    file_id: NonZeroU64::new(file_id),
  }
}

fn created() -> FsEventFlags {
  FsEventFlags::new(FsEventFlags::ITEM_CREATED.bits() | FsEventFlags::ITEM_IS_FILE.bits())
}

fn removed() -> FsEventFlags {
  FsEventFlags::new(FsEventFlags::ITEM_REMOVED.bits() | FsEventFlags::ITEM_IS_FILE.bits())
}

/// Mints a fresh, unique [`SyncTicket`] for a direct-`Command` cell. The driver
/// suites drive `Command::SyncRoot` with no `Watcher` to mint through, so they draw
/// sequences from one process-monotonic counter under a fixed brand: the driver
/// never inspects the brand (the foreign-ticket door is the watcher's), only the
/// sequence, which `by_ticket`/`TicketInUse` key on. A fresh call is a distinct
/// incarnation; a cell that needs a reused ticket binds one and passes it twice.
fn ticket() -> SyncTicket {
  static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
  SyncTicket::new(1, SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
}

fn renamed() -> FsEventFlags {
  FsEventFlags::new(FsEventFlags::ITEM_RENAMED.bits() | FsEventFlags::ITEM_IS_FILE.bits())
}

/// `next_event` plus the delivery's canonical root.
async fn next_rooted(rig: &Rig) -> (ScopeId, Arc<PathBuf>, Change) {
  tokio::time::timeout(interpreted_secs(5), rig.events.recv())
    .await
    .expect("an event arrives")
    .expect("the stream is open")
}

async fn next_event(rig: &Rig) -> (ScopeId, Change) {
  let (scope, _root, change) = tokio::time::timeout(interpreted_secs(5), rig.events.recv())
    .await
    .expect("an event arrives")
    .expect("the stream is open");
  (scope, change)
}

fn loc(parts: &[&str]) -> Location {
  Location::from_segments(parts.iter().map(|p| Segment::new(*p)))
}

/// Fences a scope's BIRTH crawl, and pins what a registration over pre-existing
/// subdirectories now delivers (42-10): the contract reports no inventory, so the
/// crawl's one signal is the window's closing `Rescan` at the SCOPE ROOT, emitted
/// at coverage settle.
///
/// That `Rescan` is a stronger fence than the inventory `Created` these cells used
/// to consume, and it is the reason this helper replaced it wholesale: it is
/// emitted at the settle edge, so it postdates the root's read AND every
/// descendant arm by construction, whereas a `Created` for one entry proved only
/// that one read had reached the consumer.
/// A mount-table row with no identity — the fake reads no namespace, so its
/// rows answer `None` for the mount id, its parent and the device exactly as
/// macOS' `getfsstat` and a pre-5.8 Linux kernel do. The driver suites here care only
/// WHERE a mount is; identity is exercised in the core's own cells.
fn bare_mount(location: &str) -> crate::os::MountRow {
  crate::os::MountRow {
    location: PathBuf::from(location),
    mnt_id: None,
    parent_id: None,
    dev: None,
  }
}

async fn fence_birth_crawl(rig: &Rig, scope: ScopeId, root: &str) {
  let (s, r, change) = next_rooted(rig).await;
  assert_eq!((s, r.as_path()), (scope, std::path::Path::new(root)));
  assert!(
    change.kind().is_rescan(),
    "a registration announces no inventory — its one signal is the window's \
     closing Rescan: {change:?}"
  );
  assert_eq!(
    change.location(),
    &loc(&[]),
    "located at the scope root, dominating the whole crawl"
  );
}

/// How much REAL time one settle round hands to the threads the runtime does not
/// schedule, before [`timing_scale`] is applied.
///
/// This is the WHOLE window a round gives an off-runtime thread, not a share of
/// a longer one — see [`settle_within`] — so it is sized for the slowest step
/// such a thread can owe a predicate: the driver creates a reaper thread on
/// demand, so the first teardown of a run must fit an OS thread spawn, its first
/// scheduling onto a CPU, and the teardown itself. On an oversubscribed machine
/// — a parallel suite in a CPU-capped container — the scheduling latency alone
/// is a scheduler quantum, hundreds of microseconds to low milliseconds. Two
/// milliseconds clears that with room and still keeps a fully expired
/// [`settle`] budget under half a second.
const SETTLE_ROUND_SLICE: Duration = Duration::from_millis(2);

/// Scales the real-clock slice below, sharing the workspace's timing knob with
/// the real-kernel suites. Instrumented builds (the sanitizer lanes set this)
/// slow a thread's spawn and its teardown work several fold while a fixed
/// wall-clock slice does not stretch to match, so the same budget that is
/// generous natively becomes marginal there. Unset it is 1 and nothing changes.
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

/// Gives the blocking pool and the driver's teardown reaper real-clock scheduler
/// slices under paused time, and REPORTS whether `done` was ever observed true.
///
/// A caller that STAGES an edge — a hold captured, a batch parked, a mailbox
/// saturated — must assert the verdict. An expired budget is otherwise
/// indistinguishable from a satisfied one, so the staging silently degrades to
/// whatever the driver happened to be doing and the cell passes through a weaker
/// path than the one it names. A caller whose own next assertion re-reads the
/// same observable may discard it: that assertion IS the check.
async fn settle(done: impl FnMut() -> bool) -> bool {
  settle_within(200, done).await
}

/// The same wait, in the round budget an INTERPRETER needs for it.
///
/// A round is a fixed slice of real time and stays one under an interpreter.
/// What changes is the distance to the observable: a gate waiting on a command
/// the driver only reaches after chewing through a mailbox of wide reconciles is
/// waiting on microseconds of instructions and minutes of interpretation, while
/// its rounds still tick at their own fixed rate. So the round COUNT is the side
/// that has to grow.
///
/// This can neither cost a passing run nor hide a failing one. A budget is spent
/// to the end only when it EXPIRES, which is already a staging failure; and every
/// condition waited on here is eventually-true, so a longer wait can only prevent
/// a spurious failure, never mask a defect — the same reasoning that lets a
/// caller choose a wider budget natively. A caller that reads the verdict as a
/// NEGATIVE — proof that something has not happened — is strengthened by it, not
/// weakened.
fn interpreted_rounds(rounds: usize) -> usize {
  if cfg!(miri) { rounds * 4 } else { rounds }
}

/// The wall-clock ceiling a `timeout` gets when the work it bounds is INTERPRETED
/// rather than executed.
///
/// [`interpreted_rounds`] rescues the budgets counted in ROUNDS, and those need
/// only a wider count because a round costs whatever a round costs. A `timeout`
/// is denominated in wall clock and cannot stretch itself: the driver reply that
/// resolves in milliseconds natively takes seconds under an interpreter, a cell
/// that awaits a whole cohort of them waits out every one, and the clock ticks at
/// its own fixed rate throughout. Measured under the interpreter on a fast host,
/// the tightest of these waits already spends three quarters of its native
/// budget, which leaves it no margin at all on a host that is merely ordinary.
///
/// One flat ceiling rather than a per-site multiple, because there is nothing
/// here to tune: a deadline is only ever SPENT when the cell is already failing,
/// so sizing it far above the measured need costs a passing run nothing. What it
/// does cost is the failure mode — a cell that genuinely hangs burns this before
/// it reports — which is why it is minutes rather than hours, with the job's own
/// `timeout-minutes` as the outer bound behind it.
const INTERPRETED_DEADLINE: Duration = Duration::from_secs(900);

/// A whole-second `timeout` budget, in the wall clock an INTERPRETER needs for it.
///
/// Every seconds-denominated deadline in this suite bounds a POSITIVE wait: its
/// result is `.expect`ed or asserted `is_ok`, so expiry is the cell's own failure
/// and a wider budget can only prevent a spurious one — the same reasoning that
/// lets a caller pick a wider budget natively. That is why the widening is
/// blanket rather than a per-site judgement. (One site drains a reply whose
/// result it never reads; there a wider budget can only spend time the cell did
/// not need, and the interpreted run measures that it does not.)
///
/// The sub-second budgets are deliberately NOT routed through here, and the
/// difference is one of kind rather than degree. Each of those is a drain loop or
/// a negative assertion — "and nothing else arrives", "keep taking while events
/// keep coming" — where the budget EXPIRING is the observation the cell is
/// making. Widening one would change what its cell proves, not how long it waits
/// to prove it.
///
/// # An INSTRUMENTED build is native, and needed the same widening
///
/// `cfg!(miri)` is two-valued and this axis is not. A sanitizer build runs native
/// code — so it took the `native` arm — while ASan and TSan slow the runtime
/// several fold and the real clock keeps its pace, which is the same ratio the
/// interpreted arm exists for. That is what took the tsan lane red on a POSITIVE
/// wait (`the driver dies rather than replying: Elapsed`) with nothing wrong but
/// the budget. [`timing_scale`] is the knob that DOES express it — the workspace
/// sets it per instrument, 6 for ASan/LSan/MSan and 12 for TSan, 1 unset — and
/// scaling by it here changes nothing on an ordinary native run while giving the
/// instrumented one exactly the proportional room the blanket argument above
/// already licenses.
fn interpreted_secs(native: u64) -> Duration {
  if cfg!(miri) {
    INTERPRETED_DEADLINE
  } else {
    Duration::from_secs(native) * timing_scale()
  }
}

/// [`settle`] with a caller-chosen budget: staging under a fully loaded parallel
/// suite can legitimately need longer than the shared 2 s, and every condition
/// waited on here is eventually-true, so a longer wait can never mask a failure
/// — only prevent a spurious one. The verdict is `#[must_use]`, because a
/// caller reaching for an explicit budget is staging.
///
/// # Why a round costs REAL time under a paused clock
///
/// These cells run on a current-thread runtime with `start_paused = true`, so
/// the driver task and the test share one thread and the virtual sleep below
/// hands the driver its next timer at no wall-clock cost. That covers everything
/// the runtime schedules — and stops exactly there. A stream teardown runs on
/// the driver's teardown reaper, an ordinary OS thread no runtime clock governs,
/// and while this task is inside an `await` the runtime, not that thread, is on
/// the CPU. A round therefore splits in two: the awaits let the driver reach the
/// point where it hands work off, and [`SETTLE_ROUND_SLICE`] of real sleep is
/// the window in which the thread it handed to can run.
///
/// That window is what a predicate reading an off-runtime observable is
/// actually waiting on, and more rounds cannot substitute for a wider one — the
/// loop returns as soon as `done` holds, so an observable published a beat after
/// the one this predicate names has only the CURRENT round's slice to land in.
///
/// This used to be implicit: while teardowns ran on the blocking pool, an
/// outstanding `spawn_blocking` inhibited the paused clock's auto-advance, so
/// the virtual sleep could not return until the pool went quiet and every round
/// silently waited on real progress. Off the pool the runtime sees itself idle,
/// auto-advances, and the budget collapses to nothing unless the slice is spent
/// deliberately.
#[must_use = "an expired settle budget is a staging failure unless the caller's own next assertion re-reads the same observable"]
async fn settle_within(rounds: usize, mut done: impl FnMut() -> bool) -> bool {
  for _ in 0..interpreted_rounds(rounds) {
    if done() {
      return true;
    }
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    std::thread::sleep(settle_round_slice());
  }
  // The last round's sleep is part of the budget: read the predicate once more
  // so a condition that landed inside it reports as met, never as expired.
  done()
}

#[tokio::test(start_paused = true)]
async fn watch_spawns_a_stream_and_events_flow() {
  let rig = rig_with_capacity(64);
  let scope = watch(&rig, "/r").await;

  rig
    .fs
    .send_batch("/r", vec![ev("/r/a/new.txt", created(), 1, 10)]);

  let (got_scope, change) = next_event(&rig).await;
  assert_eq!(got_scope, scope);
  assert!(change.kind().is_created());
  assert_eq!(change.location(), &loc(&["a", "new.txt"]));
}

#[tokio::test(start_paused = true)]
async fn cross_batch_rename_degrades_to_remove_plus_create() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;

  // Source half: the path is already gone. A vanished path has no
  // contemporaneous device evidence and no same-batch partner, so it never
  // mints a cookie — the documented cross-batch pairing cost.
  rig.fs.remove("/r/a/old");
  rig
    .fs
    .send_batch("/r", vec![ev("/r/a/old", renamed(), 10, 42)]);
  let (_, change) = next_event(&rig).await;
  assert!(change.kind().is_removed());
  assert_eq!(change.location(), &loc(&["a", "old"]));

  // Destination half in a later batch: the path exists, finds no pending
  // source, and arrives as a fresh object.
  rig.fs.put("/r/b/new", FileKind::File, 42);
  rig
    .fs
    .send_batch("/r", vec![ev("/r/b/new", renamed(), 11, 42)]);
  let (_, change) = next_event(&rig).await;
  assert!(change.kind().is_created());
  assert_eq!(change.location(), &loc(&["b", "new"]));
}

#[tokio::test(start_paused = true)]
async fn unpaired_source_half_expires_to_removed() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;
  rig.fs.remove("/r/a/left");
  rig
    .fs
    .send_batch("/r", vec![ev("/r/a/left", renamed(), 10, 7)]);

  // No cookie, no pairing window: the vanished half resolves immediately.
  let (_, change) = next_event(&rig).await;
  assert!(change.kind().is_removed());
  assert_eq!(change.location(), &loc(&["a", "left"]));
}

#[tokio::test(start_paused = true)]
async fn overflow_message_becomes_one_epoch_bumped_rescan() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;

  rig.fs.send_batch("/r", vec![ev("/r/x", created(), 1, 3)]);
  let (_, first) = next_event(&rig).await;

  rig.fs.send_lossy("/r");
  let (_, rescan) = next_event(&rig).await;
  assert!(rescan.kind().is_rescan());
  assert!(rescan.epoch() > first.epoch());
  // The driver dropped the message's ack, re-arming the source's dedup.
  settle(|| !rig.fs.overflow_pending("/r")).await;
  assert!(!rig.fs.overflow_pending("/r"));
}

#[tokio::test(start_paused = true)]
async fn lagged_consumer_gets_the_dominating_rescan() {
  let rig = rig_with_capacity(1);
  let _scope = watch(&rig, "/r").await;

  for (id, name) in [(1u64, "/r/a"), (2, "/r/b"), (3, "/r/c")] {
    rig.fs.send_batch("/r", vec![ev(name, created(), id, id)]);
  }
  // Let the driver churn: the first change fills the capacity-1 channel, the
  // rest refuse and park a dominating Rescan.
  tokio::time::sleep(Duration::from_millis(500)).await;

  let (_, first) = next_event(&rig).await;
  assert!(first.kind().is_created());
  let (_, second) = next_event(&rig).await;
  assert!(
    second.kind().is_rescan(),
    "everything dropped while lagged is covered by the parked Rescan"
  );
  assert!(second.epoch() > first.epoch());
  // The dropped ordinary events are covered, never replayed: nothing may
  // arrive after the Rescan that was produced before it.
  let third = tokio::time::timeout(Duration::from_millis(200), rig.events.recv()).await;
  assert!(
    third.is_err(),
    "an ordinary event escaped past its dominating Rescan: {third:?}"
  );
}

#[tokio::test(start_paused = true)]
async fn fatal_source_rescans_and_tears_down() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;
  rig.fs.send_fatal("/r");

  let (_, change) = next_event(&rig).await;
  assert!(change.kind().is_rescan());
  settle(|| rig.fs.shutdowns() == 1).await;
  assert_eq!(rig.fs.shutdowns(), 1, "the dead stream is torn down");
}

#[tokio::test(start_paused = true)]
async fn close_tears_down_every_stream_and_ends_the_event_stream() {
  let rig = rig_with_capacity(64);
  let fs = rig.fs.clone();
  fs.put("/s", FileKind::Dir, 2);
  let _one = watch(&rig, "/r").await;
  let _two = watch(&rig, "/s").await;

  let (reply, on_reply) = futures_channel::oneshot::channel();
  rig.commands.send(Command::Close { reply }).await.unwrap();
  on_reply.await.unwrap();
  assert_eq!(fs.shutdowns(), 2, "every stream quiesced");
  assert!(
    rig.events.recv().await.is_err(),
    "the event stream ends after close"
  );
}

#[tokio::test(start_paused = true)]
async fn unwatch_stops_one_root_and_replies() {
  let rig = rig_with_capacity(64);
  let scope = watch(&rig, "/r").await;

  let (reply, on_reply) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Unwatch {
      scope,
      reply: Some(reply),
    })
    .await
    .unwrap();
  assert!(on_reply.await.unwrap().is_torn(), "the scope existed");
  assert_eq!(rig.fs.shutdowns(), 1);
}

#[tokio::test(start_paused = true)]
async fn watch_of_a_missing_root_fails_typed() {
  let rig = rig_with_capacity(64);
  let (reply, on_reply) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Watch {
      root: PathBuf::from("/absent"),
      interest: tributary_proto::Interest::all(),
      reply,
    })
    .await
    .unwrap();
  let err = on_reply.await.unwrap().unwrap_err();
  assert!(matches!(
    err,
    WatchRootError::Source(SourceError::RootUnavailable { .. })
  ));
}

/// The queue is the source's one ordered lane: batches enqueued BEFORE a loss
/// signal deliver before the Rescan it becomes, and nothing from them may
/// follow it — ordering by construction, no drain, no barrier.
#[tokio::test(start_paused = true)]
async fn queued_data_delivers_before_a_later_loss_signal() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;

  for (id, name) in [(1u64, "/r/a"), (2, "/r/b"), (3, "/r/c")] {
    rig.fs.send_batch("/r", vec![ev(name, created(), id, id)]);
  }
  rig.fs.send_lossy("/r");

  let mut seen = Vec::new();
  while let Ok(Ok((_, _, change))) =
    tokio::time::timeout(Duration::from_millis(300), rig.events.recv()).await
  {
    seen.push(change);
  }
  let names: Vec<String> = seen
    .iter()
    .map(|c| {
      if c.kind().is_rescan() {
        "rescan".to_string()
      } else {
        c.location()
          .name()
          .map(|s| s.as_str().to_string())
          .unwrap_or_default()
      }
    })
    .collect();
  assert_eq!(
    names,
    ["a", "b", "c", "rescan"],
    "queued data precedes the loss signal, in source order"
  );
}

/// Same ordering pin for the terminal signal: batches before the Fatal
/// deliver, then the terminal Rescan, then teardown.
#[tokio::test(start_paused = true)]
async fn fatal_follows_queued_data_in_order() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;

  for (id, name) in [(1u64, "/r/a"), (2, "/r/b")] {
    rig.fs.send_batch("/r", vec![ev(name, created(), id, id)]);
  }
  rig.fs.send_fatal("/r");

  let mut seen = Vec::new();
  while let Ok(Ok((_, _, change))) =
    tokio::time::timeout(Duration::from_millis(300), rig.events.recv()).await
  {
    seen.push(change);
  }
  assert!(
    seen.len() >= 3 && seen[0].kind().is_created() && seen[1].kind().is_created(),
    "data queued before the death delivers first: {seen:?}"
  );
  assert!(
    seen[2..].iter().all(|c| c.kind().is_rescan()),
    "the terminal Rescan follows in order: {seen:?}"
  );
  settle(|| rig.fs.shutdowns() == 1).await;
  assert_eq!(rig.fs.shutdowns(), 1, "the dead stream is torn down");
}

/// The in-band Fatal needs no data traffic to wake the driver: the queue IS
/// the wake.
#[tokio::test(start_paused = true)]
async fn fatal_wakes_the_driver_with_no_data_traffic() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;
  rig.fs.send_fatal("/r");

  let (_, change) = next_event(&rig).await;
  assert!(
    change.kind().is_rescan(),
    "the in-band death surfaces as the terminal Rescan"
  );
  settle(|| rig.fs.shutdowns() == 1).await;
  assert_eq!(rig.fs.shutdowns(), 1);
}

#[tokio::test(start_paused = true)]
async fn orphaned_watch_reply_tears_the_stream_down() {
  let rig = rig_with_capacity(64);

  // The watch() future was cancelled: its reply receiver is gone before the
  // spawn completes. The driver must not leave the fresh stream unowned.
  let (reply, on_reply) = futures_channel::oneshot::channel();
  drop(on_reply);
  rig
    .commands
    .send(Command::Watch {
      root: PathBuf::from("/r"),
      interest: tributary_proto::Interest::all(),
      reply,
    })
    .await
    .unwrap();

  settle(|| rig.fs.shutdowns() == 1).await;
  assert_eq!(
    rig.fs.shutdowns(),
    1,
    "an unowned stream is torn down immediately"
  );
}

#[tokio::test(start_paused = true)]
async fn disconnected_source_is_a_dead_stream() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;

  // The source's sender vanishes without a Fatal — the receiver disconnect
  // itself must be treated as the death signal.
  rig.fs.disconnect("/r");

  let (_, change) = next_event(&rig).await;
  assert!(change.kind().is_rescan());
  settle(|| rig.fs.shutdowns() == 1).await;
  assert_eq!(rig.fs.shutdowns(), 1);
}

#[tokio::test(start_paused = true)]
async fn lagged_root_death_delivers_the_terminal_rescan() {
  let rig = rig_with_capacity(1);
  let _scope = watch(&rig, "/r").await;

  // The first change fills the capacity-1 channel; the second refusal parks
  // a dominating Rescan while the channel is still full.
  for (id, name) in [(1u64, "/r/a"), (2, "/r/b")] {
    rig.fs.send_batch("/r", vec![ev(name, created(), id, id)]);
  }
  tokio::time::sleep(Duration::from_millis(100)).await;

  // The root dies while the scope is lagged and the channel is full: the
  // terminal Rescan must survive every refusal and land once the consumer
  // finally drains.
  rig.fs.disconnect("/r");
  tokio::time::sleep(Duration::from_millis(500)).await;

  let (_, first) = next_event(&rig).await;
  assert!(first.kind().is_created());
  let (_, second) = next_event(&rig).await;
  assert!(
    second.kind().is_rescan(),
    "the terminal Rescan is never lost: {second:?}"
  );
  assert!(second.epoch() > first.epoch());
  settle(|| rig.fs.shutdowns() == 1).await;
  assert_eq!(rig.fs.shutdowns(), 1, "the dead stream is torn down");
}

#[tokio::test(start_paused = true)]
async fn uncommitted_watch_grant_unwinds_the_stream() {
  let rig = rig_with_capacity(64);

  // The reply receiver stays ALIVE while the driver spawns the stream and
  // sends the grant — then drops without ever being polled, the shape of a
  // watch() future cancelled after the reply landed. The unread grant must
  // unwind the stream it owns.
  let (reply, on_reply) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Watch {
      root: PathBuf::from("/r"),
      interest: tributary_proto::Interest::all(),
      reply,
    })
    .await
    .unwrap();
  settle(|| rig.fs.spawns() == 1).await;
  for _ in 0..50 {
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  drop(on_reply);

  settle(|| rig.fs.shutdowns() == 1).await;
  assert_eq!(
    rig.fs.shutdowns(),
    1,
    "a delivered-but-never-polled grant unwinds its stream"
  );
}

#[tokio::test(start_paused = true)]
async fn overflow_refreshes_mount_trust_and_pairing_resumes() {
  let rig = rig_with_capacity(64);
  let _scope = watch(&rig, "/r").await;

  assert_eq!(rig.fs.refreshes(), 1, "the birth refresh already ran");
  rig.fs.send_lossy("/r");
  let (_, rescan) = next_event(&rig).await;
  assert!(rescan.kind().is_rescan());

  // The loss revoked device trust and requested a mount-table refresh from
  // the blocking pool. That pool runs on REAL threads outside the paused
  // runtime, so the wait must be bounded by the real clock.
  let deadline = std::time::Instant::now() + Duration::from_secs(10);
  while rig.fs.refreshes() < 2 && std::time::Instant::now() < deadline {
    tokio::task::yield_now().await;
  }
  assert_eq!(
    rig.fs.refreshes(),
    2,
    "one refresh per loss, coalesced, on top of the birth refresh"
  );

  // With the refreshed table installed, a same-batch rename pair grounds
  // into a single Moved again — trust round-tripped end to end.
  rig.fs.remove("/r/a/old");
  rig.fs.put("/r/b/new", FileKind::File, 42);
  rig.fs.send_batch(
    "/r",
    vec![
      ev("/r/a/old", renamed(), 10, 42),
      ev("/r/b/new", renamed(), 11, 42),
    ],
  );
  let (_, change) = next_event(&rig).await;
  assert_eq!(change.kind().moved_from(), Some(&loc(&["a", "old"])));
  assert_eq!(change.location(), &loc(&["b", "new"]));
}

/// Root-death via the refresh path (design §7 gap, closed by L4.2): a refresh
/// whose folded-in root re-stat finds the root GONE lowers the death lifecycle
/// end to end — the terminal `Rescan` is delivered and the driver reclaims the
/// registry entry — with no new timer or effect (the loss-armed refresh is the
/// same one mount trust rides). The kernel-recursive backends' only unmount
/// detection.
#[tokio::test(start_paused = true)]
async fn refresh_finding_root_gone_dies_end_to_end() {
  let registry = RecordingRegistry::default();
  let rig = rig_with(64, registry.clone());
  let scope = watch(&rig, "/r").await;
  assert_eq!(rig.fs.refreshes(), 1, "the birth refresh already ran");

  // Arm the next refresh to report the root GONE, then induce the loss path
  // that runs it (the loss revokes trust and arms one refresh).
  rig.fs.set_root_liveness(RootLiveness::Missing);
  rig.fs.send_lossy("/r");

  // The loss itself yields the standing Rescan; the refresh-detected death then
  // ends the scope with its terminal Rescan and reclaims the entry.
  //
  // BOTH observables are waited on, and on an explicit budget. Each is published
  // OFF the runtime — the reclamation and the teardown both land on the driver's
  // teardown reaper, an ordinary OS thread the paused clock does not govern — so
  // what the wait actually spends is [`SETTLE_ROUND_SLICE`] of real time per
  // round, and the shared 200-round default is not enough of it on a loaded host.
  // Observed: one failure in four consecutive runs of this suite while a Miri
  // shard and a container suite shared the machine, reported at the reclamation
  // assertion below. Every condition here is eventually-true, so a wider budget
  // can only prevent a spurious failure, never mask a real one — and waiting on
  // the shutdown too stops the second assertion from reading an observable the
  // first one's wait never covered.
  assert!(
    settle_within(1000, || registry.dead() == [scope]
      && rig.fs.shutdowns() == 1)
    .await,
    "the refresh-detected death reclaimed the registry entry and tore the stream down"
  );
  assert_eq!(
    registry.dead(),
    [scope],
    "the refresh-detected death reclaimed the registry entry"
  );
  assert_eq!(
    rig.fs.shutdowns(),
    1,
    "the dead root's stream was torn down"
  );
}

/// The refresh samples the root's identity AND its mount frame from ONE object, so
/// a replaced/re-mounted root can never pair the OLD identity's verdict with a NEW
/// object's frame (the mixed sample the atomic `statx` restructure closes). The fake
/// now reads both from one node, making the mix unrepresentable: after
/// `replace_root_node` swaps the object at the root path, the refresh reports the
/// REPLACED identity together with the replacement's frame — a matched pair, never a
/// mix.
#[tokio::test]
async fn refresh_pairs_the_replaced_identity_with_its_own_frame() {
  let fs = FakeFs::with_root_mnt_id(1, 42);
  fs.put("/r", FileKind::Dir, 1);

  // Baseline: the original root (ino 1) on mount 42 — identity and frame paired.
  let before = fs.refresh_mounts(Path::new("/r"));
  assert_eq!(
    before.root,
    RootLiveness::Present(RootIdentity::new(1, 1)),
    "the original root samples its own identity"
  );
  assert_eq!(
    before.root_mnt_id,
    Some(42),
    "the original root samples its own frame (42) from the same node"
  );

  // A replace/remount at the path: a DIFFERENT object (ino 2) on a DIFFERENT mount
  // (77). The single-node read pairs THIS identity with THIS frame — the fake cannot
  // emit ino-1's "matching" verdict beside mount-77's frame.
  fs.replace_root_node("/r", 2, Some(77));
  let after = fs.refresh_mounts(Path::new("/r"));
  assert_eq!(
    after.root,
    RootLiveness::Present(RootIdentity::new(1, 2)),
    "the replaced root reports the REPLACED identity (ino 2), not the old one"
  );
  assert_eq!(
    after.root_mnt_id,
    Some(77),
    "the replaced root's frame (77) is paired with its OWN identity — never a mix with \
     the old identity's verdict"
  );
}

/// Every delivery carries the canonical root it assembles under, so the
/// consumer never needs a registry entry — a reclaimed scope's trailing
/// changes still name their absolute paths.
#[tokio::test(start_paused = true)]
async fn deliveries_carry_the_canonical_root() {
  let rig = rig_with_capacity(64);
  let scope = watch(&rig, "/r").await;

  rig
    .fs
    .send_batch("/r", vec![ev("/r/carried.txt", created(), 1, 10)]);

  let (got_scope, root, change) = tokio::time::timeout(interpreted_secs(5), rig.events.recv())
    .await
    .expect("an event arrives")
    .expect("the stream is open");
  assert_eq!(got_scope, scope);
  assert_eq!(root.as_path(), Path::new("/r"));
  assert!(change.kind().is_created());
}

/// The single-writer lifecycle contract: the driver records a scope live
/// (before its grant can reach the watcher) and dead (once per teardown), in
/// program order on one task.
#[tokio::test(start_paused = true)]
async fn registry_sees_live_then_dead_in_order() {
  let registry = RecordingRegistry::default();
  let rig = rig_with(64, registry.clone());

  let scope = watch(&rig, "/r").await;
  assert_eq!(
    registry.live(),
    [(scope, PathBuf::from("/r"), BackendKind::FsEvents)],
    "the entry was live before the grant resolved"
  );

  let (reply, on_reply) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Unwatch {
      scope,
      reply: Some(reply),
    })
    .await
    .unwrap();
  assert!(on_reply.await.unwrap().is_torn(), "the unwatch resolves");
  assert_eq!(
    registry.dead(),
    [scope],
    "exactly one scope-dead signal, naming the dead scope"
  );
}

/// Driver-level: the source dies AFTER the grant was sent but BEFORE the
/// caller polls it. Both registry transitions ran on the driver in order
/// (live, then dead); the late commit just yields a dead-on-arrival handle,
/// and the path is immediately re-watchable.
#[tokio::test(start_paused = true)]
async fn death_between_grant_send_and_poll_leaves_a_consistent_registry() {
  let registry = RecordingRegistry::default();
  let rig = rig_with(64, registry.clone());

  let (reply, on_reply) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Watch {
      root: PathBuf::from("/r"),
      interest: tributary_proto::Interest::all(),
      reply,
    })
    .await
    .unwrap();
  // The grant resolves — the registry entry is already live.
  let grant = on_reply.await.unwrap().expect("watch succeeds");
  let scope = grant.scope();
  assert_eq!(
    registry.live(),
    [(scope, PathBuf::from("/r"), BackendKind::FsEvents)]
  );

  // The source dies before the caller "polls" (commits) the grant.
  rig.fs.disconnect("/r");
  settle(|| registry.dead() == [scope]).await;
  assert_eq!(registry.dead(), [scope], "the driver reclaimed the entry");
  assert_eq!(rig.fs.shutdowns(), 1);

  // The late commit is a dead-on-arrival handle; nothing unwinds twice.
  grant.defuse();
  settle(|| rig.fs.shutdowns() == 1).await;
  assert_eq!(rig.fs.shutdowns(), 1, "no double teardown");

  // The path is free: a fresh watch succeeds.
  let scope2 = watch(&rig, "/r").await;
  assert_ne!(scope2, scope, "a fresh scope for the re-watch");
}

fn xorshift(s: &mut u64) -> u64 {
  *s ^= *s << 13;
  *s ^= *s >> 17;
  *s ^= *s << 5;
  *s
}

/// The standing end-to-end no-silent-loss storm — the one property every
/// historical finding violated: under random mutations, decode losses, budget
/// pressure, and a lagging consumer, the view reconstructed from delivered
/// events (honoring Rescans as re-reads) converges to the tree, with
/// per-scope epochs monotone. `TRIBUTARY_FS_STORM_SEEDS` scales the seed
/// count (64 in CI; run 1024 nightly).
///
/// Under miri the default drops to ONE seed: miri never reuses an address, so
/// 64 seeds' worth of path and tree churn exhausts a 32-bit target's whole
/// address space (i686 dies with "no more free addresses"). Miri is here to
/// find UB, and one seed drives every code path the others do — the
/// statistical convergence coverage is the native runs' job, where the full
/// seed count still runs.
#[tokio::test(start_paused = true)]
async fn storm_no_silent_loss_converges() {
  let default_seeds: u64 = if cfg!(miri) { 1 } else { 64 };
  let seeds: u64 = std::env::var("TRIBUTARY_FS_STORM_SEEDS")
    .ok()
    .and_then(|v| v.parse().ok())
    .unwrap_or(default_seeds);
  for seed in 1..=seeds {
    storm_seed(seed).await;
  }
}

async fn storm_seed(seed: u64) {
  let rig = rig_with_capacity(4);
  rig.fs.put("/r/w", FileKind::Dir, 2);
  let scope = watch(&rig, "/r/w").await;
  let mut s = seed.wrapping_mul(0x9E37_79B9).wrapping_add(1);
  let mut next_ino = 100u64;
  let mut next_id = 1u64;
  let mut live: Vec<(PathBuf, u64)> = Vec::new();
  let mut view: BTreeSet<PathBuf> = BTreeSet::new();
  let mut last_epoch: Option<Epoch> = None;
  let mut last_root: Option<PathBuf> = None;
  let mut current_root = PathBuf::from("/r/w");

  for _ in 0..30 {
    // The replace perturbation: ~1/8 of iterations swap the root between
    // /r/w and /r (widen, then occasionally back). Convergence and epoch
    // order must survive the swap; the commit Rescan re-reads the world.
    if xorshift(&mut s).is_multiple_of(8) {
      let target = if current_root == Path::new("/r/w") {
        PathBuf::from("/r")
      } else {
        PathBuf::from("/r/w")
      };
      let (reply, mut on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: target.clone(),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(target.clone()),
          reply,
        })
        .await
        .unwrap();
      // Keep the pipe draining while the swap settles: the commit Rescan
      // must never deadlock against a full consumer channel.
      let outcome = loop {
        match tokio::time::timeout(Duration::from_millis(50), &mut on_reply).await {
          Ok(res) => break res.expect("driver replies"),
          Err(_) => {
            if let Ok(Ok((_, root, change))) =
              tokio::time::timeout(Duration::from_millis(10), rig.events.recv()).await
            {
              apply(
                &rig,
                &mut view,
                &mut last_epoch,
                &mut last_root,
                &root,
                &change,
              );
            }
          }
        }
      };
      assert!(
        outcome.is_ok(),
        "seed {seed}: the storm swap commits: {outcome:?}"
      );
      current_root = target;
      // The storm's own mutation pool narrows with the coverage; the VIEW
      // re-bases only when the consumer OBSERVES the flip (in `apply`).
      live.retain(|(p, _)| p.starts_with(&current_root));
      continue;
    }
    let mut events = Vec::new();
    match xorshift(&mut s) % 4 {
      0 | 1 => {
        next_ino += 1;
        let path = current_root.join(format!("f{next_ino}"));
        rig.fs.put(&path, FileKind::File, next_ino);
        next_id += 1;
        events.push(ev(path.to_str().unwrap(), created(), next_id, next_ino));
        live.push((path, next_ino));
      }
      2 if !live.is_empty() => {
        let i = (xorshift(&mut s) as usize) % live.len();
        let (path, ino) = live.swap_remove(i);
        rig.fs.remove(&path);
        next_id += 1;
        events.push(ev(path.to_str().unwrap(), removed(), next_id, ino));
      }
      3 if !live.is_empty() => {
        let i = (xorshift(&mut s) as usize) % live.len();
        let (old, ino) = live.swap_remove(i);
        next_ino += 1;
        let new = current_root.join(format!("g{next_ino}"));
        rig.fs.remove(&old);
        rig.fs.put(&new, FileKind::File, ino);
        next_id += 1;
        events.push(ev(old.to_str().unwrap(), renamed(), next_id, ino));
        next_id += 1;
        events.push(ev(new.to_str().unwrap(), renamed(), next_id, ino));
        live.push((new, ino));
      }
      _ => continue,
    }
    // Perturb: one in six batches is lost at decode — the mutation happened,
    // only its report vanished, and the in-order loss signal must cover it.
    if xorshift(&mut s).is_multiple_of(6) {
      rig.fs.send_lossy(&current_root);
    } else {
      rig.fs.send_batch(&current_root, events);
    }
    // A sometimes-lagging consumer: drain a few events only occasionally.
    if xorshift(&mut s).is_multiple_of(3) {
      for _ in 0..(xorshift(&mut s) % 4) {
        match tokio::time::timeout(Duration::from_millis(100), rig.events.recv()).await {
          Ok(Ok((_, root, change))) => {
            apply(
              &rig,
              &mut view,
              &mut last_epoch,
              &mut last_root,
              &root,
              &change,
            );
          }
          _ => break,
        }
      }
    }
  }

  // Mutations stop; give pairing windows and probes time, then drain to
  // quiescence.
  for _ in 0..50 {
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(20)).await;
  }
  while let Ok(Ok((_, root, change))) =
    tokio::time::timeout(Duration::from_millis(300), rig.events.recv()).await
  {
    apply(
      &rig,
      &mut view,
      &mut last_epoch,
      &mut last_root,
      &root,
      &change,
    );
  }

  let tree = rig.fs.files_under(&current_root);
  assert_eq!(
    view, tree,
    "seed {seed}: the reconstructed view converges to the tree under {current_root:?}"
  );
}

fn apply(
  rig: &Rig,
  view: &mut BTreeSet<PathBuf>,
  last_epoch: &mut Option<Epoch>,
  last_root: &mut Option<PathBuf>,
  root: &Path,
  change: &Change,
) {
  // A delivery-root flip IS the observable root replacement: re-base the
  // view to the new coverage. In-order delivery makes this exact — the
  // lane gate guarantees no old-world delivery can follow the commit
  // Rescan, so the flip happens at the world boundary.
  if last_root.as_deref() != Some(root) {
    if last_root.is_some() {
      view.retain(|p| p.starts_with(root));
    }
    *last_root = Some(root.to_path_buf());
  }
  if let Some(prev) = *last_epoch {
    assert!(
      change.epoch() >= prev,
      "per-scope epochs are monotone: {prev:?} then {:?}",
      change.epoch()
    );
  }
  *last_epoch = Some(change.epoch());
  let abs = |l: &Location| {
    let mut p = root.to_path_buf();
    for seg in l.segments() {
      p.push(seg.as_str());
    }
    p
  };
  match change.kind() {
    tributary_proto::ChangeKind::Created => {
      view.insert(abs(change.location()));
    }
    tributary_proto::ChangeKind::Removed => {
      view.remove(&abs(change.location()));
    }
    tributary_proto::ChangeKind::Moved(from) => {
      view.remove(&abs(from));
      view.insert(abs(change.location()));
    }
    tributary_proto::ChangeKind::Modified => {}
    tributary_proto::ChangeKind::Rescan => {
      // A delivered Rescan is a re-read of current state under its location.
      let at = abs(change.location());
      view.retain(|p| !p.starts_with(&at));
      view.extend(rig.fs.files_under(&at));
    }
    _ => {}
  }
}

/// The spawn contract's full observable order: a source's `RootMeta` is
/// sealed strictly BEFORE its stream can enqueue an event (trust-bearing
/// metadata can never postdate a message on the queue), and the root is
/// revalidated strictly AFTER the stream is live — the identity bracket's
/// post-live half — before the spawn returns. A regression that seeds after
/// liveness, or commits without revalidating, fails here.
#[tokio::test(start_paused = true)]
async fn spawn_seals_root_meta_before_the_stream_goes_live() {
  let rig = rig_with_capacity(64);
  watch(&rig, "/r").await;
  assert_eq!(
    rig.fs.spawn_order(),
    vec!["meta_sealed", "stream_live", "root_revalidated"],
    "the metadata barrier precedes liveness; the identity bracket follows it"
  );
}

/// A submount present at spawn lands in the pre-start seed and vetoes trust
/// for its whole prefix from the first event on — even if the volume vanishes
/// immediately after (its unmount travels in-band and is applied late, per
/// the monotone rule); nothing can event before the seed exists.
#[tokio::test(start_paused = true)]
async fn spawn_seed_carries_a_preexisting_submount() {
  let fs = FakeFs::new(1);
  fs.put("/r", FileKind::Dir, 1);
  fs.seed_mounts(vec![bare_mount("/r/vol")]);
  let (cmd_tx, cmd_rx) = async_channel::bounded(16);
  let (cleanup, cookie_wake) = cookie_ingress();
  let (ev_tx, ev_rx) = async_channel::bounded(64);
  tokio::spawn(run::<TokioRuntime, FakeFs>(
    config(),
    fs.clone(),
    cmd_rx,
    cookie_wake,
    ev_tx,
    NullRegistry,
  ));
  let rig = Rig {
    fs,
    commands: cmd_tx,
    cleanup,
    events: ev_rx,
  };
  watch(&rig, "/r").await;

  // A colliding same-fileID rename pair spanning the seeded submount: the
  // foreign half's prefix is vetoed by the seed, so no Moved can fabricate.
  rig.fs.put("/r/dst", FileKind::File, 7);
  rig.fs.send_batch(
    "/r",
    vec![
      ev("/r/vol/src", renamed(), 10, 7),
      ev("/r/dst", renamed(), 11, 7),
    ],
  );
  let (_, change) = next_event(&rig).await;
  assert!(
    !change.kind().is_moved(),
    "a seeded foreign prefix never pairs: {change:?}"
  );
}

/// A spawn already dispatched to the blocking pool is invisible to `handles`;
/// close must hold its reply until the late stream is torn down inside the
/// close accounting. Real time: the ~1 s grace must not fire before the
/// pending-spawn check is exercised.
#[tokio::test]
async fn close_waits_for_an_in_flight_spawn_and_tears_it_down() {
  let rig = rig_with_capacity(64);
  let gate = rig.fs.hold_spawns();

  // A watch whose future is cancelled right after the command is sent: the
  // spawn is in flight with nobody left to take ownership.
  let (reply, on_reply) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Watch {
      root: PathBuf::from("/r"),
      interest: tributary_proto::Interest::all(),
      reply,
    })
    .await
    .unwrap();
  drop(on_reply);

  let (close_reply, mut on_close) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Close { reply: close_reply })
    .await
    .unwrap();

  tokio::time::sleep(Duration::from_millis(50)).await;
  assert!(
    (&mut on_close).now_or_never().is_none(),
    "close must wait for the in-flight spawn"
  );

  gate.release();
  tokio::time::timeout(interpreted_secs(5), on_close)
    .await
    .expect("close resolves once the late spawn settles")
    .expect("the driver confirms the close");
  assert_eq!(rig.fs.spawns(), 1, "the late spawn completed");
  assert_eq!(
    rig.fs.shutdowns(),
    1,
    "the late stream was torn down inside the close accounting"
  );
}

/// The failed twin: a spawn racing close that returns an error just settles
/// its accounting slot — close resolves with no stream ever live.
#[tokio::test]
async fn close_settles_an_in_flight_spawn_failure() {
  let rig = rig_with_capacity(64);
  let gate = rig.fs.hold_spawns();

  let (reply, on_reply) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Watch {
      root: PathBuf::from("/r"),
      interest: tributary_proto::Interest::all(),
      reply,
    })
    .await
    .unwrap();
  drop(on_reply);

  let (close_reply, mut on_close) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Close { reply: close_reply })
    .await
    .unwrap();

  tokio::time::sleep(Duration::from_millis(50)).await;
  assert!(
    (&mut on_close).now_or_never().is_none(),
    "close must wait for the in-flight spawn"
  );

  // The root vanishes while the spawn is parked: releasing the gate fails it.
  rig.fs.remove("/r");
  gate.release();
  tokio::time::timeout(interpreted_secs(5), on_close)
    .await
    .expect("close resolves once the failed spawn settles")
    .expect("the driver confirms the close");
  assert_eq!(rig.fs.spawns(), 0, "the spawn failed");
  assert_eq!(rig.fs.shutdowns(), 0, "no stream ever existed");
}

/// A blocking pool wedged past the grace must not hang close forever: the
/// reply reports the spawn still pending — a wedged spawn is never treated as
/// quiescent — and the orphan handle's Drop remains the reclamation backstop
/// once the wedge clears.
#[tokio::test]
async fn close_grace_bounds_a_wedged_spawn_and_drop_reclaims_it() {
  let rig = rig_with_capacity(64);
  let gate = rig.fs.hold_spawns();

  let (reply, on_reply) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Watch {
      root: PathBuf::from("/r"),
      interest: tributary_proto::Interest::all(),
      reply,
    })
    .await
    .unwrap();
  drop(on_reply);

  let (close_reply, on_close) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Close { reply: close_reply })
    .await
    .unwrap();

  let pending = tokio::time::timeout(interpreted_secs(5), on_close)
    .await
    .expect("close resolves at the grace boundary")
    .expect("the driver replied");
  assert_eq!(
    pending, 1,
    "a wedged spawn is reported — the driver cannot see which phase it \
     wedged in, so it never claims quiescence over one"
  );
  assert_eq!(
    rig.fs.shutdowns(),
    0,
    "the wedged spawn has not produced a stream yet"
  );
  assert_eq!(
    rig.fs.spawns(),
    0,
    "the wedge parked before the stream went live"
  );

  // The wedge clears after close: the orphan completes, its op message finds
  // the channel closed, and the handle's Drop reclaims the stream.
  gate.release();
  let deadline = std::time::Instant::now() + Duration::from_secs(10);
  while rig.fs.shutdowns() == 0 && std::time::Instant::now() < deadline {
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  assert_eq!(
    rig.fs.shutdowns(),
    1,
    "the Drop backstop reclaimed the orphan"
  );
}

/// A spawn wedged AFTER its stream went live — the backend's post-live
/// metadata phase — already owns a live native stream, so close must count it
/// as non-quiescent; once the wedge clears, the undeliverable result's handle
/// Drop reclaims the stream.
#[tokio::test]
async fn close_counts_a_post_live_wedged_spawn_as_non_quiescent() {
  let rig = rig_with_capacity(64);
  rig.fs.put("/r", FileKind::Dir, 1);
  let gate = rig.fs.hold_spawns_post_live();

  let (reply, on_reply) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Watch {
      root: PathBuf::from("/r"),
      interest: tributary_proto::Interest::all(),
      reply,
    })
    .await
    .unwrap();
  drop(on_reply);

  // Wait until the fake stream is genuinely live inside the parked spawn.
  let deadline = std::time::Instant::now() + Duration::from_secs(10);
  while rig.fs.spawns() == 0 && std::time::Instant::now() < deadline {
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  assert_eq!(rig.fs.spawns(), 1, "the stream went live inside the spawn");

  let (close_reply, on_close) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Close { reply: close_reply })
    .await
    .unwrap();

  let pending = tokio::time::timeout(interpreted_secs(5), on_close)
    .await
    .expect("close resolves at the grace boundary")
    .expect("the driver replied");
  assert_eq!(pending, 1, "the live-but-unreturned spawn is counted");
  assert_eq!(
    rig.fs.shutdowns(),
    0,
    "the live stream is genuinely unreclaimed at reply time"
  );

  // The wedge clears: the result finds the op channel closed and the handle's
  // Drop reclaims the live stream.
  gate.release();
  let deadline = std::time::Instant::now() + Duration::from_secs(10);
  while rig.fs.shutdowns() == 0 && std::time::Instant::now() < deadline {
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  assert_eq!(
    rig.fs.shutdowns(),
    1,
    "the Drop backstop reclaimed the stream"
  );
}

/// A teardown wedged past the grace is the residual close must NOT paper
/// over: the handle already moved into the wedged shutdown call, so no Drop
/// backstop exists until it returns — the reply carries the pending count
/// instead of claiming quiescence.
#[tokio::test]
async fn close_reports_a_wedged_teardown_instead_of_quiescence() {
  let rig = rig_with_capacity(64);
  rig.fs.put("/r", FileKind::Dir, 1);
  let _scope = watch(&rig, "/r").await;
  let gate = rig.fs.hold_teardowns();

  let (close_reply, on_close) = futures_channel::oneshot::channel();
  rig
    .commands
    .send(Command::Close { reply: close_reply })
    .await
    .unwrap();

  let pending = tokio::time::timeout(interpreted_secs(5), on_close)
    .await
    .expect("close resolves at the grace boundary")
    .expect("the driver replied");
  assert_eq!(
    pending, 1,
    "the wedged teardown is reported, not papered over"
  );
  assert_eq!(rig.fs.shutdowns(), 0, "the stream is genuinely still live");

  gate.release();
  let deadline = std::time::Instant::now() + Duration::from_secs(10);
  while rig.fs.shutdowns() == 0 && std::time::Instant::now() < deadline {
    tokio::time::sleep(Duration::from_millis(10)).await;
  }
  assert_eq!(
    rig.fs.shutdowns(),
    1,
    "the wedged call completes once released"
  );
}

mod teardown_reaper {
  //! What the driver may hand its teardown reaper, and what the reaper does when
  //! the OS will not give it a thread.

  use super::*;

  /// Arms [`REFUSE_REAPER_THREADS`] for this thread and disarms it on drop.
  /// libtest gives every cell its own thread, so the refusal never reaches
  /// another cell's driver.
  struct RefuseReaperThreads;

  impl RefuseReaperThreads {
    fn arm() -> Self {
      REFUSE_REAPER_THREADS.with(|refuse| refuse.set(true));
      Self
    }
  }

  impl Drop for RefuseReaperThreads {
    fn drop(&mut self) {
      REFUSE_REAPER_THREADS.with(|refuse| refuse.set(false));
    }
  }

  /// A teardown the reaper could not get a thread for must not run on the thread
  /// that submitted it.
  ///
  /// Submission happens on the driver's own task, and a teardown JOINS its
  /// stream's reader — a wait with no bound, because a reader already inside a
  /// syscall against a dead mount returns when the kernel says so. Running one on
  /// the submitting side therefore freezes the whole watcher, and on a
  /// current-thread runtime the executor with it: exactly the isolation the
  /// reaper exists to provide, surrendered on the failure path. Thread exhaustion
  /// is when that isolation matters most, so the answer is to queue the teardown
  /// for the reaper's baseline thread and never to run it here.
  ///
  /// Refused is not the same as dropped, either: the closure owns the stream
  /// handle, whose own `Drop` performs the same join with no completion to show
  /// for it, so the submission stays counted and close reports it.
  ///
  /// What this does NOT cover: a real OS refusal. The refusal is injected, which
  /// pins the reaper's response to it but not the syscall's failure mode.
  ///
  /// MUTATION WITNESS: run the queued teardown on the submitting thread when no
  /// reaper is alive to claim it, and the thread identity below is this cell's
  /// own.
  #[test]
  fn a_teardown_never_runs_on_the_thread_that_submitted_it() {
    let reaper = TeardownReaper::without_threads();
    let submitter = std::thread::current().id();
    let (ran_on_tx, ran_on_rx) = std::sync::mpsc::channel();
    reaper.reap(move || {
      let _ = ran_on_tx.send(std::thread::current().id());
    });

    assert_eq!(
      ran_on_rx.try_recv().ok(),
      None,
      "the teardown RAN although the reaper has no thread — on the submitting thread {submitter:?}, \
       which in the driver is its own task"
    );
    assert!(
      !reaper.settle(Duration::from_millis(20)),
      "and it is still counted outstanding, so close reports it rather than losing it"
    );
  }

  /// A driver that cannot secure a reaper admits no root.
  ///
  /// Every stream it started would owe a join it has nowhere to run: not on the
  /// blocking pool, which the live generation's control batches need, and not on
  /// its own task, which the join would freeze. Refusing the source is the only
  /// honest answer left, and it has to happen before the first one exists — a
  /// stream already live cannot be un-started. The watcher then reads a closed
  /// command channel and an ended event stream, the same signals it reads from
  /// any dead driver.
  ///
  /// What this does NOT cover: a real OS refusal, and drivers whose task is first
  /// polled somewhere other than the thread that started them — the seam is
  /// thread-scoped, so it reaches this current-thread runtime's driver and no
  /// other.
  ///
  /// MUTATION WITNESS: let the driver build its reaper lazily, or start without
  /// one, and the watch below is admitted.
  #[tokio::test(start_paused = true)]
  async fn a_driver_that_cannot_secure_a_reaper_admits_no_root() {
    let _refused = RefuseReaperThreads::arm();
    let rig = rig_with_capacity(64);

    let (reply, mut on_reply) = futures_channel::oneshot::channel();
    let _ = rig
      .commands
      .send(Command::Watch {
        root: PathBuf::from("/r"),
        interest: tributary_proto::Interest::all(),
        reply,
      })
      .await;

    // The driver dropping its command receiver is the closed channel a watcher
    // maps to `Closed`. A request already queued when it goes is never answered
    // at all, so the reply is read without waiting on it — the driver is gone and
    // nothing will ever resolve it.
    let mut gone = false;
    for _ in 0..200 {
      if rig.commands.is_closed() {
        gone = true;
        break;
      }
      tokio::task::yield_now().await;
      tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert!(
      gone,
      "a driver with no teardown reaper kept running and took commands it could not honour"
    );
    assert_eq!(rig.fs.spawns(), 0, "it started no source");
    assert!(
      matches!(on_reply.try_recv(), Ok(None)),
      "and it admitted no root it could never retire"
    );
  }

  /// A closure handed to the reaper is arbitrary: the driver's own teardown
  /// submission reports its unwind as a terminal, but the spawn sink's handoff
  /// closure has no such wrapper. So the WORKER itself must survive an unwind and
  /// leave its accounting exact — otherwise one panicking closure permanently
  /// removes a thread that `threads` still counts, and enough of them leave the
  /// cap fully "occupied" by workers that no longer exist.
  ///
  /// FAIL-ON-REVERT: replace `reap_loop`'s claim guard and containment boundary
  /// with `teardown(); finish_teardown(inner);` and the worker dies with the first
  /// closure — the healthy one behind it is never claimed and `settle` never
  /// reports quiescence.
  #[test]
  fn a_reaper_worker_survives_an_unwinding_closure_with_exact_accounting() {
    let reaper = TeardownReaper::new().expect("the baseline thread starts");
    let ran = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    reaper.reap(|| panic!("an uncontained teardown closure unwinds"));
    let flag = Arc::clone(&ran);
    reaper.reap(move || {
      flag.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    });

    // `settle` returns on ANY completion, so drive it to quiescence: what is
    // proven is that both submissions retire, not that one does.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut quiesced = false;
    while !quiesced && std::time::Instant::now() < deadline {
      quiesced = reaper.settle(Duration::from_millis(50));
    }
    assert!(
      quiesced,
      "both submissions are retired: the unwind repaired its own accounting"
    );
    assert_eq!(
      ran.load(std::sync::atomic::Ordering::SeqCst),
      1,
      "the healthy teardown queued behind the unwinding one still ran"
    );
  }

  /// Drives `reaper` to full quiescence, or gives up after `budget`.
  fn quiesce(reaper: &TeardownReaper, budget: Duration) -> bool {
    let deadline = std::time::Instant::now() + budget;
    let mut quiesced = false;
    while !quiesced && std::time::Instant::now() < deadline {
      quiesced = reaper.settle(Duration::from_millis(20));
    }
    quiesced
  }

  /// Waits until `predicate` reads true of the reaper's state, or gives up.
  fn settled_state(reaper: &TeardownReaper, predicate: impl Fn(&ReaperState) -> bool) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
      if predicate(&reaper.lock()) {
        return true;
      }
      if std::time::Instant::now() >= deadline {
        return false;
      }
      std::thread::sleep(Duration::from_millis(2));
    }
  }

  /// A legal `panic_any` payload whose own disposal unwinds.
  struct PanicsOnDrop;

  impl Drop for PanicsOnDrop {
    fn drop(&mut self) {
      std::panic::panic_any(ForgottenPayload);
    }
  }

  /// The payload [`PanicsOnDrop`]'s own disposal unwinds with.
  ///
  /// A ZST, and that is the point: this is the payload a total disposal must
  /// [forget](std::mem::forget) — the operation that cuts the recursion runs no
  /// destructor — so by contract it is unreachable for the rest of the process. A
  /// zero-sized box allocates nothing, so the cell asserts that containment while
  /// retaining nothing for a whole-process leak check to report. A `panic!("…")`
  /// message makes it a `Box<&'static str>` instead: 16 bytes LeakSanitizer reports,
  /// in a suite where every OTHER retained allocation is a real defect.
  struct ForgottenPayload;

  /// The caught PAYLOAD is not the worker's data. A `panic_any` payload is any
  /// `Send + 'static` value the panicking code chose, so disposing of it runs that
  /// code's own destructor — and one that panics starts a SECOND unwind, in ordinary
  /// control flow, one line past the boundary that just contained the first.
  ///
  /// That unwind leaves through `reap_loop` AFTER `ClaimedTeardown` has repaired
  /// `busy`/`outstanding`, so the accounting looks perfectly healthy while the worker is
  /// gone — and the abnormal escrow, reservoir, queue-drain and failed-delivery paths all
  /// submit a raw `handle.shutdown()` with no wrapper of their own, so a backend that
  /// panics with such a payload reaches this exactly.
  ///
  /// The instrument is the WORKER'S OWN IDENTITY, and it has to be: the
  /// worker-lifetime guard repairs the accounting on any abnormal exit and the next
  /// submission's growth rule then hands the queue a fresh thread, so "the healthy
  /// teardown behind it still ran" is satisfied by a reaper that lost its worker and
  /// replaced it. What the containment is for is that the worker never dies at all —
  /// so both teardowns must run on the SAME thread, which a replacement can never
  /// satisfy (a `ThreadId` is never reused).
  ///
  /// FAIL-ON-REVERT: dispose of the payload by letting `catch_unwind`'s `Err` fall out of
  /// scope (`let _unwound = ...`) instead of handing it to the contained disposal, and the
  /// second teardown reports a different thread — the first worker unwound out of its loop
  /// and only the guard's repair kept the reaper serving at all.
  #[test]
  fn a_teardown_payload_whose_drop_panics_leaves_the_worker_and_its_accounting_intact() {
    let reaper = TeardownReaper::new().expect("the baseline thread starts");
    let workers: Arc<Mutex<Vec<std::thread::ThreadId>>> = Arc::new(Mutex::new(Vec::new()));

    let seen = Arc::clone(&workers);
    reaper.reap(move || {
      seen
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(std::thread::current().id());
      std::panic::panic_any(PanicsOnDrop)
    });
    assert!(
      quiesce(&reaper, Duration::from_secs(10)),
      "the payload-panicking teardown retired its own obligation"
    );
    // The payload's disposal is asynchronous to that retirement — `ClaimedTeardown`
    // releases first — so give the worker real time to die if it is going to. Without
    // this the submission below can be claimed by a thread that was merely slow to leave.
    std::thread::sleep(Duration::from_millis(50));

    let seen = Arc::clone(&workers);
    reaper.reap(move || {
      seen
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(std::thread::current().id());
    });
    assert!(
      quiesce(&reaper, Duration::from_secs(10)),
      "the healthy teardown behind the payload-panicking one retired too"
    );

    let workers = workers.lock().unwrap_or_else(PoisonError::into_inner);
    assert_eq!(workers.len(), 2, "both teardowns ran: {workers:?}");
    assert_eq!(
      workers[0], workers[1],
      "the payload's disposal took the worker with it — the second teardown ran on a \
       replacement rather than on the worker that contained the first: {workers:?}"
    );
    assert_eq!(
      reaper.lock().threads,
      1,
      "and the reaper still counts exactly the workers it has"
    );
  }

  /// Whatever kills a worker, `threads` must stop counting it.
  ///
  /// The counter is read as EXACT by the growth rule (`threads - busy` is how many queued
  /// teardowns already have a claimant), so one phantom worker suppresses the growth that
  /// would give real queued work a thread, and enough of them leave the cap fully
  /// "occupied" by workers that do not exist. The decrement therefore cannot live on the
  /// normal-exit path, which is one of the ways a worker can end.
  ///
  /// The unwind is INJECTED because the worker's own boundaries make an escaping one
  /// unreachable through the closures it runs — which is the point: the guard is a promise
  /// about every abnormal exit, including ones no closure can currently produce.
  ///
  /// FAIL-ON-REVERT: put the `threads` decrement back on `reap_loop`'s exit predicate and
  /// drop the `LiveReaper` guard — the count below never reaches zero, and the healthy
  /// teardown after it is queued against a claimant that does not exist.
  #[test]
  fn a_worker_that_exits_abnormally_stops_being_counted() {
    let reaper = TeardownReaper::new().expect("the baseline thread starts");
    reaper
      .inner
      .unwind_after_claim
      .store(1, std::sync::atomic::Ordering::SeqCst);

    reaper.reap(|| {});
    assert!(
      settled_state(&reaper, |state| state.threads == 0),
      "the worker unwound while `threads` still counted it"
    );

    // And the repair is not cosmetic: with the count honest, the next submission's growth
    // rule sees queued work with no claimant and creates one.
    let ran = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let flag = Arc::clone(&ran);
    reaper.reap(move || {
      flag.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    });
    assert!(
      quiesce(&reaper, Duration::from_secs(10)),
      "a teardown submitted after the abnormal exit found a claimant"
    );
    assert_eq!(
      ran.load(std::sync::atomic::Ordering::SeqCst),
      1,
      "and it ran"
    );
  }

  /// A worker that leaves abnormally may have been the only claimant of a NON-EMPTY queue,
  /// and every queued closure owns a live `SourceHandle`. Nothing guarantees a further
  /// submission whose growth rule would create the replacement, so the queue would sit
  /// unclaimed until the last sink released `ReaperInner` — destroying the closure, and
  /// performing the native handle's unbounded join on whatever thread that release happened
  /// to run on. So the exiting worker re-runs the growth rule itself.
  ///
  /// The queue is loaded while thread creation is REFUSED, which is what makes a teardown
  /// sit behind a busy worker with no thread of its own; creation is restored before the
  /// exit, so what the cell reads is the guard's own replacement and not a growth the
  /// submission already performed.
  ///
  /// FAIL-ON-REVERT: reduce `LiveReaper::drop` to the bare `threads` decrement — the queued
  /// teardown below is never claimed and `settle` never reports quiescence.
  #[test]
  fn a_worker_leaving_a_non_empty_queue_replaces_its_own_claimant() {
    let reaper = TeardownReaper::new().expect("the baseline thread starts");
    reaper
      .inner
      .unwind_after_claim
      .store(1, std::sync::atomic::Ordering::SeqCst);

    // Occupy the only worker so the next submission has to queue.
    let (release, held) = std::sync::mpsc::channel::<()>();
    let (entered_tx, entered) = std::sync::mpsc::channel::<()>();
    reaper.reap(move || {
      let _ = entered_tx.send(());
      let _ = held.recv();
    });
    entered
      .recv_timeout(Duration::from_secs(10))
      .expect("the worker claimed the blocking teardown");

    // The OS gives this reaper nothing more, so the submission below cannot grow itself a
    // thread and lands in the queue behind the busy worker.
    reaper
      .inner
      .refuse_threads
      .store(true, std::sync::atomic::Ordering::SeqCst);
    let ran = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let flag = Arc::clone(&ran);
    reaper.reap(move || {
      flag.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    });
    assert_eq!(
      {
        let state = reaper.lock();
        (state.threads, state.queue.len())
      },
      (1, 1),
      "the queued teardown is behind the one busy worker, with no thread of its own"
    );
    reaper
      .inner
      .refuse_threads
      .store(false, std::sync::atomic::Ordering::SeqCst);

    // Releasing the blocking teardown lets the worker retire it and then unwind.
    drop(release);

    assert!(
      quiesce(&reaper, Duration::from_secs(10)),
      "the abnormal exit left its queued teardown a claimant"
    );
    assert_eq!(
      ran.load(std::sync::atomic::Ordering::SeqCst),
      1,
      "and the replacement ran it"
    );
    assert_eq!(
      reaper.lock().threads,
      1,
      "with the count naming exactly the replacement"
    );
  }

  /// What a teardown closure carries, and where it was destroyed.
  ///
  /// `Drop` is the whole instrument: a closure the reaper RUNS consumes this and
  /// reports the thread it ran on, while a closure nobody ever claims is dropped
  /// with the queue holding it — and in the driver that drop is a native handle's
  /// unbounded join, on whatever thread released the last sink.
  struct ReapProbe {
    ran_on: std::sync::mpsc::Sender<String>,
    dropped_on: std::sync::mpsc::Sender<String>,
    /// Set by the run, read by `Drop`: which of the two terminals this closure
    /// reached. A run must SILENCE the drop report rather than suppress the drop —
    /// the driver's own claimed closure is dropped after it runs, and a probe that
    /// skipped its destructor would model a claimed closure as one that never
    /// released the channels it holds.
    ran: bool,
  }

  impl ReapProbe {
    fn consume(mut self) {
      let _ = self.ran_on.send(this_thread());
      // The run is the terminal: `Drop` still fires, and reporting from it too
      // would make a claimed closure indistinguishable from an abandoned one.
      self.ran = true;
    }
  }

  impl Drop for ReapProbe {
    fn drop(&mut self) {
      if self.ran {
        return;
      }
      let _ = self.dropped_on.send(this_thread());
    }
  }

  fn this_thread() -> String {
    std::thread::current()
      .name()
      .unwrap_or("<unnamed>")
      .to_owned()
  }

  /// A sink outlives the driver's reaper by design — a detached spawn job carries
  /// one so a stream it cannot deliver still reaches a reaper thread instead of
  /// being joined on the shared blocking pool. So the reaper must still HAVE a
  /// thread when that late submission lands.
  ///
  /// It used to let its threads exit the moment the driver's `TeardownReaper`
  /// dropped, leaving the late submission to create one — and when creation
  /// failed the closure stayed queued with no claimant, until the last sink
  /// dropped `ReaperInner` and with it the closure and the native handle inside
  /// it. That drop performs the same unbounded join, on the pool worker releasing
  /// the sink: the exact executor the reaper exists to keep it off.
  ///
  /// FAIL-ON-REVERT: exit on `owner_gone` alone (drop the `producers` term from
  /// `reap_loop`'s exit predicate) and the baseline thread is gone before the
  /// submission arrives; the refused growth strands it, and the closure is never
  /// run at all — it is destroyed when the last sink releases `ReaperInner`.
  #[test]
  fn a_sink_outliving_its_reaper_still_has_a_thread_to_hand_a_stream_to() {
    let reaper = TeardownReaper::new().expect("the baseline thread starts");
    let sink = reaper.sink();
    // The driver's loop is over; only the detached job's sink remains.
    drop(reaper);
    // REAL time for a thread to observe that and act on it. Without this wait the
    // submission below races the exit and can be claimed by a thread that was
    // merely slow to leave — which is how a rule that lets the last thread go
    // still passes. What follows therefore tests the state each rule settles on.
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while sink.reaper_threads() > 0 && std::time::Instant::now() < deadline {
      std::thread::sleep(Duration::from_millis(2));
    }
    assert!(
      sink.reaper_threads() > 0,
      "the reaper let its last thread go while a producer could still submit — the \
       next handoff has to CREATE its own claimant"
    );

    // And the OS will give this reaper nothing further — the failure mode the
    // old exit rule made load-bearing.
    sink.refuse_further_threads();

    let (ran_on, on_run) = std::sync::mpsc::channel();
    let (dropped_on, on_drop) = std::sync::mpsc::channel();
    let probe = ReapProbe {
      ran_on,
      dropped_on,
      ran: false,
    };
    sink.reap(move || probe.consume());

    let ran = on_run.recv_timeout(Duration::from_secs(10));
    assert!(
      ran
        .as_deref()
        .is_ok_and(|on| on.starts_with("tributary-teardown")),
      "the late handoff ran on {ran:?}, not on a reaper thread"
    );

    // Releasing the last producer is what finally lets the thread go, and it
    // finds nothing left to destroy.
    drop(sink);
    assert!(
      on_drop.recv_timeout(Duration::from_millis(200)).is_err(),
      "the closure — and the native handle a real one carries — was destroyed \
       rather than run"
    );
  }
}

mod descending {
  //! The descending (inotify-profile) loop, end to end on the fake platform.

  use super::*;
  use crate::os::linux::{RawInotifyEvent, RawLinuxEvent, inotify::decode::InotifyMask};

  fn inotify_config() -> DriverConfig {
    DriverConfig {
      profile: BackendKind::Inotify,
      ..config()
    }
  }

  fn inotify_rig() -> Rig {
    inotify_rig_fs(FakeFs::new(1))
  }

  /// A descending rig whose fake source reports a root MOUNT id, so the core
  /// fences a same-device child on a different mount (a bind) end to end.
  fn inotify_rig_mnt(root_mnt_id: u64) -> Rig {
    inotify_rig_fs(FakeFs::with_root_mnt_id(1, root_mnt_id))
  }

  fn inotify_rig_fs(fs: FakeFs) -> Rig {
    inotify_rig_fs_capacity(fs, 64)
  }

  /// [`inotify_rig_fs`] with the consumer's event channel sized by the caller: a
  /// cell that must observe a REFUSED delivery needs a capacity it can fill and
  /// keep full.
  fn inotify_rig_fs_capacity(fs: FakeFs, event_capacity: usize) -> Rig {
    fs.put("/r", FileKind::Dir, 1);
    fs.spawn_backend(BackendKind::Inotify);
    let (cmd_tx, cmd_rx) = async_channel::bounded(16);
    let (cleanup, cookie_wake) = cookie_ingress();
    let (ev_tx, ev_rx) = async_channel::bounded(event_capacity);
    tokio::spawn(run::<TokioRuntime, FakeFs>(
      inotify_config(),
      fs.clone(),
      cmd_rx,
      cookie_wake,
      ev_tx,
      NullRegistry,
    ));
    Rig {
      fs,
      commands: cmd_tx,
      cleanup,
      events: ev_rx,
    }
  }

  /// The refresh cadence the ticking rigs run at, NATIVELY. The production
  /// default is 30 s and nothing about the tick depends on the interval, so a
  /// cell about WHAT the refresh derives shortens it rather than sleeping through
  /// it. Still far longer than the crawl it must not race: the birth window
  /// closes in a handful of milliseconds here.
  const NATIVE_TICK: Duration = Duration::from_millis(250);

  /// The same cadence, in the wall clock an INTERPRETER needs for it — the
  /// missing half of the argument [`config`] makes when it disables the tick
  /// outright for every cell that is not about it.
  ///
  /// That argument is about a RATE, not about a count of scopes: a driver
  /// iteration costs on the order of a second under Miri, and each tick hands the
  /// loop two units of work (arm the read, then consume its completion off
  /// `op_rx`). At 250 ms the demand outruns the service rate several times over,
  /// `op_rx` — the FIRST `select_biased!` arm — stops emptying, and the source
  /// lane and command mailbox behind it are never polled again. One live scope is
  /// enough; what varies is only how many cells have already run in the shard,
  /// which is why these cells pass alone and hang in the suite.
  ///
  /// 20 s leaves the loop room for a dozen-odd iterations per interval on a fast
  /// host and several on an ordinary one. Like [`INTERPRETED_DEADLINE`] it is one
  /// flat value rather than a tuned multiple: a cadence only has to be slower
  /// than the loop, and overshooting costs a passing run real seconds it can
  /// afford.
  const INTERPRETED_TICK: Duration = Duration::from_secs(20);

  /// The cadence these rigs run at, on whatever is executing them.
  ///
  /// The interpreted value is a cliff rather than a scale ([`INTERPRETED_TICK`]),
  /// but the axis underneath it is a RATE — the tick's demand against the driver
  /// loop's service rate — and `cfg!(miri)` is not the only thing that moves it.
  /// A SANITIZER build is native, so it takes the native arm, while ASan/TSan slow
  /// the loop several fold against a real clock that does not stretch: exactly the
  /// ratio that starved `op_rx` under the interpreter. So the native cadence rides
  /// [`timing_scale`], the same knob the workspace already sets per instrument (1
  /// unset, so an ordinary run is unchanged). Lengthening a cadence can only give
  /// the loop more room — these cells assert WHAT the refresh derives, never how
  /// quickly — so the widening is safe in the same blanket way
  /// [`interpreted_secs`]'s is.
  fn tick() -> Duration {
    if cfg!(miri) {
      INTERPRETED_TICK
    } else {
      NATIVE_TICK * timing_scale()
    }
  }

  /// A descending rig whose periodic mount refresh runs at a cadence a real-time
  /// cell can wait out ([`tick`]).
  fn inotify_rig_ticking(fs: FakeFs) -> Rig {
    fs.put("/r", FileKind::Dir, 1);
    fs.spawn_backend(BackendKind::Inotify);
    let (cmd_tx, cmd_rx) = async_channel::bounded(16);
    let (cleanup, cookie_wake) = cookie_ingress();
    let (ev_tx, ev_rx) = async_channel::bounded(64);
    tokio::spawn(run::<TokioRuntime, FakeFs>(
      DriverConfig {
        root_liveness_interval: tick(),
        ..inotify_config()
      },
      fs.clone(),
      cmd_rx,
      cookie_wake,
      ev_tx,
      NullRegistry,
    ));
    Rig {
      fs,
      commands: cmd_tx,
      cleanup,
      events: ev_rx,
    }
  }

  /// #74, end to end on the real loop. A LAZY unmount below the watched root
  /// reaches this driver through no channel at all — the control experiment
  /// measured an inotify watch on a subdirectory surviving unmount and remount
  /// with no delivery, no `Rescan` and nothing else for 120 s — so the only thing
  /// that can notice is the periodic refresh the descending profile now arms, and
  /// the only honest thing it can say is a COVER: the mount table cannot tell a
  /// vanished bind from a vanished volume, and re-enumeration answers both.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_silently_departed_mount_covers_its_subtree_end_to_end() {
    let fs = FakeFs::new(1);
    // The live table at birth: one mount under the root, with a tree on it. The
    // spawn barrier reads it AND the birth refresh confirms it, which is what a
    // mount that was already there looks like — so the row is recorded with no
    // arrival cover, and the only cover this cell can observe is the departure.
    fs.seed_mounts(vec![bare_mount("/r/vol")]);
    fs.answer_refresh(vec![bare_mount("/r/vol")], true);
    let rig = inotify_rig_ticking(fs);
    rig.fs.put("/r/vol", FileKind::Dir, 20);
    rig.fs.put("/r/vol/inner.txt", FileKind::File, 21);
    let scope = watch(&rig, "/r").await;
    fence_birth_crawl(&rig, scope, "/r").await;

    // `umount -l /r/vol`: the row leaves the table and the kernel says nothing.
    rig.fs.answer_refresh(Vec::new(), true);

    let (s, change) = next_event(&rig).await;
    assert_eq!(s, scope);
    assert!(
      change.kind().is_rescan(),
      "a departure nothing signalled is covered, never delivered: {change:?}"
    );
    assert_eq!(
      change.location(),
      &loc(&["vol"]),
      "and the cover is LOCATED at the departed mount: {change:?}"
    );
  }

  /// The same departure, reached through the operating point that used to
  /// swallow it: refresh latency at or past the interval, so the tick fires ON
  /// TOP of the read in flight. That needs no adversary — a busy blocking pool
  /// or a short interval produces it — and the interval is a public knob with no
  /// floor above zero.
  ///
  /// A tick that CONDEMNED the read it raced (marking it stale) would discard
  /// this completion, and the read it re-arms would be condemned by the next
  /// tick in turn: the mount-table install, the frame adoption and the departure
  /// diff all sit BEHIND `on_mounts_refreshed`'s stale gate, so nothing past it
  /// would ever publish again. Only the root-death check survives, being in
  /// front of the gate — which is exactly why the below-root silence would stay
  /// silent forever.
  ///
  /// Staged with the refresh gate: one read is held on the pool across several
  /// ticks, and a SUPERSEDING gate is installed before it is released, so the
  /// next read parks too and the latency stays above the interval. A condemned
  /// completion therefore cannot heal itself by re-reading quickly inside the
  /// cell — the cover either comes from the tick-raced read or it does not come.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_tick_raced_refresh_still_covers_the_departure_end_to_end() {
    let fs = FakeFs::new(1);
    // Seeded AND answered, so the mount is recorded at the barrier and merely
    // confirmed by the first read: no arrival cover can stand in for the
    // departure this cell is about.
    fs.seed_mounts(vec![bare_mount("/r/vol")]);
    fs.answer_refresh(vec![bare_mount("/r/vol")], true);
    let rig = inotify_rig_ticking(fs);
    rig.fs.put("/r/vol", FileKind::Dir, 20);
    rig.fs.put("/r/vol/inner.txt", FileKind::File, 21);
    let scope = watch(&rig, "/r").await;
    fence_birth_crawl(&rig, scope, "/r").await;

    // Every refresh from here parks on the pool.
    let held = rig.fs.hold_refreshes();
    // The budget has to outlast ONE cadence, and the cadence is 20 s under an
    // interpreter (see [`INTERPRETED_TICK`]). A round is ~12 ms of real time at
    // minimum, so the shared 200-round default cannot reach the first tick there
    // — and an expired staging budget is this cell's own failure, not a weaker
    // path through it.
    assert!(
      settle_within(3000, || held.captured() >= 1).await,
      "staging: a tick armed a refresh and it parked on the gate"
    );
    // Hold it across several ticks. This runtime is NOT paused and the driver's
    // deadline runs on the same real clock, so the ticks are the loop's own.
    // Only the LOWER bound is load-bearing: more ticks can only strengthen the
    // staging, never weaken it.
    // Four cadences of real time. `tick()` already carries `timing_scale`, so this
    // must NOT multiply by it again: doing so is quadratic in the knob and would
    // spend minutes of an instrumented lane's budget waiting out a staging step.
    tokio::time::sleep(tick() * 4).await;
    assert_eq!(
      held.captured(),
      1,
      "staging: those ticks coalesced onto the held read rather than stacking refreshes"
    );

    // `umount -l /r/vol`, seen by the read that is already parked (the gate is
    // entered before the answer is read).
    rig.fs.answer_refresh(Vec::new(), true);
    let next = rig.fs.hold_refreshes();
    held.release();

    let (s, change) = next_event(&rig).await;
    assert_eq!(s, scope);
    assert!(
      change.kind().is_rescan(),
      "the tick-raced read still covers what it found gone: {change:?}"
    );
    assert_eq!(
      change.location(),
      &loc(&["vol"]),
      "and the cover is LOCATED at the departed mount: {change:?}"
    );
    next.release();
  }

  /// A KERNEL-RECURSIVE rig at the same cadence, for the profile seam 2 exists
  /// for: one mark covers the whole root, the Monitor never descends, and the
  /// source's own walk is the only thing that ever fences a directory.
  fn fanotify_rig_ticking(fs: FakeFs) -> Rig {
    fs.put("/r", FileKind::Dir, 1);
    fs.spawn_backend(BackendKind::Fanotify);
    let (cmd_tx, cmd_rx) = async_channel::bounded(16);
    let (cleanup, cookie_wake) = cookie_ingress();
    let (ev_tx, ev_rx) = async_channel::bounded(64);
    tokio::spawn(run::<TokioRuntime, FakeFs>(
      DriverConfig {
        root_liveness_interval: tick(),
        profile: BackendKind::Fanotify,
        ..config()
      },
      fs.clone(),
      cmd_rx,
      cookie_wake,
      ev_tx,
      NullRegistry,
    ));
    Rig {
      fs,
      commands: cmd_tx,
      cleanup,
      events: ev_rx,
    }
  }

  /// SEAM 2 on the WIRE, end to end on the real loop: a boundary a live WALK
  /// declined rides the source's own ordered lane as its own message, lands in
  /// the coverage set, and its later departure is covered from there.
  ///
  /// This is the path the fanotify reader's post-loss reseed and moved-in subtree
  /// walk take — they run on the reader thread, long past the spawn result the
  /// seed walk's declines ride — and it is the path the admission reseed will
  /// take too. Nothing in the core re-derives the triple: what the walk read is
  /// what the set holds.
  ///
  /// The mount table answers EMPTY for this cell's whole life, which is what
  /// makes the verdict readable. A table that ever listed `/r/bound` would fire
  /// an ARRIVAL cover at the very location the departure assertion reads, and the
  /// cell would pass on the wrong signal. With no row ever, an arrival is
  /// impossible by construction and the only thing that can cover `/r/bound` is
  /// the departure of what the walk declined.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_live_walks_declined_boundary_rides_the_lane_and_departs_from_the_set() {
    // The root sits on mount 42; the walk's decline names mount 77 — a
    // `mount --bind` of a same-superblock directory, which the device belt cannot
    // see. Both halves known and unequal, so the seam decides `Mount(77)` and the
    // first census that does not key 77 derives its departure (and no census ever
    // will key it).
    let fs = FakeFs::with_root_mnt_id(1, 42);
    fs.answer_refresh(Vec::new(), true);
    let rig = fanotify_rig_ticking(fs);
    let scope = watch(&rig, "/r").await;

    rig.fs.send_walk_boundaries(
      "/r",
      vec![crate::os::DeclinedBoundary {
        location: PathBuf::from("/r/bound"),
        dev: 1,
        mnt_id: Some(77),
      }],
    );

    // The departure the next tick derives does NOT cover yet. This profile's
    // source admits by directory-handle membership and its walk stopped AT the
    // bind, so the ground the departure just revealed has no handles at all —
    // covering now would send the consumer to re-read a subtree the reader still
    // drops every event on. The cover parks on an admission round trip instead.
    assert!(
      settle(|| !rig.fs.admit_requests().is_empty()).await,
      "the departure asked the source to admit the revealed ground"
    );
    let requested = rig.fs.admit_requests();
    assert_eq!(
      requested.len(),
      1,
      "one round trip per departure: {requested:?}"
    );
    assert_eq!(requested[0].location, PathBuf::from("/r/bound"));
    assert!(
      tokio::time::timeout(Duration::from_millis(200), rig.events.recv())
        .await
        .is_err(),
      "and NOTHING reaches the consumer while it is outstanding — this is \
       admission-before-cover, on the real loop"
    );

    // The reader walked the revealed ground into its map and answered.
    rig
      .fs
      .answer_admit("/r", requested[0].ticket, crate::os::AdmitOutcome::Admitted);
    let (s, change) = next_event(&rig).await;
    assert_eq!(s, scope);
    assert!(
      change.kind().is_rescan(),
      "a departure nothing signalled is covered, never delivered: {change:?}"
    );
    assert_eq!(
      change.location(),
      &loc(&["bound"]),
      "and the cover is LOCATED at the boundary the WALK declined — the core \
       never saw that path any other way: {change:?}"
    );
  }

  /// **THE FAIL-CLOSED RULE ON THE WIRE**, and its routing: a scope holding an
  /// AMBIGUOUS record asks its source for a WHOLE-ROOT RECOVERY on every
  /// authoritative refresh, and the root cover reaches the consumer only behind
  /// that recovery's reply.
  ///
  /// The fake's root carries NO mount id — the pre-5.8 Linux shape, and the only
  /// one that can produce an ambiguous record at all — so the walk's id-less
  /// decline is indistinguishable from a genuine vfsmount that has departed. No
  /// per-record evidence exists to say which, so the whole root is covered.
  ///
  /// **The routing is half the assertion.** A bare `Scope::Root` cover emitted
  /// from the refresh would send the consumer to re-read a tree whose FID map the
  /// source has never seeded, and every mutation until some later reseed would
  /// drop on an unknown handle with no loss signal — the same failure the located
  /// admission round trip exists to prevent, at root scale. So nothing reaches
  /// the consumer until the recovery answers.
  #[tokio::test(flavor = "multi_thread")]
  async fn an_ambiguous_record_recovers_the_whole_root_through_the_source() {
    let fs = FakeFs::new(1);
    fs.answer_refresh(Vec::new(), true);
    let rig = fanotify_rig_ticking(fs);
    let scope = watch(&rig, "/r").await;

    // A walk decline carrying a device and NO mount id, against a scope with no
    // frame of its own: ambiguous on both sides of the comparison.
    rig.fs.send_walk_boundaries(
      "/r",
      vec![crate::os::DeclinedBoundary {
        location: PathBuf::from("/r/bound"),
        dev: 99,
        mnt_id: None,
      }],
    );

    assert!(
      settle(|| !rig.fs.recovery_requests().is_empty()).await,
      "the ambiguity made the scope fail closed, and the whole root is recovered \
       through the source"
    );
    assert!(
      rig.fs.admit_requests().is_empty(),
      "and nothing LOCATED was asked for: {:?}",
      rig.fs.admit_requests()
    );
    assert!(
      tokio::time::timeout(Duration::from_millis(200), rig.events.recv())
        .await
        .is_err(),
      "NOTHING reaches the consumer while the recovery is outstanding — a bare \
       root cover here would point at ground the FID map does not hold"
    );

    // The reader reseeded the whole map and answered with the one indivisible
    // message: the complete generation (the boundary is still there), and the
    // cutoff.
    let asked = rig.fs.recovery_requests()[0];
    rig.fs.answer_root_recovery(
      "/r",
      asked,
      vec![crate::os::DeclinedBoundary {
        location: PathBuf::from("/r/bound"),
        dev: 99,
        mnt_id: None,
      }],
      // The reseed reopened the root this scope still holds, and this fake host
      // reports no mount id for it — the honest unknown, which the frame check
      // passes exactly as every other unknown leg does.
      None,
    );
    let (s, change) = next_event(&rig).await;
    assert_eq!(s, scope);
    assert!(
      change.kind().is_rescan(),
      "the fail-closed answer is a cover, never a delivery: {change:?}"
    );
    assert_eq!(
      change.location(),
      &loc(&[]),
      "and it covers the WHOLE root: {change:?}"
    );
  }

  /// The same departure with no source to ask: `request_admits` refuses (a real
  /// handle answers that once its reader thread is gone), so the driver resolves
  /// the round trip itself and the cover goes out on the refresh's verdict alone.
  ///
  /// The alternative is the one unacceptable outcome — a cover held forever
  /// behind a reply that cannot come — so this is the leg that keeps the parked
  /// state from being a liveness hazard.
  #[tokio::test(flavor = "multi_thread")]
  async fn an_admission_no_source_can_take_still_covers_the_departure() {
    let fs = FakeFs::with_root_mnt_id(1, 42);
    fs.answer_refresh(Vec::new(), true);
    fs.refuse_admits();
    let rig = fanotify_rig_ticking(fs);
    let scope = watch(&rig, "/r").await;

    rig.fs.send_walk_boundaries(
      "/r",
      vec![crate::os::DeclinedBoundary {
        location: PathBuf::from("/r/bound"),
        dev: 1,
        mnt_id: Some(77),
      }],
    );

    let (s, change) = next_event(&rig).await;
    assert_eq!(s, scope);
    assert!(change.kind().is_rescan());
    assert_eq!(
      change.location(),
      &loc(&["bound"]),
      "the cover is not stranded by a source that cannot admit: {change:?}"
    );
    assert!(
      rig.fs.admit_requests().is_empty(),
      "and the refused request was never even recorded as accepted"
    );
  }

  /// A WHOLE-ROOT walk report is a GENERATION, and it retires the ledger entries
  /// that walk did not decline — end to end on the real loop, through the
  /// source's own ordered lane.
  ///
  /// The retirement itself emits nothing (the callers of a complete generation
  /// each carry a root-wide cover of their own behind the report), so the cell
  /// reads it through the ONE thing an entry's presence does change: a later
  /// table row at the same location is an ARRIVAL either way, but an entry that
  /// SURVIVED is still held beside it and one that was retired is not.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_whole_root_walk_report_retires_a_stale_device_only_record() {
    // Root on mount 42. The decline below names the SAME mount id on a different
    // device — a btrfs subvolume, which has no mountinfo row ever and is exempt
    // from every condemnation mechanism.
    let fs = FakeFs::with_root_mnt_id(1, 42);
    fs.answer_refresh(Vec::new(), true);
    let rig = fanotify_rig_ticking(fs);
    let scope = watch(&rig, "/r").await;

    rig.fs.send_walk_boundaries(
      "/r",
      vec![crate::os::DeclinedBoundary {
        location: PathBuf::from("/r/sub"),
        dev: 9,
        mnt_id: Some(42),
      }],
    );
    assert!(
      tokio::time::timeout(Duration::from_millis(200), rig.events.recv())
        .await
        .is_err(),
      "staging: an exempt record is not a departure on any tick"
    );

    // The post-loss reseed re-walks the whole root and declines NOTHING: the
    // subvolume was deleted while a loss window ate its removal record.
    // Taken on the root the core holds — mount 42, the id the fake reports — so
    // the generation is the scope's own to install.
    rig
      .fs
      .send_whole_root_boundaries("/r", Vec::new(), Some(42), 1);
    // FENCED, because nothing else orders this post against the one below it. A
    // report waits on the source lane, the select's LAST arm, while a tick's
    // mount refresh completes on `op_rx`, its FIRST — so a read that lands
    // anywhere in this window reaches the core AHEAD of the generation, and the
    // row below then CONFIRMS the record instead of arriving at it. Confirming
    // makes it row-confirmed — mount-backed, the partition a generation retires
    // nothing from — so the arrival never comes and this cell waits out its whole
    // budget, which is exactly how it failed on a CI runner and never here.
    //
    // What that interleaving costs in PRODUCTION is one extra located cover, not
    // this silence, and the difference is the row's identity. A real mountinfo row
    // at that location carries the departed/arrived mount's OWN id, which differs
    // from the record's, so `identity_changed` fires and the confirmation is a
    // covered REPLACEMENT; and even a silent confirmation only survives until the
    // next authoritative refresh that does not list the row, which condemns the
    // now-mount-backed record, covers it once, and drops it. Over-signal, and it
    // converges in one refresh.
    //
    // The silent leg needs a row whose KNOWN identity halves both agree with the
    // record's — here, the root's own mount id beside the subvolume's device — and
    // an authoritative table cannot carry the first. Within one proven-still
    // namespace generation every listed mount is a distinct live `struct mount`,
    // legacy mount ids are unique among live mounts, and the root's own mount is
    // live at the `statx` that reports `root_mnt_id`; `crate::os::mount_sample`
    // rejects the pair outright when the namespace moved between the two, which is
    // what makes that an enforced invariant rather than an assumption. (Round 8
    // asserted it instead, and the assertion was wrong for the code as it then
    // stood: the table and the root stat were unsynchronized samples, and mount
    // ids are allocated lowest-free.) So the fixture's identity is a CELL
    // construction, and this fence is what keeps it from reading as a verdict.
    assert!(
      settle(|| rig.fs.boundaries_ingested("/r")).await,
      "staging: the generation reached the core before any row could confirm the \
       record"
    );

    // A row now appears at the same location with the identity the record held.
    // With the record retired this is an ARRIVAL and covers; with the record
    // still standing it is a silent confirmation.
    rig.fs.answer_refresh(
      vec![crate::os::MountRow {
        location: PathBuf::from("/r/sub"),
        mnt_id: Some(42),
        parent_id: None,
        dev: Some(9),
      }],
      true,
    );

    let (s, change) = next_event(&rig).await;
    assert_eq!(s, scope);
    assert!(
      change.kind().is_rescan(),
      "an arrival shadows ground the consumer may have read: {change:?}"
    );
    assert_eq!(
      change.location(),
      &loc(&["sub"]),
      "and the generation really did retire the stale record — the row had \
       nothing to confirm: {change:?}"
    );
  }

  fn attributed(anchors: &[tributary_proto::WatchId], mask: u32, name: &[u8]) -> RawLinuxEvent {
    RawLinuxEvent::Inotify {
      anchors: anchors.to_vec(),
      event: RawInotifyEvent {
        wd: 1,
        mask: InotifyMask(mask),
        cookie: 0,
        name: Some(name.to_vec()),
      },
    }
  }

  const IN_CREATE: u32 = 0x0000_0100;

  /// Registration → root arm at spawn → enumerate against the fake tree →
  /// discovered directory armed → its own enumerate → ONE closing `Rescan` at
  /// coverage settle. The whole dormant vocabulary, driven by the real loop.
  ///
  /// Was `descending_watch_inventories_and_descends`, which drained three
  /// inventory `Created`s. A registration reports no inventory (42-10) — the
  /// contract says pre-existing state is not a change — so the delivery half
  /// inverts: the crawl is silent and its window closes with one `Rescan` at the
  /// scope root. The DESCENT half, which is what the rest of this cell is about,
  /// is asserted exactly as before.
  #[tokio::test(flavor = "multi_thread")]
  async fn descending_watch_descends_without_an_inventory() {
    let rig = inotify_rig();
    rig.fs.put("/r/a.txt", FileKind::File, 10);
    rig.fs.put("/r/sub", FileKind::Dir, 11);
    rig.fs.put("/r/sub/inner.txt", FileKind::File, 12);
    let scope = watch(&rig, "/r").await;

    // The crawl's one signal, and it postdates every read the crawl performed.
    fence_birth_crawl(&rig, scope, "/r").await;
    assert!(
      tokio::time::timeout(Duration::from_millis(200), rig.events.recv())
        .await
        .is_err(),
      "and nothing else: a registration announces no inventory at any depth"
    );
    settle(|| {
      rig
        .fs
        .enumerates()
        .iter()
        .any(|(_, p)| p == std::path::Path::new("/r/sub"))
    })
    .await;
    let arms = rig.fs.arms();
    assert!(
      arms
        .iter()
        .any(|(_, p)| p == std::path::Path::new("/r/sub")),
      "the discovered directory was armed: {arms:?}"
    );
  }

  /// End to end: a same-DEVICE child on a different MOUNT (a `mount --bind` of a
  /// same-superblock directory) is lowered `Other` and never armed/descended,
  /// while a same-mount sibling is. The device check alone would descend into the
  /// bind (its device equals the root's) and cover an out-of-root subtree — the
  /// mount-id fence is what closes it. Drives the whole path: the fake source
  /// reports the root mount id, the core carries it, the enumerate lowers by it.
  #[tokio::test(flavor = "multi_thread")]
  async fn descending_does_not_descend_a_same_device_bind_mount() {
    let rig = inotify_rig_mnt(42);
    // `bound` shares the device (1) but sits on mount 77 (a bind); `here` is on the
    // root mount (42). Both are directories with children the walk would descend if
    // it entered them.
    rig.fs.put_on_mount("/r/bound", FileKind::Dir, 20, 77);
    rig.fs.put("/r/bound/hidden.txt", FileKind::File, 21);
    rig.fs.put("/r/here", FileKind::Dir, 22);
    rig.fs.put("/r/here/seen.txt", FileKind::File, 23);
    let _scope = watch(&rig, "/r").await;

    // The in-root child directory `here` is enumerated (descended); the bind `bound`
    // never is.
    settle(|| {
      rig
        .fs
        .enumerates()
        .iter()
        .any(|(_, p)| p == std::path::Path::new("/r/here"))
    })
    .await;
    let enumerates = rig.fs.enumerates();
    assert!(
      !enumerates
        .iter()
        .any(|(_, p)| p == std::path::Path::new("/r/bound")),
      "a same-device bind on a different mount is never descended: {enumerates:?}"
    );
    let arms = rig.fs.arms();
    assert!(
      arms
        .iter()
        .any(|(_, p)| p == std::path::Path::new("/r/here")),
      "the same-mount child directory is armed: {arms:?}"
    );
    assert!(
      !arms
        .iter()
        .any(|(_, p)| p == std::path::Path::new("/r/bound")),
      "the bind-mount directory is lowered but never armed: {arms:?}"
    );
  }

  /// PREVENTION, end to end: a directory the Monitor learns from a `Created`
  /// record — the arm the enumerate fence NEVER judges — is refused when it lands
  /// across the scope's mount frame.
  ///
  /// This is the hole the decline alone cannot close. No enumerate runs between
  /// the record and the arm, and inotify's `Created` compiles to a bare record
  /// with no identity, so the executor's own object guard is `None` and passes
  /// whatever it opens. Without the frame refusal the watch installs on the far
  /// side of the bind and the live stream walks straight through a boundary the
  /// crawl honours.
  ///
  /// Refusal is observable three ways: the arm is ATTEMPTED (this is not the
  /// exclusion fence quietly dropping the record), no watch installs, and the
  /// slot's cold enumerate — which only a successful arm queues — never runs.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_created_directory_across_a_mount_boundary_is_refused_not_armed() {
    const IN_ISDIR: u32 = 0x4000_0000;
    let rig = inotify_rig_mnt(42);
    let _scope = watch(&rig, "/r").await;
    settle(|| !rig.fs.enumerates().is_empty()).await;
    let root_watch = rig
      .fs
      .enumerates()
      .first()
      .map(|(watch, _)| *watch)
      .expect("the root enumerated");

    // The bind lands, and the create announces it. Same device as the root, a
    // different mount (77) — the boundary only the mount fence sees.
    rig.fs.put_on_mount("/r/bound", FileKind::Dir, 30, 77);
    rig.fs.put("/r/bound/hidden.txt", FileKind::File, 31);
    rig.fs.send_inotify_batch(
      "/r",
      vec![attributed(&[root_watch], IN_CREATE | IN_ISDIR, b"bound")],
    );

    let armed = settle(|| {
      rig
        .fs
        .arms()
        .iter()
        .any(|(_, p)| p == Path::new("/r/bound"))
    })
    .await;
    assert!(
      armed,
      "the arm is issued — and then refused, not suppressed"
    );
    // Give a successful install every chance to publish its watch and queue its
    // read before the negative is read.
    for _ in 0..30 {
      tokio::task::yield_now().await;
      tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let enumerates = rig.fs.enumerates();
    assert!(
      !enumerates.iter().any(|(_, p)| p == Path::new("/r/bound")),
      "a refused arm queues no cold read, so the subtree beyond the boundary is \
       never walked: {enumerates:?}"
    );
    let armed_watches: Vec<WatchId> = rig
      .fs
      .arms()
      .iter()
      .filter(|(_, p)| p == Path::new("/r/bound"))
      .map(|(watch, _)| *watch)
      .collect();
    let live = rig.fs.live_watches();
    assert!(
      armed_watches.iter().all(|watch| !live.contains(watch)),
      "and nothing installed: {armed_watches:?} vs {live:?}"
    );
  }

  /// The same refusal, driven by the DEVICE half of the frame: a btrfs
  /// subvolume, which carries the ROOT's own mount id and would install happily
  /// under a mnt-id-only check.
  ///
  /// The design names that alternative and declines it, and this cell is why —
  /// the refusal and the enumerate decline must agree about what a boundary is,
  /// and `crosses_mount_boundary` fires on `device_boundary || mount_boundary`.
  ///
  /// The terminal here is different from the bind's and it is ACCEPTED: a
  /// subvolume has no mountinfo row, so no refresh arrival ever covers it and no
  /// crawl re-runs the decline. The slot becomes a persistent deficit — signalled
  /// on every sync cookie, never silent.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_created_directory_across_the_device_belt_is_refused_not_armed() {
    const IN_ISDIR: u32 = 0x4000_0000;
    let rig = inotify_rig_mnt(42);
    let scope = watch(&rig, "/r").await;
    settle(|| !rig.fs.enumerates().is_empty()).await;
    let root_watch = rig
      .fs
      .enumerates()
      .first()
      .map(|(watch, _)| *watch)
      .expect("the root enumerated");

    // The subvolume: a foreign DEVICE (99) on the root's OWN mount (42).
    rig.fs.put_on_device("/r/subvol", FileKind::Dir, 30, 99);
    rig.fs.send_inotify_batch(
      "/r",
      vec![attributed(&[root_watch], IN_CREATE | IN_ISDIR, b"subvol")],
    );

    let armed = settle(|| {
      rig
        .fs
        .arms()
        .iter()
        .any(|(_, p)| p == Path::new("/r/subvol"))
    })
    .await;
    assert!(armed, "the arm is issued");
    for _ in 0..30 {
      tokio::task::yield_now().await;
      tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let enumerates = rig.fs.enumerates();
    assert!(
      !enumerates.iter().any(|(_, p)| p == Path::new("/r/subvol")),
      "the device belt refuses it exactly as the mount fence refuses a bind — a \
       mnt-id-only check would have walked straight in: {enumerates:?}"
    );
    let armed_watches: Vec<WatchId> = rig
      .fs
      .arms()
      .iter()
      .filter(|(_, p)| p == Path::new("/r/subvol"))
      .map(|(watch, _)| *watch)
      .collect();
    let live = rig.fs.live_watches();
    assert!(
      armed_watches.iter().all(|watch| !live.contains(watch)),
      "nothing installed: {armed_watches:?} vs {live:?}"
    );
    // The refusal reaches the consumer as coverage, which is what makes the
    // deficit terminal acceptable rather than a silent hole.
    let mut covered = false;
    for _ in 0..8 {
      let Ok(Ok((s, _root, change))) =
        tokio::time::timeout(Duration::from_millis(500), rig.events.recv()).await
      else {
        break;
      };
      if s == scope && change.kind().is_rescan() && change.location() == &loc(&["subvol"]) {
        covered = true;
        break;
      }
    }
    assert!(covered, "the refused slot stands its located Rescan");
  }

  /// The UNKNOWN-FRAME legs, stated as their own cell because the whole fake
  /// harness rests on them.
  ///
  /// Below Linux 5.8 there is no `STATX_MNT_ID`, so a scope's frame and every
  /// object's mount id read `None` — and an off-Linux fake answers no frame at
  /// all. The refusal's truth table PASSES every unknown leg, exactly as
  /// `crosses_mount_boundary`'s own `None` legs do. Invert them and this cell
  /// fails alongside most of the suite: an arm with nothing to compare against is
  /// not a crossing, and treating it as one refuses every watch on those hosts.
  #[tokio::test(flavor = "multi_thread")]
  async fn an_unknown_scope_frame_refuses_no_arm() {
    const IN_ISDIR: u32 = 0x4000_0000;
    // `inotify_rig` reports NO root mount id — the pre-5.8 / off-Linux shape.
    let rig = inotify_rig();
    let _scope = watch(&rig, "/r").await;
    settle(|| !rig.fs.enumerates().is_empty()).await;
    let root_watch = rig
      .fs
      .enumerates()
      .first()
      .map(|(watch, _)| *watch)
      .expect("the root enumerated");

    rig.fs.put("/r/newdir", FileKind::Dir, 30);
    rig.fs.send_inotify_batch(
      "/r",
      vec![attributed(&[root_watch], IN_CREATE | IN_ISDIR, b"newdir")],
    );

    let read = settle(|| {
      rig
        .fs
        .enumerates()
        .iter()
        .any(|(_, p)| p == Path::new("/r/newdir"))
    })
    .await;
    assert!(
      read,
      "an unknown frame fences nothing: the created directory arms and \
       cold-reads exactly as it always did"
    );
    let armed_watches: Vec<WatchId> = rig
      .fs
      .arms()
      .iter()
      .filter(|(_, p)| p == Path::new("/r/newdir"))
      .map(|(watch, _)| *watch)
      .collect();
    let live = rig.fs.live_watches();
    assert!(
      armed_watches.iter().any(|watch| live.contains(watch)),
      "and its watch is installed: {armed_watches:?} vs {live:?}"
    );
  }

  /// A live inotify record injected through the real transport reaches the
  /// consumer as a depth-one change on the right anchor.
  #[tokio::test(flavor = "multi_thread")]
  async fn live_inotify_records_flow() {
    let rig = inotify_rig();
    let _scope = watch(&rig, "/r").await;
    // The root's Monitor watch is the first minted id under this scope; the
    // arm recording carries it.
    settle(|| !rig.fs.enumerates().is_empty()).await;
    let root_watch = rig
      .fs
      .enumerates()
      .first()
      .map(|(watch, _)| *watch)
      .expect("the root enumerated");
    rig.fs.put("/r/new.txt", FileKind::File, 20);
    rig
      .fs
      .send_inotify_batch("/r", vec![attributed(&[root_watch], IN_CREATE, b"new.txt")]);
    loop {
      let (_scope, change) = next_event(&rig).await;
      if change.kind().is_created() && change.location() == &loc(&["new.txt"]) {
        break;
      }
    }
  }

  /// A kernel IN_IGNORED for a child anchor resolves it end to end: the
  /// Monitor drops the node and the executor is told to disarm it.
  #[tokio::test(flavor = "multi_thread")]
  async fn kernel_teardown_disarms_the_child() {
    let rig = inotify_rig();
    rig.fs.put("/r/sub", FileKind::Dir, 11);
    let _scope = watch(&rig, "/r").await;
    settle(|| {
      rig
        .fs
        .arms()
        .iter()
        .any(|(_, p)| p == std::path::Path::new("/r/sub"))
    })
    .await;
    let child = rig
      .fs
      .arms()
      .iter()
      .find(|(_, p)| p == std::path::Path::new("/r/sub"))
      .map(|(watch, _)| *watch)
      .expect("child armed");
    const IN_IGNORED: u32 = 0x0000_8000;
    rig.fs.send_inotify_batch(
      "/r",
      vec![RawLinuxEvent::Inotify {
        anchors: vec![child],
        event: RawInotifyEvent {
          wd: 2,
          mask: InotifyMask(IN_IGNORED),
          cookie: 0,
          name: None,
        },
      }],
    );
    settle(|| rig.fs.disarms().contains(&child)).await;
  }

  /// Object-correct arming, end to end on the fake platform: an object replaced
  /// between the enumerate that discovered it and its arm is refused as `Gone`,
  /// and the Monitor's drop+rescan heals. The enumerate reports the child at its
  /// ORIGINAL inode (so the Monitor node carries that identity), while the object
  /// currently at the path has a DIFFERENT inode — modeling a rename/replace that
  /// slipped into the enumerate→arm window. The arm's identity check catches it,
  /// so the watch never installs on the wrong object.
  #[tokio::test(flavor = "multi_thread")]
  async fn arm_identity_mismatch_is_gone_and_rescans() {
    let rig = inotify_rig();
    // The object at /r/sub is inode 99, but the cold enumerate reports it as
    // inode 11 (the identity the Monitor descends with).
    rig.fs.put("/r/sub", FileKind::Dir, 99);
    rig.fs.enumerate_answer(
      "/r",
      crate::core::RawEnumerate::Listed {
        entries: vec![crate::core::RawDirEntry {
          name: b"sub".to_vec(),
          kind: FileKind::Dir,
          dev: 1,
          ino: 11,
          mnt_id: None,
        }],
        complete: true,
      },
    );
    let _scope = watch(&rig, "/r").await;

    // The /r/sub arm is attempted with the stale identity (11) against the live
    // object (99): a mismatch, refused as Gone.
    settle(|| {
      rig
        .fs
        .arms()
        .iter()
        .any(|(_, p)| p == std::path::Path::new("/r/sub"))
    })
    .await;

    // The Monitor heals through a rescan (the dropped subtree's coverage is
    // restored by the standing terminal reconciliation).
    let mut saw_rescan = false;
    for _ in 0..8 {
      let (_scope, change) = next_event(&rig).await;
      if change.kind().is_rescan() {
        saw_rescan = true;
        break;
      }
    }
    assert!(
      saw_rescan,
      "a mismatched arm drops the subtree and rescans to heal"
    );
  }

  /// How many arms have been executed at `path`.
  fn arms_at(rig: &Rig, path: &str) -> usize {
    rig
      .fs
      .arms()
      .iter()
      .filter(|(_, p)| p == std::path::Path::new(path))
      .count()
  }

  /// How many enumerates have been executed at `path`.
  fn enumerates_at(rig: &Rig, path: &str) -> usize {
    rig
      .fs
      .enumerates()
      .iter()
      .filter(|(_, p)| p == std::path::Path::new(path))
      .count()
  }

  /// A read that loss recovery supersedes cannot be cancelled — its blocking
  /// job is already detached — and the watch it was reading for is re-added
  /// under the SAME id. The anchor that re-add publishes must therefore survive
  /// the stranded read: an anchor is claimed at the DISPATCH that decided the
  /// read, so a job running long after its read was superseded carries the
  /// publication it was given and cannot reach for a successor's.
  ///
  /// Two losses stage exactly that ordering. The first strands `/r/a`'s
  /// recovery read on the pool; the second re-adds `/r/a` under its own id and
  /// publishes a fresh anchor while that read is still stranded; only then is
  /// the stranded read let go.
  ///
  /// Fail-on-old: with the anchor claimed by `WatchId` when the job finally
  /// runs, the second publication has already replaced the first in the shared
  /// table and the two reads SPLIT it — one lists through it, the other finds
  /// nothing and falls back to the absolute path, which a rename can point at a
  /// different directory whose children are then bound to this watch's node.
  /// The transport generation does not separate the two: a loss re-proof
  /// re-arms on the same transport, so both publications carry one generation.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_stranded_read_keeps_its_own_anchor_across_a_reproof_readd() {
    let rig = inotify_rig();
    rig.fs.put("/r/a", FileKind::Dir, 11);
    let _scope = watch(&rig, "/r").await;
    settle(|| enumerates_at(&rig, "/r/a") == 1).await;
    let child = rig
      .fs
      .arms()
      .into_iter()
      .find(|(_, p)| p == std::path::Path::new("/r/a"))
      .map(|(w, _)| w)
      .expect("/r/a armed by the cold discovery");

    // Strand `/r/a`'s reads alone: the root's own re-reads must stay free, or
    // the recovery never gets as far as re-adding the child.
    let hold = rig.fs.hold_enumerates_at("/r/a");
    rig.fs.send_lossy("/r");
    assert!(
      settle(|| hold.captured() >= 1).await,
      "staging: the recovery's read of /r/a must be STRANDED on the pool"
    );

    // The second loss re-adds /r/a under the same id and publishes a fresh
    // anchor for it — with the first read still stranded, which is the whole
    // race.
    rig.fs.send_lossy("/r");
    assert!(
      settle(|| arms_at(&rig, "/r/a") == 3 && hold.captured() >= 2).await,
      "staging: /r/a must be re-added a second time while its earlier read is stranded"
    );
    assert_eq!(
      enumerates_at(&rig, "/r/a"),
      1,
      "staging: neither stranded read has run yet"
    );

    hold.release();
    // Waited on the observable the assertions below actually read, and the
    // verdict asserted. The two are not interchangeable: the fake records an
    // execution in `enumerates` and its dispatch-time anchor in
    // `enumerate_anchors` under two separate locks, back to back, so a settle on
    // the enumerate COUNT can be satisfied while the third anchor has not landed
    // yet — and with the verdict discarded, that window and an expired budget
    // both degraded into the length mismatch below, reported as a staging
    // failure of something that had merely not happened yet.
    let anchors_for_child = || -> Vec<Option<u64>> {
      rig
        .fs
        .enumerate_anchors()
        .into_iter()
        .filter(|(w, _)| *w == child)
        .map(|(_, anchor)| anchor)
        .collect()
    };
    assert!(
      settle(|| anchors_for_child().len() == 3).await,
      "staging: the birth read plus one per loss ({:?})",
      anchors_for_child()
    );
    let listings = anchors_for_child();
    assert_eq!(
      listings.len(),
      3,
      "staging: the birth read plus one per loss ({listings:?})"
    );
    assert!(
      listings.iter().all(Option::is_some),
      "every read of /r/a listed through an anchor — none was left listing the path ({listings:?})"
    );
    let distinct: BTreeSet<Option<u64>> = listings.iter().copied().collect();
    assert_eq!(
      distinct.len(),
      listings.len(),
      "no two reads listed through one publication ({listings:?})"
    );
  }

  /// Close with an enumerate parked on the blocking pool: the listing is
  /// droppable (no OS resource — the Monitor node dies with its scope), so
  /// close resolves quiescent without waiting for it.
  #[tokio::test(flavor = "multi_thread")]
  async fn close_with_in_flight_enumerate_is_quiescent() {
    let rig = inotify_rig();
    let hold = rig.fs.hold_enumerates();
    let _scope = watch(&rig, "/r").await;
    assert!(
      settle(|| !rig.fs.enumerates().is_empty() || rig.fs.spawns() > 0).await,
      "staging: an enumerate must be IN FLIGHT when close begins, or this closes over an idle driver"
    );
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig.commands.send(Command::Close { reply }).await.unwrap();
    let quiesced = on_reply.await.expect("close replies");
    assert_eq!(quiesced, 0, "an in-flight enumerate never blocks close");
    hold.release();
  }

  /// Close with an arm parked on the blocking pool: equally droppable — the
  /// wd (if the arm did install one) is reclaimed when the scope's stream
  /// teardown closes the source fd.
  #[tokio::test(flavor = "multi_thread")]
  async fn close_with_in_flight_arm_is_quiescent() {
    let rig = inotify_rig();
    rig.fs.put("/r/sub", FileKind::Dir, 11);
    // The ROOT arm must complete — registration resolves on it — so gate the
    // cold listing instead, and only then gate arms: the child arm the
    // released listing queues is the one that parks.
    let enum_hold = rig.fs.hold_enumerates();
    let _scope = watch(&rig, "/r").await;
    let hold = rig.fs.hold_arms();
    enum_hold.release();
    // Wait until the cold listing landed (the child arm it queued is parked).
    assert!(
      settle(|| !rig.fs.enumerates().is_empty()).await,
      "staging: the cold listing must land, so the arm it queues is the one parked when close begins"
    );
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig.commands.send(Command::Close { reply }).await.unwrap();
    let quiesced = on_reply.await.expect("close replies");
    assert_eq!(quiesced, 0, "an in-flight arm never blocks close");
    hold.release();
  }

  /// The orderly close DETACHES every live scope, exactly as an ordinary
  /// `TeardownStream` does — so the executor's arm port and the scope's retained
  /// anchors are reclaimed at the close reply, not whenever the last detached job
  /// holding an `ops` clone happens to finish.
  ///
  /// The two halves are in tension, which is the whole point: a parked enumerate
  /// is deliberately NOT in the close tally (`close_with_in_flight_enumerate_is_
  /// quiescent` pins that), so an `Ok(0)` reply says nothing about it — and
  /// without the sweep's detach, that uncounted job is the only thing standing
  /// between a closed transport and its still-attached port. This cell holds one
  /// across the close and requires the detach anyway.
  ///
  /// The port is witnessed through the generation fence the executor answers arms
  /// on: an arm carrying the scope's ATTACHED generation executes, and one
  /// carrying a generation no longer attached refuses `Gone` and records a stale
  /// arm. The pre-close leg is what makes the post-close leg mean something — it
  /// proves the generation probed is the live one, so the refusal after close can
  /// only be the detach. (The fake models the port table alone; anchors are the
  /// real executor's half of the same purge, which `detach_scope` performs under
  /// one lock.)
  ///
  /// Fail-on-old: with the close sweep marking the registry dead but not
  /// detaching, the post-close arm still finds the attached generation and
  /// INSTALLS, so no stale arm is recorded and this fails.
  #[tokio::test(flavor = "multi_thread")]
  async fn an_orderly_close_detaches_every_live_scope() {
    // The first spawned scope's transport generation: lanes are minted from zero
    // and this rig spawns exactly one stream.
    const LANE: u64 = 0;

    /// Runs one arm through the executor's control path under `LANE`, handing
    /// back the outcome it resolved to.
    fn arm(rig: &Rig, scope: ScopeId, watch: u64, path: &str) -> Option<WatchOutcome> {
      let watch = WatchId::new(NonZeroU64::new(watch).unwrap());
      rig
        .fs
        .batch_control(
          scope,
          LANE,
          vec![ControlRequest::Arm {
            watch,
            attempt: None,
            parent: watch,
            name: Segment::new("r"),
            path: Arc::new(PathBuf::from(path)),
            expected: None,
            frame: crate::os::ScopeFrame::default(),
          }],
        )
        .resolutions
        .first()
        .map(|resolution| resolution.outcome)
    }

    let rig = inotify_rig();
    // A detached job parked across the whole close: it holds an `ops` clone —
    // the port and anchor maps with it — and the reply does not count it. The
    // registration still resolves, because it resolves on the root ARM.
    let parked = ReleasedOnDrop(rig.fs.hold_enumerates());
    let scope = watch(&rig, "/r").await;
    assert!(
      settle(|| parked.captured() >= 1).await,
      "staging: a detached enumerate must be PARKED across the close"
    );

    // The positive control: LANE is the scope's attached transport, so this arm
    // EXECUTES rather than refusing as a leftover.
    let armed = arm(&rig, scope, 9001, "/r");
    assert!(
      matches!(
        armed,
        Some(WatchOutcome::Installed(_) | WatchOutcome::Aliased(_))
      ),
      "staging: the probed generation must be the attached one: {armed:?}"
    );
    let stale_before = rig.fs.stale_arms().len();

    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig.commands.send(Command::Close { reply }).await.unwrap();
    let quiesced = on_reply.await.expect("close replies");
    assert_eq!(
      quiesced, 0,
      "the parked enumerate is not an outstanding obligation — the close contract is unchanged"
    );

    // The port went with the sweep: the same generation now refuses.
    let after = arm(&rig, scope, 9002, "/r");
    parked.release();
    assert!(
      matches!(
        after,
        Some(WatchOutcome::Failed(tributary_proto::WatchError::Gone))
      ),
      "the close sweep detached the scope's port: {after:?}"
    );
    assert_eq!(
      rig.fs.stale_arms().len(),
      stale_before + 1,
      "the post-close arm resolved against NO attached transport"
    );
  }

  /// The tree-equality storm under the descending profile: the fake driver
  /// services enumerates against the fake tree, arms fail sporadically, and
  /// listings degrade — the consumer's reconstructed view still converges.
  ///
  /// One seed under miri, for the address-space reason `storm_no_silent_loss_
  /// converges` documents.
  #[tokio::test(flavor = "multi_thread")]
  async fn descending_storm_converges() {
    let default_seeds: u64 = if cfg!(miri) { 1 } else { 8 };
    let seeds: u64 = std::env::var("TRIBUTARY_FS_STORM_SEEDS")
      .ok()
      .and_then(|v| v.parse().ok())
      .unwrap_or(default_seeds);
    for seed in 1..=seeds {
      descending_storm_seed(seed).await;
    }
  }

  async fn descending_storm_seed(seed: u64) {
    let rig = inotify_rig();
    let mut s = seed.wrapping_mul(0x9E37_79B9).wrapping_add(7);
    let mut next_ino = 100u64;
    for i in 0..(1 + xorshift(&mut s) % 3) {
      rig.fs.put(format!("/r/d{i}"), FileKind::Dir, 50 + i);
    }
    let _scope = watch(&rig, "/r").await;
    let mut view: BTreeSet<PathBuf> = BTreeSet::new();
    let mut last_epoch: Option<Epoch> = None;
    let mut last_root: Option<PathBuf> = None;
    let mut live: Vec<PathBuf> = Vec::new();

    for _ in 0..24 {
      match xorshift(&mut s) % 6 {
        0 | 1 => {
          next_ino += 1;
          let dir = if xorshift(&mut s).is_multiple_of(2) {
            "/r"
          } else {
            "/r/d0"
          };
          let path = PathBuf::from(format!("{dir}/f{next_ino}"));
          rig.fs.put(&path, FileKind::File, next_ino);
          live.push(path);
          // The mutation's report is a loss: the in-order signal must cover
          // it (the descending re-arm enumerates the tree back into view).
          rig.fs.send_lossy("/r");
        }
        2 if !live.is_empty() => {
          let i = (xorshift(&mut s) as usize) % live.len();
          let path = live.swap_remove(i);
          rig.fs.remove(&path);
          rig.fs.send_lossy("/r");
        }
        3 => {
          // A degraded (Partial) listing races the next re-arm; the bounded
          // retry re-reads the honest tree.
          rig.fs.enumerate_answer(
            "/r",
            crate::core::RawEnumerate::Listed {
              entries: Vec::new(),
              complete: false,
            },
          );
          rig.fs.send_lossy("/r");
        }
        4 => {
          // A sporadic arm failure: the Monitor drops the subtree and
          // rescans; the next re-arm (fresh default outcome) recovers it.
          rig
            .fs
            .fail_watch_at("/r/d0", tributary_proto::WatchError::NoSpace);
          rig.fs.send_lossy("/r");
        }
        _ => {
          rig.fs.send_lossy("/r");
        }
      }
      // Sometimes-lagging consumer.
      if xorshift(&mut s).is_multiple_of(3) {
        for _ in 0..(xorshift(&mut s) % 4) {
          match tokio::time::timeout(Duration::from_millis(100), rig.events.recv()).await {
            Ok(Ok((_, root, change))) => {
              apply_descending(
                &rig,
                &mut view,
                &mut last_epoch,
                &mut last_root,
                &root,
                &change,
              );
            }
            _ => break,
          }
        }
      }
      tokio::task::yield_now().await;
    }
    // Heal the sporadic arm failure and settle.
    rig.fs.alias_watch_at("/r/d0");
    rig.fs.send_lossy("/r");
    for _ in 0..25 {
      tokio::task::yield_now().await;
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
    while let Ok(Ok((_, root, change))) =
      tokio::time::timeout(Duration::from_millis(200), rig.events.recv()).await
    {
      apply_descending(
        &rig,
        &mut view,
        &mut last_epoch,
        &mut last_root,
        &root,
        &change,
      );
    }
    let tree = rig.fs.files_under("/r");
    assert_eq!(
      view, tree,
      "seed {seed}: the reconstructed view converges to the tree"
    );
  }

  /// The KR storm's reconstruction, with one descending addition: a `Rescan`
  /// re-reads the fake tree under its location (cold inventories then
  /// re-deliver what the re-read missed — extra `Created`s are idempotent).
  fn apply_descending(
    rig: &Rig,
    view: &mut BTreeSet<PathBuf>,
    last_epoch: &mut Option<Epoch>,
    last_root: &mut Option<PathBuf>,
    root: &Path,
    change: &Change,
  ) {
    apply(rig, view, last_epoch, last_root, root, change);
  }

  /// An inotify rig writing transitions into `registry`, for the deferred-grant
  /// never-live assertions.
  fn inotify_rig_with(registry: RecordingRegistry) -> Rig {
    let fs = FakeFs::new(1);
    fs.put("/r", FileKind::Dir, 1);
    fs.spawn_backend(BackendKind::Inotify);
    let (cmd_tx, cmd_rx) = async_channel::bounded(16);
    let (cleanup, cookie_wake) = cookie_ingress();
    let (ev_tx, ev_rx) = async_channel::bounded(64);
    tokio::spawn(run::<TokioRuntime, FakeFs>(
      inotify_config(),
      fs.clone(),
      cmd_rx,
      cookie_wake,
      ev_tx,
      registry,
    ));
    Rig {
      fs,
      commands: cmd_tx,
      cleanup,
      events: ev_rx,
    }
  }

  /// A descending scope is publicly live only once its ROOT ARM SUCCEEDS — the
  /// deferred grant commits there, so a FAILED root arm answers the caller `Err`
  /// and emits NOTHING. Without the deferred-aware fence the Monitor's root-watch
  /// failure would promote a terminal `Rescan` and DELIVER it (the scope's `root`
  /// is populated at spawn), a public event for a registration whose caller never
  /// got a handle. Draining well past every timer deadline still yields zero
  /// events — a never-live scope arms no dying-retry either.
  #[tokio::test(flavor = "multi_thread")]
  async fn failed_root_arm_answers_err_and_emits_nothing() {
    let registry = RecordingRegistry::default();
    let rig = inotify_rig_with(registry.clone());
    // The ROOT arm fails: the object vanished between the validated spawn and
    // the (absolute-path) open.
    rig
      .fs
      .fail_watch_at("/r", tributary_proto::WatchError::NotFound);

    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Watch {
        root: PathBuf::from("/r"),
        interest: tributary_proto::Interest::all(),
        reply,
      })
      .await
      .unwrap();
    let err = on_reply
      .await
      .expect("the watch replies")
      .expect_err("a failed root arm resolves the caller Err");
    assert!(
      matches!(err, WatchRootError::NotFound { .. }),
      "the arm failure lowers to the registration vocabulary: {err:?}"
    );

    // The scope went registry-live at spawn (before the arm), then dead when the
    // failed arm tore it down — reclaimed, never lingering.
    settle(|| !registry.dead().is_empty()).await;
    let scope = registry
      .live()
      .first()
      .map(|(scope, _, _)| *scope)
      .expect("the scope was recorded live at spawn");
    assert_eq!(
      registry.dead(),
      [scope],
      "a failed-root-arm scope is reclaimed via scope_dead"
    );

    // ZERO public events: the never-live fence dropped the Monitor's internal
    // failure Rescan, so nothing was ever queued. A never-live scope promotes no
    // terminal Rescan either, so there is no dying-retry timer to leak through —
    // draining under real-clock timeouts stays empty.
    for _ in 0..10 {
      tokio::task::yield_now().await;
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
      tokio::time::timeout(Duration::from_millis(200), rig.events.recv())
        .await
        .is_err(),
      "a never-publicly-live scope emits no event, ever"
    );
  }

  /// Closing while a root arm is still PENDING keeps the scope silent: the arm
  /// never resolves, so the scope never became publicly live — the deferred grant
  /// resolves `Err` at teardown and the fence drops any Monitor bookkeeping.
  #[tokio::test(flavor = "multi_thread")]
  async fn close_during_pending_root_arm_stays_silent() {
    let registry = RecordingRegistry::default();
    let rig = inotify_rig_with(registry.clone());
    // Hold every arm on the blocking pool: the ROOT arm parks, so the scope is
    // spawned-and-registry-live but not yet publicly live.
    let hold = rig.fs.hold_arms();

    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Watch {
        root: PathBuf::from("/r"),
        interest: tributary_proto::Interest::all(),
        reply,
      })
      .await
      .unwrap();
    // Wait until the scope is spawned (registry-live) with its root arm parked.
    assert!(
      settle(|| !registry.live().is_empty()).await,
      "staging: the scope must be spawned, with its root arm parked, before close"
    );

    let (creply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: creply })
      .await
      .unwrap();
    let _ = on_close.await.expect("close replies");
    hold.release();

    // The caller never receives a handle — the pending grant resolves to a
    // failure (a sent `Err`, or the reply sender dropped at close, which is
    // `Canceled`); either way it is NOT an `Ok(grant)`, so nothing went publicly
    // live. And no public event was ever emitted.
    let resolved = on_reply.await;
    assert!(
      !matches!(resolved, Ok(Ok(_))),
      "a scope closed before its root armed never hands back a live grant: {resolved:?}"
    );
    assert!(
      matches!(
        tokio::time::timeout(Duration::from_millis(200), rig.events.recv()).await,
        Err(_) | Ok(Err(_))
      ),
      "a scope closed before going publicly live emits nothing"
    );
  }

  /// A SUCCESSFUL root arm still delivers normally — the fence opens exactly at
  /// the arm, so records the arm's own coverage takes flow to the consumer. The
  /// regression guard that the deferred-aware fence did not over-tighten.
  ///
  /// Re-staged on a LIVE record. It used to loop until the bootstrap listing's
  /// `Created` for a pre-existing file arrived; registration reports no
  /// inventory, so that delivery is one the contract denies and the loop would
  /// never terminate. The claim being pinned is about the FENCE, not about the
  /// inventory — that a successful arm leaves delivery open — and the first
  /// record the armed root records proves it just as directly, while an
  /// over-tightened fence would swallow it exactly as it would have swallowed
  /// the inventory.
  #[tokio::test(flavor = "multi_thread")]
  async fn successful_root_arm_delivers_normally() {
    let rig = inotify_rig();
    rig.fs.put("/r/present.txt", FileKind::File, 10);
    let _scope = watch(&rig, "/r").await;
    // The root's arm succeeded — its post-arm read is what proves it, and the
    // recorded watch id is the anchor the live record below is attributed to.
    assert!(
      settle(|| !rig.fs.enumerates().is_empty()).await,
      "staging: the root arm succeeded and its post-arm read ran"
    );
    let root_watch = rig
      .fs
      .enumerates()
      .first()
      .map(|(watch, _)| *watch)
      .expect("the root enumerated");
    rig.fs.put("/r/live.txt", FileKind::File, 20);
    rig.fs.send_inotify_batch(
      "/r",
      vec![attributed(&[root_watch], IN_CREATE, b"live.txt")],
    );
    loop {
      let (_scope, change) = next_event(&rig).await;
      if change.kind().is_created() && change.location() == &loc(&["live.txt"]) {
        break;
      }
    }
  }

  /// How long a flood filler may stay parked in one send before it re-reads its
  /// stop flag: short enough that a guard's join is prompt, long enough that the
  /// re-registration between two parks is a rounding error against the 10 ms
  /// rounds every caller settles in.
  const FLOOD_STOP_POLL: Duration = Duration::from_millis(20);

  /// Sends one flood message, parking until the mailbox takes it, the channel
  /// closes, or `stop` is raised — `true` only if it was sent.
  ///
  /// The park is an async `send` driven by a thread-unpark waker rather than
  /// [`async_channel::Sender::send_blocking`], and the difference is what keeps
  /// every guard below joinable:
  ///
  /// - a parked `send_blocking` wakes ONLY when the channel drains or closes,
  ///   so once the driver stops consuming — an orderly close, a driver task
  ///   already past its loop — nothing will ever wake it and a join waits
  ///   forever;
  /// - this park leaves the send registered as a waiting sender for the whole
  ///   window, so it still completes the instant the driver consumes a command
  ///   (a filler that GAPPED would let the command-biased select reach the
  ///   source arm, the one thing every caller pins off), and it abandons the
  ///   send within [`FLOOD_STOP_POLL`] of the stop flag.
  ///
  /// Worker count is NOT the mechanism and must not be read as one: the fillers
  /// are dedicated OS threads, not runtime tasks, so no number of workers makes
  /// a consumer that is gone drain a full mailbox, and the `worker_threads`
  /// pinned by the cells below is about the driver's own parallelism.
  fn send_watching_stop(
    commands: &async_channel::Sender<Command>,
    message: Command,
    stop: &AtomicBool,
  ) -> bool {
    use core::future::Future;

    struct UnparkWaker(std::thread::Thread);
    impl std::task::Wake for UnparkWaker {
      fn wake(self: std::sync::Arc<Self>) {
        self.0.unpark();
      }

      fn wake_by_ref(self: &std::sync::Arc<Self>) {
        self.0.unpark();
      }
    }

    let waker = std::task::Waker::from(std::sync::Arc::new(UnparkWaker(std::thread::current())));
    let mut cx = std::task::Context::from_waker(&waker);
    let mut send = std::pin::pin!(commands.send(message));
    loop {
      if let std::task::Poll::Ready(sent) = send.as_mut().poll(&mut cx) {
        return sent.is_ok();
      }
      // Read the flag with the send still registered: a stop raised while this
      // thread was parked is observed on the very next wake, and one raised
      // between two polls no later than the timeout below.
      if stop.load(Ordering::SeqCst) {
        return false;
      }
      std::thread::park_timeout(FLOOD_STOP_POLL);
    }
  }

  /// Spawns `threads` dedicated OS-thread command fillers, each looping
  /// `message` into `commands` through [`send_watching_stop`] until `stop` is
  /// raised or the channel closes — the command-side flood body every guard in
  /// this module hands to its join.
  fn spawn_command_fillers(
    commands: &async_channel::Sender<Command>,
    stop: &std::sync::Arc<AtomicBool>,
    threads: usize,
    message: impl Fn() -> Command + Clone + Send + 'static,
  ) -> Vec<std::thread::JoinHandle<()>> {
    (0..threads)
      .map(|_| {
        let commands = commands.clone();
        let stop = std::sync::Arc::clone(stop);
        let message = message.clone();
        std::thread::spawn(move || {
          while !stop.load(Ordering::SeqCst) {
            if !send_watching_stop(&commands, message(), &stop) {
              break;
            }
          }
        })
      })
      .collect()
  }

  /// A hold released no later than its drop: a cell that parks pool jobs
  /// on a gate must release it on EVERY exit — a failing assert that skips
  /// the release leaves the job parked forever, and the test runtime's own
  /// shutdown then waits on it, turning one failed cell into a hung binary.
  struct ReleasedOnDrop(crate::driver::testing::HoldRelease);

  impl ReleasedOnDrop {
    fn release(&self) {
      self.0.release();
    }

    fn captured(&self) -> usize {
      self.0.captured()
    }
  }

  impl Drop for ReleasedOnDrop {
    fn drop(&mut self) {
      self.0.release();
    }
  }

  mod cover_fence {
    //! The set-cover effect-completion fence through the REAL loop: an acked
    //! reconcile's reply parks under its fence and resolves at SETTLE — when
    //! the grow's re-arm work has quiesced — never at effect-queue time. The
    //! core's fence table is unit-covered in `core/tests.rs`; these cells pin
    //! the driver wiring around it (parking, loop-top resolution, close).

    use super::*;
    use crate::watcher::{CoverOutcome, SkipReason};

    /// Sends an awaited `SetCover`, handing back its parked acknowledgement.
    async fn send_set_cover(
      rig: &Rig,
      scope: ScopeId,
      retained: &[&str],
    ) -> futures_channel::oneshot::Receiver<CoverOutcome> {
      let (reply, ack) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::SetCover {
          scope,
          retained: retained.iter().map(PathBuf::from).collect(),
          reply: Some(reply),
        })
        .await
        .unwrap();
      ack
    }

    /// Awaits a parked acknowledgement (pinned or not), bounded.
    async fn resolved(
      ack: impl std::future::Future<Output = Result<CoverOutcome, futures_channel::oneshot::Canceled>>,
    ) -> CoverOutcome {
      tokio::time::timeout(interpreted_secs(10), ack)
        .await
        .expect("the fence settles within the deadline")
        .expect("the driver answers the parked reply")
    }

    /// How many arms have been executed at `path`.
    fn arms_at(rig: &Rig, path: &str) -> usize {
      rig
        .fs
        .arms()
        .iter()
        .filter(|(_, p)| p == std::path::Path::new(path))
        .count()
    }

    /// A live descending rig over `/r` with the given child directories (at
    /// least one), whose registration window is not merely closed but SPENT — so
    /// the first fence a cell opens inherits nothing and a window these cells
    /// expect clean really is one.
    ///
    /// Three waits, and each covers a distinct hazard the next cannot:
    ///
    /// 1. **Every child's read ISSUED.** A later grow that coalesced into an
    ///    in-flight read rides an obligation the settle counter does not see and
    ///    is born lossy.
    /// 2. **The window's closing `Rescan` DELIVERED.** That crawl is the
    ///    registration's own re-arm-flavored one (42-10): it suppresses its
    ///    `Created`s and pays for them with one closing `Rescan` at the first
    ///    coverage settle. Issuing a read is not landing it, so wait (1) leaves
    ///    that `Rescan` in flight — and a `Rescan` routed inside a fence's window
    ///    degrades it, which is the loss signal working, not a defect. The
    ///    channel is only PEEKED (never drained), so a cell's own event
    ///    expectations are untouched, and this is the scope's first delivery by
    ///    construction — the suppressed crawl announces nothing before it.
    /// 3. **The loss it left SPENT.** Routing the `Rescan` marks the scope's
    ///    fence entry lossy, and that memory outlives the delivery: it is cleared
    ///    only by a settle observation, which for a per-directory scope must
    ///    first buy an ordering proof over a control round trip. A fence opened
    ///    inside that gap INHERITS the mark (see `CoverFence`'s lossy-window
    ///    rule) and settles `Degraded`. Waiting for the entry itself to go is
    ///    what makes the baseline clean rather than merely likely — the gap is
    ///    a round trip wide, and a loaded or instrumented runner walks straight
    ///    into it.
    ///
    /// Wait (3) is sound only behind wait (2): the entry is ABSENT both before
    /// the `Rescan` creates it and after the observation spends it, so the
    /// delivery is the edge that makes the emptiness mean the second one.
    async fn covered_rig(children: &[(&str, u64)]) -> (Rig, ScopeId) {
      covered_rig_capacity(children, 64).await
    }

    /// [`covered_rig`] with the consumer's event channel sized by the caller.
    ///
    /// At capacity ONE the staging leaves the channel FULL: the registration
    /// window's closing `Rescan` is the slot's occupant (wait (2) above proves it
    /// arrived, and nothing here drains it), so the very next change the scope
    /// produces is REFUSED. That is the state the backpressure cells need, and it
    /// is reached without injecting a single filler event.
    async fn covered_rig_capacity(
      children: &[(&str, u64)],
      event_capacity: usize,
    ) -> (Rig, ScopeId) {
      assert!(
        !children.is_empty(),
        "the helper's staging rests on the registration window installing at least one child"
      );
      let fs = FakeFs::new(1);
      for (path, ino) in children {
        fs.put(path, FileKind::Dir, *ino);
      }
      let rig = inotify_rig_fs_capacity(fs, event_capacity);
      let scope = watch(&rig, "/r").await;
      settle(|| {
        let enumerates = rig.fs.enumerates();
        children.iter().all(|(path, _)| {
          enumerates
            .iter()
            .any(|(_, p)| p == std::path::Path::new(path))
        })
      })
      .await;
      assert!(
        settle(|| !rig.events.is_empty()).await,
        "the registration window's closing `Rescan` reached the consumer"
      );
      assert!(
        cover_fence_entry_spent(&rig, scope).await,
        "and a settle observation spent the loss memory that `Rescan` left standing"
      );
      (rig, scope)
    }

    /// Waits for `scope` to hold no coverage-fence entry at all — no pending
    /// fence AND no accrued loss memory — so the next fence opened on it starts
    /// clean. Reports whether it got there, for a caller that is staging.
    #[must_use = "an expired budget leaves the baseline lossy, which is a staging failure"]
    async fn cover_fence_entry_spent(rig: &Rig, scope: ScopeId) -> bool {
      for _ in 0..200 {
        let (reply, on_reply) = futures_channel::oneshot::channel();
        rig
          .commands
          .send(Command::DebugCoverFenceEntry { scope, reply })
          .await
          .unwrap();
        if !on_reply.await.expect("the driver answers a debug probe") {
          return true;
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
        std::thread::sleep(settle_round_slice());
      }
      false
    }

    /// The sync cookie's write is parked on the SAME settle fence a cover ack
    /// rides: under a descending backend with re-arm work in flight, the
    /// cookie must not land until the coverage quiesces — otherwise a
    /// pre-sync change inside a mid-re-arm subtree was never kernel-reported
    /// and no queue ordering covers it. Once the re-arm settles, the write
    /// lands and the caller gets the cookie's path.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sync_cookie_write_parks_on_the_settle_fence() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;

      // Stall the grow: /r/drop's re-install parks on the blocking pool, so
      // the scope is NOT settled.
      let hold = rig.fs.hold_arms();
      let _ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;

      let (reply, mut on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::SyncRoot {
          scope,
          dir: PathBuf::from("/r"),
          name: ".tributaries-sync-1-2-3".to_owned(),
          ticket: ticket(),
          reply,
        })
        .await
        .unwrap();
      for _ in 0..40 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      assert!(
        futures_util::poll!(&mut on_reply).is_pending(),
        "the cookie write waits for the coverage to settle"
      );
      assert!(
        rig.fs.cookie_writes().is_empty(),
        "nothing was written while the re-arm was in flight"
      );

      hold.release();
      let path = on_reply
        .await
        .expect("the driver replies")
        .expect("the write lands once settled");
      assert_eq!(path, PathBuf::from("/r/.tributaries-sync-1-2-3"));
      assert_eq!(rig.fs.cookie_writes(), vec![path]);
    }

    /// Shrinks the live rig to `{/r/keep}` and awaits the ack: a prune grows
    /// nothing, so the fence settles at the next loop top, clean.
    async fn shrunk_to_keep(rig: &Rig, scope: ScopeId) {
      let ack = send_set_cover(rig, scope, &["/r/keep"]).await;
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Applied,
        "a prune-only reconcile settles clean"
      );
    }

    /// THE PUBLIC CONTRACT END TO END for the one loss that arrives with no cover
    /// of its own: an awaited reply over a standing classification stat reports
    /// `Degraded`, and the covering `Rescan` that verdict names is on the
    /// consumer's stream when the caller reads it.
    ///
    /// Emission, not delivery. `Degraded` promises only that a cover was emitted,
    /// so this cell gives the consumer room to take it and reads it off the
    /// stream; the sibling below runs the same window against a channel with no
    /// room and pins that the answer comes anyway.
    ///
    /// Every cover such a window could otherwise ride is absent by construction.
    /// The reconcile is a PURE grow — `/r/drop` is re-armed at the surviving
    /// `/r`, and a re-arm read stands no `Rescan` at all — and `/r/mystery`
    /// holds no watch, so the read that could not name its kind reconciled
    /// nothing for it: it booked the darkness and asked. The probe is held on
    /// the pool for the whole fence, so the answer that would end the loss never
    /// lands; and the deficit re-signal that eventually covers such a slot fires
    /// at a sync cookie's DISPATCH, which this reply passes nowhere near.
    ///
    /// The ORDERING is the assertion, and the non-blocking take is how it is
    /// made: the stream is emptied before the reconcile, and read again with
    /// `try_recv` the instant the ack resolves. A `Rescan` merely queued behind
    /// the answer is not on the stream yet, so the cell fails where a `recv`
    /// would have waited for it and passed.
    ///
    /// Mutation that kills it: stand no cover — drop the `stand_stat_cover` call
    /// from the settlement, or `Monitor::cover_stat_loss` behind it. The reply
    /// still says `Degraded`, and the consumer is told to re-enumerate by nothing
    /// at all.
    ///
    /// What this cell does NOT pin is the one-flush ORDERING. The driver sends the
    /// reply and flushes microseconds later on its own thread, so a wall-clock
    /// read from the woken caller cannot separate the two: a build that resolved
    /// the tranche where it stands passes this cell. The ordering is pinned
    /// deterministically at the core instead, where the standing pass is observed
    /// to report no verdict and to ask for the flush
    /// (`a_stat_cover_answers_behind_one_flush_however_busy_the_lane`, and the
    /// staging shared by its siblings).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stat_loss_degrade_reaches_its_caller_with_its_cover_on_the_stream() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;

      // An unclassifiable name at a slot the shrink left uncovered, with its
      // kind held unanswered for the whole fence.
      let probes = rig.fs.hold_probes();
      rig.fs.put("/r/mystery", FileKind::Unknown, 13);

      // Empty the stream, so a cover read off it below is this window's.
      while rig.events.try_recv().is_ok() {}

      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Degraded,
        "an unanswered kind over a slot the root covers with nothing is a loss"
      );
      let mut delivered = Vec::new();
      while let Ok((_, _, change)) = rig.events.try_recv() {
        delivered.push(change);
      }
      assert!(
        delivered
          .iter()
          .any(|change| change.kind().is_rescan() && change.location() == &loc(&[])),
        "the covering `Rescan` is on the stream the verdict names it to: {delivered:?}"
      );
      assert_eq!(
        rig.fs.probes(),
        0,
        "staging: and nothing answered the stat, so the loss stood throughout"
      );

      probes.release();
    }

    /// Stages a standing empty-slot stat over a FULL consumer channel: the
    /// registration `Rescan` holds the rig's one slot, the grow re-arms the
    /// pruned subtree and lists an unclassifiable name whose kind never comes
    /// back, and the settlement that follows stands its covering `Rescan` into a
    /// channel that refuses it.
    ///
    /// Hands back the acknowledgement and the held probe gate. The wait is
    /// two-part on purpose: the re-arm is waited for on its own observable, so
    /// the window's counted work is provably done and the standing stat is the
    /// only thing left between the fence and its verdict; and the rounds after it
    /// establish the two facts the cells below build on — the channel took
    /// nothing this window stood, and nothing answered the stat.
    async fn stat_loss_over_a_full_channel(
      rig: &Rig,
      scope: ScopeId,
    ) -> (
      futures_channel::oneshot::Receiver<CoverOutcome>,
      HoldRelease,
    ) {
      shrunk_to_keep(rig, scope).await;
      let probes = rig.fs.hold_probes();
      rig.fs.put("/r/mystery", FileKind::Unknown, 13);
      let ack = send_set_cover(rig, scope, &["/r/keep", "/r/drop"]).await;
      assert!(
        settle(|| arms_at(rig, "/r/drop") >= 2).await,
        "staging: the grow re-armed the pruned subtree, so the window's counted work is done"
      );
      for _ in 0..40 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      assert_eq!(
        rig.events.len(),
        1,
        "staging: the channel never had room, so nothing this window stood was delivered"
      );
      assert_eq!(
        rig.fs.probes(),
        0,
        "staging: and nothing answered the stat, so the loss stood throughout"
      );
      (ack, probes)
    }

    /// THE ANSWER IS NOT GATED ON CONSUMER PROGRESS, for BOTH consumers of the
    /// settlement report. The channel here is full and stays full,
    /// with nobody reading it: the loop-top `try_send` refuses the covering
    /// `Rescan` and parks it (INV-PARK) to be retried later, and the awaited
    /// `set_cover` reply is answered `Degraded` over that refusal — because
    /// `Degraded` reports the emit, and the caller re-enumerates rather than
    /// waiting for an instruction only its own reading could deliver.
    ///
    /// A caller awaiting `set_cover` in the same task that drains its events is
    /// the shape this protects: gating the reply on delivery makes that caller
    /// wait on itself, with nothing internal to break the tie.
    ///
    /// The sync cookie fenced on the same tranche is the second consumer, and it
    /// dispatches too — the reply and the cookie write are the two arms of one
    /// settlement report, so a hold on either is a hold on both. The cookie's own
    /// ordering guarantee is untouched by this: it is a barrier over the scope's
    /// coverage, never a claim about the consumer's read position.
    ///
    /// Mutation that kills it: gate the resolution on the delivery — hold the
    /// tranche until an offer is accepted (a delivery watermark, a lane-state
    /// inference, a queue probe). Nothing here ever accepts one, so the reply and
    /// the cookie are both stranded and the cell spends its deadline. This is a
    /// LIVENESS failure, and the one a caller can inflict on itself.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stat_loss_degrade_answers_over_a_full_consumer_channel() {
      let (rig, scope) = covered_rig_capacity(&[("/r/keep", 11), ("/r/drop", 12)], 1).await;
      assert_eq!(
        rig.events.len(),
        1,
        "staging: the registration `Rescan` fills the one slot the consumer has"
      );
      let (ack, probes) = stat_loss_over_a_full_channel(&rig, scope).await;

      // The second consumer of the same ordering: a sync cookie parked on this
      // scope's fence, whose write dispatches out of the same settlement report.
      let (reply, on_cookie) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::SyncRoot {
          scope,
          dir: PathBuf::from("/r"),
          name: ".tributaries-sync-9-9-9".to_owned(),
          ticket: ticket(),
          reply,
        })
        .await
        .unwrap();

      // NOTHING drains the channel — no `try_recv`, no drop — for the whole of
      // what follows. Both answers must arrive over a consumer that has made no
      // progress at all since the window opened.
      assert_eq!(
        tokio::time::timeout(interpreted_secs(10), ack)
          .await
          .expect("the reply never waits on the consumer reading an event")
          .expect("the driver answers the parked reply"),
        CoverOutcome::Degraded,
        "an unanswered kind over a slot the root covers with nothing is a loss"
      );
      let path = tokio::time::timeout(interpreted_secs(10), on_cookie)
        .await
        .expect("and neither does the sync fenced on the same tranche")
        .expect("the driver answers the parked reply")
        .expect("the write lands");
      assert_eq!(path, PathBuf::from("/r/.tributaries-sync-9-9-9"));
      assert_eq!(
        rig.events.len(),
        1,
        "the channel is still full and still unread: no delivery unblocked either answer"
      );

      // The refused cover is parked, not dropped: freeing the slot lets the
      // lane's own retry land it, BEHIND the verdict that named it.
      let (_, _, occupant) = rig
        .events
        .try_recv()
        .expect("the registration `Rescan` is the slot's occupant");
      assert!(occupant.kind().is_rescan(), "{occupant:?}");
      let floor = occupant.epoch();
      let covered = settle(|| {
        std::iter::from_fn(|| rig.events.try_recv().ok()).any(|(_, _, change)| {
          change.kind().is_rescan() && change.location() == &loc(&[]) && change.epoch() > floor
        })
      })
      .await;
      assert!(
        covered,
        "the parked cover is re-offered once the slot frees"
      );

      probes.release();
    }

    /// …and a consumer that is GONE is answered too, which is the harder half of
    /// the same independence. A dropped stream reports no delivery outcome at all
    /// — a closed channel yields neither an acceptance nor a refusal — so a lagged
    /// lane's parked instruction is offered once and never released, and there is
    /// no later event for anything to key off. A verdict that waited on delivery
    /// would have nothing left to wait for, which is precisely the wedge a
    /// standing stat is a loss signal, and not a barrier conjunct, to avoid.
    ///
    /// Kept as a distinct cell because the wedge shape differs from the full
    /// channel above: there the offers keep coming and are refused, here they stop
    /// entirely. A hold that a delivery retry could eventually break out of would
    /// still strand this caller forever.
    ///
    /// Mutation that kills it: hold the tranche until an offer is accepted. The
    /// reply is stranded and the cell spends its deadline.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stat_loss_degrade_answers_a_consumer_that_dropped_its_stream() {
      let (rig, scope) = covered_rig_capacity(&[("/r/keep", 11), ("/r/drop", 12)], 1).await;
      let (ack, probes) = stat_loss_over_a_full_channel(&rig, scope).await;

      // The consumer drops its stream. The command channel stays open, so the
      // driver keeps running and this is not a close.
      let Rig {
        fs: _fs,
        commands: _commands,
        cleanup: _cleanup,
        events,
      } = rig;
      drop(events);

      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Degraded,
        "a cover nobody can ever be given degrades the verdict rather than wedging the scope"
      );

      probes.release();
    }

    /// A reprove re-add racing a set-cover prune's disarm of the SAME watch —
    /// the two dispatched on independent blocking-pool workers — must not leave
    /// the watch armed with no disarm to follow (the orphaned kernel watch +
    /// O_PATH anchor the finding names). Per-scope emission-order serialization
    /// holds them in order: the disarm runs strictly AFTER the re-add and
    /// reclaims it. Mutation witness: without the serialization the disarm runs
    /// FIRST (removing nothing — the re-add is still parked), the released
    /// re-add then re-installs the watch the core has already dropped, and it is
    /// left orphaned in the live set.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reprove_readd_racing_a_prune_disarm_leaks_no_watch() {
      let (rig, scope) = covered_rig(&[("/r/a", 11), ("/r/keep", 12)]).await;
      let child = rig
        .fs
        .arms()
        .into_iter()
        .find(|(_, p)| p == std::path::Path::new("/r/a"))
        .map(|(w, _)| w)
        .expect("/r/a armed by the cold discovery");
      assert!(
        rig.fs.live_watches().contains(&child),
        "the child starts live"
      );

      // Freeze the reprove re-add of /r/a specifically — the root re-add and
      // re-enumerate run freely — so its control batch stalls with its
      // completion signal pending.
      let hold = rig.fs.hold_arm_exec_at("/r/a");
      rig.fs.send_lossy("/r");
      settle(|| hold.captured() >= 1).await;
      assert!(
        hold.captured() >= 1,
        "the reprove re-add of /r/a reached the executor and parked"
      );

      // Now the set-cover prune's disarm of the SAME watch, on its own worker.
      let _ack = send_set_cover(&rig, scope, &["/r/keep"]).await;
      // Give the disarm worker its chance: serialized it is blocked behind the
      // parked re-add; unserialized (the mutation) it removes the watch now.
      for _ in 0..40 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
      }

      // Release the re-add; the disarm then runs strictly after it.
      hold.release();
      settle(|| rig.fs.disarms().contains(&child)).await;
      for _ in 0..20 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
      }

      assert!(
        rig.fs.disarms().contains(&child),
        "the prune disarm of /r/a executed"
      );
      assert!(
        !rig.fs.live_watches().contains(&child),
        "the re-add's watch was reclaimed by the disarm — nothing left armed (live: {:?})",
        rig.fs.live_watches()
      );
    }

    /// A descending rig driven on the bounded, non-FIFO [`NonFifoRuntime`] pool.
    fn inotify_rig_non_fifo(fs: FakeFs) -> Rig {
      fs.put("/r", FileKind::Dir, 1);
      fs.spawn_backend(BackendKind::Inotify);
      let (cmd_tx, cmd_rx) = async_channel::bounded(16);
      let (cleanup, cookie_wake) = cookie_ingress();
      let (ev_tx, ev_rx) = async_channel::bounded(64);
      tokio::spawn(run::<NonFifoRuntime, FakeFs>(
        inotify_config(),
        fs.clone(),
        cmd_rx,
        cookie_wake,
        ev_tx,
        NullRegistry,
      ));
      Rig {
        fs,
        commands: cmd_tx,
        cleanup,
        events: ev_rx,
      }
    }

    /// The completion-driven per-scope control serialization must NOT depend on
    /// the blocking pool's start order. `tributary-fs` is generic over an
    /// arbitrary `RuntimeLite`, whose `spawn_blocking_detach` gives NO FIFO
    /// guarantee and may bound the pool to a few workers. Handed W+1 same-scope
    /// control batches, a bounded, non-FIFO (LIFO) pool DEADLOCKS the old in-pool
    /// chain: released together, its W successors each take a worker and park in
    /// a predecessor's receiver while the chain's ROOT stays queued behind them —
    /// every worker wedged on a batch that can never be scheduled, starving the
    /// whole driver. The completion-driven queue keeps at most ONE batch per
    /// scope ON the pool (the rest wait in the DRIVER), so no worker ever parks
    /// on another batch: all W+1 batches run, in emission order, and every disarm
    /// lands.
    ///
    /// The pool freezes (gate closed) while W+1 single-child prunes emit one
    /// disarm batch each. A prune grows nothing, so each window's barrier
    /// quiesces at the loop top with its (frozen) disarm still unexecuted — but
    /// quiescence is not a clean verdict: a settled CLEAN window owes the
    /// ordering proof one control-batch reply buys, and a frozen pool answers
    /// nothing, so every ack PENDS here (asserted) and certifies only past the
    /// gate. The emission sync is therefore completion-independent by
    /// construction: a debug command queued behind each reconcile is answered in
    /// the select BELOW the loop-top effect flush, so its reply proves the
    /// reconcile's batch was emitted (OLD: submitted to the frozen pool; NEW:
    /// submitted, or queued in the driver behind the in-flight one) without
    /// waiting on any pool work at all.
    ///
    /// Mutation witness: revert the dispatch to the in-pool `predecessor.recv()`
    /// chain and this cell TIMES OUT — the bounded LIFO pool wedges and the
    /// disarms never all land; the completion-driven fix settles well within the
    /// bound (a loud, bounded timeout, never an infinite hang).
    #[tokio::test(flavor = "multi_thread")]
    async fn control_batches_settle_off_a_bounded_non_fifo_pool() {
      const WORKERS: usize = 2;
      const BATCHES: usize = WORKERS + 1;

      // A bounded pool dispatching newest-first — the adversarial order a
      // FIFO-assuming chain deadlocks on. Installed BEFORE the driver spawns.
      let pool = install_non_fifo_pool(WORKERS);

      // A live descending rig over `/r` on that pool: BATCHES prunable children
      // plus a survivor, discovery driven while the gate is open.
      let fs = FakeFs::new(1);
      fs.put("/r/keep", FileKind::Dir, 10);
      let children: Vec<String> = (0..BATCHES).map(|i| format!("/r/c{i}")).collect();
      for (i, path) in children.iter().enumerate() {
        fs.put(path, FileKind::Dir, 20 + i as u64);
      }
      let rig = inotify_rig_non_fifo(fs);
      let scope = watch(&rig, "/r").await;

      // Discovery quiesces: every child (and the survivor) enumerated means its
      // arm batch ran and its cold read landed — no control work in flight, so
      // the pool is idle before it freezes.
      let covered: Vec<String> = children
        .iter()
        .cloned()
        .chain(std::iter::once("/r/keep".to_owned()))
        .collect();
      settle(|| {
        let enums = rig.fs.enumerates();
        covered
          .iter()
          .all(|p| enums.iter().any(|(_, ep)| ep == std::path::Path::new(p)))
      })
      .await;
      // Let the last discovery batch's completion drain through the driver.
      for _ in 0..20 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
      }

      // Freeze the pool: every control batch from here piles up undispatched.
      pool.close_gate();

      // Emit BATCHES same-scope disarm batches — one child pruned per reconcile,
      // each in its own drain. The debug round trip after each one proves that
      // reconcile's batch was EMITTED before the next is sent: the driver flushes
      // effects at the loop top, ABOVE the select that answers the probe, and the
      // probe touches no blocking pool, so it resolves with the pool frozen.
      let mut acks = Vec::new();
      for k in 0..BATCHES {
        let mut retained: Vec<&str> = children[k + 1..].iter().map(String::as_str).collect();
        retained.push("/r/keep");
        acks.push(Box::pin(send_set_cover(&rig, scope, &retained).await));
        driver_flushed_its_effects(&rig).await;
        assert!(
          rig.fs.disarms().is_empty(),
          "prune {k}'s batch is emitted, not executed — the frozen pool ran no disarm"
        );
      }

      // Every window's barrier has quiesced clean, and none may certify: the
      // proof a clean verdict rests on is a batch reply, and the frozen pool
      // answers nothing.
      for (k, ack) in acks.iter_mut().enumerate() {
        assert!(
          futures_util::poll!(ack.as_mut()).is_pending(),
          "prune {k}'s quiesced window pends on its ordering proof while the pool is frozen"
        );
      }

      // Release the pool into the worst-case (successors-before-predecessor)
      // start order. NEW: batch 1 runs, its completion releases batch 2, … every
      // disarm lands. OLD: the LIFO pool wedges — the disarms never all land.
      pool.open_gate();

      settle(|| rig.fs.disarms().len() >= BATCHES).await;
      assert!(
        rig.fs.disarms().len() >= BATCHES,
        "all {BATCHES} same-scope control batches settled off the bounded, non-FIFO pool \
         (disarms landed: {}); the old in-pool `predecessor.recv()` chain deadlocks here",
        rig.fs.disarms().len()
      );

      // And the windows certify past the gate: the batch replies the pool can now
      // deliver carry the ordering proof each pending fence was waiting for.
      for (k, ack) in acks.into_iter().enumerate() {
        assert_eq!(
          resolved(ack).await,
          CoverOutcome::Applied,
          "prune {k} settles clean once a batch reply can prove its window's ordering"
        );
      }
    }

    /// A scope's queued control batches must COALESCE under churn, never
    /// accumulate one per drain. Only one batch per scope executes at a time and
    /// every completion costs the reader's pre-reply kernel-queue cut, while the
    /// enqueue rate is set by directory churn alone: a producer minting creates
    /// faster than batches complete grows the queue by an entry per drain, and the
    /// ordering proof a set-cover or sync waits on sits behind every one of them —
    /// a barrier starved for as long as the churn lasts, with each completed arm's
    /// `O_PATH` anchor held open until its disarm, stuck behind the same backlog,
    /// finally runs.
    ///
    /// The queue is driver-local and unobservable; the SUBMITTED batches are not.
    /// Coalescing therefore reads as FEWER batches carrying MORE requests each,
    /// with the total conserved.
    ///
    /// The staging, and why each step is load-bearing:
    ///
    /// - ONE batch is stalled in flight on the arm gate FIRST, so the scope has an
    ///   in-flight batch for the whole churn and every later drain's work can only
    ///   queue behind it. Without that stall each drain's batch is submitted the
    ///   instant it is emitted and there is no queue to coalesce at all.
    /// - the churn is driven by GROWS, not prunes, so the barrier never settles
    ///   while the gate holds and no ordering proof is ever interleaved. That
    ///   isolates the tail merge: every drain here meets an ordinary entry at the
    ///   queue's back. The alternating schedule, where a proof lands between two
    ///   churn drains, is the sibling cell's boundary.
    /// - each churned directory is DELIVERED before the next is created. The
    ///   driver reads its source tap at the loop top, ABOVE the effect flush, so a
    ///   change that reached the consumer proves the drain which read it is
    ///   already past its tap read and the next event cannot join it. Sending
    ///   without that barrier lets two creates share one drain, which
    ///   `execute_effects` already groups into a single batch — the cell would
    ///   then measure grouping and pass with the coalescing removed.
    /// - the submitted count is asserted UNCHANGED across the churn, which is what
    ///   says the churn really queued rather than ran.
    ///
    /// Of the two halves asserted past the release, CONSERVED is the stronger: a
    /// queue capped by DISCARDING entries would satisfy the bound and strand every
    /// registration waiting on a dropped arm, since even a refused arm owes the
    /// `WatchInstalled` its Monitor node is parked on. So the requests that
    /// actually crossed the fake are counted, and every churned directory is owed
    /// its arm — that is what separates coalescing from pruning.
    ///
    /// MUTATION WITNESS: revert the enqueue to an unconditional `push_back` and
    /// the bounded half FAILS — one batch per churn round is submitted, each
    /// carrying a single request, instead of the one coalesced batch.
    #[tokio::test(flavor = "multi_thread")]
    async fn churned_control_batches_coalesce_instead_of_queueing_one_per_drain() {
      const IN_ISDIR: u32 = 0x4000_0000;
      /// Enough drains that an entry-per-drain queue is unmistakable against the
      /// handful of batches a coalescing one submits.
      const CHURN: usize = 48;
      /// The whole churn collapses into one batch; the slack absorbs any
      /// follow-on batch the released arms' cold reads mint without ever
      /// approaching a per-drain count.
      const BOUNDED: usize = 4;

      let (rig, scope) = covered_rig(&[("/r/keep", 11)]).await;
      let root_watch = rig
        .fs
        .enumerates()
        .first()
        .map(|(watch, _)| *watch)
        .expect("the root enumerated");

      // Stall one batch in flight: this arm parks inside `batch_control`, so the
      // scope holds an in-flight batch for the whole churn below.
      let hold = ReleasedOnDrop(rig.fs.hold_arms());
      rig.fs.put("/r/stall", FileKind::Dir, 100);
      rig.fs.send_inotify_batch(
        "/r",
        vec![attributed(&[root_watch], IN_CREATE | IN_ISDIR, b"stall")],
      );
      assert!(
        settle(|| hold.captured() >= 1).await,
        "staging: the discovery arm of /r/stall parked in flight, so nothing else can be \
         submitted for the scope"
      );
      let stalled = rig.fs.control_batches().len();

      // CHURN separate drains, each discovering one new directory and emitting one
      // arm for it. The delivered change is the per-round drain barrier.
      for round in 0..CHURN {
        let name = format!("c{round}");
        rig
          .fs
          .put(format!("/r/{name}"), FileKind::Dir, 200 + round as u64);
        rig.fs.send_inotify_batch(
          "/r",
          vec![attributed(
            &[root_watch],
            IN_CREATE | IN_ISDIR,
            name.as_bytes(),
          )],
        );
        let want = loc(&[name.as_str()]);
        let mut delivered = false;
        for _ in 0..16 {
          let (_scope, change) = next_event(&rig).await;
          if change.kind().is_created() && *change.location() == want {
            delivered = true;
            break;
          }
        }
        assert!(
          delivered,
          "staging (round {round}): {name}'s create must be delivered before the next is \
           injected, or two creates share a drain and this measures grouping"
        );
      }

      assert_eq!(
        rig.fs.control_batches().len(),
        stalled,
        "staging: the churn queued behind the stalled batch — nothing further was submitted \
         while it held: {:?}",
        rig.fs.control_batches()
      );

      // Release: the stalled batch completes and the scope drains what it queued.
      hold.release();
      let armed =
        settle(|| (0..CHURN).all(|round| arms_at(&rig, &format!("/r/c{round}")) >= 1)).await;
      let submitted = rig.fs.control_batches();
      let drained: Vec<usize> = submitted[stalled..]
        .iter()
        .filter(|(s, _)| *s == scope)
        .map(|(_, requests)| *requests)
        .collect();

      // BOUNDED: a small constant, not one batch per churned directory.
      assert!(
        drained.len() <= BOUNDED,
        "the churn drains in at most {BOUNDED} batches, not one per drain: {} batches for \
         {CHURN} rounds ({drained:?})",
        drained.len()
      );

      // CONSERVED: every request emitted crossed the fake exactly once. A queue
      // bounded by dropping entries passes the assertion above and fails here.
      assert!(
        armed,
        "every churned directory is armed once the queue drains"
      );
      let unarmed: Vec<String> = (0..CHURN)
        .map(|round| format!("/r/c{round}"))
        .filter(|path| arms_at(&rig, path) != 1)
        .collect();
      assert!(
        unarmed.is_empty(),
        "no queued arm was dropped to bound the queue — each churned directory is armed \
         exactly once (missing or duplicated: {unarmed:?})"
      );
      assert_eq!(
        drained.iter().sum::<usize>(),
        CHURN,
        "the coalesced batches carry every emitted request and no more: {drained:?}"
      );

      // And the scope still settles: a barrier opened past the churn reaches its
      // ordering proof and certifies, which is the thing an unbounded queue starved.
      let mut retained: Vec<String> = (0..CHURN).map(|round| format!("/r/c{round}")).collect();
      retained.push("/r/keep".to_owned());
      retained.push("/r/stall".to_owned());
      let retained: Vec<&str> = retained.iter().map(String::as_str).collect();
      assert_eq!(
        resolved(send_set_cover(&rig, scope, &retained).await).await,
        CoverOutcome::Applied,
        "the scope settles past the churn — the ordering proof is reached, not starved"
      );
    }

    /// The alternating schedule: an ordering proof lands BETWEEN two churn
    /// drains, and the queue must still drain in a bounded number of batches.
    ///
    /// This is the case a tail-only merge does not cover. `queue_cut_proof`
    /// coalesces its own request by dropping the obsolete proof entries and
    /// appending a fresh one at the back, so a proof sitting at the back forces the
    /// next drain's batch to land BEHIND it as a separate entry — and when the
    /// following proof drops that one, the two ordinary entries it separated become
    /// adjacent with nothing to fuse them. Each alternation round strands one more,
    /// and the barrier the proof serves drifts back behind an unbounded run of
    /// batches: the very starvation the tail merge was meant to end. The queue's
    /// invariant is therefore adjacency-wide, not tail-local, and the compaction
    /// after that drop is what restores it.
    ///
    /// Prunes are what make the alternation reachable through the real loop. A
    /// prune grows nothing, so its window quiesces at the loop top and asks for the
    /// ordering proof a clean verdict owes — one proof request per round, emitted
    /// in the same pass as that round's disarm and after it. A GROW schedule cannot
    /// stage this: its re-arm work is outstanding for as long as the gate holds, the
    /// barrier never settles, and `covers_awaiting_cut` offers nothing.
    ///
    /// The rest of the staging, and why each step is load-bearing:
    ///
    /// - the FIRST prune's disarm batch is stalled in flight on the arm gate, so
    ///   every later round can only queue. It also keeps each round's proof queued
    ///   rather than answered, which is what lets the next round's disarm land
    ///   behind it.
    /// - the debug probe after each prune is answered in the SELECT, which sits
    ///   below both the loop-top effect flush and the pass that asks for the proof.
    ///   Its reply therefore proves that round's disarm AND its proof request are
    ///   already queued before the next prune is sent — without it the rounds
    ///   collapse into one drain and the alternation never happens.
    /// - the submitted count is asserted UNCHANGED across the rounds, which is what
    ///   says the churn queued rather than ran.
    ///
    /// CONSERVED remains the stronger half: capping the queue by DISCARDING entries
    /// satisfies the bound and silently drops disarms, orphaning a kernel watch and
    /// its `O_PATH` anchor apiece. So every pruned child is owed its disarm exactly
    /// once, and none may be left armed.
    ///
    /// MUTATION WITNESS: keep the tail merge and remove only the compaction — leave
    /// `queue_cut_proof` dropping obsolete proofs and appending — and the bounded
    /// half FAILS with one stranded batch per alternation round.
    #[tokio::test(flavor = "multi_thread")]
    async fn churn_alternating_with_ordering_proofs_coalesces_across_the_dropped_proof() {
      /// Enough alternations that one stranded entry per round is unmistakable
      /// against the handful of batches a compacting queue submits.
      const ROUNDS: usize = 32;
      /// The queued prunes collapse into one batch, which the coalesced proof
      /// follows; the slack absorbs a further proof round without ever approaching
      /// a per-round count.
      const BOUNDED: usize = 4;

      let names: Vec<String> = (0..ROUNDS).map(|round| format!("/r/p{round}")).collect();
      let mut tree: Vec<(&str, u64)> = names
        .iter()
        .enumerate()
        .map(|(round, path)| (path.as_str(), 20 + round as u64))
        .collect();
      tree.push(("/r/keep", 11));
      let (rig, scope) = covered_rig(&tree).await;

      // The pruned children's watches, read before anything is disarmed: the
      // conserved half is asserted against these, not against a count.
      let armed = rig.fs.arms();
      let watches: Vec<WatchId> = names
        .iter()
        .map(|path| {
          armed
            .iter()
            .find(|(_, p)| p == std::path::Path::new(path))
            .map(|(watch, _)| *watch)
            .unwrap_or_else(|| panic!("{path} was armed by the cold discovery"))
        })
        .collect();

      // Round 0's disarm batch is submitted and PARKS, so the scope holds a batch
      // in flight — and its window, having grown nothing, asks for the proof that
      // every later round's disarm must then queue behind.
      let hold = ReleasedOnDrop(rig.fs.hold_arms());
      let mut acks = Vec::new();
      let mut retained: Vec<&str> = names[1..].iter().map(String::as_str).collect();
      retained.push("/r/keep");
      acks.push(send_set_cover(&rig, scope, &retained).await);
      driver_flushed_its_effects(&rig).await;
      assert!(
        settle(|| hold.captured() >= 1).await,
        "staging: the first prune's disarm batch parked in flight, so nothing else can be \
         submitted for the scope"
      );
      let stalled = rig.fs.control_batches().len();

      // Each remaining round: one disarm, then one proof request in the same pass —
      // the alternation, one entry per round.
      for round in 1..ROUNDS {
        let mut retained: Vec<&str> = names[round + 1..].iter().map(String::as_str).collect();
        retained.push("/r/keep");
        acks.push(send_set_cover(&rig, scope, &retained).await);
        driver_flushed_its_effects(&rig).await;
      }
      assert_eq!(
        rig.fs.control_batches().len(),
        stalled,
        "staging: every round after the first queued behind the stalled batch — nothing \
         further was submitted while it held: {:?}",
        rig.fs.control_batches()
      );

      // Release: the stalled batch completes and the scope drains what it queued.
      hold.release();
      let settled = settle(|| rig.fs.disarms().len() >= ROUNDS).await;
      let submitted = rig.fs.control_batches();
      let drained: Vec<usize> = submitted[stalled..]
        .iter()
        .filter(|(s, _)| *s == scope)
        .map(|(_, requests)| *requests)
        .collect();

      // BOUNDED: a small constant across the whole alternating schedule, not one
      // stranded batch per round.
      assert!(
        drained.len() <= BOUNDED,
        "the alternating schedule drains in at most {BOUNDED} batches, not one per round: \
         {} batches for {ROUNDS} rounds ({drained:?})",
        drained.len()
      );

      // CONSERVED: nothing was dropped to reach that bound. Every pruned child is
      // disarmed exactly once and none is left armed.
      assert!(settled, "every prune's disarm ran once the queue drained");
      let missed: Vec<&WatchId> = watches
        .iter()
        .filter(|watch| rig.fs.disarms().iter().filter(|d| d == watch).count() != 1)
        .collect();
      assert!(
        missed.is_empty(),
        "no queued disarm was dropped to bound the queue — each pruned child is disarmed \
         exactly once (missing or duplicated: {missed:?})"
      );
      let orphaned: Vec<&WatchId> = watches
        .iter()
        .filter(|watch| rig.fs.live_watches().contains(watch))
        .collect();
      assert!(
        orphaned.is_empty(),
        "and none is left armed behind a dropped disarm: {orphaned:?}"
      );
      assert_eq!(
        drained.iter().sum::<usize>(),
        ROUNDS - 1,
        "the compacted batch carries every request the rounds after the stalled one emitted, \
         and no more: {drained:?}"
      );

      // And every parked barrier is answered: each round's window certifies clean
      // once the coalesced proof crosses the reader.
      for (round, ack) in acks.into_iter().enumerate() {
        assert_eq!(
          resolved(ack).await,
          CoverOutcome::Applied,
          "round {round}'s window certifies past the churn — its ordering proof is reached, \
           not starved"
        );
      }
    }

    /// A completion-independent driver-progress sync: a debug command queued
    /// behind another command is answered in the SELECT, which sits below the
    /// loop-top effect flush — so its reply proves the driver already handled the
    /// earlier command and dispatched the effects that command queued. It reaches
    /// no blocking pool, so it resolves with the pool frozen; a cell that must
    /// observe an EMITTED-but-unexecuted control batch cannot use an awaited
    /// cover ack for this, because a clean verdict now waits on a batch reply.
    async fn driver_flushed_its_effects(rig: &Rig) {
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::DebugLaneCount { reply })
        .await
        .unwrap();
      tokio::time::timeout(interpreted_secs(10), on_reply)
        .await
        .expect("the driver answers a debug probe with the pool frozen")
        .expect("the driver replies");
    }

    /// The fence's core promise at the driver level: the ack PENDS while the
    /// grow's re-arm work is in flight — here an arm parked on the blocking
    /// pool — and resolves `Applied` only once that work lands. Under the old
    /// queue-time ack this future resolved before the arm even dispatched.
    #[tokio::test(flavor = "multi_thread")]
    async fn ack_pends_until_the_grow_settles_then_applies() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;

      // Hold the grow's arms: the root's re-arm read runs (enumerates are not
      // held), but re-installing /r/drop parks — the fence must pend with it.
      let hold = rig.fs.hold_arms();
      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      let mut ack = Box::pin(ack);
      // Generous scheduler slices: the reconcile applies, its re-arm read
      // completes, the /r/drop arm parks — and the ack still pends.
      for _ in 0..50 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      assert!(
        futures_util::poll!(ack.as_mut()).is_pending(),
        "the ack pends while the grow's arm is parked — settle-time, not queue-time"
      );
      hold.release();
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Applied,
        "the released arm lands, the cascade quiesces, the clean window applies"
      );
    }

    /// A cancel storm against a STALLED grow stays bounded and healthy: each
    /// issued-then-dropped `set_cover` ack's fence is abandoned on both sides
    /// of the driver/core seam at the next loop-top prune (the sender AND the
    /// core's pending tuple), the loss memory is untouched, and a live caller
    /// issued after the storm still resolves `Applied` once the stall lifts.
    /// Fail-on-old: only the sender was pruned — one core pending tuple
    /// accumulated per processed request for the whole stall.
    #[tokio::test(flavor = "multi_thread")]
    async fn cancelled_acks_under_a_stalled_grow_stay_bounded_and_resolve_the_live_caller() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;

      // Stall the grow: /r/drop's re-install parks on the blocking pool.
      let hold = rig.fs.hold_arms();
      // The storm: issue-and-cancel many acked reconciles against the stall.
      for _ in 0..64 {
        let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
        drop(ack);
        tokio::task::yield_now().await;
      }
      // The live caller arrives after the storm and pends on the same stall.
      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      let mut ack = Box::pin(ack);
      for _ in 0..50 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      assert!(
        futures_util::poll!(ack.as_mut()).is_pending(),
        "the live ack pends on the stalled grow"
      );
      hold.release();
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Applied,
        "the storm's abandoned fences never poison the live caller's clean settle"
      );
    }

    /// A failed grow arm is loss inside the window: the fence settles
    /// `Degraded`, and the covering `Rescan` that dominates the gap reaches
    /// the consumer in-band.
    #[tokio::test(flavor = "multi_thread")]
    async fn failed_grow_arm_settles_degraded() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;
      rig
        .fs
        .fail_watch_at("/r/drop", tributary_proto::WatchError::NoSpace);

      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Degraded,
        "a failed re-arm is signaled loss, not a clean apply"
      );
      let mut saw_rescan = false;
      for _ in 0..8 {
        let (_scope, change) = next_event(&rig).await;
        if change.kind().is_rescan() {
          saw_rescan = true;
          break;
        }
      }
      assert!(
        saw_rescan,
        "the degraded window's covering Rescan is delivered"
      );
    }

    /// The applied-cover-lie regression at the driver level: after a lossy
    /// settle the cover is rewound, so RE-ISSUING the same cover computes a
    /// non-empty broadening delta and the grow re-attempts its arms — here
    /// healed, so the re-issue settles `Applied` over real coverage.
    #[tokio::test(flavor = "multi_thread")]
    async fn reissue_after_lossy_settle_re_attempts_the_arms() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;
      rig
        .fs
        .fail_watch_at("/r/drop", tributary_proto::WatchError::NoSpace);
      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      assert_eq!(resolved(ack).await, CoverOutcome::Degraded);

      // Re-issue the SAME cover after healing the arm: without the settle
      // rewind the delta would be empty — no arm attempted, an instant clean
      // settle over the hole the failed arm left.
      rig.fs.heal_watch_at("/r/drop");
      let attempts = arms_at(&rig, "/r/drop");
      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      // The re-attempted grow HEALS the standing arm-refused hole, and a heal
      // window owes the hole's dark interval a closing Rescan — so this
      // window is honestly Degraded (the caller's contract: re-issue once
      // more), never a clean claim over darkness the failed arm left.
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Degraded,
        "the grow that heals the hole degrades — its closing Rescan is owed"
      );
      assert!(
        arms_at(&rig, "/r/drop") > attempts,
        "the rewound cover made the delta non-empty — the arm was re-attempted"
      );

      // The NEXT re-issue finds no hole and no fresh installs — survivors
      // only — and settles clean: the degrade is self-resolving.
      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Applied,
        "the hole-free re-issue settles clean over re-attempted coverage"
      );
    }

    /// A loss the kernel has COMMITTED but nobody has read cannot be certified
    /// over — even when the whole window is reads.
    ///
    /// The hole-free re-issue above is the shape: its cascade is re-arm
    /// enumerates, which complete on the blocking pool and never cross the
    /// reader, so nothing it does forwards a record. `SourceSnapshot` counts only
    /// what the reader has ALREADY forwarded into the per-scope taps, so a
    /// kernel-resident `IN_Q_OVERFLOW` sits in NO lane: the settle-edge drain
    /// reads trivially spent and the barrier's counted work — which proves the
    /// coverage was REBUILT, never that the kernel was quiet while it was —
    /// would mint a clean verdict straight over the loss.
    ///
    /// One empty control batch per window closes it: the reader cuts its kernel
    /// queue onto the lane before answering ANY batch, so the reply's arrival
    /// proves the loss was ingested ahead of it, and this window degrades
    /// honestly instead.
    ///
    /// Mutation witness: treat every window as already proven (drop the
    /// `CutProof` deferral in `poll_cover_settlements`) and the verdict is
    /// `Applied` — the loss is still sitting in the kernel, uncounted, with the
    /// staged flag never flushed because no batch is ever sent.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_kernel_resident_loss_degrades_a_reads_only_reissue() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;
      rig
        .fs
        .fail_watch_at("/r/drop", tributary_proto::WatchError::NoSpace);
      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      assert_eq!(resolved(ack).await, CoverOutcome::Degraded);
      rig.fs.heal_watch_at("/r/drop");
      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Degraded,
        "the grow that heals the hole degrades — its closing Rescan is owed"
      );

      // The kernel commits an overflow with the scope idle: staged, so it is in
      // no lane and no drain can reach it. `overflow_pending` reads the transport
      // itself — nothing has been forwarded, which is the whole point.
      rig.fs.stage_kernel_loss("/r");
      assert!(
        !rig.fs.overflow_pending("/r"),
        "a kernel-resident loss is in no queue until a batch reply flushes it"
      );

      // The hole-free re-issue: survivors only, so its whole cascade is re-arm
      // READS — no install and no disarm, hence no control batch of its own and
      // nothing that would forward the loss as a side effect. That this exact
      // sequence re-reads without re-arming, and settles clean when the kernel
      // is quiet, is `reissue_after_lossy_settle_re_attempts_the_arms`'s third
      // leg; the counters cannot be re-checked HERE, because the surfaced loss
      // immediately re-proves the scope's bindings and moves them.
      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Degraded,
        "the window's proof batch surfaces the kernel's loss ahead of the settle"
      );
    }

    /// The ZERO-counted-work window, which no arm- or read-shaped proof can
    /// reach: re-issuing an already-applied cover computes an empty broadening
    /// delta and an empty prune set, so the fence opens onto a barrier that is
    /// ALREADY settled — no enumerate, no arm, no disarm, nothing to hook an
    /// ordering proof onto but the round trip itself. A kernel-resident loss
    /// across such a window must still degrade it.
    ///
    /// Mutation witness: treat every window as already proven and this settles
    /// `Applied` — the strongest form of the defect, since the window certifies
    /// over the loss without having performed a single unit of work.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_kernel_resident_loss_degrades_a_zero_work_reissue() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;
      // Grow back and settle CLEAN, so the recorded claim is truthful and the
      // re-issue below really does compute an empty delta.
      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Applied,
        "the grow applies, so the cover it recorded is provable"
      );

      // The window's shape, established with the kernel quiet: re-issuing the
      // applied cover computes an empty delta both ways, so it settles clean
      // having counted no work whatsoever — and the rig is unchanged by the
      // staging seam existing, since nothing is staged.
      let counted = |rig: &Rig| {
        (
          rig.fs.enumerates().len(),
          rig.fs.arms().len(),
          rig.fs.disarms().len(),
        )
      };
      let before = counted(&rig);
      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Applied,
        "an already-applied cover re-applies"
      );
      assert_eq!(
        counted(&rig),
        before,
        "and counted nothing: no enumerate, no arm, no disarm in the window"
      );

      // The SAME window, differing only in that the kernel has committed a loss
      // nobody has read. Staged, so it is in no lane: `overflow_pending` reads
      // the transport itself, and nothing has been forwarded onto it.
      rig.fs.stage_kernel_loss("/r");
      assert!(
        !rig.fs.overflow_pending("/r"),
        "a kernel-resident loss is in no queue until a batch reply flushes it"
      );
      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Degraded,
        "a window with no work to prove still cannot certify over the kernel's loss"
      );
    }

    /// Ordering-proof requests COALESCE: one in flight plus at most one queued
    /// successor, however many latch resets pile up behind a blocked round trip.
    ///
    /// The latch has two invalidations — a reconcile putting new work into the
    /// window, and a newly opened fence starting later than the proof — and both
    /// reset it to `Unproven`. A scope whose proof batch is blocked therefore
    /// re-enters `covers_awaiting_cut` once per accepted request, and appending
    /// one empty batch per reset grows the scope's control queue with the
    /// REQUEST count: the bounded command mailbox limits only instantaneous
    /// input, the abandoned-fence prune never touches these, and when traffic
    /// stops every obsolete token must cross the reader serially before the
    /// newest can prove — unbounded memory, O(N) barrier delay.
    ///
    /// Staged on the ZERO-work re-issue (an already-applied cover computes an
    /// empty broadening delta and an empty prune set), so the requests below add
    /// no arm, disarm or enumerate work at all and EVERY batch this cell counts
    /// is an ordering-proof round trip — the `(scope, 0)` signature.
    ///
    /// The queued depth is read where it becomes observable: a queued batch is
    /// invisible until it dispatches, so "one successor was queued" and "exactly
    /// one successor round trip happened after the blocked one completed" are
    /// the same measurement, taken after the release.
    ///
    /// The ghost `SetCover` is the driver-progress barrier. It is answered at
    /// COMMAND time (an unknown scope is skipped before any fence work), and the
    /// command channel is FIFO with one command serviced per loop pass, so its
    /// reply proves every request ahead of it was consumed — and consumed in a
    /// pass whose top had already minted that request's proof.
    ///
    /// MUTATION WITNESS: drop the coalescing (`push_back` per request, as
    /// before) and the released queue drains one round trip PER request instead
    /// of one — `RESETS + 1` where this asserts 1.
    #[tokio::test(flavor = "multi_thread")]
    async fn queued_ordering_proofs_coalesce_to_one_successor() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;
      // Grow back and settle CLEAN, so the re-issues below really are zero-work.
      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Applied,
        "the grow applies, so the cover it recorded is provable"
      );

      /// Ordering-proof round trips this scope has dispatched: an empty batch is
      /// the round trip's signature — an arm or disarm batch carries requests.
      fn proofs(rig: &Rig, scope: ScopeId) -> usize {
        rig
          .fs
          .control_batches()
          .iter()
          .filter(|(s, requests)| *s == scope && *requests == 0)
          .count()
      }
      let before = proofs(&rig, scope);

      // Block the round trip the first re-issue asks for.
      let hold = ReleasedOnDrop(rig.fs.hold_arms());
      let mut acks = vec![send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await];
      assert!(
        settle(|| hold.captured() >= 1).await,
        "staging: the window's proof batch reached the fake and parked"
      );
      assert_eq!(
        proofs(&rig, scope) - before,
        1,
        "staging: exactly one proof batch is in flight, and it is stuck"
      );

      // The identical zero-work request, over and over. Each reconcile and each
      // opened fence resets the latch, so each is re-asked — and every re-ask
      // lands in the scope's queue behind the blocked batch.
      const RESETS: usize = 8;
      for _ in 0..RESETS {
        acks.push(send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await);
      }
      let ghost = ScopeId::new(core::num::NonZeroU64::new(4242).unwrap());
      assert_eq!(
        resolved(send_set_cover(&rig, ghost, &["/r/keep"]).await).await,
        CoverOutcome::Skipped(SkipReason::UnknownRoot),
        "barrier: every request above has been consumed by the driver loop"
      );
      assert_eq!(
        proofs(&rig, scope) - before,
        1,
        "the successors are QUEUED, not dispatched: the scope still has exactly one \
         batch in flight"
      );

      hold.release();
      for ack in acks {
        assert_eq!(
          resolved(ack).await,
          CoverOutcome::Applied,
          "every parked caller is answered once the newest token proves"
        );
      }
      assert_eq!(
        proofs(&rig, scope) - before,
        2,
        "the whole reset churn collapsed onto ONE queued successor: one blocked round \
         trip plus one that proved, never one per request"
      );
    }

    /// Supersession: two acked covers of one root queued back to back — the
    /// second while the first's re-arm work is still parked — both pend, both
    /// resolve at the shared settle, and the latest cover's subtree holds a
    /// live watch again. (FIFO application and latest-wins bookkeeping are
    /// core-pinned; this cell pins the driver's one-fence-one-reply routing.)
    #[tokio::test(flavor = "multi_thread")]
    async fn superseding_acks_resolve_at_the_shared_settle() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12), ("/r/other", 13)]).await;
      shrunk_to_keep(&rig, scope).await;
      let other_arms = arms_at(&rig, "/r/other");

      let hold = rig.fs.hold_arms();
      let first = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      // The first grow's re-arm READ of the root must land before the second
      // cover applies: a cover racing an in-flight re-arm read dirties it,
      // and the dirtied read's completion stands a Rescan that would
      // (honestly) degrade both windows — this cell wants the clean shape.
      // The read having FED the core is observable as the survivor cascade's
      // own read (its second /r/keep enumerate), which that feeding queues.
      settle(|| {
        rig
          .fs
          .enumerates()
          .iter()
          .filter(|(_, p)| p == std::path::Path::new("/r/keep"))
          .count()
          >= 2
      })
      .await;
      let second = send_set_cover(&rig, scope, &["/r/keep", "/r/drop", "/r/other"]).await;
      let mut first = Box::pin(first);
      let mut second = Box::pin(second);
      for _ in 0..50 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      assert!(
        futures_util::poll!(first.as_mut()).is_pending(),
        "the first ack pends on the held grow"
      );
      assert!(
        futures_util::poll!(second.as_mut()).is_pending(),
        "the superseding ack pends on the same scope settle"
      );
      hold.release();
      assert_eq!(resolved(first).await, CoverOutcome::Applied);
      assert_eq!(resolved(second).await, CoverOutcome::Applied);
      assert!(
        arms_at(&rig, "/r/other") > other_arms,
        "the latest cover's /r/other was re-armed"
      );
    }

    /// Close mid-fence DROPS the parked reply (the ratified semantics): the
    /// caller's ack resolves as a cancellation — `UnwatchError::Closed` at the
    /// watcher surface — never as a fabricated outcome over a torn-down
    /// driver.
    #[tokio::test(flavor = "multi_thread")]
    async fn close_mid_fence_drops_the_parked_reply() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;

      let hold = rig.fs.hold_arms();
      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      // The reconcile has been applied once its re-arm read of the root is
      // re-executed; the /r/drop arm it queued is parked on the hold.
      assert!(
        settle(|| {
          rig
            .fs
            .enumerates()
            .iter()
            .filter(|(_, p)| p == std::path::Path::new("/r"))
            .count()
            >= 2
        })
        .await,
        "staging: the reconcile's re-arm read must land, leaving the /r/drop arm parked under an OPEN fence"
      );

      let (creply, on_close) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Close { reply: creply })
        .await
        .unwrap();
      let _ = on_close.await.expect("close replies");
      assert!(
        ack.await.is_err(),
        "a fence still pending at close drops its reply — the watcher maps it to Closed"
      );
      hold.release();
    }

    /// A kernel-recursive scope answers `Recursive` IMMEDIATELY — its
    /// whole-subtree stream never narrowed, so there is no reconcile to fence
    /// — and no per-directory arm or disarm is ever attempted.
    #[tokio::test(flavor = "multi_thread")]
    async fn kernel_recursive_scope_answers_recursive_immediately() {
      // The plain rig IS the kernel-recursive shape: an FsEvents profile with
      // FsEvents-claiming spawns (the hermetic default).
      let rig = rig_with_capacity(64);
      let scope = watch(&rig, "/r").await;
      let ack = send_set_cover(&rig, scope, &["/r/keep"]).await;
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Recursive,
        "kernel-recursive coverage never narrowed — reported, not fenced"
      );
      assert!(
        rig.fs.arms().is_empty() && rig.fs.disarms().is_empty(),
        "a kernel-recursive scope holds no per-directory watches to reconcile"
      );

      // An unknown scope is the immediate driver-side skip.
      let ghost = ScopeId::new(core::num::NonZeroU64::new(999).unwrap());
      let ack = send_set_cover(&rig, ghost, &["/r/keep"]).await;
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Skipped(SkipReason::UnknownRoot),
        "an unknown scope is skipped at command time"
      );
    }

    /// How many enumerates have been executed at `path`.
    fn enumerates_at(rig: &Rig, path: &str) -> usize {
      rig
        .fs
        .enumerates()
        .iter()
        .filter(|(_, p)| p == std::path::Path::new(path))
        .count()
    }

    /// Out-of-window coverage loss through the public API: an overflow lands
    /// AFTER a clean settle with NO reconcile pending, then the SAME cover is
    /// re-issued. The loss must degrade the recorded claim, so the re-issue
    /// re-attempts real arm work and its ack inherits the still-unobserved
    /// loss (`Degraded`); a second re-issue then settles `Applied`. Fail-on-old
    /// twice over: without the out-of-window handling the first re-issue
    /// computes an EMPTY broadening delta (no work) and settles `Applied` over
    /// whatever the overflow cost, and the second re-issue re-arms nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn out_of_window_overflow_degrades_then_reissue_applies() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;
      // Grow back to the full pair and settle clean: the recorded claim is
      // truthful and no fence entry remains.
      let ack = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      assert_eq!(resolved(ack).await, CoverOutcome::Applied);

      // Hold enumerates so the overflow's recovery re-arm cannot quiesce: the
      // loss memory stays unobserved until the re-issued cover's fence opens
      // into it (the deterministic stand-in for a reconcile racing the loss).
      let hold = rig.fs.hold_enumerates();
      rig.fs.send_lossy("/r");
      // The overflow's covering Rescan reaching the consumer proves the loss
      // was routed (and, with the fix, the claim degraded).
      loop {
        let (_scope, change) = next_event(&rig).await;
        if change.kind().is_rescan() {
          break;
        }
      }

      // Re-issue the IDENTICAL cover: the degraded claim yields a full
      // broadening delta, so the reconcile re-arms the retained set; its fence
      // shares the loss's still-unobserved window.
      let first = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      let mut first = Box::pin(first);
      for _ in 0..25 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      assert!(
        futures_util::poll!(first.as_mut()).is_pending(),
        "the re-issue pends on the held recovery — never an instant clean settle over the loss"
      );
      hold.release();
      assert_eq!(
        resolved(first).await,
        CoverOutcome::Degraded,
        "the first re-issue inherits the unobserved out-of-window loss"
      );

      // The second re-issue starts a fresh window against the (still degraded)
      // claim: real re-arm work again, settling clean this time.
      let keep_reads = enumerates_at(&rig, "/r/keep");
      let drop_reads = enumerates_at(&rig, "/r/drop");
      let second = send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await;
      assert_eq!(
        resolved(second).await,
        CoverOutcome::Applied,
        "the clean re-issue re-proves the claim"
      );
      assert!(
        enumerates_at(&rig, "/r/keep") > keep_reads && enumerates_at(&rig, "/r/drop") > drop_reads,
        "the re-issue re-arms the FULL retained set against the degraded claim"
      );
    }

    /// A saturated, continuously-refilled command channel must not starve op
    /// completions: op results are polled before commands, so a held grow's
    /// arm still lands, its scope still settles, and the awaited ack still
    /// resolves while the spam continues. Under the old command-first arm
    /// order this ack hangs until the `resolved` deadline trips: each spam
    /// command is a reply-less SetCover whose reconcile walks the scope's
    /// whole watch table (the cover here spans dozens of watches), so
    /// consuming one costs far more than producing one and the slot-filling
    /// spammers keep the command branch ready at every loop-top poll — the
    /// starvation is a cost ratio, which is why cheap spam (a ghost unwatch)
    /// cannot reproduce it: the tight consume loop out-races production and
    /// the branch reads not-ready often enough for op results to slip in.
    #[tokio::test(flavor = "multi_thread")]
    async fn command_flood_does_not_starve_op_completions() {
      use std::sync::atomic::{AtomicBool, Ordering};

      // A scope wide enough that every spam reconcile's watch-table walk has
      // real cost: keep + drop + [`flood_rig_width`] filler directories. The
      // registration is silent now (42-10 — it announces no inventory, only its closing
      // `Rescan`), so the rig's 64-slot event channel has even more headroom
      // than the 32 `Created`s this budget was sized for: no lag Rescan can
      // pollute the fence verdict.
      let filler: Vec<String> = (0..flood_rig_width())
        .map(|i| format!("/r/d{i:02}"))
        .collect();
      let mut children: Vec<(&str, u64)> = vec![("/r/keep", 11), ("/r/drop", 12)];
      children.extend(
        filler
          .iter()
          .enumerate()
          .map(|(i, p)| (p.as_str(), 100 + i as u64)),
      );
      let (rig, scope) = covered_rig(&children).await;
      let full_cover: Vec<&str> = children.iter().map(|(p, _)| *p).collect();
      let without_drop: Vec<&str> = full_cover
        .iter()
        .copied()
        .filter(|p| *p != "/r/drop")
        .collect();

      // Prune /r/drop only (instant clean settle), then grow it back with the
      // arms held: the ack now waits on op completions — the root's re-arm
      // cascade and the parked /r/drop arm — that the flood will try to starve.
      let ack = send_set_cover(&rig, scope, &without_drop).await;
      assert_eq!(resolved(ack).await, CoverOutcome::Applied);
      let hold = rig.fs.hold_arms();
      let ack = send_set_cover(&rig, scope, &full_cover).await;
      // The reconcile has been applied once its re-arm read of the root
      // re-executed (its second /r enumerate); the /r/drop arm it queued is
      // parked on the hold.
      assert!(
        settle(|| enumerates_at(&rig, "/r") >= 2).await,
        "staging: the reconcile must be applied with the /r/drop arm parked, or the ack has no op completion to wait on"
      );

      // Saturate the 16-slot command channel with reply-less SetCovers of the
      // scope's own full cover — each reconcile re-walks every watch against
      // every retained prefix and changes nothing (the delta against the
      // recorded cover is empty, nothing is outside it, no fence is opened) —
      // continuously refilled from tasks that fill EVERY free slot per wakeup.
      let stop = std::sync::Arc::new(AtomicBool::new(false));
      let spam_cover: Vec<PathBuf> = full_cover.iter().map(PathBuf::from).collect();
      let mut spammers = Vec::new();
      for _ in 0..4 {
        let commands = rig.commands.clone();
        let stop = std::sync::Arc::clone(&stop);
        let spam_cover = spam_cover.clone();
        spammers.push(tokio::spawn(async move {
          while !stop.load(Ordering::Relaxed) {
            loop {
              match commands.try_send(Command::SetCover {
                scope,
                retained: spam_cover.clone(),
                reply: None,
              }) {
                Ok(()) => {}
                Err(async_channel::TrySendError::Full(_)) => break,
                Err(async_channel::TrySendError::Closed(_)) => return,
              }
            }
            tokio::task::yield_now().await;
          }
        }));
      }
      // Let the flood establish before the held op completes.
      tokio::time::sleep(Duration::from_millis(100)).await;
      hold.release();

      // The op results and the settlement make progress under sustained
      // command pressure: the ack resolves within the bounded await.
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Applied,
        "op completions and fence settlements outrank the command flood"
      );
      stop.store(true, Ordering::Relaxed);
      for spammer in spammers {
        let _ = spammer.await;
      }
    }

    /// How many filler directories the wide flood rigs carry beside `keep` and
    /// `drop`.
    ///
    /// The width is what makes a spam reconcile cost more than PRODUCING one,
    /// which is the property every flood in this module stands on. A reconcile
    /// walks each of the scope's watches against each retained prefix, so its
    /// cost grows with the SQUARE of the width, while producing a command — one
    /// cover clone — grows linearly with it. Thirty sizes that margin for a real
    /// machine, where it has to survive a filler thread losing the CPU.
    ///
    /// Interpreted, the same shape stops being microseconds and becomes minutes:
    /// one full-width reconcile runs longer than a caller's entire staging
    /// budget, and a cell that needs `Close` queued BEHIND one mailbox of spam
    /// has to wait out sixteen of them in a row. No budget covers that — the
    /// wait grows quadratically with a width the budget cannot see, and on a
    /// 32-bit target the same window is what walks the address space.
    ///
    /// Narrowing it there cuts the wait quadratically and leaves the margin it
    /// exists for intact: an interpreted reconcile still outweighs an
    /// interpreted cover clone by orders of magnitude. Nothing rests on that
    /// being taken on trust — every caller stages on
    /// [`flood_starves_the_source`], which reads the mailbox FULL and fails the
    /// cell if the flood ever stops outpacing the driver.
    fn flood_rig_width() -> usize {
      if cfg!(miri) { 6 } else { 30 }
    }

    /// The wide starved-settle rig: keep + drop + [`flood_rig_width`] filler
    /// directories, cold discovery quiesced, `/r/drop` pruned clean, then grown
    /// back with the arms HELD — the awaited ack now parks on exactly one re-install.
    /// The width is load-bearing for the flood the callers start: each spam
    /// reconcile's watch-table walk must cost more than producing it, or the
    /// command branch reads not-ready often enough for the stream to slip in.
    ///
    /// The arm hold comes back as a [`ReleasedOnDrop`] for the same reason
    /// [`park_a_sync_keyed`]'s does: it parks a blocking-pool job, and every
    /// caller runs staging assertions while it is still held. A raw
    /// `HoldRelease` is only ever released on the success path, so a failing
    /// staging assertion would leave that job parked on the condvar and the
    /// test runtime's shutdown would wait on it forever — converting a
    /// fail-fast report into a hung binary.
    async fn starved_settle_rig() -> (
      Rig,
      ScopeId,
      Vec<String>,
      ReleasedOnDrop,
      futures_channel::oneshot::Receiver<CoverOutcome>,
    ) {
      let filler: Vec<String> = (0..flood_rig_width())
        .map(|i| format!("/r/d{i:02}"))
        .collect();
      let mut children: Vec<(&str, u64)> = vec![("/r/keep", 11), ("/r/drop", 12)];
      children.extend(
        filler
          .iter()
          .enumerate()
          .map(|(i, p)| (p.as_str(), 100 + i as u64)),
      );
      let (rig, scope) = covered_rig(&children).await;
      let full_cover: Vec<String> = children.iter().map(|(p, _)| (*p).to_owned()).collect();
      let without_drop: Vec<&str> = children
        .iter()
        .map(|(p, _)| *p)
        .filter(|p| *p != "/r/drop")
        .collect();
      let full: Vec<&str> = full_cover.iter().map(String::as_str).collect();
      let ack = send_set_cover(&rig, scope, &without_drop).await;
      assert_eq!(resolved(ack).await, CoverOutcome::Applied);
      let hold = ReleasedOnDrop(rig.fs.hold_arms());
      let ack = send_set_cover(&rig, scope, &full).await;
      // The reconcile has been applied once its re-arm read of the root
      // re-executed (its second /r enumerate); the /r/drop arm is parked.
      assert!(
        settle(|| enumerates_at(&rig, "/r") >= 2).await,
        "staging: the reconcile must be applied with the /r/drop arm parked, or the returned ack parks on nothing"
      );
      (rig, scope, full_cover, hold, ack)
    }

    /// Awaits a parked acknowledgement under a flood: same contract as
    /// [`resolved`], with headroom for the settle racing four spammers on an
    /// oversubscribed host — the normal resolution is still sub-second.
    async fn resolved_under_flood(
      ack: impl std::future::Future<Output = Result<CoverOutcome, futures_channel::oneshot::Canceled>>,
    ) -> CoverOutcome {
      tokio::time::timeout(interpreted_secs(45), ack)
        .await
        .expect("the fence settles within the deadline")
        .expect("the driver answers the parked reply")
    }

    /// How many filler threads a [`flood_commands`] flood runs.
    ///
    /// Four is what a real machine needs. The fillers must keep the lane
    /// GAPLESS, and on an oversubscribed host a single one can be descheduled
    /// between two of its own sends for long enough that the mailbox drains and
    /// the select reaches the source arm — the one thing every caller pins off.
    /// The other three cover that gap.
    ///
    /// An interpreter has no such gap to cover, because it has no parallelism to
    /// lose: every thread is interleaved onto the one interpreter, so a second
    /// filler cannot put a command into the mailbox any sooner than the first
    /// does. One saturates it outright — it takes all sixteen slots before the
    /// staging gate below returns, and across the whole flooded settle that
    /// follows the driver consumes only a handful of them, so the mailbox is
    /// never within reach of draining.
    ///
    /// The other three are not free there. Each parks on a short poll timeout
    /// and re-polls its registered send on every wake, and that cycle is
    /// interpreted work drawn from the SAME interpreter as the settle the caller
    /// is waiting on — enough of it to roughly double how long a flooded settle
    /// takes. So the interpreter runs the smallest flood that still starves the
    /// source, and the native lane keeps its gap insurance.
    fn flood_filler_threads() -> usize {
      if cfg!(miri) { 1 } else { 4 }
    }

    /// Saturates the 16-slot command channel with reply-less same-cover
    /// reconciles from four filler threads — the documented, test-pinned
    /// starvation capability (`command_flood_does_not_starve_op_completions`):
    /// while it runs, the command branch is ready at every loop-top poll, so
    /// the source stream is never selected and anything queued there stays
    /// queued; op completions still outrank it.
    ///
    /// The fillers are dedicated OS threads, not runtime tasks: a parked sender
    /// completes the instant the driver consumes a command, so the lane cannot
    /// GAP the way a task the scheduler has not reached yet does on an
    /// oversubscribed host — and a gap lets the select reach the source arm,
    /// which is the one thing every caller pins off. They park through
    /// [`send_watching_stop`], so stopping them is enough to end them whatever
    /// the driver is doing. Stop the flood with [`CommandFlood::stop`] and JOIN
    /// the fillers with [`CommandFlood::stop_and_join`] in wind-down.
    fn flood_commands(rig: &Rig, scope: ScopeId, cover: &[String]) -> CommandFlood {
      let stop = std::sync::Arc::new(AtomicBool::new(false));
      let spam_cover: Vec<PathBuf> = cover.iter().map(PathBuf::from).collect();
      let spammers =
        spawn_command_fillers(&rig.commands, &stop, flood_filler_threads(), move || {
          Command::SetCover {
            scope,
            retained: spam_cover.clone(),
            reply: None,
          }
        });
      CommandFlood { stop, spammers }
    }

    /// Waits until a [`flood_commands`] flood is provably OUTPACING the driver,
    /// and REPORTS the verdict — the precondition every caller stages before it
    /// injects the thing it needs to stay queued.
    ///
    /// The witness is the command mailbox observed FULL at least once: a
    /// bounded channel only fills when its producers outrun its consumer, and
    /// a driver whose command branch is ready at every loop-top poll is a
    /// driver whose select never reaches the source arm. A blind wall-clock
    /// pause proves none of that — on an oversubscribed host the filler threads
    /// can still be behind the driver when it expires, and the cell then
    /// measures an UNSTARVED schedule while asserting an outcome only
    /// starvation produces.
    ///
    /// This is a one-time STAGING gate, never an invariant. The driver consumes
    /// one command per loop iteration, so a saturated mailbox oscillates
    /// between full and one-slot-free; fullness is a snapshot that is
    /// legitimately false at arbitrary later instants. Having been full once is
    /// what establishes the capability, so no caller may re-read it afterwards
    /// as a steady state.
    #[must_use = "a flood that never saturated the mailbox never starved the source, and everything the caller queues afterwards can be consumed out from under it"]
    async fn flood_starves_the_source(rig: &Rig) -> bool {
      settle_within(3000, || rig.commands.is_full()).await
    }

    /// A flood wound down no later than its drop — the second half of the same
    /// obligation [`ReleasedOnDrop`] carries for a gate.
    ///
    /// While the fillers run the driver has an ALWAYS-READY command source: its
    /// loop can never observe a closed channel, so its task never completes and
    /// the runtime's blocking-pool shutdown waits on it forever. A caller that
    /// unwinds out of a staging assertion before its explicit wind-down
    /// therefore wedges shutdown exactly as a held gate does, and libtest never
    /// gets to print the failure. Winding down on drop keeps a failing assertion
    /// a REPORT.
    ///
    /// The wind-down does not depend on the driver still consuming: the fillers
    /// park through [`send_watching_stop`], which observes the stop flag, so
    /// both joins below are bounded by construction — after a close, after a
    /// driver task that has already exited its loop, and with no consumer at all
    /// (`a_command_flood_winds_down_with_no_consumer`).
    struct CommandFlood {
      stop: std::sync::Arc<AtomicBool>,
      spammers: Vec<std::thread::JoinHandle<()>>,
    }

    impl CommandFlood {
      /// Signals the fillers to stop without waiting for them — for the callers
      /// that must stop the flood at one point and join it at a later, ordered
      /// one.
      fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
      }

      /// The explicit wind-down: stops the fillers and JOINS every one of them,
      /// keeping the assertion that each terminates.
      fn stop_and_join(mut self) {
        self.stop();
        for spammer in std::mem::take(&mut self.spammers) {
          spammer.join().expect("the flood thread stops");
        }
      }
    }

    impl Drop for CommandFlood {
      fn drop(&mut self) {
        self.stop();
        // Joins without asserting: a panic raised while unwinding aborts the
        // process, destroying the very report this wind-down exists to allow.
        for spammer in std::mem::take(&mut self.spammers) {
          let _ = spammer.join();
        }
      }
    }

    /// The guard's own liveness pin: its DROP path must terminate with no
    /// consumer at all, because that is what an unwind past the explicit
    /// wind-down meets — a driver already past its loop in a close sweep, or one
    /// the panic left unpolled. A filler parked on a full mailbox wakes only
    /// when the channel drains or closes, so a wind-down that waits for a drain
    /// waits on a consumer that is gone and the join never returns; the fillers
    /// must observe the stop flag instead.
    ///
    /// Staged against a standalone channel whose receiver is HELD and never
    /// read: 16 slots taken, four fillers parked, nothing draining. The join
    /// runs on the blocking pool under a bounded await, so the regression this
    /// pins reports as a timeout rather than hanging the binary, and the
    /// receiver is dropped before the verdict so the fillers are freed either
    /// way. Worker count is irrelevant here and nothing in this cell pins one:
    /// the fillers are OS threads, and no consumer exists to schedule.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_command_flood_winds_down_with_no_consumer() {
      let (commands, receiver) = async_channel::bounded::<Command>(16);
      let ghost = ScopeId::new(core::num::NonZeroU64::new(999_999).unwrap());
      let stop = std::sync::Arc::new(AtomicBool::new(false));
      let spammers = spawn_command_fillers(&commands, &stop, 4, move || Command::SetCover {
        scope: ghost,
        retained: vec![PathBuf::from("/nowhere")],
        reply: None,
      });
      let flood = CommandFlood { stop, spammers };
      assert!(
        settle(|| commands.len() >= 16).await,
        "staging: the fillers must saturate the mailbox and park"
      );

      let wind_down = tokio::task::spawn_blocking(move || drop(flood));
      let bounded = tokio::time::timeout(interpreted_secs(5), wind_down).await;
      // Free the fillers before the verdict: a regression that wedged the join
      // above would otherwise wedge the runtime's own shutdown too, and the
      // report would be lost to a hang.
      drop(receiver);
      assert!(
        bounded.is_ok(),
        "the guard's drop path is bounded with no consumer to drain the mailbox"
      );
    }

    /// A loss the source elects BEFORE answering an arm batch must degrade
    /// the fence even when the reply is ingested first. The two travel on
    /// unordered channels — the loss on the source queue, the ACK on the op
    /// channel — and the op-first select can leave the queue unread right
    /// through the settle edge (here pinned deterministically by the command
    /// flood, with the transport's pending-overflow bit as the staging
    /// witness). The observation must ingest the queued loss before it may
    /// certify. Fail-on-old: the ACK quiesces the barrier, the next loop top
    /// resolves the fence `Applied` over a window the queued loss already
    /// voided, and the caller holds an uncorrectable clean certificate.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_loss_queued_behind_the_settling_ack_settles_degraded_not_applied() {
      let (rig, scope, full_cover, hold, ack) = starved_settle_rig().await;
      let flood = flood_commands(&rig, scope, &full_cover);
      assert!(
        flood_starves_the_source(&rig).await,
        "staging: the flood must be outpacing the driver before the loss is elected, or the \
         select still reaches the source arm and the loss is consumed long before the settle edge \
         this cell exists to measure"
      );

      // The loss lands on the QUEUE and — starved — stays there.
      rig.fs.send_lossy("/r");
      assert!(
        settle_within(300, || rig.fs.overflow_pending("/r")).await,
        "staging: the flood must keep the elected loss queued until the ACK lands"
      );

      // Release: the ACK outranks the flood, so the barrier quiesces while
      // the loss is still queued — the exact edge under test.
      hold.release();
      let outcome = resolved_under_flood(ack).await;
      flood.stop_and_join();
      assert_eq!(
        outcome,
        CoverOutcome::Degraded,
        "a loss elected before the settling reply is loss inside the window — never a clean certificate"
      );
      assert!(
        !rig.fs.overflow_pending("/r"),
        "the observation ingested the queued loss rather than certifying around it"
      );
    }

    /// The companion boundary: the SAME starved settle edge with only BENIGN
    /// traffic queued must still certify clean, in the same settle pass — the
    /// loss fence ingests what is queued but neither defers the observation
    /// nor degrades it for a mere non-empty queue — and the drained batch
    /// reaches the consumer rather than being dropped by the edge.
    #[tokio::test(flavor = "multi_thread")]
    async fn queued_benign_traffic_at_the_settle_edge_still_certifies_applied() {
      let (rig, scope, full_cover, hold, ack) = starved_settle_rig().await;
      let flood = flood_commands(&rig, scope, &full_cover);
      assert!(
        flood_starves_the_source(&rig).await,
        "staging: the flood must be outpacing the driver before the batch is injected, or the \
         select drains it early and the settle edge carries an EMPTY queue — the opposite of the \
         boundary this cell names"
      );

      // A plain change under the retained cover queues behind the starved
      // stream — no loss anywhere.
      let keep_watch = rig
        .fs
        .arms()
        .iter()
        .rev()
        .find(|(_, p)| p == std::path::Path::new("/r/keep"))
        .expect("the retained child is armed")
        .0;
      rig.fs.send_inotify_batch(
        "/r",
        vec![attributed(&[keep_watch], IN_CREATE, b"plain.txt")],
      );

      // Read the loss bit on BOTH sides of the barrier so a degraded verdict
      // names its own origin. This cell's premise is that no loss exists
      // anywhere: a loss already pending at the settle edge means the setup
      // elected one and the premise never held, whereas a loss that appears
      // only after the settle arose during the settle itself — a question
      // about the route the product took, not about how the cell was staged.
      // Nothing between the two reads may distinguish them, so the mailbox
      // depth and the root's read count are sampled at the same edge, ahead of
      // the wind-down that would decay both.
      let loss_before_release = rig.fs.overflow_pending("/r");
      hold.release();
      let outcome = resolved_under_flood(ack).await;
      let loss_after_settle = rig.fs.overflow_pending("/r");
      let root_reads = enumerates_at(&rig, "/r");
      let queued_commands = rig.commands.len();
      flood.stop_and_join();
      assert_eq!(
        outcome,
        CoverOutcome::Applied,
        "benign queued traffic is not loss: the fence neither defers nor degrades the clean \
         settle. Loss pending before the release: {loss_before_release} — true means the setup \
         staged a loss and this cell's premise never held. Loss pending after the settle: \
         {loss_after_settle} — true only there means a loss arose during the settle. Root reads: \
         {root_reads}; commands queued at the settle: {queued_commands}"
      );
      let mut delivered = false;
      for _ in 0..64 {
        let (_scope, change) = next_event(&rig).await;
        if change.location() == &loc(&["keep", "plain.txt"]) {
          delivered = true;
          break;
        }
      }
      assert!(
        delivered,
        "the batch drained at the settle edge reaches the consumer"
      );
    }

    /// The CLOSE-path twin of the settle-edge loss fence: an op result landing
    /// during the close grace can quiesce a fence's barrier while a loss the
    /// source elected earlier is still on the source queue (the grace drain
    /// services only the op channel), and the one final settlement poll must
    /// ingest that loss before it may resolve. Staged deterministically: the
    /// grow's LAST obligation — the re-installed child's re-arm read — is
    /// parked on the enumerate hold before close (so the grace can finish it
    /// with no effect flush), a command flood keeps the elected loss queued
    /// until `Close` breaks the loop with the fence still open, and the read
    /// is released only INSIDE the grace — the barrier settles with the loss
    /// still queued, exactly the edge the final poll's drain exists for.
    /// Fail-on-old: without that drain the final poll reads the
    /// grace-settled barrier as clean and resolves the parked ack `Applied`
    /// over a window the queued loss already voided — a fabricated clean
    /// certificate at close. Honest resolutions are `Degraded` (the drained
    /// loss marked the open fence) or the dropped reply (the drained loss
    /// re-held the barrier, so the fence rode the ratified close-mid-fence
    /// semantics) — never `Applied`; an overloaded host that outruns the
    /// 1 s grace degrades to the dropped reply, never to a false failure.
    ///
    /// EVERY staging step is asserted before `Close` is queued, and that is what
    /// licenses the dropped reply as honest: a dropped reply is only the
    /// close-mid-fence semantics if the fence was genuinely open over a queued
    /// loss when the loop broke. Tolerated silently, an expired staging budget
    /// would make this cell an ordinary close — no parked read, no queued loss —
    /// whose dropped reply then reads as a pass without the drain ever running.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_loss_queued_across_close_never_resolves_the_parked_ack_applied() {
      let (rig, scope, full_cover, hold, ack) = starved_settle_rig().await;
      // Quiesce the grow's survivor cascade so the parked re-install is the
      // barrier's ONE outstanding obligation and the enumerate hold below can
      // only ever capture that install's follow-up read.
      let survivors: Vec<&str> = full_cover
        .iter()
        .map(String::as_str)
        .filter(|p| *p != "/r/drop")
        .collect();
      assert!(
        settle_within(3000, || {
          survivors.iter().all(|p| enumerates_at(&rig, p) >= 2)
        })
        .await,
        "staging: the grow's survivor cascade must quiesce, or the hold below \
         captures a survivor's read instead of the re-install's"
      );

      // Convert the parked install into a parked READ: releasing the arms
      // lands the install's ack live, and its re-arm read — the quiesce above
      // left nothing else to bind — then parks on the enumerate hold,
      // dispatched to the pool BEFORE close so the op-only grace drain can
      // complete it in-grace.
      let read_hold = ReleasedOnDrop(rig.fs.hold_enumerates());
      hold.release();
      assert!(
        settle_within(3000, || arms_at(&rig, "/r/drop") >= 2).await,
        "staging: the released arm must re-install /r/drop, whose follow-up read is the barrier's last obligation"
      );
      assert!(
        settle_within(3000, || read_hold.captured() >= 1).await,
        "staging: that read must be PARKED on the pool before close, or the grace has nothing to settle the barrier with"
      );

      // The flood starves the source arm; the loss lands on the QUEUE and
      // stays there through the break.
      let flood = flood_commands(&rig, scope, &full_cover);
      assert!(
        flood_starves_the_source(&rig).await,
        "staging: the flood must be outpacing the driver before the loss is elected, or the \
         select still reaches the source arm and the loss is ingested long before close breaks \
         the loop"
      );
      rig.fs.send_lossy("/r");
      assert!(
        settle_within(300, || rig.fs.overflow_pending("/r")).await,
        "staging: the flood must keep the elected loss queued until close breaks the loop"
      );

      // Hold teardowns so the grace drain outlives the release below, then
      // race Close into the flooded mailbox (FIFO: once queued it is reached
      // behind at most one mailbox of spam).
      let teardown_hold = ReleasedOnDrop(rig.fs.hold_teardowns());
      let (creply, on_close) = futures_channel::oneshot::channel();
      let mut close = Command::Close { reply: creply };
      loop {
        match rig.commands.try_send(close) {
          Ok(()) => break,
          Err(async_channel::TrySendError::Full(returned)) => {
            close = returned;
            tokio::task::yield_now().await;
          }
          Err(async_channel::TrySendError::Closed(_)) => {
            unreachable!("the driver holds the command receiver until close")
          }
        }
      }
      // The parked shutdown proves the loop broke and the close sweep ran. A
      // generous budget only ever costs grace: the sweep's teardown dispatch is
      // immediate once the FIFO reaches `Close`, and a host slow enough to spend
      // the 1 s grace here lands on the dropped reply, which is honest.
      assert!(
        settle_within(3000, || teardown_hold.captured() >= 1).await,
        "staging: the close sweep must have run — without the broken loop there is no grace to settle in"
      );
      flood.stop();

      // INSIDE the grace: the released read completes through the op channel
      // and the barrier settles — while the loss is still queued.
      read_hold.release();
      assert!(
        settle_within(3000, || enumerates_at(&rig, "/r/drop") >= 2).await,
        "staging: the released read must complete, or the barrier never settles inside the grace"
      );
      tokio::time::sleep(Duration::from_millis(50)).await;
      teardown_hold.release();

      let _ = on_close.await.expect("close replies");
      // The verdict is captured, and the flood wound down, BEFORE anything is
      // inspected: the reply is already sent, so neither step can move it, and
      // a failing assertion must not be able to jump over the join. Nothing
      // drains this mailbox any more — the driver is past its loop — so the join
      // is bounded only because the fillers observe the stop flag while parked.
      let resolved_ack = ack.await;
      flood.stop_and_join();
      // A dropped reply is the drained loss re-holding the barrier, so the
      // fence fell with the driver — the ratified close-mid-fence `Closed`,
      // equally honest. Any RESOLVED verdict, though, must be the degraded
      // one, with the queued loss provably ingested.
      if let Ok(outcome) = resolved_ack {
        assert_eq!(
          outcome,
          CoverOutcome::Degraded,
          "a loss queued across close is loss inside the window — never a clean certificate"
        );
        assert!(
          !rig.fs.overflow_pending("/r"),
          "the final settle poll ingested the queued loss rather than certifying around it"
        );
      }
    }

    // A parked sync is a ledger obligation from admission. Birth is admission,
    // not dispatch: a sync admitted onto its settle fence is a full obligation —
    // counted by the global cap Φ, marked by a cancel, swept by teardown and
    // close — before any write reaches the pool. These cells hold a sync PARKED
    // (a held grow keeps the scope un-settled) and pin the pre-dispatch lifecycle
    // end to end. The birth-at-dispatch predecessor has no record for a parked
    // sync, so `park_a_sync`'s count assertion is the shared fail-on-old
    // discriminator for every cell below.

    /// The ledger's live obligation count, read end to end (the global gauge Φ).
    async fn debug_cookie_count(rig: &Rig) -> usize {
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::DebugCookieCount { reply })
        .await
        .unwrap();
      on_reply.await.expect("the driver replies")
    }

    /// The birth/terminal census paired with the live record count.
    async fn debug_census(rig: &Rig) -> (Census, usize) {
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::DebugCookieCensus { reply })
        .await
        .unwrap();
      on_reply.await.expect("the driver replies")
    }

    /// Settles until the ledger holds exactly `target` obligations.
    async fn settle_count(rig: &Rig, target: usize) {
      for _ in 0..200 {
        if debug_cookie_count(rig).await == target {
          return;
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
      }
    }

    /// Admits a sync that PARKS on its scope's coverage-settle fence: a held grow
    /// keeps `/r/drop`'s re-install in flight, so the coverage never settles and
    /// the admitted write cannot dispatch. Returns the arm hold (release it to let
    /// the fence settle) and the caller's reply receiver.
    ///
    /// The hold comes back as a [`ReleasedOnDrop`], because the gate it installs
    /// parks a blocking-pool job and this helper's OWN assertions run while it is
    /// held: a raw release could only ever be reached on the success path, and a
    /// panic here — or in any caller — would leave the job parked and wedge the
    /// runtime's shutdown instead of reporting the failure.
    ///
    /// The sync is genuinely ADMITTED — its obligation is born and parked — but no
    /// write has reached the pool. The `count == 1` assertion here is the whole
    /// suite's fail-on-old anchor: on birth-at-dispatch a parked sync has no
    /// record, so this count stays 0 and every cell below fails.
    /// Parks a sync under a fresh ticket (see [`park_a_sync_keyed`] for the
    /// cancel-by-ticket form).
    async fn park_a_sync(
      rig: &Rig,
      scope: ScopeId,
      name: &str,
    ) -> (
      ReleasedOnDrop,
      futures_channel::oneshot::Receiver<Result<PathBuf, crate::error::SyncRootError>>,
    ) {
      park_a_sync_keyed(rig, scope, name, ticket()).await
    }

    async fn park_a_sync_keyed(
      rig: &Rig,
      scope: ScopeId,
      name: &str,
      ticket: SyncTicket,
    ) -> (
      ReleasedOnDrop,
      futures_channel::oneshot::Receiver<Result<PathBuf, crate::error::SyncRootError>>,
    ) {
      let hold = ReleasedOnDrop(rig.fs.hold_arms());
      let _ack = send_set_cover(rig, scope, &["/r/keep", "/r/drop"]).await;
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::SyncRoot {
          scope,
          dir: PathBuf::from("/r"),
          name: name.to_owned(),
          ticket,
          reply,
        })
        .await
        .unwrap();
      settle_count(rig, 1).await;
      assert_eq!(
        debug_cookie_count(rig).await,
        1,
        "a parked sync is a counted obligation from admission, before any write dispatches"
      );
      assert!(
        rig.fs.cookie_writes().is_empty(),
        "no write is dispatched while the sync is parked"
      );
      (hold, on_reply)
    }

    /// The parked obligation is a counted, pre-physical record, and its dispatch
    /// is a TRANSITION of that record — never a second birth. Admission births it
    /// `Parked`, the settle moves it `Parked → InPool` under the SAME id, and the
    /// census counts exactly one birth across the whole life.
    ///
    /// Fail-on-old (birth-at-dispatch): while parked there is no record, so
    /// `park_a_sync`'s `count == 1` — and the census `births == 1` here — both fail.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_parked_sync_is_one_counted_obligation_and_dispatch_only_transitions_it() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;
      let (hold, on_reply) = park_a_sync(&rig, scope, ".tributaries-sync-parked-1").await;

      // The birth is counted structurally, with no dispatch yet — captured
      // UNINSPECTED, because the hold still parks a blocking-pool job and a
      // failing assertion must reach its report, not the runtime's shutdown.
      let parked = debug_census(&rig).await;

      // Release the fence: the SAME record transitions to the pool and its write
      // lands. Dispatch is a transition, not a birth.
      hold.release();
      let dispatched = tokio::time::timeout(interpreted_secs(10), on_reply).await;
      let settled = debug_census(&rig).await;

      let (census, live) = parked;
      assert_eq!(
        (census.births, live),
        (1, 1),
        "admission births the parked obligation; the global gauge counts it in one term"
      );
      assert!(
        census.balances(live),
        "the census balances a parked, pre-physical record"
      );
      let path = dispatched
        .expect("the write lands once the fence settles")
        .expect("the driver replies")
        .expect("the parked sync dispatches and claims");
      assert_eq!(path, PathBuf::from("/r/.tributaries-sync-parked-1"));
      let (census, _) = settled;
      assert_eq!(
        census.births, 1,
        "the settle moved the record Parked → InPool under one id — one birth for the whole life"
      );
    }

    /// T13: cancelling a sync while it is PARKED marks its obligation and retires
    /// it `NeverCreated` — nothing physical was ever created — answering the caller
    /// `Retired`, dispatching no write, unlinking nothing. The cancel folds into
    /// the phase machine: the mark rides the record, the driver's reap handling
    /// retires it.
    ///
    /// Fail-on-old (birth-at-dispatch): the parked sync has no record to mark or
    /// count, so the census `(births, never_created) == (1, 1)` fails (it is
    /// `(0, 0)`), as does `park_a_sync`'s count.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_cancel_of_a_parked_sync_retires_it_never_created() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;
      let name = ".tributaries-sync-parked-cancel";
      let t = ticket();
      let (hold, on_reply) = park_a_sync_keyed(&rig, scope, name, t).await;

      // Cancel by ticket while parked: the ingress marks the obligation and the
      // driver's wake sweep retires it pre-physically, answering the caller Retired.
      rig.cleanup.request_cancel(t);
      // Every verdict is captured UNINSPECTED and the held arm released — so the
      // pool drains, and nothing more can dispatch — BEFORE anything is read out:
      // an assertion that jumped over the release would leave a pool job parked
      // on the gate and hang the runtime's shutdown instead of reporting.
      let answered = tokio::time::timeout(interpreted_secs(5), on_reply).await;
      settle_count(&rig, 0).await;
      let (census, live) = debug_census(&rig).await;
      let writes = rig.fs.cookie_writes();
      let removes = rig.fs.cookie_removes();
      hold.release();

      assert!(
        matches!(
          answered
            .expect("the cancel resolves the parked caller")
            .expect("the driver replies"),
          Err(crate::error::SyncRootError::Retired)
        ),
        "a cancel of a parked sync answers Retired"
      );
      assert_eq!(
        (census.births, census.never_created, live),
        (1, 1, 0),
        "the parked obligation earns the pre-physical NeverCreated terminal"
      );
      assert!(
        census.balances(live),
        "births = terminals + live across the cancel"
      );
      assert!(
        writes.is_empty(),
        "no write was ever dispatched for the cancelled parked sync"
      );
      assert!(
        removes.is_empty(),
        "and nothing physical existed to unlink — a parked record is never unlinked"
      );
    }

    /// A stream `Fatal` ingested INSIDE the settle-edge drain answers the dying
    /// scope's parked sync `Retired` and retires its obligation `NeverCreated` —
    /// from the settlement verdict alone, at an instant when every liveness map the
    /// driver owns still describes the scope as live.
    ///
    /// The interleaving, and why it is the one that matters. The drain that arms
    /// when a settlement is due ingests the death SYNCHRONOUSLY: the core drops the
    /// scope and folds its pending fences inside that statement, but
    /// `Effect::TeardownStream` — the sole clearer of `handles`, `root_of` and the
    /// retiring flag — is merely QUEUED. `resolve_cover_settlements` then runs with
    /// NO `execute_effects` between, so a parked-cookie branch that re-derives
    /// liveness from those maps reads a scope that is already gone as live,
    /// dispatches its cookie write, and answers the caller `Ok` for a barrier no
    /// live stream can ever report the cookie on. The verdict carries the fact
    /// instead, and the branch short-circuits on it before consulting any map.
    ///
    /// Staging it needs two scopes and a saturated command mailbox, and neither is
    /// incidental:
    ///
    /// - the drain arms on `cover_fences.keys().any(barrier_settled)` — ANY scope —
    ///   so it is the QUIESCENT scope's reconcile window that holds the drain open
    ///   while the other scope's death is ingested inside it. One scope cannot
    ///   stage this at all: its own fence resolves the instant its barrier settles,
    ///   and while the barrier is held nothing is due, so the drain never arms.
    /// - a saturated mailbox keeps the command-biased select off the source arm, so
    ///   the drain is the stream's ONLY reader. Taken by the select instead, the
    ///   death lands in a pass that flushes effects BEFORE the resolve, the maps are
    ///   already cleared, and the fallback answers correctly for the wrong reason —
    ///   which is exactly why the `Unwatch` twin below witnesses nothing here.
    ///
    /// Fail-on-old (re-derive the death from the driver's maps instead of the
    /// verdict): they still read live, so the cookie write dispatches and
    /// `cookie_writes()` is no longer empty.
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn an_in_band_fatal_under_a_parked_sync_retires_it_from_the_verdict() {
      let (rig, dying) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;

      // The second scope, on its own root and its own source: a same-cover
      // reconcile of it is a structural no-op (nothing outside to prune, an empty
      // broadening delta to grow) that still re-opens its fence entry, and its
      // barrier is up because nothing of its own is in flight. Its cold read is
      // awaited so that is true from the first flood command on.
      rig.fs.put("/quiet", FileKind::Dir, 20);
      let quiet = watch(&rig, "/quiet").await;
      assert!(
        settle(|| {
          rig
            .fs
            .enumerates()
            .iter()
            .any(|(_, p)| p == std::path::Path::new("/quiet"))
        })
        .await,
        "staging: the quiescent scope's cold read must complete, or its barrier is not up when the flood starts"
      );

      shrunk_to_keep(&rig, dying).await;
      let (hold, on_reply) = park_a_sync(&rig, dying, ".tributaries-sync-parked-fatal").await;

      // The flood, established BEFORE the death is queued and held up until the
      // caller is answered: dedicated OS threads keep the bounded mailbox saturated,
      // so the instant the driver consumes a command a parked sender completes and
      // the lane never gaps the way runtime-scheduled tasks do.
      // Every command is a reply-less same-cover reconcile of the quiescent root, so
      // it enqueues no work of its own and its ONLY effect is to re-open that scope's
      // fence entry — which the resolve consumes each pass and the next command
      // restores. Every pass is therefore a due pass with the drain armed, and no
      // pass can reach the source arm.
      let flood_stop = std::sync::Arc::new(AtomicBool::new(false));
      let spammers =
        spawn_command_fillers(&rig.commands, &flood_stop, 2, move || Command::SetCover {
          scope: quiet,
          retained: vec![PathBuf::from("/quiet")],
          reply: None,
        });
      // Handed to the guard the moment it exists: everything below — the staging
      // settle included — can unwind, and a live flood keeps the driver's command
      // source ready forever, so an unwind past the explicit wind-down would wedge
      // the blocking-pool shutdown instead of reporting the failure.
      let flood = CommandFlood {
        stop: flood_stop,
        spammers,
      };
      assert!(
        settle(|| rig.commands.len() >= 16).await,
        "staging: the flood must own the command lane before the death is queued"
      );

      // The death, queued on the dying scope's source with the select pinned off it:
      // the drain is what ingests it, one statement above the resolve.
      rig.fs.send_fatal("/r");

      // Both verdicts are captured UNINSPECTED, then the rig is wound down before
      // anything can panic — including the timeout's own unwrap. The arm hold parks
      // a blocking-pool job, and a panic that jumped over its release would wedge
      // the runtime's shutdown and hang instead of reporting the failure. Neither
      // wind-down step can move a verdict: the fence is resolved, the scope is
      // dead, and the cookie left `parked_cookies` in the very step under test.
      let answered = tokio::time::timeout(interpreted_secs(10), on_reply).await;
      let writes = rig.fs.cookie_writes();
      hold.release();
      flood.stop_and_join();

      let answered = answered
        .expect("the in-band death resolves the parked caller")
        .expect("the driver replies");
      assert!(
        matches!(answered, Err(crate::error::SyncRootError::Retired)),
        "a scope killed inside the drain answers its parked sync Retired: {answered:?}"
      );
      assert!(
        writes.is_empty(),
        "no write is dispatched for a scope that died under the fence: {writes:?}"
      );

      settle_count(&rig, 0).await;
      let (census, live) = debug_census(&rig).await;
      assert_eq!(
        (census.births, census.never_created, live),
        (1, 1, 0),
        "the obligation earns the pre-physical terminal, not a physical one"
      );
      assert!(
        census.balances(live),
        "births = terminals + live across the in-band death"
      );
    }

    /// Tearing down a scope while its sync is PARKED retires the obligation
    /// `NeverCreated` and answers the caller `Retired`: the teardown resolves the
    /// sync's fence `Dead`, reaching the pre-physical terminal — no write ever
    /// dispatched, nothing to unlink.
    ///
    /// The command route, as against the in-band route above. Both now resolve
    /// through the verdict, because the verdict travels with the fence and does not
    /// depend on when `Effect::TeardownStream` clears the driver's maps — which is
    /// why this cell cannot witness that ordering and the in-band one can.
    ///
    /// Fail-on-old (birth-at-dispatch): no record is born or counted for the parked
    /// sync, so the census `(births, never_created) == (1, 1)` fails.
    #[tokio::test(flavor = "multi_thread")]
    async fn unwatching_a_scope_with_a_parked_sync_retires_it_never_created() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;
      let (hold, on_reply) = park_a_sync(&rig, scope, ".tributaries-sync-parked-unwatch").await;

      let (reply, on_unwatch) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Unwatch {
          scope,
          reply: Some(reply),
        })
        .await
        .unwrap();
      // Captured UNINSPECTED, then wound down — the held arm released and the
      // unwatch reply drained — before a single verdict is read out: the hold
      // parks a blocking-pool job, and an assertion that jumped over its release
      // would hang the runtime's shutdown instead of reporting the failure.
      let answered = tokio::time::timeout(interpreted_secs(5), on_reply).await;
      settle_count(&rig, 0).await;
      let (census, live) = debug_census(&rig).await;
      let writes = rig.fs.cookie_writes();
      let removes = rig.fs.cookie_removes();
      hold.release();
      let _ = tokio::time::timeout(interpreted_secs(5), on_unwatch).await;

      assert!(
        matches!(
          answered
            .expect("the teardown resolves the parked caller")
            .expect("the driver replies"),
          Err(crate::error::SyncRootError::Retired)
        ),
        "a scope torn down under a parked sync answers it Retired"
      );
      assert_eq!(
        (census.births, census.never_created, live),
        (1, 1, 0),
        "the torn-down scope's parked obligation earns NeverCreated"
      );
      assert!(
        census.balances(live),
        "births = terminals + live across the teardown"
      );
      assert!(
        writes.is_empty() && removes.is_empty(),
        "no write was dispatched and nothing physical existed to unlink"
      );
    }

    /// Closing while a sync is PARKED retires the obligation (the close sweep
    /// reaches it before the drain) and answers the caller `Retired`, so a
    /// pre-physical record never wedges close nor is mistaken for a hung cookie:
    /// close reports a clean quiescent count.
    ///
    /// Fail-on-old (birth-at-dispatch): the parked sync has no record, so
    /// `park_a_sync`'s `count == 1` before close fails.
    #[tokio::test(flavor = "multi_thread")]
    async fn closing_with_a_parked_sync_retires_it_and_reports_quiescent() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;
      let (hold, on_reply) = park_a_sync(&rig, scope, ".tributaries-sync-parked-close").await;

      // The parked obligation is counted right up to the close sweep — read here,
      // where it is still pre-close, and asserted only after the wind-down.
      let counted = debug_cookie_count(&rig).await;

      let (reply, on_close) = futures_channel::oneshot::channel();
      rig.commands.send(Command::Close { reply }).await.unwrap();
      // Both replies and the physical ledger are captured UNINSPECTED, then the
      // held arm is released, and only THEN is anything read out: the hold parks
      // a blocking-pool job that an assertion jumping over the release would
      // leave parked, hanging the runtime's shutdown instead of reporting. The
      // release cannot move a verdict — close has already answered both callers.
      let answered = tokio::time::timeout(interpreted_secs(5), on_reply).await;
      let closed = tokio::time::timeout(interpreted_secs(5), on_close).await;
      let writes = rig.fs.cookie_writes();
      let removes = rig.fs.cookie_removes();
      hold.release();

      assert_eq!(
        counted, 1,
        "the parked sync is a counted obligation the close sweep must resolve"
      );
      assert!(
        matches!(
          answered
            .expect("close resolves the parked caller")
            .expect("the driver replies"),
          Err(crate::error::SyncRootError::Retired)
        ),
        "close answers a parked sync Retired"
      );
      let outstanding = closed
        .expect("close returns within grace")
        .expect("the driver replies");
      assert_eq!(
        outstanding, 0,
        "the parked obligation was retired at close, never counted as a non-quiesced cookie"
      );
      assert!(
        writes.is_empty() && removes.is_empty(),
        "no write was dispatched and nothing physical existed to unlink"
      );
    }

    /// The FAIL-CLOSED unwind path, end to end: a control batch that DIES on the
    /// blocking pool takes its scope down, rather than leaving the scope owed
    /// answers nobody can ever give.
    ///
    /// The batch that dies here is the ordering-proof round trip — the empty batch
    /// a settled CLEAN window asks for — and its death is the unrecoverable one.
    /// Withholding the proof (the completion carries `completed == false`, so no
    /// `prove_cut` runs) is necessary but NOT sufficient, because the fence is
    /// already latched `InFlight(token)` and that latch is a dead end:
    /// `covers_awaiting_cut` offers only an `Unproven` fence, so the request is
    /// never re-asked, and `poll_cover_settlements` skips a clean fence whose proof
    /// is not `Proven`, so the window never resolves. A `set_cover` ack parked on
    /// it — and a `sync_root` admitted onto the same window — would then wait
    /// forever on a reply that cannot be produced, while the scope stayed live
    /// behind an unbacked coverage claim.
    ///
    /// So `completed == false` routes `on_source_fatal` instead: the scope's queued
    /// control batches are dropped and its teardown fold answers everything it owed
    /// — fences `Dead`, parked grants retired pre-physically — and submits nothing
    /// further over kernel state that no arm result describes.
    ///
    /// The staging, step by step, and why each step is load-bearing:
    ///
    /// - the GROW is held FIRST, so the barrier is DOWN while the sync is
    ///   admitted. A proof is only asked of a SETTLED window, so nothing is latched
    ///   yet and both fences join the entry ahead of the single latch below.
    ///   Admitting the sync AFTER a latch would reset the proof (a fence may not
    ///   inherit one older than itself) and queue a SECOND round trip, whose reply
    ///   would close the very fence the first one's death stranded — the defect
    ///   would repair itself and the cell would witness nothing.
    /// - the gate is then SUPERSEDED rather than reopened. The grow's batch holds
    ///   the old gate instance and is already past the death arm, so releasing that
    ///   instance lets its arm land while every LATER batch parks on the new gate.
    ///   That is what puts the death on the proof round trip instead of the grow.
    /// - the frozen batch is asserted EMPTY, which is the round trip's signature:
    ///   an arm or a disarm batch carries requests, this one carries nothing but
    ///   the reply.
    ///
    /// Every await is bounded, so the regression this pins reports as a loud
    /// timeout and never as a hung binary.
    ///
    /// MUTATION WITNESS: revert the branch to withholding the proof ALONE — keep
    /// `pending_control`, still `kick_control_queue` — and this cell FAILS. The
    /// fence stays `InFlight` on a request whose batch is dead, so neither the
    /// cover ack nor the sync is ever answered and both bounded awaits expire.
    ///
    /// One panic is printed from a blocking-pool thread while this cell runs: it is
    /// the injected death, not a failure. Tokio catches it in the task harness, the
    /// pool thread survives, and the one-shot arm is spent.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_dead_control_batch_fails_the_scope_closed_and_answers_what_it_owed() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;

      // A GROW held on the pool: re-installing /r/drop is counted re-arm work, so
      // the barrier is DOWN and no ordering proof can be asked for yet.
      let grow_hold = ReleasedOnDrop(rig.fs.hold_arms());
      let mut ack = Box::pin(send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await);

      // A sync admitted onto the SAME un-settled window: one fence entry, two
      // fences, so the single proof request below covers both and the death has two
      // callers to answer.
      let (sync_reply, on_sync) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::SyncRoot {
          scope,
          dir: PathBuf::from("/r"),
          name: ".tributaries-sync-dead-batch".to_owned(),
          ticket: ticket(),
          reply: sync_reply,
        })
        .await
        .unwrap();
      let mut on_sync = Box::pin(on_sync);
      settle_count(&rig, 1).await;
      assert_eq!(
        debug_cookie_count(&rig).await,
        1,
        "staging: the sync is admitted and parked on the same window as the cover ack"
      );
      assert!(
        settle(|| grow_hold.captured() >= 1).await,
        "staging: the grow's arm batch reached the fake and parked, so it is already past the death arm"
      );

      // Supersede the gate, THEN release the old one: the grow completes and its
      // arm lands, while the batch the settled window asks for next parks here.
      let proof_hold = ReleasedOnDrop(rig.fs.hold_arms());
      grow_hold.release();
      assert!(
        settle(|| proof_hold.captured() >= 1).await,
        "staging: a later batch parked on the superseding gate — which can only be \
         submitted on the grow batch's completion, so the grow is done"
      );
      assert_eq!(
        arms_at(&rig, "/r/drop"),
        2,
        "staging: the grow's re-install of /r/drop ran to completion (cold discovery, then this)"
      );
      let submitted = rig.fs.control_batches();
      assert_eq!(
        submitted.last(),
        Some(&(scope, 0)),
        "staging: the parked batch carries NO requests — the ordering-proof round trip, \
         not an arm or disarm batch: {submitted:?}"
      );
      assert!(
        futures_util::poll!(ack.as_mut()).is_pending()
          && futures_util::poll!(on_sync.as_mut()).is_pending(),
        "staging: both callers are still parked, waiting on exactly that round trip"
      );
      let submitted_before_death = submitted.iter().filter(|(s, _)| *s == scope).count();
      assert_eq!(
        rig.fs.shutdowns(),
        0,
        "staging: the scope's stream is still live going into the death"
      );

      // Kill it. The batch unwinds, its completion reports `completed == false`, and
      // the scope must fail closed.
      rig.fs.panic_next_control_batch(scope);
      proof_hold.release();

      // Bounded on both legs: the defect this pins is a barrier that waits forever,
      // so an unanswered caller must surface as an expiring timeout.
      let cover = tokio::time::timeout(interpreted_secs(10), ack.as_mut()).await;
      let synced = tokio::time::timeout(interpreted_secs(10), on_sync.as_mut()).await;

      // Named first and together, because "neither caller was ever answered" is the
      // whole defect and a per-leg expect below would report only half of it.
      let leg = |ok: bool| if ok { "answered" } else { "TIMED OUT" };
      assert!(
        cover.is_ok() && synced.is_ok(),
        "both callers must be ANSWERED, never left on a proof that cannot arrive \
         (cover ack: {}, parked sync: {})",
        leg(cover.is_ok()),
        leg(synced.is_ok())
      );
      let cover = cover
        .expect("the dead batch answers the parked cover ack")
        .expect("the driver answers the parked reply");
      assert_eq!(
        cover,
        CoverOutcome::Degraded,
        "a scope that died under the fence reports the degraded verdict, never Applied"
      );
      let synced = synced
        .expect("the dead batch answers the parked sync")
        .expect("the driver answers the parked reply");
      assert!(
        matches!(synced, Err(crate::error::SyncRootError::Retired)),
        "the parked sync earns the pre-physical terminal, answered rather than stranded: {synced:?}"
      );

      // CLOSED, not merely answered: the scope's stream is gone. Both callers could
      // in principle be resolved by a scope that stayed live over kernel state no
      // arm result describes; this is the assertion that says it did not.
      assert!(
        settle(|| rig.fs.shutdowns() >= 1).await,
        "the dead batch failed the scope CLOSED — its stream was torn down rather than \
         left live behind a coverage claim nothing backs"
      );

      settle_count(&rig, 0).await;
      let (census, live) = debug_census(&rig).await;
      assert_eq!(
        (census.births, census.never_created, live),
        (1, 1, 0),
        "nothing physical was ever created for the parked sync, and its record is retired"
      );
      assert!(
        census.balances(live),
        "births = terminals + live across the dead batch"
      );
      assert!(
        rig.fs.cookie_writes().is_empty(),
        "no cookie write is dispatched for a scope that died under its own fence: {:?}",
        rig.fs.cookie_writes()
      );

      // Nothing further is submitted for the dead scope: its queue was dropped with
      // it, so no batch runs over kernel state no arm result describes.
      for _ in 0..40 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      let submitted_for_scope = rig
        .fs
        .control_batches()
        .iter()
        .filter(|(s, _)| *s == scope)
        .count();
      assert_eq!(
        submitted_for_scope, submitted_before_death,
        "the dead scope submitted no further control batch (before: {submitted_before_death}, \
         after: {submitted_for_scope})"
      );

      // And close is not left holding the scope's debts.
      let (reply, on_close) = futures_channel::oneshot::channel();
      rig.commands.send(Command::Close { reply }).await.unwrap();
      let outstanding = tokio::time::timeout(interpreted_secs(10), on_close)
        .await
        .expect("close returns within grace rather than wedging on the dead scope")
        .expect("the driver replies");
      assert_eq!(
        outstanding, 0,
        "close reports quiescence — the dead scope's obligation was retired, not left hanging"
      );
    }

    /// The FAIL-CLOSED path for the OTHER way a batch goes unanswered: the reader
    /// dies between dequeuing the ordering-proof round trip and replying to it, so
    /// `batch_control` RETURNS — normally, with nothing to show for it.
    ///
    /// Nothing in the return distinguishes that from a served batch. The proof
    /// round trip carries no arms, so it resolves none either way, and the two
    /// returns are one empty vector each. Read as a completion it certifies the
    /// reader's pre-reply cut, which is the whole content of the proof: the driver
    /// grants it, the settled window resolves CLEAN, the parked cover ack answers
    /// `Applied` and the parked sync dispatches its cookie — all over a stream whose
    /// reader is already gone and whose kernel queue was never cut onto the lane.
    /// The stream death that follows can retract none of it.
    ///
    /// So the answer travels beside the replies rather than inside them, and it is
    /// what `completed` is set from. An unanswered batch then takes the same
    /// terminal an unwinding one does — the scope's queued control dropped, its
    /// fences folded `Dead`, its parked callers resolved as failures — because what
    /// is unknown is identical: how far the batch got, and what its callers are
    /// still owed.
    ///
    /// Staged exactly as the unwind cell above it, whose reasoning applies here
    /// unchanged; only the death differs, and it is the death that is the point.
    ///
    /// MUTATION WITNESS: let the completion report `completed: true` for a batch
    /// nobody answered — the one bit the returns have in common — and this cell
    /// FAILS: the cut is proven, the cover ack comes back `Applied`, the sync's
    /// cookie is written, and the scope stays live.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unanswered_control_batch_grants_no_proof_and_fails_the_scope_closed() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;
      shrunk_to_keep(&rig, scope).await;

      // A GROW held on the pool: re-installing /r/drop is counted re-arm work, so
      // the barrier is DOWN and no ordering proof can be asked for yet.
      let grow_hold = ReleasedOnDrop(rig.fs.hold_arms());
      let mut ack = Box::pin(send_set_cover(&rig, scope, &["/r/keep", "/r/drop"]).await);

      // A sync admitted onto the SAME un-settled window: one fence entry, two
      // fences, so the single proof request below covers both — and the sync is what
      // makes the dispatch half of this observable, since a granted proof would send
      // its cookie write to the filesystem.
      let (sync_reply, on_sync) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::SyncRoot {
          scope,
          dir: PathBuf::from("/r"),
          name: ".tributaries-sync-unanswered-batch".to_owned(),
          ticket: ticket(),
          reply: sync_reply,
        })
        .await
        .unwrap();
      let mut on_sync = Box::pin(on_sync);
      settle_count(&rig, 1).await;
      assert_eq!(
        debug_cookie_count(&rig).await,
        1,
        "staging: the sync is admitted and parked on the same window as the cover ack"
      );
      assert!(
        settle(|| grow_hold.captured() >= 1).await,
        "staging: the grow's arm batch reached the fake and parked, so it is already past the death arm"
      );

      // Supersede the gate, THEN release the old one: the grow completes and its
      // arm lands, while the batch the settled window asks for next parks here.
      let proof_hold = ReleasedOnDrop(rig.fs.hold_arms());
      grow_hold.release();
      assert!(
        settle(|| proof_hold.captured() >= 1).await,
        "staging: a later batch parked on the superseding gate — which can only be \
         submitted on the grow batch's completion, so the grow is done"
      );
      let submitted = rig.fs.control_batches();
      assert_eq!(
        submitted.last(),
        Some(&(scope, 0)),
        "staging: the parked batch carries NO requests — the ordering-proof round trip, \
         whose empty return is precisely what a dead reader's is: {submitted:?}"
      );
      assert!(
        futures_util::poll!(ack.as_mut()).is_pending()
          && futures_util::poll!(on_sync.as_mut()).is_pending(),
        "staging: both callers are still parked, waiting on exactly that round trip"
      );
      assert_eq!(
        rig.fs.shutdowns(),
        0,
        "staging: the scope's stream is still live going into the death"
      );

      // Kill the READER, not the worker: the batch returns, and only its answer
      // says the reader was never there to serve it.
      rig.fs.kill_next_control_reader(scope);
      proof_hold.release();

      // Bounded on both legs: a proof that is withheld without the fail-closed
      // terminal strands both callers, which must surface as an expiring timeout
      // rather than a hung binary.
      let cover = tokio::time::timeout(interpreted_secs(10), ack.as_mut()).await;
      let synced = tokio::time::timeout(interpreted_secs(10), on_sync.as_mut()).await;
      let leg = |ok: bool| if ok { "answered" } else { "TIMED OUT" };
      assert!(
        cover.is_ok() && synced.is_ok(),
        "both callers must be ANSWERED, never left on a proof that cannot arrive \
         (cover ack: {}, parked sync: {})",
        leg(cover.is_ok()),
        leg(synced.is_ok())
      );

      // Half one: the proof was NOT granted. A clean `Applied` here would be the
      // fence certified over a cut that never happened.
      let cover = cover
        .expect("the unanswered batch answers the parked cover ack")
        .expect("the driver answers the parked reply");
      assert_eq!(
        cover,
        CoverOutcome::Degraded,
        "a window whose proof round trip went unanswered reports degraded, never Applied"
      );
      let synced = synced
        .expect("the unanswered batch answers the parked sync")
        .expect("the driver answers the parked reply");
      assert!(
        matches!(synced, Err(crate::error::SyncRootError::Retired)),
        "the parked sync earns the pre-physical terminal, answered rather than stranded: {synced:?}"
      );
      assert!(
        rig.fs.cookie_writes().is_empty(),
        "no cookie is dispatched onto a stream whose reader is gone: {:?}",
        rig.fs.cookie_writes()
      );

      // Half two: CLOSED, not merely withheld. Both callers could in principle be
      // resolved by a scope that stayed live over kernel state no arm result
      // describes; this is the assertion that says it did not.
      assert!(
        settle(|| rig.fs.shutdowns() >= 1).await,
        "the unanswered batch failed the scope CLOSED — its stream was torn down rather \
         than left live behind a coverage claim nothing backs"
      );

      settle_count(&rig, 0).await;
      let (census, live) = debug_census(&rig).await;
      assert_eq!(
        (census.births, census.never_created, live),
        (1, 1, 0),
        "nothing physical was ever created for the parked sync, and its record is retired"
      );
      assert!(
        census.balances(live),
        "births = terminals + live across the unanswered batch"
      );
    }

    /// A control batch stuck on a RETIRED transport must not hold the
    /// replacement's control queue: the scope's serialization wait is
    /// generation-scoped, so the new lane's arms and its ordering proof go out
    /// while the old batch is still inside its call.
    ///
    /// The batch is not preemptible. An arm blocked in a syscall against a hung
    /// or retired filesystem — a dead NFS mount, a wedged device — returns when
    /// the kernel says so, and the reader observes its own shutdown only BETWEEN
    /// operations, so nothing bounds the wait. A replace is not a teardown, so
    /// nothing reclaims the stalled batch's in-flight mark either. Keyed by scope
    /// alone, that mark would park every one of the replacement's batches behind
    /// a call that may never return: the new root stays partially armed, and
    /// every clean fence stays latched on an ordering proof that is queued and
    /// never submitted. Keyed by scope AND generation, the stalled batch holds
    /// back only its own retired world — which orders nothing anyway, because a
    /// retired batch fails the source's front-check and publishes nothing into
    /// the swapped scope.
    ///
    /// The staging, and why each step is load-bearing:
    ///
    /// - the stall is an OLD-world discovery arm, dispatched before the commit,
    ///   so it carries the pre-replace generation and is genuinely retired by the
    ///   swap rather than merely slow.
    /// - the gate is SUPERSEDED and opened rather than released, so the batch
    ///   already bound to the first instance stays frozen while every later batch
    ///   runs. Releasing it instead would let the queue drain the ordinary way
    ///   and the cell would witness nothing.
    /// - the first cover ABSORBS the replace's covering `Rescan`: that loss marks
    ///   the scope's fence entry, so any fence opened before the entry settles
    ///   reports `Degraded` whatever the control queue does. The second cover is
    ///   the one that must be `Applied`, and a clean verdict is exactly what
    ///   cannot be reached without an ordering-proof batch being submitted AND
    ///   completed on the new lane.
    ///
    /// Then the stall is released and its completion must be inert: it may not
    /// clear a mark that now names a newer batch, release a successor a second
    /// time, or license a proof with a cut taken on the transport it belongs to.
    ///
    /// MUTATION WITNESS: key the in-flight mark by scope alone (a
    /// `BTreeSet<ScopeId>`, with `kick_control_queue` refusing while the scope is
    /// present) and this cell FAILS at the first assertion past the commit — the
    /// replacement's arm of `/r2/child` is queued and never submitted for as long
    /// as the old batch is held.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stalled_retired_batch_does_not_hold_the_replacements_control_queue() {
      const IN_ISDIR: u32 = 0x4000_0000;

      let (rig, scope) = covered_rig(&[("/r/keep", 11)]).await;
      rig.fs.put("/r2", FileKind::Dir, 40);
      rig.fs.put("/r2/child", FileKind::Dir, 41);
      let root_watch = rig
        .fs
        .enumerates()
        .first()
        .map(|(watch, _)| *watch)
        .expect("the root enumerated");

      // Stall one OLD-generation batch inside `batch_control`: this discovery arm
      // is dispatched under the pre-replace generation and parks there.
      let stalled = ReleasedOnDrop(rig.fs.hold_arms());
      rig.fs.put("/r/stall", FileKind::Dir, 100);
      rig.fs.send_inotify_batch(
        "/r",
        vec![attributed(&[root_watch], IN_CREATE | IN_ISDIR, b"stall")],
      );
      assert!(
        settle(|| stalled.captured() >= 1).await,
        "staging: the old-world discovery arm reached the fake and parked, so the scope holds \
         an in-flight batch across the commit below"
      );
      assert_eq!(
        arms_at(&rig, "/r/stall"),
        0,
        "staging: the stalled batch is frozen BEFORE its arm executed"
      );

      // Supersede the gate and open it: the batch above stays bound to the first
      // instance, every later batch runs.
      let pass = ReleasedOnDrop(rig.fs.hold_arms());
      pass.release();

      // Commit the replace. Its pre-arm rides `prearm_hold` (not held), so the
      // swap mints a new lane while the old batch is still parked.
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: PathBuf::from("/r2"),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
          reply,
        })
        .await
        .unwrap();
      assert!(
        tokio::time::timeout(interpreted_secs(10), on_reply)
          .await
          .expect("the replace commits within the deadline")
          .expect("the driver replies")
          .is_ok(),
        "staging: the replace committed, so the scope's lane generation moved past the \
         stalled batch"
      );

      // THE WITNESS. The replacement's own control work is submitted and runs
      // while the retired batch is still inside its call.
      assert!(
        settle(|| arms_at(&rig, "/r2/child") >= 1).await,
        "the replacement's arms go out while the retired batch is stuck: /r2/child armed \
         (batches submitted: {:?})",
        rig.fs.control_batches()
      );
      assert_eq!(
        arms_at(&rig, "/r/stall"),
        0,
        "and the retired batch really is still frozen — nothing released it"
      );
      assert!(
        settle(|| rig
          .fs
          .enumerates()
          .iter()
          .any(|(_, p)| p == std::path::Path::new("/r2/child")))
        .await,
        "the rebuild's cold read of the new tree lands too, so the barrier can settle"
      );

      // The first cover absorbs the commit's covering Rescan; the second must be
      // CLEAN, which no fence can reach without an ordering-proof batch of the
      // NEW generation being submitted and completed.
      let absorbed = resolved(send_set_cover(&rig, scope, &["/r2/child"]).await).await;
      assert!(
        matches!(absorbed, CoverOutcome::Applied | CoverOutcome::Degraded),
        "staging: the post-commit window resolves rather than latching: {absorbed:?}"
      );
      assert_eq!(
        resolved(send_set_cover(&rig, scope, &["/r2/child"]).await).await,
        CoverOutcome::Applied,
        "the replacement's fence settles CLEAN while the retired batch is stuck — its \
         ordering proof was submitted and answered on the new lane"
      );
      let armed_before_release = arms_at(&rig, "/r2/child");
      let shutdowns_before_release = rig.fs.shutdowns();

      // Release the stall: its late completion belongs to a generation the scope
      // has retired and must disturb nothing the new one built.
      stalled.release();
      assert!(
        settle(|| rig
          .fs
          .stale_arms()
          .iter()
          .any(|(_, p)| p == std::path::Path::new("/r/stall")))
        .await,
        "the released batch runs against the NEW generation and is refused: {:?}",
        rig.fs.stale_arms()
      );
      for _ in 0..40 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      assert_eq!(
        arms_at(&rig, "/r/stall"),
        0,
        "the stale arm never installed on any transport"
      );
      assert_eq!(
        rig.fs.shutdowns(),
        shutdowns_before_release,
        "the late completion did not fail the live scope closed"
      );
      assert_eq!(
        arms_at(&rig, "/r2/child"),
        armed_before_release,
        "and it did not provoke a re-arm of the new world"
      );
      assert_eq!(
        resolved(send_set_cover(&rig, scope, &["/r2/child"]).await).await,
        CoverOutcome::Applied,
        "the scope still settles clean past the late completion — no mark it did not own was \
         cleared, and no successor was released twice"
      );
    }

    /// A retired transport's TEARDOWN must not run on the executor its
    /// replacement's control work has to run on.
    ///
    /// Generation-aware serialization releases the scope's control queue across a
    /// swap, so the replacement's arms and its ordering proof are free to be
    /// SUBMITTED while the retired batch is still stuck (the sibling cell above).
    /// Free to be submitted is not the same as able to run. The blocking pool is
    /// BOUNDED — `RuntimeLite` promises nothing more, and this driver's own
    /// control-queue argument is written for exactly that — and the wedged reader
    /// holding the retired batch also holds the JOIN that retires it. Dispatch
    /// both onto the pool and two workers is all it takes to occupy it: the
    /// replacement commits, and then nothing of it ever runs. Its root stays
    /// partially armed and its fences wait on an ordering proof with no worker
    /// left to run on — the liveness the release was supposed to buy, handed
    /// straight back. So the join goes to the driver's teardown reaper instead,
    /// and the pool the live generation shares keeps a worker.
    ///
    /// The staging, and why each step is load-bearing:
    ///
    /// - the runtime is built HERE, with the pool bounded to `WORKERS`, so "the
    ///   pool is full" is a fact of this cell rather than a hope about someone
    ///   else's default (the test macro's pool is 512 wide and can never be
    ///   filled).
    /// - the first worker goes to an OLD-generation discovery arm parked for the
    ///   rest of the cell — the reader admitted into a syscall against the very
    ///   filesystem the replace exists to escape.
    /// - the second is what the retired handle's join would take.
    ///   [`FakeFs::hold_teardowns`] parks INSIDE `shutdown`, where no `Drop`
    ///   backstop can exist, which is what a reader that will not exit looks like
    ///   from the caller.
    /// - every assertion comes AFTER the cell has settled on that park. Work
    ///   emitted before it might still catch a free worker and prove nothing;
    ///   work emitted after it cannot, so a clean verdict past that line is
    ///   reachable only if the join is running somewhere the pool is not.
    ///
    /// What this does NOT cover: the reaper's own progress. The invariant pinned
    /// here is that the LIVE generation always has pool capacity, not that
    /// teardowns keep up with unboundedly many wedged transports — reaper threads
    /// are capped, and past that cap teardowns queue behind each other.
    ///
    /// MUTATION WITNESS: dispatch the teardowns through `R::spawn_blocking_detach`
    /// again and this cell fails at the first assertion past the park — the
    /// replacement's arm of `/r2/child` never runs and its fence never settles,
    /// because both of this pool's workers are held by a transport that is dead.
    #[test]
    fn a_retired_transports_teardown_does_not_consume_the_replacements_pool() {
      const IN_ISDIR: u32 = 0x4000_0000;
      const WORKERS: usize = 2;

      let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(WORKERS)
        .enable_all()
        .build()
        .expect("the bounded runtime builds");

      runtime.block_on(async {
        let (rig, scope) = covered_rig(&[("/r/keep", 11)]).await;
        rig.fs.put("/r2", FileKind::Dir, 40);
        rig.fs.put("/r2/child", FileKind::Dir, 41);
        let root_watch = rig
          .fs
          .enumerates()
          .first()
          .map(|(watch, _)| *watch)
          .expect("the root enumerated");

        // Worker one: an OLD-generation discovery arm, parked inside
        // `batch_control` for the rest of the cell.
        let stalled = ReleasedOnDrop(rig.fs.hold_arms());
        rig.fs.put("/r/stall", FileKind::Dir, 100);
        rig.fs.send_inotify_batch(
          "/r",
          vec![attributed(&[root_watch], IN_CREATE | IN_ISDIR, b"stall")],
        );
        assert!(
          settle(|| stalled.captured() >= 1).await,
          "staging: the old-world discovery arm reached the fake and took a worker"
        );
        assert_eq!(
          arms_at(&rig, "/r/stall"),
          0,
          "staging: the stalled batch is frozen BEFORE its arm executed"
        );

        // Supersede the arm gate and open it, so every LATER batch runs while the
        // one above stays bound to the first instance.
        let pass = ReleasedOnDrop(rig.fs.hold_arms());
        pass.release();

        // The retired reader will never exit, so whatever executor its join runs
        // on is occupied for the rest of the cell.
        let joined = ReleasedOnDrop(rig.fs.hold_teardowns());

        let (reply, on_reply) = futures_channel::oneshot::channel();
        rig
          .commands
          .send(Command::Replace {
            scope,
            root: PathBuf::from("/r2"),
            reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
            reply,
          })
          .await
          .unwrap();
        assert!(
          tokio::time::timeout(interpreted_secs(10), on_reply)
            .await
            .expect("the replace commits within the deadline")
            .expect("the driver replies")
            .is_ok(),
          "staging: the replace committed, so the scope owes a teardown for the retired stream"
        );

        assert!(
          settle(|| joined.captured() >= 1).await,
          "staging: the retired handle's teardown is inside its join"
        );
        assert_eq!(
          rig.fs.shutdowns(),
          0,
          "staging: and that join has not returned — the retired transport is genuinely still \
           winding down for every assertion below"
        );

        // THE WITNESS. Both of the pool's workers are spoken for by the dead
        // transport under the old dispatch; the new generation's control work
        // runs anyway.
        assert!(
          settle(|| arms_at(&rig, "/r2/child") >= 1).await,
          "the replacement's arms go out while the retired transport holds a stuck batch AND an \
           outstanding join: /r2/child armed (batches submitted: {:?})",
          rig.fs.control_batches()
        );
        assert!(
          settle(|| rig
            .fs
            .enumerates()
            .iter()
            .any(|(_, p)| p == std::path::Path::new("/r2/child")))
          .await,
          "the rebuild's cold read of the new tree lands too, so the barrier can settle"
        );

        // The first cover absorbs the commit's covering `Rescan`; the second must
        // be CLEAN, which no fence reaches without an ordering-proof batch of the
        // NEW generation being submitted AND completed on a worker.
        let absorbed = resolved(send_set_cover(&rig, scope, &["/r2/child"]).await).await;
        assert!(
          matches!(absorbed, CoverOutcome::Applied | CoverOutcome::Degraded),
          "staging: the post-commit window resolves rather than latching: {absorbed:?}"
        );
        assert_eq!(
          resolved(send_set_cover(&rig, scope, &["/r2/child"]).await).await,
          CoverOutcome::Applied,
          "the replacement's fence settles CLEAN on a pool the dead transport could have filled"
        );

        assert_eq!(
          rig.fs.shutdowns(),
          0,
          "and none of it waited on the retirement: the join is STILL outstanding"
        );
        assert_eq!(
          arms_at(&rig, "/r/stall"),
          0,
          "nor on the stalled batch, which never moved"
        );
      });
    }

    /// A control batch a retired transport's reader NEVER ANSWERS must not
    /// consume the blocking-pool capacity its replacement's control work needs.
    ///
    /// This is the other half of the argument the two cells above make. Keying
    /// the scope's serialization on the generation frees the replacement's arms
    /// and its ordering proof to be SUBMITTED across a swap, and keeping the
    /// retired stream's join off the pool leaves a worker for them to run on —
    /// but the retired batch itself is still outstanding somewhere, and the
    /// question is what that costs. A batch handed to a reader is answered when
    /// the reader replies, which a reader admitted into a syscall against a
    /// wedged filesystem does when the kernel says so and not before. Waited on
    /// by a pool worker, one such batch spends a worker for that whole time, and
    /// a driver can hold arbitrarily many of them: each replace retires the
    /// transport its stuck batch was addressed to, and the next one strands
    /// another the same way. No fixed pool width survives that, so nothing waits
    /// at all: the answer sink travels with the batch and is REPORTED through by
    /// whichever thread finally produces the outcome.
    ///
    /// The staging, and why each step is load-bearing:
    ///
    /// - the pool is bounded to ONE worker HERE, so "the wait costs a worker" and
    ///   "the replacement has no capacity" are the same statement and the cell
    ///   cannot pass by having spare workers around (the test macro's pool is 512
    ///   wide and can never be filled).
    /// - the batch that is stranded is an OLD-world discovery arm, dispatched
    ///   before the commit, so it carries the pre-replace generation and is
    ///   genuinely retired by the swap rather than merely slow.
    /// - the stranded reader executes NOTHING and answers NOTHING, which is what
    ///   a reader stuck in a syscall looks like — distinct from a reader that
    ///   dies (which answers every arm refused) and from a worker that unwinds
    ///   (which reaches a terminal). Neither of those can strand capacity;
    ///   this is the one that can.
    /// - every assertion comes AFTER the strand is confirmed, so work that might
    ///   have caught the worker before it is spoken for proves nothing and is not
    ///   relied on.
    ///
    /// What this does NOT cover: a wedged reader of the scope's CURRENT
    /// transport. Such a scope has one batch outstanding at a time by its own
    /// serialization, its arms genuinely cannot proceed until the reader speaks,
    /// and its liveness is the stream-death path's business, not the pool's.
    ///
    /// MUTATION WITNESS: have the dispatching pool worker wait for the batch to
    /// reach its end — what a blocking control port does inside its reply receive
    /// — and this cell fails at the first thing the scope asks of the pool past
    /// the strand: `the replace commits within the deadline` expires, because the
    /// one worker is inside a reply that will not come, so the replacement is
    /// never even spawned, let alone armed or proven.
    #[test]
    fn a_stranded_retired_reader_does_not_consume_the_replacements_pool() {
      const IN_ISDIR: u32 = 0x4000_0000;
      const WORKERS: usize = 1;

      let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(WORKERS)
        .enable_all()
        .build()
        .expect("the bounded runtime builds");

      runtime.block_on(async {
        let (rig, scope) = covered_rig(&[("/r/keep", 11)]).await;
        rig.fs.put("/r2", FileKind::Dir, 40);
        rig.fs.put("/r2/child", FileKind::Dir, 41);
        let root_watch = rig
          .fs
          .enumerates()
          .first()
          .map(|(watch, _)| *watch)
          .expect("the root enumerated");

        // What would hold the single worker if the answer were still waited on
        // there: an OLD-generation discovery arm, taken by a reader that never
        // speaks again.
        rig.fs.strand_next_control_reader(scope);
        rig.fs.put("/r/stall", FileKind::Dir, 100);
        rig.fs.send_inotify_batch(
          "/r",
          vec![attributed(&[root_watch], IN_CREATE | IN_ISDIR, b"stall")],
        );
        assert!(
          settle(|| !rig.fs.stranded_control_batches().is_empty()).await,
          "staging: the old-world discovery arm reached the stranded reader (batches \
           submitted: {:?})",
          rig.fs.control_batches()
        );
        assert_eq!(
          arms_at(&rig, "/r/stall"),
          0,
          "staging: the stranded reader ran none of the batch — it is outstanding, not slow"
        );

        // The swap retires the generation that batch was emitted for, so the
        // replacement's own control work is free to be submitted from here.
        let (reply, on_reply) = futures_channel::oneshot::channel();
        rig
          .commands
          .send(Command::Replace {
            scope,
            root: PathBuf::from("/r2"),
            reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
            reply,
          })
          .await
          .unwrap();
        assert!(
          tokio::time::timeout(interpreted_secs(10), on_reply)
            .await
            .expect("the replace commits within the deadline")
            .expect("the driver replies")
            .is_ok(),
          "staging: the replace committed, so the stranded batch's generation is retired"
        );

        // THE WITNESS. Every one of these needs the worker the never-answered
        // batch would otherwise be sitting on.
        assert!(
          settle(|| arms_at(&rig, "/r2/child") >= 1).await,
          "the replacement's arms go out while the retired batch is outstanding forever: \
           /r2/child armed (batches submitted: {:?})",
          rig.fs.control_batches()
        );
        assert!(
          settle(|| rig
            .fs
            .enumerates()
            .iter()
            .any(|(_, p)| p == std::path::Path::new("/r2/child")))
          .await,
          "the rebuild's cold read of the new tree lands too, so the barrier can settle"
        );

        // The first cover absorbs the commit's covering `Rescan`; the second must
        // be CLEAN, which no fence reaches without an ordering-proof batch of the
        // NEW generation being submitted AND completed on a worker.
        let absorbed = resolved(send_set_cover(&rig, scope, &["/r2/child"]).await).await;
        assert!(
          matches!(absorbed, CoverOutcome::Applied | CoverOutcome::Degraded),
          "staging: the post-commit window resolves rather than latching: {absorbed:?}"
        );
        assert_eq!(
          resolved(send_set_cover(&rig, scope, &["/r2/child"]).await).await,
          CoverOutcome::Applied,
          "the replacement's fence settles CLEAN on a one-worker pool a dead reader could \
           have taken outright"
        );

        assert_eq!(
          rig.fs.stranded_control_batches().len(),
          1,
          "and none of it waited on the retired batch: it is STILL unanswered"
        );
        assert_eq!(arms_at(&rig, "/r/stall"), 0, "nor did its ops ever run");
      });
    }

    /// An UNANSWERED batch of a RETIRED generation must not take the
    /// REPLACEMENT down with it. The reader that failed to answer it served a
    /// transport the scope has already swapped away from, so its going missing
    /// is the ordinary end of that transport rather than evidence against the
    /// live one.
    ///
    /// The two ways a batch goes unanswered are not one fact, and this is where
    /// the difference is paid for. An UNWIND stops at an unknown point, having
    /// fed back none of the arm results its callers are parked on, so nothing
    /// bounds what the scope is still owed and it fails closed whatever its
    /// generation. A batch that RETURNS unanswered stops at a known one: every
    /// arm it carried came back refused, and whatever a dying reader half-ran it
    /// ran against an fd the swap has already abandoned, whose watches die with
    /// it. Judged as the unwind is, the second one kills a healthy scope — its
    /// `replace_root` already answered `Ok`, its new tree armed, its fences
    /// settling clean — on the word of the world it replaced.
    ///
    /// The staging, and why each step is load-bearing:
    ///
    /// - the batch that dies is an OLD-world discovery arm, dispatched before
    ///   the commit, so it carries the pre-replace generation and is genuinely
    ///   retired by the swap rather than merely late.
    /// - the fake takes its reader-death arm BELOW the hold, so freezing that
    ///   batch on a gate and arming the death while it is parked puts the death
    ///   on exactly it. Every later batch is parked on a SUPERSEDING gate, so no
    ///   batch of the live generation can reach the one-shot arm first.
    /// - the new lane's ordering-proof round trip is left parked on that second
    ///   gate ACROSS the death. That is what makes "licenses no cut" observable:
    ///   the window is settled and latched on a request whose batch has not run,
    ///   so a proof granted to the stale completion would resolve the parked
    ///   cover ack early, before its round trip was ever served.
    /// - the new lane is driven to a clean verdict BEFORE the death, so survival
    ///   is asserted of a scope that was demonstrably healthy going in.
    ///
    /// MUTATION WITNESS: collapse the completion back to two states — every
    /// unanswered batch failing the scope closed whatever its generation — and
    /// this cell FAILS: the stale return tears the replacement's stream down and
    /// answers its parked cover ack over a fence folded `Dead`.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unanswered_retired_batch_does_not_fail_the_replacement_closed() {
      const IN_ISDIR: u32 = 0x4000_0000;

      let (rig, scope) = covered_rig(&[("/r/keep", 11)]).await;
      rig.fs.put("/r2", FileKind::Dir, 40);
      rig.fs.put("/r2/child", FileKind::Dir, 41);
      rig.fs.put("/r2/other", FileKind::Dir, 42);
      let root_watch = rig
        .fs
        .enumerates()
        .first()
        .map(|(watch, _)| *watch)
        .expect("the root enumerated");

      // Freeze one OLD-generation batch inside `batch_control`, above the point
      // the fake consults its death arm: this discovery arm is dispatched under
      // the pre-replace generation and parks there.
      let stalled = ReleasedOnDrop(rig.fs.hold_arms());
      rig.fs.put("/r/stall", FileKind::Dir, 100);
      rig.fs.send_inotify_batch(
        "/r",
        vec![attributed(&[root_watch], IN_CREATE | IN_ISDIR, b"stall")],
      );
      assert!(
        settle(|| stalled.captured() >= 1).await,
        "staging: the old-world discovery arm reached the fake and parked, so the scope holds \
         an in-flight batch of the outgoing generation across the commit below"
      );

      // Supersede the gate and open it: the batch above stays bound to the first
      // instance, everything the replacement does runs.
      let pass = ReleasedOnDrop(rig.fs.hold_arms());
      pass.release();

      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: PathBuf::from("/r2"),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
          reply,
        })
        .await
        .unwrap();
      assert!(
        tokio::time::timeout(interpreted_secs(10), on_reply)
          .await
          .expect("the replace commits within the deadline")
          .expect("the driver replies")
          .is_ok(),
        "staging: the replace committed — its caller has been told the new root is live, and \
         the stalled batch's generation is now retired"
      );
      assert!(
        settle(|| arms_at(&rig, "/r2/child") >= 1 && arms_at(&rig, "/r2/other") >= 1).await,
        "staging: the rebuild armed the new tree: {:?}",
        rig.fs.arms()
      );
      assert!(
        settle(|| {
          let enumerates = rig.fs.enumerates();
          ["/r2/child", "/r2/other"].iter().all(|path| {
            enumerates
              .iter()
              .any(|(_, p)| p == std::path::Path::new(path))
          })
        })
        .await,
        "staging: the rebuild's cold read of the new tree landed, so its windows can settle"
      );

      // A HEALTHY scope going in: the first cover absorbs the commit's covering
      // Rescan, the second must be clean.
      let absorbed = resolved(send_set_cover(&rig, scope, &["/r2/child"]).await).await;
      assert!(
        matches!(absorbed, CoverOutcome::Applied | CoverOutcome::Degraded),
        "staging: the post-commit window resolves rather than latching: {absorbed:?}"
      );
      assert_eq!(
        resolved(send_set_cover(&rig, scope, &["/r2/child"]).await).await,
        CoverOutcome::Applied,
        "staging: the replacement settles CLEAN before the stale batch returns"
      );

      // A GROW held on the pool: /r2/other's re-install is counted re-arm work,
      // so the window it opens cannot ask for its ordering proof yet.
      let grow_hold = ReleasedOnDrop(rig.fs.hold_arms());
      let mut ack = Box::pin(send_set_cover(&rig, scope, &["/r2/child", "/r2/other"]).await);
      assert!(
        settle(|| grow_hold.captured() >= 1).await,
        "staging: the grow's arm batch reached the fake and parked"
      );

      // Supersede that gate too, THEN release it: the grow completes, and the
      // round trip the settled window asks for next parks on the new instance —
      // where it stays for the whole of the death below.
      let proof_hold = ReleasedOnDrop(rig.fs.hold_arms());
      grow_hold.release();
      assert!(
        settle(|| proof_hold.captured() >= 1).await,
        "staging: a later batch parked on the superseding gate — which can only be submitted \
         on the grow batch's completion, so the grow is done"
      );
      let submitted = rig.fs.control_batches();
      assert_eq!(
        submitted.last(),
        Some(&(scope, 0)),
        "staging: the parked batch carries NO requests — the live lane's ordering-proof round \
         trip, latched and unanswered: {submitted:?}"
      );
      assert!(
        futures_util::poll!(ack.as_mut()).is_pending(),
        "staging: the cover ack is parked on exactly that round trip"
      );
      let shutdowns_before = rig.fs.shutdowns();
      assert!(
        shutdowns_before >= 1,
        "staging: the replace already tore the OLD stream down, so a further shutdown can only \
         be the replacement's"
      );

      // The old reader dies holding its batch: it RETURNS, having answered
      // nothing, under a generation the swap has retired.
      rig.fs.kill_next_control_reader(scope);
      stalled.release();

      // THE WITNESS. The replacement survives its predecessor's last word. The
      // wait is the full settle budget and its verdict is inverted: the defect
      // this pins tears the stream down within a channel hop of the release, so
      // an expired budget IS the passing observation.
      assert!(
        !settle(|| rig.fs.shutdowns() > shutdowns_before).await,
        "the retired batch's unanswered return must not fail the live scope closed — the \
         reader it lost was the one the swap already retired"
      );
      assert_eq!(
        arms_at(&rig, "/r/stall"),
        0,
        "and the stale arm installed on no transport"
      );

      // It licensed no cut either: the window is still latched on the round trip
      // parked on the pool, which nobody has served.
      assert!(
        futures_util::poll!(ack.as_mut()).is_pending(),
        "the stale completion proved no cut — a fence may be certified only by the batch that \
         carried its request, answered"
      );

      // And the replacement's control work still runs: the round trip is served,
      // the fence settles CLEAN rather than folded `Dead`, and fresh kernel
      // records still reach the pool.
      proof_hold.release();
      assert_eq!(
        resolved(ack).await,
        CoverOutcome::Applied,
        "the replacement's own fence settles clean once its round trip is answered"
      );
      assert!(
        settle(|| arms_at(&rig, "/r2/other") >= 2).await,
        "the grow's re-install of /r2/other landed: {:?}",
        rig.fs.arms()
      );
      rig.fs.put("/r2/after", FileKind::Dir, 43);
      rig.fs.send_inotify_batch(
        "/r2",
        vec![attributed(&[root_watch], IN_CREATE | IN_ISDIR, b"after")],
      );
      assert!(
        settle(|| arms_at(&rig, "/r2/after") >= 1).await,
        "the replacement still arms what its kernel reports: {:?}",
        rig.fs.arms()
      );
      assert_eq!(
        rig.fs.shutdowns(),
        shutdowns_before,
        "and it is still the same live stream that did it"
      );
    }

    /// An awaited `set_cover` is retained twice over — one reply sender in the
    /// driver and one pending fence record in the core — until its coverage window
    /// settles. Re-issuing an already-applied cover is a real reconcile, so a
    /// caller can open fences against a scope whose control round trip is stalled
    /// as fast as the driver drains its mailbox.
    ///
    /// FAIL-ON-REVERT: remove the `pending_cover_fences(..) >= MAX_PARKED_SETTLEMENTS`
    /// arm from `Command::SetCover` and every reissue opens another fence — the
    /// core's pending count grows with total admitted calls and nothing is refused.
    #[tokio::test(flavor = "multi_thread")]
    async fn awaited_set_covers_stop_at_the_parked_bound() {
      let (rig, scope) = covered_rig(&[("/r/keep", 11), ("/r/drop", 12)]).await;

      // Stall the scope's control round trip: no coverage window can settle.
      let _stalled = rig.fs.hold_arms();

      let mut waiters = Vec::new();
      let mut refused = 0usize;
      for _ in 0..(MAX_PARKED_SETTLEMENTS * 4) {
        let (reply, on_reply) = futures_channel::oneshot::channel();
        rig
          .commands
          .send(Command::SetCover {
            scope,
            retained: vec![PathBuf::from("/r/keep")],
            reply: Some(reply),
          })
          .await
          .unwrap();
        waiters.push(on_reply);
        tokio::task::yield_now().await;
      }
      tokio::time::sleep(Duration::from_millis(100)).await;

      for waiter in &mut waiters {
        if let core::task::Poll::Ready(Ok(outcome)) = futures_util::poll!(waiter) {
          assert!(
            matches!(
              outcome,
              crate::CoverOutcome::Skipped(crate::SkipReason::Backlogged)
            ),
            "the only resolved reconciles are the refused ones: {outcome:?}"
          );
          refused += 1;
        }
      }
      assert!(
        refused > 0,
        "admission stops at the bound while the scope cannot settle"
      );

      let (q, on_q) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::DebugPendingCoverFences { scope, reply: q })
        .await
        .unwrap();
      let pending = on_q.await.unwrap();
      assert!(
        pending <= MAX_PARKED_SETTLEMENTS,
        "the core retains at most the parked bound of fence records: {pending}"
      );
    }
  }

  /// The descending replace end to end: the new root pre-arms on the NEW
  /// transport (the arms ledger shows it), the commit delivers exactly one
  /// covering Rescan, the rebuild re-arms the new tree, and post-swap
  /// records deliver under the new root on the surviving scope.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_descending_replace_rebinds_on_a_fresh_transport() {
    let rig = inotify_rig();
    rig.fs.put("/r2", FileKind::Dir, 20);
    rig.fs.put("/r2/sub", FileKind::Dir, 21);
    let scope = watch(&rig, "/r").await;
    let root_arm = rig.fs.arms().first().cloned().expect("the birth root arm");

    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r2"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
        reply,
      })
      .await
      .unwrap();
    assert!(on_reply.await.expect("driver replies").is_ok());
    settle(|| rig.fs.shutdowns() == 1).await;

    // The pre-arm rode the SAME surviving WatchId to the new root.
    let arms = rig.fs.arms();
    assert!(
      arms
        .iter()
        .any(|(w, p)| *w == root_arm.0 && p == std::path::Path::new("/r2")),
      "the new root pre-armed on the surviving watch id: {arms:?}"
    );

    // The commit's covering Rescan, re-rooted.
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(root.as_path(), std::path::Path::new("/r2"));
    assert!(change.kind().is_rescan(), "{change:?}");
    let commit_epoch = change.epoch();

    // The rebuild walked the new tree and re-armed it — announcing nothing.
    settle(|| {
      rig
        .fs
        .arms()
        .iter()
        .any(|(_, p)| p == std::path::Path::new("/r2/sub"))
    })
    .await;
    assert!(
      rig
        .fs
        .arms()
        .iter()
        .any(|(_, p)| p == std::path::Path::new("/r2/sub")),
      "the rebuild re-arms the new tree: {:?}",
      rig.fs.arms()
    );

    // The rebuild's settle closes the bridge window: a change landing after
    // the commit but before a rebuilt watch armed is recorded by nothing and
    // suppressed by the re-arm read, so the window owes a SECOND root Rescan
    // whose epoch strictly dominates the commit's (replace = commit + close).
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(root.as_path(), std::path::Path::new("/r2"));
    assert!(change.kind().is_rescan(), "{change:?}");
    assert!(
      change.epoch() > commit_epoch,
      "the closing Rescan strictly dominates the commit: {change:?}"
    );

    // Post-swap records deliver under the new root.
    rig.fs.send_inotify_batch(
      "/r2",
      vec![attributed(&[root_arm.0], IN_CREATE, b"post.txt")],
    );
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(root.as_path(), std::path::Path::new("/r2"));
    assert!(change.kind().is_created());
    assert_eq!(change.location(), &loc(&["post.txt"]));
  }

  /// A refused pre-arm unwinds atomically: the caller gets the typed source
  /// failure, the replacement is torn down inside the accounting, and the
  /// old tree keeps delivering.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_failed_pre_arm_unwinds_and_the_old_tree_survives() {
    let rig = inotify_rig();
    rig.fs.put("/r2", FileKind::Dir, 20);
    rig
      .fs
      .fail_watch_at("/r2", tributary_proto::WatchError::NoSpace);
    let scope = watch(&rig, "/r").await;
    let root_arm = rig.fs.arms().first().cloned().expect("the birth root arm");

    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r2"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
        reply,
      })
      .await
      .unwrap();
    let outcome = on_reply.await.expect("driver replies");
    assert!(
      matches!(outcome, Err(crate::error::ReplaceRootError::Source(_))),
      "{outcome:?}"
    );
    settle(|| rig.fs.shutdowns() == 1).await;
    assert_eq!(rig.fs.shutdowns(), 1, "only the refused replacement died");

    rig.fs.send_inotify_batch(
      "/r",
      vec![attributed(&[root_arm.0], IN_CREATE, b"still.txt")],
    );
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(root.as_path(), std::path::Path::new("/r"));
    assert!(change.kind().is_created());
  }

  /// Close lands while the pre-arm is parked on the blocking pool: the sweep
  /// retires the spawned-but-uncommitted replacement inside the counted
  /// accounting — both streams torn down, the replace answered Closed.
  #[tokio::test(flavor = "multi_thread")]
  async fn close_during_the_pre_arm_counts_both_streams() {
    let rig = inotify_rig();
    rig.fs.put("/r2", FileKind::Dir, 20);
    let scope = watch(&rig, "/r").await;

    let gate = rig.fs.hold_prearms();
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r2"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
        reply,
      })
      .await
      .unwrap();
    // The replacement spawned and its pre-arm is parked.
    settle(|| rig.fs.spawns() == 2).await;

    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    // Close settles while the pre-arm is STILL PARKED: the sweep alone must
    // account for the held replacement (releasing first would race the
    // commit against the close and sometimes swap successfully — a
    // different, also-legal ordering this cell is not about).
    assert!(on_close.await.is_ok(), "close settles");
    settle(|| rig.fs.shutdowns() == 2).await;
    assert_eq!(rig.fs.shutdowns(), 2, "old stream AND held replacement");
    assert!(matches!(
      on_reply.await,
      Ok(Err(crate::error::ReplaceRootError::Closed)) | Err(_)
    ));
    gate.release();
  }

  /// The lowering gate, both diagonals: a replacement resolving to a
  /// different recursiveness than the live scope refuses as
  /// BackendDiverged, the old coverage untouched, the fresh stream retired.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_lowering_flip_is_refused_both_ways() {
    // Descending → kernel-recursive.
    let rig = inotify_rig();
    rig.fs.put("/r2", FileKind::Dir, 20);
    let scope = watch(&rig, "/r").await;
    rig.fs.spawn_backend(BackendKind::Fanotify);
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r2"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
        reply,
      })
      .await
      .unwrap();
    assert!(matches!(
      on_reply.await.expect("driver replies"),
      Err(crate::error::ReplaceRootError::BackendDiverged)
    ));
    settle(|| rig.fs.shutdowns() == 1).await;

    // Kernel-recursive → descending.
    let rig = rig_with_capacity(64);
    rig.fs.put("/r2", FileKind::Dir, 20);
    let scope = watch(&rig, "/r").await;
    rig.fs.spawn_backend(BackendKind::Inotify);
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r2"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
        reply,
      })
      .await
      .unwrap();
    assert!(matches!(
      on_reply.await.expect("driver replies"),
      Err(crate::error::ReplaceRootError::BackendDiverged)
    ));
    settle(|| rig.fs.shutdowns() == 1).await;
  }

  /// The transport-generation fence: an old-world discovery arm dispatched
  /// before a descending replace, but completing AFTER the swap, must NOT
  /// install on the replacement's fd — it names an old-world path and belongs
  /// to a transport the swap retired. Held on `arm_hold` across the commit
  /// (whose pre-arm rides its own gate), the batch runs against the new
  /// generation and is refused, landing nothing on the new transport.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_stale_discovery_arm_across_a_replace_lands_nothing() {
    const IN_ISDIR: u32 = 0x4000_0000;
    let rig = inotify_rig();
    rig.fs.put("/r2", FileKind::Dir, 40);
    rig.fs.put("/r2/child", FileKind::Dir, 41);
    let scope = watch(&rig, "/r").await;
    settle(|| !rig.fs.enumerates().is_empty()).await;
    let root_watch = rig
      .fs
      .enumerates()
      .first()
      .map(|(watch, _)| *watch)
      .expect("the root enumerated");

    // Freeze discovery arms, then discover a new OLD-world directory: its arm
    // batch is dispatched carrying the current (pre-replace) generation and
    // parks here.
    let hold = rig.fs.hold_arms();
    rig.fs.put("/r/newdir", FileKind::Dir, 30);
    rig.fs.send_inotify_batch(
      "/r",
      vec![attributed(&[root_watch], IN_CREATE | IN_ISDIR, b"newdir")],
    );
    for _ in 0..30 {
      tokio::task::yield_now().await;
      tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
      !rig
        .fs
        .arms()
        .iter()
        .any(|(_, p)| p == Path::new("/r/newdir")),
      "the discovery arm is parked, not yet landed"
    );

    // Commit the replace: its pre-arm rides `prearm_hold` (not held), so the
    // swap completes and bumps the transport generation while the discovery
    // batch is still parked on `arm_hold`.
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r2"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
        reply,
      })
      .await
      .unwrap();
    assert!(on_reply.await.expect("driver replies").is_ok());
    settle(|| rig.fs.shutdowns() == 1).await;

    // Release: the parked old-world batch runs against the NEW generation and
    // is refused, while the rebuild arms the new tree.
    hold.release();
    settle(|| {
      rig
        .fs
        .stale_arms()
        .iter()
        .any(|(_, p)| p == Path::new("/r/newdir"))
    })
    .await;
    assert!(
      rig
        .fs
        .stale_arms()
        .iter()
        .any(|(_, p)| p == Path::new("/r/newdir")),
      "the stale discovery arm was refused: {:?}",
      rig.fs.stale_arms()
    );
    assert!(
      !rig
        .fs
        .arms()
        .iter()
        .any(|(_, p)| p == Path::new("/r/newdir")),
      "and it never installed on any transport"
    );
    settle(|| {
      rig
        .fs
        .arms()
        .iter()
        .any(|(_, p)| p == Path::new("/r2/child"))
    })
    .await;
    assert!(
      rig
        .fs
        .arms()
        .iter()
        .any(|(_, p)| p == Path::new("/r2/child")),
      "the rebuild armed the new tree on the new transport"
    );
  }

  /// The reply-side twin of the generation fence: a ROOT re-add (the loss
  /// recovery's binding re-proof) dispatched before a replace but resolving
  /// AFTER the swap synthesizes `Failed(Gone)` against the retired
  /// generation — and the root's `WatchId` SURVIVES the rebind, so without
  /// the reply fence that stale failure would invalidate the fresh world.
  /// The stale reply must be dropped whole: the rebound scope lives on and
  /// rebuilds.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_stale_root_readd_reply_across_a_replace_does_not_invalidate() {
    let rig = inotify_rig();
    rig.fs.put("/r2", FileKind::Dir, 40);
    rig.fs.put("/r2/child", FileKind::Dir, 41);
    let scope = watch(&rig, "/r").await;
    assert!(
      settle(|| !rig.fs.enumerates().is_empty()).await,
      "staging: the birth crawl must land before arms freeze, or the parked batch is not the root re-add"
    );

    // Freeze arms, then the loss: the recovery's root re-add batch parks,
    // carrying the pre-replace generation.
    let hold = rig.fs.hold_arms();
    rig.fs.send_lossy("/r");
    for _ in 0..30 {
      tokio::task::yield_now().await;
      tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // The replace commits while the re-add is parked (its pre-arm rides the
    // separate prearm gate).
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r2"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
        reply,
      })
      .await
      .unwrap();
    assert!(on_reply.await.expect("driver replies").is_ok());
    assert!(
      settle(|| rig.fs.shutdowns() == 1).await,
      "staging: the replace's old stream must retire before the parked re-add is released"
    );

    // Release: the parked re-add resolves refused against the new generation,
    // and its synthesized failure is dropped by the reply fence — the rebound
    // scope's own recovery (the post-commit re-add on the NEW root, then the
    // rebuild) proceeds to the new tree.
    hold.release();
    settle(|| {
      rig
        .fs
        .stale_arms()
        .iter()
        .any(|(_, p)| p == Path::new("/r"))
    })
    .await;
    settle(|| {
      rig
        .fs
        .arms()
        .iter()
        .any(|(_, p)| p == Path::new("/r2/child"))
    })
    .await;
    // The proof of no spurious invalidation: nothing beyond the replace's own
    // retirement ever tears down.
    for _ in 0..30 {
      tokio::task::yield_now().await;
      tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
      rig.fs.shutdowns(),
      1,
      "the stale root-arm failure never invalidated the rebound scope"
    );
  }

  /// The barrier-honesty acceptance cells: on the descending backend, a sync
  /// cookie must never dispatch ahead of the covering `Rescan` a
  /// level-persistent deficit owes — a replace-rebuild bridge (C1), a standing
  /// arm-refused or exhausted-read hole (C2/C3, bounded per C4), a held move
  /// source (C5), or a latent coalesced cold read (C6). The umbrella turns any
  /// delivered scope `Rescan` ordered ahead of the cookie's event into
  /// `SyncOutcome::Dominated` through its two proven choke points
  /// (`dominate_pending_syncs`, the `loss_gen` install snapshot), so the
  /// queue-order facts pinned here are exactly the inputs barrier honesty
  /// needs.
  mod barrier_honesty {
    use super::*;
    use crate::os::linux::{RawInotifyEvent, RawLinuxEvent, inotify::decode::InotifyMask};

    const IN_CREATE: u32 = 0x0000_0100;
    const IN_MOVED_FROM: u32 = 0x0000_0040;
    const IN_MOVED_TO: u32 = 0x0000_0080;
    const IN_ISDIR: u32 = 0x4000_0000;

    /// The settle-edge drain's snapshot is what LICENSES a clean verdict, and a
    /// partially drained snapshot licenses nothing.
    ///
    /// The drain polls the merged source stream until the items it counted are
    /// ingested, and only then may the resolve mint a clean verdict. A `Pending`
    /// poll is NOT proof those items are gone: the fan-in may answer `Pending`
    /// while a ready item exists, because a wake landing mid-poll is enqueued for
    /// a LATER poll and the drain takes only one. So the loop can break with items
    /// still counted — and certifying clean there mints a false certificate over a
    /// loss the fence's own ordering placed INSIDE the snapshot, omitting the
    /// `Rescan` that loss owes.
    ///
    /// This pins the predicate the clean-certification gate reads. It does not pin
    /// the wiring end to end: forcing the fan-in to answer a transient `Pending`
    /// would take a hand-rolled waker inside the loop the gate lives in, which is
    /// a worse risk than the gap it would close.
    #[test]
    fn a_partially_drained_snapshot_does_not_license_a_clean_verdict() {
      let scope = ScopeId::new(NonZeroU64::new(1).unwrap());
      let (tx, rx) = async_channel::unbounded();
      for _ in 0..2 {
        tx.try_send(crate::os::SourceMessage::Fatal(
          crate::os::SourceError::CallbackPanic,
        ))
        .expect("queued");
      }
      let lanes = BTreeMap::from([(scope, 7u64)]);
      let taps = BTreeMap::from([(scope, rx)]);

      let mut snapshot = SourceSnapshot::taken(&lanes, &taps);
      assert!(!snapshot.spent(), "two queued items stand outstanding");
      snapshot.consume(scope, 7);
      assert!(
        !snapshot.spent(),
        "a drain that stopped one item short has NOT spent its snapshot, so its \
         pass may not certify clean"
      );
      snapshot.consume(scope, 7);
      assert!(
        snapshot.spent(),
        "and once every counted item is ingested the pass may certify"
      );
      drop(tx);
    }

    /// The settle pass withholds BY SCOPE, and this is the set it withholds on.
    ///
    /// A partially drained snapshot licenses no live verdict for the scope whose
    /// lane it left unread — clean or lossy, because an unread terminal `Fatal`
    /// makes either one a claim about a stream that may already be gone. But the
    /// residue is per lane, so one scope's backlog must not defer a neighbour's
    /// window: a global flag would let a continuously producing source hold an
    /// unrelated fence open for as long as it kept producing.
    ///
    /// A scope drops out of the set the instant its counted items are all
    /// ingested — the budget map is the residue — which is what bounds the
    /// deferral to the residue that caused it.
    #[test]
    fn a_snapshot_owes_its_residue_by_scope_and_drops_each_as_it_drains() {
      let busy = ScopeId::new(NonZeroU64::new(1).unwrap());
      let quiet = ScopeId::new(NonZeroU64::new(2).unwrap());
      let (busy_tx, busy_rx) = async_channel::unbounded();
      let (quiet_tx, quiet_rx) = async_channel::unbounded();
      for _ in 0..2 {
        busy_tx
          .try_send(crate::os::SourceMessage::Fatal(
            crate::os::SourceError::CallbackPanic,
          ))
          .expect("queued");
      }
      quiet_tx
        .try_send(crate::os::SourceMessage::Fatal(
          crate::os::SourceError::CallbackPanic,
        ))
        .expect("queued");
      let lanes = BTreeMap::from([(busy, 7u64), (quiet, 9u64)]);
      let taps = BTreeMap::from([(busy, busy_rx), (quiet, quiet_rx)]);

      let mut snapshot = SourceSnapshot::taken(&lanes, &taps);
      assert_eq!(
        snapshot.unspent_scopes(),
        BTreeSet::from([busy, quiet]),
        "both lanes hold counted items, so neither scope's fences may resolve"
      );
      snapshot.consume(quiet, 9);
      assert_eq!(
        snapshot.unspent_scopes(),
        BTreeSet::from([busy]),
        "a fully drained lane stops withholding at once, whatever its neighbour still owes"
      );
      assert!(!snapshot.spent(), "the busy lane still bounds the pass");
      snapshot.consume(busy, 7);
      assert_eq!(
        snapshot.unspent_scopes(),
        BTreeSet::from([busy]),
        "a lane drained one item short still withholds — it may hold the death"
      );
      snapshot.consume(busy, 7);
      assert!(
        snapshot.unspent_scopes().is_empty(),
        "a spent snapshot withholds nothing"
      );
      assert!(snapshot.spent());
      drop((busy_tx, quiet_tx));
    }

    /// Dispatches a sync without awaiting it, returning the pending reply.
    async fn sync_pending(
      rig: &Rig,
      scope: ScopeId,
      dir: &str,
      name: &str,
    ) -> futures_channel::oneshot::Receiver<Result<PathBuf, crate::error::SyncRootError>> {
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::SyncRoot {
          scope,
          dir: PathBuf::from(dir),
          name: name.to_owned(),
          // These cells never cancel by ticket, so a fresh per-call ticket suffices.
          ticket: ticket(),
          reply,
        })
        .await
        .unwrap();
      on_reply
    }

    /// Dispatches a sync and awaits its cookie path, retrying the retryable
    /// single-flight refusal (the previous write's `CookieWriteDone` is
    /// asynchronous relative to its reply) and bounding the whole await so a
    /// wedged fence fails the cell instead of hanging the suite.
    async fn sync_ok(rig: &Rig, scope: ScopeId, dir: &str, name: &str) -> PathBuf {
      for _ in 0..400 {
        let pending = sync_pending(rig, scope, dir, name).await;
        let outcome = tokio::time::timeout(interpreted_secs(10), pending)
          .await
          .expect("the sync resolves in bounded time — never parked forever")
          .expect("the driver replies");
        match outcome {
          Ok(path) => return path,
          Err(crate::error::SyncRootError::WriteInFlight) => {
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
          }
          Err(other) => panic!("unexpected sync error: {other:?}"),
        }
      }
      panic!("the single-flight gate never admitted the sync");
    }

    /// Asserts the parked sync stays pending across generous scheduler slices
    /// with `written` cookie writes on disk — the fence gate observable.
    async fn assert_parked(
      rig: &Rig,
      pending: &mut futures_channel::oneshot::Receiver<
        Result<PathBuf, crate::error::SyncRootError>,
      >,
      written: usize,
    ) {
      for _ in 0..40 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      assert!(
        futures_util::poll!(&mut *pending).is_pending(),
        "the sync is parked on the coverage gate"
      );
      assert_eq!(
        rig.fs.cookie_writes().len(),
        written,
        "no cookie is written while the gate holds"
      );
    }

    /// Reads events until a `Rescan` with an epoch strictly above `floor`
    /// arrives, returning its epoch — the "a fresh covering Rescan precedes
    /// the cookie" observable (the event was queued before the write
    /// dispatched; `next_event`'s deadline fails the cell when it never comes).
    async fn next_rescan_above(rig: &Rig, floor: Epoch) -> Epoch {
      loop {
        let (_scope, change) = next_event(rig).await;
        if change.kind().is_rescan() && change.epoch() > floor {
          return change.epoch();
        }
      }
    }

    /// Drains the event channel until it stays quiet across a settle window,
    /// returning the highest `Rescan` epoch seen (or `floor`).
    async fn drain_to_quiet(rig: &Rig, floor: Epoch) -> Epoch {
      let mut top = floor;
      let mut quiet = 0u32;
      while quiet < 20 {
        match rig.events.try_recv() {
          Ok((_scope, _root, change)) => {
            quiet = 0;
            if change.kind().is_rescan() && change.epoch() > top {
              top = change.epoch();
            }
          }
          Err(_) => {
            quiet += 1;
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(10)).await;
          }
        }
      }
      top
    }

    /// C1 (F1, flagship): a sync issued while the replace rebuild is held
    /// parks; a change landing in the held window (`put` with NO batch — dark:
    /// its directory's watch is not armed yet, and the re-arm read suppresses
    /// it) is covered by the closing `Rescan` the rebuild's settle emits, with
    /// an epoch strictly above the commit's, QUEUED before the cookie write
    /// dispatches. Fails on old: only the commit `Rescan` ever arrives and the
    /// cookie precedes any later `Rescan` — the umbrella would read
    /// `Delivered` over the dark change.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sync_across_a_replace_rebuild_is_covered_by_the_closing_rescan() {
      let rig = inotify_rig();
      rig.fs.put("/r2", FileKind::Dir, 20);
      rig.fs.put("/r2/a", FileKind::Dir, 21);
      let scope = watch(&rig, "/r").await;
      assert!(
        settle(|| {
          rig
            .fs
            .enumerates()
            .iter()
            .any(|(_, p)| p == std::path::Path::new("/r"))
        })
        .await,
        "staging: the birth crawl must land before the replace rebuilds the scope"
      );

      // Hold the rebuild's reads, then commit the replace.
      let hold = rig.fs.hold_enumerates();
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: PathBuf::from("/r2"),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
          reply,
        })
        .await
        .unwrap();
      assert!(on_reply.await.expect("driver replies").is_ok());
      let (_s, change) = next_event(&rig).await;
      assert!(change.kind().is_rescan(), "the commit Rescan: {change:?}");
      let commit_epoch = change.epoch();

      // The barrier over the held rebuild parks; the dark change lands.
      let mut pending = sync_pending(&rig, scope, "/r2", ".tributaries-sync-c1").await;
      assert_parked(&rig, &mut pending, 0).await;
      rig.fs.put("/r2/a/f", FileKind::File, 30);

      // Release: the rebuild settles, the closing Rescan is queued, and only
      // then does the write dispatch.
      hold.release();
      let path = tokio::time::timeout(interpreted_secs(10), pending)
        .await
        .expect("the sync resolves once the rebuild settles")
        .expect("the driver replies")
        .expect("the write lands");
      let closing = next_rescan_above(&rig, commit_epoch).await;
      assert!(closing > commit_epoch);
      assert_eq!(rig.fs.cookie_writes(), vec![path]);
    }

    /// C2 (F2a, flagship): a sync over a standing arm-refused hole completes
    /// (never parked forever) with a FRESH covering `Rescan` — epoch strictly
    /// above the failure's — queued ahead of its cookie write, plus a bounded
    /// heal re-attempt of the refused arm; after the hole heals, the healing
    /// window closes with the closing `Rescan`, and a deficit-free sync adds
    /// no `Rescan` at all. Fails on old: after the failure's one edge
    /// `Rescan`, NOTHING precedes any later sync's cookie — the umbrella would
    /// read `Delivered` over changes in the permanently-dark subtree.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sync_over_an_arm_refused_hole_resignals_then_heals() {
      let fs = FakeFs::new(1);
      fs.put("/r", FileKind::Dir, 1);
      fs.put("/r/a", FileKind::Dir, 11);
      fs.fail_watch_at("/r/a", tributary_proto::WatchError::NoSpace);
      let rig = inotify_rig_fs(fs);
      let scope = watch(&rig, "/r").await;

      // Boot: the refused arm's edge Rescan.
      let edge = next_rescan_above(&rig, Epoch::START).await;
      let arms_before = arms_at(&rig, "/r/a");

      // Sync #1 over the standing hole: the refreshing Rescan precedes the
      // cookie, and the heal kick re-attempts the arm (which fails again).
      let path1 = sync_ok(&rig, scope, "/r", ".tributaries-sync-c2-1").await;
      let refreshed = next_rescan_above(&rig, edge).await;
      assert_eq!(
        rig.fs.cookie_writes(),
        vec![path1],
        "the write landed behind the refreshing Rescan"
      );
      settle(|| arms_at(&rig, "/r/a") > arms_before).await;
      assert!(
        arms_at(&rig, "/r/a") > arms_before,
        "the heal kick re-attempted the refused arm"
      );
      let top = drain_to_quiet(&rig, refreshed).await;

      // Heal, then sync #2: its re-signal + heal kick succeed, and the healing
      // window closes with the closing Rescan.
      rig.fs.heal_watch_at("/r/a");
      let _path2 = sync_ok(&rig, scope, "/r", ".tributaries-sync-c2-2").await;
      let after_heal = next_rescan_above(&rig, top).await;
      let quiet = drain_to_quiet(&rig, after_heal).await;

      // Sync #3 over the healed scope: no deficit, no new Rescan.
      let _path3 = sync_ok(&rig, scope, "/r", ".tributaries-sync-c2-3").await;
      let end = drain_to_quiet(&rig, quiet).await;
      assert_eq!(end, quiet, "a deficit-free sync adds no Rescan");
    }

    /// C3 (F2b): a sync over an exhausted-read interior re-signals a fresh
    /// covering `Rescan` and kicks a fresh read per degraded sync; once the
    /// directory reads cleanly, a later sync adds nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sync_over_an_exhausted_read_interior_resignals_then_heals() {
      let fs = FakeFs::new(1);
      fs.put("/r", FileKind::Dir, 1);
      fs.put("/r/a", FileKind::Dir, 11);
      // The boot read and its bounded retries all fail: exhaustion.
      for _ in 0..3 {
        fs.enumerate_answer(
          "/r/a",
          crate::core::RawEnumerate::Failed(IoClass::Permission),
        );
      }
      let rig = inotify_rig_fs(fs);
      let scope = watch(&rig, "/r").await;
      settle(|| enumerates_at(&rig, "/r/a") == 3).await;
      assert_eq!(enumerates_at(&rig, "/r/a"), 3, "the read exhausted");
      let floor = drain_to_quiet(&rig, Epoch::START).await;

      // Sync #1: the still-failing interior re-signals and re-reads (the kick
      // burns another failure ladder), staying degraded.
      for _ in 0..3 {
        rig.fs.enumerate_answer(
          "/r/a",
          crate::core::RawEnumerate::Failed(IoClass::Permission),
        );
      }
      let reads = enumerates_at(&rig, "/r/a");
      let _path1 = sync_ok(&rig, scope, "/r", ".tributaries-sync-c3-1").await;
      let refreshed = next_rescan_above(&rig, floor).await;
      settle(|| enumerates_at(&rig, "/r/a") > reads).await;
      assert!(
        enumerates_at(&rig, "/r/a") > reads,
        "the heal kick re-read the interior"
      );
      let top = drain_to_quiet(&rig, refreshed).await;

      // Sync #2: the queued failures are burned — the kicked read now serves
      // the real (clean) directory and the interior heals.
      let _path2 = sync_ok(&rig, scope, "/r", ".tributaries-sync-c3-2").await;
      let after_heal = next_rescan_above(&rig, top).await;
      let quiet = drain_to_quiet(&rig, after_heal).await;

      // Sync #3: healed — no new Rescan.
      let _path3 = sync_ok(&rig, scope, "/r", ".tributaries-sync-c3-3").await;
      let end = drain_to_quiet(&rig, quiet).await;
      assert_eq!(end, quiet, "a healed interior owes later syncs nothing");
    }

    /// C4 (no-loop): a PERMANENTLY broken hole never parks a sync forever —
    /// each of two sequential syncs completes in bounded time, each preceded
    /// by its own fresh covering `Rescan` (strictly increasing epochs): an
    /// unbounded sequence of honest `Dominated` barriers, never a wedged one.
    #[tokio::test(flavor = "multi_thread")]
    async fn syncs_over_a_permanently_broken_hole_stay_bounded() {
      let fs = FakeFs::new(1);
      fs.put("/r", FileKind::Dir, 1);
      fs.put("/r/a", FileKind::Dir, 11);
      fs.fail_watch_at("/r/a", tributary_proto::WatchError::NoSpace);
      let rig = inotify_rig_fs(fs);
      let scope = watch(&rig, "/r").await;
      let edge = next_rescan_above(&rig, Epoch::START).await;

      let _path1 = sync_ok(&rig, scope, "/r", ".tributaries-sync-c4-1").await;
      let first = next_rescan_above(&rig, edge).await;
      let top = drain_to_quiet(&rig, first).await;
      let _path2 = sync_ok(&rig, scope, "/r", ".tributaries-sync-c4-2").await;
      let second = next_rescan_above(&rig, top).await;
      assert!(second > first, "each sync re-signals its own fresh Rescan");
      assert_eq!(rig.fs.cookie_writes().len(), 2, "both writes landed");
    }

    /// C5 (P3, hold gate): a sync issued mid-rename-hold parks — the
    /// suppressed under-hold record's covering `Rescan` is emitted only at the
    /// pairing — and dispatches only after the pairing's `Rescan` is queued.
    /// The rig's move window is stretched far past the parked-assertion's
    /// real-time slices, so it is the PAIRING that releases the gate, never
    /// the timeout racing the assertion. Fails on old: `rearm_settled` never
    /// counted the hold, the cookie was written mid-window, and the pairing
    /// `Rescan` arrived AFTER it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sync_mid_hold_parks_until_the_pairing_rescan() {
      let fs = FakeFs::new(1);
      fs.put("/r", FileKind::Dir, 1);
      fs.put("/r/d", FileKind::Dir, 11);
      fs.spawn_backend(BackendKind::Inotify);
      let (cmd_tx, cmd_rx) = async_channel::bounded(16);
      let (cleanup, cookie_wake) = cookie_ingress();
      let (ev_tx, ev_rx) = async_channel::bounded(64);
      tokio::spawn(run::<TokioRuntime, FakeFs>(
        DriverConfig {
          move_window: Duration::from_secs(60),
          ..inotify_config()
        },
        fs.clone(),
        cmd_rx,
        cookie_wake,
        ev_tx,
        NullRegistry,
      ));
      let rig = Rig {
        fs,
        commands: cmd_tx,
        cleanup,
        events: ev_rx,
      };
      let scope = watch(&rig, "/r").await;
      settle(|| {
        rig
          .fs
          .arms()
          .iter()
          .any(|(_, p)| p == std::path::Path::new("/r/d"))
      })
      .await;
      let root_watch = rig.fs.arms().first().cloned().expect("the root arm").0;
      let d_watch = rig
        .fs
        .arms()
        .iter()
        .find(|(_, p)| p == std::path::Path::new("/r/d"))
        .expect("the child arm")
        .0;
      let floor = drain_to_quiet(&rig, Epoch::START).await;

      // The on-disk rename happens first, then its source half arrives: the
      // watched directory detaches-and-holds for the pairing window.
      rig.fs.remove("/r/d");
      rig.fs.put("/r/e", FileKind::Dir, 11);
      rig.fs.send_inotify_batch(
        "/r",
        vec![RawLinuxEvent::Inotify {
          anchors: vec![root_watch],
          event: RawInotifyEvent {
            wd: 1,
            mask: InotifyMask(IN_MOVED_FROM | IN_ISDIR),
            cookie: 7,
            name: Some(b"d".to_vec()),
          },
        }],
      );
      // A record under the held source: suppressed (stale pre-move path), so
      // its covering Rescan is owed at the pairing.
      rig.fs.send_inotify_batch(
        "/r",
        vec![RawLinuxEvent::Inotify {
          anchors: vec![d_watch],
          event: RawInotifyEvent {
            wd: 2,
            mask: InotifyMask(IN_CREATE),
            cookie: 0,
            name: Some(b"x".to_vec()),
          },
        }],
      );
      // A delivered sentinel behind the hold on the same FIFO stream: seeing
      // it proves the MovedFrom was ingested — the command channel is polled
      // ahead of source batches, so without it the sync below could be
      // admitted (and its fence settle) before the hold even exists.
      rig.fs.send_inotify_batch(
        "/r",
        vec![RawLinuxEvent::Inotify {
          anchors: vec![root_watch],
          event: RawInotifyEvent {
            wd: 1,
            mask: InotifyMask(IN_CREATE),
            cookie: 0,
            name: Some(b"z".to_vec()),
          },
        }],
      );
      loop {
        let (_s, change) = next_event(&rig).await;
        if change.kind().is_created() && change.location() == &loc(&["z"]) {
          break;
        }
      }

      // The barrier mid-hold: parked, nothing written.
      let mut pending = sync_pending(&rig, scope, "/r", ".tributaries-sync-c5").await;
      assert_parked(&rig, &mut pending, 0).await;

      // The pairing resolves the hold: its Rescan (the dirtied-hold cover at
      // the destination) is queued, the re-arm settles, the write dispatches.
      rig.fs.send_inotify_batch(
        "/r",
        vec![RawLinuxEvent::Inotify {
          anchors: vec![root_watch],
          event: RawInotifyEvent {
            wd: 1,
            mask: InotifyMask(IN_MOVED_TO | IN_ISDIR),
            cookie: 7,
            name: Some(b"e".to_vec()),
          },
        }],
      );
      let path = tokio::time::timeout(interpreted_secs(10), pending)
        .await
        .expect("the sync resolves once the hold pairs")
        .expect("the driver replies")
        .expect("the write lands");
      let _pairing = next_rescan_above(&rig, floor).await;
      assert_eq!(rig.fs.cookie_writes(), vec![path]);
    }

    /// C6 (P4, latent gate): a loss re-arm folded into an in-flight COLD read
    /// leaves `rearm_settled` true while the re-walk obligation is latent — a
    /// sync issued in that window parks, and dispatches only after the
    /// completion's escalation (and the window's closing `Rescan`) are queued.
    /// Fails on old: the fence settled during the latency and the cookie beat
    /// the escalation.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sync_during_a_coalesced_latent_rearm_parks_until_escalation() {
      let fs = FakeFs::new(1);
      fs.put("/r", FileKind::Dir, 1);
      fs.put("/r/sub", FileKind::Dir, 11);
      fs.spawn_backend(BackendKind::Inotify);
      // Hold the boot cold read in flight before the loss arrives.
      let hold = fs.hold_enumerates();
      let rig = inotify_rig_fs(fs);
      let scope = watch(&rig, "/r").await;

      // The loss folds its re-arm into the held cold read (Coalesced).
      rig.fs.send_lossy("/r");
      let (_s, change) = next_event(&rig).await;
      assert!(change.kind().is_rescan(), "the overflow Rescan: {change:?}");
      let overflow_epoch = change.epoch();

      // The barrier inside the latent window: parked, nothing written.
      let mut pending = sync_pending(&rig, scope, "/r", ".tributaries-sync-c6").await;
      assert_parked(&rig, &mut pending, 0).await;

      // Release: the dirtied completion escalates (covering Rescan + counted
      // retry), the suppressed re-walk closes with the closing Rescan, and
      // only then does the write dispatch.
      hold.release();
      let path = tokio::time::timeout(interpreted_secs(10), pending)
        .await
        .expect("the sync resolves once the escalation drains")
        .expect("the driver replies")
        .expect("the write lands");
      let escalation = next_rescan_above(&rig, overflow_epoch).await;
      assert!(escalation > overflow_epoch);
      assert_eq!(rig.fs.cookie_writes(), vec![path]);
    }

    /// Arms executed at `path` so far.
    fn arms_at(rig: &Rig, path: &str) -> usize {
      rig
        .fs
        .arms()
        .iter()
        .filter(|(_, p)| p == std::path::Path::new(path))
        .count()
    }

    /// Enumerates executed at `path` so far.
    fn enumerates_at(rig: &Rig, path: &str) -> usize {
      rig
        .fs
        .enumerates()
        .iter()
        .filter(|(_, p)| p == std::path::Path::new(path))
        .count()
    }
  }

  /// The same-transport WIDEN (D2): a widening replace on the descending
  /// backend keeps the live stream — no spawn, no teardown, no lane swap, no
  /// covering Rescan — and the old subtree's coverage rides across
  /// continuously while the newly covered ground is discovered cold.
  mod widen {
    use super::*;

    async fn replace(
      rig: &Rig,
      scope: ScopeId,
      new_root: &str,
    ) -> Result<(), crate::error::ReplaceRootError> {
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: PathBuf::from(new_root),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from(
            new_root,
          )),
          reply,
        })
        .await
        .unwrap();
      on_reply.await.expect("driver replies")
    }

    /// A flood wound down no later than its drop.
    ///
    /// The fillers below are dedicated OS threads, not runtime tasks, and while
    /// they run the driver has an ALWAYS-READY input: a parked command filler
    /// completes the instant the driver consumes a command, so the loop can never
    /// observe a closed mailbox, and a source filler keeps the lane hot the same
    /// way. Either way the driver task never completes and the runtime's
    /// blocking-pool shutdown waits on it forever, so a caller that unwinds out of
    /// an assertion before its explicit wind-down wedges the test binary and
    /// libtest never gets to print the failure. Winding down on drop keeps a
    /// failing assertion a REPORT.
    ///
    /// Both joins are bounded by construction, whatever the driver is doing by
    /// then. A command filler parks through [`send_watching_stop`], which observes
    /// the stop flag rather than waiting for a drain that a driver past its loop
    /// will never perform (`a_widen_flood_winds_down_with_no_consumer`); a source
    /// filler pushes onto an UNBOUNDED lane, so it never parks at all.
    struct Flood {
      stop: std::sync::Arc<AtomicBool>,
      fillers: Vec<std::thread::JoinHandle<()>>,
    }

    impl Flood {
      /// Signals the fillers to stop without waiting for them.
      fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
      }

      /// The explicit wind-down: stops the fillers and JOINS every one of them,
      /// keeping the assertion that each terminates.
      fn stop_and_join(mut self) {
        self.stop();
        for filler in std::mem::take(&mut self.fillers) {
          filler.join().expect("the flood thread stops");
        }
      }
    }

    impl Drop for Flood {
      fn drop(&mut self) {
        self.stop();
        // Joins without asserting: a panic raised while unwinding aborts the
        // process, destroying the very report this wind-down exists to allow.
        for filler in std::mem::take(&mut self.fillers) {
          let _ = filler.join();
        }
      }
    }

    /// This guard's liveness pin, the twin of
    /// `a_command_flood_winds_down_with_no_consumer`: its DROP path — the path an
    /// unwind takes, with the driver already past its loop or left unpolled by the
    /// panic — must terminate against a full mailbox that nothing will ever drain.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_widen_flood_winds_down_with_no_consumer() {
      let (commands, receiver) = async_channel::bounded::<Command>(16);
      let ghost = ScopeId::new(core::num::NonZeroU64::new(999_999).unwrap());
      let stop = std::sync::Arc::new(AtomicBool::new(false));
      let fillers = spawn_command_fillers(&commands, &stop, 2, move || Command::SetCover {
        scope: ghost,
        retained: vec![PathBuf::from("/nowhere")],
        reply: None,
      });
      let flood = Flood { stop, fillers };
      assert!(
        settle(|| commands.len() >= 16).await,
        "staging: the fillers must saturate the mailbox and park"
      );

      let wind_down = tokio::task::spawn_blocking(move || drop(flood));
      let bounded = tokio::time::timeout(interpreted_secs(5), wind_down).await;
      // Free the fillers before the verdict, so a regression reports as a failed
      // assertion instead of wedging the runtime's shutdown on the stuck join.
      drop(receiver);
      assert!(
        bounded.is_ok(),
        "the guard's drop path is bounded with no consumer to drain the mailbox"
      );
    }

    /// The flagship no-gap cell: the widen commits on the SAME stream (one
    /// spawn ever, zero shutdowns), emits NO Rescan and bumps NO epoch, keeps
    /// delivering old-subtree records on the surviving watch — re-rooted and
    /// chain-prefixed at their unchanged absolute paths — and announces the
    /// newly covered ground as cold `Created` discovery.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_widening_replace_keeps_the_stream_and_dominates_nothing() {
      let rig = inotify_rig();
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 3);
      rig.fs.put("/r/sub/deep/leaf", FileKind::Dir, 6);
      rig.fs.put("/r/other", FileKind::Dir, 4);
      rig.fs.put("/r/other/kid", FileKind::Dir, 5);
      let scope = watch(&rig, "/r/sub").await;
      let sub_watch = rig
        .fs
        .arms()
        .first()
        .cloned()
        .expect("the birth root arm")
        .0;

      // Let the birth crawl finish before driving records: the registration's
      // closing `Rescan` is emitted at COVERAGE SETTLE, so consuming it proves
      // the root's AND `deep`'s reads completed (a record racing an in-flight
      // read would dirty it into the ordinary escalation Rescan — a different
      // story than the widen's). It replaces the pair of inventory `Created`s
      // this used to consume, which a registration no longer delivers (42-10),
      // and fences strictly more: the pair proved two reads, the settle edge
      // proves every one of them.
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      // A pre-widen delivery pins the epoch the widen must NOT dominate.
      rig.fs.send_inotify_batch(
        "/r/sub",
        vec![attributed(&[sub_watch], IN_CREATE, b"pre.txt")],
      );
      let (s, root, change) = next_rooted(&rig).await;
      assert_eq!((s, root.as_path()), (scope, std::path::Path::new("/r/sub")));
      assert!(change.kind().is_created());
      let pre_epoch = change.epoch();

      assert!(replace(&rig, scope, "/r").await.is_ok());
      assert_eq!(rig.fs.spawns(), 1, "the widen spawns nothing");
      assert_eq!(rig.fs.shutdowns(), 0, "the widen retires nothing");

      // The widened root pre-armed on the live port and cold-read: the newly
      // covered ground announces as Created (state facts) all the way down —
      // the adopted slot is reused (its interior is never re-read) — and
      // NOTHING is a Rescan. Waiting for `other/kid` also proves `other`'s own
      // cold read completed, so the record below cannot race (and dirty) it.
      let mut seen_other = false;
      let mut seen_sub_entry = false;
      let mut seen_other_kid = false;
      while !(seen_other && seen_sub_entry && seen_other_kid) {
        let (s, root, change) = next_rooted(&rig).await;
        assert_eq!((s, root.as_path()), (scope, std::path::Path::new("/r")));
        assert!(
          change.kind().is_created(),
          "the widen's discovery is Created-only, never a Rescan: {change:?}"
        );
        seen_other |= change.location() == &loc(&["other"]);
        seen_sub_entry |= change.location() == &loc(&["sub"]);
        seen_other_kid |= change.location() == &loc(&["other", "kid"]);
      }

      // Continuity: the SAME kernel watches keep recording the old subtree —
      // root and interior alike — re-rooted under the widened path at the SAME
      // epoch, at their unchanged absolute paths.
      let deep_watch = rig
        .fs
        .arms()
        .iter()
        .find(|(_, p)| p == std::path::Path::new("/r/sub/deep"))
        .expect("the old interior armed at birth")
        .0;
      rig.fs.send_inotify_batch(
        "/r/sub",
        vec![attributed(&[sub_watch], IN_CREATE, b"post.txt")],
      );
      let (s, root, change) = next_rooted(&rig).await;
      assert_eq!((s, root.as_path()), (scope, std::path::Path::new("/r")));
      assert!(change.kind().is_created());
      assert_eq!(change.location(), &loc(&["sub", "post.txt"]));
      assert_eq!(
        change.epoch(),
        pre_epoch,
        "no reconciliation generation bump across the widen"
      );
      rig.fs.send_inotify_batch(
        "/r/sub",
        vec![attributed(&[deep_watch], IN_CREATE, b"d.txt")],
      );
      let (s, root, change) = next_rooted(&rig).await;
      assert_eq!((s, root.as_path()), (scope, std::path::Path::new("/r")));
      assert_eq!(change.location(), &loc(&["sub", "deep", "d.txt"]));

      // The widened ground is genuinely armed: records under it deliver.
      let other_watch = rig
        .fs
        .arms()
        .iter()
        .find(|(_, p)| p == std::path::Path::new("/r/other"))
        .expect("the new ground armed")
        .0;
      rig.fs.send_inotify_batch(
        "/r/sub",
        vec![attributed(&[other_watch], IN_CREATE, b"new.txt")],
      );
      let (s, root, change) = next_rooted(&rig).await;
      assert_eq!((s, root.as_path()), (scope, std::path::Path::new("/r")));
      assert_eq!(change.location(), &loc(&["other", "new.txt"]));

      // Unwatch tears exactly the ONE stream that ever existed.
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Unwatch {
          scope,
          reply: Some(reply),
        })
        .await
        .unwrap();
      assert!(on_reply.await.unwrap().is_torn());
      settle(|| rig.fs.shutdowns() == 1).await;
      assert_eq!(rig.fs.spawns(), 1);
    }

    /// A failed meta resolve answers the typed source error and leaves the old
    /// world untouched — no spawn, no teardown, coverage still delivering.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_widen_meta_failure_unwinds_with_the_old_world_untouched() {
      let rig = inotify_rig();
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 3);
      let scope = watch(&rig, "/r/sub").await;
      let sub_watch = rig
        .fs
        .arms()
        .first()
        .cloned()
        .expect("the birth root arm")
        .0;
      // Fence the birth crawl (see the flagship cell): the root's read is
      // complete once its discovery delivers, so later records cannot dirty it.
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      rig.fs.remove("/r");
      let err = replace(&rig, scope, "/r")
        .await
        .expect_err("the meta fails");
      assert!(
        matches!(err, crate::error::ReplaceRootError::Source(_)),
        "{err:?}"
      );
      assert_eq!(rig.fs.spawns(), 1);
      assert_eq!(rig.fs.shutdowns(), 0);

      rig.fs.send_inotify_batch(
        "/r/sub",
        vec![attributed(&[sub_watch], IN_CREATE, b"alive.txt")],
      );
      let (s, root, change) = next_rooted(&rig).await;
      assert_eq!((s, root.as_path()), (scope, std::path::Path::new("/r/sub")));
      assert_eq!(change.location(), &loc(&["alive.txt"]));
    }

    /// A failed live-port pre-arm unwinds atomically: nothing was installed,
    /// nothing retires, and the old coverage keeps delivering.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_widen_pre_arm_failure_unwinds_with_the_old_coverage_untouched() {
      let rig = inotify_rig();
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 3);
      rig
        .fs
        .fail_watch_at("/r", tributary_proto::WatchError::NoSpace);
      let scope = watch(&rig, "/r/sub").await;
      let sub_watch = rig
        .fs
        .arms()
        .first()
        .cloned()
        .expect("the birth root arm")
        .0;
      // Fence the birth crawl (see the flagship cell).
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      let err = replace(&rig, scope, "/r").await.expect_err("the arm fails");
      assert!(
        matches!(err, crate::error::ReplaceRootError::Source(_)),
        "{err:?}"
      );
      assert_eq!(rig.fs.spawns(), 1, "no fallback spawn on an arm failure");
      assert_eq!(rig.fs.shutdowns(), 0);

      rig.fs.send_inotify_batch(
        "/r/sub",
        vec![attributed(&[sub_watch], IN_CREATE, b"alive.txt")],
      );
      let (s, root, change) = next_rooted(&rig).await;
      assert_eq!((s, root.as_path()), (scope, std::path::Path::new("/r/sub")));
      assert_eq!(change.location(), &loc(&["alive.txt"]));
    }

    /// A widen whose resolved target sits on a DIFFERENT mount frame falls
    /// back to the general stream replace: the enumerate lowering would mark
    /// the adopted slot `Other` and tear the old coverage down, so the driver
    /// re-validates the frame at the meta and routes D1 — observable as the
    /// replacement spawn, the old stream's retirement, and the commit Rescan.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_cross_frame_widen_falls_back_to_the_stream_replace() {
      let rig = inotify_rig_mnt(5);
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      let scope = watch(&rig, "/r/sub").await;
      // The widened root lives on another mount instance (a bind/submount
      // seam between old and new), same device.
      rig.fs.put_on_mount("/r", FileKind::Dir, 1, 7);

      assert!(replace(&rig, scope, "/r").await.is_ok());
      settle(|| rig.fs.shutdowns() == 1).await;
      assert_eq!(rig.fs.spawns(), 2, "the fallback took the new-stream path");
      let (s, root, change) = next_rooted(&rig).await;
      assert_eq!((s, root.as_path()), (scope, std::path::Path::new("/r")));
      assert!(
        change.kind().is_rescan(),
        "the stream replace bridges with its covering Rescan: {change:?}"
      );
    }

    /// The DEPTH CAP, end to end. An old root more than one segment below the new
    /// one takes the general new-stream path: the splice would have to mint
    /// intermediate connectors whose edges no marker proves and no `MoveSelf`
    /// invalidates, so the commit gate declines it as a legitimate fallback rather
    /// than a bug.
    ///
    /// What the cap costs is visible here and it is only the SHORTCUT: a second
    /// spawn, the old stream retired, and the replace's covering `Rescan` instead
    /// of a zero-gap ride. What it does not cost is the capability — the scope
    /// still ends up rooted at the distant ancestor, and settles there.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_deep_widen_falls_back_to_the_stream_replace() {
      let rig = inotify_rig();
      rig.fs.put("/r/a", FileKind::Dir, 5);
      rig.fs.put("/r/a/b", FileKind::Dir, 6);
      let scope = watch(&rig, "/r/a/b").await;

      // Two segments up (`a`, `b`) — one past the depth the splice serves.
      assert!(replace(&rig, scope, "/r").await.is_ok());
      settle(|| rig.fs.shutdowns() == 1).await;
      assert_eq!(rig.fs.spawns(), 2, "the fallback took the new-stream path");
      let (s, root, change) = next_rooted(&rig).await;
      assert_eq!((s, root.as_path()), (scope, std::path::Path::new("/r")));
      assert!(
        change.kind().is_rescan(),
        "the stream replace bridges with its covering Rescan: {change:?}"
      );

      // And it is a LIVE scope on the new root, not a wedged one: the ordinary
      // unwatch resolves, retiring exactly the one stream the fallback spawned.
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Unwatch {
          scope,
          reply: Some(reply),
        })
        .await
        .unwrap();
      assert!(on_reply.await.unwrap().is_torn());
      settle(|| rig.fs.shutdowns() == 2).await;
      assert_eq!(rig.fs.spawns(), 2, "and no further spawn was needed");
    }

    /// Death wins mid-widen: a scope torn down while the pre-arm is parked
    /// answers `Retired`, and a parked unwatch resolves at quiescence — the
    /// widen's obligation is counted by the same fence as every other.
    #[tokio::test(flavor = "multi_thread")]
    async fn death_during_the_widen_pre_arm_answers_retired() {
      let rig = inotify_rig();
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      let scope = watch(&rig, "/r/sub").await;

      let hold = rig.fs.hold_prearms();
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: PathBuf::from("/r"),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
          reply,
        })
        .await
        .unwrap();

      // The unwatch tears the live stream while the pre-arm is parked; its
      // reply waits for the widen obligation to quiesce.
      let (ureply, on_unwatch) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Unwatch {
          scope,
          reply: Some(ureply),
        })
        .await
        .unwrap();
      assert!(
        settle(|| rig.fs.shutdowns() == 1).await,
        "staging: the stream must retire before the pre-arm is released"
      );
      hold.release();

      assert!(
        matches!(
          on_reply.await.expect("driver replies"),
          Err(crate::error::ReplaceRootError::Retired)
        ),
        "death wins over the in-flight widen"
      );
      assert!(
        on_unwatch.await.unwrap().is_torn(),
        "the unwatch resolves at quiescence"
      );
      assert_eq!(rig.fs.spawns(), 1);
    }

    /// Repeated widens ride the one stream end to end: two same-transport
    /// commits, one spawn ever, nothing retired until the final unwatch.
    #[tokio::test(flavor = "multi_thread")]
    async fn repeated_widens_reuse_the_one_stream() {
      let rig = inotify_rig();
      rig.fs.put("/r/a", FileKind::Dir, 5);
      rig.fs.put("/r/a/b", FileKind::Dir, 6);
      let scope = watch(&rig, "/r/a/b").await;

      assert!(replace(&rig, scope, "/r/a").await.is_ok());
      assert!(replace(&rig, scope, "/r").await.is_ok());
      assert_eq!(rig.fs.spawns(), 1, "both widens kept the stream");
      assert_eq!(rig.fs.shutdowns(), 0);

      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Unwatch {
          scope,
          reply: Some(reply),
        })
        .await
        .unwrap();
      assert!(on_reply.await.unwrap().is_torn());
      settle(|| rig.fs.shutdowns() == 1).await;
      assert_eq!(rig.fs.spawns(), 1);
    }

    /// The no-generation-bump observable: a cookie write dispatched BEFORE
    /// the widen still CLAIMS after it — the stream never retired, so the
    /// write's claim generation is still current. (A stream replace bumps the
    /// generation at its lane swap and such a write self-reaps instead.)
    #[tokio::test(flavor = "multi_thread")]
    async fn a_pre_widen_cookie_write_claims_after_the_commit() {
      let rig = inotify_rig();
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 3);
      let scope = watch(&rig, "/r/sub").await;
      // Fence the birth crawl (see the flagship cell).
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      // Park the write IN THE POOL: dispatched under the pre-widen world,
      // claiming only after the commit.
      let hold = rig.fs.hold_cookie_writes();
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::SyncRoot {
          scope,
          dir: PathBuf::from("/r/sub"),
          name: ".tributaries-sync-widen-claim".to_owned(),
          ticket: ticket(),
          reply,
        })
        .await
        .unwrap();
      assert!(
        settle(|| rig.fs.cookie_dispatches() == 1).await,
        "staging: the write must be PARKED in the pool before the widen commits"
      );

      assert!(replace(&rig, scope, "/r").await.is_ok());
      assert_eq!(rig.fs.shutdowns(), 0, "the widen retires nothing");
      hold.release();

      let path = on_reply
        .await
        .expect("the driver replies")
        .expect("the pre-widen write claims after the commit");
      assert_eq!(path, PathBuf::from("/r/sub/.tributaries-sync-widen-claim"));
      assert_eq!(rig.fs.cookie_writes(), vec![path]);
    }

    const IN_MOVE_SELF: u32 = 0x0000_0800;

    /// The Codex R1 finding-1 cell: a sync admitted after a widen PARKS
    /// until the adoption tripwire resolves. The old root moved during the
    /// dark window with nothing observing the adopted slot, so the move is
    /// unrecorded — without the
    /// adoptions settle conjunct the cookie would dispatch immediately and
    /// resolve Delivered across the undelivered move; with it, the write
    /// waits, the covering root Rescan lands, and only then does
    /// the barrier resolve.
    ///
    /// Both halves of the barrier's hold are separated here, in order, because
    /// they are different claims. FIRST the edge is merely UNVERIFIED — no record
    /// of the move exists yet — and the adoptions conjunct alone is what parks the
    /// write. THEN the adopted object's own `MoveSelf` arrives and SPENDS the
    /// proof (round eight: a non-root `MoveSelf` is otherwise a deliberate no-op,
    /// and an unproven adopted watch is the one exception), which retires the edge
    /// under a counted covering root `Rescan` — so the release resolves on that
    /// rebuild and not on a listing whose restored occupancy would have confirmed.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sync_across_an_unverified_adoption_parks_until_the_tripwire_resolves() {
      let rig = inotify_rig();
      rig.fs.put("/r/sub", FileKind::Dir, 11);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 12);
      let scope = watch(&rig, "/r/sub").await;
      let old_watch = rig
        .fs
        .arms()
        .first()
        .cloned()
        .expect("the birth root arm")
        .0;
      // Fence the birth crawl (see the flagship cell).
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      // Freeze every post-commit read: the tripwire cannot resolve.
      let hold = rig.fs.hold_enumerates();
      assert!(replace(&rig, scope, "/r").await.is_ok());
      assert_eq!(
        rig.fs.spawns(),
        1,
        "the SPLICE committed — a fallback's spawn barrier would park this sync \
         for reasons that have nothing to do with an unverified adoption"
      );

      // The dark-window move: `/r/sub` renames to `/r/sub2` with nothing
      // observing the adopted slot — the widened root's own records were dropped
      // by the unknown-watch guard until the commit, and its first listing is
      // held. The object's own `MoveSelf` is deliberately withheld until after the
      // poll below, so what parks the write there is the UNVERIFIED edge itself
      // and not a spent one.
      rig.fs.remove("/r/sub/deep");
      rig.fs.remove("/r/sub");
      rig.fs.put("/r/sub2", FileKind::Dir, 11);
      rig.fs.put("/r/sub2/deep", FileKind::Dir, 12);

      let (reply, mut on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::SyncRoot {
          scope,
          dir: PathBuf::from("/r"),
          name: ".tributaries-sync-adopt".to_owned(),
          ticket: ticket(),
          reply,
        })
        .await
        .unwrap();
      for _ in 0..40 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      assert!(
        futures_util::poll!(&mut on_reply).is_pending(),
        "the barrier waits for the unverified adoption"
      );
      assert_eq!(
        rig.fs.cookie_dispatches(),
        0,
        "no write dispatches over the unverified window"
      );

      // NOW the object's own move record lands. Round eight's exception: the old
      // root is the widen's unproven adopted watch, so this spends the proof a
      // later listing could still appear to give, and retires the edge under a
      // COUNTED covering root Rescan. The barrier stays down across it — the
      // release is owed to the rebuild, never to the move.
      rig
        .fs
        .send_inotify_batch("/r/sub", vec![attributed(&[old_watch], IN_MOVE_SELF, b"")]);
      for _ in 0..40 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      assert!(
        futures_util::poll!(&mut on_reply).is_pending(),
        "the spent proof hands the barrier to its counted cover, not to nothing"
      );
      assert_eq!(
        rig.fs.cookie_dispatches(),
        0,
        "and still no write over the interval the move ended"
      );

      // The invalidation's covering root Rescan, delivered BEFORE the reads are
      // released — which is what makes this half of the cell decisive. With the
      // `MoveSelf` exception gone the marker would simply stay unverified, every
      // assertion above would still pass, and nothing would be signalled until a
      // listing ran; the Rescan arriving here is the record that the object's own
      // move is what spent the proof.
      loop {
        let (s, root, change) = next_rooted(&rig).await;
        if s == scope && root.as_path() == std::path::Path::new("/r") && change.kind().is_rescan() {
          break;
        }
      }

      // Release: the counted rebuild quiesces, and only then does the write
      // dispatch and the barrier resolve.
      hold.release();
      let path = tokio::time::timeout(interpreted_secs(10), on_reply)
        .await
        .expect("the sync resolves once the tripwire settled")
        .expect("the driver replies")
        .expect("the write lands");
      assert_eq!(rig.fs.cookie_writes(), vec![path]);
    }

    /// The Codex R1 finding-2 cell: the ADOPTED SLOT replaced by a FILE during
    /// the dark window. The widened root's cold listing reconciles the slot and
    /// tears down the adopted old tree and the pending
    /// tripwire in one drop — which must stand the closing covering Rescan
    /// (an erased unverified adoption is erased coverage), never disarm the
    /// old watches in silence. The scope stays serviceable: a later sync
    /// resolves.
    ///
    /// At the one depth the splice serves this slot IS the adopted edge, so the
    /// finding's shape — an unverified adoption erased by a reconcile, driven by
    /// the widened root's own first listing — is reached directly rather than
    /// through an intermediate connector.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_adopted_slot_turned_file_tears_down_loudly() {
      let rig = inotify_rig();
      rig.fs.put("/r/sub", FileKind::Dir, 11);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 12);
      let scope = watch(&rig, "/r/sub").await;
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      let hold = rig.fs.hold_enumerates();
      assert!(replace(&rig, scope, "/r").await.is_ok());
      assert_eq!(
        rig.fs.spawns(),
        1,
        "the SPLICE committed — a fallback's own covering Rescan and stream \
         retirement would satisfy every assertion below without an adoption \
         ever having been erased"
      );
      rig.fs.remove("/r/sub/deep");
      rig.fs.remove("/r/sub");
      rig.fs.put("/r/sub", FileKind::File, 40);
      hold.release();

      // The closing root Rescan is the teardown's honesty.
      loop {
        let (s, root, change) = next_rooted(&rig).await;
        if s == scope && root.as_path() == std::path::Path::new("/r") && change.kind().is_rescan() {
          break;
        }
      }
      // The old coverage was disarmed — loudly, and the scope still serves.
      settle(|| !rig.fs.disarms().is_empty()).await;
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::SyncRoot {
          scope,
          dir: PathBuf::from("/r"),
          name: ".tributaries-sync-after-teardown".to_owned(),
          ticket: ticket(),
          reply,
        })
        .await
        .unwrap();
      let path = tokio::time::timeout(interpreted_secs(10), on_reply)
        .await
        .expect("the sync resolves after the loud teardown")
        .expect("the driver replies")
        .expect("the write lands");
      assert!(rig.fs.cookie_writes().contains(&path));
    }

    /// The ratified F-C chain extension: a resolved mount prefix covering the
    /// old root sits on the connecting chain, so the widen must fall back to
    /// the stream replace — the chain crawl would `Other`-lower that slot
    /// and destroy the adopted coverage.
    ///
    /// The chain is one segment at the only depth the splice serves, so the seed
    /// is placed at the old root itself: the SAME `old.starts_with(m)` gate, at
    /// the only chain position that still exists. The seed must reach this gate
    /// on its own merits, which is why the widen is depth-one — a deeper one
    /// would be declined for its depth before the mount was ever consulted.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_mount_on_the_connecting_chain_falls_back_to_the_stream_replace() {
      let rig = inotify_rig();
      rig.fs.put("/r/sub", FileKind::Dir, 11);
      let scope = watch(&rig, "/r/sub").await;
      // The widen target's meta resolves with a mount seeded at the old root.
      rig.fs.seed_mounts(vec![bare_mount("/r/sub")]);

      assert!(replace(&rig, scope, "/r").await.is_ok());
      settle(|| rig.fs.shutdowns() == 1).await;
      assert_eq!(rig.fs.spawns(), 2, "the fallback took the new-stream path");
      let (s, root, change) = next_rooted(&rig).await;
      assert_eq!((s, root.as_path()), (scope, std::path::Path::new("/r")));
      assert!(
        change.kind().is_rescan(),
        "the stream replace bridges with its covering Rescan: {change:?}"
      );
    }

    /// INV-ROOT's happy-path dividend: a CLEAN witnessed window's commit
    /// already proved the reserved binding live, so a sync after the widen
    /// certifies as soon as the Monitor's own conjuncts clear — with the
    /// mount refresh HELD the whole time. The retired design serialized
    /// this behind a refresh round-trip; the deleted `root_verified`
    /// conjunct must not silently return.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_clean_widen_window_certifies_without_the_refresh() {
      let rig = inotify_rig();
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 3);
      let scope = watch(&rig, "/r/sub").await;
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      // Park the verification edge, then widen and let the adoption confirm
      // (the slice discovery delivering proves the widened root's read ran).
      let hold = rig.fs.hold_refreshes();
      assert!(replace(&rig, scope, "/r").await.is_ok());
      loop {
        let (s, root, change) = next_rooted(&rig).await;
        assert_eq!((s, root.as_path()), (scope, std::path::Path::new("/r")));
        if change.location() == &loc(&["sub"]) {
          break;
        }
      }

      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::SyncRoot {
          scope,
          dir: PathBuf::from("/r"),
          name: ".tributaries-sync-verify".to_owned(),
          ticket: ticket(),
          reply,
        })
        .await
        .unwrap();
      // The refreshes stay HELD: the clean window's commit is the whole
      // verification, so the sync certifies without one.
      let path = tokio::time::timeout(interpreted_secs(10), on_reply)
        .await
        .expect("a clean widen window certifies without the refresh")
        .expect("the driver replies")
        .expect("the write lands");
      assert_eq!(rig.fs.cookie_writes(), vec![path]);
      hold.release();
    }

    /// The adoption seal releases the coverage barrier from INSIDE the driver's
    /// choke point — the one release in the loop that does not ride an ingest of
    /// its own. A `sync_root` opened while the seal's cut is still in flight is
    /// waiting on exactly that release, so the pass that takes it must also be the
    /// pass that offers the fence its own ordering cut. Otherwise the fence is
    /// judged against a barrier the next line settles, and with nothing left to
    /// ingest the loop parks with the sync unanswered.
    ///
    /// Staged deterministically by holding the widened root's own listing on the
    /// pool, so the marker cannot stage until the sync's fence is already open.
    ///
    /// Mutation witness: resolve the seals after the cover-fence demand instead of
    /// before it, and this sync never answers.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sync_opened_under_a_staged_adoption_still_answers() {
      let rig = inotify_rig();
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 3);
      let scope = watch(&rig, "/r/sub").await;
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      // The widened root's cold read parks on the gate, so the adoption marker
      // stands UNSTAGED across everything below.
      let hold = rig.fs.hold_enumerates_at("/r");
      assert!(replace(&rig, scope, "/r").await.is_ok());
      assert!(
        settle(|| hold.captured() > 0).await,
        "staging: the widened root's listing must be on the gate"
      );

      // The sync opens its fence over a barrier the standing marker holds down.
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::SyncRoot {
          scope,
          dir: PathBuf::from("/r"),
          name: ".tributaries-sync-seal".to_owned(),
          ticket: ticket(),
          reply,
        })
        .await
        .unwrap();
      let mut opened = false;
      for _ in 0..200 {
        let (q, on_q) = futures_channel::oneshot::channel();
        rig
          .commands
          .send(Command::DebugPendingCoverFences { scope, reply: q })
          .await
          .unwrap();
        if on_q.await.unwrap() == 1 {
          opened = true;
          break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      assert!(
        opened,
        "staging: the sync's fence must be open while the seal's cut is out"
      );

      hold.release();
      let path = tokio::time::timeout(interpreted_secs(10), on_reply)
        .await
        .expect("the sync answers on the pass the seal releases the barrier")
        .expect("the driver replies")
        .expect("the write lands");
      assert_eq!(rig.fs.cookie_writes(), vec![path]);
    }

    /// W5/W6 end-to-end — the witnessed window's loss leg: a transport loss
    /// drained while the pre-arm is parked taints the window, so the commit
    /// refuses the same-fd splice and the obligation falls back to the
    /// general stream replace — a fresh fd whose spawn barrier re-establishes
    /// the binding the window could not prove — while the pre-armed
    /// descriptor is disarmed rather than left attributing noise (OQ5).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_lossy_widen_window_falls_back_to_the_stream_replace() {
      let rig = inotify_rig();
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 3);
      let scope = watch(&rig, "/r/sub").await;
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      // Park the pre-arm, dispatch the widen, and wait for the pre-arm to be
      // ENTERED: the witnessed window is provably open from here (the
      // reservation and the pre-arm dispatch share one handler).
      let hold = rig.fs.hold_prearms();
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: PathBuf::from("/r"),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
          reply,
        })
        .await
        .unwrap();
      settle(|| rig.fs.prearm_entries() == 1).await;

      // The loss, provably inside the window; waiting out the overflow ack
      // proves the driver consumed it (the core latched) before the release.
      rig.fs.send_lossy("/r/sub");
      settle(|| !rig.fs.overflow_pending("/r/sub")).await;
      assert!(
        !rig.fs.overflow_pending("/r/sub"),
        "could not stage the interleaving: the loss must drain into the witnessed window before release"
      );
      hold.release();

      // The tainted commit falls back: the caller still resolves Ok — through
      // the stream replace's commit — on a SECOND spawn, with the first
      // stream retired and the pre-armed descriptor disarmed.
      let resolved = tokio::time::timeout(interpreted_secs(10), on_reply)
        .await
        .expect("the fallback replace resolves the caller")
        .expect("the driver replies");
      assert!(
        resolved.is_ok(),
        "the fallback commit answers Ok: {resolved:?}"
      );
      assert_eq!(rig.fs.spawns(), 2, "the tainted widen re-spawned");
      settle(|| rig.fs.shutdowns() == 1).await;
      // "/r" armed twice, strictly ordered: the released PRE-ARM gates the
      // fallback (its outcome is what the tainted commit refuses), so the
      // first "/r" arm is the reserved descriptor and the second is the
      // fallback's own root arm on the fresh transport.
      let r_arms: Vec<WatchId> = rig
        .fs
        .arms()
        .iter()
        .filter(|(_, path)| path == std::path::Path::new("/r"))
        .map(|(watch, _)| *watch)
        .collect();
      assert!(
        r_arms.len() >= 2,
        "pre-arm then fallback root arm: {r_arms:?}"
      );
      settle(|| rig.fs.disarms().contains(&r_arms[0])).await;
      assert!(
        rig.fs.disarms().contains(&r_arms[0]),
        "the pre-armed descriptor is disarmed on the tainted path (OQ5): {:?} not in {:?}",
        r_arms[0],
        rig.fs.disarms()
      );

      // The D1 bridge dominates the fallback window: a covering Rescan
      // reaches the consumer under the widened root.
      loop {
        let (s, root, change) = next_rooted(&rig).await;
        if s == scope && root.as_path() == std::path::Path::new("/r") && change.kind().is_rescan() {
          break;
        }
      }
    }

    /// A widen rig whose registry publications are observable — the Golden-2
    /// cells read which root each publish named.
    fn inotify_rig_registry(registry: impl ScopeRegistry) -> Rig {
      let fs = FakeFs::new(1);
      fs.put("/r", FileKind::Dir, 1);
      fs.spawn_backend(BackendKind::Inotify);
      let (cmd_tx, cmd_rx) = async_channel::bounded(16);
      let (cleanup, cookie_wake) = cookie_ingress();
      let (ev_tx, ev_rx) = async_channel::bounded(64);
      tokio::spawn(run::<TokioRuntime, FakeFs>(
        inotify_config(),
        fs.clone(),
        cmd_rx,
        cookie_wake,
        ev_tx,
        registry,
      ));
      Rig {
        fs,
        commands: cmd_tx,
        cleanup,
        events: ev_rx,
      }
    }

    /// The last root the registry published for `scope`, if any.
    fn last_published(registry: &RecordingRegistry, scope: ScopeId) -> Option<PathBuf> {
      registry
        .live()
        .into_iter()
        .filter(|(s, _, _)| *s == scope)
        .map(|(_, root, _)| root)
        .next_back()
    }

    /// The two INV-ROOT funnels, at the core gate: a reserved-root death
    /// record and a transport `Overflow` each taint the witnessed window when
    /// the source arm ingests them ([`apply_source_message`], the shared body
    /// the catch-up runs one message per loop iteration) BEFORE the commit gate
    /// reads. The record leg reads TAINTED `RootDeath`, the loss leg `Loss` —
    /// never a stale clean verdict. End to end this is the catch-up phase (the
    /// arm processes the prefix, then [`resolve_widen_catchups`] reads the
    /// tainted window and falls back); see
    /// `a_loss_queued_at_widen_ready_orders_behind_the_commit_cut`.
    #[test]
    fn a_queued_loss_taints_the_widen_commit_gate() {
      use crate::{
        core::{TaintCause, WidenCommit, WidenTaint},
        os::transport::{TransportState, forward_batch},
      };
      use tributary_proto::RecordKind;

      fn live_core_at(root: &str) -> (DriverCore, ScopeId) {
        let mut core = DriverCore::new(Duration::from_millis(100), Duration::ZERO);
        let scope = core
          .on_watch(
            PathBuf::from(root),
            tributary_proto::Interest::all(),
            BackendKind::Inotify,
          )
          .expect("a fresh scope registers");
        while core.poll_effect().is_some() {}
        core.on_stream_spawned(
          scope,
          Ok(RootMeta {
            root: PathBuf::from(root),
            root_dev: 1,
            root_mnt_id: None,
            mounts: Vec::new(),
            declined: Vec::new(),
            identity: crate::os::RootIdentity::new(1, 1),
            ancestors: Vec::new(),
            backend: BackendKind::Inotify,
          }),
        );
        let root_watch = loop {
          match core.poll_effect() {
            Some(crate::core::Effect::AddWatch { watch, parent, .. }) if watch == parent => {
              break watch;
            }
            Some(_) => continue,
            None => panic!("the descending root arms"),
          }
        };
        core.on_watch_installed(
          root_watch,
          core.arm_attempt(root_watch),
          WatchOutcome::Installed(1),
        );
        while core.poll_effect().is_some() {}
        (core, scope)
      }
      fn widen_meta(root: &str) -> RootMeta {
        RootMeta {
          root: PathBuf::from(root),
          root_dev: 1,
          root_mnt_id: None,
          mounts: Vec::new(),
          declined: Vec::new(),
          identity: crate::os::RootIdentity::new(1, 9),
          ancestors: Vec::new(),
          backend: BackendKind::Inotify,
        }
      }
      let at = || tributary_proto::Instant::from_origin(Duration::from_millis(5));

      // Leg A — a reserved-root DEATH RECORD, ingested by the arm's own body.
      let (mut core, scope) = live_core_at("/r/sub");
      let reserved = core.reserve_watch_id();
      core.begin_widen_watch(scope, reserved);
      crate::driver::apply_source_message(
        &mut core,
        scope,
        crate::os::SourceMessage::Batch(crate::os::BatchPayload::detached(vec![
          crate::os::SourceEvent::Linux(RawLinuxEvent::Inotify {
            anchors: vec![reserved],
            event: RawInotifyEvent {
              wd: 7,
              mask: InotifyMask(0x0000_8000), // IN_IGNORED
              cookie: 0,
              name: None,
            },
          }),
        ])),
        &at,
      );
      assert_eq!(
        core.on_root_widened(scope, widen_meta("/r"), reserved, at()),
        WidenCommit::TaintedWindow(WidenTaint {
          cause: TaintCause::RootDeath(RecordKind::Ignored),
          benign: 0,
        }),
        "a reserved death record taints before the commit gate reads"
      );

      // Leg B — a transport OVERFLOW (a real election, ack and all).
      let (mut core, scope) = live_core_at("/q/sub");
      let reserved = core.reserve_watch_id();
      core.begin_widen_watch(scope, reserved);
      let transport = TransportState::new(4);
      let mut minted = Vec::new();
      forward_batch::<crate::os::SourceEvent, _>(&transport, Vec::new(), true, |msg| {
        minted.push(msg);
        true
      });
      let overflow = minted
        .pop()
        .expect("a lossy empty batch elects an Overflow");
      assert!(matches!(overflow, crate::os::SourceMessage::Overflow(_)));
      crate::driver::apply_source_message(&mut core, scope, overflow, &at);
      assert_eq!(
        core.on_root_widened(scope, widen_meta("/q"), reserved, at()),
        WidenCommit::TaintedWindow(WidenTaint {
          cause: TaintCause::Loss,
          benign: 0,
        }),
        "a transport Overflow taints before the commit gate reads"
      );
    }

    /// The queued-loss race end to end, DETERMINISTIC: the loss and the
    /// widen-ready completion are BOTH queued when the (single-threaded,
    /// test-starved) driver loop next runs, so `select_biased!` provably
    /// services `WidenArmed` with the `Overflow` still unprocessed on the
    /// source lane. Under the catch-up phase the loss is simply IN THE PREFIX:
    /// `WidenArmed` snapshots it into `remaining`, the source arm taints the
    /// window through the loss funnel, and the commit — resolving only once the
    /// prefix is consumed — reads TAINTED and falls back to the stream replace,
    /// never committing over the unwitnessed loss.
    #[tokio::test]
    async fn a_loss_queued_at_widen_ready_orders_behind_the_commit_cut() {
      let rig = inotify_rig();
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 3);
      let scope = watch(&rig, "/r/sub").await;
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      let hold = rig.fs.hold_prearms();
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: PathBuf::from("/r"),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
          reply,
        })
        .await
        .unwrap();
      settle(|| rig.fs.prearm_entries() == 1).await;

      // SYNCHRONOUS section: this test owns the runtime's ONLY thread, so
      // the driver loop cannot run until the next await. Queue the loss,
      // release the pre-arm, and wait (blocking) for the pool thread to run
      // the post-arm bracket — after the probe only the WidenArmed
      // `try_send` remains, and the stall gives it ample time to land. Both
      // messages are then queued before the loop ever wakes.
      rig.fs.send_lossy("/r/sub");
      let probes_before = rig.fs.probes();
      hold.release();
      for _ in 0..5_000 {
        if rig.fs.probes() > probes_before {
          break;
        }
        std::thread::sleep(Duration::from_millis(1));
      }
      assert!(rig.fs.probes() > probes_before, "the bracket probe ran");
      std::thread::sleep(Duration::from_millis(50));

      // First await: the loop wakes with BOTH ready; the op arm wins the
      // biased select and snapshots the loss into `remaining`; the source arm
      // taints the window before the catch-up commit reads it.
      let resolved = tokio::time::timeout(interpreted_secs(10), on_reply)
        .await
        .expect("the fallback replace resolves the caller")
        .expect("the driver replies");
      assert!(
        resolved.is_ok(),
        "the fallback commit answers Ok: {resolved:?}"
      );
      assert_eq!(
        rig.fs.spawns(),
        2,
        "the queued loss tainted the window: the widen fell back, never committed"
      );
      settle(|| rig.fs.shutdowns() == 1).await;
    }

    /// Golden-2, the held-fallback interim: a tainted widen's D1 fallback is
    /// dispatched but its spawn is HELD — the registry must keep naming the
    /// OLD root (the live truth) through the whole interim, and adopt the
    /// widened root only when the fallback COMMITS.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_tainted_fallback_keeps_the_registry_on_the_old_root_until_its_commit() {
      let registry = RecordingRegistry::default();
      let rig = inotify_rig_registry(registry.clone());
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 3);
      let scope = watch(&rig, "/r/sub").await;
      fence_birth_crawl(&rig, scope, "/r/sub").await;
      assert_eq!(
        last_published(&registry, scope),
        Some(PathBuf::from("/r/sub")),
        "birth published the old root"
      );

      let spawns_hold = rig.fs.hold_spawns();
      let prearm_hold = rig.fs.hold_prearms();
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: PathBuf::from("/r"),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
          reply,
        })
        .await
        .unwrap();
      assert!(
        settle(|| rig.fs.prearm_entries() == 1).await,
        "staging: the pre-arm must be parked, or the loss below lands outside the witnessed window"
      );
      rig.fs.send_lossy("/r/sub");
      assert!(
        settle(|| !rig.fs.overflow_pending("/r/sub")).await,
        "staging: the elected loss must be ingested, or the window is never tainted"
      );
      prearm_hold.release();

      // The tainted fallback's spawn is dispatched (its resume point records
      // before the hold parks it): the widened root must NOT be published.
      assert!(
        settle(|| rig.fs.spawn_resume_points().len() == 2).await,
        "staging: the tainted fallback's spawn must be dispatched before the registry is read"
      );
      assert_eq!(
        last_published(&registry, scope),
        Some(PathBuf::from("/r/sub")),
        "the tainted interim never publishes the widened root"
      );

      spawns_hold.release();
      let resolved = tokio::time::timeout(interpreted_secs(10), on_reply)
        .await
        .expect("the fallback resolves")
        .expect("the driver replies");
      assert!(resolved.is_ok(), "{resolved:?}");
      settle(|| last_published(&registry, scope) == Some(PathBuf::from("/r"))).await;
    }

    /// Golden-2, the failure exit: the tainted fallback's D1 spawn FAILS —
    /// the caller gets the error, the registry still names the OLD root, and
    /// the old stream's coverage keeps delivering (atomic-on-failure: the
    /// entry always names the root that is actually covered).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_tainted_fallback_keeps_the_registry_on_the_old_root() {
      let registry = RecordingRegistry::default();
      let rig = inotify_rig_registry(registry.clone());
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 3);
      let scope = watch(&rig, "/r/sub").await;
      let sub_watch = rig
        .fs
        .arms()
        .first()
        .cloned()
        .expect("the birth root arm")
        .0;
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      let spawns_hold = rig.fs.hold_spawns();
      let prearm_hold = rig.fs.hold_prearms();
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: PathBuf::from("/r"),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
          reply,
        })
        .await
        .unwrap();
      assert!(
        settle(|| rig.fs.prearm_entries() == 1).await,
        "staging: the pre-arm must be parked, or the loss below lands outside the witnessed window"
      );
      rig.fs.send_lossy("/r/sub");
      assert!(
        settle(|| !rig.fs.overflow_pending("/r/sub")).await,
        "staging: the elected loss must be ingested, or the window is never tainted"
      );
      prearm_hold.release();
      assert!(
        settle(|| rig.fs.spawn_resume_points().len() == 2).await,
        "staging: the tainted fallback's spawn must be dispatched before its root is removed"
      );

      // The widened root vanishes while the fallback spawn is parked: the
      // released spawn fails, the replace surfaces the error — and the
      // registry never adopted a root nobody covers.
      rig.fs.remove("/r");
      spawns_hold.release();
      let resolved = tokio::time::timeout(interpreted_secs(10), on_reply)
        .await
        .expect("the failed fallback resolves")
        .expect("the driver replies");
      assert!(
        matches!(resolved, Err(crate::error::ReplaceRootError::Source(_))),
        "the fallback spawn failure surfaces typed: {resolved:?}"
      );
      assert_eq!(
        last_published(&registry, scope),
        Some(PathBuf::from("/r/sub")),
        "the registry still names the root that is actually covered"
      );

      // The old coverage never blinked: the surviving stream still delivers.
      rig.fs.send_inotify_batch(
        "/r/sub",
        vec![attributed(&[sub_watch], IN_CREATE, b"still-alive.txt")],
      );
      loop {
        let (s, root, change) = next_rooted(&rig).await;
        if s == scope
          && root.as_path() == std::path::Path::new("/r/sub")
          && change.location() == &loc(&["still-alive.txt"])
        {
          break;
        }
      }
    }

    /// G2-1: a lane whose source DIED (sender dropped, end marker still
    /// unprocessed) is never a clean widen window. Deterministic via the
    /// starved current-thread runtime: the disconnect and the widen-ready
    /// completion are both pending when the loop wakes, the biased select
    /// services `WidenArmed` first (parking the catch-up), and the closed lane
    /// keeps the commit WAITING (`resolve_widen_catchups`) while the source
    /// arm's end-marker path routes `on_source_fatal` — so the liveness gate
    /// answers `Retired`, publishes nothing, and spawns nothing.
    #[tokio::test]
    async fn a_disconnected_lane_retires_the_widen_before_the_commit() {
      let registry = RecordingRegistry::default();
      let rig = inotify_rig_registry(registry.clone());
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 3);
      let scope = watch(&rig, "/r/sub").await;
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      let hold = rig.fs.hold_prearms();
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: PathBuf::from("/r"),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
          reply,
        })
        .await
        .unwrap();
      settle(|| rig.fs.prearm_entries() == 1).await;

      // SYNCHRONOUS section (single-threaded runtime, loop starved): the
      // source dies, then the pre-arm releases; only after the bracket probe
      // and a generous stall does the test yield — the loop wakes with the
      // dead lane's end marker and `WidenArmed` BOTH pending, and op-bias
      // services the completion first (parking the catch-up).
      rig.fs.disconnect("/r/sub");
      let probes_before = rig.fs.probes();
      hold.release();
      for _ in 0..5_000 {
        if rig.fs.probes() > probes_before {
          break;
        }
        std::thread::sleep(Duration::from_millis(1));
      }
      assert!(rig.fs.probes() > probes_before, "the bracket probe ran");
      std::thread::sleep(Duration::from_millis(50));

      let resolved = tokio::time::timeout(interpreted_secs(10), on_reply)
        .await
        .expect("the dead-lane widen resolves")
        .expect("the driver replies");
      assert!(
        matches!(resolved, Err(crate::error::ReplaceRootError::Retired)),
        "a dead transport retires the widen, never commits over it: {resolved:?}"
      );
      assert_eq!(
        last_published(&registry, scope),
        Some(PathBuf::from("/r/sub")),
        "the widened root is never published over a dead lane"
      );
      assert_eq!(
        rig.fs.spawns(),
        1,
        "no fallback: the scope died, nothing re-spawns"
      );
      // The death is honest: the terminal Rescan reaches the consumer.
      loop {
        let (s, _root, change) = next_rooted(&rig).await;
        if s == scope && change.kind().is_rescan() {
          break;
        }
      }
    }

    /// G2-2 under real load: the catch-up commit does BOUNDED work when a
    /// producer refills the (unbounded) lane as fast as the source arm drains
    /// it — the commit waits only for the `remaining` snapshot (post-snapshot
    /// arrivals ride the post-commit regime), never "until the flood pauses".
    /// A continuously-flooding source must not starve the widen reply (nor
    /// commands behind it): the replace resolves PROMPTLY whatever verdict the
    /// flood forced (a budget-refused batch degrades to a loss, which legally
    /// taints the window into the D1 fallback — promptness, not the verdict, is
    /// the pin). The exact `remaining` count-down is pinned deterministically by
    /// `a_catch_up_delivers_its_prefix_at_the_old_root_then_flips`; this cell
    /// catches gross liveness regressions the timing there cannot.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_hot_lane_widen_catches_up_bounded_and_replies_promptly() {
      let rig = inotify_rig();
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 3);
      let scope = watch(&rig, "/r/sub").await;
      let sub_watch = rig
        .fs
        .arms()
        .first()
        .cloned()
        .expect("the birth root arm")
        .0;
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      let hold = rig.fs.hold_prearms();
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: PathBuf::from("/r"),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
          reply,
        })
        .await
        .unwrap();
      assert!(
        settle(|| rig.fs.prearm_entries() == 1).await,
        "staging: the pre-arm must be parked, or the flood below runs outside the commit window"
      );

      // The flood: THREE dedicated OS threads refill the lane at full tilt
      // (no yields) for the whole commit window — benign records on the
      // KNOWN old watch, so only the catch-up bound is under test.
      let stop = std::sync::Arc::new(AtomicBool::new(false));
      let fillers: Vec<_> = (0..3)
        .map(|_| {
          let fs = rig.fs.clone();
          let stop = std::sync::Arc::clone(&stop);
          std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
              fs.send_inotify_batch(
                "/r/sub",
                vec![attributed(&[sub_watch], IN_CREATE, b"flood.txt")],
              );
            }
          })
        })
        .collect();
      let flood = Flood { stop, fillers };
      hold.release();

      // The pin: the reply is PROMPT — the catch-up waited on a finite prefix
      // snapshot, not "until the flood pauses".
      let resolved = tokio::time::timeout(interpreted_secs(10), on_reply)
        .await
        .expect("a hot lane must not starve the widen reply")
        .expect("the driver replies");
      assert!(
        resolved.is_ok(),
        "the widen resolves under load: {resolved:?}"
      );
      flood.stop_and_join();
    }

    /// The catch-up ingests the prefix through [`apply_source_message`] — the
    /// same body the source arm runs, one message at a time — so a reserved
    /// death record LAST behind three benign records still taints the window
    /// (the prefix is never partial), and a source DEATH tears the scope down
    /// core-side (root watch gone, stream teardown enqueued), so a catch-up
    /// over a dead lane can only answer `Retired`, never commit over it. The
    /// `remaining` snapshot/decrement that bounds the catch-up is pinned
    /// separately (`catch_up_remaining_counts_the_prefix_and_saturates` and the
    /// starved `the_catch_up_delivers_the_whole_prefix_before_the_commit`).
    #[test]
    fn a_death_behind_benign_records_taints_and_a_source_death_retires() {
      use crate::core::{TaintCause, WidenCommit, WidenTaint};
      use tributary_proto::RecordKind;

      fn unit_core_at(root: &str) -> (DriverCore, ScopeId, tributary_proto::WatchId) {
        let mut core = DriverCore::new(Duration::from_millis(100), Duration::ZERO);
        let scope = core
          .on_watch(
            PathBuf::from(root),
            tributary_proto::Interest::all(),
            BackendKind::Inotify,
          )
          .expect("a fresh scope registers");
        while core.poll_effect().is_some() {}
        core.on_stream_spawned(
          scope,
          Ok(RootMeta {
            root: PathBuf::from(root),
            root_dev: 1,
            root_mnt_id: None,
            mounts: Vec::new(),
            declined: Vec::new(),
            identity: crate::os::RootIdentity::new(1, 1),
            ancestors: Vec::new(),
            backend: BackendKind::Inotify,
          }),
        );
        let root_watch = loop {
          match core.poll_effect() {
            Some(crate::core::Effect::AddWatch { watch, parent, .. }) if watch == parent => {
              break watch;
            }
            Some(_) => continue,
            None => panic!("the descending root arms"),
          }
        };
        core.on_watch_installed(
          root_watch,
          core.arm_attempt(root_watch),
          WatchOutcome::Installed(1),
        );
        while core.poll_effect().is_some() {}
        (core, scope, root_watch)
      }
      fn benign(watch: tributary_proto::WatchId, name: &[u8]) -> crate::os::SourceMessage {
        crate::os::SourceMessage::Batch(crate::os::BatchPayload::detached(vec![
          crate::os::SourceEvent::Linux(attributed(&[watch], IN_CREATE, name)),
        ]))
      }
      fn reserved_death(reserved: tributary_proto::WatchId, mask: u32) -> crate::os::SourceMessage {
        crate::os::SourceMessage::Batch(crate::os::BatchPayload::detached(vec![
          crate::os::SourceEvent::Linux(RawLinuxEvent::Inotify {
            anchors: vec![reserved],
            event: RawInotifyEvent {
              wd: 7,
              mask: InotifyMask(mask),
              cookie: 0,
              name: None,
            },
          }),
        ]))
      }
      let at = || tributary_proto::Instant::from_origin(Duration::from_millis(5));

      // Leg 1 — the death record LAST behind three benign records still
      // taints: the catch-up processes the WHOLE prefix (never a partial one).
      let (mut core, scope, root_watch) = unit_core_at("/r/sub");
      let reserved = core.reserve_watch_id();
      core.begin_widen_watch(scope, reserved);
      for name in [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()] {
        crate::driver::apply_source_message(&mut core, scope, benign(root_watch, name), &at);
      }
      crate::driver::apply_source_message(
        &mut core,
        scope,
        reserved_death(reserved, 0x0000_8000), // IN_IGNORED
        &at,
      );
      assert_eq!(
        core.on_root_widened(
          scope,
          RootMeta {
            root: PathBuf::from("/r"),
            root_dev: 1,
            root_mnt_id: None,
            mounts: Vec::new(),
            declined: Vec::new(),
            identity: crate::os::RootIdentity::new(1, 9),
            ancestors: Vec::new(),
            backend: BackendKind::Inotify,
          },
          reserved,
          at(),
        ),
        WidenCommit::TaintedWindow(WidenTaint {
          cause: TaintCause::RootDeath(RecordKind::Ignored),
          benign: 0,
        }),
        "the LAST prefix message still taints — the prefix is never partial"
      );

      // Leg 2 — a source DEATH: the reserved MoveSelf taints the window but
      // does NOT tear the scope down; the lane then closes with its end marker
      // and the source arm's `None` path routes the fatal — the scope's core
      // state is gone BEFORE any commit gate could read a window, so the
      // catch-up can only answer `Retired`.
      let (mut core, scope, root_watch) = unit_core_at("/q/sub");
      let reserved = core.reserve_watch_id();
      core.begin_widen_watch(scope, reserved);
      crate::driver::apply_source_message(&mut core, scope, benign(root_watch, b"pre-death"), &at);
      crate::driver::apply_source_message(
        &mut core,
        scope,
        reserved_death(reserved, 0x0000_0800), // IN_MOVE_SELF
        &at,
      );
      assert!(
        core.root_watch(scope).is_some(),
        "a reserved move-self taints but does not tear the scope down"
      );
      core.on_source_fatal(scope, at());
      assert!(
        core.root_watch(scope).is_none(),
        "the source death tore the scope down before any gate could read"
      );
      let mut torn_down = false;
      while let Some(effect) = core.poll_effect() {
        torn_down |=
          matches!(effect, crate::core::Effect::TeardownStream { scope: s } if s == scope);
      }
      assert!(
        torn_down,
        "the death funnel tears the dead scope's stream down"
      );
    }

    /// R5 regression — the per-scope CONTROL QUEUE must not leak state for a
    /// scope torn down in the SAME effect drain that also carried a control op
    /// for it. The finding: an `AddWatch`/`RemoveWatch` collected for a scope
    /// BEFORE its `TeardownStream` — one decoded inotify batch losing a child
    /// binding (`IN_IGNORED`) then killing the root (`IN_DELETE_SELF`) — left
    /// the post-drain dispatch re-marking the now-dead scope in-flight (and
    /// queuing its stale batch), state nothing ever reclaims (scope ids are
    /// never reused). The maps then grew unbounded under repeated root churn
    /// until driver shutdown.
    ///
    /// The cell drives the REAL core to that exact queued shape — one drain
    /// whose effects carry a LIVE scope's arm AND a DEAD scope's disarm-then-
    /// teardown (the empirical order the core emits: `RemoveWatch(dead)` sits
    /// immediately ahead of `TeardownStream(dead)`) — then runs the PRODUCTION
    /// [`execute_effects`] over it and pins the no-residual invariant: after a
    /// drain that tore a scope down, NEITHER `pending_control` nor
    /// `control_inflight` holds an entry for it, while the LIVE scope's batch is
    /// dispatched (in-flight), not dropped.
    ///
    /// Mutation witness: drop the post-drain `torn_down` skip and the dead
    /// scope's stale disarm batch re-marks it in-flight — the
    /// `!control_inflight.contains(dead)` assertion fails with a residual entry.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_control_op_and_teardown_in_one_drain_leaks_no_chain_tail() {
      const IN_CREATE: u32 = 0x0000_0100;
      const IN_ISDIR: u32 = 0x4000_0000;
      const IN_DELETE_SELF: u32 = 0x0000_0400;
      const IN_IGNORED: u32 = 0x0000_8000;

      // A live core with `root` spawned and its self-parented root watch armed.
      fn spawn_root(
        core: &mut DriverCore,
        root: &str,
        ino: u128,
      ) -> (ScopeId, tributary_proto::WatchId) {
        let scope = core
          .on_watch(
            PathBuf::from(root),
            tributary_proto::Interest::all(),
            BackendKind::Inotify,
          )
          .expect("a fresh scope registers");
        while core.poll_effect().is_some() {}
        core.on_stream_spawned(
          scope,
          Ok(RootMeta {
            root: PathBuf::from(root),
            root_dev: 1,
            root_mnt_id: None,
            mounts: Vec::new(),
            declined: Vec::new(),
            identity: crate::os::RootIdentity::new(1, ino),
            ancestors: Vec::new(),
            backend: BackendKind::Inotify,
          }),
        );
        let root_watch = loop {
          match core.poll_effect() {
            Some(crate::core::Effect::AddWatch { watch, parent, .. }) if watch == parent => {
              break watch;
            }
            Some(_) => continue,
            None => panic!("the descending root arms"),
          }
        };
        core.on_watch_installed(
          root_watch,
          core.arm_attempt(root_watch),
          WatchOutcome::Installed(1),
        );
        while core.poll_effect().is_some() {}
        (scope, root_watch)
      }
      fn batch(events: Vec<RawLinuxEvent>) -> crate::os::SourceMessage {
        crate::os::SourceMessage::Batch(crate::os::BatchPayload::detached(
          events
            .into_iter()
            .map(crate::os::SourceEvent::Linux)
            .collect(),
        ))
      }
      let at = || Instant::from_origin(Duration::from_millis(5));

      let mut core = DriverCore::new(Duration::from_millis(100), Duration::ZERO);
      // The scope that dies in the drain: root plus one armed child, so a lost
      // child binding mints a real `RemoveWatch` ahead of the root death.
      let (dead, dead_root) = spawn_root(&mut core, "/r", 1);
      crate::driver::apply_source_message(
        &mut core,
        dead,
        batch(vec![attributed(&[dead_root], IN_CREATE | IN_ISDIR, b"sub")]),
        &at,
      );
      let dead_child = loop {
        match core.poll_effect() {
          Some(crate::core::Effect::AddWatch { watch, parent, .. }) if parent == dead_root => {
            break watch;
          }
          Some(_) => continue,
          None => panic!("the created child arms"),
        }
      };
      core.on_watch_installed(
        dead_child,
        core.arm_attempt(dead_child),
        WatchOutcome::Installed(2),
      );
      while core.poll_effect().is_some() {}
      // The scope that stays live through the drain: root armed, ready to arm a
      // child (its own control op) with no death.
      let (live, live_root) = spawn_root(&mut core, "/q", 5);

      // ONE drain's worth of effects, accumulated WITHOUT draining: the core
      // pushes to its effect queue but only `poll_effect` (which `execute_effects`
      // owns) drains it, so both scopes' effects coexist in the single flush.
      //
      // Live scope: a directory create arms a child — an `AddWatch(live)`, a
      // control op with no teardown.
      crate::driver::apply_source_message(
        &mut core,
        live,
        batch(vec![attributed(
          &[live_root],
          IN_CREATE | IN_ISDIR,
          b"keep",
        )]),
        &at,
      );
      // Dead scope: the child binding is lost (`IN_IGNORED`) and THEN the root
      // dies (`IN_DELETE_SELF`) — `RemoveWatch(dead)` queued immediately ahead of
      // `TeardownStream(dead)`, the finding's exact same-drain shape.
      crate::driver::apply_source_message(
        &mut core,
        dead,
        batch(vec![
          RawLinuxEvent::Inotify {
            anchors: vec![dead_child],
            event: RawInotifyEvent {
              wd: 2,
              mask: InotifyMask(IN_IGNORED),
              cookie: 0,
              name: None,
            },
          },
          attributed(&[dead_root], IN_DELETE_SELF, b""),
        ]),
        &at,
      );

      // Run the PRODUCTION drain over that queue with a minimal live-loop state.
      let fs = FakeFs::new(1);
      let (op_tx, _op_rx) = async_channel::unbounded::<OpResult<FakeHandle>>();
      let (events_tx, _events_rx) = async_channel::unbounded::<(ScopeId, Arc<PathBuf>, Change)>();
      let (_ingress, wake) = crate::driver::cookie_ingress();
      let mut cookies = CookieRegistry::new::<TokioRuntime>(fs.clone(), wake.ledger);
      let mut handles: BTreeMap<ScopeId, FakeHandle> = BTreeMap::new();
      let mut pending_spawns: BTreeSet<ScopeId> = BTreeSet::new();
      let mut pending_teardowns: BTreeMap<ScopeId, usize> = BTreeMap::new();
      let mut scope_backends: BTreeMap<ScopeId, BackendKind> = BTreeMap::new();
      // Both scopes hold a live lane; the dead scope's is reclaimed at teardown.
      let mut lanes: BTreeMap<ScopeId, u64> = BTreeMap::from([(dead, 0u64), (live, 1u64)]);
      let mut source_taps: BTreeMap<ScopeId, EventReceiver> = BTreeMap::new();
      let mut unwatch_replies: BTreeMap<
        ScopeId,
        Vec<(
          futures_channel::oneshot::Sender<crate::driver::UnwatchAck>,
          crate::driver::UnwatchAck,
        )>,
      > = BTreeMap::new();
      let mut deferred_grants: BTreeMap<ScopeId, DeferredGrant> = BTreeMap::new();
      let mut pending_control: crate::driver::PendingControl = BTreeMap::new();
      let mut control_inflight: crate::driver::ControlInflight = BTreeMap::new();
      let registry = NullRegistry;
      let now = || Instant::from_origin(Duration::from_millis(5));
      let reaper = crate::driver::TeardownReaper::new().expect("the reaper secures its thread");

      crate::driver::execute_effects::<TokioRuntime, FakeFs>(
        &mut core,
        &fs,
        &config(),
        &op_tx,
        &reaper,
        &mut handles,
        &mut pending_spawns,
        &mut pending_teardowns,
        &mut scope_backends,
        &mut lanes,
        &mut source_taps,
        &events_tx,
        &mut unwatch_replies,
        &mut deferred_grants,
        &mut pending_control,
        &mut control_inflight,
        &mut cookies,
        &registry,
        &now,
      );

      assert!(
        !control_inflight.contains_key(&dead) && !pending_control.contains_key(&dead),
        "a scope torn down in the drain leaves NO control-queue state; \
         in-flight: {:?}, queued: {:?}",
        control_inflight,
        pending_control.keys().collect::<Vec<_>>()
      );
      assert_eq!(
        control_inflight.get(&live).copied(),
        lanes.get(&live).copied(),
        "a scope that stayed live has its freshly collected batch DISPATCHED \
         (in-flight) under its CURRENT lane, not dropped"
      );
    }

    /// The catch-up's boundedness is `remaining`: the queued-length snapshot
    /// taken at `WidenArmed`, counted down one per loop iteration by the source
    /// arm until the commit fires (G2-2). This unit-pins the two arithmetic
    /// pieces — the snapshot reads the lane's queued length
    /// (`EventReceiver::len`), and the decrement SATURATES so a post-snapshot
    /// arrival (transport-concurrent with the commit) never underflows the
    /// wait.
    ///
    /// Scope, stated honestly: the live `remaining` lives in the run loop's
    /// own `replace_states`, so no test (and no test-only accessor) can read
    /// the running loop's copy — this cell pins the PHASE FIELD's semantics
    /// against the same expressions production uses, and the behavioural
    /// count-down (snapshot N, N deliveries, then the commit) is pinned end to
    /// end by `a_catch_up_delivers_its_prefix_at_the_old_root_then_flips`.
    #[test]
    fn catch_up_remaining_counts_the_prefix_and_saturates() {
      // (a) The snapshot source: `WidenArmed` reads the lane's queued length,
      // so a three-message prefix snapshots `remaining == 3`.
      let (tx, rx) = async_channel::unbounded::<crate::os::SourceMessage>();
      for _ in 0..3 {
        tx.try_send(crate::os::SourceMessage::Batch(
          crate::os::BatchPayload::detached(Vec::new()),
        ))
        .unwrap();
      }
      assert_eq!(rx.len(), 3, "the snapshot reads the queued prefix length");

      // (b) The decrement: one prefix message consumed per iteration, saturating.
      let mut core = DriverCore::new(Duration::from_millis(100), Duration::ZERO);
      let reserved = core.reserve_watch_id();
      let mut phase = crate::driver::SameFdPhase::CatchUp {
        reserved,
        meta: RootMeta {
          root: PathBuf::from("/r"),
          root_dev: 1,
          root_mnt_id: None,
          mounts: Vec::new(),
          declined: Vec::new(),
          identity: crate::os::RootIdentity::new(1, 9),
          ancestors: Vec::new(),
          backend: BackendKind::Inotify,
        },
        replay: WatchOutcome::Installed(1),
        remaining: rx.len(),
      };
      for expected in [2usize, 1, 0] {
        if let crate::driver::SameFdPhase::CatchUp { remaining, .. } = &mut phase {
          *remaining = remaining.saturating_sub(1);
        }
        let crate::driver::SameFdPhase::CatchUp { remaining, .. } = &phase else {
          unreachable!("constructed CatchUp");
        };
        assert_eq!(*remaining, expected, "one prefix message consumed");
      }
      // A post-snapshot arrival: the decrement saturates, never underflows.
      if let crate::driver::SameFdPhase::CatchUp { remaining, .. } = &mut phase {
        *remaining = remaining.saturating_sub(1);
      }
      let crate::driver::SameFdPhase::CatchUp { remaining, .. } = &phase else {
        unreachable!("constructed CatchUp");
      };
      assert_eq!(
        *remaining, 0,
        "saturates: a post-snapshot arrival never underflows the commit's wait"
      );
    }

    /// The catch-up commit is BOUNDED by `remaining` AND never straddles the
    /// root flip (G2-2 + G3-1), deterministic on the starved current-thread
    /// runtime: THREE benign creates queued before `WidenArmed` are the prefix
    /// (`remaining == 3`); the source arm delivers each at the still-current
    /// OLD root — unprefixed and in order — and the commit fires only once the
    /// whole prefix is consumed, so the reply resolves AFTER the last old-root
    /// delivery. A create AFTER the commit delivers at the NEW root,
    /// chain-prefixed. Discriminates: were the prefix jumped (the pre-catch-up
    /// op-bias that processed lane messages at the commit), these creates would
    /// land at `/r` as `sub/xN`, or only after the reply.
    #[tokio::test]
    async fn a_catch_up_delivers_its_prefix_at_the_old_root_then_flips() {
      let registry = RecordingRegistry::default();
      let rig = inotify_rig_registry(registry.clone());
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 3);
      let scope = watch(&rig, "/r/sub").await;
      let sub_watch = rig
        .fs
        .arms()
        .first()
        .cloned()
        .expect("the birth root arm")
        .0;
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      let hold = rig.fs.hold_prearms();
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: PathBuf::from("/r"),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
          reply,
        })
        .await
        .unwrap();
      settle(|| rig.fs.prearm_entries() == 1).await;

      // SYNCHRONOUS section (single-threaded runtime, loop starved): THREE
      // benign creates queue on the live lane, then the pre-arm releases; only
      // after the bracket probe and a generous stall does the test yield, so
      // the loop wakes with the whole prefix AND `WidenArmed` pending. The op
      // arm snapshots `remaining == 3` and the source arm catches up first.
      for name in [b"x1".as_slice(), b"x2".as_slice(), b"x3".as_slice()] {
        rig
          .fs
          .send_inotify_batch("/r/sub", vec![attributed(&[sub_watch], IN_CREATE, name)]);
      }
      let probes_before = rig.fs.probes();
      hold.release();
      for _ in 0..5_000 {
        if rig.fs.probes() > probes_before {
          break;
        }
        std::thread::sleep(Duration::from_millis(1));
      }
      assert!(rig.fs.probes() > probes_before, "the bracket probe ran");
      std::thread::sleep(Duration::from_millis(50));

      // The whole prefix delivers at the OLD root, in order, before the flip.
      for name in ["x1", "x2", "x3"] {
        let (s, root, change) = next_rooted(&rig).await;
        assert_eq!(
          (s, root.as_path()),
          (scope, std::path::Path::new("/r/sub")),
          "a pre-commit create delivers at the old root: {change:?}"
        );
        assert!(change.kind().is_created(), "{change:?}");
        assert_eq!(
          change.location(),
          &loc(&[name]),
          "unprefixed old-root coordinates"
        );
      }

      // The commit fired only after the whole prefix — the reply resolves now.
      let resolved = tokio::time::timeout(interpreted_secs(10), on_reply)
        .await
        .expect("the catch-up commit resolves the caller")
        .expect("the driver replies");
      assert!(resolved.is_ok(), "the clean catch-up commits: {resolved:?}");
      assert_eq!(rig.fs.spawns(), 1, "the widen kept the one stream");
      settle(|| last_published(&registry, scope) == Some(PathBuf::from("/r"))).await;

      // A create AFTER the commit delivers at the NEW root, chain-prefixed.
      rig
        .fs
        .send_inotify_batch("/r/sub", vec![attributed(&[sub_watch], IN_CREATE, b"y")]);
      loop {
        let (s, root, change) = next_rooted(&rig).await;
        if s == scope
          && root.as_path() == std::path::Path::new("/r")
          && change.location() == &loc(&["sub", "y"])
        {
          break;
        }
      }
    }

    /// G3-1 for a `Moved`, whose delivered `ChangeKind::Moved(Location)`
    /// carries an old-root-relative SOURCE as well as its destination: a
    /// same-batch rename pair queued before `WidenArmed` is caught up and
    /// delivered at the OLD root with BOTH coordinates unprefixed, before the
    /// flip; a rename AFTER the commit delivers both under the NEW root,
    /// chain-prefixed. Neither half straddles.
    #[tokio::test]
    async fn a_move_queued_before_the_widen_delivers_at_the_old_root() {
      fn move_pair(watch: WatchId, cookie: u32, from: &[u8], to: &[u8]) -> Vec<RawLinuxEvent> {
        const IN_MOVED_FROM: u32 = 0x0000_0040;
        const IN_MOVED_TO: u32 = 0x0000_0080;
        vec![
          RawLinuxEvent::Inotify {
            anchors: vec![watch],
            event: RawInotifyEvent {
              wd: 1,
              mask: InotifyMask(IN_MOVED_FROM),
              cookie,
              name: Some(from.to_vec()),
            },
          },
          RawLinuxEvent::Inotify {
            anchors: vec![watch],
            event: RawInotifyEvent {
              wd: 1,
              mask: InotifyMask(IN_MOVED_TO),
              cookie,
              name: Some(to.to_vec()),
            },
          },
        ]
      }

      let rig = inotify_rig();
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 3);
      let scope = watch(&rig, "/r/sub").await;
      let sub_watch = rig
        .fs
        .arms()
        .first()
        .cloned()
        .expect("the birth root arm")
        .0;
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      let hold = rig.fs.hold_prearms();
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: PathBuf::from("/r"),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
          reply,
        })
        .await
        .unwrap();
      settle(|| rig.fs.prearm_entries() == 1).await;

      // SYNCHRONOUS: a same-batch rename pair (ONE queued message) on the live
      // lane, then release. Its native cookie pairs the halves into a single
      // Moved the catch-up delivers at the old root before the flip.
      rig
        .fs
        .send_inotify_batch("/r/sub", move_pair(sub_watch, 7, b"from", b"to"));
      let probes_before = rig.fs.probes();
      hold.release();
      for _ in 0..5_000 {
        if rig.fs.probes() > probes_before {
          break;
        }
        std::thread::sleep(Duration::from_millis(1));
      }
      assert!(rig.fs.probes() > probes_before, "the bracket probe ran");
      std::thread::sleep(Duration::from_millis(50));

      // The Moved delivers at the OLD root, BOTH coordinates unprefixed.
      let (s, root, change) = next_rooted(&rig).await;
      assert_eq!(
        (s, root.as_path()),
        (scope, std::path::Path::new("/r/sub")),
        "old root before the flip: {change:?}"
      );
      assert_eq!(change.location(), &loc(&["to"]), "destination unprefixed");
      assert_eq!(
        change.kind().moved_from(),
        Some(&loc(&["from"])),
        "source unprefixed: {change:?}"
      );

      let resolved = tokio::time::timeout(interpreted_secs(10), on_reply)
        .await
        .expect("the catch-up commit resolves the caller")
        .expect("the driver replies");
      assert!(resolved.is_ok(), "the clean catch-up commits: {resolved:?}");

      // A rename AFTER the commit delivers both halves under the NEW root.
      rig
        .fs
        .send_inotify_batch("/r/sub", move_pair(sub_watch, 9, b"from2", b"to2"));
      loop {
        let (s, root, change) = next_rooted(&rig).await;
        if s == scope && change.kind().is_moved() && change.location() == &loc(&["sub", "to2"]) {
          assert_eq!(root.as_path(), std::path::Path::new("/r"));
          assert_eq!(
            change.kind().moved_from(),
            Some(&loc(&["sub", "from2"])),
            "post-commit source is chain-prefixed: {change:?}"
          );
          break;
        }
      }
    }

    /// The catch-up's death path: a scope that DIES mid-catch-up (the stream's
    /// terminal `Fatal` queued behind a benign prefix, so the death is IN the
    /// prefix) delivers the benign record at the old root, then the source
    /// arm routes the fatal through the ordinary funnel — the liveness gate in
    /// [`resolve_widen_catchups`] then answers `Retired`, publishes NO widened
    /// root (Golden-2's deferred publish), and the terminal Rescan reaches the
    /// consumer. No fallback: the scope died, nothing re-spawns. (The
    /// CLOSED-lane sibling — death with no queued marker — is
    /// `a_disconnected_lane_retires_the_widen_before_the_commit`.)
    #[tokio::test]
    async fn a_scope_death_mid_catch_up_retires_the_widen() {
      let registry = RecordingRegistry::default();
      let rig = inotify_rig_registry(registry.clone());
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 3);
      let scope = watch(&rig, "/r/sub").await;
      let sub_watch = rig
        .fs
        .arms()
        .first()
        .cloned()
        .expect("the birth root arm")
        .0;
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      let hold = rig.fs.hold_prearms();
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: PathBuf::from("/r"),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
          reply,
        })
        .await
        .unwrap();
      settle(|| rig.fs.prearm_entries() == 1).await;

      // SYNCHRONOUS: a benign prefix, THEN the stream's terminal Fatal, all
      // queued before the loop wakes — the scope dies WHILE the catch-up drains
      // the prefix (`remaining` started at 2).
      rig
        .fs
        .send_inotify_batch("/r/sub", vec![attributed(&[sub_watch], IN_CREATE, b"x")]);
      rig.fs.send_fatal("/r/sub");
      let probes_before = rig.fs.probes();
      hold.release();
      for _ in 0..5_000 {
        if rig.fs.probes() > probes_before {
          break;
        }
        std::thread::sleep(Duration::from_millis(1));
      }
      assert!(rig.fs.probes() > probes_before, "the bracket probe ran");
      std::thread::sleep(Duration::from_millis(50));

      // The prefix delivered at the old root before the death routed.
      let (s, root, change) = next_rooted(&rig).await;
      assert_eq!((s, root.as_path()), (scope, std::path::Path::new("/r/sub")));
      assert!(
        change.kind().is_created() && change.location() == &loc(&["x"]),
        "{change:?}"
      );

      let resolved = tokio::time::timeout(interpreted_secs(10), on_reply)
        .await
        .expect("the dead-scope widen resolves")
        .expect("the driver replies");
      assert!(
        matches!(resolved, Err(crate::error::ReplaceRootError::Retired)),
        "died mid-catch-up retires: {resolved:?}"
      );
      assert_eq!(
        rig.fs.spawns(),
        1,
        "no fallback: the scope died, nothing re-spawns"
      );
      assert_eq!(
        last_published(&registry, scope),
        Some(PathBuf::from("/r/sub")),
        "no widened publish over a dead scope"
      );

      // The death is honest: the terminal Rescan reaches the consumer.
      loop {
        let (s, _root, change) = next_rooted(&rig).await;
        if s == scope && change.kind().is_rescan() {
          break;
        }
      }
    }

    /// G4-1: a caller flooding the bounded command mailbox with reply-less
    /// `SetCover` requests cannot starve a catching-up widen. The flood runs
    /// on PARALLEL workers (a current-thread flood cannot refill the mailbox
    /// while the driver drains it without yielding — the starvation is a
    /// multi-worker phenomenon, exactly production's shape), and the flood
    /// itself pins the prefix in place: with commands continuously ready the
    /// source arm is never selected, so the queued prefix survives to the
    /// `WidenArmed` snapshot (`remaining > 0`), and only the fairness poll —
    /// one prefix message per fully-flushed iteration, command pressure
    /// notwithstanding — can drain it. The pin: `replace_root` resolves
    /// WHILE the flood continues.
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn a_command_flood_cannot_starve_the_catch_up_commit() {
      let rig = inotify_rig();
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 3);
      let scope = watch(&rig, "/r/sub").await;
      let sub_watch = rig
        .fs
        .arms()
        .first()
        .cloned()
        .expect("the birth root arm")
        .0;
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      let hold = rig.fs.hold_prearms();
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: PathBuf::from("/r"),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
          reply,
        })
        .await
        .unwrap();
      assert!(
        settle(|| rig.fs.prearm_entries() == 1).await,
        "staging: the pre-arm must be parked, or the flood below runs outside the commit window"
      );

      // The flood, ESTABLISHED before anything else can move: dedicated OS
      // threads keep the bounded mailbox saturated — the instant the driver
      // consumes a command, a parked sender completes, so the lane never gaps
      // the way runtime-scheduled tasks do. Each command is a reply-less
      // SetCover for a GHOST scope — an UnknownScope no-op, pure command
      // pressure with no effect on the widen. Waiting for the mailbox to FILL
      // proves the lane is owned before the prefix queues.
      let ghost = ScopeId::new(core::num::NonZeroU64::new(999_999).unwrap());
      let flood_stop = std::sync::Arc::new(AtomicBool::new(false));
      let fillers =
        spawn_command_fillers(&rig.commands, &flood_stop, 2, move || Command::SetCover {
          scope: ghost,
          retained: vec![PathBuf::from("/nowhere")],
          reply: None,
        });
      let flood = Flood {
        stop: flood_stop,
        fillers,
      };
      assert!(
        settle(|| rig.commands.len() >= 16).await,
        "staging: the flood must own the command lane before the prefix queues"
      );

      // The prefix queues UNDER the flood (the saturated command lane keeps
      // the source arm unselected, so these survive to the snapshot), then
      // the pre-arm releases: `WidenArmed` outranks commands and snapshots
      // `remaining > 0`.
      for name in [b"f1".as_slice(), b"f2".as_slice(), b"f3".as_slice()] {
        rig
          .fs
          .send_inotify_batch("/r/sub", vec![attributed(&[sub_watch], IN_CREATE, name)]);
      }
      hold.release();

      // The pin: the widen resolves while the flood runs — only the
      // fairness poll can have drained the prefix.
      let resolved = tokio::time::timeout(interpreted_secs(10), on_reply)
        .await
        .expect("the catch-up commit is never starved by a command flood")
        .expect("the driver replies");
      assert!(
        resolved.is_ok(),
        "the widen committed under flood: {resolved:?}"
      );
      assert_eq!(rig.fs.spawns(), 1, "the widen kept the one stream");
      flood.stop_and_join();
    }

    /// G4-1's inversion guard: the fairness poll must not hand a SOURCE
    /// flood the loop. Post-snapshot arrivals never extend `remaining`, so
    /// the poll runs at most prefix-length iterations and Close — a command
    /// — resolves promptly even while a producer floods the lane end to end.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_source_flood_cannot_starve_close_during_catch_up() {
      let rig = inotify_rig();
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 3);
      let scope = watch(&rig, "/r/sub").await;
      let sub_watch = rig
        .fs
        .arms()
        .first()
        .cloned()
        .expect("the birth root arm")
        .0;
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      let hold = rig.fs.hold_prearms();
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: PathBuf::from("/r"),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
          reply,
        })
        .await
        .unwrap();
      assert!(
        settle(|| rig.fs.prearm_entries() == 1).await,
        "staging: the pre-arm must be parked, or the prefix below never survives to the snapshot"
      );
      // Seed a modest prefix, then keep the lane HOT with a dedicated
      // producer thread for the whole close window.
      for name in [b"s1".as_slice(), b"s2".as_slice(), b"s3".as_slice()] {
        rig
          .fs
          .send_inotify_batch("/r/sub", vec![attributed(&[sub_watch], IN_CREATE, name)]);
      }
      let stop = std::sync::Arc::new(AtomicBool::new(false));
      let filler = {
        let fs = rig.fs.clone();
        let stop = std::sync::Arc::clone(&stop);
        std::thread::spawn(move || {
          while !stop.load(Ordering::SeqCst) {
            fs.send_inotify_batch(
              "/r/sub",
              vec![attributed(&[sub_watch], IN_CREATE, b"hot.txt")],
            );
          }
        })
      };
      let flood = Flood {
        stop,
        fillers: vec![filler],
      };
      hold.release();

      // Close while the lane floods: the fairness poll is bounded by the
      // snapshot, so the command lane comes back and Close resolves.
      let (close_reply, on_close) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Close { reply: close_reply })
        .await
        .unwrap();
      let wedged = tokio::time::timeout(interpreted_secs(15), on_close)
        .await
        .expect("Close is never starved by a source flood during catch-up")
        .expect("the close reply resolves");
      assert_eq!(wedged, 0, "every stream quiesced at close");
      flood.stop_and_join();
      // The widen resolved one way or the other — committed before the
      // close won the command lane, or swept by it — never left dangling.
      let resolved = tokio::time::timeout(interpreted_secs(5), on_reply).await;
      assert!(
        resolved.is_ok(),
        "the widen reply resolved (committed or swept at close)"
      );
    }

    /// G5-1, entry path (a) COMBINED with the G4 flood: the lane dies (and
    /// empties) BEFORE `WidenArmed`, so the phase enters with
    /// `remaining == 0` and only the end marker left — the state the narrow
    /// `remaining > 0` arming missed. Under a saturated command mailbox the
    /// membership-armed poll must still consume the marker, route the
    /// source death, and retire the widen — publishing nothing — while the
    /// flood continues.
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn a_command_flood_cannot_starve_a_dead_lane_retire() {
      let registry = RecordingRegistry::default();
      let rig = inotify_rig_registry(registry.clone());
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 3);
      let scope = watch(&rig, "/r/sub").await;
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      let hold = rig.fs.hold_prearms();
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: PathBuf::from("/r"),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
          reply,
        })
        .await
        .unwrap();
      assert!(
        settle(|| rig.fs.prearm_entries() == 1).await,
        "staging: the pre-arm must be parked, or the lane dies outside the phase under test"
      );

      // The saturated command lane, established before anything can move.
      let ghost = ScopeId::new(core::num::NonZeroU64::new(999_999).unwrap());
      let flood_stop = std::sync::Arc::new(AtomicBool::new(false));
      let fillers =
        spawn_command_fillers(&rig.commands, &flood_stop, 2, move || Command::SetCover {
          scope: ghost,
          retained: vec![PathBuf::from("/nowhere")],
          reply: None,
        });
      let flood = Flood {
        stop: flood_stop,
        fillers,
      };
      assert!(
        settle(|| rig.commands.len() >= 16).await,
        "staging: the flood must own the command lane before the lane dies"
      );

      // The lane dies EMPTY before the pre-arm completes: the snapshot will
      // read zero and only the end marker remains.
      rig.fs.disconnect("/r/sub");
      hold.release();

      let resolved = tokio::time::timeout(interpreted_secs(10), on_reply)
        .await
        .expect("a dead-lane retire is never starved by a command flood")
        .expect("the driver replies");
      assert!(
        matches!(resolved, Err(crate::error::ReplaceRootError::Retired)),
        "the dead lane retires the widen under flood: {resolved:?}"
      );
      assert_eq!(
        last_published(&registry, scope),
        Some(PathBuf::from("/r/sub")),
        "the widened root is never published over a dead lane"
      );
      assert_eq!(rig.fs.spawns(), 1, "no fallback: the scope died");
      flood.stop_and_join();
    }

    /// G5-1, entry path (b), deterministic: the poll itself drains the LAST
    /// queued message of a closing lane — `remaining` hits zero with the
    /// end marker still pending, exactly where the narrow arming would
    /// disarm. Membership arming keeps polling: the marker routes the
    /// source death and the widen retires, with the drained message still
    /// delivered at its truthful old-root coordinates first.
    #[tokio::test]
    async fn a_closing_lane_drained_by_the_poll_still_retires() {
      let registry = RecordingRegistry::default();
      let rig = inotify_rig_registry(registry.clone());
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 3);
      let scope = watch(&rig, "/r/sub").await;
      let sub_watch = rig
        .fs
        .arms()
        .first()
        .cloned()
        .expect("the birth root arm")
        .0;
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      let hold = rig.fs.hold_prearms();
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: PathBuf::from("/r"),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
          reply,
        })
        .await
        .unwrap();
      settle(|| rig.fs.prearm_entries() == 1).await;

      // SYNCHRONOUS section (single-threaded runtime, loop starved): one
      // benign message queues, then the lane DIES behind it, then the
      // pre-arm releases — the loop wakes with `WidenArmed`, a one-message
      // prefix, and the end marker all pending.
      rig.fs.send_inotify_batch(
        "/r/sub",
        vec![attributed(&[sub_watch], IN_CREATE, b"last.txt")],
      );
      rig.fs.disconnect("/r/sub");
      let probes_before = rig.fs.probes();
      hold.release();
      for _ in 0..5_000 {
        if rig.fs.probes() > probes_before {
          break;
        }
        std::thread::sleep(Duration::from_millis(1));
      }
      assert!(rig.fs.probes() > probes_before, "the bracket probe ran");
      std::thread::sleep(Duration::from_millis(50));

      // The drained prefix message still delivers at the OLD root before
      // anything else — the truthful pre-death rendering.
      let (s, root, change) = next_rooted(&rig).await;
      assert_eq!(
        (s, root.as_path()),
        (scope, std::path::Path::new("/r/sub")),
        "the closing lane's last message delivers at the old root: {change:?}"
      );
      assert!(change.kind().is_created(), "{change:?}");
      assert_eq!(change.location(), &loc(&["last.txt"]));

      let resolved = tokio::time::timeout(interpreted_secs(10), on_reply)
        .await
        .expect("the poll consumes the end marker past remaining == 0")
        .expect("the driver replies");
      assert!(
        matches!(resolved, Err(crate::error::ReplaceRootError::Retired)),
        "the closing lane retires the widen: {resolved:?}"
      );
      assert_eq!(
        last_published(&registry, scope),
        Some(PathBuf::from("/r/sub")),
        "nothing was published over the dead lane"
      );
      assert_eq!(rig.fs.spawns(), 1, "no fallback: the scope died");
    }

    /// The refresh death gate as the POST-COMMIT belt (its barrier conjunct
    /// is retired — INV-ROOT owns the window): the object at the widened
    /// path is replaced AFTER a clean commit with its records silently
    /// absent (the fake emits none — the standing #33 shape; in the window
    /// itself the record would have TAINTED and the commit refused, see the
    /// core `widen_window_*` cells). The delayed refresh's fresh stat then
    /// detects the divergence and the death funnel runs — terminal Rescan,
    /// scope death — so nothing the divergence hid stays silently
    /// uncovered.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_post_commit_root_divergence_dies_by_the_refresh_belt() {
      let rig = inotify_rig();
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 3);
      let scope = watch(&rig, "/r/sub").await;
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      let hold = rig.fs.hold_refreshes();
      assert!(replace(&rig, scope, "/r").await.is_ok());
      loop {
        let (s, root, change) = next_rooted(&rig).await;
        assert_eq!((s, root.as_path()), (scope, std::path::Path::new("/r")));
        if change.location() == &loc(&["sub"]) {
          break;
        }
      }
      // The post-commit swap: a different object now owns the widened path;
      // the old subtree remains attached beneath it, and no record drains
      // (the standing-class shape the refresh belt exists for).
      rig.fs.replace_root_node("/r", 99, None);

      hold.release();
      // The released refresh's fresh stat finds the divergence: the death
      // funnel's terminal Rescan reaches the consumer and the scope ends.
      loop {
        let (s, _root, change) = next_rooted(&rig).await;
        if s == scope && change.kind().is_rescan() {
          break;
        }
      }
      settle(|| rig.fs.shutdowns() == 1).await;
    }

    /// The stale-Installed bracket: the root object is swapped between the
    /// kernel arm and the bracket's re-stat — the widen is refused typed, the
    /// armed descriptor is reclaimed, and the old coverage never blinks.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_root_swapped_between_arm_and_probe_is_refused() {
      let rig = inotify_rig();
      rig.fs.put("/r/sub", FileKind::Dir, 2);
      rig.fs.put("/r/sub/deep", FileKind::Dir, 3);
      let scope = watch(&rig, "/r/sub").await;
      let sub_watch = rig
        .fs
        .arms()
        .first()
        .cloned()
        .expect("the birth root arm")
        .0;
      fence_birth_crawl(&rig, scope, "/r/sub").await;

      rig.fs.swap_after_prearm("/r", FileKind::Dir, 99);
      let err = replace(&rig, scope, "/r")
        .await
        .expect_err("the bracket refuses");
      assert!(
        matches!(err, crate::error::ReplaceRootError::Source(_)),
        "{err:?}"
      );
      assert_eq!(rig.fs.spawns(), 1);
      assert_eq!(rig.fs.shutdowns(), 0);
      settle(|| !rig.fs.disarms().is_empty()).await;

      rig.fs.send_inotify_batch(
        "/r/sub",
        vec![attributed(&[sub_watch], IN_CREATE, b"alive.txt")],
      );
      let (s, root, change) = next_rooted(&rig).await;
      assert_eq!((s, root.as_path()), (scope, std::path::Path::new("/r/sub")));
      assert_eq!(change.location(), &loc(&["alive.txt"]));
    }
  }
}

/// The Linux one-sample enumerate: `list_dir`/`dir_entry_stat` build each
/// `RawDirEntry` from ONE `statx` of the entry, so its `(kind, dev, ino)` and
/// its mount frame are always one object's — never a `(dev, ino)` from one
/// syscall paired with a mount id from another that a rename/bind could split.
/// Real syscalls, so Linux-only (the container `unit` suite).
#[cfg(all(target_os = "linux", not(miri)))]
mod enumerate_one_sample {
  use std::os::unix::fs::MetadataExt;

  use tributary_proto::FileKind;

  use super::super::{dir_entry_stat, list_dir};
  use crate::core::{RawDirEntry, RawEnumerate};

  fn scratch(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir()
      .canonicalize()
      .expect("canonicalize temp dir")
      .join(format!(
        "tributary-fs-enum-{}-{}-{}",
        tag,
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
      ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
  }

  /// A directory and a file classify correctly, and every entry's `(dev, ino)`
  /// equals a path stat of that same object — the one `statx` reports the true
  /// object, not a stale or mispaired identity.
  #[test]
  fn entries_carry_the_true_objects_facts() {
    let dir = scratch("facts");
    std::fs::create_dir(dir.join("sub")).expect("create subdir");
    std::fs::write(dir.join("file"), b"x").expect("create file");

    let RawEnumerate::Listed { entries, complete } = list_dir(&dir) else {
      panic!("a readable directory lists");
    };
    assert!(complete, "the whole directory was read");
    assert_eq!(entries.len(), 2, "both entries were sampled: {entries:?}");

    for entry in &entries {
      let name = std::str::from_utf8(&entry.name).expect("ascii entry name");
      let meta = std::fs::symlink_metadata(dir.join(name)).expect("stat the entry path");
      assert_eq!(entry.dev, meta.dev(), "{name}: device is the object's");
      assert_eq!(entry.ino, meta.ino(), "{name}: inode is the object's");
      let expected_kind = if name == "sub" {
        FileKind::Dir
      } else {
        FileKind::File
      };
      assert_eq!(entry.kind, expected_kind, "{name}: kind from the sample");
    }
    let _ = std::fs::remove_dir_all(&dir);
  }

  /// A symlink entry is classified `Symlink` — `AT_SYMLINK_NOFOLLOW` on the one
  /// `statx` reports the link itself, so the enumerate never follows it to a
  /// target that a swap could redirect.
  #[test]
  fn a_symlink_entry_is_not_followed() {
    let dir = scratch("symlink");
    std::fs::create_dir(dir.join("real")).expect("create the target dir");
    std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).expect("create a symlink");

    let RawEnumerate::Listed { entries, .. } = list_dir(&dir) else {
      panic!("a readable directory lists");
    };
    let link = entries
      .iter()
      .find(|e| e.name == b"link")
      .expect("the symlink entry is listed");
    assert_eq!(
      link.kind,
      FileKind::Symlink,
      "the symlink is reported as itself, not its target directory"
    );
    let _ = std::fs::remove_dir_all(&dir);
  }

  /// The mount frame is read from the SAME sample as the identity: when a fresh
  /// `statx` reports a mount id for the object, `dir_entry_stat` reports the
  /// identical one (both from the one call's result); when the kernel withholds
  /// it (pre-5.8), both decline it. Either way the frame and the identity are one
  /// object's — the split this fix closes.
  #[test]
  fn the_mount_frame_comes_from_the_identity_sample() {
    use rustix::fs::{AtFlags, StatxFlags, statx};
    let dir = scratch("frame");
    std::fs::create_dir(dir.join("sub")).expect("create subdir");
    let sub = dir.join("sub");

    let (kind, _dev, _ino, mnt_id) =
      dir_entry_stat(&sub).expect("the freshly created subdir samples");
    assert_eq!(kind, FileKind::Dir);

    // An independent statx of the same object: its mount-id presence and value
    // must match what the enumerate sample reported — proof the enumerate read
    // the frame from the identity's own result, not a second lookup.
    let stx = statx(
      rustix::fs::CWD,
      &sub,
      AtFlags::SYMLINK_NOFOLLOW,
      StatxFlags::BASIC_STATS.union(StatxFlags::MNT_ID),
    )
    .expect("statx the subdir");
    let reference = (stx.stx_mask & StatxFlags::MNT_ID.bits() != 0).then_some(stx.stx_mnt_id);
    assert_eq!(
      mnt_id, reference,
      "the enumerate's mount frame is the identity sample's own mount id"
    );
    let _ = std::fs::remove_dir_all(&dir);
  }

  /// A raced-away entry (nothing at the path) yields `None` — the incomplete
  /// flag drives the retry, and no half-built entry with a bogus identity is
  /// pushed.
  #[test]
  fn a_vanished_entry_samples_to_none() {
    let dir = scratch("vanished");
    let gone = dir.join("gone");
    assert!(
      dir_entry_stat(&gone).is_none(),
      "an absent path produces no entry facts"
    );
    // A directly-built entry list stays a well-formed RawEnumerate.
    let entry = RawDirEntry {
      name: b"present".to_vec(),
      kind: FileKind::File,
      dev: 1,
      ino: 2,
      mnt_id: None,
    };
    assert_eq!(entry.name, b"present");
    let _ = std::fs::remove_dir_all(&dir);
  }
}

/// The replace orchestration end to end over the fake platform: the swap
/// commits make-before-break, the handle/scope survive, the covering Rescan
/// arrives, and post-swap events deliver under the new root.
mod replace {
  use super::*;

  async fn replace(
    rig: &Rig,
    scope: ScopeId,
    new_root: &str,
  ) -> Result<(), crate::error::ReplaceRootError> {
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from(new_root),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from(new_root)),
        reply,
      })
      .await
      .unwrap();
    on_reply.await.expect("driver replies")
  }

  #[tokio::test(start_paused = true)]
  async fn the_swap_commits_and_the_scope_survives() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // Live pre-swap delivery under the old root.
    rig
      .fs
      .send_batch("/r/sub", vec![ev("/r/sub/pre.txt", created(), 1, 11)]);
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(root.as_path(), Path::new("/r/sub"));
    assert!(change.kind().is_created());
    let pre_epoch = change.epoch();

    // The swap: /r/sub widens to /r; the commit's covering Rescan arrives
    // on the SAME scope, rooted at the NEW path, on a LATER epoch.
    assert!(replace(&rig, scope, "/r").await.is_ok());
    settle(|| rig.fs.shutdowns() == 1).await;
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope, "the scope survives the swap");
    assert_eq!(root.as_path(), Path::new("/r"), "deliveries re-root");
    assert!(change.kind().is_rescan(), "the covering Rescan: {change:?}");
    assert!(
      change.epoch() > pre_epoch,
      "the epoch is monotone across the swap"
    );

    // Post-swap events flow from the NEW stream under the new root.
    rig
      .fs
      .send_batch("/r", vec![ev("/r/post.txt", created(), 2, 12)]);
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(root.as_path(), Path::new("/r"));
    assert!(change.kind().is_created());
    assert_eq!(change.location(), &loc(&["post.txt"]));

    // Unwatch after the replace tears exactly the surviving (new) stream.
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(reply),
      })
      .await
      .unwrap();
    assert!(
      on_reply.await.unwrap().is_torn(),
      "the swapped scope is unwatchable"
    );
    settle(|| rig.fs.shutdowns() == 2).await;
    assert_eq!(rig.fs.shutdowns(), 2);
  }

  #[tokio::test(start_paused = true)]
  async fn a_narrowing_replace_commits() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r").await;

    // /r narrows to /r/sub: the exemption clears the self-overlap and the
    // commit re-roots the scope downward.
    assert!(replace(&rig, scope, "/r/sub").await.is_ok());
    settle(|| rig.fs.shutdowns() == 1).await;
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(root.as_path(), Path::new("/r/sub"));
    assert!(change.kind().is_rescan());

    rig
      .fs
      .send_batch("/r/sub", vec![ev("/r/sub/in.txt", created(), 5, 15)]);
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(root.as_path(), Path::new("/r/sub"));
    assert_eq!(change.location(), &loc(&["in.txt"]));
  }

  #[tokio::test(start_paused = true)]
  async fn a_late_old_stream_batch_after_the_commit_is_dropped_by_its_lane() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // Hold teardowns: the commit retires the old handle but its stream stays
    // alive (its shutdown is parked), so a post-commit batch on the OLD
    // stream is consumable — and must be dropped by the lane gate.
    let gate = rig.fs.hold_teardowns();
    assert!(replace(&rig, scope, "/r").await.is_ok());
    let (s, _root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert!(change.kind().is_rescan(), "the commit Rescan first");

    rig
      .fs
      .send_batch("/r/sub", vec![ev("/r/sub/stale.txt", created(), 7, 17)]);
    // An ordering probe on the NEW lane: if the stale batch were going to
    // deliver, it would arrive before this later send.
    rig
      .fs
      .send_batch("/r", vec![ev("/r/probe.txt", created(), 8, 18)]);
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(
      root.as_path(),
      Path::new("/r"),
      "only the new lane delivers"
    );
    assert_eq!(change.location(), &loc(&["probe.txt"]));

    gate.release();
    settle(|| rig.fs.shutdowns() == 1).await;
  }

  #[tokio::test(start_paused = true)]
  async fn close_mid_swap_counts_both_streams() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // The replacement spawn is parked when close arrives: the drain must
    // account for the old stream AND the orphaned replacement.
    let gate = rig.fs.hold_spawns();
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
        reply,
      })
      .await
      .unwrap();
    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    gate.release();
    assert!(on_close.await.is_ok(), "close settles");
    settle(|| rig.fs.shutdowns() == 2).await;
    assert_eq!(rig.fs.shutdowns(), 2, "both streams are torn down");
    // Both resolutions of the replace/close race are legal linearizations:
    // close-first — the drain drops the reply (`Err(_)`, surfaced as `Closed`);
    // commit-first — the spawn result beats the queued Close through the op-biased
    // select, the swap fully commits, and close then tears down the committed lane
    // (the shutdowns()==2 asserts above pin both-streams accounting either way).
    assert!(matches!(
      on_reply.await,
      Ok(Ok(())) | Ok(Err(crate::error::ReplaceRootError::Closed)) | Err(_)
    ));
  }

  #[tokio::test(start_paused = true)]
  async fn a_failed_spawn_leaves_the_old_root_untouched() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // "/missing" is not in the fake tree: the replacement spawn fails and
    // the swap is atomic-on-failure.
    let outcome = replace(&rig, scope, "/missing").await;
    assert!(
      matches!(outcome, Err(crate::error::ReplaceRootError::Source(_))),
      "{outcome:?}"
    );

    // The old stream still delivers — coverage untouched.
    rig
      .fs
      .send_batch("/r/sub", vec![ev("/r/sub/still.txt", created(), 3, 13)]);
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(root.as_path(), Path::new("/r/sub"));
    assert!(change.kind().is_created());
    assert_eq!(rig.fs.shutdowns(), 0, "no stream was torn down");
  }

  // Real-clock (not start_paused): the replacement spawn is HELD on a blocking
  // thread across a `settle`, and tokio will not auto-advance paused time while
  // a blocking task is outstanding — so this cell runs on the multi-thread
  // runtime where the held thread and the driver make real concurrent progress.
  #[tokio::test(flavor = "multi_thread")]
  async fn death_wins_a_mid_swap_unwatch() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // Hold the replacement spawn so the unwatch lands first.
    let gate = rig.fs.hold_spawns();
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
        reply,
      })
      .await
      .unwrap();
    let (unwatch_reply, mut on_unwatch) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(unwatch_reply),
      })
      .await
      .unwrap();
    assert!(
      settle(|| rig.fs.shutdowns() == 1).await,
      "staging: the old stream must retire, or the unwatch below is pending for no reason yet"
    );
    assert!(
      futures_util::poll!(&mut on_unwatch).is_pending(),
      "unwatch waits for the held replacement, not just the retired stream"
    );

    gate.release();
    let outcome = on_reply.await.expect("driver replies");
    assert!(
      matches!(outcome, Err(crate::error::ReplaceRootError::Retired)),
      "death wins: {outcome:?}"
    );
    // Both the old stream (unwatch) and the orphaned replacement are torn
    // down inside the counted accounting; the unwatch resolves only now, at
    // full scope quiescence.
    assert!(
      on_unwatch.await.unwrap().is_torn(),
      "the unwatch resolves once the scope is quiescent"
    );
    settle(|| rig.fs.shutdowns() == 2).await;
  }

  #[tokio::test(start_paused = true)]
  async fn a_second_replace_in_flight_is_refused() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    let gate = rig.fs.hold_spawns();
    let (reply1, on_reply1) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
        reply: reply1,
      })
      .await
      .unwrap();
    let (reply2, on_reply2) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
        reply: reply2,
      })
      .await
      .unwrap();
    assert!(
      matches!(
        on_reply2.await.expect("driver replies"),
        Err(crate::error::ReplaceRootError::ReplaceInFlight)
      ),
      "the second replace refuses"
    );
    gate.release();
    assert!(on_reply1.await.expect("driver replies").is_ok());
  }

  /// The unwatch fence is per-scope QUIESCENCE: a replace's retired old
  /// stream is still shutting down when the unwatch starts, and its earlier
  /// completion must NOT resolve the unwatch — only the last teardown of the
  /// scope does.
  #[tokio::test(flavor = "multi_thread")]
  async fn unwatch_resolves_only_at_scope_teardown_quiescence() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // The swap commits while its old-stream teardown parks on gate1.
    let gate1 = rig.fs.hold_teardowns();
    assert!(replace(&rig, scope, "/r").await.is_ok());
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The unwatch's own teardown parks on gate2 (a fresh gate: the parked
    // old-stream thread keeps waiting on the one it cloned at park time).
    let gate2 = rig.fs.hold_teardowns();
    let (reply, mut on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(reply),
      })
      .await
      .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The old-stream straggler completes FIRST; the unwatch must keep
    // pending until the CURRENT stream is down too.
    gate1.release();
    settle(|| rig.fs.shutdowns() == 1).await;
    assert_eq!(rig.fs.shutdowns(), 1, "only the straggler completed");
    assert!(
      futures_util::poll!(&mut on_reply).is_pending(),
      "a straggler's completion must not resolve the unwatch"
    );

    gate2.release();
    assert!(on_reply.await.unwrap().is_torn(), "resolved at quiescence");
    settle(|| rig.fs.shutdowns() == 2).await;
  }

  /// The commit linearization contract, pinned: a death still QUEUED on the
  /// old lane when the commit lands is dominated whole — the swap reports
  /// success and the covering Rescan re-reads the (new) world; the old
  /// world's fate concerns nothing the scope still covers. The race is
  /// irreducible (a death can always sit in the kernel buffer, not yet in
  /// any queue), so the driver's serialization decides — and BOTH orders
  /// are safe: a death processed first wins (`death_wins_a_mid_swap_
  /// unwatch`), a death queued behind the commit is moot, and a death of
  /// the LIVE world always arrives on the new lane, which is never
  /// suppressed (the tail of this cell).
  #[tokio::test(start_paused = true)]
  async fn a_queued_old_lane_death_is_dominated_by_the_commit() {
    let registry = RecordingRegistry::default();
    let rig = rig_with(64, registry.clone());
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // Park the replacement spawn; queue the old stream's death while the
    // driver cannot run (paused current-thread runtime — it advances only
    // at our awaits); then let the spawn finish on the REAL-clock pool
    // while the driver is still frozen. At the next await both queues are
    // ready and the biased select commits BEFORE consuming the death.
    let gate = rig.fs.hold_spawns();
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
        reply,
      })
      .await
      .unwrap();
    // Let the driver process the command and PARK the spawn on the gate
    // (the send resolves on channel capacity alone, before the driver ran).
    for _ in 0..8 {
      tokio::task::yield_now().await;
    }
    rig.fs.send_fatal("/r/sub");
    gate.release();
    std::thread::sleep(Duration::from_millis(200));

    assert!(
      on_reply.await.expect("driver replies").is_ok(),
      "the commit wins the serialization"
    );
    let (s, root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert_eq!(root.as_path(), Path::new("/r"));
    assert!(change.kind().is_rescan(), "the covering Rescan: {change:?}");
    assert_eq!(registry.dead(), [], "the old world's death is moot");

    // The scope is genuinely alive on the new lane...
    rig
      .fs
      .send_batch("/r", vec![ev("/r/live.txt", created(), 9, 19)]);
    let (s, _root, change) = next_rooted(&rig).await;
    assert_eq!(s, scope);
    assert!(change.kind().is_created());

    // ...and a death of the LIVE world is never suppressed: deaths are only
    // ever reordered around the commit, never lost.
    rig.fs.disconnect("/r");
    settle(|| registry.dead() == [scope]).await;
    assert_eq!(registry.dead(), [scope], "the new lane's death lands");
  }

  #[tokio::test(start_paused = true)]
  async fn an_unknown_scope_is_refused() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let _scope = watch(&rig, "/r/sub").await;
    let ghost = ScopeId::new(core::num::NonZeroU64::new(999).unwrap());
    let outcome = replace(&rig, ghost, "/r").await;
    assert!(
      matches!(outcome, Err(crate::error::ReplaceRootError::UnknownRoot)),
      "{outcome:?}"
    );
  }

  /// The unwatch quiescence fence holds under the OTHER ordering: the old
  /// root DIES (removing the handle) while a replacement is still spawning,
  /// and only THEN does unwatch arrive. It must not answer immediately while
  /// the replacement stream is coming up — it parks until the replacement is
  /// torn down, then reports the scope gone (UnknownRoot).
  #[tokio::test(flavor = "multi_thread")]
  async fn unwatch_after_root_death_waits_for_the_replacement() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // A replace is in flight, its spawn held on the blocking pool.
    let gate = rig.fs.hold_spawns();
    let (reply, on_replace) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
        reply,
      })
      .await
      .unwrap();
    // Wait until the replacement spawn has actually been dispatched — the fake
    // records its resume point at dispatch, before the hold gate parks it — so
    // `replace_states` is populated before the death arrives. A fixed yield count
    // is not a barrier under a loaded multi-thread runtime (the driver task may
    // not have run yet); this condition is.
    settle(|| rig.fs.spawn_resume_points().len() == 2).await;

    // The OLD root dies while the replacement is still spawning: the death
    // path tears the original handle down.
    rig.fs.send_fatal("/r/sub");
    settle(|| rig.fs.shutdowns() == 1).await;

    // Unwatch arrives AFTER the handle is gone: the scope is NOT quiescent (a
    // replacement is still coming up), so the reply must park, not answer.
    let (ureply, mut on_unwatch) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(ureply),
      })
      .await
      .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
      futures_util::poll!(&mut on_unwatch).is_pending(),
      "unwatch must wait for the still-spawning replacement, not answer at once"
    );

    // Release: the replacement resolves Retired and is torn down; only then
    // does the unwatch resolve, reporting the dead scope as UnknownRoot.
    gate.release();
    assert!(matches!(
      on_replace.await.expect("driver replies"),
      Err(crate::error::ReplaceRootError::Retired)
    ));
    assert!(
      on_unwatch.await.unwrap().is_unknown(),
      "the dead scope resolves UnknownRoot, only at quiescence"
    );
    settle(|| rig.fs.shutdowns() == 2).await;
    assert_eq!(rig.fs.shutdowns(), 2, "old stream AND the replacement");
  }

  /// A `RootHandle` is `Copy`, so one scope can accrue several awaited
  /// unwatches. Every parked waiter must be kept and resolved — dropping one
  /// would surface to its caller as `Closed`, which the watcher reads as
  /// driver death. Two unwatches of the same scope, the teardown held: both
  /// pend, then resolve with their OWN verdicts (the first tore it down =
  /// `true`, the duplicate found it already dying = `false`), neither closed.
  #[tokio::test(flavor = "multi_thread")]
  async fn duplicate_awaited_unwatches_all_resolve_none_dropped() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // Hold the teardown so the scope stays non-quiescent between the two
    // unwatches (the first removes the handle; the second then lands in the
    // outstanding-obligation branch that used to OVERWRITE the first waiter).
    let gate = rig.fs.hold_teardowns();
    let (r1, mut on1) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(r1),
      })
      .await
      .unwrap();
    // Let the handle be removed and the held teardown dispatched.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (r2, mut on2) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(r2),
      })
      .await
      .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Both waiters pend while the teardown is held, and NEITHER is dropped
    // (a dropped sender would resolve as an error, not `Pending`).
    assert!(
      futures_util::poll!(&mut on1).is_pending(),
      "the first waiter is still parked, not dropped"
    );
    assert!(
      futures_util::poll!(&mut on2).is_pending(),
      "the second waiter is queued beside the first, not overwriting it"
    );

    gate.release();
    assert!(
      on1
        .await
        .expect("the first waiter is answered, never Closed")
        .is_torn(),
      "the first unwatch tore the scope down"
    );
    assert!(
      on2
        .await
        .expect("the second waiter is answered, never Closed")
        .is_unknown(),
      "the duplicate resolves UnknownRoot"
    );
    settle(|| rig.fs.shutdowns() == 1).await;
  }

  /// The waiter vector is reclaimed, not merely accrued: an issue-and-cancel
  /// storm of duplicate unwatches against a scope whose teardown is STALLED
  /// leaves the parked-waiter vector bounded (the loop-top prune drops
  /// canceled senders), while a genuinely-awaited waiter still resolves.
  #[tokio::test(flavor = "multi_thread")]
  async fn canceled_duplicate_unwatches_stay_bounded() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // Hold the teardown so the scope never quiesces during the storm.
    let gate = rig.fs.hold_teardowns();

    // One genuinely-awaited unwatch whose receiver is kept alive.
    let (survivor, on_survivor) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(survivor),
      })
      .await
      .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // The storm: each duplicate command is accepted, then its receiver
    // dropped (canceled). Without the prune these would accrue without bound
    // while the teardown stays held.
    for _ in 0..200 {
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Unwatch {
          scope,
          reply: Some(reply),
        })
        .await
        .unwrap();
      drop(on_reply);
      tokio::task::yield_now().await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (q, on_q) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::DebugUnwatchWaiters { scope, reply: q })
      .await
      .unwrap();
    let parked = on_q.await.unwrap();
    assert!(
      parked <= 3,
      "canceled waiters are reclaimed each loop-top, not accrued: {parked}"
    );

    // The genuinely-awaited waiter still resolves with its verdict.
    gate.release();
    assert!(
      on_survivor
        .await
        .expect("the survivor is answered")
        .is_torn(),
      "the live waiter resolves Torn at quiescence"
    );
    settle(|| rig.fs.shutdowns() == 1).await;
  }

  /// Close must resolve a parked unwatch even when the last obligation is a
  /// FAILED replacement spawn — which enqueues no teardown. The drain's
  /// spawn arm re-checks quiescence (like the live loop's), so the waiter
  /// gets its recorded verdict instead of dropping as `Closed` (a false
  /// driver-death report despite a clean teardown).
  #[tokio::test(flavor = "multi_thread")]
  async fn close_resolves_a_parked_unwatch_when_the_replacement_spawn_fails() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // A replacement spawn that WILL fail (/missing is not in the fake tree),
    // held so Close begins while it is still in flight.
    let gate = rig.fs.hold_spawns();
    let (rep_reply, on_replace) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/missing"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from(
          "/missing",
        )),
        reply: rep_reply,
      })
      .await
      .unwrap();
    for _ in 0..8 {
      tokio::task::yield_now().await;
    }

    // An awaited unwatch parks its waiter (handle still present → verdict
    // `true`); its own teardown completes but the waiter stays held on the
    // in-flight spawn.
    let (uw_reply, on_unwatch) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(uw_reply),
      })
      .await
      .unwrap();
    assert!(
      settle(|| rig.fs.shutdowns() == 1).await,
      "staging: the old stream must retire before close, leaving the failing spawn as the scope's last obligation"
    );

    // Close begins while the failing spawn is still held.
    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Release: the spawn fails, the drain reaches quiescence, and the parked
    // unwatch resolves with its VERDICT, never a channel closure.
    gate.release();
    assert!(on_close.await.is_ok(), "close settles");
    assert!(
      on_unwatch
        .await
        .expect("the waiter is answered, not dropped as Closed")
        .is_torn(),
      "the unwatch resolves its recorded verdict"
    );
    // The abandoned replace caller is resolved (its reservation and reply
    // dropped at the close sweep), never left hanging.
    let replace_outcome = on_replace.await;
    assert!(
      replace_outcome.is_err() || matches!(replace_outcome, Ok(Err(_))),
      "{replace_outcome:?}"
    );
  }

  /// The swap window rides the journal: the replacement spawn inherits the
  /// RETIRING stream's resume point, so a journal-bearing backend replays the
  /// window instead of leaning on the covering `Rescan` alone. A birth spawn
  /// carries none (there is nothing to resume from).
  #[tokio::test(start_paused = true)]
  async fn a_replacement_spawn_inherits_the_retiring_resume_point() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    // The live stream mints a journal point, as FSEvents does.
    let token = crate::os::ResumeToken::fsevents(4242, Some([7u8; 16]));
    rig.fs.mint_resume_token(token);

    let scope = watch(&rig, "/r/sub").await;
    assert_eq!(
      rig.fs.spawn_resume_points(),
      vec![None],
      "a birth spawn has nothing to resume from"
    );

    assert!(replace(&rig, scope, "/r").await.is_ok());
    settle(|| rig.fs.shutdowns() == 1).await;
    assert_eq!(
      rig.fs.spawn_resume_points(),
      vec![None, Some(token)],
      "the replacement resumes the retiring stream's journal point"
    );
  }

  /// Whole-scope teardown reclaims the delivery lane: repeated watch/unwatch
  /// churn leaves no lane entry behind, so `lanes` stays bounded for the
  /// driver's lifetime (scope ids never recycle).
  #[tokio::test(flavor = "multi_thread")]
  async fn watch_unwatch_churn_leaves_no_lane_entry() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    for _ in 0..16 {
      let scope = watch(&rig, "/r/sub").await;
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Unwatch {
          scope,
          reply: Some(reply),
        })
        .await
        .unwrap();
      assert!(
        on_reply.await.unwrap().is_torn(),
        "each cycle tears down cleanly"
      );
    }
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::DebugLaneCount { reply })
      .await
      .unwrap();
    assert_eq!(
      on_reply.await.unwrap(),
      0,
      "every retired scope reclaimed its lane — no unbounded growth"
    );
  }
}

/// The sync-cookie substrate on a kernel-recursive root: no re-arm work means
/// the settle fence is trivially met, so the write lands at once; the unlink
/// is a reply-less fire-and-forget; and a read-only tree refuses typed.
///
/// The registry OWNS every cookie the driver writes — never the reply oneshot —
/// so no interleaving strands a file: an abandoned reply, a scope retiring under
/// an in-flight write, a failed write, and the driver's own death (close OR
/// cancellation) each leave zero cookies on disk and zero records behind.
mod sync_cookie {
  use super::*;

  /// The exported cookie-directory classifier recognizes exactly the names this crate
  /// mints for that directory — the bare stem, and the stem qualified by any uid
  /// [`cookie_dir_name`] can actually render — and nothing else in the reserved
  /// namespace.
  ///
  /// It exists so the layer that decides what reaches a consumer does not have to
  /// re-implement the shape with a prefix test: a prefix test suppresses every user leaf
  /// that shares the stem, silently and with no recovery signal. A suffix test looser
  /// than the minter keeps a narrower slice of that same defect — `cookie_dir_name`
  /// formats a `uid_t` with `{}`, so a redundant leading zero or a number past the uid
  /// space names a directory this crate could not have created, and a consumer that
  /// suppresses what lands inside the cookie directory would erase the user's directory
  /// and everything reported within it.
  ///
  /// # A disclosed correction
  ///
  /// This cell used to assert `.tributaries-sync-cookies-4294967295` as a name this crate
  /// MINTS. It is not one: `4294967295` is `(uid_t)-1`, POSIX's invalid-uid sentinel — the
  /// value `chown` reads as "leave this id alone" — which no account is allocated and no
  /// `geteuid()` returns, so [`cookie_dir_name`] can never render that suffix. The assertion
  /// pinned the very over-acceptance this cell exists to close. The literal moved to the
  /// negative list below, and the ceiling is now proven at its true edge instead: `4294967294`
  /// is the largest uid a minter can hold, and a real `nfsnobody` on some systems.
  #[test]
  fn the_cookie_directory_classifier_admits_only_names_this_crate_mints() {
    // What this crate actually names its ONE stable directory, where it keeps
    // one. Windows keeps none — it mints per obligation, which
    // `every_minted_cookie_directory_name_is_claimed_by_the_classifier` covers
    // on every host.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert!(crate::is_sync_cookie_dir_name(&cookie_dir_name()));
    // The bare stem (no uid to qualify it) and any uid's directory: two users may
    // legitimately watch one tree, and neither one's is a user change on the other's
    // stream.
    assert!(crate::is_sync_cookie_dir_name(COOKIE_DIR_PREFIX));
    assert!(crate::is_sync_cookie_dir_name(
      ".tributaries-sync-cookies-0"
    ));
    // The uid ceiling, at the largest value a `geteuid()` can actually return. It is
    // deliberately NOT this platform's own cap: a shared filesystem carries a directory
    // minted by a process on another one, and refusing that uid would republish a genuine
    // foreign cookie directory — and every cookie inside it — as user creates.
    assert!(crate::is_sync_cookie_dir_name(
      ".tributaries-sync-cookies-4294967294"
    ));

    for user_leaf in [
      ".tributaries-sync-cookies-mine",
      ".tributaries-sync-cookies-",
      ".tributaries-sync-cookies.bak",
      ".tributaries-sync-cookie",
      ".tributaries-sync-7-42-3-00000000deadbeef",
      "cookies",
      // Numeric, but not what `format!("{euid}")` renders: a redundant leading zero, and
      // a suffix past the uid space. `cookie_dir_name` can emit neither, so neither
      // directory is this crate's.
      ".tributaries-sync-cookies-0001",
      ".tributaries-sync-cookies-00",
      ".tributaries-sync-cookies-4294967296",
      ".tributaries-sync-cookies-99999999999999999999",
      ".tributaries-sync-cookies-+1",
      // Inside the `u32` the suffix is parsed as, but still unmintable: `(uid_t)-1` is
      // POSIX's invalid-uid sentinel, so no `geteuid()` hands it to `cookie_dir_name`. See
      // this cell's disclosed correction — it was asserted as a MINTED name here.
      ".tributaries-sync-cookies-4294967295",
    ] {
      assert!(
        !crate::is_sync_cookie_dir_name(user_leaf),
        "{user_leaf} is not a name this crate mints — classifying it would erase a user file"
      );
    }
  }

  /// The Windows mint and the classifier are one round trip: every token
  /// [`mint_cookie_dir_token`] can produce names a directory the exported
  /// classifier claims, so the directory's own create — and every cookie inside
  /// it — is suppressed rather than published as a user change.
  ///
  /// Host-portable on purpose. The rule is a decision about a `u32` and a
  /// `&str`, and a rule that could only be exercised where a Windows kernel runs
  /// is a rule whose inversion this suite would never see.
  ///
  /// FAIL-ON-REVERT (drop `admissible_token` from the mint): the `u32::MAX` row
  /// below names `.tributaries-sync-cookies-4294967295`, which the classifier
  /// calls a USER directory — so on the draw that lands there the cookie
  /// directory and its whole contents reach consumer streams, silently and with
  /// no `Rescan`.
  #[test]
  fn every_minted_cookie_directory_name_is_claimed_by_the_classifier() {
    use crate::os::windows::security::admissible_token;

    // The composition the mint actually performs, at both edges of the space and
    // at the one value the classifier refuses.
    for raw in [0, 1, 2, 4_294_967_294, u32::MAX] {
      let name = cookie_dir_name_for(admissible_token(raw));
      assert!(
        crate::is_sync_cookie_dir_name(&name),
        "{name} is a name the Windows mint can render, so the classifier must claim it"
      );
    }
    // Staging for the row above: the raw value really is one the classifier
    // refuses, so the remap is doing the work rather than the assertion passing
    // vacuously.
    assert!(!crate::is_sync_cookie_dir_name(&cookie_dir_name_for(
      u32::MAX
    )));

    // And the real minter, run for real: every draw is claimed, and the draws
    // are not a constant — a mint that answered one value would still be SAFE
    // (the create is what refuses an occupied name) but would give up the
    // defence in depth of a directory an attacker must also predict.
    let draws: BTreeSet<u32> = (0..64).map(|_| mint_cookie_dir_token()).collect();
    for token in &draws {
      let name = cookie_dir_name_for(*token);
      assert!(
        crate::is_sync_cookie_dir_name(&name),
        "{name} came out of the production mint, so the classifier must claim it"
      );
    }
    assert!(
      draws.len() * 2 > 64,
      "64 draws collapsed to {} distinct values — the mint is answering a constant",
      draws.len()
    );
  }

  /// The mint loop's decision table, as a table.
  ///
  /// Three facts live here and are checked without a filesystem: `AlreadyExists`
  /// is the ONE kind that mints another candidate (the anti-adoption rule — this
  /// crate declines to look at a name it did not bind), every other kind aborts
  /// on the spot because it describes the PARENT rather than the candidate, and
  /// the retry is BOUNDED so a peer racing to occupy each candidate cannot spin
  /// a blocking-pool thread forever.
  ///
  /// FAIL-ON-REVERT in three directions: an arm that treats `AlreadyExists` as
  /// success (which is exactly what the deleted `create_directory_with_sddl`
  /// did) breaks the first row; an arm that retries every error loops on a
  /// missing parent until exhaustion and reports the wrong failure; an unbounded
  /// loop never reaches `Exhausted`.
  #[test]
  fn the_mint_loop_retries_only_an_occupied_name_and_only_so_often() {
    use std::io::ErrorKind;

    assert_eq!(mint_step(None, 1), MintStep::Bound);
    assert_eq!(
      mint_step(None, COOKIE_DIR_MINT_ATTEMPTS + 1),
      MintStep::Bound,
      "a create that succeeded is bound whatever the attempt count says"
    );

    assert_eq!(
      mint_step(Some(ErrorKind::AlreadyExists), 1),
      MintStep::Retry
    );
    assert_eq!(
      mint_step(Some(ErrorKind::AlreadyExists), COOKIE_DIR_MINT_ATTEMPTS - 1),
      MintStep::Retry,
      "the last attempt before the bound still retries"
    );
    assert_eq!(
      mint_step(Some(ErrorKind::AlreadyExists), COOKIE_DIR_MINT_ATTEMPTS),
      MintStep::Exhausted,
      "and the bound is reached rather than exceeded"
    );

    for kind in [
      ErrorKind::PermissionDenied,
      ErrorKind::NotFound,
      ErrorKind::StorageFull,
      ErrorKind::ReadOnlyFilesystem,
      ErrorKind::Other,
    ] {
      assert_eq!(
        mint_step(Some(kind), 1),
        MintStep::Failed,
        "{kind:?} describes the parent, not the candidate — another name fails identically"
      );
    }
  }

  /// The anti-adoption rule itself: the mint loop never hands back a name that
  /// was already bound, and never touches what was standing there.
  ///
  /// Host-portable because `create_dir`'s `AlreadyExists` is portable — this is
  /// the same `bind_fresh_cookie_dir` the Windows arm runs, driven with an
  /// injected candidate sequence and an injected binding call against real
  /// occupied names. Production injects the anchored `NtCreateFile` create
  /// instead; what the loop does with an `AlreadyExists` is the same either way,
  /// and that is what this pins.
  ///
  /// FAIL-ON-REVERT: restore the deleted behaviour — an occupied name accepted
  /// as success and then verified — and the first assertion fails outright,
  /// because the path returned IS the occupied one and this crate would proceed
  /// to write cookies into a directory a stranger prepared.
  #[test]
  fn an_occupied_candidate_is_discarded_rather_than_entered() {
    let parent = std::env::temp_dir().join(format!(
      "tributary-fs-mint-{}-{}",
      std::process::id(),
      line!()
    ));
    std::fs::create_dir_all(&parent).expect("create the scratch parent");

    // Two occupied candidates of different SHAPES: a directory with contents
    // (the crash-residue case, and the one an adoption verdict would have had to
    // adjudicate) and a plain file (which `create_dir` also refuses).
    let occupied_dir = parent.join(cookie_dir_name_for(7));
    std::fs::create_dir(&occupied_dir).expect("occupy the first candidate");
    std::fs::write(occupied_dir.join("stranger"), b"not this crate's").expect("plant contents");
    let occupied_file = parent.join(cookie_dir_name_for(42));
    std::fs::write(&occupied_file, b"a file, not a directory").expect("occupy the second");

    let mut sequence = [7_u32, 42, 99].into_iter();
    let mut calls = 0;
    let (bound, ()) = bind_fresh_cookie_dir(
      &parent,
      &mut || {
        calls += 1;
        sequence
          .next()
          .expect("the loop asks for no more than three")
      },
      &mut |leaf| std::fs::create_dir(parent.join(leaf)),
    )
    .expect("the third candidate is free");

    assert_eq!(
      bound.file_name().and_then(|leaf| leaf.to_str()),
      Some(cookie_dir_name_for(99).as_str()),
      "the loop returned an occupied name — an occupied name is somebody else's directory"
    );
    assert_eq!(calls, 3, "one draw per attempt, and no attempt is skipped");
    assert!(
      bound.is_dir() && std::fs::read_dir(&bound).into_iter().flatten().count() == 0,
      "what it returned is a directory this call created, so it is empty"
    );
    // Neither occupant was entered, emptied, replaced or removed.
    assert_eq!(
      std::fs::read(occupied_dir.join("stranger")).ok(),
      Some(b"not this crate's".to_vec()),
      "the occupied directory's contents are untouched"
    );
    assert_eq!(
      std::fs::read(&occupied_file).ok(),
      Some(b"a file, not a directory".to_vec()),
      "and so is the occupied file"
    );

    // A candidate sequence that never leaves the occupied name exhausts the
    // bound and reports it typed, rather than spinning forever.
    let mut attempts = 0;
    let exhausted = bind_fresh_cookie_dir(
      &parent,
      &mut || {
        attempts += 1;
        7
      },
      &mut |leaf| std::fs::create_dir(parent.join(leaf)),
    )
    .expect_err("every candidate is occupied");
    assert_eq!(exhausted.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(
      attempts, COOKIE_DIR_MINT_ATTEMPTS,
      "the loop gives up at its bound, having minted exactly that many candidates"
    );

    // And a failure that is not about the candidate aborts on the first draw.
    let mut single = 0;
    let absent = parent.join("no-such-parent");
    let missing = bind_fresh_cookie_dir(
      &absent,
      &mut || {
        single += 1;
        1
      },
      &mut |leaf| std::fs::create_dir(absent.join(leaf)),
    )
    .expect_err("the parent does not exist");
    assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);
    assert_eq!(single, 1, "another name would fail identically");

    std::fs::remove_dir_all(&parent).expect("drop the scratch parent");
  }

  /// Admits a sync under a fresh, unique ticket — the common form for a cell that
  /// does not later cancel by ticket. A cell that DOES cancel binds its own ticket
  /// and calls [`sync_root_keyed`].
  async fn sync_root(
    rig: &Rig,
    scope: ScopeId,
    dir: &str,
    name: &str,
  ) -> Result<PathBuf, crate::error::SyncRootError> {
    sync_root_keyed(rig, scope, dir, name, ticket()).await
  }

  async fn sync_root_keyed(
    rig: &Rig,
    scope: ScopeId,
    dir: &str,
    name: &str,
    ticket: SyncTicket,
  ) -> Result<PathBuf, crate::error::SyncRootError> {
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::SyncRoot {
        scope,
        dir: PathBuf::from(dir),
        name: name.to_owned(),
        ticket,
        reply,
      })
      .await
      .unwrap();
    on_reply.await.expect("the driver replies")
  }

  /// A throwaway core, only for minting the settle fences a direct-registry cell's
  /// admissions park on — these cells build a ledger state by hand, with no driver
  /// loop to settle anything.
  fn fence_source() -> DriverCore {
    DriverCore::new(Duration::from_millis(1), Duration::from_secs(30))
  }

  /// A registry over a ledger nothing else holds — the cells that drive the
  /// registry directly and never exercise the public cleanup ingress.
  fn registry(fs: FakeFs) -> CookieRegistry<FakeFs> {
    let (_, wake) = cookie_ingress();
    CookieRegistry::<FakeFs>::new::<TokioRuntime>(fs, wake.ledger)
  }

  /// A registry and the HANDLE-side ingress over ONE shared ledger — the pair
  /// `spawn_with` mints in production, so a registry-level cell can drive the real
  /// public request against real records with no driver loop in between (the wake
  /// half is returned so the cell owns the token stream).
  fn registry_with_ingress(fs: FakeFs) -> (CookieRegistry<FakeFs>, CookieIngress, CookieWake) {
    let (cleanup, wake) = cookie_ingress();
    let reg = CookieRegistry::<FakeFs>::new::<TokioRuntime>(fs, Arc::clone(&wake.ledger));
    (reg, cleanup, wake)
  }

  /// Admits one sync and dispatches its write, straight against the registry: the
  /// two steps a live driver runs — BIRTH at admission (parked on a fence) and the
  /// `Parked → InPool` transition at that fence's settle — for the cells that need
  /// an in-pool write without a driver loop. Panics if the dispatch refuses, which
  /// for a freshly admitted, unmarked obligation cannot happen.
  /// Admits and dispatches a sync under a fresh ticket sequence, straight against
  /// the registry (see [`dispatched_guard_keyed`] for the cancel-by-ticket form).
  fn dispatched_guard(
    reg: &mut CookieRegistry<FakeFs>,
    core: &mut DriverCore,
    scope: ScopeId,
    name: &str,
  ) -> CookieGuard {
    dispatched_guard_keyed(reg, core, scope, name, ticket().seq())
  }

  fn dispatched_guard_keyed(
    reg: &mut CookieRegistry<FakeFs>,
    core: &mut DriverCore,
    scope: ScopeId,
    name: &str,
    ticket: u64,
  ) -> CookieGuard {
    let fence = core.open_cover_fence(scope);
    let id = reg.admit_parked(scope, name.to_owned(), ticket, fence);
    reg
      .dispatch_guard(scope, id)
      .expect("a freshly admitted obligation dispatches")
  }

  /// Dispatches a sync without awaiting it, holding on to the reply receiver —
  /// the caller can then abandon it, or retire the scope, while the write is
  /// still in the pool.
  /// Dispatches a sync under a fresh ticket without awaiting it (see
  /// [`sync_root_keyed`] for the cancel-by-ticket form).
  async fn sync_root_pending(
    rig: &Rig,
    scope: ScopeId,
    dir: &str,
    name: &str,
  ) -> futures_channel::oneshot::Receiver<Result<PathBuf, crate::error::SyncRootError>> {
    sync_root_pending_keyed(rig, scope, dir, name, ticket()).await
  }

  async fn sync_root_pending_keyed(
    rig: &Rig,
    scope: ScopeId,
    dir: &str,
    name: &str,
    ticket: SyncTicket,
  ) -> futures_channel::oneshot::Receiver<Result<PathBuf, crate::error::SyncRootError>> {
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::SyncRoot {
        scope,
        dir: PathBuf::from(dir),
        name: name.to_owned(),
        ticket,
        reply,
      })
      .await
      .unwrap();
    on_reply
  }

  /// How many cookies the driver still OWNS. The leak oracle: every path that
  /// ends a cookie's life must leave this back where it found it — an unlinked
  /// file with a live record is a slow leak, and a record per failed attempt is
  /// unbounded growth.
  async fn cookie_count(rig: &Rig) -> usize {
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::DebugCookieCount { reply })
      .await
      .unwrap();
    on_reply.await.expect("the driver replies")
  }

  /// How many obligations the driver currently holds a reap mark on. The boundedness oracle: a
  /// mark can only be set on an obligation that exists, and dies with it — so this returns to
  /// zero after every cancel ordering, whatever the interleaving.
  async fn reap_marks(rig: &Rig) -> usize {
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::DebugCookieReapMarks { reply })
      .await
      .unwrap();
    on_reply.await.expect("the driver replies")
  }

  /// The birth/terminal census plus the live record count — the census-equation oracle.
  async fn cookie_census(rig: &Rig) -> (Census, usize) {
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::DebugCookieCensus { reply })
      .await
      .unwrap();
    on_reply.await.expect("the driver replies")
  }

  /// Asserts the census equation over everything the driver has done so far: every obligation ever
  /// born is accounted for exactly once — by one of the three typed terminals, or as a record still
  /// live. It can only hold if EVERY removal went through `retire` naming its evidence, so it is
  /// the standing structural proof that no obligation ever vanishes untyped.
  async fn assert_census_balances(rig: &Rig, scenario: &str) -> Census {
    let (census, live) = cookie_census(rig).await;
    assert!(
      census.balances(live),
      "census equation broken after {scenario}: {census:?} with {live} live",
    );
    census
  }

  /// Settles until the OWNED-cookie count reaches `target` — the async analogue of [`settle`],
  /// for the ledger count that only a `Command` round-trip can read. Gives the real-clock
  /// blocking pool scheduler slices under paused time.
  async fn settle_cookie_count(rig: &Rig, target: usize) {
    for _ in 0..200 {
      if cookie_count(rig).await == target {
        return;
      }
      tokio::task::yield_now().await;
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
  }

  /// Settles until the reap-mark count reaches `target`.
  async fn settle_reap_marks(rig: &Rig, target: usize) {
    for _ in 0..200 {
      if reap_marks(rig).await == target {
        return;
      }
      tokio::task::yield_now().await;
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
  }

  /// Dispatches a sync, retrying the retryable `WriteInFlight` refusal until the single-flight
  /// gate admits it (a completed write clears the gate on its own `CookieWriteDone`, which is
  /// asynchronous relative to the reply). Panics on any other error.
  /// Admits a sync under a fresh ticket, retrying `WriteInFlight` (see
  /// [`admit_sync_keyed`] for the cancel-by-ticket form).
  async fn admit_sync(rig: &Rig, scope: ScopeId, dir: &str, name: &str) -> PathBuf {
    admit_sync_keyed(rig, scope, dir, name, ticket()).await
  }

  async fn admit_sync_keyed(
    rig: &Rig,
    scope: ScopeId,
    dir: &str,
    name: &str,
    ticket: SyncTicket,
  ) -> PathBuf {
    for _ in 0..400 {
      // Reuse the SAME ticket across retries: a `WriteInFlight` refusal admits
      // nothing, so the ticket is unconsumed and a retry through it is not
      // `TicketInUse`.
      match sync_root_keyed(rig, scope, dir, name, ticket).await {
        Ok(path) => return path,
        Err(crate::error::SyncRootError::WriteInFlight) => {
          tokio::task::yield_now().await;
          tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Err(other) => panic!("unexpected sync error: {other:?}"),
      }
    }
    panic!("the single-flight gate never admitted the sync");
  }

  /// The finding-2 retain cells' config: a retry delay comfortably inside a [`settle`] window's
  /// budget, so the driver's own retry still confirms without a hang. The cells bracket their
  /// retained-state observation with holds rather than timing it against this delay, so no
  /// specific value is load-bearing for their determinism.
  fn retain_config() -> DriverConfig {
    DriverConfig {
      cookie_retry_base: Duration::from_millis(200),
      cookie_retry_cap: Duration::from_millis(200),
      cookie_retry_budget: 3,
      cookie_backlog_cap: 8,
      cookie_global_cap: 128,
      ..config()
    }
  }

  /// A live rig whose DRIVER TASK the caller keeps, so a cell can drop the
  /// driver future outright — the cancellation path, which no orderly close
  /// tail ever reaches.
  fn cancellable_rig() -> (Rig, tokio::task::JoinHandle<()>) {
    let fs = FakeFs::new(1);
    fs.put("/r", FileKind::Dir, 1);
    let (cmd_tx, cmd_rx) = async_channel::bounded(16);
    let (cleanup, cookie_wake) = cookie_ingress();
    let (ev_tx, ev_rx) = async_channel::bounded(64);
    let driver = tokio::spawn(run::<TokioRuntime, FakeFs>(
      config(),
      fs.clone(),
      cmd_rx,
      cookie_wake,
      ev_tx,
      NullRegistry,
    ));
    (
      Rig {
        fs,
        commands: cmd_tx,
        cleanup,
        events: ev_rx,
      },
      driver,
    )
  }

  #[tokio::test(flavor = "multi_thread")]
  async fn a_kernel_recursive_root_writes_the_cookie_at_once() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-1-7-1")
      .await
      .expect("the write lands");
    assert_eq!(path, PathBuf::from("/r/.tributaries-sync-1-7-1"));
    assert_eq!(rig.fs.cookie_writes(), vec![path.clone()]);

    // The cookie is a real object now: its create event flows like any file's,
    // which is exactly what makes it a barrier marker.
    rig.fs.send_batch(
      "/r",
      vec![ev("/r/.tributaries-sync-1-7-1", created(), 1, 9001)],
    );
    let (s, change) = next_event(&rig).await;
    assert_eq!(s, scope);
    assert!(change.kind().is_created());
    assert_eq!(
      change.location(),
      &loc(&[".tributaries-sync-1-7-1"]),
      "the cookie's own event rides the root's ordered queue"
    );

    // And it reaps, idempotently — through the public cleanup ingress.
    rig.cleanup.request_remove(&path);
    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    assert_eq!(rig.fs.cookie_removes(), vec![path]);
  }

  #[tokio::test(flavor = "multi_thread")]
  async fn a_read_only_tree_refuses_the_cookie_typed() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;
    rig
      .fs
      .fail_cookie_writes(std::io::ErrorKind::PermissionDenied);

    let outcome = sync_root(&rig, scope, "/r", ".tributaries-sync-1-7-2").await;
    match outcome {
      Err(crate::error::SyncRootError::Write { path, source }) => {
        assert_eq!(path, PathBuf::from("/r/.tributaries-sync-1-7-2"));
        assert_eq!(
          source.kind(),
          std::io::ErrorKind::PermissionDenied,
          "a read-only tree is the honest refusal, not a silent half-barrier"
        );
      }
      other => panic!("expected a typed write refusal, got {other:?}"),
    }
  }

  #[tokio::test(flavor = "multi_thread")]
  async fn a_dead_root_refuses_the_cookie() {
    let rig = rig_with_capacity(64);
    let ghost = ScopeId::new(core::num::NonZeroU64::new(404).unwrap());
    assert!(matches!(
      sync_root(&rig, ghost, "/r", ".tributaries-sync-1-7-3").await,
      Err(crate::error::SyncRootError::UnknownRoot)
    ));
  }

  // The driver owns every cookie it writes: even with NO removal request — the
  // abandoned-after-send case where the caller loses the path — the cookie is
  // unlinked when the driver tears down. This is the guarantee that lets the
  // umbrella source drop its own cookie-removes queue entirely.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_written_cookie_is_reaped_when_the_driver_tears_down() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-1-7-4")
      .await
      .expect("the write lands");
    assert_eq!(rig.fs.cookie_writes(), vec![path.clone()]);
    assert_eq!(
      cookie_count(&rig).await,
      1,
      "the registry owns the landed cookie"
    );
    assert!(
      rig.fs.cookie_removes().is_empty(),
      "no removal was requested — the cookie is still the driver's to reap"
    );

    // Close WITHOUT ever removing the cookie: the driver's terminal reap must
    // unlink it before the close reply lands.
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig.commands.send(Command::Close { reply }).await.unwrap();
    let _ = on_reply.await;

    assert_eq!(
      rig.fs.cookie_removes(),
      vec![path],
      "the driver reaped its written cookie at teardown"
    );
  }

  // A cookie whose scope is retired mid-life (unwatch, not close) is reaped by
  // that scope's stream teardown — the same ownership, one scope at a time.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_written_cookie_is_reaped_when_its_scope_is_retired() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-1-7-5")
      .await
      .expect("the write lands");
    assert_eq!(rig.fs.cookie_writes(), vec![path.clone()]);

    // Retire the scope with no removal request: the stream teardown reaps the
    // cookie the scope still owns (a reply-less, off-reactor unlink).
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(reply),
      })
      .await
      .unwrap();
    assert!(
      on_reply.await.unwrap().is_torn(),
      "the live scope was unwatched"
    );

    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    assert_eq!(
      rig.fs.cookie_removes(),
      vec![path],
      "the retiring scope's stream teardown reaped its written cookie"
    );
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "and it took the record with it — a retired scope leaves nothing behind"
    );
  }

  // A write that FAILS creates no file, so it claims nothing. This is what keeps
  // a long-lived scope's registry bounded: the old ledger recorded the path
  // BEFORE dispatching the write and never took it back on failure, so a
  // read-only tree grew it by one path per attempt, forever.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_failed_cookie_write_records_nothing() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;
    rig
      .fs
      .fail_cookie_writes(std::io::ErrorKind::PermissionDenied);

    for attempt in 0..8 {
      let outcome = sync_root(
        &rig,
        scope,
        "/r",
        &format!(".tributaries-sync-1-8-1-{attempt}"),
      )
      .await;
      assert!(
        matches!(outcome, Err(crate::error::SyncRootError::Write { .. })),
        "the read-only tree refuses every attempt"
      );
      assert_eq!(
        cookie_count(&rig).await,
        0,
        "a failed write records nothing — repeated failures cannot grow the registry (attempt {attempt})"
      );
    }
    assert!(
      rig.fs.cookie_writes().is_empty(),
      "no file was ever created"
    );
    assert!(
      rig.fs.cookie_removes().is_empty(),
      "and none had to be reaped"
    );
  }

  // The caller abandons its sync (a timeout, a dropped future) AFTER the write
  // was dispatched: the file lands into a reply nobody holds. The write reaps it
  // and hands the record back — an unlinked file left recorded would be a leak
  // of a different kind (a sweep chasing a path that no longer exists, forever).
  #[tokio::test(flavor = "multi_thread")]
  async fn an_abandoned_cookie_reply_reaps_and_forgets() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    // Hold the write in the pool: abandoning the reply EARLIER would be the
    // parked-fence prune (no write is ever dispatched), which reaps nothing
    // because nothing was written.
    let hold = rig.fs.hold_cookie_writes();
    let on_reply = sync_root_pending(&rig, scope, "/r", ".tributaries-sync-1-8-2").await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;
    assert_eq!(
      rig.fs.cookie_dispatches(),
      1,
      "the write reached the pool before the caller walked away"
    );

    drop(on_reply);
    hold.release();

    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    let written = rig.fs.cookie_writes();
    assert_eq!(written.len(), 1, "the write really did land");
    assert_eq!(
      rig.fs.cookie_removes(),
      written,
      "the abandoned cookie was reaped by the write itself"
    );
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "no file survives a sync nobody is listening for"
    );
    assert_eq!(cookie_count(&rig).await, 0, "and the record went with it");
  }

  // The scope retires while its write is still in the blocking pool: the
  // teardown's sweep runs BEFORE the file exists, so the sweep alone cannot
  // reap it. The retirement flag is what closes the window — raised before the
  // sweep, checked by the write as it hands the file over, so the write reaps
  // itself instead of landing a cookie behind a sweep that already ran.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cookie_written_for_a_retiring_scope_reaps_itself() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let hold = rig.fs.hold_cookie_writes();
    let on_reply = sync_root_pending(&rig, scope, "/r", ".tributaries-sync-1-8-3").await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;
    assert_eq!(
      rig.fs.cookie_dispatches(),
      1,
      "the write is in the pool, its file not yet created"
    );

    // Retire the scope UNDER the in-flight write.
    let (reply, on_unwatch) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(reply),
      })
      .await
      .unwrap();
    assert!(
      on_unwatch.await.unwrap().is_torn(),
      "the live scope was unwatched"
    );
    assert!(
      rig.fs.cookie_writes().is_empty(),
      "the retirement got there first — the sweep found nothing to unlink"
    );

    hold.release();
    assert!(
      matches!(
        on_reply.await.expect("the driver replies"),
        Err(crate::error::SyncRootError::Retired)
      ),
      "a cookie the dead scope could never report is refused, not silently placed"
    );

    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    assert_eq!(
      rig.fs.cookie_removes(),
      rig.fs.cookie_writes(),
      "the late write reaped the file it had just created"
    );
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "no cookie outlives the scope it was written for"
    );
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "and nothing was recorded for a scope that will never be swept again"
    );
  }

  // A FILE subscription is validly covered (it commits under an armed
  // ancestor), so the cookie key a sync carries can name a file. Writing inside
  // it would fail ENOTDIR and leave the caller with no barrier at all; the
  // cookie lands beside it instead — still under the root, so its create event
  // is still reported on this root's stream.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_covered_file_subscription_writes_its_cookie_in_the_parent_directory() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    rig.fs.put("/r/sub/notes.txt", FileKind::File, 3);

    let path = sync_root(&rig, scope, "/r/sub/notes.txt", ".tributaries-sync-1-8-4")
      .await
      .expect("a covered file subscription can still place its barrier");
    assert_eq!(
      path,
      PathBuf::from("/r/sub/.tributaries-sync-1-8-4"),
      "the cookie lands in the file's containing directory"
    );
    assert_eq!(rig.fs.cookie_writes(), vec![path.clone()]);

    // The barrier still works: the cookie's own create rides this root's queue.
    rig.fs.send_batch(
      "/r",
      vec![ev("/r/sub/.tributaries-sync-1-8-4", created(), 1, 9001)],
    );
    let (got, change) = next_event(&rig).await;
    assert_eq!(got, scope);
    assert!(change.kind().is_created());
    assert_eq!(change.location(), &loc(&["sub", ".tributaries-sync-1-8-4"]));

    // And the registry owns the path the write ACTUALLY landed at — the
    // caller's remove (keyed off that same returned path) finds it.
    assert_eq!(cookie_count(&rig).await, 1);
    rig.cleanup.request_remove(&path);
    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    assert_eq!(rig.fs.cookie_removes(), vec![path]);
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "the remove dropped the record it named"
    );
  }

  // The terminal sweep is a `Drop`, so it is not a step of the orderly close
  // that a cancelled (or panicking) driver task can skip: dropping the driver
  // future where it stands still reaps every cookie it owns — now DETACHED (a
  // best-effort off-reactor unlink), never a synchronous unlink that could
  // wedge the unwind. The runtime outlives the aborted task, so the detached
  // reap still runs.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cancelled_driver_task_still_sweeps_its_cookies() {
    let (rig, driver) = cancellable_rig();
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-1-8-5")
      .await
      .expect("the write lands");
    assert_eq!(rig.fs.cookie_writes(), vec![path.clone()]);
    assert!(rig.fs.cookie_removes().is_empty());

    // No Close, no orderly tail — the driver future is dropped mid-flight.
    driver.abort();
    assert!(
      driver.await.unwrap_err().is_cancelled(),
      "the driver was cancelled, not run to completion"
    );

    // The abnormal-path Drop DISPATCHED its sweep detached (never blocking the
    // unwind); the still-live runtime runs it, reaping the cookie shortly after.
    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    assert_eq!(
      rig.fs.cookie_removes(),
      vec![path],
      "a cancelled driver still sweeps the cookies it owns, best-effort off-reactor"
    );
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "no cookie outlives the driver that wrote it"
    );
  }

  // The write-versus-sweep race, from the far side: the driver is ALREADY GONE
  // when the write creates its file, so the sweep it should have been caught by
  // ran before the file existed — and there is no driver left to tell about it.
  // The shutdown flag is the whole handshake: raised before the sweep takes the
  // paths, checked by the write as it hands its file over, so the write reaps
  // itself. Nothing else can: this file would otherwise outlive the process's
  // watcher with no channel left to ask for its removal.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_write_landing_after_the_driver_is_gone_reaps_itself() {
    let (rig, driver) = cancellable_rig();
    let scope = watch(&rig, "/r").await;

    let hold = rig.fs.hold_cookie_writes();
    let on_reply = sync_root_pending(&rig, scope, "/r", ".tributaries-sync-1-8-6").await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;
    assert_eq!(
      rig.fs.cookie_dispatches(),
      1,
      "the write is in the pool, its file not yet created"
    );

    // The driver dies UNDER the in-flight write: its sweep finds an empty
    // registry (nothing is recorded until a write lands), and it is not around
    // to be told about what happens next.
    driver.abort();
    assert!(driver.await.unwrap_err().is_cancelled());
    assert!(
      rig.fs.cookie_writes().is_empty(),
      "the sweep ran before the file existed — it had nothing to unlink"
    );

    hold.release();
    assert!(
      matches!(
        on_reply.await.expect("the write still answers its caller"),
        Err(crate::error::SyncRootError::Retired)
      ),
      "a barrier no live driver could report is refused"
    );

    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    assert_eq!(
      rig.fs.cookie_removes(),
      rig.fs.cookie_writes(),
      "the write reaped the file it created after its driver was gone"
    );
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "no dispatched write can outlive the registry that dispatched it"
    );
  }

  // The containing-directory fallback may never climb ABOVE the root. The
  // watcher proves `dir` is inside the root, so the parent of a `dir` strictly
  // under it is inside it too — but the ROOT's parent is not, and a root that
  // died under an in-flight sync is exactly a `dir` that is no longer a
  // directory. Unclamped, that sync would drop a cookie in the root's parent:
  // outside the watched tree, unreportable, and litter in someone else's
  // directory. The typed failure is the honest answer instead.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cookie_never_climbs_above_the_root() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;
    // The root's parent is a perfectly good directory — which is exactly the
    // hazard: nothing but the floor stops the fallback from writing into it.
    rig.fs.put("/", FileKind::Dir, 99);

    let hold = rig.fs.hold_cookie_writes();
    let on_reply = sync_root_pending(&rig, scope, "/r", ".tributaries-sync-1-8-7").await;
    assert!(
      settle(|| rig.fs.cookie_dispatches() == 1).await,
      "staging: the write must be PARKED in the pool before the root dies under it"
    );

    // The root dies under the parked write, before the driver has processed its
    // death — the window in which the write still believes the scope is live.
    rig.fs.remove("/r");
    hold.release();

    match on_reply.await.expect("the driver replies") {
      Err(crate::error::SyncRootError::Write { path, source }) => {
        assert_eq!(
          path,
          PathBuf::from("/r/.tributaries-sync-1-8-7"),
          "the refusal names the location the caller asked for"
        );
        assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
      }
      other => panic!("expected a typed write refusal, got {other:?}"),
    }
    assert!(
      rig.fs.cookie_writes().is_empty(),
      "no cookie was created for a root that is gone"
    );
    assert!(
      rig.fs.files_under("/").is_empty(),
      "and nothing landed ABOVE the root, where no event could ever report it"
    );
  }

  // A cookie NAME that is not a single normal component would escape the
  // directory the barrier was validated for once joined — refused before any
  // write, never a silent placement outside coverage.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cookie_name_with_a_separator_is_refused() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    assert!(
      matches!(
        sync_root(&rig, scope, "/r", "sub/evil").await,
        Err(crate::error::SyncRootError::BadCookieName { .. })
      ),
      "a name with a separator is a contract violation, not a barrier"
    );
    assert_eq!(
      rig.fs.cookie_dispatches(),
      0,
      "the write was refused before it could reach the pool"
    );
    assert_eq!(cookie_count(&rig).await, 0);
  }

  // A directory that only appears inside the root through `..` traversal —
  // `/r/../outside` starts_with `/r` component-wise, yet escapes the tree once
  // folded — is refused, closing the lexical escape a plain `starts_with` misses.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cookie_dir_escaping_via_dotdot_is_refused() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    assert!(
      matches!(
        sync_root(&rig, scope, "/r/../outside", ".tributaries-sync-1-9-8").await,
        Err(crate::error::SyncRootError::DirOutsideRoot { .. })
      ),
      "a `..`-escaping directory is outside the root, however it lexes"
    );
    assert_eq!(
      rig.fs.cookie_dispatches(),
      0,
      "the write was refused before it could reach the pool"
    );
    assert_eq!(cookie_count(&rig).await, 0);
  }

  /// Containment is not observability. A cookie directory inside the root but
  /// under an EXCLUSION would take the write and then have its event suppressed
  /// by the very option that asked for the suppression, leaving the caller
  /// parked on an event that cannot exist. Refused before birth — and only for
  /// the excluded subtree, so the rest of the root still syncs.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cookie_dir_under_an_exclusion_is_refused() {
    let rig = rig_with_config(
      64,
      DriverConfig {
        exclusions: vec![PathBuf::from("/r/cache")],
        ..config()
      },
    );
    let scope = watch(&rig, "/r").await;

    // The exclusion itself, a directory below it, and a spelling that only folds
    // into it — the same lexical discipline containment already uses.
    for dir in ["/r/cache", "/r/cache/deep", "/r/./cache"] {
      match sync_root(&rig, scope, dir, ".tributaries-sync-1-9-1").await {
        Err(crate::error::SyncRootError::DirExcluded { exclusion, .. }) => {
          assert_eq!(exclusion, PathBuf::from("/r/cache"));
        }
        other => panic!("{dir} is excluded, so no barrier there is observable: {other:?}"),
      }
    }
    assert_eq!(
      rig.fs.cookie_dispatches(),
      0,
      "the write was refused before it could reach the pool"
    );
    assert_eq!(cookie_count(&rig).await, 0);

    // The refusal belongs to the exclusion, not to exclusions being configured:
    // a covered directory outside every exclusion still places its barrier.
    sync_root(&rig, scope, "/r", ".tributaries-sync-1-9-2")
      .await
      .expect("a directory outside every exclusion still syncs");
    assert_eq!(rig.fs.cookie_dispatches(), 1);
  }

  /// A directory that merely shares a NAME PREFIX with an exclusion is not
  /// inside it — the match is on components, so `/r/cached` survives `/r/cache`.
  #[test]
  fn an_exclusion_covers_a_subtree_not_a_name_prefix() {
    let exclusions = vec![PathBuf::from("/r/cache"), PathBuf::from("relative/skip")];
    let covered = |dir: &str| cookie_dir_excluded(&exclusions, Path::new(dir));

    assert_eq!(covered("/r/cache"), Some(Path::new("/r/cache")));
    assert_eq!(covered("/r/cache/deep/er"), Some(Path::new("/r/cache")));
    assert_eq!(covered("/r/./cache"), Some(Path::new("/r/cache")));
    assert_eq!(
      covered("/r/cached"),
      None,
      "a name prefix is not a subtree — `/r/cached` is not under `/r/cache`"
    );
    assert_eq!(covered("/r/other"), None);
    assert_eq!(covered("/r"), None, "the root itself is not excluded");
    assert_eq!(
      cookie_dir_excluded(&[], Path::new("/r/cache")),
      None,
      "no exclusions, nothing excluded"
    );
    assert_eq!(
      covered("/relative/skip"),
      None,
      "a relative exclusion matches no absolute event path, so it suppresses \
       nothing and refuses nothing"
    );
  }

  // O_NOFOLLOW on the create: a symlink swapped in where the cookie is to land
  // is refused rather than followed to a target that could sit outside the root,
  // where its create event would never meet the barrier.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_final_component_symlink_is_not_followed() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;
    // An adversary places a symlink at the exact path the cookie would take.
    rig
      .fs
      .put("/r/.tributaries-sync-1-9-6", FileKind::Symlink, 77);

    match sync_root(&rig, scope, "/r", ".tributaries-sync-1-9-6").await {
      Err(crate::error::SyncRootError::Write { source, .. }) => {
        assert_eq!(
          source.kind(),
          std::io::ErrorKind::AlreadyExists,
          "the create refuses the symlink instead of following it"
        );
      }
      other => panic!("expected a refused create, got {other:?}"),
    }
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "nothing was claimed for a barrier that could not be written"
    );
  }

  // Containment is not merely lexical. A cookie directory whose SPELLING sits
  // under the root but whose real path escapes it — an ALREADY-EXISTING
  // intermediate symlink `<root>/link` pointing outside, needing no swap — passes
  // the lexical check yet must be refused. The write canonicalizes the directory
  // (resolving the link) and verifies the result is beneath the canonical root
  // before creating anything, so no cookie lands outside the watched tree, where
  // its create event could never be reported on this root's stream.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_preexisting_intermediate_symlink_dir_is_refused() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;
    // `/r/link` is an existing symlink to `/outside`, so `/r/link/sub` really is
    // `/outside/sub`: it exists as a directory and its spelling passes the lexical
    // containment check, but it canonicalizes OUTSIDE the root.
    rig.fs.put("/r/link/sub", FileKind::Dir, 2);
    rig.fs.resolve_cookie_dir_to("/r/link/sub", "/outside/sub");

    match sync_root(&rig, scope, "/r/link/sub", ".tributaries-sync-1-9-7").await {
      Err(crate::error::SyncRootError::Write { source, .. }) => {
        assert_eq!(
          source.kind(),
          std::io::ErrorKind::Other,
          "the write refuses a directory that resolves outside the root"
        );
      }
      other => panic!("expected a refused write, got {other:?}"),
    }
    assert!(
      rig.fs.cookie_writes().is_empty(),
      "no cookie was created for a directory outside the root"
    );
    assert!(
      rig.fs.files_under("/outside").is_empty(),
      "and nothing landed outside the watched tree"
    );
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "nothing was claimed for a barrier that could not be written"
    );
  }

  // A write dispatched under the pre-replace root carries the generation current
  // at DISPATCH; a replace commit bumps it, so the write's claim is refused and
  // its file reaped — never a cookie the new stream could not report. Without the
  // generation check the stale write would claim, strand its barrier, and leave a
  // file outside coverage.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_write_dispatched_under_the_old_root_is_revoked_after_replace() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r2", FileKind::Dir, 2);
    let scope = watch(&rig, "/r").await;

    // The write is dispatched — its guard captures generation 0 — and parks in
    // the pool on the hold gate.
    let hold = rig.fs.hold_cookie_writes();
    let on_reply = sync_root_pending(&rig, scope, "/r", ".tributaries-sync-1-9-5").await;
    assert!(
      settle(|| rig.fs.cookie_dispatches() == 1).await,
      "staging: the write must be PARKED in the pool before the replace bumps the generation"
    );

    // Replace the root BEFORE the write lands: the commit bumps the generation.
    let (reply, on_replace) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r2"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
        reply,
      })
      .await
      .unwrap();
    on_replace
      .await
      .expect("driver replies")
      .expect("the swap commits");

    // Release the held write: it completes under the SUPERSEDED generation and
    // must not claim.
    hold.release();
    assert!(
      matches!(
        on_reply.await.expect("the driver replies"),
        Err(crate::error::SyncRootError::Retired)
      ),
      "a write under the old root is revoked, not silently committed"
    );
    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    assert_eq!(
      rig.fs.cookie_removes(),
      rig.fs.cookie_writes(),
      "the revoked write reaped the file it had created"
    );
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "no cookie survives under the superseded root"
    );
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "and nothing was recorded for a barrier that never claimed"
    );
  }

  // The generation bump that revokes a stale cookie write must land AT the lane
  // swap, not at the run loop's post-commit call. A write RELEASED in the window
  // after the swap — the new stream is live, the old lane retired — but before
  // that later call would otherwise claim under the still-old generation and
  // strand its barrier on the retired lane. The bump moved INTO `commit_replace`,
  // before the swap and under the ledger lock, so a claim in this window reads the
  // new generation and is refused. The gated registry freezes the owner loop at
  // the commit's registry overwrite — after the swap, before the post-commit
  // cookie call — which is exactly the window; the write is released there.
  //
  // MUST FAIL (the write wrongly commits, replying `Ok`) if the bump sits at the
  // old post-commit site: frozen here, that site has not run, so the generation
  // still matches the one the write captured.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_write_released_after_the_stream_swap_but_before_the_old_bump_site_is_revoked() {
    let registry = GatedRegistry::default();
    let rig = rig_with(64, registry.clone());
    rig.fs.put("/r2", FileKind::Dir, 2);
    let scope = watch(&rig, "/r").await;

    // The write is dispatched under the current root — its guard captures
    // generation 0 — and parks in the pool, its file not yet created.
    let hold = rig.fs.hold_cookie_writes();
    let on_reply = sync_root_pending(&rig, scope, "/r", ".tributaries-sync-1-9-9").await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;

    // Freeze the owner loop at the replace commit's registry overwrite — PAST the
    // lane swap (and, with the fix, past the generation bump), BEFORE the run
    // loop's post-commit cookie call.
    let commit = registry.hold_scope_live();
    let (reply, on_replace) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r2"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
        reply,
      })
      .await
      .unwrap();
    settle(|| registry.scope_live_frozen()).await;
    assert!(
      registry.scope_live_frozen(),
      "the owner loop is frozen in the commit, past the swap"
    );

    // Release the held write INTO that window: with the bump at the swap, the
    // live generation has already moved past the one the write captured, so the
    // claim is refused — never a barrier committed to the retired lane.
    hold.release();
    assert!(
      matches!(
        on_reply.await.expect("the write answers its caller"),
        Err(crate::error::SyncRootError::Retired)
      ),
      "a write released after the swap is revoked, not committed under the stale generation"
    );

    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    assert_eq!(
      rig.fs.cookie_removes(),
      rig.fs.cookie_writes(),
      "the revoked write reaped the file it had created"
    );
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "no cookie survives on the superseded root"
    );

    // Let the frozen commit finish; the barrier count is back to zero.
    commit.release();
    on_replace
      .await
      .expect("driver replies")
      .expect("the swap commits");
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "nothing was recorded for a barrier that never claimed"
    );
  }

  // The completed-cookie reap never touches the command channel, so a saturated
  // one cannot drop it: the request is a mark on the obligation itself. With the
  // 16-slot command channel provably full, every reap still lands and the registry
  // returns to zero while the scope stays live. A single-threaded runtime makes
  // the saturation deterministic: the fill burst yields nowhere, so the driver
  // cannot drain a slot until the next await. MUST hang (or leak) if the removal
  // rode the command channel.
  #[tokio::test(flavor = "current_thread")]
  async fn saturated_command_channel_still_reaps_completed_cookies() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    // Complete several syncs; the registry now owns their cookies.
    let mut cookies = Vec::new();
    for seq in 0..4 {
      let name = format!(".tributaries-sync-1-9-9-{seq}");
      cookies.push(
        sync_root(&rig, scope, "/r", &name)
          .await
          .expect("the write lands"),
      );
    }
    assert_eq!(cookie_count(&rig).await, cookies.len());

    // Saturate the 16-slot command channel: this burst never awaits, so on a
    // single-threaded runtime the driver cannot drain a slot mid-fill.
    for _ in 0..16 {
      let (reply, _rx) = futures_channel::oneshot::channel::<usize>();
      rig
        .commands
        .try_send(Command::DebugCookieCount { reply })
        .expect("a command slot is free");
    }
    let (reply, _rx) = futures_channel::oneshot::channel::<usize>();
    assert!(
      rig
        .commands
        .try_send(Command::DebugCookieCount { reply })
        .is_err(),
      "the command channel is saturated"
    );

    // Every completed cookie reaps despite the jammed command channel — and the
    // request cannot even be expressed as a refusal: it is a mark on a record the
    // driver already holds, so there is no channel here to jam and no outcome to
    // check.
    for path in &cookies {
      rig.cleanup.request_remove(path);
    }

    // Draining the fillers frees the command channel; the reaps land, the
    // registry empties, and the scope is still live.
    settle(|| rig.fs.cookie_removes().len() == cookies.len()).await;
    let mut reaped = rig.fs.cookie_removes();
    reaped.sort();
    let mut expected = cookies.clone();
    expected.sort();
    assert_eq!(reaped, expected, "every completed cookie was unlinked");
    assert_eq!(cookie_count(&rig).await, 0, "the registry returned to zero");
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "no cookie file lingers"
    );
    // The scope never died — a fresh barrier still lands.
    sync_root(&rig, scope, "/r", ".tributaries-sync-1-9-9-live")
      .await
      .expect("the scope is still live after the reaps");
  }

  // A transient unlink failure must not orphan the cookie: the record is
  // RETAINED (dropped only when the unlink confirms) so the path stays eligible
  // for a later sweep, and the DRIVER'S OWN backed-off retry — not a second
  // request from the caller — eventually removes it (finding 3). The old
  // fire-and-forget unlink ignored every error, silently stranding the file.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_transient_unlink_failure_retains_the_cookie_until_it_succeeds() {
    let rig = rig_with_config(64, retain_config());
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-4-1-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1, "the registry owns the cookie");

    // Hold every remove so the first (about to be refused) dispatch is captured in flight,
    // deterministically, rather than racing the driver's own retry to observe it.
    let hold = rig.fs.hold_cookie_removes();
    rig.fs.fail_next_cookie_removes(1);
    rig.cleanup.request_remove(&path);
    settle(|| rig.fs.cookie_remove_dispatches() == 1 && hold.captured() == 1).await;
    let first_dispatch = rig.fs.cookie_remove_dispatches();

    // Arm a hold for the driver's OWN retry BEFORE releasing the first attempt, so that whenever
    // its backoff fires — however long the test task stalls in between — the retry is captured
    // in flight too, rather than racing the RETAINED-state observation below.
    let retry_hold = rig.fs.hold_cookie_removes();
    hold.release();

    settle(|| rig.fs.cookie_remove_dispatches() == 2).await;
    let dispatches_before_retry_runs = rig.fs.cookie_remove_dispatches();
    let removed_before_retry = rig.fs.cookie_removes();
    let retained_count = cookie_count(&rig).await;
    let file_present = !rig.fs.files_under("/r").is_empty();
    retry_hold.release();

    assert_eq!(
      first_dispatch, 1,
      "the unlink reached the pool and was refused"
    );
    assert!(
      removed_before_retry.is_empty(),
      "a failed unlink records no removal"
    );
    assert_eq!(
      retained_count, 1,
      "the record is RETAINED across the transient failure — never orphaned"
    );
    assert!(
      file_present,
      "the file is still on disk, still eligible for a retry"
    );
    assert_eq!(
      dispatches_before_retry_runs, 2,
      "exactly two dispatches so far: the failed attempt and the driver's own retry, held before it runs"
    );

    // No second request is needed: the DRIVER OWNS the retry (finding 3). Released, it succeeds
    // and drops the record — the requester never asks twice (the old design's requester-driven
    // re-reap is gone).
    settle(|| rig.fs.cookie_removes().contains(&path)).await;
    assert!(
      rig.fs.cookie_removes().contains(&path),
      "the driver's own retry removed the cookie with no second request"
    );
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      2,
      "still exactly two dispatches: the failed attempt and the driver's own retry"
    );
    // Both halves waited on, and the STAGING half's verdict asserted. The unlink
    // landing in the fake and the driver dropping its ledger record are two
    // observables with a real window between them, so a settle on the file alone
    // left the count assertion below to fail as though the record had leaked when
    // it had merely not been dropped yet.
    assert!(
      settle(|| rig.fs.files_under("/r").is_empty()).await,
      "staging: the driver's own retry confirmed the unlink"
    );
    settle_cookie_count(&rig, 0).await;
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "the record dropped only once the unlink confirmed"
    );
  }

  // Single-flight per scope: while one physical write is outstanding, a second
  // sync is refused `WriteInFlight` rather than dispatching another — so a caller
  // that times out and retries cannot pile unbounded blocking writes against a
  // hung mount. Once the first write resolves the gate reopens.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_second_sync_while_a_write_is_in_flight_is_refused() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    // Hold the first write in the pool: the scope is now IN FLIGHT.
    let hold = rig.fs.hold_cookie_writes();
    let first = sync_root_pending(&rig, scope, "/r", ".tributaries-sync-2-1-1").await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;
    assert_eq!(
      rig.fs.cookie_dispatches(),
      1,
      "the first write is dispatched and outstanding"
    );

    // A second sync for the SAME scope is refused, never dispatched.
    assert!(
      matches!(
        sync_root(&rig, scope, "/r", ".tributaries-sync-2-1-2").await,
        Err(crate::error::SyncRootError::WriteInFlight)
      ),
      "a second sync while a write is in flight is refused single-flight"
    );
    assert_eq!(
      rig.fs.cookie_dispatches(),
      1,
      "the refusal never reached the pool — still exactly one write dispatched"
    );

    // Release the first write: it lands.
    hold.release();
    let path = first
      .await
      .expect("the driver replies")
      .expect("the first write lands");
    assert_eq!(rig.fs.cookie_writes(), vec![path.clone()]);

    // The gate reopens once the write fully resolves; a caller retries the
    // (retryable) refusal until admitted.
    let mut again = None;
    for _ in 0..200 {
      match sync_root(&rig, scope, "/r", ".tributaries-sync-2-1-3").await {
        Ok(fresh) => {
          again = Some(fresh);
          break;
        }
        Err(crate::error::SyncRootError::WriteInFlight) => {
          tokio::task::yield_now().await;
          tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Err(other) => panic!("unexpected sync error: {other:?}"),
      }
    }
    let again = again.expect("the single-flight gate reopened after the first write");
    assert_ne!(again, path, "the second barrier is its own cookie");
  }

  // A live sync obligation holds its rendered cookie name against EVERY other
  // admission for that name watcher-wide — including a DIFFERENT scope's. The gate's
  // role is PHYSICAL identity: one live obligation per name ⇒ per path, so two live
  // syncs never contend one cookie file. Refusing the second admission `NameInUse`
  // keeps `by_name` an injection; the holder is then reaped incarnation-precisely
  // through its own TICKET, to its terminal — no scope teardown involved.
  //
  // Fail-on-old (the unconditional `by_name` insert): the cross-scope admission
  // returns `Ok` and displaces the name, so the `NameInUse` assertion fails
  // IMMEDIATELY — no settle-hang.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_live_cookie_name_is_refused_across_scopes_and_cancel_by_ticket_reaps_the_holder() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/ra", FileKind::Dir, 100);
    rig.fs.put("/rb", FileKind::Dir, 101);
    let scope_a = watch(&rig, "/ra").await;
    let scope_b = watch(&rig, "/rb").await;
    let name = ".tributaries-sync-shared-name";

    // A admits and owns its cookie under `name` at /ra, keyed by its own ticket.
    let ta = ticket();
    let path_a = admit_sync_keyed(&rig, scope_a, "/ra", name, ta).await;
    assert_eq!(path_a, PathBuf::from("/ra/.tributaries-sync-shared-name"));
    settle_cookie_count(&rig, 1).await;

    // B — a DIFFERENT scope — is refused `NameInUse`: A's live obligation holds the
    // name watcher-wide.
    assert!(
      matches!(
        sync_root(&rig, scope_b, "/rb", name).await,
        Err(crate::error::SyncRootError::NameInUse { .. })
      ),
      "a second live obligation under a held name is refused across scopes"
    );
    assert_eq!(
      cookie_count(&rig).await,
      1,
      "the refused admission minted no record — still exactly A's one obligation"
    );

    // Cancel BY TICKET: A's ticket resolves A alone and reaps the delivered-but-unread
    // holder to its terminal.
    rig.cleanup.request_cancel(ta);
    settle(|| rig.fs.files_under("/ra").is_empty() && !rig.fs.cookie_removes().is_empty()).await;
    settle_cookie_count(&rig, 0).await;
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "cancel-by-ticket reaped the holder A"
    );
    assert!(
      rig.fs.files_under("/ra").is_empty(),
      "A's cookie file is gone"
    );
    assert_census_balances(&rig, "cross-scope name refusal then cancel-by-ticket").await;
  }

  // A cookie name is bound to its holder only until that holder reaches a typed
  // terminal. Once the holder's cookie is confirmed removed the name is free and a
  // fresh sync reuses it. But while a holder is still live — here its unlink
  // dispatched and HELD mid-flight, a `Removing` record whose `by_name` entry
  // stands until retire — a fresh sync under that name is refused `NameInUse`, not
  // `WriteInFlight` (the record is neither `Parked` nor `InPool`). Releasing the
  // unlink retires the holder, frees the name, and the retry admits.
  //
  // Fail-on-old (the unconditional `by_name` insert): the held-window sync is
  // admitted `Ok` instead of `NameInUse` — the assertion fails immediately.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cookie_name_frees_at_its_holders_terminal_so_sequential_reuse_admits() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;
    let name = ".tributaries-sync-reuse";

    // First holder: write, own, then reap and CONFIRM — the name frees at retire.
    let path = admit_sync(&rig, scope, "/r", name).await;
    settle_cookie_count(&rig, 1).await;
    rig.cleanup.request_remove(&path);
    settle(|| rig.fs.files_under("/r").is_empty() && !rig.fs.cookie_removes().is_empty()).await;
    settle_cookie_count(&rig, 0).await;

    // Sequential reuse of the freed name admits.
    let reused = admit_sync(&rig, scope, "/r", name).await;
    assert_eq!(
      reused, path,
      "the freed name is reusable — sequential reuse admits"
    );
    settle_cookie_count(&rig, 1).await;

    // The transient window: reap the second holder but HOLD its unlink in the pool,
    // so the record sits `Removing` with its `by_name` entry still standing.
    let hold = rig.fs.hold_cookie_removes();
    rig.cleanup.request_remove(&reused);
    settle(|| rig.fs.cookie_remove_dispatches() == 2).await;
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      2,
      "the second unlink is dispatched and held mid-flight"
    );

    // A fresh sync under the still-held name is refused `NameInUse` — the holder is
    // live (`Removing`), so `has_pending_write` is false and the single-flight
    // signal does not apply. Capture the outcome, then RELEASE the hold before
    // asserting: a failed assertion (the fail-on-old path) must not strand the held
    // blocking job, which would wedge the runtime's shutdown rather than fail fast.
    let held_window = sync_root(&rig, scope, "/r", name).await;
    hold.release();
    assert!(
      matches!(
        held_window,
        Err(crate::error::SyncRootError::NameInUse { .. })
      ),
      "a fresh sync under a name whose holder is still mid-unlink is refused NameInUse"
    );

    // The released unlink lets the holder confirm, retire, and free the name; the
    // retry admits.
    settle(|| rig.fs.files_under("/r").is_empty()).await;
    settle_cookie_count(&rig, 0).await;
    let again = admit_sync(&rig, scope, "/r", name).await;
    assert_eq!(
      again, path,
      "once the holder retires the name frees and the retry admits"
    );

    // Clean the last holder so close proves quiescence.
    rig.cleanup.request_remove(&again);
    settle_cookie_count(&rig, 0).await;
    assert_census_balances(&rig, "sequential reuse across a held then freed name").await;
  }

  // The refusal ORDER at admission: `WriteInFlight` precedes `NameInUse`, and a
  // `NameInUse` refusal creates nothing. While a same-scope write is still in the
  // pipeline (`Parked`/`InPool`) a same-name retry reads the transient
  // single-flight signal `WriteInFlight` — renaming is not its remedy. Only once
  // the holder leaves the pipeline (here, `Owned`) does a same-name admission read
  // the permanent `NameInUse`, and that refusal mints no record and no census
  // birth.
  #[tokio::test(flavor = "multi_thread")]
  async fn write_in_flight_precedes_name_in_use_and_a_refusal_creates_nothing() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;
    let name = ".tributaries-sync-order";

    // Hold the first write in the pool: the holder is `InPool`, its name already in
    // `by_name` (inserted at birth). A same-name retry reads `WriteInFlight`, NOT
    // `NameInUse` — the single-flight signal wins while the write is pending.
    let hold = rig.fs.hold_cookie_writes();
    let first = sync_root_pending(&rig, scope, "/r", name).await;
    assert!(
      settle(|| rig.fs.cookie_dispatches() == 1).await,
      "staging: the holder's write must be in the pool, or the retry below reads a different refusal"
    );
    assert!(
      matches!(
        sync_root(&rig, scope, "/r", name).await,
        Err(crate::error::SyncRootError::WriteInFlight)
      ),
      "a same-name retry while the write is in the pool reads WriteInFlight, not NameInUse"
    );

    // Release the write: the holder becomes `Owned`.
    hold.release();
    let path = first
      .await
      .expect("the driver replies")
      .expect("the first write lands");
    settle_cookie_count(&rig, 1).await;
    let (before, live_before) = cookie_census(&rig).await;

    // Now a same-name admission reads `NameInUse` — the write is no longer pending.
    assert!(
      matches!(
        sync_root(&rig, scope, "/r", name).await,
        Err(crate::error::SyncRootError::NameInUse { .. })
      ),
      "once the holder is Owned a same-name admission reads NameInUse"
    );

    // The refusal created nothing: the live count and the census birth tally are
    // exactly where they were.
    let (after, live_after) = cookie_census(&rig).await;
    assert_eq!(
      live_after, live_before,
      "the NameInUse refusal minted no record"
    );
    assert_eq!(after.births, before.births, "…and no census birth");
    assert_eq!(cookie_count(&rig).await, 1, "still exactly the one holder");

    // Cleanup for a quiescent close.
    rig.cleanup.request_remove(&path);
    settle_cookie_count(&rig, 0).await;
    assert_census_balances(&rig, "order and no-residue on a NameInUse refusal").await;
  }

  // A physical write still outstanding at close makes close report `NotQuiesced`
  // with the write counted — honest, never an indefinite hang. The write rides
  // the same `pending_cookie_ops` accounting a teardown does.
  #[tokio::test(flavor = "multi_thread")]
  async fn an_outstanding_cookie_write_makes_close_report_not_quiesced() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    // Hold a write in the pool: it is outstanding when close begins.
    let hold = rig.fs.hold_cookie_writes();
    let on_reply = sync_root_pending(&rig, scope, "/r", ".tributaries-sync-2-2-1").await;
    assert!(
      settle(|| rig.fs.cookie_dispatches() == 1).await,
      "staging: the write must be OUTSTANDING in the pool when close begins"
    );

    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    let pending = tokio::time::timeout(interpreted_secs(5), on_close)
      .await
      .expect("close resolves at the grace boundary, not an indefinite hang")
      .expect("the driver replied");
    assert_eq!(
      pending, 1,
      "the outstanding write is counted — close is honest, not wedged"
    );

    // The released write's claim is refused against the raised shutdown flag, and
    // its self-reap unlink happens-before the sync reply is sent — so awaiting the
    // reply is the deterministic reap witness (no settle race on the create window).
    hold.release();
    let outcome = on_reply.await;
    assert!(
      matches!(outcome, Ok(Err(crate::error::SyncRootError::Retired))),
      "{outcome:?}"
    );
    assert_eq!(
      rig.fs.cookie_removes().len(),
      1,
      "the late write reaped the file it created"
    );
    assert!(rig.fs.files_under("/r").is_empty());
  }

  // A hung TERMINAL unlink must never wedge close: the orderly sweep dispatches
  // it as a tracked, grace-covered job, so close returns `NotQuiesced` within the
  // grace instead of blocking forever inside a synchronous Drop.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_hung_terminal_unlink_does_not_wedge_close() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-3-1-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1);

    // The terminal unlink hangs.
    let hold = rig.fs.hold_cookie_removes();
    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    let pending = tokio::time::timeout(interpreted_secs(5), on_close)
      .await
      .expect("close returns within the grace, never wedged on a hung unlink")
      .expect("the driver replied");
    assert_eq!(
      pending, 1,
      "the hung terminal unlink is counted, not papered over"
    );

    // Released, the unlink completes and the cookie is gone.
    hold.release();
    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    assert!(rig.fs.cookie_removes().contains(&path));
    settle(|| rig.fs.files_under("/r").is_empty()).await;
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "the hung unlink completed once the mount unwedged"
    );
  }

  // The abnormal-path Drop dispatches its unlinks DETACHED, so it never blocks
  // the unwind: a cancelled driver whose terminal unlink is hung still returns
  // promptly (the OLD synchronous Drop would hang here forever), and the reap is
  // still ATTEMPTED best-effort off-reactor.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cancelled_driver_with_a_hung_unlink_does_not_block_its_drop() {
    let (rig, driver) = cancellable_rig();
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-3-2-1")
      .await
      .expect("the write lands");
    assert_eq!(rig.fs.cookie_writes(), vec![path.clone()]);

    // The terminal unlink hangs, then the driver is cancelled: Drop must not
    // block on the unlink.
    let hold = rig.fs.hold_cookie_removes();
    driver.abort();
    let joined = tokio::time::timeout(interpreted_secs(5), driver).await;
    assert!(
      joined.is_ok(),
      "Drop dispatched its unlink detached — the unwind was never blocked on the hung remove"
    );
    assert!(joined.unwrap().unwrap_err().is_cancelled());

    // The reap was still attempted (detached, parked on the hung mount).
    settle(|| rig.fs.cookie_remove_dispatches() == 1).await;
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      1,
      "the abnormal-path Drop still dispatches the reap best-effort"
    );

    // Released, the detached unlink completes.
    hold.release();
    settle(|| !rig.fs.cookie_removes().is_empty()).await;
    assert!(rig.fs.cookie_removes().contains(&path));
  }

  // Finding 1 (fs half): a cancel for a cookie whose write LANDED and CLAIMED — its
  // `reply.send(Ok)` succeeded because the caller's receiver was alive, so the write's own
  // send-failure self-reap did NOT run — but the caller never read it reaps the OWNED cookie
  // through the ledger. This is the delivered-but-unread cookie the umbrella's abandon arm names
  // by token; without the cancel it would survive until teardown.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cancel_for_a_delivered_but_unread_cookie_reaps_it() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let name = ".tributaries-sync-1-1-1";
    let path = PathBuf::from("/r").join(name);
    let t = ticket();
    // The write lands and CLAIMS while the caller's receiver is alive but unread.
    let on_reply = sync_root_pending_keyed(&rig, scope, "/r", name, t).await;
    settle(|| rig.fs.cookie_writes() == vec![path.clone()]).await;
    settle_cookie_count(&rig, 1).await;
    assert_eq!(
      cookie_count(&rig).await,
      1,
      "the write's Ok reply succeeded and the cookie is OWNED, unread"
    );

    // The caller walks away UNREAD. The driver already saw its send succeed, so nothing
    // self-reaps — the cookie would survive without the token cancel.
    drop(on_reply);

    // The abandon arm cancels by TICKET: the driver finds it OWNED and reaps it through the
    // removal state machine.
    rig.cleanup.request_cancel(t);
    settle(|| rig.fs.cookie_removes().contains(&path)).await;
    assert!(
      rig.fs.cookie_removes().contains(&path),
      "the owned cookie was unlinked by the cancel"
    );
    settle_cookie_count(&rig, 0).await;
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "the record went with the confirmed unlink"
    );
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "no file survives the cancel of a delivered-but-unread cookie"
    );

    // The gate and scope are unharmed — a fresh sync still lands.
    admit_sync(&rig, scope, "/r", ".tributaries-sync-1-1-2").await;
  }

  // A reap mark that lands while a record is Removing COALESCES (the mark stays) and spends the
  // record's sole capacity-1 wake token. If that arming then fails all the way to its budget, the
  // failing completion SERVICES the standing mark — consumes it into exactly one fresh arming —
  // rather than parking the record stranded with the mark set but no wake and no deadline. Without
  // this, an idle watcher would retain the cookie until an unrelated event or teardown.
  //
  // Fail-on-old (schedule_retry parks a marked record past the budget without consuming the mark):
  // the mark stays set with an empty wake channel and `retry_at` None, so no sweep and no retry ever
  // re-examine it — `reap_marks` never returns to 0 and the settle-then-assert fails.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_standing_reap_mark_is_serviced_at_retry_exhaustion() {
    let mut config = tuned_config();
    config.cookie_retry_budget = 0; // one attempt per arming, then exhaustion
    let rig = rig_with_config(64, config);
    let scope = watch(&rig, "/r").await;
    let t = ticket();
    let path = admit_sync_keyed(&rig, scope, "/r", ".tributaries-sync-strand", t).await;
    settle_cookie_count(&rig, 1).await;

    // Every unlink fails; hold them so the first reap's dispatched unlink is frozen mid-flight.
    rig.fs.fail_cookie_removes_under("/r");
    let hold = rig.fs.hold_cookie_removes();

    // Reap 1 (Owned + mark): the sweep clears the mark, moves the record to Removing, and spawns the
    // (now-held) unlink.
    rig.cleanup.request_remove(&path);
    settle_reap_marks(&rig, 0).await;
    assert_eq!(
      reap_marks(&rig).await,
      0,
      "the Owned reap dispatched and cleared its own mark",
    );

    // Reap 2 (Removing + mark): coalesces onto the in-flight unlink — the mark STAYS, and its sole
    // wake token is spent by the coalescing sweep.
    rig.cleanup.request_cancel(t);
    settle_reap_marks(&rig, 1).await;
    assert_eq!(
      reap_marks(&rig).await,
      1,
      "the second request's mark stands on the Removing record",
    );

    // Release: the held unlink runs, FAILS, the record parks, and its completion exhausts the
    // (zero) budget — the point where a standing mark is serviced.
    hold.release();

    // NEW: the exhaustion clause consumes the standing mark. OLD: it is stranded at 1, with no wake
    // and no deadline to ever revisit it.
    settle_reap_marks(&rig, 0).await;
    assert_eq!(
      reap_marks(&rig).await,
      0,
      "the standing mark is serviced (consumed) at the failing arming's budget exhaustion",
    );

    // No leak: the serviced record is a normal parked obligation — a fresh reap on a healed fs reaps
    // it to its typed terminal.
    rig.fs.clear_cookie_remove_failures_under("/r");
    rig.cleanup.request_remove(&path);
    settle_cookie_count(&rig, 0).await;
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "the serviced-then-healed cookie reaps to its terminal",
    );
    assert!(rig.fs.files_under("/r").is_empty(), "no file survives");
    assert_census_balances(&rig, "a serviced standing reap mark").await;
  }

  // Spin guard: servicing a standing mark grants EXACTLY ONE fresh arming (the mark is consumed in
  // the same critical section as the grant), so a permafailing unlink cannot loop fail -> re-arm ->
  // fail. After the one serviced arming also exhausts, the record parks UNMARKED — the accepted
  // demand-driven floor — and stays there.
  #[tokio::test(flavor = "multi_thread")]
  async fn servicing_a_standing_mark_grants_exactly_one_fresh_arming() {
    let mut config = tuned_config();
    config.cookie_retry_budget = 0;
    let rig = rig_with_config(64, config);
    let scope = watch(&rig, "/r").await;
    let t = ticket();
    let path = admit_sync_keyed(&rig, scope, "/r", ".tributaries-sync-spin", t).await;
    settle_cookie_count(&rig, 1).await;

    rig.fs.fail_cookie_removes_under("/r"); // stays failing for the whole cell
    let hold = rig.fs.hold_cookie_removes();
    rig.cleanup.request_remove(&path);
    settle_reap_marks(&rig, 0).await;
    rig.cleanup.request_cancel(t);
    settle_reap_marks(&rig, 1).await;
    hold.release();

    // The mark is consumed into one fresh arming; that arming also fails and the record parks
    // UNMARKED — no fail -> re-arm loop keeps re-setting the mark.
    settle_reap_marks(&rig, 0).await;
    assert_eq!(
      reap_marks(&rig).await,
      0,
      "the mark is consumed, not re-set in a loop"
    );

    // The real dispatch count is the discriminator an unconditional re-arm spin would fail: one
    // attempt at budget 0, plus exactly the one serviced arming's own attempt — never a third.
    settle(|| rig.fs.cookie_remove_dispatches() == 2).await;
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      2,
      "exactly two attempts: the original arming and the one arming the serviced mark granted"
    );

    // Over a generous window the state is stable: the mark stays 0 and the record stays one parked
    // obligation (a spin would keep re-marking or churn the count).
    for _ in 0..20 {
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(reap_marks(&rig).await, 0, "no re-arm loop re-sets the mark");
    assert_eq!(
      cookie_count(&rig).await,
      1,
      "the unremovable cookie is one stable parked obligation",
    );
    assert!(
      !rig.fs.files_under("/r").is_empty(),
      "the file is still on the failing fs",
    );
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      2,
      "still exactly two dispatches after the stability window — a spin would have kept climbing"
    );
  }

  // The mark/wake protocol's OTHER completion route: a cancel that lands while a write sits in
  // the pool marks that write's own in-pool record, and the sole wake token is consumed by the
  // coalescing sweep that finds it InPool (the mark is what the landing claim is meant to read).
  // If the claim then refuses on that mark and its self-reap's own unlink ALSO fails, the record
  // survives parked with the mark STILL SET, so its completion reaches `schedule_retry` through
  // the write-done call site rather than the remove-done one every mark+retry-exhaustion cell
  // above drives. This pins the single-request, umbrella-reachable shape: the one servicing
  // clause must consume the mark from either call site, not just the remove-done one.
  //
  // Fail-on-old (schedule_retry parks a marked record past the budget without consuming the
  // mark): the mark stays set with an empty wake channel and `retry_at` None, so nothing left
  // ever re-examines it — `reap_marks` never returns to 0 and the bounded settle-then-assert
  // below fails (does not hang).
  #[tokio::test(flavor = "multi_thread")]
  async fn a_mark_surviving_a_refused_claims_failed_self_reap_is_serviced_at_write_done() {
    let mut config = tuned_config();
    config.cookie_retry_budget = 0;
    let rig = rig_with_config(64, config);
    let scope = watch(&rig, "/r").await;

    let name = ".tributaries-sync-strand-writedone";
    let path = PathBuf::from("/r").join(name);

    // Hold the write in the pool: DISPATCHED, not yet claimed.
    let hold = rig.fs.hold_cookie_writes();
    let t = ticket();
    let on_reply = sync_root_pending_keyed(&rig, scope, "/r", name, t).await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;
    assert_eq!(
      rig.fs.cookie_dispatches(),
      1,
      "the write is in the pool, not yet claimed"
    );

    // Cancel by ticket while it is in the pool: marks the InPool record, and the sole wake token is
    // consumed by the coalescing sweep that finds it InPool.
    rig.cleanup.request_cancel(t);
    settle_reap_marks(&rig, 1).await;
    assert_eq!(
      reap_marks(&rig).await,
      1,
      "an in-pool write's cancel marks its own obligation"
    );

    // Arm the unlink to fail BEFORE releasing the write: the refused claim's self-reap must fail
    // too, so the record survives parked instead of retiring with the mark.
    rig.fs.fail_cookie_removes_under("/r");

    // Release: the claim reads the mark and REFUSES; the self-reap re-asserts the record and
    // unlinks; that unlink FAILS; the record parks RemoveFailed still carrying the mark, and its
    // `CookieWriteDone` reaches `schedule_retry` with attempts 1 > budget 0 — exhaustion at the
    // write-done call site.
    hold.release();
    assert!(
      matches!(
        on_reply.await.expect("the driver replies"),
        Err(crate::error::SyncRootError::Retired)
      ),
      "the mark forced the claim to refuse — the reply is Retired"
    );

    // NEW: the exhaustion clause consumes the standing mark from this call site too. OLD: it
    // stays stranded at 1, with no wake and no deadline to ever revisit it — this bounded
    // settle-then-assert is the fail-fast discriminator.
    settle_reap_marks(&rig, 0).await;
    assert_eq!(
      reap_marks(&rig).await,
      0,
      "the mark survived the failed self-reap and is serviced at the write-done exhaustion"
    );

    // No leak: heal the fs, a fresh reap drives the serviced-then-parked record to its typed
    // terminal.
    rig.fs.clear_cookie_remove_failures_under("/r");
    rig.cleanup.request_remove(&path);
    settle_cookie_count(&rig, 0).await;
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "the serviced-then-healed cookie reaps to its terminal"
    );
    assert!(rig.fs.files_under("/r").is_empty(), "no file survives");
    assert_census_balances(&rig, "a mark serviced at write-done exhaustion").await;
  }

  // Finding 1 (fs half): a cancel that arrives while the write is STILL IN THE POOL marks that
  // write's own obligation; when the write lands, its claim reads the mark and is REFUSED, so the
  // write self-reaps the file it just created. The refusal is driven by the mark alone (the caller
  // is kept alive), which is why the reply reads `Retired`.
  //
  // Fail-on-old (the claim ignores its record's mark): the claim is admitted, the cookie survives
  // as an owned record, and both the `Retired` reply and the empty-directory assertion fail.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cancel_while_the_write_is_in_the_pool_makes_it_self_reap() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let name = ".tributaries-sync-1-2-1";
    // Hold the write in the pool: DISPATCHED, not yet claimed.
    let hold = rig.fs.hold_cookie_writes();
    let t = ticket();
    let on_reply = sync_root_pending_keyed(&rig, scope, "/r", name, t).await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;
    assert_eq!(
      rig.fs.cookie_dispatches(),
      1,
      "the write is in the pool, not yet claimed"
    );

    // Cancel by ticket while it is in the pool: the write's obligation exists (it was born at
    // dispatch), so the cancel MARKS it. Nothing is dispatched — only the write knows where its
    // cookie will land.
    rig.cleanup.request_cancel(t);
    settle_reap_marks(&rig, 1).await;
    assert_eq!(
      reap_marks(&rig).await,
      1,
      "an in-pool write's cancel marks its own obligation"
    );
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      0,
      "nothing is unlinked for a write whose path nobody knows yet"
    );

    // Release the held write: its claim READS the mark and is refused, so it self-reaps the file
    // and answers its still-held caller `Retired`.
    hold.release();
    assert!(
      matches!(
        on_reply.await.expect("the driver replies"),
        Err(crate::error::SyncRootError::Retired)
      ),
      "the mark forced the claim to refuse — the reply is Retired"
    );
    settle(|| rig.fs.files_under("/r").is_empty()).await;
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "the refused write self-reaped the file it created"
    );
    settle_cookie_count(&rig, 0).await;
    assert_eq!(cookie_count(&rig).await, 0, "nothing was left owned");
    assert_eq!(
      reap_marks(&rig).await,
      0,
      "the mark died with the record it marked — it never survives its write"
    );
    assert_census_balances(&rig, "a cancelled in-pool write").await;
  }

  // The reap mark's boundedness rule across all three cancel-versus-write orderings: an
  // unknown-ticket cancel marks nothing, a cancel-then-complete's mark is what refuses the claim,
  // and a complete-then-cancel marks the owned record the same cancel reaps. Each ends with zero
  // outstanding marks — the bound holds by construction, because a mark exists only as a field of
  // a live obligation and cannot outlive it. Every phase (parked-then-in-pool, owned) reaps through
  // the sync's own ticket.
  #[tokio::test(flavor = "multi_thread")]
  async fn reap_marks_never_survive_their_writes() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    // Ordering A — cancel an UNKNOWN ticket (never admitted): dropped at the lookup. There is no
    // obligation for that sequence, so there is nothing a mark could even be stored on.
    rig.cleanup.request_cancel(ticket());
    for _ in 0..8 {
      tokio::task::yield_now().await;
    }
    assert_eq!(
      reap_marks(&rig).await,
      0,
      "a cancel for an unknown ticket marks nothing"
    );

    // Ordering B — cancel-then-complete: the mark lands on the in-pool write's obligation, and the
    // refused claim acts on it.
    {
      let name = ".tributaries-sync-1-3-1";
      let hold = rig.fs.hold_cookie_writes();
      let t = ticket();
      let on_reply = sync_root_pending_keyed(&rig, scope, "/r", name, t).await;
      settle(|| rig.fs.cookie_dispatches() == 1).await;
      rig.cleanup.request_cancel(t);
      settle_reap_marks(&rig, 1).await;
      assert_eq!(
        reap_marks(&rig).await,
        1,
        "the in-pool write's own obligation carries the mark"
      );
      hold.release();
      let _ = on_reply.await;
      settle_cookie_count(&rig, 0).await;
      settle_reap_marks(&rig, 0).await;
      assert_eq!(
        reap_marks(&rig).await,
        0,
        "the mark died with its record — it never survives its write"
      );
    }

    // Ordering C — complete-then-cancel: the write is OWNED first, so the cancel marks that record
    // and reaps it through the phase machine in the same critical section.
    {
      let name = ".tributaries-sync-1-3-2";
      let t = ticket();
      let path = admit_sync_keyed(&rig, scope, "/r", name, t).await;
      settle_cookie_count(&rig, 1).await;
      rig.cleanup.request_cancel(t);
      settle(|| rig.fs.cookie_removes().contains(&path)).await;
      settle_cookie_count(&rig, 0).await;
      assert_eq!(
        reap_marks(&rig).await,
        0,
        "the reaped record took its mark with it"
      );
      assert!(
        rig.fs.files_under("/r").is_empty(),
        "the owned cookie was reaped by the cancel"
      );
    }
    assert_census_balances(&rig, "the three cancel orderings").await;
  }

  // Incarnation-addressed cancel closes the SEQUENTIAL same-name window a name-addressed cancel
  // could not. A cancel is minted for A, then delayed on the caller's thread ACROSS A's retirement
  // AND a successor B's admission under the SAME freed name. Addressed by A's ticket, the delayed
  // cancel resolves A's (retired) incarnation — nothing — so B, a genuinely distinct sync holding
  // its own ticket, is never marked: the documented "a cancel after resolution is a no-op" holds by
  // construction, not by a caller convention.
  //
  // Fail-on-old: the pre-fix name-addressed cancel resolved `by_name[n]` at MARK time, which by
  // then names B, so the same delayed cancel would mark B — reads `reap_marks == 1` immediately,
  // the wrong-target kill. The imprecise (name) address is INEXPRESSIBLE on the ticket API, so the
  // cell pins the no-op via the marks probe fail-FAST (no settle-hang).
  #[tokio::test(flavor = "multi_thread")]
  async fn a_delayed_cancel_for_a_retired_sync_never_touches_a_same_name_successor() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;
    let name = ".tributaries-sync-seq-reuse";

    // A admits and owns its cookie under `name`, keyed by ticket tA.
    let ta = ticket();
    let path_a = admit_sync_keyed(&rig, scope, "/r", name, ta).await;
    settle_cookie_count(&rig, 1).await;

    // A reaches its typed terminal: reap-and-confirm frees the name (and retires tA's record).
    rig.cleanup.request_remove(&path_a);
    settle_cookie_count(&rig, 0).await;

    // B — a genuinely distinct sync — admits under the SAME freed name with its own ticket tB.
    // Sequential reuse of a freed name still admits.
    let tb = ticket();
    let _path_b = admit_sync_keyed(&rig, scope, "/r", name, tb).await;
    settle_cookie_count(&rig, 1).await;

    // The DELAYED cancel for A lands now — across A's retire and B's re-admit of the name. It is
    // addressed by tA, which mapped to A's (now retired) incarnation alone, so it resolves nothing:
    // B is never marked. One Debug round-trip settles the ingress's wake sweep; assert fail-FAST.
    rig.cleanup.request_cancel(ta);
    settle_reap_marks(&rig, 0).await;
    assert_eq!(
      reap_marks(&rig).await,
      0,
      "the delayed cancel for retired A resolved nothing — the successor B carries no mark"
    );
    assert_eq!(
      cookie_count(&rig).await,
      1,
      "B is live and uncancelled — the same-name successor is untouched"
    );

    // B completes normally through its own reap: it was never harmed by the delayed cancel.
    rig.cleanup.request_remove(&PathBuf::from("/r").join(name));
    settle_cookie_count(&rig, 0).await;
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "B reaped normally — nothing left"
    );
    assert_census_balances(&rig, "a delayed cancel across sequential same-name reuse").await;
  }

  // The ticket refusals and their order. (1) One ticket passed to two concurrently-live syncs is
  // refused `TicketInUse` — a ticket is single-use. (2) A name+ticket double collision reads
  // `NameInUse` first (the pinned order UnknownRoot → BadCookieName → DirOutsideRoot →
  // WriteInFlight → NameInUse → TicketInUse → CleanupBacklog → admit). (3) A refusal creates
  // nothing, so the SAME ticket admits later once its contended holder retires — no re-mint dance.
  //
  // Fail-on-old (no `TicketInUse` arm): the second same-ticket admission returns `Ok` and displaces
  // `by_ticket`, so the `TicketInUse` assertion fails IMMEDIATELY — no settle-hang.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_ticket_is_single_use_and_ordered_after_the_name_gate() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/ra", FileKind::Dir, 200);
    rig.fs.put("/rb", FileKind::Dir, 201);
    let scope_a = watch(&rig, "/ra").await;
    let scope_b = watch(&rig, "/rb").await;

    // A owns a cookie under `name_a` on /ra, keyed by ticket `t`.
    let t = ticket();
    let name_a = ".tributaries-sync-ticket-a";
    let path_a = admit_sync_keyed(&rig, scope_a, "/ra", name_a, t).await;
    settle_cookie_count(&rig, 1).await;

    // (1) The SAME ticket on a second live sync — a DIFFERENT scope and a DIFFERENT name, so
    // neither `WriteInFlight` (per-scope) nor `NameInUse` can fire first — is refused `TicketInUse`.
    let name_b = ".tributaries-sync-ticket-b";
    assert!(
      matches!(
        sync_root_keyed(&rig, scope_b, "/rb", name_b, t).await,
        Err(crate::error::SyncRootError::TicketInUse {})
      ),
      "one ticket on two concurrently-live syncs is refused TicketInUse"
    );
    assert_eq!(
      cookie_count(&rig).await,
      1,
      "the TicketInUse refusal minted no record"
    );

    // (2) A name AND ticket double collision reads `NameInUse` first — name is ordered before
    // ticket, keeping every earlier pinned outcome verbatim.
    assert!(
      matches!(
        sync_root_keyed(&rig, scope_a, "/ra", name_a, t).await,
        Err(crate::error::SyncRootError::NameInUse { .. })
      ),
      "a name+ticket collision reads NameInUse — name is ordered before ticket"
    );

    // (3) The SAME ticket `t` — refused twice above — still admits once its holder A retires (a
    // refusal burns nothing). Reap A to free `name_a` and `t`, then admit B under `t`.
    rig.cleanup.request_remove(&path_a);
    settle_cookie_count(&rig, 0).await;
    let path_b = admit_sync_keyed(&rig, scope_b, "/rb", name_b, t).await;
    assert_eq!(
      path_b,
      PathBuf::from("/rb/.tributaries-sync-ticket-b"),
      "the twice-refused ticket admits once its holder retired — the refusals burned nothing"
    );

    rig.cleanup.request_remove(&path_b);
    settle_cookie_count(&rig, 0).await;
    assert_census_balances(&rig, "ticket single-use, name ordering, and retry").await;
  }

  // The PATH axis keeps the temporal ABA the ticket axis closes — the DOCUMENTED imprecision of
  // `request_remove_cookie(path)` for a caller that reuses names sequentially. A remove for A,
  // delayed across A's retire and B's claim of the SAME path (same dir + same name ⇒ same path),
  // resolves the path's CURRENT holder — B — and reaps it. The incarnation-precise form is the
  // ticket (`request_cancel_sync`), which leaves B untouched under this same interleaving (see
  // `a_delayed_cancel_for_a_retired_sync_never_touches_a_same_name_successor`).
  #[tokio::test(flavor = "multi_thread")]
  async fn a_delayed_path_remove_can_reap_a_same_path_successor_the_documented_imprecision() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;
    let name = ".tributaries-sync-path-reuse";
    let path = PathBuf::from("/r").join(name);

    // A owns the cookie at `path`.
    let ta = ticket();
    let path_a = admit_sync_keyed(&rig, scope, "/r", name, ta).await;
    assert_eq!(path_a, path);
    settle_cookie_count(&rig, 1).await;

    // A retires (its cookie confirmed removed); the path frees.
    rig.cleanup.request_remove(&path);
    settle_cookie_count(&rig, 0).await;

    // B claims the SAME path (same name) — a distinct incarnation with its own ticket.
    let tb = ticket();
    let path_b = admit_sync_keyed(&rig, scope, "/r", name, tb).await;
    assert_eq!(path_b, path);
    settle_cookie_count(&rig, 1).await;

    // A delayed remove for A, addressed by the SHARED path, resolves the path's CURRENT holder — B
    // — and reaps it. This is the path form's documented imprecision; the ticket form does not have
    // it.
    rig.cleanup.request_remove(&path);
    settle(|| rig.fs.cookie_removes().contains(&path)).await;
    settle_cookie_count(&rig, 0).await;
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "the path-addressed remove reaped the current holder B"
    );
    assert_census_balances(&rig, "a delayed path remove reaps a same-path successor").await;
  }

  // Finding 2: a self-reap for an ABANDONED caller (its `reply.send(Ok)` fails) whose own unlink
  // FAILS must RE-ASSERT ownership, never discard it — the record is retained as failed WHILE the
  // file is still on disk, and the DRIVER'S OWN retry (no external request) later confirms it.
  //
  // Fail-on-old (the self-reap discards ownership on unlink failure): the record is gone with the
  // file still on disk, so the `cookie_count == 1` retain assertion fails.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_failed_reply_abandon_self_reap_retains_ownership_and_retries() {
    let rig = rig_with_config(64, retain_config());
    let scope = watch(&rig, "/r").await;

    let name = ".tributaries-sync-2-1-1";
    // Hold the write, then abandon the caller so its `reply.send(Ok)` will FAIL when the write
    // lands — the reply-fail self-reap path.
    let write_hold = rig.fs.hold_cookie_writes();
    let on_reply = sync_root_pending(&rig, scope, "/r", name).await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;
    drop(on_reply);
    // The self-reap's own unlink FAILS once. Hold every remove so its dispatch is captured in
    // flight, deterministically, rather than racing the driver's own retry to observe it.
    rig.fs.fail_next_cookie_removes(1);
    let remove_hold = rig.fs.hold_cookie_removes();
    write_hold.release();
    settle(|| rig.fs.cookie_remove_dispatches() == 1 && remove_hold.captured() == 1).await;

    // Arm a hold for the driver's OWN retry BEFORE releasing the self-reap's attempt, so that
    // whenever its backoff fires — however long the test task stalls in between — the retry is
    // captured in flight too, rather than racing the RETAINED-state observation below.
    let retry_hold = rig.fs.hold_cookie_removes();
    remove_hold.release();

    settle(|| rig.fs.cookie_remove_dispatches() == 2).await;
    let dispatches_before_retry_runs = rig.fs.cookie_remove_dispatches();
    let retained_count = cookie_count(&rig).await;
    let file_present = !rig.fs.files_under("/r").is_empty();
    retry_hold.release();

    assert_eq!(
      dispatches_before_retry_runs, 2,
      "the self-reap attempt reached the pool and failed, then the driver's own retry \
       dispatched, held before it runs"
    );
    // The record is RETAINED as failed while the file is still present — never orphaned.
    assert_eq!(
      retained_count, 1,
      "ownership is retained across the failed self-reap"
    );
    assert!(file_present, "the file is still on disk, still retry-owned");

    // The driver retries ON ITS OWN and confirms — no external request.
    settle(|| rig.fs.files_under("/r").is_empty()).await;
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "the driver's own retry removed the file"
    );
    settle_cookie_count(&rig, 0).await;
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "the record dropped only once the retry confirmed"
    );
  }

  // Finding 2: a self-reap for a REFUSED claim (the scope retired under the in-flight write)
  // whose unlink FAILS is OWNED as failed, and the retry that removes it is scope-INDEPENDENT —
  // the scope is already gone, yet the driver still owns and drives the file to removal.
  //
  // Fail-on-old (the refused self-reap orphans a failed unlink): no record is inserted, so
  // `cookie_count == 1` fails and the file is stranded forever.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_refused_claim_self_reap_failure_is_owned_and_retried() {
    let rig = rig_with_config(64, retain_config());
    let scope = watch(&rig, "/r").await;

    let name = ".tributaries-sync-2-2-1";
    // The write must be IN the pool before the scope retires (a still-parked write is revoked at
    // its fence instead of self-reaping).
    let write_hold = rig.fs.hold_cookie_writes();
    let on_reply = sync_root_pending(&rig, scope, "/r", name).await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;

    // Retire the scope: the raised flag makes the landing write's claim REFUSE.
    let (reply, on_unwatch) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(reply),
      })
      .await
      .unwrap();
    assert!(
      on_unwatch.await.unwrap().is_torn(),
      "the live scope was unwatched"
    );

    // The refused self-reap's unlink FAILS once: the file must be OWNED as failed, not orphaned.
    // Hold every remove so the self-reap's dispatch is captured in flight, deterministically,
    // rather than racing the driver's own retry to observe it. The claim-refused path runs its
    // self-reap to completion BEFORE sending the write's reply, so `remove_hold` must release —
    // letting that first attempt actually fail — before `on_reply` is awaited below, or the
    // reply would never come.
    rig.fs.fail_next_cookie_removes(1);
    let remove_hold = rig.fs.hold_cookie_removes();
    write_hold.release();
    settle(|| rig.fs.cookie_remove_dispatches() == 1 && remove_hold.captured() == 1).await;

    // Arm a hold for the driver's OWN retry BEFORE releasing the self-reap's attempt, so that
    // whenever its backoff fires — however long the test task stalls in between — the retry is
    // captured in flight too, rather than racing the RETAINED-state observation below.
    let retry_hold = rig.fs.hold_cookie_removes();
    remove_hold.release();
    let claim_reply = on_reply.await.expect("the driver replies");

    settle(|| rig.fs.cookie_remove_dispatches() == 2).await;
    let dispatches_before_retry_runs = rig.fs.cookie_remove_dispatches();
    let owned_count = cookie_count(&rig).await;
    let file_present = !rig.fs.files_under("/r").is_empty();
    retry_hold.release();

    assert!(
      matches!(claim_reply, Err(crate::error::SyncRootError::Retired)),
      "the retiring scope refused the claim"
    );
    assert_eq!(
      dispatches_before_retry_runs, 2,
      "the refused self-reap failed, then the driver's own retry dispatched, held before it runs"
    );
    assert_eq!(
      owned_count, 1,
      "the refused-and-failed self-reap OWNS the file, never orphans it"
    );
    assert!(file_present, "the file is still present, retry-owned");

    // The retry is scope-INDEPENDENT — the scope is gone, yet the driver removes the file.
    settle(|| rig.fs.files_under("/r").is_empty()).await;
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "the scope-independent retry removed the orphan-candidate"
    );
    settle_cookie_count(&rig, 0).await;
    assert_eq!(
      cookie_count(&rig).await,
      0,
      "the record dropped once the retry confirmed"
    );
  }

  // A plain std::thread regression pinning the property the three cells above now settle on
  // before installing a superseding hold: a job that has CAPTURED a gate (cloned it and
  // committed to parking on it) can never be stolen by a gate installed afterward, even though
  // the dispatch counter alone only proves a dispatch happened, not which gate it bound to.
  //
  // The original race (preemption between the dispatch increment and the gate clone) cannot be
  // forced deterministically without an injection hook, so this test instead pins the
  // capture-before-supersede contract the ack provides: every bounded wait below fails fast at
  // its deadline rather than hanging, so a regression here is a clear assertion failure, not a
  // wedged test binary.
  #[test]
  fn a_hold_gate_is_captured_before_it_can_be_superseded() {
    let fs = FakeFs::new(1);
    let hold = fs.hold_cookie_removes();

    let worker = {
      let fs = fs.clone();
      std::thread::spawn(move || {
        fs.remove_cookie(&fs.cookie_at("/x"))
          .expect("the unlink succeeds");
      })
    };

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while fs.cookie_remove_dispatches() != 1 {
      assert!(
        std::time::Instant::now() < deadline,
        "the dispatch never reached the pool"
      );
      std::thread::sleep(Duration::from_millis(5));
    }
    while hold.captured() != 1 {
      assert!(
        std::time::Instant::now() < deadline,
        "the dispatch never captured its gate — the ack ordering regressed"
      );
      std::thread::sleep(Duration::from_millis(5));
    }

    // Install a superseding gate BEFORE releasing the first — exactly the handoff the three
    // cells above perform.
    let retry_hold = fs.hold_cookie_removes();
    hold.release();

    // If the ack were unsound, the worker could have bound to `retry_hold` instead, and the
    // release above would have freed nobody: the worker would hang forever, and this poll fails
    // fast instead of wedging the test binary.
    while !worker.is_finished() {
      assert!(
        std::time::Instant::now() < deadline,
        "the worker never completed — a superseding gate stole the capture"
      );
      std::thread::sleep(Duration::from_millis(5));
    }
    worker.join().expect("the worker thread does not panic");

    assert_eq!(
      retry_hold.captured(),
      0,
      "the superseding gate captured nothing: the first attempt had already committed to its \
       own gate before the second was installed"
    );
  }

  // Finding 3: duplicate reap requests against a HUNG unlink coalesce to ONE job — the
  // single-flight-per-path invariant. A caller that times out and storms 50 reaps against a wedged
  // mount cannot pile 50 blocking unlink jobs (the pool-exhaustion re-creation Codex named).
  //
  // Fail-on-old (no coalescing): 50 dispatches.
  #[tokio::test(flavor = "multi_thread")]
  async fn duplicate_reap_requests_for_a_hung_unlink_coalesce_to_one_job() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-3-1-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1);

    // The terminal unlink hangs; a caller storms 50 reap requests against it.
    let hold = rig.fs.hold_cookie_removes();
    for _ in 0..50 {
      rig.cleanup.request_remove(&path);
    }
    // The first dispatches ONE unlink (now `Removing`); the other 49 coalesce.
    settle(|| rig.fs.cookie_remove_dispatches() == 1).await;
    for _ in 0..16 {
      tokio::task::yield_now().await;
    }
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      1,
      "50 requests against a hung unlink coalesce to exactly ONE job"
    );

    // Released, the single unlink confirms and the record drops.
    hold.release();
    settle(|| rig.fs.cookie_removes().contains(&path)).await;
    settle_cookie_count(&rig, 0).await;
    assert_eq!(cookie_count(&rig).await, 0);
  }

  // Finding 3: a transient unlink failure is retried by the DRIVER, not the requester — ONE reap
  // request suffices, and the driver's own backed-off retry drives the confirm.
  //
  // Fail-on-old (no retry owner): the file persists forever after its single failed dispatch.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_transient_unlink_failure_is_retried_by_the_driver_not_the_requester() {
    let rig = rig_with_config(64, tuned_config());
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-3-2-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1);

    // ONE reap request; the first unlink fails transiently.
    rig.fs.fail_next_cookie_removes(1);
    rig.cleanup.request_remove(&path);

    settle(|| rig.fs.files_under("/r").is_empty()).await;
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "the driver's own retry removed the file after ONE request"
    );
    settle_cookie_count(&rig, 0).await;
    assert_eq!(cookie_count(&rig).await, 0);
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      2,
      "exactly two dispatches: the failed attempt and the driver's retry"
    );
  }

  // Finding 3: past its attempt budget a failing unlink PARKS — it stops retrying (no CPU-spin)
  // yet stays honestly OWNED, and an explicit reap RE-ARMS it with a fresh budget (T9).
  #[tokio::test(flavor = "multi_thread")]
  async fn the_retry_budget_parks_without_spinning() {
    let rig = rig_with_config(64, tuned_config()); // budget = 3
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-3-3-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1);

    // The unlink fails effectively forever.
    rig.fs.fail_next_cookie_removes(10_000);
    rig.cleanup.request_remove(&path);

    // One initial attempt plus a budget of 3 retries, then the record PARKS.
    settle(|| rig.fs.cookie_remove_dispatches() == 4).await;
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      4,
      "one attempt plus a budget of 3 retries"
    );

    // Parked: over a generous window the count does NOT grow (no spin), and the cookie is owned.
    for _ in 0..30 {
      tokio::task::yield_now().await;
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      4,
      "past the budget the record PARKS — no CPU-spinning retry"
    );
    assert_eq!(
      cookie_count(&rig).await,
      1,
      "the parked cookie is still honestly owned"
    );

    // A fresh explicit reap RE-ARMS the parked record with a fresh budget (T9): dispatches grow.
    rig.cleanup.request_remove(&path);
    settle(|| rig.fs.cookie_remove_dispatches() >= 5).await;
    assert!(
      rig.fs.cookie_remove_dispatches() >= 5,
      "an explicit reap re-arms a parked record (T9)"
    );

    // Close bridges to finding 4: the still-owned, unremovable cookie holds close in NotQuiesced.
    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    let pending = tokio::time::timeout(interpreted_secs(5), on_close)
      .await
      .expect("close returns within the grace")
      .expect("the driver replied");
    assert!(
      pending >= 1,
      "the still-owned, unremovable cookie holds close in NotQuiesced"
    );
  }

  /// The real-clock window [`a_wedged_teardown_does_not_stop_the_close_drain`]
  /// gives ONE drain cycle, in milliseconds — wider under an interpreter, because
  /// the wall clock is what the window is denominated in and an interpreter buys
  /// far less of the drain with it.
  ///
  /// What the measurement needs is a SHARE of the driver's one-second close grace
  /// big enough to hold one drain cycle — a landed completion consumed, then the
  /// retry deadline that completion scheduled serviced — and ending strictly
  /// before the grace does. The grace is the driver's own constant, so the share
  /// is the only side that can move. Natively a cycle costs a few milliseconds
  /// and 400 ms of it carries twenty-odd cycles of headroom. Under an interpreter
  /// the cycle costs interpreted WORK that no wall clock scales, and how much
  /// depends on the borrow model: a cycle that stacked borrows finishes in
  /// 150–450 ms takes up to 750 ms under tree borrows, which consults far more
  /// aliasing state per access. Hence a window that looks far less generous than
  /// the native one beside it while proving the same thing.
  ///
  /// The window is anchored at the sweep's OWN unlink dispatch rather than at the
  /// close send, and under an interpreter that anchor is what makes it fit. The
  /// command hop and the sweep ahead of the cycle cost 150–650 ms of
  /// interpretation between them — as much as the cycle they precede — so
  /// charging them to the window left under half of it for the thing being
  /// measured, which the tree-borrows cycle did not fit in. They are staging, and
  /// [`close_drain_setup_ms`] bounds them on their own.
  ///
  /// Ending strictly inside the grace is what keeps the cell's witness true. The
  /// mutation spends the grace inside ONE synchronous wait anchored on the real
  /// clock, so its first retry cannot land before that second is up however
  /// slowly the interpreter runs — while this window is a share of that same
  /// second, started where the driver starts counting it, so it closes first
  /// whatever the interpreter costs.
  fn close_drain_window_ms() -> u64 {
    if cfg!(miri) { 900 } else { 400 }
  }

  /// How long [`a_wedged_teardown_does_not_stop_the_close_drain`] waits for the
  /// close sweep's own unlink dispatch, in milliseconds, before it starts timing
  /// the drain cycle that follows.
  ///
  /// This bounds STAGING rather than the measurement. The sweep dispatches
  /// unconditionally, so the budget is only ever SPENT when the cell is already
  /// failing, and sizing it many times over the 150–650 ms an interpreter needs
  /// costs a passing run nothing while still reporting a sweep that never
  /// dispatches in seconds rather than minutes. Nor can it hide a slow cycle: the
  /// window above starts when this dispatch LANDS, so a late sweep moves the
  /// measurement rather than shortening it, and the driver anchors its own grace
  /// at the same point and moves with it.
  fn close_drain_setup_ms() -> u64 {
    if cfg!(miri) { 4_000 } else { 200 }
  }

  /// A teardown wedged for the whole grace must not stop close from draining.
  ///
  /// Close waits on two clocks. The reaper's completions come off threads no
  /// runtime timer governs, so the drain has to spend REAL time on their clock or
  /// a runtime with a virtual timer would retire the entire grace before those
  /// threads ran at all. But that wait is synchronous, so spending the grace
  /// inside ONE of them lets a single reader stuck on a dead filesystem stop close
  /// from consuming the results that already landed and from servicing the
  /// cookie-unlink retries the sweep just pulled forward — the very retries whose
  /// confirmation decides whether close may report quiescence — and on a
  /// current-thread runtime it holds every other task on the executor for a
  /// second. So the real time is spent in slices with the drain running between
  /// them.
  ///
  /// The staging: one owned cookie whose every unlink fails, so the close sweep's
  /// attempt parks the record and only the drain's own retry arm can move it
  /// again; and a teardown parked INSIDE `shutdown`, which is what a reader that
  /// will not exit looks like from the driver. The wedge is in place before close
  /// is sent, so the drain is reaper-bound for the whole window measured below.
  ///
  /// MUTATION WITNESS: hand `settle` the rest of the grace instead of a slice and
  /// the window closes with the dispatch count still at the sweep's one — the
  /// retry lands only once the grace expires, a full second later.
  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn a_wedged_teardown_does_not_stop_the_close_drain() {
    let rig = rig_with_config(64, tuned_config());
    let scope = watch(&rig, "/r").await;
    sync_root(&rig, scope, "/r", ".tributaries-sync-3-9-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1);

    // Every unlink fails, so the record the close sweep dispatches parks
    // `RemoveFailed` and moving it again is the drain's own work.
    rig.fs.fail_next_cookie_removes(1_000_000);
    let wedged = rig.fs.hold_teardowns();
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      0,
      "staging: nothing has attempted the unlink yet"
    );

    let (close_reply, on_close) = futures_channel::oneshot::channel();
    let closed_at = std::time::Instant::now();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();

    // Staging: the close sweep's own unlink attempt, which parks `RemoveFailed`.
    // It is not what this cell measures — the drain cycle after it is — so it
    // gets its own budget and the window below starts where it lands.
    let swept_by = closed_at + Duration::from_millis(close_drain_setup_ms());
    while rig.fs.cookie_remove_dispatches() < 1 && std::time::Instant::now() < swept_by {
      tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert!(
      rig.fs.cookie_remove_dispatches() >= 1,
      "staging: the close sweep dispatched the unlink it parks"
    );

    // Inside the one-second grace, by the share [`close_drain_window_ms`] sizes.
    // Reaching a SECOND dispatch takes both halves of the drain the wedge would
    // otherwise hold: the sweep's failed attempt has to be consumed off the
    // result channel, and the retry deadline it schedules has to be serviced.
    let window_ms = close_drain_window_ms();
    let window = std::time::Instant::now() + Duration::from_millis(window_ms);
    let mut serviced = false;
    while std::time::Instant::now() < window {
      if rig.fs.cookie_remove_dispatches() >= 2 {
        serviced = true;
        break;
      }
      tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert!(
      serviced,
      "close serviced no cookie-retry deadline in {window_ms} ms of its grace while a teardown \
       was wedged (unlink dispatches: {})",
      rig.fs.cookie_remove_dispatches()
    );

    // And what the slicing must not cost: close still observes the teardown, and
    // still reports the residue it cannot clear.
    wedged.release();
    let pending = tokio::time::timeout(interpreted_secs(5), on_close)
      .await
      .expect("close resolves at the grace boundary")
      .expect("the driver replied");
    assert!(
      pending >= 1,
      "the unremovable cookie is reported, not papered over"
    );
    assert_eq!(rig.fs.shutdowns(), 1, "and the stream was torn down");
  }

  // Finding 3: a scope whose cookie cleanup is BACKLOGGED past the per-scope cap refuses new syncs
  // with the retryable `CleanupBacklog` — the hard memory bound. On a recovered fs the backlog
  // would drain and syncs resume; here it stays wedged so the cap is provably hit.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_backlogged_scope_refuses_new_syncs_retryably() {
    let rig = rig_with_config(64, tuned_config()); // backlog_cap = 3
    let scope = watch(&rig, "/r").await;

    // Every unlink fails: the backlog fills with owned-but-unremovable cookies.
    rig.fs.fail_next_cookie_removes(1_000_000);

    // Fill the scope's backlog to the cap: three syncs, each reaped-but-failing.
    for seq in 0..3 {
      let name = format!(".tributaries-sync-3-4-{seq}");
      let path = admit_sync(&rig, scope, "/r", &name).await;
      rig.cleanup.request_remove(&path);
      settle_cookie_count(&rig, seq + 1).await;
      assert_eq!(
        cookie_count(&rig).await,
        seq + 1,
        "the failing unlink keeps the cookie owned"
      );
    }

    // The 4th sync is refused CleanupBacklog — a transient, retryable refusal with no physical
    // write (drive past any lingering single-flight gate to reach the cap check).
    let mut outcome = None;
    for _ in 0..400 {
      match sync_root(&rig, scope, "/r", ".tributaries-sync-3-4-cap").await {
        Err(crate::error::SyncRootError::WriteInFlight) => {
          tokio::task::yield_now().await;
          tokio::time::sleep(Duration::from_millis(5)).await;
        }
        other => {
          outcome = Some(other);
          break;
        }
      }
    }
    assert!(
      matches!(
        outcome,
        Some(Err(crate::error::SyncRootError::CleanupBacklog))
      ),
      "the backlogged scope refuses a new sync with the retryable CleanupBacklog, got {outcome:?}"
    );
    assert_eq!(
      cookie_count(&rig).await,
      3,
      "the refusal wrote nothing — the ledger is unchanged at the cap"
    );
  }

  // Finding 4: close reports NotQuiesced BECAUSE a cookie is still owned — a mount whose unlinks
  // fail through every grace retry leaves the file, and close counts the LIVE LEDGER, not a job
  // count that a failed unlink would have drained.
  //
  // Fail-on-old (close counts jobs, ignores the ledger): close returns 0 with the file still on
  // disk — the `pending >= 1` assertion fails.
  #[tokio::test(flavor = "multi_thread")]
  async fn close_reports_not_quiesced_while_a_cookie_survives_repeated_unlink_failures() {
    let rig = rig_with_config(64, tuned_config());
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-4-1-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1);

    // Every unlink fails, through every grace retry.
    rig.fs.fail_next_cookie_removes(100_000);
    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    let pending = tokio::time::timeout(interpreted_secs(5), on_close)
      .await
      .expect("close returns within the grace, never wedged")
      .expect("the driver replied");

    assert!(
      pending >= 1,
      "close reports NotQuiesced BECAUSE the cookie is still owned"
    );
    assert!(
      rig.fs.files_under("/r").contains(&path),
      "the file remains — the live ledger, not a drained job count, is the drain condition"
    );
  }

  // Finding 4: a transiently-failing terminal unlink is RETRIED by the close drain INSIDE the
  // grace — reply `Ok(0)` with the file already gone AT reply time, driven by the drain's own
  // retry, not the registry `Drop`'s post-reply detached tail (whose completion the reply never
  // waits for). The dispatch count is the discriminator: exactly the failed attempt plus the
  // drain's retry.
  #[tokio::test(flavor = "multi_thread")]
  async fn close_retries_a_transiently_failing_unlink_inside_the_grace() {
    let rig = rig_with_config(64, tuned_config());
    let scope = watch(&rig, "/r").await;

    let _path = sync_root(&rig, scope, "/r", ".tributaries-sync-4-2-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1);

    // The terminal unlink fails ONCE; the drain's own retry (inside the grace) drives the confirm.
    rig.fs.fail_next_cookie_removes(1);
    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    let pending = tokio::time::timeout(interpreted_secs(5), on_close)
      .await
      .expect("close returns within the grace")
      .expect("the driver replied");

    assert_eq!(
      pending, 0,
      "the transient failure was retried and confirmed INSIDE the grace"
    );
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "the file is gone AT reply time — the drain's retry, not Drop's detached tail"
    );
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      2,
      "exactly the failed attempt and the drain's own retry"
    );
  }

  /// A config whose GLOBAL cookie cap is the low bound while the per-scope cap
  /// sits well above it, so a churn of fresh scopes — each owning at most one
  /// cookie — can only ever be refused by the watcher-wide ceiling.
  fn low_global_cap_config() -> DriverConfig {
    DriverConfig {
      cookie_retry_base: Duration::from_millis(5),
      cookie_retry_cap: Duration::from_millis(20),
      cookie_retry_budget: 3,
      cookie_backlog_cap: 8,
      cookie_global_cap: 3,
      ..config()
    }
  }

  /// A config whose retry backoff climbs fast under a large cap and a generous
  /// budget, so a few consecutive unlink failures park a record on a deadline
  /// BEYOND the close grace — the state the close-sweep deadline clamp rescues.
  fn far_backoff_config() -> DriverConfig {
    DriverConfig {
      cookie_retry_base: Duration::from_millis(400),
      cookie_retry_cap: Duration::from_secs(5),
      cookie_retry_budget: 8,
      cookie_backlog_cap: 8,
      cookie_global_cap: 128,
      ..config()
    }
  }

  // The global cookie cap ceilings total owned cookies across every scope, live
  // or retired. A sync → failing-cleanup → unwatch → rewatch churn mints a fresh
  // scope each round, and a fresh scope's own per-scope backlog is always one, so
  // only a watcher-wide ceiling can bound the residue the retired scopes leave.
  // Once the cap is reached a further sync is refused `CleanupBacklog`, and the
  // owned count never climbs past it however long the churn runs.
  #[tokio::test(flavor = "multi_thread")]
  async fn churn_across_retired_scopes_is_bounded_by_the_global_cap() {
    let rig = rig_with_config(64, low_global_cap_config());
    // Every unlink fails forever, so each round's cookie survives its scope's
    // retirement and adds to the global residue.
    rig.fs.fail_next_cookie_removes(1_000_000);

    let cap = low_global_cap_config().cookie_global_cap;
    let mut admitted = 0usize;
    // Churn several rounds past the cap, each on a fresh sibling root.
    for i in 0..(cap + 3) {
      let root = format!("/ra{i}");
      rig.fs.put(&root, FileKind::Dir, 100 + i as u64);
      let scope = watch(&rig, &root).await;
      let name = format!(".tributaries-sync-A-{i}");
      match sync_root(&rig, scope, &root, &name).await {
        Ok(path) => {
          admitted += 1;
          // Ask for the cookie's removal; it fails permanently, so the owned
          // record is retained across the unwatch below.
          rig.cleanup.request_remove(&path);
        }
        Err(crate::error::SyncRootError::CleanupBacklog) => {}
        Err(other) => panic!("unexpected sync error: {other:?}"),
      }
      // Retire the scope. Its failing cookie record stays owned — a retired scope
      // no longer re-arms it, but the file is never orphaned.
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Unwatch {
          scope,
          reply: Some(reply),
        })
        .await
        .unwrap();
      let _ = on_reply.await;
      assert!(
        cookie_count(&rig).await <= cap,
        "the global cap bounds total owned cookies across retired scopes"
      );
    }

    assert_eq!(
      admitted, cap,
      "exactly the cap's worth of syncs land before the global ceiling refuses"
    );
    assert_eq!(
      cookie_count(&rig).await,
      cap,
      "the residue sits exactly at the global cap, never beyond it"
    );

    // With the cap reached, one more sync on yet another fresh scope is refused
    // retryably — whatever scope owns the residue.
    rig.fs.put("/ra-final", FileKind::Dir, 999);
    let scope = watch(&rig, "/ra-final").await;
    assert!(
      matches!(
        sync_root(&rig, scope, "/ra-final", ".tributaries-sync-A-final").await,
        Err(crate::error::SyncRootError::CleanupBacklog)
      ),
      "a fresh scope is refused because the GLOBAL residue is at the cap"
    );
  }

  // Cleanup makes steady progress even under a saturating command flood. The live
  // loop's select is command-biased, so without the loop-top fairness check a
  // caller that keeps the bounded command mailbox continuously ready would starve
  // the wake — cookies would linger owned with their marks set. Form: a sustained
  // real flood (a spawned task that never lets the command channel drain) racing a
  // reap for a live owned cookie.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_command_flood_does_not_starve_the_cleanup_sweep() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-B-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1);

    // Saturate the bounded command channel continuously with a cheap command the
    // driver answers synchronously and statelessly, so the biased select always
    // finds `commands` ready at poll time.
    let commands = rig.commands.clone();
    let flood = tokio::spawn(async move {
      loop {
        let (reply, _drop) = futures_channel::oneshot::channel();
        if commands
          .send(Command::DebugCookieCount { reply })
          .await
          .is_err()
        {
          break;
        }
      }
    });

    // Under the sustained flood, mark the cookie for reaping.
    rig.cleanup.request_remove(&path);

    // The loop-top fairness check sweeps it regardless of the flood: the unlink is
    // dispatched and confirms. Observed fs-side — the flooded command channel
    // cannot carry an observation command through.
    settle(|| rig.fs.cookie_removes().contains(&path)).await;
    flood.abort();

    assert!(
      rig.fs.cookie_removes().contains(&path),
      "the marked reap was swept despite the command flood"
    );
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "the cookie file is gone"
    );
    // And the registry no longer owns it.
    settle_cookie_count(&rig, 0).await;
    assert_eq!(cookie_count(&rig).await, 0, "the cookie is no longer owned");
  }

  // The registry's abnormal-path Drop dispatches a best-effort unlink only for a
  // record with NO unlink already in flight. A cookie the close sweep already
  // moved to `Removing` (its unlink hung past the grace) has one — a second
  // unlink for the same path is exactly the duplicate the single-flight choke
  // point forbids. So a hung cookie is dispatched exactly ONCE across the whole
  // close.
  #[tokio::test(flavor = "multi_thread")]
  async fn close_dispatches_exactly_one_unlink_for_a_hung_cookie() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let _path = sync_root(&rig, scope, "/r", ".tributaries-sync-C-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1);

    // The terminal unlink hangs: the close sweep dispatches it and it never
    // confirms within the grace, so the record stays `Removing` through the Drop.
    let hold = rig.fs.hold_cookie_removes();
    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    let pending = tokio::time::timeout(interpreted_secs(5), on_close)
      .await
      .expect("close returns within the grace, never wedged on a hung unlink")
      .expect("the driver replied");
    assert_eq!(pending, 1, "the hung cookie is counted once");

    // The Drop has already run — it precedes the close reply. Give any erroneous
    // second dispatch time to reach the pool, then prove it never happened: the
    // sweep's single unlink is the only one.
    settle(|| rig.fs.cookie_remove_dispatches() >= 2).await;
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      1,
      "the sweep dispatched one unlink; the Drop skipped the still-Removing record"
    );

    // Released, the one hung unlink completes and the file is gone.
    hold.release();
    settle(|| rig.fs.files_under("/r").is_empty()).await;
    assert!(rig.fs.files_under("/r").is_empty());
  }

  // A write whose `reply.send(Ok)` fails after it CLAIMED its record is ONE physical
  // obligation — one record, phase `Removing`, its self-reap unlink in flight — from its
  // dispatch to its terminal, even though its `CookieWriteDone` is still outstanding behind
  // the hung unlink. The close count tallies it once because there is only one thing to count.
  #[tokio::test(flavor = "multi_thread")]
  async fn close_counts_a_held_self_reap_obligation_once() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    // Hold the write in the pool so the reply receiver can be dropped in the
    // window after dispatch (the scope's obligation is `InPool`) but before the
    // write lands. The parked write is already past the cover-fence cancel prune,
    // so it still writes, claims, and then finds its reply send failed.
    let write_hold = rig.fs.hold_cookie_writes();
    let on_reply = sync_root_pending(&rig, scope, "/r", ".tributaries-sync-D-1").await;
    settle(|| rig.fs.cookie_dispatches() == 1).await;
    assert_eq!(
      rig.fs.cookie_dispatches(),
      1,
      "the write is dispatched and parked"
    );

    // Arm the self-reap's unlink to hang, drop the receiver, then release the
    // write: it lands, claims (the scope is live), its `reply.send(Ok)` fails, and
    // its self-reap transitions the record to `Removing` and hangs in the unlink.
    let remove_hold = rig.fs.hold_cookie_removes();
    drop(on_reply);
    write_hold.release();
    settle(|| rig.fs.cookie_remove_dispatches() == 1).await;
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      1,
      "the self-reap's unlink is in flight, held"
    );
    assert_eq!(
      cookie_count(&rig).await,
      1,
      "the claimed record is owned, its scope still in flight"
    );

    // Close: the one obligation is counted once, not once per place it appears.
    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    let pending = tokio::time::timeout(interpreted_secs(5), on_close)
      .await
      .expect("close returns within the grace")
      .expect("the driver replied");
    assert_eq!(
      pending, 1,
      "one physical obligation — the held self-reap — counted once, not twice"
    );

    // Release the hung unlink so the parked pool thread can finish.
    remove_hold.release();
  }

  // A cookie whose unlink has failed several times sits on an exponential-backoff
  // deadline that can exceed the close grace. The close sweep pulls every pending
  // retry forward to one base delay, so a record on a far deadline is still
  // retried inside the grace — and on a recovered fs the retry confirms, so close
  // proves quiescence instead of reporting a spurious NotQuiesced.
  #[tokio::test(flavor = "multi_thread")]
  async fn close_retries_a_pre_existing_long_backoff_within_the_grace() {
    let rig = rig_with_config(64, far_backoff_config());
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-E-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1);

    // Fail the unlink three times: with a 400ms base the third failure parks the
    // record on a ~1.6s retry deadline, well past the 1s grace. The fourth attempt
    // (the fs has recovered) would succeed, but it is scheduled far out.
    rig.fs.fail_next_cookie_removes(3);
    rig.cleanup.request_remove(&path);
    settle(|| rig.fs.cookie_remove_dispatches() >= 3).await;
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      3,
      "exactly three failed attempts"
    );

    // Let the third failure's reschedule land, and confirm the far retry has NOT
    // auto-fired: the record waits on a deadline beyond the grace.
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      3,
      "the far retry has not fired — the record waits on a >1s deadline"
    );
    assert_eq!(cookie_count(&rig).await, 1, "the cookie is still owned");

    // Close: the sweep clamps the far deadline into the grace; the retry fires and
    // confirms against the recovered fs.
    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    let pending = tokio::time::timeout(interpreted_secs(5), on_close)
      .await
      .expect("close returns within the grace")
      .expect("the driver replied");
    assert_eq!(
      pending, 0,
      "the clamped retry confirmed inside the grace — no spurious NotQuiesced"
    );
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "the cookie file is gone at reply time"
    );
  }

  /// Settles until cookie-remove dispatches STOP growing across a window longer
  /// than the retry cap: every failing record has spent its budget and PARKED,
  /// with no scheduled retry left to fire. Under a still-failing fs a stable
  /// dispatch count is the proof that the backlog is fully parked — the
  /// precondition the recovery cell must start from, since a record still inside
  /// its budget would drain on the healed fs through the driver's OWN retry
  /// timer, masking whether the admission-time re-arm did the work.
  async fn settle_removes_parked(rig: &Rig) {
    let mut last = usize::MAX;
    for _ in 0..40 {
      let now = rig.fs.cookie_remove_dispatches();
      if now == last {
        return;
      }
      last = now;
      tokio::time::sleep(Duration::from_millis(60)).await;
    }
  }

  // A since-recovered filesystem DRAINS a global-cap-filling backlog of PARKED
  // (budget-spent) records left on RETIRED scopes, and syncs resume — there is no
  // permanent lockout. A parked record on a retired scope has no live scope to
  // sweep it and no timer to retry it, so only the `SyncRoot`-admission re-arm —
  // kicked right before a cap refusal — can ever retry it: the caller that hits
  // the backlog is what drives recovery.
  //
  // Fail-on-old (the admission re-arm disabled): the parked records never retry,
  // the owned count stays pinned at the cap, and every later sync stays refused —
  // the drain settle times out and its `< cap` assertion fails.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_recovered_fs_drains_the_backlog_and_admits_new_syncs() {
    // global_cap = 3 is the binding ceiling; backlog_cap = 8 never binds, since
    // each scope below owns exactly one cookie.
    let rig = rig_with_config(64, low_global_cap_config());
    let cap = low_global_cap_config().cookie_global_cap;

    // Every unlink fails while the backlog is built, so each scope's cookie
    // survives its retirement and its removal budget spends down to a PARK.
    rig.fs.fail_next_cookie_removes(1_000_000);

    // Fill the GLOBAL cap with parked records spread across scopes that are then
    // RETIRED: watch → sync (the write lands) → unwatch (the retire sweep reaps
    // it, the reap fails through the whole budget, the record parks with no live
    // scope left to re-arm it).
    for i in 0..cap {
      let root = format!("/rp{i}");
      rig.fs.put(&root, FileKind::Dir, 200 + i as u64);
      let scope = watch(&rig, &root).await;
      let _path = sync_root(
        &rig,
        scope,
        &root,
        &format!(".tributaries-sync-r10-recover-{i}"),
      )
      .await
      .expect("the write lands");
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Unwatch {
          scope,
          reply: Some(reply),
        })
        .await
        .unwrap();
      let _ = on_reply.await;
      settle_cookie_count(&rig, i + 1).await;
      assert_eq!(
        cookie_count(&rig).await,
        i + 1,
        "the failing reap keeps the retired scope's cookie owned"
      );
    }
    settle_removes_parked(&rig).await;
    assert_eq!(
      cookie_count(&rig).await,
      cap,
      "the residue sits exactly at the global cap, every record parked"
    );

    // At the cap a fresh live scope is refused retryably. On the fixed driver this
    // refusal ALSO kicks the re-arm — the fs is still failing, so the re-armed
    // records simply re-park and the cap holds.
    rig.fs.put("/rk", FileKind::Dir, 900);
    let kicker = watch(&rig, "/rk").await;
    assert!(
      matches!(
        sync_root(&rig, kicker, "/rk", ".tributaries-sync-r10-recover-cap").await,
        Err(crate::error::SyncRootError::CleanupBacklog)
      ),
      "a fresh scope is refused while the global residue is at the cap"
    );
    settle_removes_parked(&rig).await;
    assert_eq!(
      cookie_count(&rig).await,
      cap,
      "a still-failing fs drains nothing — the residue is parked back at the cap"
    );

    // The filesystem HEALS: unlinks succeed from here on.
    rig.fs.fail_next_cookie_removes(0);

    // The next sync attempt kicks the re-arm, which re-dispatches the parked
    // records; they confirm against the healed fs and leave the ledger. The
    // attempt itself is still refused — admission reads the cap before the drain
    // it just kicked can land — but it is what drives recovery.
    assert!(
      matches!(
        sync_root(&rig, kicker, "/rk", ".tributaries-sync-r10-recover-kick").await,
        Err(crate::error::SyncRootError::CleanupBacklog)
      ),
      "the kicking sync is refused at admission, having re-armed the parked backlog"
    );
    settle_cookie_count(&rig, 0).await;
    assert!(
      cookie_count(&rig).await < cap,
      "the recovered fs drained the parked backlog — no permanent lockout"
    );

    // Syncs resume, on the SAME driver and the SAME watch — no operator action.
    let path = admit_sync(&rig, kicker, "/rk", ".tributaries-sync-r10-recover-ok").await;
    assert_eq!(
      path,
      PathBuf::from("/rk/.tributaries-sync-r10-recover-ok"),
      "a new sync lands once the backlog has drained"
    );
  }

  // The accepted residual, asserted HONEST: an orderly-close unlink that hangs
  // past the grace and only THEN fails is skipped by the registry `Drop` and its
  // file persists — but close never claimed quiescence over it. Close counts every
  // owned record, so the un-removed cookie comes back in `pending` (`NotQuiesced`)
  // rather than being silently dropped or falsely reported `Ok`.
  //
  // This documents the residual's honesty; it does NOT assert the file is reaped.
  #[tokio::test(flavor = "multi_thread")]
  async fn an_orderly_close_honestly_counts_a_hung_then_failing_unlink() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-r10-residual-1")
      .await
      .expect("the write lands");
    assert_eq!(cookie_count(&rig).await, 1);

    // The close-sweep unlink HANGS past the grace, and is armed to FAIL once
    // finally released: a hung-then-failing terminal unlink whose file can never
    // be reclaimed. The hold parks the job before the failure is consulted, so the
    // whole grace elapses with the record `Removing`.
    let hold = rig.fs.hold_cookie_removes();
    rig.fs.fail_next_cookie_removes(1_000_000);

    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    let pending = tokio::time::timeout(interpreted_secs(5), on_close)
      .await
      .expect("close returns within the grace, never wedged on the hung unlink")
      .expect("the driver replied");
    assert!(
      pending >= 1,
      "the hung-then-failing unlink is honestly counted as outstanding — never a false Ok"
    );

    // Exactly one unlink was dispatched: the `Drop` skipped the still-`Removing`
    // record rather than duplicating a job the single-flight choke point forbids.
    settle(|| rig.fs.cookie_remove_dispatches() >= 2).await;
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      1,
      "the sweep dispatched one unlink; the Drop skipped the still-Removing record"
    );

    // Release the hung unlink — armed to fail, so it confirms nothing and the file
    // stays. The residual is real, and close already reported it in `pending`.
    hold.release();
    assert!(
      rig.fs.files_under("/r").contains(&path),
      "the hung-then-failing cookie persists — the residual close counted honestly, never reaped and never falsely reported gone"
    );
  }

  // ==== R11-3: the forced same-path ABA and the id guards (cells 1–4) ====

  // The flagship id guard, pinned at the registry harness. Public admission now
  // refuses a second live obligation under a held name (`NameInUse`), so two live
  // same-name records can no longer be minted through `sync_root` — but the guard
  // that protects a same-path successor from a predecessor's stale confirm must
  // stay pinned where the state IS constructible: straight against the registry,
  // which admits and claims below the admission refusal.
  //
  // A confirmed unlink for a record since REPLACED at its path (a predecessor whose
  // unlink physically ran, then a successor reclaiming the freed path) must NOT
  // drop the successor: the pool job's confirm-drop is keyed by INCARNATION id, so
  // the stale confirm retires only the predecessor. This drives the REAL unlink job
  // through the held preemption window, so the id guard is exercised at the actual
  // confirm-drop site, not a stand-in.
  //
  // Fail-on-old (a path-keyed confirm-drop): releasing the held confirm removes
  // whoever now occupies the path — the successor — so the count drops to 0 with
  // the file still present and the survivor assertion fails.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_confirmed_unlink_for_a_replaced_record_does_not_drop_it() {
    let fs = FakeFs::new(1);
    let mut reg = registry(fs.clone());
    let mut core = fence_source();
    let scope_pred = ScopeId::new(NonZeroU64::new(1).unwrap());
    let scope_succ = ScopeId::new(NonZeroU64::new(2).unwrap());
    let name = ".tributaries-sync-aba-1";
    let path = PathBuf::from("/r").join(name);
    let (op_tx, _op_rx) = async_channel::unbounded::<OpResult<FakeHandle>>();

    // Predecessor: admit, land its file at P, claim it Owned.
    let guard_pred = dispatched_guard(&mut reg, &mut core, scope_pred, name);
    fs.put(&path, FileKind::File, 1);
    let id_pred = guard_pred
      .claim(&fs.cookie_residue_at(&path))
      .expect("the predecessor claims P");

    // Reap it, but HOLD the pool job at the preemption window: the unlink syscall
    // has run (the file is gone) but the job has not yet taken the ledger lock to
    // confirm-drop.
    let hold = fs.hold_cookie_remove_confirms();
    reg.request_removal::<TokioRuntime>(&op_tx, RemovalRequest::Targeted(id_pred));
    settle(|| !fs.files_under("/r").contains(&path) && fs.cookie_remove_dispatches() == 1).await;
    assert!(
      !fs.files_under("/r").contains(&path),
      "the unlink syscall ran — the file is gone at the preemption window"
    );

    // Successor, SAME path: admit, recreate the freed file, claim it. Keyed by its
    // own id; the predecessor's held-`Removing` record keeps its own key, so both
    // are tracked at once — the ledger count is pessimistic-honest.
    let guard_succ = dispatched_guard(&mut reg, &mut core, scope_succ, name);
    fs.put(&path, FileKind::File, 2);
    let id_succ = guard_succ
      .claim(&fs.cookie_residue_at(&path))
      .expect("the successor reclaims P");
    assert_ne!(
      id_pred, id_succ,
      "predecessor and successor are distinct incarnations"
    );
    assert_eq!(
      reg.len(),
      2,
      "both incarnations are tracked — the successor's claim displaces neither record"
    );

    // Release the held confirm: the predecessor's job resumes and confirm-drops —
    // but keyed by its own id, so the stale confirm cannot touch the successor.
    hold.release();
    settle(|| reg.len() == 1).await;
    // Let the stale confirm-drop and its report fully land.
    for _ in 0..24 {
      tokio::task::yield_now().await;
      tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
      reg.len(),
      1,
      "the stale confirm was refused by id — the successor record survives"
    );
    assert!(
      matches!(
        lock_ledger(&reg.ledger)
          .obligations
          .get(&id_succ)
          .map(|ob| &ob.phase),
        Some(Phase::Owned)
      ),
      "the successor is still Owned"
    );
    assert!(
      !lock_ledger(&reg.ledger).obligations.contains_key(&id_pred),
      "the predecessor is retired by its own id"
    );
    assert!(
      fs.files_under("/r").contains(&path),
      "the successor's file survives the stale confirm"
    );

    // The successor reaps normally to a typed terminal; physical state converges.
    reg.request_removal::<TokioRuntime>(&op_tx, RemovalRequest::Targeted(id_succ));
    settle(|| reg.len() == 0 && fs.files_under("/r").is_empty()).await;
    assert_eq!(reg.len(), 0, "the successor is confirmed gone");
    let (census, live) = reg.census();
    assert!(
      census.balances(live),
      "every incarnation reached a typed terminal"
    );
  }

  // The birth-overwrite hazard, forced deterministically: write A creates its
  // file and its CLAIM is delayed; A's file is externally deleted; a same-path
  // write B (a different scope) lands and claims the live file; THEN A's delayed
  // claim fires. Because each claim inserts a record keyed by its own unique
  // incarnation id, A's late claim can never displace B's live record — the two
  // coexist under distinct keys, and both reach a typed terminal.
  //
  // Fail-on-old: with the claim keyed by PATH (an insert that overwrites the
  // record at the landing path), A's late claim OVERWRITES B's live record — the
  // record-identity assertion (B's id still owns its `Owned` state) fails.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_delayed_claim_never_displaces_a_live_same_path_successor() {
    let fs = FakeFs::new(1);
    let mut reg = registry(fs.clone());
    let mut core = fence_source();
    let scope_a = ScopeId::new(NonZeroU64::new(1).unwrap());
    let scope_b = ScopeId::new(NonZeroU64::new(2).unwrap());
    let name = ".tributaries-sync-h1";
    let path = PathBuf::from("/r").join(name);

    // Write A dispatched and created its file at P; its claim is not run yet.
    let guard_a = dispatched_guard(&mut reg, &mut core, scope_a, name);
    fs.put(&path, FileKind::File, 1);
    // A's file is externally deleted before A ever claims.
    fs.remove(&path);

    // Write B (a different scope) lands at the SAME path and claims: its file is
    // the live one now.
    let guard_b = dispatched_guard(&mut reg, &mut core, scope_b, name);
    fs.put(&path, FileKind::File, 2);
    let id_b = guard_b
      .claim(&fs.cookie_residue_at(&path))
      .expect("B claims the live file");
    {
      let inner = lock_ledger(&reg.ledger);
      // Both writes are tracked from their dispatch; only B has claimed a path.
      assert_eq!(
        inner.obligations.len(),
        2,
        "both dispatched writes are tracked"
      );
      assert!(
        matches!(
          inner.obligations.get(&guard_a.id).map(|ob| &ob.phase),
          Some(Phase::InPool)
        ),
        "A's write is still in the pool"
      );
      assert_eq!(inner.by_path.get(&path), Some(&id_b), "by_path names B");
    }

    // A's delayed claim finally fires.
    let id_a = guard_a
      .claim(&fs.cookie_residue_at(&path))
      .expect("A's late claim is admitted");
    assert_ne!(id_a, id_b, "A and B are distinct incarnations");
    {
      let inner = lock_ledger(&reg.ledger);
      // B's live record survives by IDENTITY — its own id still owns its state.
      assert!(
        matches!(
          inner.obligations.get(&id_b).map(|ob| &ob.phase),
          Some(Phase::Owned)
        ),
        "B's live record is never displaced by A's late claim"
      );
      assert!(
        inner.obligations.contains_key(&id_a),
        "A's record coexists under its own key"
      );
      // Pessimistic-honest: both obligations are counted, never one dropped.
      assert_eq!(inner.obligations.len(), 2, "both incarnations are tracked");
      // Newest-claim-wins on the index; the displaced entry never destroys B.
      assert_eq!(inner.by_path.get(&path), Some(&id_a), "by_path names A now");
    }

    // Both incarnations reach a typed terminal, and physical state converges.
    let (op_tx, _op_rx) = async_channel::unbounded::<OpResult<FakeHandle>>();
    reg.sweep_owned::<TokioRuntime>(&op_tx);
    settle(|| reg.len() == 0 && fs.files_under("/r").is_empty()).await;
    assert_eq!(reg.len(), 0, "both incarnations are retired");
    assert!(fs.files_under("/r").is_empty(), "the physical file is gone");
    let (census, live) = reg.census();
    assert!(
      census.balances(live),
      "every incarnation reached a typed terminal"
    );
  }

  // A confirmed unlink for an incarnation that has since been REPLACED at the
  // same path must retire ONLY its own incarnation: the retire is keyed by id, so
  // a stale confirm for N structurally cannot touch a successor M that reclaimed
  // the path.
  //
  // Fail-on-old: with a path-keyed drop (retire whoever currently occupies the
  // record's path), the stale confirm for N deletes the live successor M — the
  // survivor assertion fails.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_confirm_retire_is_id_keyed_and_spares_a_same_path_successor() {
    let fs = FakeFs::new(1);
    let mut reg = registry(fs.clone());
    let mut core = fence_source();
    let scope_n = ScopeId::new(NonZeroU64::new(1).unwrap());
    let scope_m = ScopeId::new(NonZeroU64::new(2).unwrap());
    let name = ".tributaries-sync-aba-structural";
    let path = PathBuf::from("/r").join(name);

    // Incarnation N claims P, then its removal is in flight (its unlink ran, so
    // the file is gone) but its confirm has not yet landed.
    let guard_n = dispatched_guard(&mut reg, &mut core, scope_n, name);
    fs.put(&path, FileKind::File, 1);
    let id_n = guard_n
      .claim(&fs.cookie_residue_at(&path))
      .expect("N claims P");
    {
      let mut inner = lock_ledger(&reg.ledger);
      inner
        .obligations
        .get_mut(&id_n)
        .expect("N's record is present")
        .phase = Phase::Removing { attempts: 0 };
    }
    fs.remove(&path); // N's unlink physically ran

    // Incarnation M reclaims the same path and owns the live file.
    let guard_m = dispatched_guard(&mut reg, &mut core, scope_m, name);
    fs.put(&path, FileKind::File, 2);
    let id_m = guard_m
      .claim(&fs.cookie_residue_at(&path))
      .expect("M reclaims P");

    // N's stale confirm lands: retire N. Keyed by id, it removes only N.
    lock_ledger(&reg.ledger).retire(id_n, Reaped::ConfirmedGone);
    {
      let inner = lock_ledger(&reg.ledger);
      assert!(!inner.obligations.contains_key(&id_n), "N is retired");
      assert!(
        matches!(
          inner.obligations.get(&id_m).map(|ob| &ob.phase),
          Some(Phase::Owned)
        ),
        "the successor M survives the stale confirm for N"
      );
      assert_eq!(
        inner.by_path.get(&path),
        Some(&id_m),
        "by_path still names M"
      );
    }
    assert!(
      fs.files_under("/r").contains(&path),
      "M's live file survives the stale confirm"
    );

    // M reaps normally to a typed terminal; physical state converges.
    let (op_tx, _op_rx) = async_channel::unbounded::<OpResult<FakeHandle>>();
    reg.sweep_owned::<TokioRuntime>(&op_tx);
    settle(|| reg.len() == 0 && fs.files_under("/r").is_empty()).await;
    assert_eq!(reg.len(), 0, "M is confirmed gone");
    assert!(fs.files_under("/r").is_empty(), "the physical file is gone");
  }

  // A stale self-reap (carrying an incarnation id that no longer matches the
  // record at the path) must NEVER physically unlink the path: the successor's
  // live file (or whatever now lives there) is not ours to delete.
  //
  // Fail-on-old is STRUCTURAL: the old `self_reap(refusal: bool)` has no id, and
  // with an ABSENT record its `None => {}` fall-through unlinks `P` outright
  // (`cookie_remove_dispatches == 1`) — the wrong-file-delete the id guard closes.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_stale_self_reap_never_unlinks_a_successor_cookie() {
    let fs = FakeFs::new(1);
    let mut reg = registry(fs.clone());
    let mut core = fence_source();
    let scope = ScopeId::new(NonZeroU64::new(7).unwrap());
    let name = ".tributaries-sync-stale-selfreap";
    let path = PathBuf::from("/r").join(name);

    // A real claim inserts record M (Owned) at P.
    let guard = dispatched_guard(&mut reg, &mut core, scope, name);
    let m = guard
      .claim(&fs.cookie_residue_at(&path))
      .expect("the claim lands");
    let stale = CookieId(m.0 + 999);

    // Case A: record M present, self-reap with a STALE id — no unlink, untouched.
    self_reap(&fs, &guard, fs.cookie_residue_at(&path), Some(stale));
    assert_eq!(
      fs.cookie_remove_dispatches(),
      0,
      "no unlink was attempted for a stale id"
    );
    assert!(
      lock_ledger(&reg.ledger)
        .obligations
        .get(&m)
        .is_some_and(|ob| matches!(ob.phase, Phase::Owned)
          && ob.residue.as_ref().map(CookieResidue::path) == Some(&*path)),
      "the live record M is untouched"
    );

    // Case B: NO record at P (a racing cancel confirmed our record away, a
    // successor could own the path) — a stale self-reap still must not unlink.
    {
      let mut inner = lock_ledger(&reg.ledger);
      inner.obligations.clear();
      inner.by_path.clear();
      inner.by_name.clear();
    }
    self_reap(&fs, &guard, fs.cookie_residue_at(&path), Some(stale));
    assert_eq!(
      fs.cookie_remove_dispatches(),
      0,
      "no unlink for an absent record either — never a wrong-file delete"
    );
  }

  // A stale removal report (for an incarnation the ledger no longer holds) must touch NOTHING of
  // the successor that reclaimed its path: not its attempts, not the LRU clock, not its live
  // deadline. Both halves of the completion split are id-guarded — the pool-side failure TRUTH
  // (`record_remove_failed`, written by the job that performed the unlink) and the driver-side
  // SCHEDULING (`on_cookie_remove_done`, the only writer of deadlines).
  //
  // Fail-on-old is STRUCTURAL: the old `record_remove_failed(path)` / `on_cookie_remove_done(path,
  // …)` carry no id, so the stale failure bumps attempts to 3 and both stale arms remove the
  // path-keyed slot.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_stale_remove_failure_does_not_touch_the_successors_state() {
    let fs = FakeFs::new(1);
    let reg = registry(fs.clone());
    let cfg = tuned_config();
    let scope = ScopeId::new(NonZeroU64::new(3).unwrap());
    let name = ".tributaries-sync-stale-fail";
    let path = PathBuf::from("/r").join(name);
    let m = CookieId(42);
    // M is SCHEDULED: its deadline is a field of its own record, so no other
    // incarnation can address, clobber, or inherit it.
    let scheduled = Instant::from_origin(Duration::from_secs(100));
    {
      let mut inner = lock_ledger(&reg.ledger);
      inner.obligations.insert(
        m,
        Obligation {
          scope,
          name: name.to_owned(),
          ticket: m.0,
          id: m,
          residue: Some(fs.cookie_residue_at(&path)),
          reap_requested: false,
          last_failure_seq: 5,
          phase: Phase::RemoveFailed {
            attempts: 2,
            retry_at: Some(scheduled),
          },
        },
      );
      inner.by_name.insert(name.to_owned(), m);
      inner.by_path.insert(path.clone(), m);
      inner.failure_clock = 5;
    }
    let k = CookieId(m.0 + 1); // a stale successor id
    let now = Instant::from_origin(Duration::from_secs(0));

    // The pool-side half: a stale failure writes no truth at all.
    assert_eq!(
      lock_ledger(&reg.ledger).record_remove_failed(k),
      None,
      "a stale failure reports no attempt count — it transitioned nothing"
    );
    // The driver-side half: neither a stale failure nor a stale confirm schedules anything.
    on_cookie_remove_done(&reg, &cfg, k, false, now, false);
    on_cookie_remove_done(&reg, &cfg, k, true, now, false);

    let inner = lock_ledger(&reg.ledger);
    assert!(
      matches!(
        inner.obligations.get(&m).map(|ob| &ob.phase),
        Some(Phase::RemoveFailed {
          attempts: 2,
          retry_at: Some(at),
        }) if *at == scheduled
      ),
      "M keeps its attempts AND its own live deadline through both stale reports"
    );
    assert_eq!(
      inner.failure_clock, 5,
      "a stale failure never advances the LRU clock"
    );
    assert_eq!(
      inner.obligations.get(&m).map(|ob| ob.last_failure_seq),
      Some(5),
      "…nor refreshes the successor's LRU key"
    );
  }

  // Every removal dispatch is id-matched: only a request carrying the record's
  // CURRENT incarnation id transitions it. The public path-addressed contract is
  // preserved through the ingress, which resolves the path to an id — so "remove
  // the cookie at this path" still acts on the record currently at the path, and
  // does so without a path-addressed decision existing in the driver at all.
  //
  // Fail-on-old is STRUCTURAL: the `Targeted(id)`/`RetryDue(id)` variants do not
  // exist, and old `RetryDue` dispatches any `RemoveFailed` at the path.
  #[tokio::test(flavor = "multi_thread")]
  async fn retry_and_targeted_dispatch_are_id_matched() {
    let fs = FakeFs::new(1);
    let (reg, cleanup, _wake) = registry_with_ingress(fs.clone());
    let scope = ScopeId::new(NonZeroU64::new(9).unwrap());
    let path = PathBuf::from("/r/.tributaries-sync-idmatch");
    let m = CookieId(100);
    {
      let mut inner = lock_ledger(&reg.ledger);
      inner.obligations.insert(
        m,
        Obligation {
          scope,
          name: "n".to_owned(),
          ticket: m.0,
          id: m,
          residue: Some(fs.cookie_residue_at(&path)),
          reap_requested: false,
          last_failure_seq: 1,
          phase: Phase::RemoveFailed {
            attempts: 1,
            retry_at: None,
          },
        },
      );
      inner.by_name.insert("n".to_owned(), m);
      inner.by_path.insert(path.clone(), m);
    }
    let k = CookieId(m.0 + 7);

    // A stale RetryDue is a no-op.
    {
      let mut inner = lock_ledger(&reg.ledger);
      let d =
        CookieRegistry::<FakeFs>::removal_decision_locked(&mut inner, &RemovalRequest::RetryDue(k));
      assert!(d.is_none(), "a stale RetryDue dispatches nothing");
      assert!(matches!(
        inner.obligations.get(&m).map(|ob| &ob.phase),
        Some(Phase::RemoveFailed {
          attempts: 1,
          retry_at: None
        })
      ));
    }
    // A stale Targeted is a no-op.
    {
      let mut inner = lock_ledger(&reg.ledger);
      let d =
        CookieRegistry::<FakeFs>::removal_decision_locked(&mut inner, &RemovalRequest::Targeted(k));
      assert!(d.is_none(), "a stale Targeted dispatches nothing");
      assert!(matches!(
        inner.obligations.get(&m).map(|ob| &ob.phase),
        Some(Phase::RemoveFailed {
          attempts: 1,
          retry_at: None
        })
      ));
    }
    // A matching Targeted re-arms the parked record.
    {
      let mut inner = lock_ledger(&reg.ledger);
      let d =
        CookieRegistry::<FakeFs>::removal_decision_locked(&mut inner, &RemovalRequest::Targeted(m));
      assert_eq!(
        d.map(|(_, id)| id),
        Some(m),
        "a matching Targeted dispatches M"
      );
      assert!(matches!(
        inner.obligations.get(&m).map(|ob| &ob.phase),
        Some(Phase::Removing { attempts: 0 })
      ));
    }
    // The PUBLIC path-addressed request on a fresh `Owned` record dispatches
    // (public semantics pinned). The path resolves to an id at the door, so what
    // reaches the decision is the same id-addressed request every internal
    // producer makes.
    let fresh = PathBuf::from("/r/.tributaries-sync-idmatch-2");
    let f = CookieId(200);
    {
      let mut inner = lock_ledger(&reg.ledger);
      inner.obligations.insert(
        f,
        Obligation {
          scope,
          name: "n2".to_owned(),
          ticket: f.0,
          id: f,
          residue: Some(fs.cookie_residue_at(&fresh)),
          reap_requested: false,
          last_failure_seq: 0,
          phase: Phase::Owned,
        },
      );
      inner.by_name.insert("n2".to_owned(), f);
      inner.by_path.insert(fresh.clone(), f);
    }
    cleanup.request_remove(&fresh);
    assert!(
      lock_ledger(&reg.ledger)
        .obligations
        .get(&f)
        .is_some_and(|ob| ob.reap_requested),
      "the path resolved to the record currently at it, and marked THAT record"
    );
    {
      let mut inner = lock_ledger(&reg.ledger);
      let d =
        CookieRegistry::<FakeFs>::removal_decision_locked(&mut inner, &RemovalRequest::Targeted(f));
      assert_eq!(
        d.map(|(_, id)| id),
        Some(f),
        "the marked record at the path dispatches"
      );
      assert!(matches!(
        inner.obligations.get(&f).map(|ob| &ob.phase),
        Some(Phase::Removing { attempts: 0 })
      ));
    }
  }

  /// The DIRECTORY-ONLY obligation: what a record becomes when its cookie has
  /// settled and the directory minted to hold it has not.
  ///
  /// These cells mint a REAL [`CookieDir`] — the type has no other constructor,
  /// and none is wanted — and drive it against the fake, because what they pin is
  /// the ledger's state machine and not any platform's syscalls. The disposal
  /// verdict comes from the fake for the same reason the removal verdict always
  /// has: this crate's development host keeps ONE shared cookie directory whose
  /// real disposal cannot fail (`CookieDir::dispose` there is a no-op success), so
  /// a directory that SURVIVES its obligation has no other source here.
  #[cfg(all(
    not(miri),
    any(target_os = "linux", target_os = "macos", target_os = "windows")
  ))]
  mod directory_only {
    use super::*;

    /// A real, unique parent for one cell, with a real cookie directory minted
    /// inside it — the anchored shape a real write produces.
    fn minted(tag: &str) -> (PathBuf, Arc<CookieDir>) {
      use std::sync::atomic::{AtomicU32, Ordering};
      static COUNTER: AtomicU32 = AtomicU32::new(0);
      let parent = std::env::temp_dir().join(format!(
        "tributary-fs-dironly-{}-{}-{}",
        tag,
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
      ));
      std::fs::create_dir_all(&parent).expect("create the scratch parent");
      let dir = Arc::new(CookieDir::open_or_create(&parent).expect("a cookie directory is minted"));
      (parent, dir)
    }

    /// One landed cookie ANCHORED to that directory, in the shape only a real
    /// write mints: a create's own descriptor, and the identity read off it.
    ///
    /// The file is real so the pin holds something; the fake's node map is what
    /// the removal's identity proof actually reads, so the landing is staged
    /// there under `ino` and the two agree by construction.
    fn anchored_cookie(fs: &FakeFs, dir: &Arc<CookieDir>, name: &str, ino: u64) -> CookieFile {
      let created = dir
        .create(name)
        .expect("a cookie is created in the minted directory");
      let landing = dir.path().join(name);
      fs.put(&landing, FileKind::File, ino);
      let identity = fs
        .cookie_at(&landing)
        .identity()
        .expect("the staged node answers an identity");
      CookieFile::anchored(
        Arc::clone(dir),
        name,
        CookieProof::Object(identity),
        created,
      )
    }

    fn phase_of(reg: &CookieRegistry<FakeFs>, id: CookieId) -> Option<Phase> {
      lock_ledger(&reg.ledger)
        .obligations
        .get(&id)
        .map(|ob| match ob.phase {
          Phase::Parked { fence } => Phase::Parked { fence },
          Phase::InPool => Phase::InPool,
          Phase::Owned => Phase::Owned,
          Phase::Removing { attempts } => Phase::Removing { attempts },
          Phase::RemoveFailed { attempts, retry_at } => Phase::RemoveFailed { attempts, retry_at },
        })
    }

    /// A retry after the pin is SPENT never touches a name again.
    ///
    /// The reap settles the cookie, releases the create's retained handle, and
    /// then fails to dispose of the directory. From that instant the identity the
    /// record captured names nothing: the kernel is free to reissue the file id
    /// the pin was holding out of the allocator's reach, so a successor bound at
    /// the cookie's name can be handed the very same id and compare EQUAL. This
    /// cell stages exactly that — the name re-taken by a stranger carrying the
    /// REISSUED identity — and requires the retry to leave it alone.
    ///
    /// It cannot merely decline to delete it. The retry must not consult the name
    /// at all, and it structurally cannot: the record's residue is
    /// `CookieResidue::Dir`, which holds no `CookieFile`, so there is no argument
    /// with which `FsOps::remove_cookie` could be called. `cookie_remove_dispatches`
    /// is the observable for that — it counts every removal that reached the
    /// blocking pool, before any proof is consulted.
    ///
    /// FAIL-ON-REVERT: leave the residue shaped as a `File` across the failed
    /// disposal (which is what a record carrying `Option<CookieFile>` has no
    /// choice but to do) and the retry re-enters the identity arm, matches the
    /// reissued id, and deletes the stranger's file — the last three assertions
    /// fail together.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_retry_after_the_pin_is_spent_never_consults_the_cookies_name() {
      let (parent, dir) = minted("spent-pin");
      let fs = FakeFs::new(1);
      let mut reg = registry(fs.clone());
      let mut core = fence_source();
      let scope = ScopeId::new(NonZeroU64::new(21).unwrap());
      let name = ".tributaries-sync-spent-pin";
      let landing = dir.path().join(name);
      let (op_tx, _op_rx) = async_channel::unbounded::<OpResult<FakeHandle>>();

      let guard = dispatched_guard(&mut reg, &mut core, scope, name);
      let residue = CookieResidue::File(anchored_cookie(&fs, &dir, name, 4242));
      let id = guard.claim(&residue).expect("the claim lands");

      // Something is inside the directory, so its disposition will refuse — the
      // same-uid peer case, and the one that makes the directory outlive the
      // cookie it held.
      fs.fail_cookie_disposal_of(dir.path());

      reg.request_removal::<TokioRuntime>(&op_tx, RemovalRequest::Targeted(id));
      settle(|| matches!(phase_of(&reg, id), Some(Phase::RemoveFailed { .. }))).await;

      assert_eq!(
        (
          fs.cookie_remove_dispatches(),
          fs.cookie_dispose_dispatches()
        ),
        (1, 1),
        "staging: the file half settled and the directory half did not"
      );
      {
        let inner = lock_ledger(&reg.ledger);
        let ob = inner.obligations.get(&id).expect("the record is retained");
        assert!(
          matches!(
            ob.phase,
            Phase::RemoveFailed {
              attempts: 1,
              retry_at: None
            }
          ),
          "a surviving directory keeps the obligation counted and parked for retry"
        );
        assert_eq!(
          ob.residue.as_ref().and_then(CookieResidue::owed_dir),
          Some(dir.path()),
          "what it owes is the DIRECTORY — the whole of what is left"
        );
        assert!(
          ob.residue.as_ref().and_then(CookieResidue::file).is_none(),
          "and it owes no file half, so it carries no identity and no pin: there \
           is nothing left for a comparison to be made with"
        );
      }

      // The identity slot the spent pin released, reissued to a stranger who has
      // taken the cookie's name. This is the object the stale comparison would
      // match.
      fs.put(&landing, FileKind::File, 4242);

      reg.request_removal::<TokioRuntime>(&op_tx, RemovalRequest::RetryDue(id));
      settle(|| fs.cookie_dispose_dispatches() == 2).await;
      settle(|| matches!(phase_of(&reg, id), Some(Phase::RemoveFailed { .. }))).await;

      assert_eq!(
        fs.cookie_remove_dispatches(),
        1,
        "the retry performed NO file removal: a record whose pin is spent has no \
         name it may still speak for"
      );
      assert!(
        fs.files_under(dir.path()).contains(&landing),
        "the stranger holding the reissued identity is untouched"
      );
      assert!(
        matches!(
          phase_of(&reg, id),
          Some(Phase::RemoveFailed { attempts: 2, .. })
        ),
        "and the retry rode the SAME attempt budget the file half was retried on"
      );

      // Whatever was holding the directory goes away; the next retry converges.
      fs.clear_cookie_disposal_failure_of(dir.path());
      reg.request_removal::<TokioRuntime>(&op_tx, RemovalRequest::RetryDue(id));
      settle(|| reg.len() == 0).await;
      assert_eq!(
        reg.len(),
        0,
        "the obligation retires once the directory is gone"
      );
      assert_eq!(
        fs.cookie_remove_dispatches(),
        1,
        "…having never repeated the file removal"
      );

      let _ = std::fs::remove_dir_all(&parent);
    }

    /// A write that FAILED after minting its directory is counted, retried, and
    /// retired on evidence — never `NeverCreated`.
    ///
    /// `CookieWriteError::clean` means "nothing of this write is on disk". Once a
    /// directory has been minted that is false wherever the directory is the
    /// obligation's own, and reporting it anyway retires the record
    /// `NeverCreated`, frees the cap slot that was supposed to bound exactly this,
    /// and leaves the directory to `CookieDir::drop` — whose failure is discarded
    /// by design. A peer that races the cookie's name into the fresh directory
    /// without replacing the directory produces that failure on every attempt, so
    /// every repeat would leave another permanent, uncounted directory.
    ///
    /// The verdict itself is platform-specific and this cell asserts THIS host's:
    /// a platform that mints per obligation owes the directory, and one that
    /// shares a single directory owes nothing, so `clean` is the literal truth
    /// there. What the rest of the cell drives is the LEDGER half, which is the
    /// same everywhere — so the residue is built here, exactly as
    /// `post_mint_failure` builds it where one is owed.
    ///
    /// FAIL-ON-REVERT: retire the obligation `NeverCreated` on this failure (which
    /// is what a `clean` verdict makes the write path do) and the live count, the
    /// census, and the phase all fail at once — with the directory still on disk.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_post_mint_write_failure_is_counted_and_retried_not_never_created() {
      let (parent, dir) = minted("post-mint");
      let fs = FakeFs::new(1);
      let mut reg = registry(fs.clone());
      let mut core = fence_source();
      let scope = ScopeId::new(NonZeroU64::new(22).unwrap());
      let name = ".tributaries-sync-post-mint";
      let landing = dir.path().join(name);
      let (op_tx, _op_rx) = async_channel::unbounded::<OpResult<FakeHandle>>();

      // The write path's own verdict for a failure that lands after the mint.
      let failure = post_mint_failure(
        &dir,
        name,
        std::io::Error::new(
          std::io::ErrorKind::AlreadyExists,
          "a peer took the cookie's name",
        ),
      );
      assert_eq!(
        failure.residue.is_some(),
        dir.owed(landing.clone()).is_some(),
        "a post-mint failure reports a residue exactly where the directory is this \
         obligation's to destroy, and reports `clean` only where nothing of the \
         write is left for anyone to reap"
      );
      if cfg!(all(target_os = "windows", not(miri))) {
        assert_eq!(
          failure.residue.as_deref().and_then(CookieResidue::owed_dir),
          Some(dir.path()),
          "the platform that mints per obligation hands the DIRECTORY back"
        );
        assert!(
          failure
            .residue
            .as_deref()
            .and_then(CookieResidue::file)
            .is_none(),
          "…and only the directory: no file was ever created for this failure"
        );
      } else {
        assert!(
          failure.residue.is_none(),
          "the platform that SHARES one cookie directory owes nothing for it — \
           counting it would admit a debt no obligation may ever discharge"
        );
      }

      // The ledger half, which is one shape on every platform: the residue such a
      // failure hands back where a directory IS owed.
      let residue = CookieResidue::Dir(CookieDirDebt {
        path: landing.clone(),
        dir: Arc::clone(&dir),
      });
      fs.fail_cookie_disposal_of(dir.path());

      let guard = dispatched_guard(&mut reg, &mut core, scope, name);
      let claimed = guard.claim(&residue);
      assert!(
        claimed.is_some(),
        "the residue is admitted like any owned cookie"
      );
      self_reap(&fs, &guard, residue, claimed);

      let id = claimed.expect("the claim landed");
      assert_eq!(
        reg.len(),
        1,
        "the obligation did NOT retire: its directory is on disk"
      );
      assert!(
        matches!(
          phase_of(&reg, id),
          Some(Phase::RemoveFailed {
            attempts: 1,
            retry_at: None
          })
        ),
        "it reaches RemoveFailed — counted by both caps, parked for the driver to \
         schedule, swept by close"
      );
      assert_eq!(
        fs.cookie_remove_dispatches(),
        0,
        "and it never asked for a file removal: there is no file, and no identity \
         with which to ask for one"
      );
      let (census, live) = reg.census();
      assert_eq!(
        (census.births, census.never_created, live),
        (1, 0, 1),
        "nothing here is `NeverCreated`: something WAS created"
      );
      assert_eq!(
        lock_ledger(&reg.ledger).by_path.get(&landing),
        Some(&id),
        "the landing is published, so a path-addressed removal still resolves it"
      );

      // The directory becomes disposable; the retry converges on evidence.
      fs.clear_cookie_disposal_failure_of(dir.path());
      reg.request_removal::<TokioRuntime>(&op_tx, RemovalRequest::RetryDue(id));
      settle(|| reg.len() == 0).await;
      let (census, live) = reg.census();
      assert_eq!(
        (
          census.births,
          census.confirmed_gone,
          census.never_created,
          live
        ),
        (1, 1, 0, 0),
        "it retires ConfirmedGone — on the disposal's own verdict"
      );
      assert!(
        lock_ledger(&reg.ledger).by_path.is_empty(),
        "and its landing leaves the index with it"
      );
      assert_eq!(
        fs.cookie_remove_dispatches(),
        0,
        "still no file removal, ever"
      );

      let _ = std::fs::remove_dir_all(&parent);
    }
  }

  // ==== R11-1: fair, refusing-scope-first recovery re-arm (cells 5–7) ====

  /// How many of `scope`'s records are PARKED (`RemoveFailed`, unscheduled) — the
  /// recovery-fairness oracle.
  async fn parked_for(rig: &Rig, scope: ScopeId) -> usize {
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::DebugCookieParkedFor { scope, reply })
      .await
      .unwrap();
    on_reply.await.expect("the driver replies")
  }

  // The deterministic pin for R11-1's selection order (cell 6). `rearm_parked_batch`
  // serves the REFUSING scope first (its own budget) and then the rest
  // least-recently-FAILED-first — with `last_failure_seq` refreshed on every
  // failure so repeat offenders sink behind records that have not failed since a
  // mount recovered.
  //
  // Every unlink is HELD in the pool and armed to FAIL, so a served record sits in
  // `Removing` until the hold releases: no job can confirm a record away, and none
  // can write its own failure back over it. The SYNCHRONOUS `Removing` transition
  // rearm performs under the decision lock is then a fully deterministic oracle for
  // which records were served.
  #[tokio::test(flavor = "multi_thread")]
  async fn rearm_serves_least_recently_failed_first() {
    fn insert_owned_rec(
      reg: &CookieRegistry<FakeFs>,
      scope: ScopeId,
      name: &str,
      path: &Path,
    ) -> CookieId {
      let mut inner = lock_ledger(&reg.ledger);
      inner.next_cookie_id += 1;
      let id = CookieId(inner.next_cookie_id);
      inner.obligations.insert(
        id,
        Obligation {
          scope,
          name: name.to_owned(),
          ticket: id.0,
          id,
          residue: Some(CookieResidue::File(CookieFile::new(
            path.to_path_buf(),
            RootIdentity::new(1, 0),
          ))),
          reap_requested: false,
          last_failure_seq: 0,
          phase: Phase::Owned,
        },
      );
      inner.by_name.insert(name.to_owned(), id);
      inner.by_path.insert(path.to_path_buf(), id);
      id
    }
    fn is_removing(reg: &CookieRegistry<FakeFs>, path: &Path) -> bool {
      let inner = lock_ledger(&reg.ledger);
      matches!(
        inner
          .by_path
          .get(path)
          .and_then(|id| inner.obligations.get(id))
          .map(|ob| &ob.phase),
        Some(Phase::Removing { .. })
      )
    }
    fn is_parked(reg: &CookieRegistry<FakeFs>, path: &Path) -> bool {
      let inner = lock_ledger(&reg.ledger);
      matches!(
        inner
          .by_path
          .get(path)
          .and_then(|id| inner.obligations.get(id))
          .map(|ob| &ob.phase),
        Some(Phase::RemoveFailed { retry_at: None, .. })
      )
    }

    let sa = ScopeId::new(NonZeroU64::new(1).unwrap()); // scope A
    let sb = ScopeId::new(NonZeroU64::new(2).unwrap()); // scope B
    let sc = ScopeId::new(NonZeroU64::new(3).unwrap()); // scope C (refusing, no parked)
    let a1 = PathBuf::from("/a/a1");
    let a2 = PathBuf::from("/a/a2");
    let b1 = PathBuf::from("/b/b1");

    let fs = FakeFs::new(1);
    fs.fail_next_cookie_removes(1_000_000);
    let hold = fs.hold_cookie_removes();
    let reg = registry(fs.clone());
    let (op_tx, _op_rx) = async_channel::unbounded::<OpResult<FakeHandle>>();

    // Fail each in order: last_failure_seq = 1, 2, 3 for a1, a2, b1.
    let ida1 = insert_owned_rec(&reg, sa, "a1", &a1);
    let ida2 = insert_owned_rec(&reg, sa, "a2", &a2);
    let idb1 = insert_owned_rec(&reg, sb, "b1", &b1);
    let fail = |id| lock_ledger(&reg.ledger).record_remove_failed(id);
    assert_eq!(fail(ida1), Some(1)); // seq 1
    assert_eq!(fail(ida2), Some(1)); // seq 2
    assert_eq!(fail(idb1), Some(1)); // seq 3

    // Refusing = C (no parked of C): others = a1,a2,b1 by seq → [a1,a2] (limit 2).
    let n = reg.rearm_parked_batch::<TokioRuntime>(&op_tx, sc, 2);
    assert_eq!(n, 2, "two records re-armed");
    assert!(is_removing(&reg, &a1), "a1 (seq1) served");
    assert!(is_removing(&reg, &a2), "a2 (seq2) served");
    assert!(
      is_parked(&reg, &b1),
      "b1 (seq3) not served — LRU picks the two oldest"
    );

    // Re-fail a1, a2 (now Removing → RemoveFailed) so their seqs become 4, 5 —
    // BEHIND b1's seq 3: the refresh-on-failure rule sinks repeat offenders.
    assert_eq!(fail(ida1), Some(1)); // seq 4
    assert_eq!(fail(ida2), Some(1)); // seq 5
    let n = reg.rearm_parked_batch::<TokioRuntime>(&op_tx, sc, 2);
    assert_eq!(n, 2);
    assert!(
      is_removing(&reg, &b1),
      "b1 (now oldest at seq3) served this round"
    );
    assert!(is_removing(&reg, &a1), "a1 (seq4) served");
    assert!(
      is_parked(&reg, &a2),
      "a2 (seq5, newest failure) sinks to the back"
    );

    // The two-budget rule: refusing = A, all three parked → a1,a2 (mine) AND b1
    // (others' separate budget) — up to 2·limit dispatches per refusal.
    let fs2 = FakeFs::new(1);
    fs2.fail_next_cookie_removes(1_000_000);
    let hold2 = fs2.hold_cookie_removes();
    let reg2 = registry(fs2.clone());
    let (op_tx2, _op_rx2) = async_channel::unbounded::<OpResult<FakeHandle>>();
    let ja1 = insert_owned_rec(&reg2, sa, "a1", &a1);
    let ja2 = insert_owned_rec(&reg2, sa, "a2", &a2);
    let jb1 = insert_owned_rec(&reg2, sb, "b1", &b1);
    for id in [ja1, ja2, jb1] {
      lock_ledger(&reg2.ledger).record_remove_failed(id);
    }
    let n = reg2.rearm_parked_batch::<TokioRuntime>(&op_tx2, sa, 2);
    assert_eq!(
      n, 3,
      "the refusing scope's budget and the others' budget are separate (≤ 2·limit)"
    );
    assert!(
      is_removing(&reg2, &a1),
      "A's a1 served under the mine-budget"
    );
    assert!(
      is_removing(&reg2, &a2),
      "A's a2 served under the mine-budget"
    );
    assert!(
      is_removing(&reg2, &b1),
      "B's b1 served under the SEPARATE others-budget"
    );

    // Let the held unlink jobs finish so no pool thread outlives the cell.
    hold.release();
    hold2.release();
  }

  /// The R11-1 recovery-fairness config: a low per-scope backlog cap, a budget of
  /// one, and a fast retry so records park and re-arm in real (multi-thread) time.
  fn rearm_fairness_config() -> DriverConfig {
    DriverConfig {
      cookie_retry_base: Duration::from_millis(1),
      cookie_retry_cap: Duration::from_millis(4),
      cookie_retry_budget: 1,
      cookie_backlog_cap: 2,
      cookie_global_cap: 128,
      ..config()
    }
  }

  // A cap refusal re-arms the REFUSING scope's own parked backlog FIRST, so a
  // scope whose mount recovered drains its backlog and is re-admitted even while
  // OTHER scopes' still-failing residue dominates the ledger — the R11-1 property
  // end-to-end through the rig. `/rb` recovers; `/ra` (and a churned pad) keep
  // failing; `/rb` is served within a few refusals regardless.
  //
  // Fail-on-old is OVERWHELMING-PROBABILITY, not certain (old selection rides
  // HashMap iteration order over the whole ledger; padding `/ra`'s side so the
  // old first-`limit` batch is almost surely all-`/ra` makes `/rb` starve, but a
  // seed could still serve it). The DETERMINISTIC pin of the selection order is
  // the unit `rearm_serves_least_recently_failed_first` above.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cap_refusal_rearms_the_refusing_scopes_parked_records_first() {
    let rig = rig_with_config(64, rearm_fairness_config());
    rig.fs.put("/ra", FileKind::Dir, 200);
    rig.fs.put("/rb", FileKind::Dir, 201);
    rig.fs.put("/pad", FileKind::Dir, 202);
    let ra = watch(&rig, "/ra").await;
    let rb = watch(&rig, "/rb").await;
    // Both mounts fail their unlinks; a churned pad dominates the ledger.
    rig.fs.fail_cookie_removes_under("/ra");
    rig.fs.fail_cookie_removes_under("/rb");
    rig.fs.fail_cookie_removes_under("/pad");

    // Park two records on each of /ra and /rb (sequentially, so failure order is
    // deterministic: ra1, ra2, rb1, rb2).
    for i in 0..2 {
      let path = admit_sync(&rig, ra, "/ra", &format!(".tributaries-sync-ra-{i}")).await;
      rig.cleanup.request_remove(&path);
      settle_removes_parked(&rig).await;
    }
    for i in 0..2 {
      let path = admit_sync(&rig, rb, "/rb", &format!(".tributaries-sync-rb-{i}")).await;
      rig.cleanup.request_remove(&path);
      settle_removes_parked(&rig).await;
    }

    // Pad /ra's side of the ledger: ≥ 8 parked records across churned (retired)
    // scopes, so the old scope-blind selection is almost surely all-non-rb.
    for j in 0..8 {
      let root = format!("/pad/p{j}");
      rig.fs.put(&root, FileKind::Dir, 300 + j as u64);
      let scope = watch(&rig, &root).await;
      let path = admit_sync(&rig, scope, &root, &format!(".tributaries-sync-pad-{j}")).await;
      rig.cleanup.request_remove(&path);
      settle_removes_parked(&rig).await;
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Unwatch {
          scope,
          reply: Some(reply),
        })
        .await
        .unwrap();
      let _ = on_reply.await;
      settle_removes_parked(&rig).await;
    }
    assert_eq!(
      parked_for(&rig, rb).await,
      2,
      "/rb has two parked records before recovery"
    );
    assert_eq!(parked_for(&rig, ra).await, 2, "/ra has two parked records");

    // /rb's mount recovers.
    rig.fs.clear_cookie_remove_failures_under("/rb");

    // Loop: each refused sync kicks rearm(refusing=rb); its mine-half re-arms
    // /rb's own backlog, which confirms on the recovered mount and drops.
    let mut admitted = None;
    for _ in 0..3 {
      match sync_root(&rig, rb, "/rb", ".tributaries-sync-rb-recover").await {
        Ok(path) => {
          admitted = Some(path);
          break;
        }
        Err(crate::error::SyncRootError::CleanupBacklog) => {
          settle(|| rig.fs.files_under("/rb").is_empty()).await;
        }
        Err(other) => panic!("unexpected sync error: {other:?}"),
      }
    }
    assert!(
      admitted.is_some(),
      "the recovered /rb was admitted within 3 attempts — its own backlog was re-armed first"
    );

    // The still-failing residue is HONESTLY parked — no lockout, and /rb was
    // served despite the pad dominating the ledger.
    settle_removes_parked(&rig).await;
    assert_eq!(
      parked_for(&rig, ra).await,
      2,
      "/ra's still-failing residue stays parked — never starved rb, never falsely drained"
    );
  }

  // Cell 7: the R10 recovery/global-cap cells
  // (`churn_across_retired_scopes_is_bounded_by_the_global_cap`,
  // `a_recovered_fs_drains_the_backlog_and_admits_new_syncs`) stay green
  // UNMODIFIED — R11-1 is a strict superset (still re-armed on every refusal,
  // still bounded, now prioritized + starvation-free). No new cell; validated by
  // the full-suite run.

  // ==== R11-2: the whole-lifecycle global cap (cells 8–10) ====

  // Hung (blocking, unclaimed) cookie WRITES count against the global cap: the
  // admission gauge Φ is the whole lifecycle in one term — every dispatched write
  // is a counted `InPool` obligation, not just claimed `owned` records. Three held
  // writes fill a cap of 3, so the fourth is refused promptly (an honest,
  // retryable `Busy`) rather than piling a fourth blocking job on the pool.
  //
  // Fail-on-old (the gauge counted only claimed records): with the writes held,
  // nothing is claimed, so the gauge would read 0, the 4th write would be
  // admitted, dispatched, and PARK behind the hold — its reply never resolving,
  // and the prompt-error assertion timing out. Deterministic.
  #[tokio::test(flavor = "multi_thread")]
  async fn hung_writes_count_against_the_global_cap() {
    // global_cap = 3, backlog_cap = 8 (the per-scope cap never binds — each scope
    // owns at most one in-flight write).
    let rig = rig_with_config(64, low_global_cap_config());
    let mut scopes = Vec::new();
    for i in 1..=4 {
      let root = format!("/r{i}");
      rig.fs.put(&root, FileKind::Dir, 400 + i as u64);
      scopes.push((root.clone(), watch(&rig, &root).await));
    }

    // Every cookie write hangs in the pool — a genuinely backlogged/hung fs.
    let hold = rig.fs.hold_cookie_writes();

    // r1, r2, r3 each admit, park, and dispatch a blocking write into the held
    // pool; settle the dispatch growth so each is counted before the next.
    let mut pending_replies = Vec::new();
    for (i, (root, scope)) in scopes.iter().take(3).enumerate() {
      let reply =
        sync_root_pending(&rig, *scope, root, &format!(".tributaries-sync-hung-{i}")).await;
      pending_replies.push(reply);
      let want = i + 1;
      settle(|| rig.fs.cookie_dispatches() >= want).await;
      assert_eq!(
        rig.fs.cookie_dispatches(),
        want,
        "each held write is dispatched and counted before the next admission"
      );
    }

    // The 4th sync: the gauge is `unremoved()` (3 hung in-pool writes) + parked (0)
    // = 3 ≥ cap → refused PROMPTLY, never queued behind the hold.
    let (root4, scope4) = &scopes[3];
    let r4_reply = sync_root_pending(&rig, *scope4, root4, ".tributaries-sync-hung-4").await;
    let r4 = tokio::time::timeout(interpreted_secs(3), r4_reply)
      .await
      .expect("the 4th admission refusal resolves promptly, never pends behind the write hold")
      .expect("the driver replies");
    assert!(
      matches!(r4, Err(crate::error::SyncRootError::CleanupBacklog)),
      "the 4th hung write is refused — hung writes count against the whole-lifecycle cap, got {r4:?}"
    );

    // Cleanup: release the hold so the held writes drain, then drop the receivers.
    hold.release();
    settle(|| rig.fs.cookie_writes().len() >= 3).await;
    drop(pending_replies);
  }

  // The global cookie cap counts every in-flight write by its own INCARNATION id,
  // never collapsing distinct writes into one gauge slot: k held writes across k
  // disjoint scopes are k records, so the cap binds at the (cap+1)-th admission and
  // a caller cannot flood the blocking pool past it. The property is ID-COUNTING,
  // so it is pinned with DISTINCT names — a caller reusing ONE name across live
  // obligations is now refused `NameInUse` before a second same-name write can even
  // be dispatched (folded below; the umbrella mints per-sync-unique names, so it
  // never trips either path).
  //
  // Fail-on-old (a gauge that collapsed writes): the (cap+1)-th sync would be
  // ADMITTED, its held write would PARK behind the hold, and the prompt-refusal
  // assertion would time out. Deterministic via the write hold.
  #[tokio::test(flavor = "multi_thread")]
  async fn distinct_name_writes_on_disjoint_scopes_each_count_against_the_global_cap() {
    // global_cap = 3, backlog_cap = 8 (the per-scope cap never binds — one cookie
    // per scope).
    let rig = rig_with_config(64, low_global_cap_config());
    let cap = low_global_cap_config().cookie_global_cap;

    // cap + 1 disjoint scopes, each separately rooted.
    let mut scopes = Vec::new();
    for i in 0..=cap {
      let root = format!("/rs{i}");
      rig.fs.put(&root, FileKind::Dir, 700 + i as u64);
      scopes.push((root.clone(), watch(&rig, &root).await));
    }

    // Scope 0's sync COMPLETES and leaves one cookie owned (unlink unconfirmed).
    let (root0, scope0) = &scopes[0];
    let owned = admit_sync(&rig, *scope0, root0, ".tributaries-sync-distinct-0").await;
    assert_eq!(
      owned,
      PathBuf::from(format!("{root0}/.tributaries-sync-distinct-0"))
    );
    settle_cookie_count(&rig, 1).await;

    // Folded: a second admission reusing the held name is refused `NameInUse`
    // before it can mint a record — a same-name flood cannot even begin (the
    // cross-scope refusal is pinned end-to-end in
    // `a_live_cookie_name_is_refused_across_scopes_and_cancel_by_name_reaps_the_holder`).
    let (root1, scope1) = &scopes[1];
    assert!(
      matches!(
        sync_root(&rig, *scope1, root1, ".tributaries-sync-distinct-0").await,
        Err(crate::error::SyncRootError::NameInUse { .. })
      ),
      "a second live obligation under the held name is refused NameInUse, never dispatched"
    );

    // From here every write hangs in the pool; each DISTINCTLY named held write must
    // add one MORE obligation (by its own id), never be masked.
    let hold = rig.fs.hold_cookie_writes();

    // Syncs on scopes 1..cap, each distinctly named: each admits and dispatches a
    // held write. With owned(1) + (cap-1) held writes the gauge reaches the cap.
    let mut pending = Vec::new();
    for (j, (root, scope)) in scopes[1..cap].iter().enumerate() {
      let name = format!(".tributaries-sync-distinct-{}", j + 1);
      let reply = sync_root_pending(&rig, *scope, root, &name).await;
      pending.push(reply);
      // owned's completed write (1) + this held write and its predecessors.
      let want = j + 2;
      settle(|| rig.fs.cookie_dispatches() >= want).await;
      assert_eq!(
        rig.fs.cookie_dispatches(),
        want,
        "each distinct-name held write is dispatched and counted by id before the next admission"
      );
    }

    // The (cap+1)-th sync (scope `cap`), distinctly named: the gauge is owned(1) +
    // (cap-1) held = cap ≥ cap → refused PROMPTLY, never parked behind the hold.
    let (root_last, scope_last) = &scopes[cap];
    let last_reply = sync_root_pending(
      &rig,
      *scope_last,
      root_last,
      ".tributaries-sync-distinct-last",
    )
    .await;
    let last = tokio::time::timeout(interpreted_secs(3), last_reply)
      .await
      .expect("the (cap+1)-th refusal resolves promptly, never pends behind the write hold")
      .expect("the driver replies");
    assert!(
      matches!(last, Err(crate::error::SyncRootError::CleanupBacklog)),
      "the write past the cap is refused — id-counting counts each once, got {last:?}"
    );

    // Cleanup: release the hold so the held writes drain, then drop the receivers.
    hold.release();
    settle(|| rig.fs.cookie_writes().len() >= cap).await;
    drop(pending);
  }

  /// Cell 10's config: a global cap of 2 (backlog never binds), so one claimed
  /// self-reap plus one fresh sync sit exactly at the boundary the dedup governs.
  fn double_bar_config() -> DriverConfig {
    DriverConfig {
      cookie_retry_base: Duration::from_millis(5),
      cookie_retry_cap: Duration::from_millis(20),
      cookie_retry_budget: 3,
      cookie_backlog_cap: 8,
      cookie_global_cap: 2,
      ..config()
    }
  }

  // A claimed self-reap that is still mid-unlink counts as ONE against the cap — so a second
  // scope's sync is admitted at a cap of 2 rather than double-barred by one physical
  // obligation. One write has one record for its whole life, so this holds by construction.
  //
  // GUARD CELL: it pins the gauge against any widening that would tally one physical write
  // more than once (reading 2 here, and wrongly refusing scope 2).
  #[tokio::test(flavor = "multi_thread")]
  async fn a_claimed_self_reap_does_not_double_bar_admission() {
    let rig = rig_with_config(64, double_bar_config());
    rig.fs.put("/r1", FileKind::Dir, 500);
    rig.fs.put("/r2", FileKind::Dir, 501);
    let s1 = watch(&rig, "/r1").await;
    let s2 = watch(&rig, "/r2").await;

    // Stage scope 1's claimed-but-reply-failed self-reap, parked mid-unlink.
    let hold_w = rig.fs.hold_cookie_writes();
    let r1_reply = sync_root_pending(&rig, s1, "/r1", ".tributaries-sync-double-1").await;
    settle(|| rig.fs.cookie_dispatches() >= 1).await;
    drop(r1_reply); // the caller abandons the sync — reply.send will fail
    let hold_r = rig.fs.hold_cookie_removes();
    hold_w.release(); // the write proceeds: it claims, reply.send fails, self-reap unlinks
    settle(|| rig.fs.cookie_remove_dispatches() >= 1).await;
    assert_eq!(
      rig.fs.cookie_remove_dispatches(),
      1,
      "the claimed self-reap parked mid-unlink, its write's completion still outstanding"
    );

    // Scope 2 admits: the one physical obligation is one record, so the gauge is 1 < 2. A
    // widening that counted its write and its record separately would read 2 and refuse.
    let path2 = admit_sync(&rig, s2, "/r2", ".tributaries-sync-double-2").await;
    assert_eq!(
      path2,
      PathBuf::from("/r2/.tributaries-sync-double-2"),
      "scope 2 is admitted and completes — the claimed self-reap did not double-bar the cap"
    );

    // Cleanup: release the unlink so the self-reap confirms and drains.
    hold_r.release();
    settle(|| rig.fs.cookie_removes().iter().any(|p| p.starts_with("/r1"))).await;
  }
  // The single-flight write gate is a PHASE PROBE over the one ledger: a scope with an
  // obligation `InPool` refuses a second sync, and the gate opens the moment that write leaves
  // `InPool` — at its CLAIM, or at the typed terminal of a write that created nothing — rather
  // than at the tail of its completion message. A scope can therefore transiently hold one write
  // JOB plus one COMPLETING TAIL (a claimed write whose completion is still in flight). That is
  // the ACCEPTED WIDENING, and the bound the gate exists for still holds: at most one
  // `write_cookie` syscall per scope is ever outstanding, so a caller that times out and retries
  // still cannot pile blocking writes against a hung mount (pinned end-to-end by
  // `a_second_sync_while_a_write_is_in_flight_is_refused`).
  //
  // Through the whole widened window the obligation stays COUNTED: the claim moves the record's
  // PHASE, never its existence, so nothing physical is ever invisible to the close count.
  //
  // Fail-on-old (the claim leaves its record `InPool` instead of transitioning it to `Owned`):
  // the gate never reopens and the "opens at the claim" assertion fails.
  #[tokio::test(flavor = "multi_thread")]
  async fn the_write_gate_opens_at_the_claim_and_never_uncounts_the_obligation() {
    let fs = FakeFs::new(1);
    let mut reg = registry(fs.clone());
    let mut core = fence_source();
    let scope = ScopeId::new(NonZeroU64::new(1).unwrap());
    let other = ScopeId::new(NonZeroU64::new(2).unwrap());
    let path = PathBuf::from("/r/.tributaries-sync-gate");

    // Dispatch: the write's obligation is born `InPool`, shutting its own scope's gate.
    let guard = dispatched_guard(&mut reg, &mut core, scope, ".tributaries-sync-gate");
    assert!(
      reg.has_pending_write(scope),
      "a dispatched write shuts its scope's gate"
    );
    assert!(!reg.has_pending_write(other), "the gate is per scope");
    assert_eq!(
      reg.unremoved(),
      1,
      "the in-pool write is a counted obligation from the instant it can create a file"
    );

    // The CLAIM opens the gate — before this write's completion message is sent, which is the
    // whole of the widening.
    let id = guard
      .claim(&fs.cookie_residue_at(&path))
      .expect("the claim lands");
    assert!(
      !reg.has_pending_write(scope),
      "the gate opens at the claim, not at the completion tail"
    );
    assert!(
      lock_ledger(&reg.ledger)
        .obligations
        .get(&id)
        .is_some_and(|ob| matches!(ob.phase, Phase::Owned)),
      "the claim moved the record's phase, not its existence"
    );
    assert_eq!(
      reg.unremoved(),
      1,
      "the claimed obligation is still counted — never a false Ok(0) across the window"
    );

    // A second write for the scope may now dispatch: ONE write job (this one) alongside the
    // first write's completing tail — never two write jobs.
    let second = dispatched_guard(&mut reg, &mut core, scope, ".tributaries-sync-gate-2");
    assert!(
      reg.has_pending_write(scope),
      "the second write shuts the gate again"
    );
    assert_eq!(reg.unremoved(), 2, "both obligations are counted");

    // A write that created NOTHING opens the gate at its typed terminal, taking its obligation
    // with it — the other way out of `InPool`.
    lock_ledger(&reg.ledger).retire(second.id, Reaped::NeverCreated);
    assert!(
      !reg.has_pending_write(scope),
      "a never-created write's terminal opens the gate"
    );
    assert_eq!(reg.unremoved(), 1, "…and leaves nothing counted behind it");
  }

  // THE CENSUS EQUATION, over every shape a cookie's life can take on one driver: births =
  // ConfirmedGone + NeverCreated + AbnormalResidual + live. It holds only if every obligation
  // that ever left the ledger left through a typed `retire` naming its evidence — so it is the
  // standing structural proof that no obligation can vanish untyped, and the per-variant
  // assertions pin that each terminal is the RIGHT type rather than merely some type.
  //
  // Fail-on-old (any removal that bypasses the typed terminal — e.g. a bare
  // `obligations.remove(&id)` on a confirm): the births no longer balance and the equation fails
  // at the first scenario that exercises it.
  #[tokio::test(flavor = "multi_thread")]
  async fn every_obligation_is_born_counted_and_typed_out() {
    let rig = rig_with_config(64, tuned_config());
    let scope = watch(&rig, "/r").await;

    let census = assert_census_balances(&rig, "a fresh driver").await;
    assert_eq!(census, Census::default(), "nothing is born before a sync");

    // 1. A completed sync, then its reap: born at dispatch, confirmed gone at its unlink.
    let path = admit_sync(&rig, scope, "/r", ".tributaries-sync-census-1").await;
    settle_cookie_count(&rig, 1).await;
    let census = assert_census_balances(&rig, "a completed sync").await;
    assert_eq!(census.births, 1, "the write's obligation was born");
    rig.cleanup.request_remove(&path);
    settle_cookie_count(&rig, 0).await;
    let census = assert_census_balances(&rig, "a reaped cookie").await;
    assert_eq!(
      (census.births, census.confirmed_gone),
      (1, 1),
      "a reaped cookie earns ConfirmedGone from its own syscall"
    );

    // 2. A cancel while the write is IN THE POOL: the refused claim self-reaps, and the file it
    //    created is confirmed gone — the obligation never leaks, whatever the interleaving.
    let name = ".tributaries-sync-census-2";
    let hold = rig.fs.hold_cookie_writes();
    let dispatched = rig.fs.cookie_dispatches();
    let t = ticket();
    let on_reply = sync_root_pending_keyed(&rig, scope, "/r", name, t).await;
    settle(|| rig.fs.cookie_dispatches() == dispatched + 1).await;
    assert_eq!(
      cookie_census(&rig).await.0.births,
      2,
      "the in-pool write is already born"
    );
    rig.cleanup.request_cancel(t);
    settle_reap_marks(&rig, 1).await;
    hold.release();
    let _ = on_reply.await;
    settle_cookie_count(&rig, 0).await;
    let census = assert_census_balances(&rig, "a cancelled in-pool write").await;
    assert_eq!(
      (census.births, census.confirmed_gone),
      (2, 2),
      "the refused claim's self-reap confirmed its own file gone"
    );

    // 3. An ABANDONED reply: the claim lands, `reply.send` fails, the self-reap confirms.
    let hold = rig.fs.hold_cookie_writes();
    let dispatched = rig.fs.cookie_dispatches();
    let on_reply = sync_root_pending(&rig, scope, "/r", ".tributaries-sync-census-3").await;
    settle(|| rig.fs.cookie_dispatches() == dispatched + 1).await;
    drop(on_reply);
    hold.release();
    settle_cookie_count(&rig, 0).await;
    let census = assert_census_balances(&rig, "an abandoned reply").await;
    assert_eq!(
      (census.births, census.confirmed_gone),
      (3, 3),
      "an abandoned sync's cookie is confirmed gone, never orphaned"
    );

    // 4. A HUNG unlink: the obligation stays LIVE and the equation absorbs it there — the term
    //    that keeps the count honest while physical work is still outstanding.
    let path = admit_sync(&rig, scope, "/r", ".tributaries-sync-census-4").await;
    settle_cookie_count(&rig, 1).await;
    let hold = rig.fs.hold_cookie_removes();
    let unlinked = rig.fs.cookie_remove_dispatches();
    rig.cleanup.request_remove(&path);
    settle(|| rig.fs.cookie_remove_dispatches() == unlinked + 1).await;
    let (census, live) = cookie_census(&rig).await;
    assert!(
      census.balances(live),
      "a hung unlink balances as a LIVE record"
    );
    assert_eq!(
      (census.births, live),
      (4, 1),
      "the obligation is still counted while its unlink hangs"
    );
    hold.release();
    settle_cookie_count(&rig, 0).await;
    let census = assert_census_balances(&rig, "a released hung unlink").await;
    assert_eq!((census.births, census.confirmed_gone), (4, 4));

    // 5. A FAILED write (last: the fake's write failure is permanent): nothing physical was ever
    //    created, so the obligation retires as NeverCreated — a distinct, evidenced terminal.
    rig
      .fs
      .fail_cookie_writes(std::io::ErrorKind::PermissionDenied);
    assert!(
      matches!(
        sync_root(&rig, scope, "/r", ".tributaries-sync-census-5").await,
        Err(crate::error::SyncRootError::Write { .. })
      ),
      "the write fails typed"
    );
    settle_cookie_count(&rig, 0).await;
    let census = assert_census_balances(&rig, "a failed write").await;
    assert_eq!(
      (census.births, census.confirmed_gone, census.never_created),
      (5, 4, 1),
      "a write that created nothing retires NeverCreated, never as a confirmed removal"
    );
  }

  // A write that FAILED but left a file behind is not a write that created nothing. The
  // obligation stays counted, keeps owning the file, and never earns the pre-physical
  // `NeverCreated` terminal — because that terminal is what would take the file out of the
  // 128-record cap while it is still on disk, letting repeated attempts fill the tree with
  // artifacts nothing tracks and nothing ever reaps.
  //
  // Removes are failed for the whole cell so the residue's own reap cannot converge: what is
  // left standing at the end is exactly the state the accounting has to survive.
  //
  // Fail-on-old (a discarded residue, `NeverCreated` retired anyway): `never_created` is 1,
  // `live` is 0, and the file is still there — uncounted.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_write_that_stranded_a_file_stays_counted() {
    let rig = rig_with_config(64, tuned_config());
    let scope = watch(&rig, "/r").await;
    rig.fs.fail_next_cookie_removes(usize::MAX);
    rig.fs.strand_cookie_writes(std::io::ErrorKind::Unsupported);

    let denied = sync_root(&rig, scope, "/r", ".tributaries-sync-stranded").await;
    // The retry the failing reap schedules keeps re-entering the pool; settle on the
    // ledger rather than on quiescence, which this cell deliberately never reaches.
    let (census, live) = cookie_census(&rig).await;
    let files = rig.fs.files_under("/r");

    assert!(
      matches!(denied, Err(crate::error::SyncRootError::Write { .. })),
      "the caller is told the write failed: it has no cookie and no barrier"
    );
    assert_eq!(
      census.never_created, 0,
      "a write that left a file on disk never earns the pre-physical terminal"
    );
    assert_eq!(
      (census.births, live),
      (1, 1),
      "its obligation is still counted, so the file it stranded still counts against the cap"
    );
    assert!(
      census.balances(live),
      "births = terminals + live across a stranded write"
    );
    assert_eq!(
      files.len(),
      1,
      "and the file is exactly what the live obligation is still accounting for"
    );
  }

  // The abnormal-path backstop's terminal is typed and counted too: a `Drop` with no orderly
  // close takes every remaining record as an AbnormalResidual, so even the path that exists
  // BECAUSE the driver died accounts for what it swept. Read through a ledger handle cloned
  // before the drop — the census outlives the registry, as the equation requires.
  #[tokio::test(flavor = "multi_thread")]
  async fn the_abnormal_backstop_types_and_counts_what_it_sweeps() {
    let fs = FakeFs::new(1);
    let mut reg = registry(fs.clone());
    let mut core = fence_source();
    let ledger = Arc::clone(&reg.ledger);
    let scope = ScopeId::new(NonZeroU64::new(1).unwrap());

    // One claimed cookie, and one write still in the pool.
    let claimed = dispatched_guard(&mut reg, &mut core, scope, ".tributaries-sync-abnormal-1");
    let path = PathBuf::from("/r/.tributaries-sync-abnormal-1");
    fs.put(&path, FileKind::File, 1);
    claimed
      .claim(&fs.cookie_residue_at(&path))
      .expect("the claim lands");
    let _in_pool = dispatched_guard(&mut reg, &mut core, scope, ".tributaries-sync-abnormal-2");
    assert_eq!(reg.unremoved(), 2, "both obligations are counted");

    drop(reg);
    let (census, live) = {
      let inner = lock_ledger(&ledger);
      (inner.census, inner.obligations.len())
    };
    assert!(
      census.balances(live),
      "the backstop's sweep balances the census"
    );
    assert_eq!(
      (census.births, census.abnormal_residual, live),
      (2, 2, 0),
      "every record the backstop took is counted as the abnormal residual it is"
    );
    // The claimed cookie's file is reaped best-effort; the pathless in-pool write is covered by
    // the raised flag, which makes its claim refuse and the write reap its own file.
    settle(|| fs.files_under("/r").is_empty()).await;
    assert!(fs.files_under("/r").is_empty(), "the swept file is gone");
  }

  // A genuine reap is PROMPT: an otherwise idle driver — parked in its select with no deadline
  // armed, no command inbound, no event flowing — is woken by the request itself and confirms the
  // unlink, earning the `ConfirmedGone` terminal from its own syscall.
  //
  // The cell deliberately observes fs-side only until the terminal has landed: any command
  // (a count probe included) would itself wake the driver and mask what is under test.
  //
  // Fail-on-old (no wake arm — the request lands on the record but rings nothing): the idle driver
  // parks forever on `pending()`, the unlink never dispatches, and the settle times out with the
  // cookie still on disk.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_genuine_reap_wakes_an_idle_driver_and_confirms_gone() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-prompt")
      .await
      .expect("the write lands");
    // Let the driver go fully idle: the sync resolved, so nothing is scheduled and nothing is
    // pending. From here only the cleanup wake can move it.
    settle(|| rig.fs.cookie_writes().contains(&path)).await;
    assert!(
      rig.fs.cookie_removes().is_empty(),
      "nothing is reaped before it is asked for"
    );

    // The request the umbrella's `end_sync` makes, on the path the sync's own reply returned.
    rig.cleanup.request_remove(&path);

    // One wake cycle later the unlink has run — observed fs-side, so no command of ours can be
    // what woke the driver.
    settle(|| rig.fs.cookie_removes().contains(&path)).await;
    assert!(
      rig.fs.cookie_removes().contains(&path),
      "the wake alone drove an idle driver to reap the cookie"
    );
    assert!(
      rig.fs.files_under("/r").is_empty(),
      "the file is gone, not merely dispatched"
    );

    settle_cookie_count(&rig, 0).await;
    let census = assert_census_balances(&rig, "a genuine prompt reap").await;
    assert_eq!(
      (census.births, census.confirmed_gone),
      (1, 1),
      "the reap earned ConfirmedGone from its own syscall verdict"
    );
  }

  // The wake sweep's phase table, cell by cell: a mark on EACH phase resolves to EXACTLY ONE
  // outcome — never two, never none. Scripted at the registry level so each cell is a chosen
  // interleaving rather than a scheduler race, and asserted on the PHASE (which the sweep writes
  // under the lock, synchronously) rather than on a pool job's timing.
  //
  // Together these are every way a cancel can race the machine: the mark racing the DISPATCH
  // (parked), racing the CLAIM (in pool), landing on an owned cookie, racing an unlink already in
  // flight, and racing a failed record whether or not a retry owns it.
  //
  // Fail-on-old (the mark not read at the dispatch decision, as a free-standing tombstone set was
  // not): the parked cell dispatches a write for a sync already cancelled.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_mark_resolves_to_exactly_one_outcome_per_phase() {
    let fs = FakeFs::new(1);
    let (mut reg, cleanup, _wake) = registry_with_ingress(fs.clone());
    let mut core = fence_source();
    let (op_tx, _op_rx) = async_channel::unbounded::<OpResult<<FakeFs as FsOps>::Handle>>();
    let scope = ScopeId::new(NonZeroU64::new(1).unwrap());
    let phase_of = |reg: &CookieRegistry<FakeFs>, id: CookieId| -> String {
      let inner = lock_ledger(&reg.ledger);
      let ob = inner.obligations.get(&id).expect("the record stands");
      match ob.phase {
        Phase::Parked { .. } => "parked".to_owned(),
        Phase::InPool => "in_pool".to_owned(),
        Phase::Owned => "owned".to_owned(),
        Phase::Removing { attempts } => format!("removing({attempts})"),
        Phase::RemoveFailed { attempts, retry_at } => {
          format!("failed({attempts},{})", retry_at.is_some())
        }
      }
    };

    // PARKED + mark: the mark races the dispatch, and the dispatch refuses on it — the sync is
    // retired pre-physically, so no write is ever made and no file can exist to unlink.
    {
      let name = ".tributaries-sync-phase-parked";
      let t = ticket();
      let fence = core.open_cover_fence(scope);
      let id = reg.admit_parked(scope, name.to_owned(), t.seq(), fence);
      cleanup.request_cancel(t);
      assert!(
        reg.dispatch_guard(scope, id).is_none(),
        "a marked parked sync must never be dispatched"
      );
      assert!(
        !lock_ledger(&reg.ledger).obligations.contains_key(&id),
        "…it is retired right there, pre-physically"
      );
      assert!(fs.cookie_writes().is_empty(), "nothing was ever written");
    }

    // IN POOL + mark: only the write knows where its cookie will land, so the sweep dispatches
    // nothing and the mark SURVIVES — it is what the claim reads and refuses on.
    let in_pool = {
      let name = ".tributaries-sync-phase-inpool";
      let t = ticket();
      let guard = dispatched_guard_keyed(&mut reg, &mut core, scope, name, t.seq());
      let id = guard.id;
      cleanup.request_cancel(t);
      reg.sweep_reap_marks::<TokioRuntime>(&op_tx);
      assert_eq!(
        phase_of(&reg, id),
        "in_pool",
        "the sweep dispatched nothing"
      );
      assert!(
        lock_ledger(&reg.ledger).obligations[&id].reap_requested,
        "the mark stays for the claim to refuse on"
      );
      let path = PathBuf::from("/r").join(name);
      fs.put(&path, FileKind::File, 1);
      assert!(
        guard.claim(&fs.cookie_residue_at(&path)).is_none(),
        "the claim refuses on the mark"
      );
      (guard, path)
    };

    let hold = fs.hold_cookie_removes();
    // OWNED + mark: exactly one unlink is dispatched, and the mark dies with the action it caused.
    let owned = {
      let name = ".tributaries-sync-phase-owned";
      let guard = dispatched_guard(&mut reg, &mut core, scope, name);
      let id = guard.id;
      let path = PathBuf::from("/r").join(name);
      fs.put(&path, FileKind::File, 1);
      guard
        .claim(&fs.cookie_residue_at(&path))
        .expect("the claim lands");
      cleanup.request_remove(&path);
      reg.sweep_reap_marks::<TokioRuntime>(&op_tx);
      assert_eq!(
        phase_of(&reg, id),
        "removing(0)",
        "one unlink was dispatched"
      );
      assert!(
        !lock_ledger(&reg.ledger).obligations[&id].reap_requested,
        "the mark is cleared exactly as it is acted on"
      );

      // REMOVING + mark: a second request while that unlink is in flight COALESCES — no second
      // unlink is ever dispatched for one record — and the mark stays, so the failure path
      // still has a standing request to re-arm against.
      cleanup.request_remove(&path);
      reg.sweep_reap_marks::<TokioRuntime>(&op_tx);
      assert_eq!(
        phase_of(&reg, id),
        "removing(0)",
        "a marked Removing record dispatches nothing: no double unlink per record"
      );
      assert!(
        lock_ledger(&reg.ledger).obligations[&id].reap_requested,
        "…and the mark survives for the failure path to observe"
      );
      id
    };

    // REMOVE-FAILED, PARKED + mark: budget spent and no retry scheduled — the request RE-ARMS it
    // with a fresh budget. This is the demand edge that keeps a stalled backlog drainable.
    {
      lock_ledger(&reg.ledger).record_remove_failed(owned);
      assert_eq!(phase_of(&reg, owned), "failed(1,false)", "parked as failed");
      reg.sweep_reap_marks::<TokioRuntime>(&op_tx);
      assert_eq!(
        phase_of(&reg, owned),
        "removing(0)",
        "the standing mark re-armed the parked record with a fresh budget"
      );
    }

    // REMOVE-FAILED, SCHEDULED + mark: the retry deadline already owns it, so the request
    // coalesces onto that rather than racing a second unlink against it.
    {
      lock_ledger(&reg.ledger).record_remove_failed(owned);
      // Attempt 1, not 2: the re-arm above restarted the budget, which is what a fresh request
      // for a parked record is entitled to.
      reg.schedule_retry(
        &tuned_config(),
        owned,
        Instant::from_origin(Duration::ZERO),
        false,
      );
      assert_eq!(
        phase_of(&reg, owned),
        "failed(1,true)",
        "a retry is scheduled"
      );
      cleanup.request_remove(&PathBuf::from("/r/.tributaries-sync-phase-owned"));
      reg.sweep_reap_marks::<TokioRuntime>(&op_tx);
      assert_eq!(
        phase_of(&reg, owned),
        "failed(1,true)",
        "a scheduled record is left to its own retry"
      );
    }
    hold.release();

    // The in-pool write's refused claim still reaps the file it created: exactly one of the three
    // outcomes fired per record, and nothing leaked.
    let (guard, path) = in_pool;
    self_reap(&fs, &guard, fs.cookie_residue_at(&path), None);
    settle(|| fs.files_under("/r").len() <= 1).await;
  }

  // No request can be lost, INCLUDING the one whose wake finds the channel already full.
  // The ingress orders set-the-bit then `try_send`; the driver orders `recv` then lock-and-sweep.
  // So a `try_send` that finds a token pending has NOT lost its request: that pending token's
  // sweep has not taken the lock yet, and when it does it sees every bit set before it — which is
  // exactly why a capacity-1 wake can coalesce without dropping anything.
  //
  // Driven with no driver loop at all, so the ordering under test is the PROTOCOL's rather than a
  // scheduler's: the wake is consumed by hand, exactly once, and must serve BOTH requests.
  //
  // Fail-on-old (a wake that carried the request, as the lane's messages did): one token can only
  // name one target, so the second request would need its own queue slot — the whole reason the
  // lane could not be bounded.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_request_whose_wake_finds_the_channel_full_rides_the_pending_sweep() {
    let fs = FakeFs::new(1);
    let (mut reg, cleanup, wake) = registry_with_ingress(fs.clone());
    let mut core = fence_source();
    let scope = ScopeId::new(NonZeroU64::new(1).unwrap());
    let (op_tx, _op_rx) = async_channel::unbounded::<OpResult<<FakeFs as FsOps>::Handle>>();

    // Two owned cookies — two independent obligations, each addressable by its own path.
    let mut owned = |name: &str| {
      let guard = dispatched_guard(&mut reg, &mut core, scope, name);
      let path = PathBuf::from("/r").join(name);
      fs.put(&path, FileKind::File, 1);
      guard
        .claim(&fs.cookie_residue_at(&path))
        .expect("the claim lands");
      path
    };
    let first = owned(".tributaries-sync-wake-1");
    let second = owned(".tributaries-sync-wake-2");

    // The first request fills the capacity-1 wake.
    cleanup.request_remove(&first);
    assert_eq!(wake.wake.len(), 1, "the first request rang the wake");

    // The second finds the wake FULL. Its `try_send` therefore fails — and that is precisely the
    // case the protocol has to survive, because no second token can exist to carry it.
    cleanup.request_remove(&second);
    assert_eq!(
      wake.wake.len(),
      1,
      "a full wake coalesces: it never grows past its one token"
    );
    assert_eq!(
      lock_ledger(&reg.ledger)
        .obligations
        .values()
        .filter(|ob| ob.reap_requested)
        .count(),
      2,
      "both requests landed ON their records — the wake carries no request, so a full \
       channel cannot lose one"
    );

    // ONE recv, ONE sweep — everything a driver would do for the single pending token.
    assert!(
      wake.wake.try_recv().is_ok(),
      "the pending token is consumed"
    );
    assert!(
      wake.wake.try_recv().is_err(),
      "and it was the only one — no second wake exists to service the second request"
    );
    let hold = fs.hold_cookie_removes();
    reg.sweep_reap_marks::<TokioRuntime>(&op_tx);

    // That single sweep serviced BOTH: each record is Removing, and neither mark survives the
    // action it caused.
    for (path, id) in [(&first, 1u64), (&second, 2)] {
      let inner = lock_ledger(&reg.ledger);
      let ob = inner
        .obligations
        .get(&CookieId(id))
        .expect("the record stands until its unlink confirms");
      assert!(
        matches!(ob.phase, Phase::Removing { attempts: 0 }),
        "{path:?} was dispatched by the pending token's sweep"
      );
      assert!(
        !ob.reap_requested,
        "the mark is cleared exactly as the sweep acts on it"
      );
    }
    hold.release();
    settle(|| fs.cookie_removes().len() == 2).await;
    let mut reaped = fs.cookie_removes();
    reaped.sort();
    let mut expected = vec![first, second];
    expected.sort();
    assert_eq!(
      reaped, expected,
      "both cookies were unlinked by the one sweep"
    );
  }

  // Close stays bounded and HONEST while the public ingress hammers it. The flood cannot delay
  // the close (it enqueues nothing the drain must service), cannot wedge it (every request is a
  // lock-and-store the driver never has to answer), and cannot corrupt its count: the reply still
  // reports the one genuine obligation whose unlink is hung, because the count is the ledger
  // itself rather than a gauge the flood could skew.
  //
  // Fail-on-old: the flood's messages pile into the cleanup lane, which the close drain must then
  // service before it can quiesce.
  #[tokio::test(flavor = "multi_thread")]
  async fn close_is_bounded_and_honest_while_the_ingress_hammers() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    let path = sync_root(&rig, scope, "/r", ".tributaries-sync-close-flood")
      .await
      .expect("the write lands");
    // One genuine, GENUINELY stuck obligation: its unlink hangs past the grace, so close must
    // report exactly one non-quiesced cookie — the honest count the flood must not move.
    let hold = rig.fs.hold_cookie_removes();
    rig.fs.fail_next_cookie_removes(1_000_000);
    rig.cleanup.request_remove(&path);
    assert!(
      settle(|| rig.fs.cookie_remove_dispatches() == 1).await,
      "staging: the hung unlink must be dispatched, or close has no genuinely stuck obligation to count"
    );

    // Hammer the ingress throughout the close, from another task: unknown paths, unknown tickets,
    // and the live cookie's own path over and over.
    let flooder = {
      let cleanup = rig.cleanup.clone();
      let live = path.clone();
      tokio::spawn(async move {
        // Under miri the flood must shrink: miri never reuses an address, so a
        // 200k-iteration flood exhausts the 32-bit address space (i686), and its
        // sheer volume starves miri's cooperative scheduler into a blocking-pool
        // deadlock. A small flood exercises the same property — a hostile ingress
        // inflates nothing countable and wedges no close (the `outstanding == 1`
        // assertion is flood-count-independent).
        let flood: u64 = if cfg!(miri) { 64 } else { 200_000 };
        for i in 0..flood {
          cleanup.request_remove(&PathBuf::from(format!("/r/.tributaries-sync-x{i}")));
          cleanup.request_cancel(ticket());
          cleanup.request_remove(&live);
          if i % 4096 == 0 {
            tokio::task::yield_now().await;
          }
        }
      })
    };

    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply })
      .await
      .expect("the close command lands");
    let outstanding = tokio::time::timeout(interpreted_secs(10), on_reply)
      .await
      .expect("close returns within its grace despite the flood")
      .expect("the driver replies");
    assert_eq!(
      outstanding, 1,
      "close counts the ONE genuinely hung cookie — the flood addressed nothing countable, \
       so it cannot inflate the count, and the hung unlink cannot be hidden from it"
    );

    flooder.abort();
    hold.release();
  }

  // The ingress after an ABNORMAL driver death is inert, and leaks nothing. The handle keeps its
  // half of the ledger alive, so a late reap or cancel still runs — against an empty ledger, since
  // the `Drop` backstop already swept every record and typed it. The wake's `try_send` finds a
  // closed channel and is a no-op. Nothing is retained, nothing panics, and the files are gone.
  #[tokio::test(flavor = "multi_thread")]
  async fn the_ingress_after_a_driver_death_is_inert_and_leaks_nothing() {
    let fs = FakeFs::new(1);
    let (mut reg, cleanup, wake) = registry_with_ingress(fs.clone());
    let mut core = fence_source();
    let scope = ScopeId::new(NonZeroU64::new(1).unwrap());

    let t = ticket();
    let guard = dispatched_guard_keyed(
      &mut reg,
      &mut core,
      scope,
      ".tributaries-sync-dead-1",
      t.seq(),
    );
    let path = PathBuf::from("/r/.tributaries-sync-dead-1");
    fs.put(&path, FileKind::File, 1);
    guard
      .claim(&fs.cookie_residue_at(&path))
      .expect("the claim lands");
    assert_eq!(reg.unremoved(), 1, "the obligation is counted");

    // The driver dies abnormally: its registry and its half of the wake drop together, exactly as
    // a panicked or cancelled driver task's locals would.
    drop(reg);
    drop(wake);
    settle(|| fs.files_under("/r").is_empty()).await;
    assert!(
      fs.files_under("/r").is_empty(),
      "the Drop backstop swept the file"
    );

    // The public ingress still answers — it cannot fail, cannot block, and cannot panic — and it
    // finds nothing, because the backstop's typed terminal already removed every record.
    cleanup.request_remove(&path);
    cleanup.request_cancel(t);
    cleanup.request_remove(&PathBuf::from("/r/.tributaries-sync-never"));
    assert_eq!(
      cleanup.ledger_len(),
      0,
      "the ledger the handle still holds is empty, and the late requests added nothing to it"
    );
    assert_eq!(
      cleanup.wake_len(),
      0,
      "a closed wake swallows the token: the driver that would have read it is gone"
    );
  }

  /// A cookie removal destroys the OBJECT the write created, never merely the
  /// name it created it under — and it reaches that object through the directory
  /// descriptor the create used, never by resolving a path a second time.
  ///
  /// Real files, real inodes, the real `FsOps`: the defects are a `remove_file`
  /// addressed by pathname and a directory nobody owns, and no fake tree can
  /// witness what a kernel does with a name whose object was swapped underneath
  /// it — only the syscalls themselves can.
  #[cfg(all(unix, not(miri)))]
  mod identity {
    use super::*;

    /// A unique real directory for one cell, canonicalized so the production
    /// beneath-check compares two paths resolved by the same resolver (the
    /// system temp dir is itself a symlink on some hosts).
    fn scratch(tag: &str) -> PathBuf {
      use std::sync::atomic::{AtomicU32, Ordering};
      static COUNTER: AtomicU32 = AtomicU32::new(0);
      let dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir")
        .join(format!(
          "tributary-fs-cookie-{}-{}-{}",
          tag,
          std::process::id(),
          COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
      std::fs::create_dir_all(&dir).expect("create scratch dir");
      dir
    }

    /// The replacement's contents, so the survivor is proven by what it HOLDS and
    /// not merely by something existing at the name.
    const STRANGER: &[u8] = b"a file the watcher never created";

    /// The destructive case, as a peer running under the SAME user — the one
    /// actor the directory's mode cannot exclude, and therefore the only one the
    /// identity comparison still has to answer. It takes the cookie's name and
    /// leaves its own file there; the removal must destroy nothing.
    ///
    /// Fail-on-old (an unlink addressed by name alone): the stranger's file is
    /// deleted, and no error is reported anywhere, because from the caller's side
    /// the removal succeeded exactly as it was asked to.
    #[test]
    fn a_reclaimed_cookie_name_is_never_unlinked() {
      let root = scratch("displaced");
      let fs = RealFs::new();
      let cookie = fs
        .write_cookie(&root, &root, ".tributaries-sync-displaced")
        .expect("a cookie is created in a writable scratch root");

      // Delete and recreate rather than truncate-and-rewrite: a fresh create is
      // what mints a fresh inode, and a distinct inode under an identical
      // pathname is precisely the difference the removal has to notice.
      std::fs::remove_file(cookie.path()).expect("the cookie is removed by the stranger");
      std::fs::write(cookie.path(), STRANGER).expect("the stranger takes the freed name");

      let verdict = fs
        .remove_cookie(&cookie)
        .expect("a displaced name is a settled verdict, not a failure to retry");
      let survivor = std::fs::read(cookie.path());
      std::fs::remove_dir_all(&root).expect("drop the scratch tree");

      assert_eq!(
        survivor.as_deref().ok(),
        Some(STRANGER),
        "the stranger's file must still be on disk: this removal had no proof it was the cookie"
      );
      assert_eq!(
        verdict,
        CookieRemoval::Displaced,
        "the name is settled as displaced, so the obligation retires instead of retrying forever"
      );
    }

    /// The ordinary path, which the refusal above must not have cost: an
    /// untouched cookie is still unlinked, and reported as such. It also states
    /// WHERE the cookie went — inside the private directory, inside the caller's
    /// directory, inside the root — because the barrier only works while the
    /// cookie's event rides the watched root's queue.
    #[test]
    fn an_untouched_cookie_is_unlinked() {
      let root = scratch("unlinked");
      let fs = RealFs::new();
      let cookie = fs
        .write_cookie(&root, &root, ".tributaries-sync-plain")
        .expect("a cookie is created in a writable scratch root");
      assert_eq!(
        identity_of_handle(&std::fs::File::open(cookie.path()).expect("the cookie is readable"))
          .expect("an identity reads off the open cookie"),
        cookie.identity(),
        "staging: the name denotes the created object, so the removal below proves something"
      );
      let holder = cookie
        .path()
        .parent()
        .expect("the cookie has a containing directory");
      assert!(
        holder.starts_with(&root)
          && holder
            .file_name()
            .and_then(|leaf| leaf.to_str())
            .is_some_and(crate::is_sync_cookie_dir_name),
        "the cookie lands in the driver's own directory, and that directory is inside \
         the watched root — outside it, no event of the cookie could ever reach the stream. \
         The exported classifier must recognize the name this driver actually created: it is \
         what keeps the directory's own create off a consumer's stream"
      );

      let verdict = fs
        .remove_cookie(&cookie)
        .expect("an untouched cookie unlinks");
      let present = cookie.path().exists();
      std::fs::remove_dir_all(&root).expect("drop the scratch tree");

      assert!(!present, "the cookie this write created is gone from disk");
      assert_eq!(
        verdict,
        CookieRemoval::Unlinked,
        "the name still denoted the created object, so the unlink is the reported verdict"
      );
    }

    /// Idempotence, unchanged by the proof: a cookie already reaped by someone
    /// else is success, and the removal does not even reach the identity
    /// comparison it has nothing to compare against.
    #[test]
    fn an_already_gone_cookie_is_success() {
      let root = scratch("gone");
      let fs = RealFs::new();
      let cookie = fs
        .write_cookie(&root, &root, ".tributaries-sync-gone")
        .expect("a cookie is created in a writable scratch root");
      std::fs::remove_file(cookie.path()).expect("someone else reaps it first");

      let verdict = fs.remove_cookie(&cookie);
      std::fs::remove_dir_all(&root).expect("drop the scratch tree");

      assert_eq!(
        verdict.expect("an already-gone cookie is not a failure"),
        CookieRemoval::AlreadyGone,
        "the ledger record retires: nothing a later sweep could do would find this file"
      );
    }

    /// The identity a create captures is an ALLOCATOR SLOT, not a name: once the
    /// object holding it is freed the filesystem may hand the very same number to
    /// an unrelated successor, and a removal comparing numbers alone would then
    /// find its own identity standing on a stranger's file and delete it.
    ///
    /// What forecloses that is the descriptor the create keeps open for the life
    /// of the obligation: an object with a live reference cannot have its slot
    /// reissued, so every successor at the name necessarily reads back something
    /// different and the comparison refuses.
    ///
    /// Fail-on-old (identity captured, descriptor dropped): after enough churn a
    /// successor is handed the retired number, compares EQUAL, and is unlinked.
    #[test]
    fn a_recycled_identifier_never_authorizes_an_unlink() {
      /// Create/delete cycles each half of the cell is allowed. Generous enough
      /// that an allocator which reissues its most recently freed slot — the
      /// common case — does so well inside it, small enough to stay instant.
      const CHURN: usize = 256;

      /// One create-then-read of `path`, leaving the file in place.
      fn mint(path: &Path) -> RootIdentity {
        let file = std::fs::OpenOptions::new()
          .write(true)
          .create_new(true)
          .open(path)
          .expect("the scratch name is free");
        identity_of_handle(&file)
          .expect("an identity reads off a freshly created file")
          .expect("this filesystem answers identities")
      }

      let root = scratch("reuse");
      let fs = RealFs::new();

      // The CONTROL, run first and with nothing held open: the same delete-then-
      // recreate cycle the cookie faces, but free to reuse. Its answer is what
      // says how much the pinned half below proves on THIS filesystem — an
      // allocator that mints monotonically (APFS) never reissues and would make
      // the cookie safe by accident, while one that reuses the freed slot at once
      // (ext4) leaves the held descriptor as the only thing standing between the
      // removal and a stranger's file.
      let control = root.join("control");
      let freed = mint(&control);
      std::fs::remove_file(&control).expect("the control's object is freed");
      let mut reissues = false;
      for _ in 0..CHURN {
        let seen = mint(&control);
        std::fs::remove_file(&control).expect("the control cycles");
        if seen == freed {
          reissues = true;
          break;
        }
      }

      // The cookie: created through the production write, so its descriptor is
      // pinned by the `CookieFile` this cell holds for the whole cycle below.
      let cookie = fs
        .write_cookie(&root, &root, ".tributaries-sync-reuse")
        .expect("a cookie is created in a writable scratch root");
      std::fs::remove_file(cookie.path()).expect("the stranger deletes the cookie");

      // The property everything else rests on, and the only one observable on an
      // allocator that never reissues: the object OUTLIVES the loss of its name,
      // because this descriptor still references it. An allocator cannot hand a
      // referenced object's slot to anyone, so the churn below is guaranteed to
      // miss — the assertion after it states a consequence, this states the cause.
      let held = cookie
        .pinned_handle()
        .expect("the create's descriptor is retained for the life of the cookie");
      assert_eq!(
        identity_of_handle(held).expect("the retained descriptor still answers"),
        cookie.identity(),
        "the created object is still alive and still itself after its name was destroyed"
      );

      // Churn the cookie's OWN name, which is where a reissued slot would do its
      // damage: every occupant must read back as something other than the cookie.
      let mut collided = false;
      for _ in 0..CHURN {
        let seen = mint(cookie.path());
        std::fs::remove_file(cookie.path()).expect("the churn cycles");
        if Some(seen) == cookie.identity() {
          collided = true;
          break;
        }
      }

      // Leave a stranger standing at the name and ask for the removal, so the
      // refusal is proven on the file that survives rather than on numbers alone.
      std::fs::write(cookie.path(), STRANGER).expect("the stranger takes the name");
      let verdict = fs
        .remove_cookie(&cookie)
        .expect("a displaced name is a settled verdict, not a failure to retry");
      let survivor = std::fs::read(cookie.path());
      std::fs::remove_dir_all(&root).expect("drop the scratch tree");

      assert!(
        !collided,
        "a successor was handed the pinned cookie's identity: the create's \
         descriptor is not being held, so the removal's proof compares numbers \
         a stranger can wear (this filesystem reissues freed identifiers: \
         {reissues})"
      );
      assert_eq!(
        survivor.as_deref().ok(),
        Some(STRANGER),
        "the stranger's file must still be on disk"
      );
      assert_eq!(
        verdict,
        CookieRemoval::Displaced,
        "the name is settled as displaced, so the obligation retires instead of retrying forever"
      );
    }

    /// A cookie that was CREATED but whose object could not be identified is
    /// DESTROYED, not tracked. Nothing else is fail-closed: a tracked cookie with
    /// no identity is a cookie no comparison can ever tell apart from a successor
    /// at its name. The write reports the failure instead, which the sync already
    /// models as a typed, retryable outcome.
    ///
    /// Fail-on-old (an identity read whose error was erased to "no identity"):
    /// the write returns a cookie the ledger accepts, and its removal has nothing
    /// to prove.
    #[test]
    fn an_unidentifiable_cookie_is_destroyed_rather_than_tracked() {
      let root = scratch("unidentified");
      let dir = Arc::new(CookieDir::open_or_create(&root).expect("the cookie directory opens"));
      let name = ".tributaries-sync-unidentified";
      let created = dir.create(name).expect("a cookie is created in it");
      let path = dir.path().join(name);

      let failure = destroy_unidentified(
        Arc::clone(&dir),
        name,
        created,
        std::io::Error::new(std::io::ErrorKind::Unsupported, "no identity"),
      );
      let residue = path.exists();
      std::fs::remove_dir_all(&root).expect("drop the scratch tree");

      assert!(
        !residue,
        "the unidentifiable cookie is gone: nothing is left for a later sweep to own"
      );
      assert!(
        failure.residue.is_none(),
        "and the write hands back no residue, because there is no file to account for"
      );
      assert_eq!(
        failure.source.kind(),
        std::io::ErrorKind::Unsupported,
        "the write reports the identity failure verbatim, so the sync fails rather than degrading"
      );
    }

    /// A removal that cannot reach the object it must prove returns the failure,
    /// so its ledger record survives for a later sweep — and unlinks nothing in
    /// the meantime. Only two open failures are settled verdicts: the name being
    /// empty (idempotent success) and a symlink standing at it (displaced, and no
    /// retry could ever converge). Everything else is unknown, and answering a
    /// verdict on an unknown retires a record whose file is still on disk.
    ///
    /// The obstruction is a UNIX SOCKET at the cookie's name: `open` refuses one
    /// on every Unix, and refuses it for EVERY caller — a permission-based
    /// obstruction would be bypassed by the root the container suite runs as, and
    /// would silently stop testing anything there.
    ///
    /// Fail-on-old (an unprovable open folded into `Displaced`): the record
    /// retires as settled while a foreign object is still standing at its name —
    /// the leak half of erasing the distinction between "not this object" and
    /// "cannot tell".
    #[test]
    fn an_unprovable_name_is_returned_not_settled() {
      let root = scratch("unprovable");
      let dir = root.join("d");
      std::fs::create_dir(&dir).expect("the cookie's own directory");
      let fs = RealFs::new();
      let cookie = fs
        .write_cookie(&root, &dir, ".tributaries-sync-unprovable")
        .expect("a cookie is created in a writable scratch root");

      // Free the name, then move a socket onto it: nothing about the cookie's
      // anchor changes, but what stands at the name can no longer be opened. The
      // socket is bound SHORT and renamed in, because a bind address is capped
      // near a hundred bytes and the cookie's own path is longer than that.
      std::fs::remove_file(cookie.path()).expect("the cookie's name is freed");
      let bound = std::env::temp_dir().join(format!("ts{}.s", std::process::id()));
      let _ = std::fs::remove_file(&bound);
      let socket = std::os::unix::net::UnixListener::bind(&bound).expect("a socket binds");
      std::fs::rename(&bound, cookie.path()).expect("the socket takes the cookie's name");

      let verdict = fs.remove_cookie(&cookie);
      let survivor = cookie.path().exists();
      drop(socket);
      std::fs::remove_dir_all(&root).expect("drop the scratch tree");

      assert!(
        verdict.is_err(),
        "an unprovable removal is a failure to retry, never a settled verdict"
      );
      assert!(
        survivor,
        "nothing was unlinked: an object nothing could classify is still standing"
      );
    }

    /// A FIFO at the cookie's name must not park the removal FOREVER. A blocking
    /// `O_RDONLY` of a FIFO waits for a writer that never comes, and the thread it
    /// waits on is one of the driver's blocking-pool threads — so the whole sync
    /// machinery, not just this removal, stops. `O_NONBLOCK` is what bounds it,
    /// and once the open returns the FIFO is simply not the cookie.
    ///
    /// Bounded by construction: the removal runs on its own thread and this cell
    /// waits with a deadline, because the failure being tested IS a hang and an
    /// unbounded cell would report it as a hung suite instead of a failed test.
    ///
    /// Fail-on-old (a blocking classification open): the join times out.
    #[test]
    fn a_fifo_at_a_cookie_name_never_parks_the_removal() {
      /// Long enough that a loaded machine never trips it, short enough that a
      /// genuine indefinite wait is reported rather than endured.
      const DEADLINE: Duration = Duration::from_secs(20);

      let root = scratch("fifo");
      let fs = RealFs::new();
      let cookie = fs
        .write_cookie(&root, &root, ".tributaries-sync-fifo")
        .expect("a cookie is created in a writable scratch root");
      std::fs::remove_file(cookie.path()).expect("the cookie's name is freed");
      let fifo = std::ffi::CString::new(cookie.path().as_os_str().as_encoded_bytes())
        .expect("the scratch path holds no NUL");
      // SAFETY: `fifo` is a live NUL-terminated C string for the call, and `0o600`
      // is a valid mode word.
      let made = unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) };
      assert_eq!(made, 0, "the scratch tree accepts a FIFO");

      // No writer is ever opened for this FIFO: a blocking open would therefore
      // never return, which is exactly the state this cell must not enter.
      let (tx, rx) = std::sync::mpsc::channel();
      let worker = std::thread::spawn(move || {
        let verdict = fs.remove_cookie(&cookie);
        let _ = tx.send(verdict.map(|removal| (removal, cookie.path().exists())));
      });
      let answered = rx.recv_timeout(DEADLINE);
      let outcome = answered.inspect(|_| {
        worker.join().expect("the removal thread does not panic");
      });
      let cleaned = std::fs::remove_dir_all(&root);

      let verdict = outcome.expect(
        "the removal never answered: a FIFO standing at a cookie's name parked the \
         classification open, and with it the blocking-pool thread it ran on",
      );
      assert_eq!(
        verdict.expect("a FIFO is a classifiable object, not a transient failure"),
        (CookieRemoval::Displaced, true),
        "the FIFO is not the cookie, so it is settled as displaced and left on disk"
      );
      cleaned.expect("drop the scratch tree");
    }

    /// The unwind is anchored too. A path-based destroy re-resolves the cookie's
    /// spelling, so a directory moved aside and rebuilt underneath it makes the
    /// unwind delete whatever now stands at that spelling — a file it never
    /// created. Anchored to the create's own directory descriptor, the unwind
    /// destroys the object it made no matter what the name resolves to now.
    ///
    /// Fail-on-old (`remove_file(path)` after dropping the handle): the decoy is
    /// destroyed and the cookie the write actually created survives — both halves
    /// of the assertion invert.
    #[test]
    fn the_unwind_destroys_what_it_created_not_what_the_name_now_holds() {
      let root = scratch("unwind-anchor");
      let holder = root.join("d");
      std::fs::create_dir(&holder).expect("the cookie's own directory");
      let dir = Arc::new(CookieDir::open_or_create(&holder).expect("the cookie directory opens"));
      let name = ".tributaries-sync-unwind-anchor";
      let created = dir.create(name).expect("a cookie is created in it");
      let created_at = dir.path().join(name);

      // Move the whole directory aside and rebuild the ORIGINAL spelling around a
      // decoy. Every path component the create used now resolves to something
      // else; only the descriptor still refers to the directory the cookie is in.
      let moved = root.join("moved");
      std::fs::rename(&holder, &moved).expect("the cookie's directory moves aside");
      let decoy_dir = created_at
        .parent()
        .expect("the cookie has a containing directory")
        .to_path_buf();
      std::fs::create_dir_all(&decoy_dir).expect("the original spelling is rebuilt");
      let decoy = decoy_dir.join(name);
      std::fs::write(&decoy, STRANGER).expect("a decoy takes the original spelling");

      let failure = destroy_unidentified(
        Arc::clone(&dir),
        name,
        created,
        std::io::Error::new(std::io::ErrorKind::Unsupported, "no identity"),
      );
      let real_survived = moved
        .join(dir.path().file_name().expect("named"))
        .join(name)
        .exists();
      let decoy_contents = std::fs::read(&decoy);
      std::fs::remove_dir_all(&root).expect("drop the scratch tree");

      assert_eq!(
        decoy_contents.as_deref().ok(),
        Some(STRANGER),
        "the decoy standing at the cookie's old spelling must be untouched: the unwind \
         resolved a path instead of using the descriptor it created through"
      );
      assert!(
        !real_survived,
        "the file the create actually made is destroyed, wherever its name now leads"
      );
      assert!(
        failure.residue.is_none(),
        "the destroy succeeded, so there is no file left to account for"
      );
    }

    /// The unwind reports what it could not destroy. A name it cannot unlink —
    /// here a DIRECTORY, which `unlinkat` refuses without the removal flag — leaves
    /// a file on disk, and a write that answered "nothing was created" would strand
    /// it: uncounted, unreapable, and free to repeat.
    ///
    /// Fail-on-old (a discarded unlink result): the residue is `None` and the
    /// created file is invisible to every later sweep.
    #[test]
    fn an_undestroyable_cookie_comes_back_as_a_residue() {
      let root = scratch("unwind-residue");
      let dir = Arc::new(CookieDir::open_or_create(&root).expect("the cookie directory opens"));
      let name = ".tributaries-sync-unwind-residue";
      let created = dir.create(name).expect("a cookie is created in it");
      // Free the name and put a DIRECTORY there: `unlinkat` without
      // `AT_REMOVEDIR` refuses one on every Unix, so the destroy below fails for a
      // reason no privilege bypasses.
      std::fs::remove_file(dir.path().join(name)).expect("the cookie's name is freed");
      std::fs::create_dir(dir.path().join(name)).expect("a directory takes the name");

      let failure = destroy_unidentified(
        Arc::clone(&dir),
        name,
        created,
        std::io::Error::new(std::io::ErrorKind::Unsupported, "no identity"),
      );
      let residue = failure.residue;
      std::fs::remove_dir_all(&root).expect("drop the scratch tree");

      assert!(
        residue.is_some(),
        "a destroy that failed must hand the file back: an unreported one is a file \
         nothing counts and nothing ever reaps"
      );
      assert_eq!(
        residue
          .as_deref()
          .and_then(CookieResidue::file)
          .and_then(CookieFile::identity),
        None,
        "and it is handed back proven by its anchor alone — there is no identity to compare"
      );
      assert!(
        residue.as_deref().and_then(CookieResidue::file).is_some(),
        "the FILE is what survived, so the residue is the file half — the directory \
         rides inside it and is disposed of when this record's removal settles"
      );
    }

    /// The counted reap SPENDS the create's retained handle, and it has to: the
    /// directory disposal that follows it cannot run while that handle is open.
    ///
    /// This is the ordering the whole two-step retirement rests on. Windows mints a
    /// directory PER OBLIGATION and destroys it at the end of `reap_residue`, and a
    /// disposal attempted over a live pin meets a NON-EMPTY directory under EITHER
    /// disposition class: the cookie is deleted THROUGH the pin, so POSIX semantics
    /// take its name away only once the pin closes, and the classic
    /// `FILE_DISPOSITION_INFO` fallback keeps the entry until the object's LAST
    /// handle closes — which the pin also is. A rare residue turned into a
    /// guaranteed one, on every volume rather than only the ones that fall back. No
    /// kernel here does any of that, so what this cell witnesses is the
    /// PRECONDITION, in the platform-neutral code that establishes it: by the time
    /// `reap_residue` reaches the disposal, the pin is gone.
    ///
    /// The same line is why releasing it is sound. The pin holds the cookie's
    /// identity slot out of the allocator's reach so a removal can tell the cookie
    /// apart from a successor at its name, and it is reached only once the removal
    /// has SETTLED that question.
    ///
    /// FAIL-ON-REVERT (dispose before clearing the pin, or never clear it): the
    /// last assertion fails here, and every Windows sync on a fallback volume
    /// leaves a directory whose removal retries forever.
    #[test]
    fn a_confirmed_reap_spends_the_creates_retained_handle() {
      let root = scratch("reap-pin");
      let fs = RealFs::new();
      let cookie = fs
        .write_cookie(&root, &root, ".tributaries-sync-reap-pin")
        .expect("a cookie is created in a writable scratch root");
      assert!(
        cookie.pinned_handle().is_some(),
        "staging: the create's descriptor is retained while the cookie stands"
      );

      let mut residue = CookieResidue::File(cookie);
      let verdict = reap_residue(&fs, &mut residue);
      let held = residue.file().and_then(CookieFile::pinned_handle).is_some();
      let present = residue.path().exists();
      std::fs::remove_dir_all(&root).expect("drop the scratch tree");

      verdict.expect("a cookie standing at its own name reaps");
      assert!(!present, "the cookie left the tree");
      assert!(
        !held,
        "the reap would reach its directory disposal still holding the cookie's own \
         handle: on a volume that falls back to the classic disposition that \
         directory is not empty, and its removal fails every time"
      );
    }

    /// And a reap that FAILED keeps that handle, because the retry still needs it.
    ///
    /// Release it on a removal that never settled and the object it was pinning can
    /// be freed, its identity handed to a successor at the same name, and the
    /// retry's comparison then reads that successor back as a MATCH. So the release
    /// is conditioned on the removal having settled, never on it having been
    /// attempted — and the record takes the pin back from the failing job for
    /// exactly this reason (`spawn_unlink`).
    ///
    /// The obstruction is the same unopenable socket the cell above it uses: it
    /// leaves the removal unable to say what stands at the name, which is a
    /// returned failure rather than a verdict.
    ///
    /// FAIL-ON-REVERT (clear the pin unconditionally, or before the verdict): the
    /// assertion below fails, and a retry against a reissued identity unlinks a
    /// stranger's file.
    #[test]
    fn a_failed_reap_keeps_the_creates_retained_handle() {
      let root = scratch("reap-pin-kept");
      let dir = root.join("d");
      std::fs::create_dir(&dir).expect("the cookie's own directory");
      let fs = RealFs::new();
      let cookie = fs
        .write_cookie(&root, &dir, ".tributaries-sync-reap-pin-kept")
        .expect("a cookie is created in a writable scratch root");

      std::fs::remove_file(cookie.path()).expect("the cookie's name is freed");
      let bound = std::env::temp_dir().join(format!("tp{}.s", std::process::id()));
      let _ = std::fs::remove_file(&bound);
      let socket = std::os::unix::net::UnixListener::bind(&bound).expect("a socket binds");
      std::fs::rename(&bound, cookie.path()).expect("the socket takes the cookie's name");

      let mut residue = CookieResidue::File(cookie);
      let verdict = reap_residue(&fs, &mut residue);
      let held = residue.file().and_then(CookieFile::pinned_handle).is_some();
      drop(socket);
      std::fs::remove_dir_all(&root).expect("drop the scratch tree");

      assert!(
        verdict.is_err(),
        "staging: an unprovable removal is a failure to retry, not a settled verdict"
      );
      assert!(
        held,
        "a reap that settled nothing released the cookie's identity slot: the retry \
         can no longer tell the cookie apart from a successor at its name"
      );
    }

    /// One `Anchor` residue: created through the private directory, marked as the
    /// write's failed destroy would mark it, and still holding the create's own
    /// descriptor.
    fn anchor_residue(dir: &Arc<CookieDir>, name: &str) -> CookieFile {
      let created = dir.create(name).expect("a cookie is created in it");
      CookieFile::anchored(Arc::clone(dir), name, CookieProof::Anchor, created)
    }

    /// An `Anchor` residue must never be retried BY NAME.
    ///
    /// The record exists because nothing could identify what the write created,
    /// so the retry used to go straight to the anchored unlink with no comparison
    /// at all — not even the displacement check an identified cookie gets. Being
    /// anchored bounds WHERE that lands (inside the private directory) and
    /// nothing else: the object at the name is whatever is at the name, and
    /// destroying it is `remove_file(path)` minus only the path resolution.
    ///
    /// What replaces it is a promotion, not a weaker check: the identity is read
    /// off the create's OWN retained descriptor, which is a lookup of nothing and
    /// therefore names this write's object and no other. The removal then runs
    /// the ordinary comparison and refuses.
    ///
    /// FAIL-ON-REVERT: send `CookieProof::Anchor` straight to `dir.unlink(name)`
    /// again and the stranger's file is DELETED, with a clean `Unlinked` verdict
    /// reported to a caller that asked only for its own cookie back.
    #[test]
    fn an_anchor_residue_is_never_retried_by_name() {
      let root = scratch("anchor-displaced");
      let dir = Arc::new(CookieDir::open_or_create(&root).expect("the cookie directory opens"));
      let name = ".tributaries-sync-anchor-displaced";
      let residue = anchor_residue(&dir, name);
      let path = dir.path().join(name);

      // A peer under the same user frees the name and leaves its own file there.
      std::fs::remove_file(&path).expect("the residue's name is freed");
      std::fs::write(&path, STRANGER).expect("the stranger takes the freed name");

      let verdict = RealFs::new().remove_cookie(&residue);
      let survivor = std::fs::read(&path);
      std::fs::remove_dir_all(&root).expect("drop the scratch tree");

      assert_eq!(
        survivor.as_deref().ok(),
        Some(STRANGER),
        "the stranger's file must still be on disk: this removal had no proof it was \
         the residue"
      );
      assert_eq!(
        verdict.expect("a promoted identity settles a verdict rather than failing"),
        CookieRemoval::Displaced,
        "the name is settled as displaced, so the obligation retires instead of \
         retrying forever"
      );
    }

    /// The refusal above must not cost convergence: an `Anchor` residue still
    /// standing at its own name is promoted and UNLINKED, so the obligation
    /// retires and the file leaves the tree.
    ///
    /// Not a fail-on-revert cell — the old by-name unlink removed this file too.
    /// It is here so that a fix which simply refuses every `Anchor` removal (and
    /// leaks the file forever, reporting it at every close) cannot pass.
    #[test]
    fn an_anchor_residue_at_its_own_name_still_unlinks() {
      let root = scratch("anchor-unlink");
      let dir = Arc::new(CookieDir::open_or_create(&root).expect("the cookie directory opens"));
      let name = ".tributaries-sync-anchor-unlink";
      let residue = anchor_residue(&dir, name);
      let path = dir.path().join(name);

      let verdict = RealFs::new().remove_cookie(&residue);
      let present = path.exists();
      std::fs::remove_dir_all(&root).expect("drop the scratch tree");

      assert!(!present, "the residue this write created is gone from disk");
      assert_eq!(
        verdict.expect("an untouched residue unlinks"),
        CookieRemoval::Unlinked,
        "the name still denoted the created object, so the unlink is the verdict"
      );
    }

    /// And where there is nothing to promote FROM, the removal fails closed.
    ///
    /// A record with no retained descriptor can say nothing whatever about the
    /// name it holds, so the only two answers are "unlink it anyway" and "report
    /// it". Reporting keeps the ledger record, which is what makes close count
    /// the residue honestly instead of claiming a file it never removed.
    ///
    /// FAIL-ON-REVERT: fall through to `dir.unlink(name)` and the file below is
    /// destroyed and the call reports success.
    #[test]
    fn an_anchor_removal_with_nothing_to_promote_fails_closed() {
      let root = scratch("anchor-closed");
      let dir = CookieDir::open_or_create(&root).expect("the cookie directory opens");
      let name = ".tributaries-sync-anchor-closed";
      let path = dir.path().join(name);
      std::fs::write(&path, STRANGER).expect("something stands at the name");

      let verdict = remove_anchored(&dir, name, CookieProof::Anchor, None);
      let survivor = std::fs::read(&path);
      std::fs::remove_dir_all(&root).expect("drop the scratch tree");

      assert!(
        verdict.is_err(),
        "a removal with no evidence about the name is a reported failure, never a \
         settled verdict"
      );
      assert_eq!(
        survivor.as_deref().ok(),
        Some(STRANGER),
        "and it unlinked nothing"
      );
    }

    /// The cookie directory is VERIFIED, never adopted. A directory already
    /// standing at the name with permissions beyond its owner is refused, because
    /// the whole race argument is that nobody else may bind a name inside it —
    /// which is false the moment its mode says otherwise. The ownership half is
    /// checked the same way, and exercised wherever this cell can actually make a
    /// directory it does not own.
    ///
    /// Fail-on-old (a directory adopted on faith): the write succeeds into a
    /// directory a stranger may write, and every removal through it is back to
    /// racing a name.
    #[test]
    fn a_permissive_cookie_directory_is_refused() {
      use std::os::unix::fs::PermissionsExt;

      let root = scratch("dir-mode");
      let fs = RealFs::new();
      // Create it through the production path first, so the name and location are
      // exactly the ones the next write will resolve.
      let cookie = fs
        .write_cookie(&root, &root, ".tributaries-sync-dir-mode")
        .expect("a cookie is created in a writable scratch root");
      let cookie_dir = cookie
        .path()
        .parent()
        .expect("the cookie has a containing directory")
        .to_path_buf();
      drop(cookie);

      std::fs::set_permissions(&cookie_dir, std::fs::Permissions::from_mode(0o777))
        .expect("the scratch tree accepts the widened mode");
      let widened = fs.write_cookie(&root, &root, ".tributaries-sync-dir-mode-2");

      // SAFETY: `geteuid` reads no memory, takes no arguments, and cannot fail.
      let root_user = unsafe { libc::geteuid() } == 0;
      // Ownership can only be witnessed where this process may give a directory
      // away; where it cannot, the mode half above is the whole cell.
      let foreign = root_user.then(|| {
        std::fs::set_permissions(&cookie_dir, std::fs::Permissions::from_mode(0o700))
          .expect("the mode is restored before the ownership half");
        let path = std::ffi::CString::new(cookie_dir.as_os_str().as_encoded_bytes())
          .expect("the scratch path holds no NUL");
        // SAFETY: `path` is a live NUL-terminated C string for the call; `uid 1`
        // is a uid this process (running as root) may assign.
        let given = unsafe { libc::chown(path.as_ptr(), 1, u32::MAX) };
        assert_eq!(given, 0, "root may give the cookie directory away");
        fs.write_cookie(&root, &root, ".tributaries-sync-dir-owner")
      });
      let _ = std::fs::set_permissions(&cookie_dir, std::fs::Permissions::from_mode(0o700));
      std::fs::remove_dir_all(&root).expect("drop the scratch tree");

      assert_eq!(
        widened.err().map(|failure| failure.source.kind()),
        Some(std::io::ErrorKind::PermissionDenied),
        "a cookie directory anyone may write is refused, not adopted"
      );
      if let Some(foreign) = foreign {
        assert_eq!(
          foreign.err().map(|failure| failure.source.kind()),
          Some(std::io::ErrorKind::PermissionDenied),
          "a cookie directory owned by somebody else is refused, not adopted"
        );
      }
    }
  }

  /// The Windows cookie directory is NEVER ADOPTED: it is minted, created, used
  /// and destroyed by one obligation, and nothing already standing on disk is
  /// ever entered or removed.
  ///
  /// Real directories, real handles, the real `FsOps`. The properties are about
  /// what a kernel does with a name it already holds and with a delete
  /// disposition on an open handle, and no fake tree can witness either.
  #[cfg(all(target_os = "windows", not(miri)))]
  mod windows_non_adoption {
    use super::*;

    /// A unique real directory for one cell.
    ///
    /// Deliberately NOT canonicalized, unlike the Unix `scratch`: production
    /// canonicalizes both sides of its own beneath-check, so nothing here needs
    /// the verbatim `\\?\` form — and the junction cell drives `mklink`, a `cmd`
    /// builtin under no obligation to understand one.
    fn scratch(tag: &str) -> PathBuf {
      use std::sync::atomic::{AtomicU32, Ordering};
      static COUNTER: AtomicU32 = AtomicU32::new(0);
      let dir = std::env::temp_dir().join(format!(
        "tributary-fs-cookie-{}-{}-{}",
        tag,
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
      ));
      std::fs::create_dir_all(&dir).expect("create scratch dir");
      dir
    }

    /// The directory a completed write put its cookie in.
    fn cookie_dir_of(cookie: &CookieFile) -> PathBuf {
      cookie
        .path()
        .parent()
        .expect("the cookie has a containing directory")
        .to_path_buf()
    }

    /// Every leaf under `root` the exported classifier claims — what a sync must
    /// leave none of once its obligation has retired.
    fn reserved_leaves(root: &Path) -> Vec<String> {
      std::fs::read_dir(root)
        .expect("the scratch root is readable")
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|leaf| crate::is_sync_cookie_dir_name(leaf))
        .collect()
    }

    /// A whole write/remove round trip leaves NOTHING behind — not the cookie,
    /// and not the directory that held it. The disposal proof.
    ///
    /// FAIL-ON-REVERT (drop `CookieDir`'s `Drop`, or open the directory without
    /// `DELETE`): every sync on this platform accumulates one permanent empty
    /// directory in the watched tree, forever, since nothing else ever removes
    /// one. That is also what makes the retry bound affordable — a name that is
    /// reclaimed cannot pile up.
    ///
    /// It equally pins the field order in `CookieFile`: put `dir` before `pin`
    /// and the directory's disposition is attempted while the cookie's own
    /// handle still holds its entry, which leaves the directory standing. That
    /// holds on EVERY volume rather than only the ones that fall back to the
    /// classic disposition — the removal now deletes through the pin itself, so
    /// under POSIX semantics too the cookie's name leaves this directory exactly
    /// when the pin closes.
    #[test]
    fn a_completed_write_leaves_no_cookie_directory_behind() {
      let root = scratch("dispose");
      let fs = RealFs::new();
      let cookie = fs
        .write_cookie(&root, &root, ".tributaries-sync-dispose")
        .expect("a cookie is created in a writable scratch root");
      let cookie_dir = cookie_dir_of(&cookie);
      assert!(
        cookie_dir.is_dir(),
        "staging: the write created a directory to put the cookie in"
      );
      assert_eq!(
        reserved_leaves(&root).len(),
        1,
        "staging: exactly one cookie directory stands while the obligation lives"
      );

      let removal = fs
        .remove_cookie(&cookie)
        .expect("the cookie's removal settles");
      // The obligation retires HERE — the record's last clone goes, the cookie's
      // own handle closes, and the directory's disposition follows it.
      drop(cookie);

      let leftovers = reserved_leaves(&root);
      let stood = cookie_dir.exists();
      std::fs::remove_dir_all(&root).expect("drop the scratch tree");

      assert_eq!(removal, CookieRemoval::Unlinked);
      assert!(
        !stood,
        "the directory the obligation created outlived the obligation"
      );
      assert!(
        leftovers.is_empty(),
        "a retired sync left cookie directories behind: {leftovers:?}"
      );
    }

    /// A cookie RENAMED inside its own directory is still destroyed, and the
    /// directory still goes with it.
    ///
    /// Rust opens the cookie granting `FILE_SHARE_DELETE`, so a peer under the same
    /// user can rename this obligation's cookie WITHIN the directory the obligation
    /// minted while the create's handle stays open. Nothing defends the NAME, and
    /// nothing needs to: the removal deletes through the handle, so the object it
    /// destroys is the object it created, wherever that object's name has gone.
    ///
    /// FAIL-ON-REVERT (resolve `dir.path().join(name)` again, as the `Object` arm
    /// did): the removal finds the original name absent, answers `AlreadyGone` — a
    /// SUCCESS — and `reap_residue` believes it, spends the pin and converts the
    /// record to directory-only debt on the strength of it. The renamed cookie is
    /// still on disk, so the disposal that follows meets a non-empty directory and
    /// fails; the reap below returns `Err`, and every retry can then only repeat
    /// that same failing disposal with no handle, name or proof left to reach the
    /// file with. The file and the directory persist and the record consumes
    /// backlog and global capacity forever.
    #[test]
    fn a_renamed_cookie_is_still_destroyed_through_the_creates_handle() {
      let root = scratch("renamed");
      let fs = RealFs::new();
      let cookie = fs
        .write_cookie(&root, &root, ".tributaries-sync-renamed")
        .expect("a cookie is created in a writable scratch root");
      let cookie_dir = cookie_dir_of(&cookie);
      // The peer's rename: a different name, the SAME directory this obligation
      // minted, and this process's own handle open across it.
      let moved = cookie_dir.join("renamed-by-a-peer");
      std::fs::rename(cookie.path(), &moved)
        .expect("a peer renames the cookie inside the directory the obligation minted");

      let mut residue = CookieResidue::File(cookie);
      let reaped = reap_residue(&fs, &mut residue);
      let settled_the_file_half = residue.file().is_none();
      // The directory's handle is released only here. A POSIX-semantics disposition
      // takes the name away at once, but the classic fallback keeps it until the
      // last handle closes, so reading the tree before this would be reading a
      // difference between volumes rather than the property.
      drop(residue);

      let survivor = moved.exists();
      let leftovers = reserved_leaves(&root);
      let stood = cookie_dir.exists();
      let _ = std::fs::remove_dir_all(&root);

      reaped.expect(
        "the reap must settle: the cookie is destroyed through the handle its own \
         create returned, which a rename cannot redirect",
      );
      assert!(
        !survivor,
        "the renamed cookie survived: the removal followed the NAME, so the object \
         this obligation created was never destroyed"
      );
      assert!(
        settled_the_file_half,
        "staging: a settled file half leaves the directory-only debt behind"
      );
      assert!(
        !stood,
        "the directory outlived the obligation that minted it"
      );
      assert!(
        leftovers.is_empty(),
        "a converged reap left cookie directories behind: {leftovers:?}"
      );
    }

    /// A residue whose PIN is gone deletes NOTHING by name, on either proof — this
    /// platform opens no name for deletion at all.
    ///
    /// Two rows of one contract. With a stranger standing at the cookie's name the
    /// removal REFUSES: an identity whose pin has been spent is not evidence — the
    /// pin is what held the object's file id out of the allocator's reach, so once
    /// it is gone that id may already name a successor — and deleting on it is the
    /// unlink this design forbids. With the name EMPTY it answers the idempotent
    /// success, which is the retry case this platform actually produces: a residue
    /// destroyed through its retained handle, the handle then spent so the
    /// directory can be disposed of, and a failed disposal coming back here with
    /// the cookie already gone.
    ///
    /// FAIL-ON-REVERT (open the name for DELETE once an identity matches, as the
    /// `Object` arm did): a record with no pin left reaches a name it can prove
    /// nothing about, and the first assertion finds the stranger's file destroyed.
    #[test]
    fn a_pinless_residue_deletes_nothing_by_name() {
      const STRANGER: &[u8] = b"a file the watcher never created";

      let root = scratch("pinless");
      let dir = CookieDir::open_or_create(&root).expect("a cookie directory is minted");
      let name = ".tributaries-sync-pinless";
      let created = dir.create(name).expect("a cookie is created in it");
      let identity = identity_of_handle(&created)
        .expect("staging: the create's own handle answers")
        .expect("staging: this filesystem reads an identity off a handle");
      // The pin is SPENT and the name reclaimed by a stranger — the state a failed
      // disposal used to be able to leave a record in.
      drop(created);
      std::fs::remove_file(dir.path().join(name)).expect("the cookie's name is freed");
      std::fs::write(dir.path().join(name), STRANGER).expect("a stranger takes the freed name");

      let refused = remove_anchored(&dir, name, CookieProof::Object(identity), None);
      let survivor = std::fs::read(dir.path().join(name)).ok();

      // And the row that must still make PROGRESS: nothing at the name at all.
      std::fs::remove_file(dir.path().join(name)).expect("the stranger's file goes away");
      let empty = remove_anchored(&dir, name, CookieProof::Object(identity), None);

      drop(dir);
      let _ = std::fs::remove_dir_all(&root);

      assert_eq!(
        survivor.as_deref(),
        Some(STRANGER),
        "the stranger's file was destroyed by a record whose only evidence is an \
         identity its spent pin had stopped vouching for"
      );
      assert!(
        refused.is_err(),
        "an occupied name is a REFUSAL, not a verdict: settling one would retire a \
         record whose own file may still be on disk"
      );
      assert!(
        matches!(empty, Ok(CookieRemoval::AlreadyGone)),
        "an empty name must be the idempotent success, or the directory this \
         obligation minted is never disposed of: {empty:?}"
      );
    }

    /// A directory disposition that FAILS keeps the whole reap failing, so the
    /// obligation stays counted — and a later retry converges once the obstruction
    /// clears.
    ///
    /// Mandatory `DELETE` on the create grants the RIGHT to request the deletion;
    /// it does not make the deletion infallible. A read-only volume, a filter
    /// driver, or — the sharp case staged here — a same-uid peer that plants a file
    /// inside this obligation's directory all leave a disposition that refuses.
    /// Because a directory is minted PER OBLIGATION, a failure that was discarded
    /// would leave one fresh permanent residue per sync, with no ledger record, no
    /// cap, no retry and no diagnostic against it.
    ///
    /// Returning the failure enrolls the directory in the accounting the cookie
    /// FILE already has: the caller keeps the record, parks it `RemoveFailed`,
    /// counts it against both backlog caps and re-arms it on the same attempt
    /// budget (`spawn_unlink`, `self_reap`). This cell proves the physical half of
    /// that contract — the failure is reported and the directory is still standing.
    ///
    /// The retry row is its own property, and against a real kernel it is the
    /// sharper one. By then the cookie file is already unlinked and the pin that
    /// held its file id out of the allocator's reach has been SPENT, so the
    /// identity the write captured names nothing this obligation still owns. The
    /// residue the failed reap hands back is therefore directory-only, and the
    /// retry disposes without ever consulting the cookie's name — there is no
    /// `CookieFile` left in it to consult one with.
    ///
    /// FAIL-ON-REVERT (discard the disposal's error, which is all `CookieDir`'s
    /// `Drop` can do): the first reap reports success, the obligation retires, and
    /// the directory below stands forever with nothing counting it. FAIL-ON-REVERT
    /// (keep the residue shaped as a file across the failed disposal): the middle
    /// assertion finds an identity the obligation has no right to act on any more.
    #[test]
    fn a_refused_directory_disposal_keeps_the_reap_failing_until_it_clears() {
      let root = scratch("dispose-refused");
      let fs = RealFs::new();
      let cookie = fs
        .write_cookie(&root, &root, ".tributaries-sync-dispose-refused")
        .expect("a cookie is created in a writable scratch root");
      let cookie_dir = cookie_dir_of(&cookie);
      // A peer under the same user plants a file inside the directory this
      // obligation minted. Nothing about the cookie changes — the directory simply
      // stops being empty, and an occupied directory is one the disposition
      // refuses.
      let planted = cookie_dir.join("planted-by-a-peer");
      std::fs::write(&planted, b"not this crate's").expect("the peer's file lands");

      let mut residue = CookieResidue::File(cookie);
      let refused = reap_residue(&fs, &mut residue);
      let stood = cookie_dir.is_dir();
      let owes_only_the_directory =
        residue.file().is_none() && residue.owed_dir() == Some(&*cookie_dir);

      // Clear the obstruction and retry, which is what the ledger's re-arm does to
      // a record parked `RemoveFailed`. The retry's own `Ok` is what proves the
      // disposal succeeded; the tree is read afterwards only to confirm the end
      // state.
      std::fs::remove_file(&planted).expect("the peer's file goes away");
      let cleared = reap_residue(&fs, &mut residue);
      // The directory handle is released only here. A POSIX-semantics disposition
      // takes the name away at once, but the classic fallback keeps it until the
      // last handle closes, so reading the tree before this would be reading a
      // difference between volumes rather than the property.
      drop(residue);
      let leftovers = reserved_leaves(&root);
      let still_stood = cookie_dir.exists();
      std::fs::remove_dir_all(&root).expect("drop the scratch tree");

      assert!(
        refused.is_err(),
        "a directory that could not be disposed of must be REPORTED: an unreported \
         one is a residue with no record, no cap and no retry"
      );
      assert!(
        stood,
        "staging: the refused disposal left the directory exactly where it was"
      );
      assert!(
        owes_only_the_directory,
        "the failed reap handed back an obligation that still claims a cookie: its \
         pin is spent, so the identity it carries can be reissued to a successor \
         at that very name"
      );
      cleared.expect("the retry settles once the obstruction is gone");
      assert!(
        !still_stood,
        "the directory outlived the obligation that minted it"
      );
      assert!(
        leftovers.is_empty(),
        "a converged reap left cookie directories behind: {leftovers:?}"
      );
    }

    /// A name that is already bound is never entered — the anti-adoption rule
    /// against a real kernel, including the case-variant occupant only a
    /// case-insensitive filesystem produces.
    ///
    /// The candidate sequence is injected so the collision is certain rather
    /// than waited for: production draws from 2^32 and would never collide on
    /// demand.
    ///
    /// FAIL-ON-REVERT (accept `ERROR_ALREADY_EXISTS` as success, which is
    /// exactly what the deleted `create_directory_with_sddl` did): the value
    /// returned names the STRANGER's directory, this crate writes its cookies
    /// into it, and the case-variant row shows the same defect reached through a
    /// name that does not even match byte for byte.
    #[test]
    fn an_occupied_candidate_name_is_never_entered() {
      let root = scratch("occupied");
      let occupied = root.join(cookie_dir_name_for(7));
      std::fs::create_dir(&occupied).expect("occupy the first candidate");
      std::fs::write(occupied.join("stranger"), b"not this crate's").expect("plant contents");
      // The SECOND candidate is occupied by a differently-cased spelling of its
      // name. Windows resolves names case-insensitively, so the create still
      // refuses it — and an implementation that compared names itself, byte for
      // byte, would call this candidate free and enter a directory it did not
      // make.
      let variant = root.join(cookie_dir_name_for(42).to_uppercase());
      std::fs::create_dir(&variant).expect("occupy the second candidate, cased differently");

      let mut sequence = [7_u32, 42, 99].into_iter();
      let dir = CookieDir::minted(&root, &mut || {
        sequence
          .next()
          .expect("the loop asks for no more than three")
      })
      .expect("the third candidate is free");
      let landed = dir.path().to_path_buf();
      // Retiring it here also exercises the disposal on a directory the mint
      // reached only after two refusals.
      drop(dir);

      let occupant = std::fs::read(occupied.join("stranger")).ok();
      let variant_stood = variant.is_dir();
      let landed_stood = landed.exists();
      std::fs::remove_dir_all(&root).expect("drop the scratch tree");

      assert_eq!(
        landed.file_name().and_then(|leaf| leaf.to_str()),
        Some(cookie_dir_name_for(99).as_str()),
        "the mint entered a name it did not create"
      );
      assert_eq!(
        occupant.as_deref(),
        Some(&b"not this crate's"[..]),
        "the occupied directory was entered, emptied or replaced"
      );
      assert!(
        variant_stood,
        "the case-variant occupant was removed — nothing this crate did not create may be"
      );
      assert!(
        !landed_stood,
        "and what the mint did create was disposed of"
      );
    }

    /// Junk wearing reserved names neither blocks a sync nor is destroyed by
    /// one, in both directions that matter.
    ///
    /// A junction planted at the very name the mint asks for next is REFUSED by
    /// the create — a junction is a bound name like any other — so the loop moves
    /// on, nothing is created through it, and it is still standing afterwards. A
    /// junction at the legacy bare stem and a squatter at a qualified reserved
    /// name likewise stand while a full write/remove round trip runs beside them.
    ///
    /// This is the availability half of the architecture, and a FAIL-ON-OLD cell
    /// in the strongest sense: on the stable-name arm a junction at the one
    /// well-known name was a PERMANENT unhealable sync failure, because nothing
    /// in this crate ever removed a cookie directory. It pins the other direction
    /// too — a mint that "cleaned up" a name it wanted would destroy a stranger's
    /// object, which is what this whole design forbids.
    #[test]
    fn reserved_name_junk_neither_blocks_a_sync_nor_is_deleted_by_it() {
      let root = scratch("junk");
      let elsewhere = scratch("junk-target");
      std::fs::write(elsewhere.join("outside"), b"beyond the watched root")
        .expect("the junction's target holds a file");

      /// Plants a junction at `at`, pointing at `target`. A junction needs no
      /// privilege, so a failure is this cell's own precondition and not a
      /// verdict.
      fn junction(at: &Path, target: &Path) {
        let linked = std::process::Command::new("cmd")
          .args(["/c", "mklink", "/J"])
          .arg(at)
          .arg(target)
          .output()
          .expect("cmd runs");
        assert!(
          linked.status.success(),
          "a junction needs no privilege, so a failure here is the cell's own precondition \
           and not a verdict: {}",
          String::from_utf8_lossy(&linked.stderr)
        );
      }

      // A junction standing at the FIRST candidate the mint will ask for, and a
      // second at the legacy bare stem nothing may ever enter again.
      let aimed_at = root.join(cookie_dir_name_for(7));
      junction(&aimed_at, &elsewhere);
      let legacy = root.join(COOKIE_DIR_PREFIX);
      junction(&legacy, &elsewhere);
      let squatter = root.join(cookie_dir_name_for(0));
      std::fs::create_dir(&squatter).expect("plant a squatter at a qualified reserved name");
      std::fs::write(squatter.join("stranger"), b"not this crate's").expect("with contents");

      // The mint is aimed straight at the junction, so the collision is certain
      // rather than waited for.
      let mut sequence = [7_u32, 51].into_iter();
      let aimed = CookieDir::minted(&root, &mut || {
        sequence.next().expect("the loop asks for no more than two")
      })
      .expect("a junction at a candidate name costs one retry, not a failed sync");
      let aimed_leaf = aimed
        .path()
        .file_name()
        .and_then(|leaf| leaf.to_str())
        .map(str::to_owned);
      drop(aimed);

      // And the production path, with the same junk standing.
      let fs = RealFs::new();
      let written = fs.write_cookie(&root, &root, ".tributaries-sync-junk");
      let landed = written.as_ref().ok().map(cookie_dir_of);
      let removal = written.as_ref().ok().map(|cookie| fs.remove_cookie(cookie));
      let refusal = written
        .as_ref()
        .err()
        .map(|failure| failure.source.to_string());
      drop(written);

      let escaped = std::fs::read_dir(&elsewhere)
        .expect("the junction's target is readable")
        .count();
      let squatted = std::fs::read(squatter.join("stranger")).ok();
      let junctions_stood =
        std::fs::symlink_metadata(&aimed_at).is_ok() && std::fs::symlink_metadata(&legacy).is_ok();
      let landed_stood = landed.as_ref().is_some_and(|dir| dir.exists());
      let landed_leaf = landed
        .as_ref()
        .and_then(|dir| dir.file_name())
        .and_then(|leaf| leaf.to_str())
        .map(str::to_owned);

      // The junctions are unlinked FIRST: removing one through a recursive walk
      // would be the one operation that must never descend it.
      let _ = std::fs::remove_dir(&aimed_at);
      let _ = std::fs::remove_dir(&legacy);
      let _ = std::fs::remove_dir_all(&root);
      let _ = std::fs::remove_dir_all(&elsewhere);

      assert_eq!(
        aimed_leaf.as_deref(),
        Some(cookie_dir_name_for(51).as_str()),
        "the mint entered the junction rather than minting past it"
      );
      assert_eq!(
        refusal, None,
        "junk at a reserved name blocked the sync: {refusal:?}"
      );
      assert!(
        matches!(removal, Some(Ok(CookieRemoval::Unlinked))),
        "and the cookie the sync wrote is removed normally: {removal:?}"
      );
      assert!(
        landed_leaf
          .as_deref()
          .is_some_and(|leaf| leaf != COOKIE_DIR_PREFIX && leaf != cookie_dir_name_for(0)),
        "the sync landed in junk somebody else planted: {landed_leaf:?}"
      );
      assert_eq!(
        escaped, 1,
        "something was created through a junction — a cookie beyond the watched root \
         mints an event no stream ever reports"
      );
      assert_eq!(
        squatted.as_deref(),
        Some(&b"not this crate's"[..]),
        "the squatter's directory was entered or emptied"
      );
      assert!(
        junctions_stood,
        "the sync deleted a junction it did not create"
      );
      assert!(
        !landed_stood,
        "and the directory it did create was disposed of"
      );
    }

    /// A crash leaves a cookie directory still holding its cookie. A later run
    /// neither enters it nor removes it, and syncs normally beside it.
    ///
    /// Both halves matter and pull opposite ways. Entering it is the adoption
    /// this architecture deletes — the residue is indistinguishable, from the
    /// outside, from a directory a stranger planted. Removing it is the
    /// destruction the design forbids, since a directory this process did not
    /// create is one it cannot prove anything about; the disposal is addressed
    /// to a RETAINED handle precisely so it can never reach one.
    #[test]
    fn a_crash_residue_is_left_untouched_while_a_new_sync_succeeds_beside_it() {
      let root = scratch("residue");
      let stale = root.join(cookie_dir_name_for(123_456));
      std::fs::create_dir(&stale).expect("plant a previous run's cookie directory");
      std::fs::write(
        stale.join(".tributaries-sync-crashed"),
        b"a cookie nobody removed",
      )
      .expect("with the cookie the crash stranded in it");

      let fs = RealFs::new();
      let cookie = fs
        .write_cookie(&root, &root, ".tributaries-sync-residue")
        .expect("a stale cookie directory beside it blocks nothing");
      let landed = cookie_dir_of(&cookie);
      let removal = fs.remove_cookie(&cookie);
      drop(cookie);

      let stranded = std::fs::read(stale.join(".tributaries-sync-crashed")).ok();
      let residue_stood = stale.is_dir();
      let landed_stood = landed.exists();
      // Compared by LEAF, not by path: the write canonicalizes its side, so two
      // spellings of the same directory would differ anyway.
      let landed_leaf = landed
        .file_name()
        .and_then(|leaf| leaf.to_str())
        .map(str::to_owned);
      let _ = std::fs::remove_dir_all(&root);

      assert!(
        matches!(removal, Ok(CookieRemoval::Unlinked)),
        "the new sync's own cookie is removed normally: {removal:?}"
      );
      assert_ne!(
        landed_leaf.as_deref(),
        Some(cookie_dir_name_for(123_456).as_str()),
        "the new sync entered the residue instead of minting its own directory"
      );
      assert!(
        residue_stood,
        "the residue directory was destroyed — a directory this run did not create is one \
         it can prove nothing about"
      );
      assert_eq!(
        stranded.as_deref(),
        Some(&b"a cookie nobody removed"[..]),
        "the residue was entered or emptied"
      );
      assert!(
        !landed_stood,
        "and the directory it did create was disposed of"
      );
    }
  }
}

/// The anchor map ends in the order the control batch itself carried: a `Disarm`
/// that follows its own `Arm` inside ONE batch leaves NO anchor behind, and
/// repeating that shape strands no `O_PATH` descriptor.
///
/// Real inotify, real anchors, real process descriptors — the defect IS a
/// descriptor the executor retains, so no fake can witness it. The cells live in
/// the lib suite (the container `unit` run) rather than `tests/linux_inotify.rs`
/// because the anchor map is `RealFs`-private state: the integration binary sees
/// only the public API, where the descriptor growth would eventually show but
/// WHICH watch retained an anchor never would.
#[cfg(all(target_os = "linux", not(miri)))]
mod control_batch_publication_order {
  use super::*;

  /// The transport generation these cells attach their one port under.
  const LANE: u64 = 0;

  /// A unique real directory tree for one cell.
  fn scratch(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir()
      .canonicalize()
      .expect("canonicalize temp dir")
      .join(format!(
        "tributary-fs-anchor-{}-{}-{}",
        tag,
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
      ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
  }

  fn watch_id(n: u64) -> WatchId {
    WatchId::new(NonZeroU64::new(n).expect("watch ids start at one"))
  }

  /// An arm of `path` as its OWN parent — the root form, so the request resolves
  /// by absolute path and no parent anchor participates.
  fn arm(watch: WatchId, path: &Path) -> ControlRequest {
    ControlRequest::Arm {
      watch,
      // A synthetic batch this test answers itself: nothing echoes the outcome
      // back through the core's attempt fence.
      attempt: None,
      parent: watch,
      name: Segment::new("churn"),
      path: Arc::new(path.to_path_buf()),
      expected: None,
      frame: crate::os::ScopeFrame::default(),
    }
  }

  /// The descriptors this process holds that resolve INTO `root` (an anchor on a
  /// since-unlinked directory still reads back as its path, marked deleted).
  ///
  /// Scoped to the cell's own tree deliberately: the lib binary runs its cells in
  /// PARALLEL, so the process-wide descriptor total drifts under sibling tests
  /// (every tokio runtime opens its own epoll and eventfd). No sibling opens
  /// anything beneath this cell's unique scratch root, so the scoped count is the
  /// leak's exact signature — a strictly sharper assertion than a slack-bounded
  /// global count, and a deterministic one.
  fn fds_into(root: &Path) -> usize {
    let root = root.to_string_lossy().into_owned();
    std::fs::read_dir("/proc/self/fd")
      .expect("read /proc/self/fd")
      .filter_map(Result::ok)
      .filter(|entry| {
        std::fs::read_link(entry.path())
          .is_ok_and(|target| target.to_string_lossy().contains(&root))
      })
      .count()
  }

  /// A live inotify source on `root` with its control port attached under
  /// [`LANE`], so `batch_control` passes the generation front-check.
  fn attach(fs: &RealFs, scope: ScopeId, root: &Path) -> SpawnedSource<SourceHandle> {
    let mut config = SourceConfig::new(vec![root.to_path_buf()]);
    // Pinned, never `Auto`: under a privileged suite `Auto` resolves fanotify,
    // whose port is `Inert` and carries no arm traffic at all.
    config.backend = Backend::Inotify;
    let spawned = fs
      .spawn_source(config)
      .expect("a real inotify source spawns on the scratch root");
    fs.attach_scope(scope, spawned.handle.scope_port(), LANE);
    spawned
  }

  /// Detach, stop the reader, drop the tree — the detach first, so the anchors
  /// purge runs while the port is still the one the cell attached.
  fn teardown(fs: &RealFs, scope: ScopeId, spawned: SpawnedSource<SourceHandle>, root: &Path) {
    fs.detach_scope(scope);
    let _ = spawned.handle.shutdown();
    let _ = std::fs::remove_dir_all(root);
  }

  /// `Arm(a), Disarm(a), Arm(b)` in ONE batch — the shape rapid
  /// create/delete/create churn on a single slot mints. Only `b`, the batch's
  /// final live watch, may retain an anchor.
  ///
  /// Fail-on-old: with publication deferred wholesale to after the batch, `a`'s
  /// disarm removes an anchor that does not exist yet and the post-batch pass
  /// then inserts it — the map ends holding a RETIRED watch's `O_PATH` fd, which
  /// no cold enumerate will ever consume.
  #[test]
  fn a_disarm_retires_the_anchor_of_its_own_arm() {
    let root = scratch("order");
    let dir = root.join("churn");
    std::fs::create_dir(&dir).expect("create the churned directory");
    let fs = RealFs::new();
    let scope = ScopeId::new(NonZeroU64::new(1).expect("scope ids start at one"));
    let spawned = attach(&fs, scope, &root);

    let (a, b) = (watch_id(1), watch_id(2));
    let outcomes = fs.batch_control(
      scope,
      LANE,
      vec![
        arm(a, &dir),
        ControlRequest::Disarm { watch: a },
        arm(b, &dir),
      ],
    );

    // Reply alignment, end to end: one resolution per ARM in arm order — the
    // disarm sitting between them consumed no reply slot.
    assert!(
      outcomes.answered,
      "a live reader ANSWERS: this is the positive control for the report a dead one gives"
    );
    let outcomes = outcomes.resolutions;
    let resolved: Vec<WatchId> = outcomes.iter().map(|r| r.watch).collect();
    assert_eq!(
      resolved,
      vec![a, b],
      "the batch's two arms resolve in arm order; the interleaved disarm takes no reply"
    );
    for resolution in &outcomes {
      assert!(
        matches!(
          resolution.outcome,
          WatchOutcome::Installed(_) | WatchOutcome::Aliased(_)
        ),
        "staging: {:?} must install for an anchor to exist at all: {:?}",
        resolution.watch,
        resolution.outcome
      );
    }

    let anchored: Vec<WatchId> = fs.anchors.lock().unwrap().keys().copied().collect();
    teardown(&fs, scope, spawned, &root);
    assert_eq!(
      anchored,
      vec![b],
      "the batch's own order decides the map: {a:?} was disarmed AFTER its own arm, so only {b:?} retains an anchor"
    );
  }

  /// The same churn repeated: every round creates the directory, runs the same
  /// three-op batch, consumes the live watch's anchor exactly as the cold
  /// enumerate does, disarms it, and deletes the directory. The descriptors this
  /// process holds into the tree must return to their steady state every round.
  ///
  /// Fail-on-old: each round strands the disarmed watch's anchor in the map, so
  /// the count climbs by one per round — the walk toward `RLIMIT_NOFILE` at which
  /// real arms and binding re-proofs begin to fail.
  #[test]
  fn churned_batches_strand_no_descriptors() {
    const ROUNDS: u64 = 64;

    let root = scratch("churn");
    let dir = root.join("churn");
    let fs = RealFs::new();
    let scope = ScopeId::new(NonZeroU64::new(1).expect("scope ids start at one"));
    let spawned = attach(&fs, scope, &root);

    let mut steady: Option<usize> = None;
    for round in 0..ROUNDS {
      std::fs::create_dir(&dir).expect("create the churned directory");
      let (a, b) = (watch_id(2 * round + 1), watch_id(2 * round + 2));
      let outcomes = fs.batch_control(
        scope,
        LANE,
        vec![
          arm(a, &dir),
          ControlRequest::Disarm { watch: a },
          arm(b, &dir),
        ],
      );
      for resolution in &outcomes.resolutions {
        assert!(
          matches!(
            resolution.outcome,
            WatchOutcome::Installed(_) | WatchOutcome::Aliased(_)
          ),
          "staging (round {round}): {:?} must install: {:?}",
          resolution.watch,
          resolution.outcome
        );
      }
      // Anti-vacuity: a round whose live arm published NO anchor would hold the
      // descriptor count flat while proving nothing about the ordering.
      assert!(
        fs.anchors.lock().unwrap().contains_key(&b),
        "staging (round {round}): the live arm published its anchor, so the count below measures something"
      );

      // The production consumer, in its two production steps: the dispatch takes
      // the live anchor out of the map and the cold enumerate reads through it
      // and closes it, which is why a correctly ordered map returns to steady
      // state.
      let listed = fs.enumerate(b, fs.take_enumerate_anchor(b), &dir);
      assert!(
        matches!(listed, RawEnumerate::Listed { .. }),
        "staging (round {round}): the anchor-relative listing succeeds: {listed:?}"
      );

      fs.batch_control(scope, LANE, vec![ControlRequest::Disarm { watch: b }]);
      std::fs::remove_dir(&dir).expect("remove the churned directory");
      // The source's queue is bounded; nothing here consumes it, so drain what
      // the churn minted rather than letting a full channel stall the reader.
      while spawned.receiver.try_recv().is_ok() {}

      let open = fds_into(&root);
      match steady {
        // Round zero fixes the steady state — whatever the live source itself
        // holds into the tree — and every later round must match it exactly.
        None => steady = Some(open),
        Some(expected) => assert_eq!(
          open, expected,
          "round {round}: {open} descriptors resolve into {root:?}, not the steady {expected} — a disarmed watch's anchor was left behind"
        ),
      }
    }

    let anchored = fs.anchors.lock().unwrap().len();
    teardown(&fs, scope, spawned, &root);
    assert_eq!(
      anchored, 0,
      "every round's anchor was published and consumed in the batch's order, so none is retained"
    );
  }
}

/// Bounded ingress is not bounded retention: the driver admits a request past a
/// fixed-capacity mailbox and then RETAINS its reply sender, fence record or
/// native handle until a settlement it does not control. Every cell here pins one
/// of those retained populations against the failure state that makes it grow —
/// a native transport that will not quiesce.
mod retention {
  use super::*;

  /// A teardown closure that UNWINDS must not corrupt the reaper.
  ///
  /// The worker used to call the arbitrary closure and only then retire the
  /// operation, so an unwind killed the thread with `threads`, `busy` and
  /// `outstanding` still counting it. Close parks on `outstanding`, and the
  /// growth rule reads `threads - busy`, so both then reason from state that can
  /// never be repaired: close reports a phantom obligation forever, and enough
  /// unwinds leave `threads == busy == MAX_TEARDOWN_REAPERS` with no worker
  /// alive to claim anything.
  ///
  /// FAIL-ON-REVERT: drop the RAII claim guard and the containment boundary in
  /// `reap_loop` (back to `teardown(); finish_teardown(inner);`), and the healthy
  /// teardown below is never reclaimed — the panicking worker is gone and the
  /// close never resolves inside its deadline.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_panicking_teardown_does_not_strand_the_reaper() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/s", FileKind::Dir, 2);
    let first = watch(&rig, "/r").await;
    let second = watch(&rig, "/s").await;

    // The first scope's teardown unwinds inside `shutdown`.
    rig.fs.panic_teardowns(1);
    let (reply, on_first) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope: first,
        reply: Some(reply),
      })
      .await
      .unwrap();
    assert!(
      tokio::time::timeout(interpreted_secs(10), on_first)
        .await
        .expect("the unwound teardown still retires its obligation")
        .expect("the waiter is answered, never dropped")
        .is_unproven(),
      "an unwound teardown discharges its obligation — leaving it owed would make \
       every later close report work that already stopped — but it proves nothing, \
       so the waiter is answered with the unproven verdict rather than `Torn`"
    );

    // A LATER healthy teardown still runs: the worker survived the unwind, so the
    // queue is still drainable.
    let (reply, on_second) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope: second,
        reply: Some(reply),
      })
      .await
      .unwrap();
    assert!(
      tokio::time::timeout(interpreted_secs(10), on_second)
        .await
        .expect("a healthy teardown after a panic still completes")
        .expect("the waiter is answered")
        .is_torn(),
      "the reaper keeps claiming work after containing an unwind"
    );
    assert!(
      settle(|| rig.fs.shutdowns() == 1).await,
      "exactly the healthy stream counted a completed shutdown"
    );

    // Close is BOUNDED and HONEST: it never waits on the discharged obligation,
    // and it never reports `Ok` over a teardown whose quiescence was not proven.
    let (reply, on_close) = futures_channel::oneshot::channel();
    rig.commands.send(Command::Close { reply }).await.unwrap();
    let pending = tokio::time::timeout(interpreted_secs(10), on_close)
      .await
      .expect("close resolves — the phantom obligation is gone")
      .expect("the driver replies");
    assert_eq!(
      pending, 1,
      "the unproven teardown is reported, so close cannot claim quiescence over it"
    );
  }

  /// A `shutdown` that RETURNS while reporting its quiescence unproven is the
  /// same terminal as one that unwound.
  ///
  /// The unwind was never the only way to fail a teardown, and on Windows it is
  /// not even the common one. Those pumps own overlapped reads, so between a
  /// successful issue and the dequeue of that issue's completion the KERNEL owns
  /// the buffer and the `OVERLAPPED`. A pump that panicked, or whose cancellation
  /// drain never dequeued the read's final completion, therefore RETAINS that
  /// memory (and, on the panic path, the directory and port handles with it)
  /// rather than freeing what the kernel may still write into — and then returns
  /// normally, because leaking is the memory-safe answer, not a crash.
  ///
  /// Reading the RETURN as success made the driver classify that leak as
  /// `TornDown`: repeated failures grew unbounded native state while nothing was
  /// incremented anywhere, and `unwatch` and `close` went on certifying
  /// quiescence over streams nobody had observed stop. The leak stays; what
  /// changes is that it is now reported.
  ///
  /// FAIL-ON-REVERT: choose the terminal in `submit_teardown` from the unwind
  /// alone (`if unwound { TeardownFailed } else { TornDown }`) and every
  /// assertion here flips — the waiters resolve `Torn` and close reports 0.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_teardown_that_returns_unproven_is_reported_like_one_that_unwound() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/s", FileKind::Dir, 2);
    let first = watch(&rig, "/r").await;
    let second = watch(&rig, "/s").await;

    // The first scope's teardown COMPLETES — no unwind — and answers that it
    // could not prove the stream gone.
    rig.fs.unproven_teardowns(1);
    assert!(
      unwatch_ack(&rig, first).await.is_unproven(),
      "a teardown that retained state it could not prove dead is not `Torn`, \
       however normally its call returned"
    );
    assert!(
      settle(|| rig.fs.shutdowns() == 1).await,
      "and it RETURNED: the backend counted a completed shutdown, so this is not \
       the unwind path in disguise"
    );

    // Latched per scope, exactly as an unwind latches: the scope is gone, and the
    // arm that would otherwise answer `Unknown` still carries the fact.
    assert!(
      unwatch_ack(&rig, first).await.is_unproven(),
      "the latch outlives the scope it names"
    );

    // Per scope, never global.
    assert!(
      unwatch_ack(&rig, second).await.is_torn(),
      "a scope whose teardown proved its stream gone still reports proven quiescence"
    );

    // Close counts it for the rest of the driver's life and refuses to report
    // `Ok` over it — while staying BOUNDED, because the obligation itself was
    // discharged when the terminal landed.
    let (reply, on_close) = futures_channel::oneshot::channel();
    rig.commands.send(Command::Close { reply }).await.unwrap();
    let pending = tokio::time::timeout(interpreted_secs(10), on_close)
      .await
      .expect("close resolves — nothing is still owed")
      .expect("the driver replies");
    assert_eq!(
      pending, 1,
      "the unproven teardown is reported, so close cannot claim quiescence over it"
    );
  }

  /// Sends one `Watch` and hands back the refusal it must produce.
  async fn refused_watch(rig: &Rig, root: &str) -> WatchRootError {
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Watch {
        root: PathBuf::from(root),
        interest: tributary_proto::Interest::all(),
        reply,
      })
      .await
      .unwrap();
    let outcome = tokio::time::timeout(interpreted_secs(10), on_reply)
      .await
      .expect("the watch resolves")
      .expect("the driver replies");
    match outcome {
      Ok(grant) => {
        // A grant that is dropped unread unwinds its stream, which would leave
        // the cell racing a teardown it never asked for; defuse first, then fail.
        grant.defuse();
        panic!("this watch is expected to be refused");
      }
      Err(err) => err,
    }
  }

  /// A spawn that fails AFTER its stream went live retires the rollback inside
  /// the driver's COUNTED teardown, so an unproven rollback reaches the same
  /// terminal a committed stream's failed teardown does.
  ///
  /// The barrier used to shut its own post-live stream down and discard the
  /// `Quiesce` that call answered, on the reasoning that a failing spawn owns no
  /// scope and owes no counted obligation. A Windows pump that cannot prove its
  /// overlapped read's pin ended RETAINS the buffer and the handle — the correct
  /// memory-safety choice — and returns normally, so that discard reduced a
  /// retained buffer and handle to a plain spawn error: nothing counted it,
  /// nothing bounded admission over it, and `close` still reported quiescence.
  /// The scope not existing never made the retained state stop existing.
  ///
  /// FAIL-ON-REVERT: have the fake's post-live rejection tear its own stream
  /// down and return a bare `SourceError` (the old barrier shape) and the
  /// unproven ingest below never reaches 1 — close reports 0 over a rollback
  /// nobody proved gone.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_post_live_spawn_failure_retires_its_rollback_under_the_counted_teardown() {
    let rig = rig_with_capacity(64);
    // The root's object is swapped the instant the stream goes live, so the
    // barrier's post-live identity re-proof refuses with a RUNNING stream in
    // hand — the phase the finding is about.
    rig.fs.replace_at_live("/r", FileKind::Dir, 99);
    // And that rollback's teardown completes without proving the stream gone.
    rig.fs.unproven_teardowns(1);

    let err = refused_watch(&rig, "/r").await;
    assert!(
      matches!(
        err,
        WatchRootError::Source(SourceError::RootReplaced { .. })
      ),
      "the post-live bracket refuses the swapped object: {err:?}"
    );
    assert_eq!(
      rig.fs.spawns(),
      1,
      "staging: the stream went live before the bracket refused it"
    );

    // The stream is reclaimed by the driver's reaper — not inside the failing
    // spawn, and not left running either.
    assert!(
      settle(|| rig.fs.shutdowns() == 1).await,
      "the rollback is torn down through the driver, after the caller's error"
    );
    // And its verdict arrived as `TeardownFailed`, which is the whole point: the
    // retained state is now counted somewhere.
    settle_unproven(&rig, 1).await;

    let (reply, on_close) = futures_channel::oneshot::channel();
    rig.commands.send(Command::Close { reply }).await.unwrap();
    let pending = tokio::time::timeout(interpreted_secs(10), on_close)
      .await
      .expect("close resolves — the obligation is discharged, only unproven")
      .expect("the driver replies");
    assert_eq!(
      pending, 1,
      "close cannot claim quiescence over a rollback whose stream nobody proved gone"
    );
  }

  /// Repeated post-live spawn failures that prove nothing BOUND admission.
  ///
  /// This is the accumulation the finding names. Each failure retains native
  /// state; with the verdict discarded inside the spawn, nothing incremented and
  /// the driver went on admitting new streams forever. Routed through the counted
  /// teardown they reach `MAX_TEARDOWN_BACKLOG` like any other unproven teardown,
  /// and the next watch is refused with the typed, retryable terminal.
  ///
  /// FAIL-ON-REVERT: let the post-live rejection reclaim its own stream and
  /// return a bare error, and the backlog stays at 0 no matter how many failures
  /// pile up — the watch below is admitted and answers `RootReplaced`.
  #[tokio::test(flavor = "multi_thread")]
  async fn post_live_rollbacks_that_prove_nothing_bound_admission() {
    let rig = rig_with_capacity(64);
    rig.fs.unproven_teardowns(MAX_TEARDOWN_BACKLOG);
    for n in 0..MAX_TEARDOWN_BACKLOG {
      // A fresh object identity each round, so every spawn seals one identity
      // and finds another once its stream is live.
      rig.fs.replace_at_live("/r", FileKind::Dir, 100 + n as u64);
      let err = refused_watch(&rig, "/r").await;
      assert!(
        matches!(
          err,
          WatchRootError::Source(SourceError::RootReplaced { .. })
        ),
        "round {n} refuses post-live: {err:?}"
      );
    }
    settle_unproven(&rig, MAX_TEARDOWN_BACKLOG).await;

    let err = refused_watch(&rig, "/r").await;
    assert!(
      matches!(err, WatchRootError::CleanupBacklog),
      "past the bound a new stream is refused with the retryable terminal rather \
       than admitted over state nothing can reclaim: {err:?}"
    );
  }

  /// Queues one `Watch` and hands back its reply receiver WITHOUT waiting for
  /// the outcome — the shape a burst needs, where several admissions are judged
  /// before any of their spawns has returned.
  async fn queue_watch(
    rig: &Rig,
    root: String,
  ) -> futures_channel::oneshot::Receiver<Result<WatchGrant, WatchRootError>> {
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Watch {
        root: PathBuf::from(root),
        interest: tributary_proto::Interest::all(),
        reply,
      })
      .await
      .unwrap();
    on_reply
  }

  /// Reads the gauge admission compares against `MAX_TEARDOWN_BACKLOG`.
  ///
  /// Doubles as a mailbox BARRIER: the command channel is FIFO and the driver
  /// judges one command per loop iteration, so when this answers, every command
  /// queued ahead of it has already been admitted or refused.
  async fn teardown_pressure(rig: &Rig) -> usize {
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::DebugTeardownPressure { reply })
      .await
      .unwrap();
    tokio::time::timeout(interpreted_secs(10), on_reply)
      .await
      .expect("the driver answers")
      .expect("the driver replies")
  }

  /// A DESCENDING rig — the profile whose `replace_root` can take the
  /// same-transport widen route, which is the replacement window that owns no
  /// spawn to reserve against.
  fn descending_rig() -> Rig {
    let fs = FakeFs::new(1);
    fs.put("/r", FileKind::Dir, 1);
    fs.spawn_backend(BackendKind::Inotify);
    let (cmd_tx, cmd_rx) = async_channel::bounded(16);
    let (cleanup, cookie_wake) = cookie_ingress();
    let (ev_tx, ev_rx) = async_channel::bounded(64);
    tokio::spawn(run::<TokioRuntime, FakeFs>(
      DriverConfig {
        profile: BackendKind::Inotify,
        ..config()
      },
      fs.clone(),
      cmd_rx,
      cookie_wake,
      ev_tx,
      NullRegistry,
    ));
    Rig {
      fs,
      commands: cmd_tx,
      cleanup,
      events: ev_rx,
    }
  }

  /// Drives `count` post-live spawn failures CONCURRENTLY and leaves every
  /// rollback counted-but-UNPROVEN, so the pressure gauge settles at exactly
  /// `count` and stays there for the driver's life — a stable floor a cell can
  /// then push one further admission against.
  async fn stage_unproven_backlog(rig: &Rig, count: usize) {
    rig.fs.unproven_teardowns(count);
    for n in 0..count {
      rig
        .fs
        .put(format!("/stage/{n}"), FileKind::Dir, 5_000 + n as u64);
    }
    let spawned_before = rig.fs.spawns();
    let hold = rig.fs.hold_spawns_post_live();
    let mut queued = Vec::with_capacity(count);
    for n in 0..count {
      queued.push(queue_watch(rig, format!("/stage/{n}")).await);
    }
    assert!(
      settle(|| rig.fs.spawns() == spawned_before + count).await,
      "staging: every backlog spawn is parked with its stream already live"
    );
    for n in 0..count {
      rig.fs.remove(format!("/stage/{n}"));
    }
    hold.release();
    for on_reply in queued {
      let outcome = tokio::time::timeout(interpreted_secs(30), on_reply)
        .await
        .expect("every staged watch is answered")
        .expect("the driver never drops a watch reply");
      match outcome {
        Ok(grant) => {
          grant.defuse();
          panic!("the root vanished under the live stream — the bracket must refuse");
        }
        Err(err) => assert!(
          matches!(
            err,
            WatchRootError::Source(SourceError::RootUnavailable { .. })
          ),
          "staging: a backlog round refuses post-live rather than at admission: {err:?}"
        ),
      }
    }
  }

  /// A BURST of watches racing one another's in-flight spawns cannot exceed the
  /// backlog bound by the size of the burst.
  ///
  /// The sequential cell above cannot see this, and neither can any sequential
  /// cell: it drives one post-live failure at a time, so each failure's teardown
  /// is already counted before the next watch is judged. The defect lives in the
  /// window where nothing has failed YET — a spawn owes no teardown until it
  /// returns, so a gauge built only from landed obligations reads the same
  /// below-limit value for every admission that races one window. All of them
  /// pass, all of them then surrender a rollback into the counted path, and the
  /// bound is overshot by however many were in flight.
  ///
  /// The post-live hold is what makes that window deterministic rather than a
  /// timing accident: every admitted spawn parks with its stream LIVE and its
  /// outcome undecided, so the whole cohort is genuinely simultaneous while the
  /// admissions behind it are being judged.
  ///
  /// FAIL-ON-REVERT: drop the reservation term from `teardown_pressure` (return
  /// the landed sum alone) and the staged gauge reads 0 with the whole burst in
  /// flight, every watch is admitted, and the backlog settles at `BURST` — the
  /// bound exceeded by exactly the burst size.
  #[tokio::test(flavor = "multi_thread")]
  async fn concurrent_spawns_cannot_burst_past_the_teardown_backlog_bound() {
    const BURST: usize = MAX_TEARDOWN_BACKLOG + 4;

    let rig = rig_with_capacity(64);
    // Each rollback's teardown completes WITHOUT proving its stream gone, so the
    // obligation stays counted for the driver's life. That is what makes the
    // final read below a settled fact rather than a sample of a draining
    // backlog, which a burst would otherwise sweep through on its way past.
    rig.fs.unproven_teardowns(BURST);
    for n in 0..BURST {
      rig
        .fs
        .put(format!("/burst/{n}"), FileKind::Dir, 1_000 + n as u64);
    }

    let post_live = rig.fs.hold_spawns_post_live();
    let mut queued = Vec::with_capacity(BURST);
    for n in 0..BURST {
      queued.push(queue_watch(&rig, format!("/burst/{n}")).await);
    }
    let staged = teardown_pressure(&rig).await;

    // Every watch has been judged. A REFUSAL is answered on the command arm, so
    // its reply is already here; an ADMITTED watch answers only when its spawn
    // returns, and every spawn is parked — so this split is exact, not a race.
    let mut refusals = Vec::new();
    let mut admitted = Vec::new();
    for mut on_reply in queued {
      match on_reply.try_recv() {
        Ok(None) => admitted.push(on_reply),
        Ok(Some(Ok(grant))) => {
          grant.defuse();
          panic!("an admitted watch cannot answer while its spawn is parked post-live");
        }
        Ok(Some(Err(err))) => refusals.push(err),
        Err(_) => panic!("the driver never drops a watch reply"),
      }
    }
    assert_eq!(
      staged, MAX_TEARDOWN_BACKLOG,
      "with the whole cohort in flight the gauge counts every reserved stream, so \
       admission sees the pressure the burst is about to land rather than the zero \
       it has landed so far"
    );
    assert_eq!(
      admitted.len(),
      MAX_TEARDOWN_BACKLOG,
      "exactly the bound is admitted, whatever the burst size"
    );
    assert!(
      refusals.len() == BURST - MAX_TEARDOWN_BACKLOG
        && refusals
          .iter()
          .all(|err| matches!(err, WatchRootError::CleanupBacklog)),
      "the overflow of the burst is refused with the typed retryable terminal: {refusals:?}"
    );

    // Now convert every reservation. The roots vanish under the parked spawns,
    // so each identity bracket refuses with a RUNNING stream in hand and hands
    // it back — the surrender that becomes a counted teardown.
    assert!(
      settle(|| rig.fs.spawns() == MAX_TEARDOWN_BACKLOG).await,
      "staging: every admitted spawn is parked with its stream already live"
    );
    for n in 0..BURST {
      rig.fs.remove(format!("/burst/{n}"));
    }
    post_live.release();

    // The driver retires a surrendered stream BEFORE it answers the caller, so
    // once the last reply is in, every rollback this burst produced is counted.
    for on_reply in admitted {
      let outcome = tokio::time::timeout(interpreted_secs(30), on_reply)
        .await
        .expect("every admitted watch is answered")
        .expect("the driver never drops a watch reply");
      match outcome {
        Ok(grant) => {
          grant.defuse();
          panic!("the root vanished under the live stream — the bracket must refuse");
        }
        Err(err) => assert!(
          matches!(
            err,
            WatchRootError::Source(SourceError::RootUnavailable { .. })
          ),
          "the post-live bracket refuses the vanished root: {err:?}"
        ),
      }
    }
    assert_eq!(
      teardown_pressure(&rig).await,
      MAX_TEARDOWN_BACKLOG,
      "the landed backlog is exactly the bound — the reservations converted \
       one-for-one and none of the burst was admitted over the top of them"
    );
  }

  /// A cohort of DESCENDING births parked on held ROOT ARMS holds its units of
  /// the bound, so nothing is admitted over the top of it.
  ///
  /// The spawn term alone stops covering a descending birth the moment its spawn
  /// RETURNS. What returns is a running stream the caller has not been handed and
  /// cannot unwatch: the registration is still in flight, still the driver's own
  /// work, and still fallible on both sides — the root arm can fail, and the
  /// `watch()` future can be cancelled — with either outcome retiring the stream
  /// into the counted teardown path. Between the spawn's return and the root
  /// arm's resolution a gauge built from spawns and landed teardowns therefore
  /// reads a below-limit value however many births are staged, and admission
  /// walks straight past the bound; when the arms then fail, every staged stream
  /// retires at once and lands the whole overshoot as retained handles and
  /// readers.
  ///
  /// The concurrency is what makes this visible, and it is not the concurrency
  /// the spawn-burst cell above stages. There every admission races ONE in-flight
  /// spawn window, which `pending_spawns` already covers; the gap opens only once
  /// those spawns RESOLVE, so the cohort has to be simultaneously past its spawns
  /// and short of its grants. Holding the root arms puts it there deterministically
  /// — every birth commits its stream, defers its grant, dispatches its root arm
  /// and stops — and the admissions judged afterwards read a gauge whose spawn
  /// reservations have all been released.
  ///
  /// FAIL-ON-REVERT: drop the `deferred_grants` term from `teardown_pressure` and
  /// the staged gauge reads 0 with 64 live ungranted streams parked, every
  /// overflow watch is ADMITTED, and the failed cohort lands `COHORT + OVERFLOW`
  /// unproven teardowns — the bound exceeded by the overflow.
  #[tokio::test(flavor = "multi_thread")]
  async fn held_root_arms_cannot_burst_past_the_teardown_backlog_bound() {
    const COHORT: usize = MAX_TEARDOWN_BACKLOG;
    const OVERFLOW: usize = 4;

    let rig = descending_rig();
    // Every teardown this cell converts completes WITHOUT proving its stream
    // gone, so the landed backlog it ends on is a settled fact rather than a
    // sample of a draining one. Sized for the OVERSHOOT as well as the cohort, so
    // a reverted gauge is measured rather than accidentally bounded here.
    rig.fs.unproven_teardowns(COHORT + OVERFLOW);
    for n in 0..COHORT {
      rig
        .fs
        .put(format!("/deferred/{n}"), FileKind::Dir, 2_000 + n as u64);
    }

    // Held from before the first spawn: the root arm is the first control batch a
    // descending birth dispatches, so every admitted birth parks there with its
    // stream live and its grant undelivered.
    let arms = rig.fs.hold_arms();
    let mut queued = Vec::with_capacity(COHORT);
    for n in 0..COHORT {
      queued.push(queue_watch(&rig, format!("/deferred/{n}")).await);
    }
    assert!(
      settle(|| arms.captured() == COHORT).await,
      "staging: every birth is past its spawn and parked on ITS root arm, so the \
       whole cohort is simultaneously live, ungranted and unreserved by the spawn term"
    );

    // Doubles as the mailbox barrier: every watch above has been judged.
    let staged = teardown_pressure(&rig).await;
    assert_eq!(
      staged, COHORT,
      "the deferred cohort holds a unit each — the gauge counts the streams the \
       driver is still on the hook for, not only the ones it has finished with"
    );
    for (n, on_reply) in queued.iter_mut().enumerate() {
      assert!(
        matches!(on_reply.try_recv(), Ok(None)),
        "staging: cohort member {n} is admitted and still waiting on its root arm"
      );
    }

    // Now the admissions the bound has to refuse. Their spawn reservations would
    // be free — every cohort spawn has already returned — so only the deferred
    // term can be holding them out.
    for n in 0..OVERFLOW {
      rig
        .fs
        .put(format!("/overflow/{n}"), FileKind::Dir, 3_000 + n as u64);
    }
    let mut overflow = Vec::with_capacity(OVERFLOW);
    for n in 0..OVERFLOW {
      overflow.push(queue_watch(&rig, format!("/overflow/{n}")).await);
    }
    assert_eq!(
      teardown_pressure(&rig).await,
      COHORT,
      "the barrier proves every overflow watch has been judged, and the gauge is \
       unchanged — none of them created anything"
    );
    let mut refusals = Vec::new();
    for mut on_reply in overflow {
      match on_reply.try_recv() {
        Ok(None) => panic!(
          "an overflow watch was ADMITTED over a cohort of live ungranted streams — \
           the bound is bypassable for as long as the root arms are held"
        ),
        Ok(Some(Ok(grant))) => {
          grant.defuse();
          panic!("an admitted watch cannot answer while its root arm is parked");
        }
        Ok(Some(Err(err))) => refusals.push(err),
        Err(_) => panic!("the driver never drops a watch reply"),
      }
    }
    assert!(
      refusals.len() == OVERFLOW
        && refusals
          .iter()
          .all(|err| matches!(err, WatchRootError::CleanupBacklog)),
      "every overflow admission is refused with the typed retryable terminal, \
       before any state is touched: {refusals:?}"
    );

    // Convert the cohort the way the finding names: fail every held root arm, so
    // each staged birth refuses the registration it never granted and retires the
    // stream behind it. (A cancelled `watch()` future is the same conversion by
    // the other door — the grant commit fails and unwinds the scope.)
    for n in 0..COHORT {
      rig
        .fs
        .fail_watch_at(format!("/deferred/{n}"), tributary_proto::WatchError::Io);
    }
    arms.release();
    for on_reply in queued {
      let outcome = tokio::time::timeout(interpreted_secs(30), on_reply)
        .await
        .expect("every staged watch is answered")
        .expect("the driver never drops a watch reply");
      match outcome {
        Ok(grant) => {
          grant.defuse();
          panic!("a root arm that failed cannot hand the caller coverage");
        }
        Err(err) => assert!(
          matches!(
            err,
            WatchRootError::Source(SourceError::RootUnavailable { .. })
          ),
          "the deferred grant is refused with the arm's own failure: {err:?}"
        ),
      }
    }

    settle_unproven(&rig, COHORT).await;
    assert_eq!(
      teardown_pressure(&rig).await,
      COHORT,
      "the cohort retires together and lands exactly the bound — only the bounded \
       number was ever admitted, so there is no overshoot to land"
    );
  }

  /// A replacement in flight reserves its unit too, even before it owns a
  /// stream to reserve against.
  ///
  /// The spawn term alone does not cover this. A same-transport WIDEN resolves
  /// over the LIVE fd and dispatches no spawn at all, so for its whole meta and
  /// pre-arm window it is invisible to a gauge built from spawns and landed
  /// teardowns — and it is not free: its fallback dispatches the general
  /// replacement spawn, and the general route retires the old stream on the very
  /// commit that reports success. A cohort of widens therefore passes the same
  /// below-limit state that a cohort of spawns did, and converts together
  /// afterwards.
  ///
  /// FAIL-ON-REVERT: drop the `replace_states` term from `teardown_pressure`
  /// (leave the spawn term in place) and the watch below is admitted — the
  /// gauge reads only the staged floor and never sees the widen holding the
  /// last unit.
  #[tokio::test(flavor = "multi_thread")]
  async fn an_in_flight_replacement_holds_its_unit_of_the_backlog_bound() {
    let rig = descending_rig();
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // One unit short of the bound, and permanently so.
    stage_unproven_backlog(&rig, MAX_TEARDOWN_BACKLOG - 1).await;
    assert_eq!(
      teardown_pressure(&rig).await,
      MAX_TEARDOWN_BACKLOG - 1,
      "staging: the floor is one unit below the bound"
    );

    // The widen enters `replace_states` on its own command arm and is parked at
    // the pre-arm, so it is in flight — owning no spawn — for the rest of the
    // cell.
    let hold = rig.fs.hold_prearms();
    let (reply, on_replace) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r")),
        reply,
      })
      .await
      .unwrap();

    // FIFO mailbox, one command judged per loop iteration: this watch is judged
    // strictly after the replace was admitted, so it reads the replace's
    // reservation.
    let err = refused_watch(&rig, "/r/other").await;
    assert!(
      matches!(err, WatchRootError::CleanupBacklog),
      "the in-flight replacement holds the last unit, so a new stream is refused \
       with the typed retryable terminal: {err:?}"
    );

    hold.release();
    drop(on_replace);
  }

  /// Sends one awaited `Unwatch` and hands back its reply receiver.
  async fn request_unwatch(
    rig: &Rig,
    scope: ScopeId,
  ) -> futures_channel::oneshot::Receiver<crate::driver::UnwatchAck> {
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Unwatch {
        scope,
        reply: Some(reply),
      })
      .await
      .unwrap();
    on_reply
  }

  async fn unwatch_ack(rig: &Rig, scope: ScopeId) -> crate::driver::UnwatchAck {
    let on_reply = request_unwatch(rig, scope).await;
    tokio::time::timeout(interpreted_secs(10), on_reply)
      .await
      .expect("the unwatch resolves")
      .expect("the waiter is answered, never dropped")
  }

  /// Waits until the DRIVER has ingested `target` unwound teardowns.
  ///
  /// Staging on the panicking thread does not work: the last observable a
  /// panicking `shutdown` touches is reached BEFORE the unwind, and the panic
  /// runtime's own reporting then runs for as long as symbolising a backtrace
  /// takes — so a cell that continues there is racing the terminal, not ordered
  /// after it.
  async fn settle_unproven(rig: &Rig, target: usize) {
    for _ in 0..200 {
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::DebugUnprovenTeardowns { reply })
        .await
        .unwrap();
      let seen = tokio::time::timeout(interpreted_secs(10), on_reply)
        .await
        .expect("the driver answers")
        .expect("the driver replies");
      if seen >= target {
        return;
      }
      tokio::time::sleep(Duration::from_millis(10)).await;
      std::thread::sleep(settle_round_slice());
    }
    panic!("the driver never ingested {target} unwound teardown(s)");
  }

  /// An unwatch parked BEFORE the unwind is re-verdicted in place, and one
  /// admitted after the scope is gone entirely still reports the unwind.
  ///
  /// A waiter carries the verdict its admission chose and resolves later, at
  /// quiescence — so the unwind that voids that verdict lands in between and has
  /// to rewrite it. Answering `Torn` here is the contradiction the close reply
  /// already refuses to make: unwatch would license the caller to release
  /// everything the stream can still reach, while close reports one teardown
  /// whose quiescence nobody proved.
  ///
  /// FAIL-ON-REVERT: drop the `taint_unproven_scope` call from the live loop's
  /// `TeardownFailed` arm and the parked waiter resolves `Torn`; drop
  /// `admitted_verdict` from the `Command::Unwatch` immediate-answer arm and the
  /// later unwatch resolves `Unknown`.
  #[tokio::test(flavor = "multi_thread")]
  async fn an_unwound_teardown_re_verdicts_the_waiters_it_finds_and_those_that_follow() {
    let rig = rig_with_capacity(64);
    let scope = watch(&rig, "/r").await;

    // The waiter is admitted while the scope is live and healthy, so its
    // admission chooses `Torn`; the hold keeps it parked until the unwind lands.
    let hold = rig.fs.hold_teardowns();
    let parked = request_unwatch(&rig, scope).await;
    assert!(
      settle(|| hold.captured() == 1).await,
      "staging: the scope's teardown is inside `shutdown` with the waiter parked"
    );

    rig.fs.panic_teardowns(1);
    hold.release();
    assert!(
      tokio::time::timeout(interpreted_secs(10), parked)
        .await
        .expect("the parked waiter is answered")
        .expect("never dropped")
        .is_unproven(),
      "a waiter admitted before the unwind is re-verdicted, not resolved with the \
       `Torn` its admission chose"
    );

    // Every obligation is retired and the scope is gone, so this one is answered
    // immediately — on the arm that would otherwise report the root simply
    // unknown, dropping the one fact the caller asked for.
    assert!(
      unwatch_ack(&rig, scope).await.is_unproven(),
      "the latch outlives the scope it names"
    );

    // Per scope, never global: a scope whose every teardown was proven still
    // reports proven quiescence.
    rig.fs.put("/other", FileKind::Dir, 3);
    let other = watch(&rig, "/other").await;
    assert!(
      unwatch_ack(&rig, other).await.is_torn(),
      "an untainted scope is unaffected by another scope's unwind"
    );
  }

  /// A replace retires the old lane make-before-break, so a scope can be LIVE on
  /// a healthy successor while the stream it replaced was never proven gone. An
  /// unwatch admitted in that window must not be admitted as `Torn`.
  ///
  /// The rewrite alone cannot cover this: the unwind has already been processed
  /// when the waiter is admitted, so nothing will revisit it. The caller releases
  /// against the SCOPE, and part of the scope was never accounted for.
  ///
  /// FAIL-ON-REVERT: drop `admitted_verdict` from the live-scope arm of
  /// `Command::Unwatch` and the waiter below resolves `Torn` — its own teardown
  /// was healthy, and the retired lane's unwind is no longer consulted.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_scope_tainted_while_live_admits_later_unwatches_as_unproven() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/alt", FileKind::Dir, 2);
    let scope = watch(&rig, "/r").await;

    // The retiring lane's teardown parks on the first gate; the replace itself
    // reports success without waiting for it.
    let retiring = rig.fs.hold_teardowns();
    let (reply, on_replace) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/alt"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/alt")),
        reply,
      })
      .await
      .unwrap();
    tokio::time::timeout(interpreted_secs(10), on_replace)
      .await
      .expect("the replace resolves")
      .expect("the driver replies")
      .expect("make-before-break commits without waiting for the retired lane");
    assert!(
      settle(|| retiring.captured() == 1).await,
      "staging: the retired lane's teardown is inside `shutdown`"
    );

    // A second gate takes every LATER teardown, so releasing the first one
    // releases exactly the teardown that is about to unwind.
    let successor = rig.fs.hold_teardowns();
    rig.fs.panic_teardowns(1);
    retiring.release();
    // Staged on the DRIVER's own view of the unwind, so the unwatch below is
    // genuinely admitted after the taint rather than racing it.
    settle_unproven(&rig, 1).await;

    // The scope is still live on its replacement, so this takes the live-scope
    // admission arm — the one that chooses `Torn`.
    let on_live_arm = request_unwatch(&rig, scope).await;
    assert!(
      settle(|| successor.captured() == 1).await,
      "staging: the successor's own teardown runs, and it is healthy"
    );

    // The handle is gone now but the teardown is still owed, so this second
    // unwatch takes the OTHER parking arm — the one that chooses `Unknown`.
    let on_dead_arm = request_unwatch(&rig, scope).await;

    successor.release();
    for (waiter, arm) in [(on_live_arm, "live"), (on_dead_arm, "already-dead")] {
      assert!(
        tokio::time::timeout(interpreted_secs(10), waiter)
          .await
          .expect("the waiter is answered")
          .expect("never dropped")
          .is_unproven(),
        "the scope carries the retired lane's unwind on the {arm} admission arm, \
         even though the stream these unwatches wait on quiesced cleanly"
      );
    }
    assert!(
      settle(|| rig.fs.shutdowns() == 1).await,
      "staging: exactly the successor's teardown completed a shutdown"
    );
  }

  /// `MAX_TEARDOWN_REAPERS` bounds THREADS, not retained native handles.
  /// A make-before-break `replace_root` retires the live stream and reports
  /// success without waiting for it, so ordinary sequential replacements against
  /// a wedged filesystem pile up handles nothing can reclaim.
  ///
  /// FAIL-ON-REVERT: remove the `teardown_pressure(..) >= MAX_TEARDOWN_BACKLOG`
  /// arm from `Command::Replace` and every replacement is admitted — the loop
  /// below runs to completion with no `CleanupBacklog` and the retained-handle
  /// count grows past the bound.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_wedged_teardown_backlog_stops_replacement_admission() {
    let rig = rig_with_capacity(64);
    for n in 0..2 {
      rig.fs.put(format!("/alt{n}"), FileKind::Dir, 100 + n);
    }
    let scope = watch(&rig, "/r").await;

    // No teardown ever completes: the state the reaper exists to survive.
    let _wedged = rig.fs.hold_teardowns();

    let mut admitted = 0usize;
    let mut refused = false;
    for round in 0..(MAX_TEARDOWN_BACKLOG + 8) {
      let root = if round % 2 == 0 { "/alt0" } else { "/alt1" };
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Replace {
          scope,
          root: PathBuf::from(root),
          reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from(root)),
          reply,
        })
        .await
        .unwrap();
      match tokio::time::timeout(interpreted_secs(10), on_reply)
        .await
        .expect("the replace resolves")
        .expect("the driver replies")
      {
        Ok(()) => admitted += 1,
        Err(crate::error::ReplaceRootError::CleanupBacklog) => {
          refused = true;
          break;
        }
        Err(other) => panic!("unexpected replace refusal: {other}"),
      }
    }
    assert!(
      refused,
      "admission stops at the backlog bound; it admitted {admitted} replacements instead"
    );
    assert!(
      admitted <= MAX_TEARDOWN_BACKLOG,
      "retained streams stay within the bound: {admitted} admitted"
    );

    // A `watch` is the same shape — it admits a new stream, hence a teardown this
    // driver will one day owe — so it is refused by the same bound.
    let (reply, on_watch) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Watch {
        root: PathBuf::from("/alt0"),
        interest: tributary_proto::Interest::all(),
        reply,
      })
      .await
      .unwrap();
    assert!(
      matches!(
        tokio::time::timeout(interpreted_secs(10), on_watch)
          .await
          .expect("the watch resolves")
          .expect("the driver replies"),
        Err(crate::error::WatchRootError::CleanupBacklog)
      ),
      "a new root is a new teardown obligation, refused by the same bound"
    );
  }

  /// A spawn whose result cannot be DELIVERED must not destroy its native
  /// handle where it stands. The job runs on the runtime's shared blocking pool,
  /// and a successful message owns a live stream whose `Drop` joins the reader it
  /// just started — the unbounded join the teardown contract forbids on that
  /// executor, where it starves every later spawn, enumerate, control and cookie
  /// operation sharing the runtime.
  ///
  /// FAIL-ON-REVERT: restore `let _ = tx.try_send(OpResult::Spawned { .. })` in
  /// the spawn job and the stream is reclaimed by the handle's `Drop` on the
  /// blocking worker — the reclaiming thread is a pool worker, not
  /// `tributary-teardown`.
  #[tokio::test(flavor = "multi_thread")]
  async fn an_undeliverable_spawn_hands_its_stream_to_the_reaper() {
    let rig = rig_with_capacity(64);
    // Wedge the spawn AFTER its stream goes live — the backend's post-live
    // metadata phase, where the job already owns a real transport.
    let gate = rig.fs.hold_spawns_post_live();

    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Watch {
        root: PathBuf::from("/r"),
        interest: tributary_proto::Interest::all(),
        reply,
      })
      .await
      .unwrap();
    drop(on_reply);

    // Close honestly reports the wedged spawn, then the driver returns and drops
    // its result receiver.
    let (close_reply, on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    assert_eq!(
      tokio::time::timeout(interpreted_secs(10), on_close)
        .await
        .expect("close resolves at its grace boundary")
        .expect("the driver replies"),
      1,
      "staging: the post-live wedge is counted as non-quiescent"
    );

    // The wedge clears: the completed spawn finds its channel closed.
    gate.release();
    assert!(
      settle(|| rig.fs.shutdowns() == 1).await,
      "the undeliverable stream is reclaimed once the wedge clears"
    );
    let reclaimer = rig.fs.reclaim_thread().unwrap_or_default();
    assert!(
      reclaimer.starts_with("tributary-teardown"),
      "the stream was reclaimed on {reclaimer:?}, not on the teardown reaper — a \
       native join on the shared blocking pool is exactly what the contract forbids"
    );
  }

  /// An awaited `unwatch` resolves only at quiescence, so duplicates of one
  /// handle are RETAINED while a teardown is wedged. The 16-slot mailbox bounds
  /// only requests waiting to be received; the driver keeps draining it and
  /// parking every admitted caller.
  ///
  /// FAIL-ON-REVERT: remove the `MAX_PARKED_SETTLEMENTS` arm from
  /// `Command::Unwatch` and the parked population grows with total admitted
  /// calls — the census below far exceeds the bound and nothing is refused.
  #[tokio::test(flavor = "multi_thread")]
  async fn duplicate_awaited_unwatches_stop_at_the_parked_bound() {
    let rig = rig_with_capacity(64);
    rig.fs.put("/r/sub", FileKind::Dir, 2);
    let scope = watch(&rig, "/r/sub").await;

    // The teardown never quiesces, so no parked waiter is ever answered.
    let _wedged = rig.fs.hold_teardowns();

    // Retain every receiver: cancellation pruning cannot help a caller that is
    // genuinely still waiting.
    let mut waiters = Vec::new();
    let mut refused = 0usize;
    for _ in 0..(MAX_PARKED_SETTLEMENTS * 8) {
      let (reply, on_reply) = futures_channel::oneshot::channel();
      rig
        .commands
        .send(Command::Unwatch {
          scope,
          reply: Some(reply),
        })
        .await
        .unwrap();
      waiters.push(on_reply);
      tokio::task::yield_now().await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    for waiter in &mut waiters {
      if let core::task::Poll::Ready(Ok(ack)) = futures_util::poll!(waiter) {
        assert!(
          matches!(ack, crate::driver::UnwatchAck::Backlogged),
          "the only resolved waiters are the refused ones — the rest are parked \
           on a teardown that never quiesces"
        );
        refused += 1;
      }
    }
    assert!(refused > 0, "admission stopped at the bound");

    let (q, on_q) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::DebugUnwatchWaiters { scope, reply: q })
      .await
      .unwrap();
    let parked = on_q.await.unwrap();
    assert!(
      parked <= MAX_PARKED_SETTLEMENTS,
      "the driver retains at most the parked bound, not one per admitted call: {parked}"
    );
  }

  /// An enumerate is a bounded REQUEST whose retained size the filesystem
  /// chooses. Uncapped, one directory written by someone else decides how much
  /// memory the process holds; capped, the read reports itself INCOMPLETE, which
  /// the Monitor already lowers to a bounded retry plus a covering `Rescan`.
  ///
  /// FAIL-ON-REVERT: remove the `entries.len() >= enumerate_entry_cap()` break
  /// from `list_dir` and the listing reports every entry with `complete: true` —
  /// the truncation, and with it the loss signal, disappears.
  #[test]
  fn an_oversized_directory_enumerates_as_an_incomplete_read() {
    let dir = std::env::temp_dir().join(format!(
      "tributary-fs-enumerate-bound-{}-{:?}",
      std::process::id(),
      std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the temp dir is created");
    for n in 0..6u32 {
      std::fs::write(dir.join(format!("f{n}")), b"x").expect("the entry is created");
    }

    let RawEnumerate::Listed { entries, complete } = list_dir(&dir) else {
      panic!("the directory reads");
    };
    assert_eq!(entries.len(), 6, "staging: an unbounded read sees them all");
    assert!(complete, "staging: an unbounded read is complete");

    // The same directory, read under a bound below its size.
    let (entries, complete) = crate::driver::ENUMERATE_ENTRY_CAP.with(|cap| {
      cap.set(4);
      let read = list_dir(&dir);
      cap.set(crate::driver::MAX_ENUMERATE_ENTRIES);
      match read {
        RawEnumerate::Listed { entries, complete } => (entries.len(), complete),
        RawEnumerate::Failed(class) => panic!("the directory reads: {class:?}"),
      }
    });
    assert_eq!(entries, 4, "the retained listing stops at the bound");
    assert!(
      !complete,
      "and reports itself INCOMPLETE, so the Monitor covers the remainder with a \
       Rescan rather than silently omitting it"
    );
    let _ = std::fs::remove_dir_all(&dir);
  }
}

/// A driver that stops WITHOUT reaching its orderly close still holds native
/// streams, and reclaiming one is an unbounded JOIN of its reader thread.
///
/// The close sweep is the only path that can pair a teardown with a counted
/// obligation and a terminal, and three exits never reach it: the task's future
/// is dropped (cancellation), the runtime is shut down and drops every task it
/// holds, or the loop unwinds. On all three the frame's locals drop where they
/// stand, and a handle's `Drop` backstop performs exactly the join the teardown
/// reaper exists to keep off every executor the runtime owns.
///
/// The witness in every cell below is WHICH THREAD reclaimed the stream, and —
/// where a wedge is staged — that a reaper thread is the one parked. The fake's
/// `Drop` deliberately never parks on the teardown hold; only `shutdown` does,
/// so a captured hold is proof the join went to the reaper rather than running
/// inline.
mod abnormal_exit {
  use super::*;

  /// A rig whose driver task handle the cell KEEPS, so it can end the driver
  /// abnormally instead of through `Command::Close`.
  fn detachable_rig_with(
    config: DriverConfig,
    fs: FakeFs,
    registry: impl ScopeRegistry,
  ) -> (Rig, tokio::task::JoinHandle<()>) {
    fs.put("/r", FileKind::Dir, 1);
    let (cmd_tx, cmd_rx) = async_channel::bounded(16);
    let (cleanup, cookie_wake) = cookie_ingress();
    let (ev_tx, ev_rx) = async_channel::bounded(64);
    let driver = tokio::spawn(run::<TokioRuntime, FakeFs>(
      config,
      fs.clone(),
      cmd_rx,
      cookie_wake,
      ev_tx,
      registry,
    ));
    (
      Rig {
        fs,
        commands: cmd_tx,
        cleanup,
        events: ev_rx,
      },
      driver,
    )
  }

  fn detachable_rig() -> (Rig, tokio::task::JoinHandle<()>) {
    detachable_rig_with(config(), FakeFs::new(1), NullRegistry)
  }

  fn assert_reaped_off_the_runtime(fs: &FakeFs) {
    let reclaimer = fs.reclaim_thread().unwrap_or_default();
    assert!(
      reclaimer.starts_with("tributary-teardown"),
      "the stream was reclaimed on {reclaimer:?}, not on the teardown reaper — a \
       native join on a thread the runtime owns is exactly what the contract forbids"
    );
  }

  /// A CANCELLED driver task hands its live streams to the reaper.
  ///
  /// FAIL-ON-REVERT: hold `handles` in a plain local again (drop the
  /// `StreamReservoir` guard) and the map drops in place — the stream is
  /// reclaimed by its `Drop` backstop on the runtime worker that dropped the
  /// task, so the reclaiming thread is `tokio-runtime-worker`.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cancelled_driver_hands_its_live_streams_to_the_reaper() {
    let (rig, driver) = detachable_rig();
    let _scope = watch(&rig, "/r").await;

    driver.abort();
    assert!(
      driver.await.is_err(),
      "staging: the task is dropped, never allowed to finish"
    );

    assert!(
      settle(|| rig.fs.shutdowns() == 1).await,
      "the abandoned stream is still reclaimed"
    );
    assert_reaped_off_the_runtime(&rig.fs);
  }

  /// An abandoned teardown that WEDGES must park a reaper thread, not the
  /// runtime's. This is the whole point of the guard: the freeze it prevents is
  /// only visible when the join does not return.
  ///
  /// FAIL-ON-REVERT: without the guard the handle's `Drop` runs inline instead
  /// of `shutdown`, so nothing ever captures the hold and the stream reports a
  /// completed reclamation while the wedge is still in force.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_wedged_abandoned_teardown_never_parks_the_runtime() {
    let (rig, driver) = detachable_rig();
    let _scope = watch(&rig, "/r").await;

    let wedge = rig.fs.hold_teardowns();
    driver.abort();
    assert!(driver.await.is_err(), "staging: the task is dropped");

    assert!(
      settle(|| wedge.captured() == 1).await,
      "the abandoned stream's join runs on a reaper thread, parked inside `shutdown`"
    );
    assert_eq!(
      rig.fs.shutdowns(),
      0,
      "nothing completed while the join is wedged — and nothing was joined off the \
       reaper either"
    );
    // The runtime this task was cancelled on is untouched by that wedge.
    tokio::time::timeout(
      interpreted_secs(5),
      tokio::time::sleep(Duration::from_millis(1)),
    )
    .await
    .expect("the runtime still schedules while a native join is wedged");

    wedge.release();
    assert!(
      settle(|| rig.fs.shutdowns() == 1).await,
      "and it completes once the wedge clears"
    );
  }

  /// A registry whose `scope_live` panics, so the driver task UNWINDS with the
  /// just-born stream already in its handle map — the birth arm stores the
  /// handle before it publishes the scope.
  struct PanickingRegistry;

  impl ScopeRegistry for PanickingRegistry {
    fn scope_live(
      &self,
      _scope: ScopeId,
      _root: &Path,
      _identity: RootIdentity,
      _ancestors: &[RootIdentity],
      _backend: BackendKind,
      _stats: Option<crate::os::BackendStatsHandle>,
    ) {
      panic!("an injected unwind out of the driver task");
    }

    fn scope_dead(&self, _scope: ScopeId) {}

    fn final_root_conflict(
      &self,
      _final_root: &Path,
      _identity: RootIdentity,
      _ancestors: &[RootIdentity],
      _reserved: Option<&Path>,
      _exempt: Option<ScopeId>,
    ) -> Option<PathBuf> {
      None
    }
  }

  /// A driver task that UNWINDS hands its live streams to the reaper.
  ///
  /// One panic is printed from the runtime worker while this cell runs: it is
  /// the injected unwind, not a failure.
  ///
  /// FAIL-ON-REVERT: drop the `StreamReservoir` guard and the map unwinds in
  /// place, joining the reader on the worker thread that was running the task.
  #[tokio::test(flavor = "multi_thread")]
  async fn an_unwinding_driver_hands_its_live_streams_to_the_reaper() {
    let (rig, driver) = detachable_rig_with(config(), FakeFs::new(1), PanickingRegistry);

    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Watch {
        root: PathBuf::from("/r"),
        interest: tributary_proto::Interest::all(),
        reply,
      })
      .await
      .unwrap();
    // The unwind happens between the handle's storage and the grant, so this
    // caller sees a dropped sender rather than a reply.
    assert!(
      tokio::time::timeout(interpreted_secs(10), on_reply)
        .await
        .expect("the driver dies rather than replying")
        .is_err(),
      "staging: the registry call unwound before the grant was sent"
    );
    assert!(
      tokio::time::timeout(interpreted_secs(10), driver)
        .await
        .expect("the task ends")
        .is_err(),
      "staging: the task ended by panicking"
    );

    assert!(
      settle(|| rig.fs.shutdowns() == 1).await,
      "the stream the unwind abandoned is still reclaimed"
    );
    assert_reaped_off_the_runtime(&rig.fs);
  }

  /// A RUNTIME SHUTDOWN drops every task it holds, including the driver's.
  ///
  /// Not a `#[tokio::test]`: the runtime under test is the one being dropped, so
  /// the cell owns it and observes from an ordinary thread afterwards.
  ///
  /// FAIL-ON-REVERT: drop the `StreamReservoir` guard and the reclaiming thread
  /// is whichever thread the runtime's shutdown dropped the task on.
  #[test]
  fn a_runtime_shutdown_hands_the_driver_streams_to_the_reaper() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
      .worker_threads(2)
      .enable_all()
      .build()
      .expect("a runtime");
    let fs = FakeFs::new(1);
    fs.put("/r", FileKind::Dir, 1);
    let (cmd_tx, cmd_rx) = async_channel::bounded(16);
    let (cleanup, cookie_wake) = cookie_ingress();
    let (ev_tx, ev_rx) = async_channel::bounded(64);
    runtime.spawn(run::<TokioRuntime, FakeFs>(
      config(),
      fs.clone(),
      cmd_rx,
      cookie_wake,
      ev_tx,
      NullRegistry,
    ));
    let rig = Rig {
      fs: fs.clone(),
      commands: cmd_tx,
      cleanup,
      events: ev_rx,
    };
    runtime.block_on(async {
      let _scope = watch(&rig, "/r").await;
    });

    drop(runtime);

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while fs.shutdowns() == 0 && std::time::Instant::now() < deadline {
      std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(
      fs.shutdowns(),
      1,
      "the stream outliving its runtime is still reclaimed"
    );
    assert_reaped_off_the_runtime(&fs);
  }

  /// The replacement state is a stream reservoir too: a descending replace parks
  /// its spawned-but-uncommitted stream there while the new root pre-arms, and
  /// the handle map does not cover it.
  ///
  /// FAIL-ON-REVERT: guard only `handles` and exactly one of the two streams
  /// reaches the reaper — the pre-armed replacement is reclaimed by its `Drop`
  /// on the cancelling thread, so the hold captures one join instead of two and
  /// a completed shutdown is reported while the wedge still stands.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_cancelled_driver_hands_its_uncommitted_replacement_to_the_reaper() {
    let fs = FakeFs::new(1);
    fs.spawn_backend(BackendKind::Inotify);
    let (rig, driver) = detachable_rig_with(
      DriverConfig {
        profile: BackendKind::Inotify,
        ..config()
      },
      fs,
      NullRegistry,
    );
    rig.fs.put("/r2", FileKind::Dir, 20);
    let scope = watch(&rig, "/r").await;

    // The replacement spawns and is parked in `arming` while its pre-arm runs.
    let prearm = rig.fs.hold_prearms();
    let (reply, _on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r2"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
        reply,
      })
      .await
      .unwrap();
    assert!(
      settle(|| rig.fs.prearm_entries() == 1).await,
      "staging: the pre-arm is parked, so the uncommitted replacement is held in \
       the replace state"
    );

    let wedge = rig.fs.hold_teardowns();
    driver.abort();
    assert!(driver.await.is_err(), "staging: the task is dropped");

    assert!(
      settle(|| wedge.captured() == 2).await,
      "BOTH streams — the live one and the uncommitted replacement — are joined on \
       reaper threads: {} captured",
      wedge.captured()
    );
    assert_eq!(
      rig.fs.shutdowns(),
      0,
      "neither was reclaimed inline while the wedge stands"
    );

    wedge.release();
    prearm.release();
    assert!(
      settle(|| rig.fs.shutdowns() == 2).await,
      "and both complete once the wedge clears"
    );
  }

  /// A registry whose FINAL-ROOT CONFLICT check unwinds.
  ///
  /// That check is the first thing both stream commits do, and it runs while the
  /// driver holds a just-spawned stream OUTSIDE every map — dequeued from the
  /// result channel, not yet in `handles` and not in `replace_states`. It is
  /// caller code, so it is exactly the shape that can unwind there, and the
  /// reservoir guards cannot see the handle at that instant.
  ///
  /// `on_replacement` picks WHICH commit unwinds: the birth arm exempts no scope,
  /// the replacement commit exempts the scope it is replacing.
  struct PanickingConflictRegistry {
    on_replacement: bool,
  }

  impl ScopeRegistry for PanickingConflictRegistry {
    fn scope_live(
      &self,
      _scope: ScopeId,
      _root: &Path,
      _identity: RootIdentity,
      _ancestors: &[RootIdentity],
      _backend: BackendKind,
      _stats: Option<crate::os::BackendStatsHandle>,
    ) {
    }

    fn scope_dead(&self, _scope: ScopeId) {}

    fn final_root_conflict(
      &self,
      _final_root: &Path,
      _identity: RootIdentity,
      _ancestors: &[RootIdentity],
      _reserved: Option<&Path>,
      exempt: Option<ScopeId>,
    ) -> Option<PathBuf> {
      assert!(
        exempt.is_some() != self.on_replacement,
        "an injected unwind out of the final-root conflict check"
      );
      None
    }
  }

  /// A BIRTH that unwinds between the result channel and the handle map hands
  /// its stream to the reaper.
  ///
  /// The stream is live from the moment the spawn returns it, and the birth arm
  /// then runs the conflict check, mints the lane, attaches the scope's port and
  /// reads the stats handle before it commits — a stretch of caller code and a
  /// backend lock, either of which can unwind. A plain local there drops the
  /// handle where it stands, and its `Drop` backstop is the unbounded reader join
  /// on the runtime's own thread.
  ///
  /// One panic is printed from a runtime worker while this cell runs: it is the
  /// injected unwind, not a failure.
  ///
  /// FAIL-ON-REVERT: bind the dequeued spawn to a plain local again (drop the
  /// `EscrowedSpawn` in the birth arm) and nothing captures the hold — the
  /// handle's `Drop` reclaims it inline on the worker running the task, so a
  /// completed shutdown is reported while the wedge still stands.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_birth_unwinding_before_its_commit_hands_the_stream_to_the_reaper() {
    let (rig, driver) = detachable_rig_with(
      config(),
      FakeFs::new(1),
      PanickingConflictRegistry {
        on_replacement: false,
      },
    );
    let wedge = rig.fs.hold_teardowns();

    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Watch {
        root: PathBuf::from("/r"),
        interest: tributary_proto::Interest::all(),
        reply,
      })
      .await
      .unwrap();
    assert!(
      tokio::time::timeout(interpreted_secs(10), on_reply)
        .await
        .expect("the driver dies rather than replying")
        .is_err(),
      "staging: the conflict check unwound before the grant was sent"
    );
    assert!(
      tokio::time::timeout(interpreted_secs(10), driver)
        .await
        .expect("the task ends")
        .is_err(),
      "staging: the task ended by panicking"
    );

    assert!(
      settle(|| wedge.captured() == 1).await,
      "the in-transit stream's join runs on a reaper thread, parked inside \
       `shutdown`: {} captured",
      wedge.captured()
    );
    assert_eq!(
      rig.fs.shutdowns(),
      0,
      "nothing was reclaimed inline while the wedge stands"
    );

    wedge.release();
    assert!(
      settle(|| rig.fs.shutdowns() == 1).await,
      "and it completes once the wedge clears"
    );
  }

  /// The REPLACEMENT COMMIT has the same window, and it holds two streams at
  /// once: the live one the map still carries and the replacement the commit is
  /// about to install. Only the first is in a reservoir.
  ///
  /// One panic is printed from a runtime worker while this cell runs: it is the
  /// injected unwind, not a failure.
  ///
  /// FAIL-ON-REVERT: take the replacement by value again (drop the
  /// `EscrowedSpawn` from `commit_replace`) and the hold captures ONE join — the
  /// live stream, via the reservoir — while the replacement is reclaimed inline
  /// by its `Drop` on the unwinding worker.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_replacement_commit_that_unwinds_hands_its_stream_to_the_reaper() {
    let (rig, driver) = detachable_rig_with(
      config(),
      FakeFs::new(1),
      PanickingConflictRegistry {
        on_replacement: true,
      },
    );
    rig.fs.put("/r2", FileKind::Dir, 20);
    let scope = watch(&rig, "/r").await;

    let wedge = rig.fs.hold_teardowns();
    let (reply, _on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Replace {
        scope,
        root: PathBuf::from("/r2"),
        reservation: crate::watcher::ReservationGuard::detached_for_tests(PathBuf::from("/r2")),
        reply,
      })
      .await
      .unwrap();
    assert!(
      tokio::time::timeout(interpreted_secs(10), driver)
        .await
        .expect("the task ends")
        .is_err(),
      "staging: the task ended by panicking"
    );

    assert!(
      settle(|| wedge.captured() == 2).await,
      "BOTH streams — the live one the reservoir holds and the uncommitted \
       replacement the escrow does — are joined on reaper threads: {} captured",
      wedge.captured()
    );
    assert_eq!(
      rig.fs.shutdowns(),
      0,
      "neither was reclaimed inline while the wedge stands"
    );

    wedge.release();
    assert!(
      settle(|| rig.fs.shutdowns() == 2).await,
      "and both complete once the wedge clears"
    );
  }

  /// A registry whose scope reclaim unwinds — the close sweep's own caller code,
  /// run once per live scope with that scope's stream already out of the map.
  struct PanickingReclaimRegistry;

  impl ScopeRegistry for PanickingReclaimRegistry {
    fn scope_live(
      &self,
      _scope: ScopeId,
      _root: &Path,
      _identity: RootIdentity,
      _ancestors: &[RootIdentity],
      _backend: BackendKind,
      _stats: Option<crate::os::BackendStatsHandle>,
    ) {
    }

    fn scope_dead(&self, _scope: ScopeId) {
      panic!("an injected unwind out of the close sweep");
    }

    fn final_root_conflict(
      &self,
      _final_root: &Path,
      _identity: RootIdentity,
      _ancestors: &[RootIdentity],
      _reserved: Option<&Path>,
      _exempt: Option<ScopeId>,
    ) -> Option<PathBuf> {
      None
    }
  }

  /// The ORDERLY close sweep is not exempt from the rule either.
  ///
  /// It used to take the whole handle map (`std::mem::take`) and iterate the
  /// result, so from its first line the reservoir covered nothing: an unwind out
  /// of the per-scope reclaim or detach dropped the stream being swept AND every
  /// stream the sweep had not reached, all in place, on the driver's own thread.
  /// Draining one at a time leaves the remainder in the reservoir and the one in
  /// flight in an escrow.
  ///
  /// Two roots, so the two halves are distinguishable: the first is the escrowed
  /// one, the second is the one the sweep never reached.
  ///
  /// One panic is printed from a runtime worker while this cell runs: it is the
  /// injected unwind, not a failure.
  ///
  /// FAIL-ON-REVERT: sweep `std::mem::take(&mut streams.handles)` again and
  /// NEITHER stream reaches a reaper thread — both are reclaimed inline by their
  /// `Drop` backstop while the wedge stands.
  #[tokio::test(flavor = "multi_thread")]
  async fn a_close_sweep_that_unwinds_hands_every_stream_it_still_holds_to_the_reaper() {
    let (rig, driver) = detachable_rig_with(config(), FakeFs::new(1), PanickingReclaimRegistry);
    rig.fs.put("/r2", FileKind::Dir, 20);
    let _first = watch(&rig, "/r").await;
    let _second = watch(&rig, "/r2").await;

    let wedge = rig.fs.hold_teardowns();
    let (close_reply, _on_close) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Close { reply: close_reply })
      .await
      .unwrap();
    assert!(
      tokio::time::timeout(interpreted_secs(10), driver)
        .await
        .expect("the task ends")
        .is_err(),
      "staging: the sweep's first reclaim unwound the task"
    );

    assert!(
      settle(|| wedge.captured() == 2).await,
      "both streams are joined on reaper threads — the one the sweep had in hand \
       and the one it never reached: {} captured",
      wedge.captured()
    );
    assert_eq!(
      rig.fs.shutdowns(),
      0,
      "neither was reclaimed inline while the wedge stands"
    );

    wedge.release();
    assert!(
      settle(|| rig.fs.shutdowns() == 2).await,
      "and both complete once the wedge clears"
    );
  }

  /// A spawn result the driver ACCEPTED and never read owns a live stream too.
  ///
  /// `deliver_spawned` already covers the result that cannot be delivered — its
  /// `try_send` fails and the handle goes to the sink. This is the other half:
  /// the send SUCCEEDED, so the stream is sitting in the driver's own queue when
  /// the queue is dropped.
  ///
  /// Staged on a current-thread runtime: the test body holds the very thread the
  /// driver task runs on, so the pool's result provably lands in a queue the
  /// driver has no opportunity to read. `abort` then drops the task's future
  /// without polling it again.
  ///
  /// FAIL-ON-REVERT: drop the `OpQueue` guard and the queued result dies with the
  /// channel — the handle's `Drop` reclaims it inline, so nothing captures the
  /// hold and a completed shutdown is reported while the wedge still stands.
  #[tokio::test]
  async fn an_unread_spawn_result_hands_its_stream_to_the_reaper() {
    let (rig, driver) = detachable_rig();
    // Park the spawn AFTER its stream goes live, so the result is produced only
    // when this cell releases it.
    let gate = rig.fs.hold_spawns_post_live();
    let (reply, on_reply) = futures_channel::oneshot::channel();
    rig
      .commands
      .send(Command::Watch {
        root: PathBuf::from("/r"),
        interest: tributary_proto::Interest::all(),
        reply,
      })
      .await
      .unwrap();
    drop(on_reply);
    assert!(
      settle(|| rig.fs.spawns() == 1).await,
      "staging: the spawn is parked past the point its stream went live"
    );

    let wedge = rig.fs.hold_teardowns();
    gate.release();
    // The runtime thread is this one, and it is not going to an await: the pool
    // job completes and its result queues unread.
    std::thread::sleep(Duration::from_millis(200));
    driver.abort();
    assert!(
      driver.await.is_err(),
      "staging: the task is dropped unpolled"
    );

    assert!(
      settle(|| wedge.captured() == 1).await,
      "the unread result's stream is joined on a reaper thread"
    );
    assert_eq!(
      rig.fs.shutdowns(),
      0,
      "it was not reclaimed inline while the wedge stands"
    );

    wedge.release();
    assert!(
      settle(|| rig.fs.shutdowns() == 1).await,
      "and it completes once the wedge clears"
    );
  }
}
