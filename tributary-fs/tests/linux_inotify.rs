//! End-to-end integration through the public API against real inotify.
//!
//! Real-kernel timing is nondeterministic, so every assertion is
//! convergence-style: wait (bounded) until the expected fact is observed;
//! extra events — coalesced kinds, additional `Rescan`s — are always legal.
//!
//! The privileged cells (queue overflow, watch-limit exhaustion, the bind-mount
//! boundary) self-probe and skip loudly without `CAP_SYS_ADMIN`; the
//! `inotify-priv` suite of `ci/linux-verify.sh` (or `sudo -E` in CI) unlocks
//! them.
//!
//! ALWAYS run this binary with `--test-threads=1` (the verify script and CI
//! do): the sysctl cells shrink the user namespace's inotify limits, which
//! would starve any event-flow test running concurrently.

// not(miri): drives real inotify/statx syscalls and a tokio runtime — none of
// which miri can execute. The sans-I/O logic is covered by the lib unit tests.
#![cfg(all(target_os = "linux", feature = "tokio", not(miri)))]

use std::{
  ffi::{CStr, CString, OsStr},
  fs::File,
  os::fd::{AsRawFd, FromRawFd},
  path::{Path, PathBuf},
  sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, Ordering},
  },
  time::Duration,
};

use tributary_fs::{
  Backend, CoverOutcome, Event, Interest, ProbeStage, ReplaceRootError, SourceError, TokioWatcher,
  WatchRootError, WatcherOptions,
};

mod common;

use common::{Inventory, covers, delivered, drive};

/// Generous ceiling for one expected observation; CI runners are slow.
const DEADLINE: Duration = Duration::from_secs(20);

/// Scales every real-kernel timing budget in this binary. Under sanitizer
/// instrumentation the runtime is slowed several fold while the raw syscalls the
/// producer issues are not, so a fixed budget that is generous natively becomes
/// marginal: the CI sanitizer job sets this so the cells keep their coverage
/// instead of being skipped. Unset (native runs) it is 1 and nothing changes.
fn timing_scale() -> u32 {
  std::env::var("TRIBUTARY_FS_TIMING_SCALE")
    .ok()
    .and_then(|v| v.parse().ok())
    .filter(|n| *n > 0)
    .unwrap_or(1)
}

fn scaled(d: Duration) -> Duration {
  d * timing_scale()
}

/// A fresh scratch root under `TMPDIR` (the container mounts a tmpfs there,
/// keeping every test on container-native paths), canonicalized so event
/// paths and expectations share one byte form.
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
  dir
}

fn watcher() -> TokioWatcher {
  TokioWatcher::new(WatcherOptions::new()).expect("build watcher")
}

/// A watcher pinned to the inotify (descending) backend. The D2 same-fd widen
/// continuity is inotify-specific; under `CAP_SYS_ADMIN` (root / sudo /
/// privileged CI) `Backend::Auto` selects fanotify, which is kernel-recursive
/// and legitimately Rescan-BRIDGES a widen (the whole widen surfaces as one
/// structural Rescan) — so cells asserting the same-fd continuous DELIVERY
/// (distinct from that structural bridge) must pin inotify rather than take the
/// ambient backend.
fn inotify_watcher() -> TokioWatcher {
  TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Inotify)).expect("build watcher")
}

/// Waits until an event satisfying `pred` arrives, or the deadline lapses.
async fn wait_for(
  watcher: &mut TokioWatcher,
  mut pred: impl FnMut(&Event) -> bool,
) -> Option<Event> {
  tokio::time::timeout(scaled(DEADLINE), async {
    while let Some(event) = watcher.next().await {
      if pred(&event) {
        return Some(event);
      }
    }
    None
  })
  .await
  .ok()
  .flatten()
}

/// Converges on live coverage of `dir`: creates a fresh file there and waits
/// briefly for its delivery, retrying until one lands. A descending re-arm
/// (a `replace_root` widen rebuilds the tree on a new inotify instance)
/// descends asynchronously, so a single create in a not-yet-armed directory
/// is lost — inotify never re-delivers a create that predates its watch — but
/// once the re-arm reaches `dir`, a subsequent create is delivered. Returns
/// `false` only if coverage never becomes live within the retry budget.
async fn coverage_becomes_live(watcher: &mut TokioWatcher, dir: &Path, tag: &str) -> bool {
  for attempt in 0..40 {
    let probe = dir.join(format!("{tag}-{attempt}.txt"));
    if std::fs::write(&probe, b"x").is_err() {
      return false;
    }
    let seen = tokio::time::timeout(scaled(Duration::from_millis(500)), async {
      while let Some(event) = watcher.next().await {
        if covers(&event, &probe) {
          return true;
        }
      }
      false
    })
    .await
    .unwrap_or(false);
    if seen {
      return true;
    }
  }
  false
}

/// Converges on the CHILD'S OWN kernel watch DELIVERING for `dir`: creates a
/// fresh probe file there and waits for that file's exact [`delivered`] event,
/// retrying with a new probe until one lands. `false` means no such delivery ever
/// came.
///
/// # Why this is not [`coverage_becomes_live`], and why nothing may substitute it
///
/// The two ask the two questions [`covers`] and [`delivered`] exist to keep
/// apart, and they are not interchangeable in the direction that matters.
/// `coverage_becomes_live` asks only that the caller now owes a re-enumeration
/// below here — all a re-arm handshake needs to see.
///
/// This asks that `dir` ITSELF is watched, and only the exact path can settle
/// that. inotify attributes a create inside a directory to THAT directory's own
/// watch descriptor, so an event naming the probe file is a positive observation
/// that `dir`'s own kernel watch exists and is delivering, while an ancestor
/// `Rescan` is precisely what the Monitor emits when it could NOT arm `dir` and
/// dropped the subtree.
async fn child_watch_delivers(watcher: &mut TokioWatcher, dir: &Path, tag: &str) -> bool {
  for attempt in 0..40 {
    let probe = dir.join(format!("{tag}-{attempt}.txt"));
    if std::fs::write(&probe, b"x").is_err() {
      return false;
    }
    let arrived = tokio::time::timeout(scaled(Duration::from_millis(500)), async {
      while let Some(event) = watcher.next().await {
        if delivered(&event, &probe) {
          return true;
        }
      }
      false
    })
    .await
    .unwrap_or(false);
    if arrived {
      return true;
    }
  }
  false
}

/// Snapshot-and-set one `/proc/sys` knob; `None` = unwritable (unprivileged).
fn sysctl_swap(knob: &str, value: &str) -> Option<String> {
  let path = format!("/proc/sys/{knob}");
  let old = std::fs::read_to_string(&path).ok()?.trim().to_string();
  std::fs::write(&path, value).ok()?;
  Some(old)
}

fn sysctl_restore(knob: &str, value: &str) {
  let _ = std::fs::write(format!("/proc/sys/{knob}"), value);
}

/// Loud self-probe for the privileged cells.
fn privileged_or_skip(cell: &str) -> bool {
  match sysctl_swap("fs/inotify/max_queued_events", "16384") {
    Some(old) => {
      sysctl_restore("fs/inotify/max_queued_events", &old);
      true
    }
    None => {
      common::skip_notice(format_args!(
        "{cell}: needs CAP_SYS_ADMIN (run via linux-verify.sh inotify-priv)"
      ));
      false
    }
  }
}

/// Restores one `/proc/sys` knob on EVERY exit path, including the unwind out
/// of a failing assertion — which is exactly the path a cell takes the moment it
/// finds a real defect.
///
/// A restore reached only on normal fallthrough is a restore that never runs
/// when it matters. Libtest keeps running the remaining cells after a panicking
/// one, so a leaked shrink leaves the whole rest of the binary racing a 16-slot
/// kernel queue (or an 8-watch ceiling) — contamination that reads as unrelated
/// flakiness — and after a local `sudo` run it outlives the process entirely.
struct SysctlGuard {
  knob: &'static str,
  /// The exact text read back before the change, restored verbatim.
  previous: String,
  restored: bool,
}

/// How many times a guard's `Drop` re-attempts a cleanup that did not take.
/// `Drop` is the last line of defence, so it retries rather than reporting the
/// first refusal; the flags the retries consult record only VERIFIED success, so
/// each pass is a real second chance.
///
/// A sysctl restore is one cheap write, so it gets many closely-spaced passes.
/// A loop fixture's release already retries the unmount internally for ~2s per
/// pass, so a handful of outer passes is already a long wait on a mount that will
/// not come apart — and a genuinely wedged fixture must be REPORTED, not retried
/// until the suite's own budget runs out.
const CLEANUP_ATTEMPTS: usize = 25;

/// See [`CLEANUP_ATTEMPTS`]: the loop fixture's own passes are expensive. This count
/// is not their only bound — all of them together share ONE aggregate cleanup
/// deadline ([`cleanup_budget`]), so passes whose utilities keep RETURNING cannot
/// spend the count into a wall-clock hole.
const RELEASE_ATTEMPTS: usize = 5;

impl SysctlGuard {
  /// Sets `knob` to `value`, remembering the previous setting. `None` means the
  /// knob is unwritable (unprivileged) and nothing was changed.
  fn swap(knob: &'static str, value: &str) -> Option<Self> {
    Some(Self {
      knob,
      previous: sysctl_swap(knob, value)?,
      restored: false,
    })
  }

  /// Restores the knob and VERIFIES the readback, marking the guard restored
  /// only then.
  ///
  /// `restored` records a PROVEN restore, so it is set after the proof rather
  /// than on entry: a write the kernel accepted but did not honour — the very
  /// behaviour [`WatchBudgetHog`] probes for on this container class — leaves the
  /// flag clear, so [`Drop`] still retries instead of treating the failed attempt
  /// as done.
  fn restore_once(&mut self) -> std::io::Result<()> {
    if self.restored {
      return Ok(());
    }
    let path = format!("/proc/sys/{}", self.knob);
    std::fs::write(&path, &self.previous)?;
    let readback = std::fs::read_to_string(&path)?;
    if readback.trim() != self.previous.trim() {
      return Err(std::io::Error::other(format!(
        "wrote {} but it reads back as {}",
        self.previous.trim(),
        readback.trim()
      )));
    }
    self.restored = true;
    Ok(())
  }

  /// The explicit normal close: restores the knob and FAILS when it would not go
  /// back. A knob left shrunk leaves every later cell in this binary racing a
  /// 16-slot kernel queue (or an 8-watch ceiling), and a printed warning nobody
  /// reads is precisely how that becomes the next cell's mystery result — so the
  /// cell that could not clean up owns the failure.
  fn close(mut self) {
    if let Err(err) = self.restore_once() {
      panic!(
        "CLEANUP {}: could not restore to {}: {err}",
        self.knob, self.previous
      );
    }
  }
}

impl Drop for SysctlGuard {
  fn drop(&mut self) {
    // Reports, never panics: a panic while unwinding aborts the process and
    // destroys the very failure report this cleanup exists to protect. Bounded
    // retries, because `restored` stays clear until a restore verifiably took —
    // so a knob still contended by a dying helper gets more than one chance —
    // and loud evidence when every pass failed.
    let mut last = None;
    for _ in 0..CLEANUP_ATTEMPTS {
      match self.restore_once() {
        Ok(()) => return,
        Err(err) => {
          last = Some(err);
          std::thread::sleep(Duration::from_millis(20));
        }
      }
    }
    eprintln!(
      "CLEANUP FAILED {}: could not restore to {} in {CLEANUP_ATTEMPTS} attempts — every later \
       cell in this binary now runs against a contaminated knob: {last:?}",
      self.knob, self.previous
    );
  }
}

/// Suite 1 (§6.3): create/modify/remove churn converges through the descending
/// profile.
///
/// Convergence is asserted as what it MEANS — a consumer that obeyed the stream
/// ends holding the real tree, the top-level file's creation and removal both
/// accounted for — rather than as "something covering each mutated path
/// arrived", which one root `Rescan` supplies for the entire subtree without
/// decoding anything. That first claim is one a rescan-only backend legitimately
/// satisfies, by re-reading its way to the same tree.
///
/// The deep create carries a second, stronger claim beside it: the descent
/// reached `a/b` and the create was DELIVERED at that exact path — as the
/// kernel's own `IN_CREATE`, or as the cold enumerate's `Created` when the arm
/// landed after the write. A backend whose descent had stopped arming would
/// converge and fail this.
///
/// Both facts are collected in ONE pass over the stream; a second wait would be
/// looking for events the first already consumed.
#[tokio::test]
async fn churn_converges() {
  let root = scratch_root("churn");
  let mut w = watcher();
  let _h = w.watch(&root, Interest::all()).await.expect("watch");
  let mut inventory = Inventory::seeded(&root);

  std::fs::create_dir_all(root.join("a/b")).unwrap();
  std::fs::write(root.join("a/b/one.txt"), b"1").unwrap();
  std::fs::write(root.join("top.txt"), b"t").unwrap();
  std::fs::remove_file(root.join("top.txt")).unwrap();

  let deep = root.join("a/b/one.txt");
  let _ = drive(&mut w, &mut inventory, scaled(DEADLINE), |model| {
    model.delivered_at(&deep) && model.disagreement().is_empty()
  })
  .await;

  assert!(
    inventory.disagreement().is_empty(),
    "the consumer's view converged on the churned tree: {:?}",
    inventory.disagreement()
  );
  assert!(
    inventory.delivered_at(&deep),
    "the deep create was delivered at {} rather than only covered ({} rescans discharged)",
    deep.display(),
    inventory.rescans()
  );
}

/// Suite 2: native cookie pairing — a same-directory rename surfaces as one
/// `Moved` (kernel cookies pair inside the Monitor's window; no settle logic
/// exists driver-side).
#[tokio::test]
async fn rename_pairs_into_moved() {
  let root = scratch_root("rename");
  std::fs::write(root.join("old.txt"), b"x").unwrap();
  // This cell pins PAIRING correctness, not window tightness: when the two
  // rename halves split across reader batches, a sanitizer-slowed host can
  // stretch the gap past the default move window, and the halves then
  // LEGALLY degrade to Removed + Created — a different contract than the
  // one under test. A generous window keeps the cell about the pairing.
  let mut w =
    TokioWatcher::new(WatcherOptions::new().with_move_window(scaled(Duration::from_secs(10))))
      .expect("build watcher");
  let _h = w.watch(&root, Interest::all()).await.expect("watch");

  std::fs::rename(root.join("old.txt"), root.join("new.txt")).unwrap();

  let from = root.join("old.txt");
  let to = root.join("new.txt");
  let moved = wait_for(&mut w, |e| {
    e.kind().moved().is_some_and(|m| m.from() == from) && e.path() == to
  })
  .await;
  assert!(moved.is_some(), "the same-dir rename pairs into one Moved");

  // Cross-directory pairing needs BOTH directories armed at rename time: the
  // kernel reports each half on its own watched parent, so an unarmed
  // destination never attributes the `MovedTo` half to `sub` at all and the
  // halves legally degrade to Removed + the enumerate's Created — the other
  // contract, not this one. That makes the destination's OWN kernel watch a
  // PREREQUISITE of the assertion below rather than a detail, and only the
  // exact, non-`Rescan` event of a probe under `sub` can establish it: a
  // covering `Rescan` at `root` is what the Monitor emits when it could NOT arm
  // `sub`, so a staging step that accepted one would admit precisely the state
  // that makes the cell measure the degradation instead. See
  // [`child_watch_delivers`].
  std::fs::create_dir(root.join("sub")).unwrap();
  assert!(
    child_watch_delivers(&mut w, &root.join("sub"), "arm").await,
    "the destination directory's own kernel watch must be proven to DELIVER before the \
     cross-directory rename runs: unarmed, the kernel reports no MovedTo half under `sub`, the \
     pair degrades to Removed plus the enumerate's Created, and the pairing assertion below would \
     be measuring that degradation rather than the pairing it exists to pin"
  );

  std::fs::rename(root.join("new.txt"), root.join("sub/into.txt")).unwrap();
  let to2 = root.join("sub/into.txt");
  assert!(
    wait_for(&mut w, |e| e.kind().moved().is_some() && e.path() == to2)
      .await
      .is_some(),
    "the cross-dir rename pairs into one Moved"
  );
}

/// Suite 3: `IN_IGNORED` teardown — a kernel-removed watched directory
/// resolves (`Removed` covered) and its siblings keep flowing.
#[tokio::test]
async fn kernel_teardown_resolves_and_siblings_flow() {
  let root = scratch_root("ignored");
  std::fs::create_dir(root.join("gone")).unwrap();
  std::fs::create_dir(root.join("stays")).unwrap();
  let mut w = watcher();
  let _h = w.watch(&root, Interest::all()).await.expect("watch");

  std::fs::remove_dir(root.join("gone")).unwrap();
  let gone = root.join("gone");
  assert!(
    wait_for(&mut w, |e| covers(e, &gone)).await.is_some(),
    "the removed watched directory is observed"
  );

  std::fs::write(root.join("stays/alive.txt"), b"y").unwrap();
  let alive = root.join("stays/alive.txt");
  assert!(
    wait_for(&mut w, |e| covers(e, &alive)).await.is_some(),
    "siblings keep delivering after a kernel-side teardown"
  );
}

/// Suite 3b: self-induced teardown — after `unwatch` acknowledges, churn
/// produces nothing (bounded quiet-window assertion).
#[tokio::test]
async fn unwatch_quiesces() {
  let root = scratch_root("unwatch");
  let mut w = watcher();
  let h = w.watch(&root, Interest::all()).await.expect("watch");
  w.unwatch(h).await.expect("unwatch");

  std::fs::write(root.join("after.txt"), b"z").unwrap();
  // The quiet window is SCALED like every other budget here: this is a
  // proof-of-absence, and an instrumentation-slowed runtime shrinks an unscaled
  // window's real observation to a fraction of it — a leak that arrives late then
  // certifies quiescence it never had.
  let got = tokio::time::timeout(scaled(Duration::from_secs(2)), w.next()).await;
  assert!(
    !matches!(got, Ok(Some(_))),
    "no event may arrive after unwatch acknowledged"
  );
}

/// Suite 4: the wd follows the inode — a watched directory renamed within the
/// root keeps its coverage (the Monitor's O(1) reparent, end to end against
/// the real kernel).
#[tokio::test]
async fn moved_directory_keeps_coverage() {
  let root = scratch_root("reparent");
  std::fs::create_dir(root.join("before")).unwrap();
  let mut w = watcher();
  let _h = w.watch(&root, Interest::all()).await.expect("watch");

  std::fs::rename(root.join("before"), root.join("after")).unwrap();
  std::fs::write(root.join("after/inside.txt"), b"i").unwrap();

  let inside = root.join("after/inside.txt");
  assert!(
    wait_for(&mut w, |e| covers(e, &inside)).await.is_some(),
    "a file created under the moved directory is observed at its new path"
  );
}

/// Suite 5 (privileged): deterministic queue overflow — a 16-slot kernel
/// queue plus a rename storm forces `IN_Q_OVERFLOW`, which must surface as an
/// epoch-bumped `Rescan`, never silence.
#[tokio::test]
async fn queue_overflow_surfaces_as_rescan() {
  if !privileged_or_skip("queue_overflow_surfaces_as_rescan") {
    return;
  }
  let queue = SysctlGuard::swap("fs/inotify/max_queued_events", "16").expect("shrink queue");
  let root = scratch_root("overflow");
  let mut w = watcher();
  let _h = w.watch(&root, Interest::all()).await.expect("watch");

  let mut observed = false;
  'bursts: for burst in 0..3 {
    for i in 0..400 {
      let a = root.join(format!("f-{burst}-{i}-a"));
      let b = root.join(format!("f-{burst}-{i}-b"));
      std::fs::write(&a, b"x").unwrap();
      std::fs::rename(&a, &b).unwrap();
      std::fs::remove_file(&b).unwrap();
    }
    if wait_for(&mut w, |e| e.is_rescan()).await.is_some() {
      observed = true;
      break 'bursts;
    }
  }
  queue.close();
  assert!(observed, "a forced kernel overflow surfaces as a Rescan");
}

/// Holds the user's ENTIRE inotify watch budget, so the next
/// `inotify_add_watch` this user makes — the watcher's own ROOT add — is
/// refused with `ENOSPC`.
///
/// Adds watches on `dirs` to a private inotify fd until the kernel refuses one.
/// That refusal doubles as the enforcement PROOF the exhaustion cell needs: some
/// containerized kernels accept the `max_user_watches` write — it even reads back
/// as the new value — yet never charge watches against it, and there the
/// exhaustion path can never fire at all. Placing strictly more than `limit`
/// watches without a refusal proves exactly that.
///
/// The budget stays consumed until the hog is DROPPED (closing the fd releases
/// every watch it charged). That is the whole point: a probe that releases its
/// watches immediately leaves the watch under test facing a clean budget, so the
/// root's own arm could never be starved deterministically — only the descent
/// below it.
struct WatchBudgetHog {
  fd: libc::c_int,
  /// How many watches this hog itself holds.
  held: usize,
  /// Whether the kernel actually refused an add with `ENOSPC` — i.e. the budget
  /// is provably full AND this kernel charges against the shrunk limit.
  exhausted: bool,
}

impl WatchBudgetHog {
  /// Takes the budget, retrying until the hog HOLDS it rather than merely
  /// finding it full, so the ceiling the next add meets cannot evaporate under
  /// the leg that needs it.
  ///
  /// Releasing an instance's watches is DEFERRED kernel work (the marks are
  /// destroyed on a workqueue, past an RCU grace period), so at cell entry the
  /// budget may still be charged with an earlier cell's already-closed watches:
  /// a first pass then sees the `ENOSPC` while holding almost nothing, and the
  /// ceiling it proved would lift again milliseconds later. A pass that ends
  /// holding `limit` watches owns the whole budget outright; a pass that placed
  /// MORE than `limit` proves the kernel does not charge against the shrink at
  /// all, which no retry can change.
  ///
  /// Owning it is not always possible: `max_user_watches` is charged per USER
  /// across the whole kernel, so in a container sharing its root user with the
  /// VM's own daemons the shrink puts the user over the ceiling before this hog
  /// places anything. Finding the budget full is then permanent rather than
  /// racy — which starves the root arm just as well — so the hog reports what it
  /// holds and the cell keeps its own counsel about why.
  async fn take(dirs: &[PathBuf], limit: usize) -> Self {
    let mut hog = Self::fill_once(dirs, limit);
    for _ in 0..BUDGET_SETTLE_PASSES {
      if !hog.exhausted || hog.held >= limit {
        return hog;
      }
      drop(hog);
      tokio::time::sleep(scaled(BUDGET_SETTLE_PAUSE)).await;
      hog = Self::fill_once(dirs, limit);
    }
    hog
  }

  fn fill_once(dirs: &[PathBuf], limit: usize) -> Self {
    use std::os::unix::ffi::OsStrExt;
    let mut hog = Self {
      fd: unsafe { libc::inotify_init1(libc::IN_CLOEXEC) },
      held: 0,
      exhausted: false,
    };
    if hog.fd < 0 {
      return hog;
    }
    for dir in dirs {
      let Ok(cpath) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
        continue;
      };
      let wd = unsafe { libc::inotify_add_watch(hog.fd, cpath.as_ptr(), libc::IN_ATTRIB) };
      if wd < 0 {
        // A freshly-created dir yields only the watch-limit `ENOSPC` here — which is
        // exactly the enforcement being probed for.
        hog.exhausted = std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOSPC);
        break;
      }
      hog.held += 1;
      if hog.held > limit {
        break;
      }
    }
    hog
  }
}

impl Drop for WatchBudgetHog {
  fn drop(&mut self) {
    if self.fd >= 0 {
      unsafe {
        libc::close(self.fd);
      }
      self.fd = -1;
    }
  }
}

/// How many passes the watch budget gets to settle, and the pause between them.
/// A release is deferred kernel work, so both directions — the budget filling up
/// and giving way again — need converging on rather than assuming. Milliseconds
/// is the real scale (the reaper runs off a jiffy-delayed work item), so the
/// budget is deliberately short: where the settle CANNOT happen — the shrunk
/// ceiling is VM-wide, and a container whose root user already holds more
/// watches elsewhere is over it the moment the knob moves — every pass is spent
/// for nothing, and the cell says so and judges the ceiling where it lands.
const BUDGET_SETTLE_PASSES: usize = 12;
const BUDGET_SETTLE_PAUSE: Duration = Duration::from_millis(25);

/// Waits until the user's watch budget can charge an add again, so a leg that
/// needs the root's arm to SUCCEED does not race the deferred release of the
/// watches it just gave back (see [`WatchBudgetHog::take`]). `false` = the
/// budget never freed within the wait; the caller stays honest either way,
/// because a starved root arm is judged as the ceiling it is.
///
/// The proving add is itself released immediately, so it costs the following leg
/// at most one draining slot out of the budget — which the descent below the
/// root runs out of regardless.
async fn watch_budget_frees(dir: &Path) -> bool {
  use std::os::unix::ffi::OsStrExt;
  let Ok(cpath) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
    return false;
  };
  for _ in 0..BUDGET_SETTLE_PASSES {
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    if fd < 0 {
      return false;
    }
    let wd = unsafe { libc::inotify_add_watch(fd, cpath.as_ptr(), libc::IN_ATTRIB) };
    unsafe {
      libc::close(fd);
    }
    if wd >= 0 {
      return true;
    }
    tokio::time::sleep(scaled(BUDGET_SETTLE_PAUSE)).await;
  }
  false
}

/// Whether `err` is the watch ceiling landing on the ROOT's OWN arm — the only
/// registration error [`watch_limit_exhaustion_is_honest`] may read as the
/// honest exhaustion ending.
///
/// Exhaustion has ONE reply shape: [`WatchRootError::Source`] carrying a
/// [`SourceError::RootUnavailable`] whose io cause is
/// [`std::io::ErrorKind::StorageFull`] — the flavor the driver lowers the root
/// arm's `ENOSPC` through, on this deferred-grant path exactly as on the
/// `replace_root`/widen pre-arm replies. Nothing else qualifies: `NotFound`,
/// `NotADirectory`, `Overlaps` and `Closed` describe the cell's own fixture
/// coming apart, every other `SourceError` names a different backend failure,
/// and a `RootUnavailable` whose cause is `ENOENT` or `EACCES` is a vanished or
/// unreadable root rather than a full watch budget. Accepting any of those is
/// how a broken fixture reads as the very ending this cell exists to prove —
/// [`unrelated_source_errors`] is the standing proof it does not.
fn is_watch_ceiling(err: &WatchRootError) -> bool {
  match err {
    WatchRootError::Source(SourceError::RootUnavailable { source, .. }) => {
      source.kind() == std::io::ErrorKind::StorageFull
    }
    _ => false,
  }
}

/// Every `SourceError` [`is_watch_ceiling`] must REFUSE: the whole public
/// backend vocabulary except the exhaustion shape itself, including the near
/// miss — the right variant naming the wrong cause (`EACCES`). Constructed
/// rather than described, because "only the ceiling greens this cell" is a
/// claim about these values and nothing weaker: the arm it guards accepted any
/// `Source` at all, so every one of them used to pass for exhaustion.
fn unrelated_source_errors() -> Vec<SourceError> {
  let elsewhere = PathBuf::from("/tributary-fs-no-such-root");
  vec![
    SourceError::Unsupported,
    SourceError::NoRoots,
    SourceError::NotADirectory {
      root: elsewhere.clone(),
    },
    SourceError::RootReplaced {
      root: elsewhere.clone(),
    },
    SourceError::TooManyExclusions { supplied: 4096 },
    SourceError::ExclusionRejected,
    SourceError::CreateFailed,
    SourceError::InstanceLimit,
    SourceError::ReadFailed {
      source: std::io::Error::from_raw_os_error(libc::EIO),
    },
    SourceError::StartFailed,
    SourceError::CallbackPanic,
    SourceError::BackendProbeFailed {
      stage: ProbeStage::Mark,
    },
    SourceError::ForeignBackend {
      requested: Backend::Rdcw,
    },
    // The near miss: the exhaustion VARIANT, a different cause.
    SourceError::RootUnavailable {
      root: elsewhere,
      source: std::io::Error::from_raw_os_error(libc::EACCES),
    },
  ]
}

/// Suite 6 (privileged): watch-limit exhaustion is honest on BOTH sides of the
/// root's arm. `ENOSPC` mid-descent lands on the Monitor's `NoSpace` path —
/// honest `Rescan`, no silence, no panic, and the watcher survives — while
/// `ENOSPC` on the ROOT'S OWN arm is a registration error that names the
/// ceiling exactly: `RootUnavailable` with a `StorageFull` cause, not an
/// untyped `Other` whose only residue is a substring.
#[tokio::test]
async fn watch_limit_exhaustion_is_honest() {
  // The ceiling predicate, guarded from both sides BEFORE the privilege gate so
  // it holds in the default-caps suite too (where the kernel legs themselves
  // skip): every unrelated backend failure is refused, and the exhaustion shape
  // itself is accepted — a predicate that refused everything would make the
  // refusals vacuous and the leg below unfailable.
  for source in unrelated_source_errors() {
    let unrelated = WatchRootError::Source(source);
    assert!(
      !is_watch_ceiling(&unrelated),
      "an unrelated backend failure must not read as watch exhaustion: {unrelated:?}"
    );
  }
  assert!(
    is_watch_ceiling(&WatchRootError::Source(SourceError::RootUnavailable {
      root: PathBuf::from("/tributary-fs-no-such-root"),
      source: std::io::Error::from_raw_os_error(libc::ENOSPC),
    })),
    "the exhaustion shape itself greens the predicate, or the refusals above prove nothing"
  );

  if !privileged_or_skip("watch_limit_exhaustion_is_honest") {
    return;
  }
  let root = scratch_root("nospace");
  let mut dirs = Vec::new();
  for i in 0..12 {
    let dir = root.join(format!("d{i}"));
    std::fs::create_dir(&dir).unwrap();
    dirs.push(dir);
  }
  let watches = SysctlGuard::swap("fs/inotify/max_user_watches", "8").expect("shrink watches");
  // The exhaustion path is inotify-specific: `max_user_watches` does not bound the
  // kernel-recursive fanotify backend that `Backend::Auto` selects under privilege,
  // so both legs pin inotify.
  //
  // LEG 1 — the ceiling on the ROOT'S OWN arm. The budget stays full across the
  // `watch()` call, so the descending spawn's FIRST add (the root's) takes the
  // `ENOSPC`: the deferred grant is answered with a registration error instead of
  // a stream, and that error must name the ceiling exactly. The hog's own refusal
  // to add is also the enforcement probe — a kernel that does not charge against
  // the shrink soft-skips rather than failing on an exhaustion that could not
  // happen.
  let hog = WatchBudgetHog::take(&dirs, 8).await;
  let enforced = hog.exhausted;
  let starved = {
    let w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Inotify))
      .expect("build inotify watcher");
    let watched = w.watch(&root, Interest::all()).await;
    let verdict = watched
      .as_ref()
      .err()
      .map(|err| (is_watch_ceiling(err), format!("{err} / {err:?}")));
    // The starved watcher owns a live-but-uncovering stream on the error path;
    // close it so leg 2 meets no stray instance.
    let _ = tokio::time::timeout(scaled(DEADLINE), w.close()).await;
    verdict
  };
  // Releases every watch the hog charged — deferred kernel work, so leg 2 waits
  // for the budget to actually give way instead of racing it.
  drop(hog);
  if !watch_budget_frees(&dirs[0]).await {
    eprintln!(
      "NOTE watch_limit_exhaustion_is_honest: the watch budget never gave way after the hog was \
       released; leg 2 judges the ceiling wherever it lands"
    );
  }

  // LEG 2 — the ceiling mid-descent: root + 12 subdirectories against a budget of
  // 8, so the root arms and the descent runs out of watches below it.
  let mut w = TokioWatcher::new(WatcherOptions::new().with_backend(Backend::Inotify))
    .expect("build inotify watcher");
  let watched = w.watch(&root, Interest::all()).await;
  let honest = match &watched {
    // The descent hit the ceiling after the root armed: coverage loss must
    // surface as a Rescan.
    Ok(_) => wait_for(&mut w, |e| e.is_rescan()).await.is_some(),
    // Or the ceiling hit the root arm ITSELF even here: honest only as the
    // ceiling's own registration error, judged by the same exact predicate.
    Err(err) => is_watch_ceiling(err),
  };
  watches.close();

  // Leg 1's verdict, once the knob is restored (a leaked shrink would contaminate
  // every later cell in this binary). A starved arm that answered ANY error must
  // have named the ceiling; one that answered a stream never reached the path, and
  // says so loudly rather than passing quietly.
  match &starved {
    Some((exact, text)) => assert!(
      *exact,
      "the root arm starved by a full watch budget must name the ceiling exactly — \
       RootUnavailable with a StorageFull cause, the same flavor the replace_root/widen \
       pre-arm replies carry — not an untyped error whose cause survives only as a \
       substring: {text}"
    ),
    None => eprintln!(
      "NOTE watch_limit_exhaustion_is_honest: the root arm succeeded against a full watch \
       budget (enforced={enforced}); leg 1 (root-arm ceiling) not exercised"
    ),
  }

  // Only an enforcing kernel exercises the exhaustion path. The single soft-skip
  // shape is a kernel that does not enforce the shrink AND a watch that SUCCEEDED
  // with no Rescan — exhaustion never triggered. A watch that FAILED is never
  // that shape: it either hit the ceiling (honest, asserted below) or it names a
  // different failure this cell must not absorb. Whenever exhaustion WAS
  // triggered the honesty assertion stands unweakened: a silent NoSpace fails.
  if !enforced && watched.is_ok() && !honest {
    common::skip_notice(format_args!(
      "watch_limit_exhaustion_is_honest: this kernel does not enforce the \
       max_user_watches shrink; exhaustion never triggered"
    ));
    return;
  }
  assert!(
    honest,
    "watch exhaustion surfaces as a Rescan or the root arm's own ceiling error — never silence, \
     and never an unrelated failure: {watched:?}"
  );
}

/// Suite 7 (privileged): a bind mount inside the root is a MOUNT BOUNDARY, not an
/// alias to descend. `root/b` bound from `root/a` sits on a different mount id, so
/// the enumerate lowering marks it non-descendable — the Monitor never arms a watch
/// under it, and a write reached through the bind spelling (`root/b/...`) surfaces
/// only under the ORIGINAL (`root/a/...`), never a second time under `b`.
///
/// On Linux a directory has exactly one inode-sharing spelling per bind (hardlinked
/// directories do not exist), so a directory bind is the only alias the EEXIST
/// fan-out ever handled — and the mount-id fence now makes that case a uniform
/// boundary on both backends (design-consistent), the intended change. The EEXIST
/// alias machinery remains the belt for any NON-mount aliasing.
#[tokio::test]
async fn bind_mount_inside_root_is_a_boundary() {
  if !privileged_or_skip("bind_mount_inside_root_is_a_boundary") {
    return;
  }
  let root = scratch_root("bind-boundary");
  std::fs::create_dir(root.join("a")).unwrap();
  std::fs::create_dir(root.join("b")).unwrap();
  let status = std::process::Command::new("mount")
    .arg("--bind")
    .arg(root.join("a"))
    .arg(root.join("b"))
    .status()
    .expect("run mount");
  if !status.success() {
    common::skip_notice(format_args!(
      "bind_mount_inside_root_is_a_boundary: bind mount refused"
    ));
    return;
  }

  let mut w = watcher();
  let _h = w.watch(&root, Interest::all()).await.expect("watch");
  // A write reached through the BIND spelling `root/b/shared.txt` lands on the same
  // object as `root/a/shared.txt` (b is bound from a). The original `a` is watched
  // (same mount as root); the bind `b` is a boundary and is not.
  let via_a = root.join("a/shared.txt");
  let via_b = root.join("b/shared.txt");
  std::fs::write(&via_b, b"s").unwrap();

  // The original spelling is observed — `a` is in-root and descended.
  let saw_a = wait_for(&mut w, |e| covers(e, &via_a)).await.is_some();
  // The bind spelling must NOT surface: `b` was fenced as a mount boundary and
  // never armed, so no watch reports a `b/...` path. A bounded quiet window proves
  // its absence — SCALED, because an unscaled window on an instrumentation-slowed
  // runtime observes proportionally less and would certify an absence it never saw.
  let leaked_b = tokio::time::timeout(scaled(Duration::from_secs(3)), async {
    while let Some(event) = w.next().await {
      if event.path().starts_with(root.join("b")) {
        return true;
      }
    }
    false
  })
  .await
  .unwrap_or(false);
  let _ = std::process::Command::new("umount")
    .arg("-l")
    .arg(root.join("b"))
    .status();
  assert!(
    saw_a,
    "the write to the bound object is observed under the original in-root spelling"
  );
  assert!(
    !leaked_b,
    "the bind point is a mount boundary — no event surfaces under its spelling"
  );
}

/// §7's documented limitation, pinned end to end: a non-UTF-8 name cannot
/// become a `Segment`, so it escalates to a covering located `Rescan` —
/// coverage-honest, never a panic, never silence.
#[tokio::test]
async fn non_utf8_name_escalates_to_rescan() {
  use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
  let root = scratch_root("nonutf8");
  let mut w = watcher();
  let _h = w.watch(&root, Interest::all()).await.expect("watch");

  let weird = root.join(OsStr::from_bytes(&[0xFF, 0xFE, b'x']));
  std::fs::write(&weird, b"?").unwrap();

  // The covering Rescan lands at the parent directory (or an ancestor, up to
  // the root itself) — anywhere that obliges re-reading the affected region.
  assert!(
    wait_for(&mut w, |e| e.is_rescan()
      && (e.path().starts_with(&root) || root.starts_with(e.path())))
    .await
    .is_some(),
    "an undeliverable name surfaces as a covering Rescan"
  );
}

/// A DEGRADED cover window settles behind the same ordering proof a clean one
/// does — a real round trip through the real reader — and the sync parked on
/// that window still writes and delivers.
///
/// A degraded verdict is a LIVE verdict: it answers its caller and dispatches
/// the fence's parked cookie exactly as a clean one does. So it rests on the
/// same proof, one empty control batch whose reply proves the reader cut its
/// kernel queue onto the lane before answering. Exempting the window from it —
/// on the true but incomplete ground that more loss cannot falsify a degraded
/// verdict — is what let an unread root DEATH slip past the verdict; requiring
/// the proof without also OFFERING it would park every degraded window forever,
/// which is what the bounded await below would report.
///
/// The staging is publicly witnessed, not assumed. The grow re-enumerates a
/// directory holding a non-UTF-8 name, which cannot become a `Segment` and
/// escalates to a covering `Rescan` generated BY the very cascade the fence is
/// open over — so `Degraded` in the outcome is proof this round really was a
/// lossy window, and its arrival within the deadline is proof the round trip
/// completed. An `Applied` would mean the escalation landed outside the window
/// and the round sampled the clean path instead, which the assertion says
/// rather than passing quietly.
///
/// # What this does not cover
///
/// Not the race the proof exists to catch: a root renamed away and its pathname
/// recreated while `IN_MOVE_SELF` is still unread in the kernel queue, with an
/// off-reader enumerate completion settling coverage at that instant. Staging it
/// needs the reader held off the fd while the driver keeps running, and the only
/// lever this rig has — `SIGSTOP` on the process group — stops both. That leg is
/// pinned sans-I/O by
/// `an_unread_root_death_under_a_lossy_fence_is_caught_by_the_cut_it_owes`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_degraded_cover_settles_behind_its_ordering_proof() {
  use std::os::unix::ffi::OsStrExt;

  let root = scratch_root("degraded-cut");
  let keep = root.join("keep");
  let dropped = root.join("dropped");
  std::fs::create_dir_all(&keep).expect("create keep");
  std::fs::create_dir_all(&dropped).expect("create dropped");
  let mut w = inotify_watcher();
  let handle = w.watch(&root, Interest::all()).await.expect("watch");
  assert!(
    coverage_becomes_live(&mut w, &dropped, "birth").await,
    "the birth crawl settles"
  );

  // Narrow first, so the grow below has a real broadening delta to re-arm — a
  // cover that grows nothing would quiesce with no read to escalate.
  let narrowed = tokio::time::timeout(scaled(DEADLINE), w.set_cover(handle, vec![keep.clone()]))
    .await
    .expect("the narrowing cover settles within the deadline")
    .expect("the narrowing cover is accepted");
  assert!(
    matches!(narrowed, CoverOutcome::Applied | CoverOutcome::Degraded),
    "the narrowing cover reconciles: {narrowed:?}"
  );

  // The undeliverable name the grow's re-enumeration must find.
  std::fs::write(dropped.join(OsStr::from_bytes(&[0xFF, 0xFE, b'x'])), b"?")
    .expect("place the undeliverable name");

  // The grow and a sync admitted onto the SAME window: two fences on one entry,
  // one ordering proof between them, and both owed an answer.
  let (admission, _ticket) = w.mint_sync_ticket();
  let (grown, cookie) = tokio::time::timeout(scaled(DEADLINE), async {
    tokio::join!(
      w.set_cover(handle, vec![keep.clone(), dropped.clone()]),
      w.sync_root(
        handle,
        root.clone(),
        ".tributaries-sync-degraded",
        admission
      )
    )
  })
  .await
  .expect(
    "the degraded window settles within the deadline — a window that owes an ordering proof and \
     is never offered one waits for it forever",
  );

  assert_eq!(
    grown.expect("the grow is accepted"),
    CoverOutcome::Degraded,
    "the escalation inside the window degrades the verdict, which is what makes this round a \
     sample of the degraded path rather than of the clean one"
  );
  let cookie = cookie.expect("the sync parked on the degraded window still writes its cookie");
  assert!(
    wait_for(&mut w, |e| e.path() == cookie).await.is_some(),
    "the cookie the degraded settle dispatched is reported on the live stream"
  );

  w.unwatch(handle).await.expect("unwatch");
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// Reader-teardown fairness under sustained traffic (the container companion to
/// the hermetic mid-drain unit test). A producer churns files continuously so the
/// inotify fd stays readable, then the watcher is CLOSED under that load.
/// `close()` must fully quiesce (`Ok(())`): the reader observes the shutdown
/// between reads rather than after an `EAGAIN` the sustained stream never yields.
/// Without the interleaved control check the teardown `join` would wedge past the
/// close grace and surface as `NotQuiesced`.
#[tokio::test]
async fn close_quiesces_under_sustained_traffic() {
  let root = scratch_root("close-load");
  let mut w = watcher();
  let _h = w.watch(&root, Interest::all()).await.expect("watch");

  let stop = Arc::new(AtomicBool::new(false));
  let producer = {
    let root = root.clone();
    let stop = Arc::clone(&stop);
    std::thread::spawn(move || {
      let mut i = 0u64;
      while !stop.load(Ordering::Relaxed) {
        let p = root.join(format!("churn-{}", i % 64));
        let _ = std::fs::write(&p, b"x");
        let _ = std::fs::remove_file(&p);
        i = i.wrapping_add(1);
      }
    })
  };

  // Confirm the stream is actually flowing (the reader is under load) before
  // tearing down, so the close races a live drain rather than an idle one.
  assert!(
    wait_for(&mut w, |e| e.path().starts_with(&root))
      .await
      .is_some(),
    "events flow under the producer before close"
  );

  let closed = tokio::time::timeout(scaled(DEADLINE), w.close()).await;
  stop.store(true, Ordering::Relaxed);
  producer.join().expect("producer joins");
  assert!(
    matches!(closed, Ok(Ok(()))),
    "close must fully quiesce under sustained traffic — the reader observes shutdown mid-drain, \
     not after an EAGAIN that never comes: {closed:?}"
  );
}

/// Widening `x/y` → `x` on the descending backend is CONTINUOUS (the
/// same-transport commit): the live stream is kept and the old subtree keeps
/// delivering at its unchanged absolute paths, while the newly covered ground
/// goes live via cold discovery. The STRICT no-Rescan / no-epoch-bump contract
/// is pinned deterministically by the hermetic cell
/// `a_widening_replace_keeps_the_stream_and_dominates_nothing`; here — on a real
/// kernel — an honest root-`[]` `Rescan` (a dirty cold-read escalation on the
/// freshly-covered ground) is TOLERATED as a covering delivery, but a misaddress
/// or a lost write is not. Narrowing back is the stream-replace (Rescan-bridged)
/// path, and repeated swap cycles neither leak watch descriptors into refusals
/// nor strand coverage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replace_root_widens_and_rebinds() {
  let root = scratch_root("replace-widen");
  let sub = root.join("y");
  std::fs::create_dir_all(sub.join("deep")).expect("create tree");
  let mut w = inotify_watcher();
  let handle = w.watch(&sub, Interest::all()).await.expect("watch");
  // Settle the birth crawl before the swap so the widen's own window is the
  // only thing under test.
  assert!(
    coverage_becomes_live(&mut w, &sub.join("deep"), "birth").await,
    "the birth crawl reaches the deep old ground"
  );

  w.replace_root(handle, &root)
    .await
    .expect("the swap commits");
  assert_eq!(w.root_path(handle), Some(root.clone()));

  // Zero-gap continuity (the point of D2): a write under the OLD subtree lands
  // at its EXACT unchanged absolute path on the SAME stream after the widen.
  // The strict no-Rescan / no-epoch-bump contract is pinned deterministically by
  // the hermetic cell `a_widening_replace_keeps_the_stream_and_dominates_nothing`;
  // a real kernel under a signal storm may additionally escalate a dirty
  // cold-read of the fresh ground into an honest root-`[]` `Rescan` (which covers
  // `post` by ancestry) — tolerated via `covers`. A MISADDRESSED delivery or a
  // LOST write covers `post` by neither and fails the deadline below.
  let post = sub.join("post-widen.txt");
  std::fs::write(&post, b"post").expect("write post");
  let delivered = tokio::time::timeout(scaled(DEADLINE), async {
    while let Some(event) = w.next().await {
      if covers(&event, &post) {
        return true;
      }
    }
    false
  })
  .await
  .unwrap_or(false);
  assert!(
    delivered,
    "the old subtree delivers across the widen — at its exact path, or via an honest covering Rescan"
  );

  // The deep old ground stayed live, and the newly covered ground is armed
  // by the cold crawl.
  assert!(
    coverage_becomes_live(&mut w, &sub.join("deep"), "old-ground").await,
    "the old subtree's interior coverage rode across the widen"
  );
  assert!(
    coverage_becomes_live(&mut w, &root, "outside").await,
    "newly covered ground is live"
  );

  // Narrowing back is the stream-replace path — Rescan-bridged.
  w.replace_root(handle, &sub).await.expect("narrow commits");
  let covering = wait_for(&mut w, |e| e.is_rescan() && e.path() == sub).await;
  assert!(
    covering.is_some(),
    "a narrowing replace bridges with a Rescan"
  );

  // Swap cycles: watch bookkeeping survives — a leak of descriptors (or a
  // stranded adoption) would surface as arm refusals or dead coverage here.
  for _ in 0..3 {
    w.replace_root(handle, &root).await.expect("widen commits");
    w.replace_root(handle, &sub).await.expect("narrow commits");
  }
  w.replace_root(handle, &root).await.expect("final widen");
  assert!(
    coverage_becomes_live(&mut w, &root, "after-cycles").await,
    "coverage is live after swap cycles"
  );

  match w.watch(&sub, Interest::all()).await {
    Err(tributary_fs::WatchRootError::Overlaps { existing, .. }) => assert_eq!(existing, root),
    other => panic!("the widened coverage must contain the old root: {other:?}"),
  }
  w.unwatch(handle).await.expect("unwatch");
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// The barrier-honesty headline (INV-ROOT): a change under the old subtree made
/// BEFORE a widening replace is either individually DELIVERED at its exact path
/// or DOMINATED by an honest `Rescan`, and a `sync_root` cookie written after the
/// widen resolves the barrier strictly behind it on the one surviving kernel
/// queue. The barrier NEVER certifies `Delivered` over a change it neither
/// delivered nor dominated. The strict no-Rescan continuity is pinned by the
/// hermetic cell; a signal-storm kernel's honest dirty-read `Rescan` is the
/// domination signal, tolerated here — never a false Delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sync_barrier_across_a_widen_resolves_by_delivery() {
  let root = scratch_root("widen-sync");
  let sub = root.join("y");
  std::fs::create_dir_all(&sub).expect("create tree");
  let mut w = inotify_watcher();
  let handle = w.watch(&sub, Interest::all()).await.expect("watch");
  assert!(
    coverage_becomes_live(&mut w, &sub, "birth").await,
    "the birth crawl settles"
  );

  // The pre-widen change: written, recorded by the live stream, NOT consumed.
  let pre = sub.join("before-the-widen.txt");
  std::fs::write(&pre, b"x").expect("write pre");

  w.replace_root(handle, &root)
    .await
    .expect("the widen commits");
  assert_eq!(w.root_path(handle), Some(root.clone()));

  // The barrier: the cookie's create rides the SAME queue behind the pre-widen
  // change, so the cookie resolves the barrier. INV-ROOT — the barrier must
  // NEVER certify `Delivered` over a change it did not deliver — holds two ways:
  // the pre-widen change is DELIVERED at its exact path before the cookie, OR an
  // honest root-`[]` `Rescan` DOMINATES it (covers `pre` by ancestry), re-obliging
  // its re-enumeration. A signal-storm kernel can emit that dominating Rescan; it
  // is tolerated because it IS the domination signal, not a false Delivered. The
  // one dishonest ending — the cookie reached with `pre` NEITHER delivered NOR
  // dominated — is a false Delivered and fails the assertion below.
  let (admission, _ticket) = w.mint_sync_ticket();
  let cookie = w
    .sync_root(handle, root.clone(), ".tributaries-sync-widen", admission)
    .await
    .expect("the cookie writes");
  let barrier_honest = tokio::time::timeout(scaled(DEADLINE), async {
    let mut saw_pre = false;
    let mut dominated = false;
    while let Some(event) = w.next().await {
      if event.is_rescan() && pre.starts_with(event.path()) {
        // An honest Rescan at the root (an ancestor of `pre`) dominates the
        // pre-widen change: the barrier resolves by domination, not delivery.
        dominated = true;
      }
      if event.path() == pre {
        saw_pre = true;
      }
      if event.path() == cookie {
        // The barrier resolves here. Honest iff `pre` was already delivered or
        // an honest Rescan dominated it; a bare cookie is a false Delivered.
        return saw_pre || dominated;
      }
    }
    false
  })
  .await
  .unwrap_or(false);
  assert!(
    barrier_honest,
    "the barrier resolves honestly — the pre-widen change is DELIVERED before the cookie, \
     or an honest Rescan dominates it; never a false Delivered over lost coverage"
  );

  // The freshly covered ground goes live via the widen's cold discovery.
  assert!(
    coverage_becomes_live(&mut w, &root, "fresh").await,
    "newly covered ground is live after the widen"
  );

  w.unwatch(handle).await.expect("unwatch");
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// The move-out barrier: a `sync_root` cookie must never overtake a rename half
/// the monitor is still holding.
///
/// A file renamed OUT of the watched root produces one cookie-bearing
/// `IN_MOVED_FROM` and no destination. The monitor consumes that record and
/// parks it for the pairing window — which of `Moved`, `Removed` or nothing it
/// becomes is unknown until a destination arrives or the window elapses — and an
/// ordinary FILE source detaches no subtree and arms no read, so the transition
/// exists only in monitor memory, seen by nothing else the barrier counts.
/// `sync_root` promises the opposite: its cookie's event rides the root's queue
/// BEHIND every change the backend reported before the write. A caller may
/// therefore finalize state on the cookie, and a `Removed` landing after it
/// describes a past the caller has already closed.
///
/// So the assertion is an ORDER, not a latency: of the two paths, the removal is
/// the one the stream must reach first.
///
/// # What this does not cover
///
/// It cannot force the interleaving. If the pipeline needs longer than the
/// pairing window to ingest the `IN_MOVED_FROM`, the half resolves before the
/// barrier is ever consulted and the round observes the right order for the
/// wrong reason — legal, and visible in the reported staging time, which on a
/// round that genuinely held the half cannot be shorter than the pairing window.
/// The gate itself is pinned deterministically, on the clock the monitor
/// actually reads, by `a_parked_rename_half_advances_the_coverage_work_epoch`.
///
/// It also says nothing about a rename whose destination is inside the root: that
/// half pairs into a `Moved` and is a different resolution path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sync_cookie_never_overtakes_a_parked_move_out() {
  let root = scratch_root("move-out-sync");
  // The destination is a separate scratch root, so the rename's other half lands
  // outside every watch: the source can never pair and must serve its whole
  // window.
  let away = scratch_root("move-out-away");
  let moved = root.join("moved.txt");
  std::fs::write(&moved, b"x").expect("stage the file to be moved out");

  let mut w = inotify_watcher();
  let handle = w.watch(&root, Interest::all()).await.expect("watch");
  // The root's OWN watch must be delivering first: a rename that predates it is
  // never reported, and the cell would then assert over an empty window.
  assert!(
    child_watch_delivers(&mut w, &root, "armed").await,
    "the root's own kernel watch delivers before the move-out is staged"
  );

  let staged_at = std::time::Instant::now();
  std::fs::rename(&moved, away.join("moved.txt")).expect("move the file out of the root");
  // The stream marker. It is created in the same directory right after the
  // rename, so the kernel queues its record behind the `IN_MOVED_FROM` on that
  // one watch — and the monitor ingests in that order. Everything the consumer
  // sees up to this event therefore predates the parked half and is noise for
  // this cell (the staged file's own birth, a crawl result racing the probes);
  // everything after it postdates the half's arrival, which is what makes a
  // later covering `Rescan` genuinely dominating rather than merely earlier.
  let marker = root.join("after-the-move.txt");
  std::fs::write(&marker, b"x").expect("write the stream marker");

  let (admission, _ticket) = w.mint_sync_ticket();
  let cookie = tokio::time::timeout(
    scaled(DEADLINE),
    w.sync_root(
      handle,
      root.clone(),
      ".tributaries-sync-move-out",
      admission,
    ),
  )
  .await
  .expect(
    "the sync resolves within the deadline — a barrier parked on a half whose window never \
     expires would wedge here",
  )
  .expect("the sync is admitted and writes its cookie");
  let staged_for = staged_at.elapsed();

  // ONE pass over the stream: whichever fact it reaches first IS the verdict, so
  // waiting for them in sequence would consume the evidence.
  let verdict = tokio::time::timeout(scaled(DEADLINE), async {
    let mut past_the_move = false;
    while let Some(event) = w.next().await {
      if !past_the_move {
        past_the_move = event.path() == marker;
        continue;
      }
      // The vacated slot's own resolution: the removal it owes, or the covering
      // `Rescan` a window that saw interleaved activity stands in its place.
      if event.path() == moved && (event.kind().is_removed() || event.is_rescan()) {
        return Some(true);
      }
      // A `Rescan` above the vacated slot re-obliges its re-enumeration, and
      // past the marker it provably postdates the parked half — so the barrier
      // resolved by domination rather than by delivery, which is honest.
      if event.is_rescan() && moved.starts_with(event.path()) {
        return Some(true);
      }
      if event.path() == cookie {
        return Some(false);
      }
    }
    None
  })
  .await
  .ok()
  .flatten();
  assert_eq!(
    verdict,
    Some(true),
    "the sync cookie overtook a rename half the monitor was still holding: the barrier \
     certified over a transition it had already consumed and not yet written, so the move-out \
     lands behind state the caller has finalized on the cookie (the cookie was written \
     {staged_for:?} after the move-out; `None` means the stream never reached the marker or \
     resolved neither way, so this round decided nothing)"
  );
  eprintln!(
    "NOTE: the move-out was staged for {staged_for:?} before the cookie was written — a round \
     shorter than the monitor's pairing window resolved the half before the barrier was ever \
     consulted, and did not sample the window"
  );

  w.request_remove_cookie(cookie);
  w.unwatch(handle).await.expect("unwatch");
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
  let _ = std::fs::remove_dir_all(&away);
}

/// A DEEP widen (`r/a/b/c` → `r`) adopts across a multi-segment chain: the old
/// subtree keeps delivering at its exact absolute paths, the connecting interior
/// and the fresh ground both go live, and the handle reports the new root. The
/// strict no-Rescan continuity is pinned hermetically
/// (`a_widening_replace_keeps_the_stream_and_dominates_nothing`); on a real
/// kernel an honest root-`[]` `Rescan` (a dirty cold-read escalation) is
/// tolerated as a covering delivery.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deep_widen_adopts_across_the_chain() {
  let root = scratch_root("deep-widen");
  let old = root.join("a").join("b").join("c");
  std::fs::create_dir_all(&old).expect("create tree");
  let mut w = inotify_watcher();
  let handle = w.watch(&old, Interest::all()).await.expect("watch");
  assert!(
    coverage_becomes_live(&mut w, &old, "birth").await,
    "the birth crawl settles"
  );

  w.replace_root(handle, &root)
    .await
    .expect("the deep widen commits");
  assert_eq!(w.root_path(handle), Some(root.clone()));

  // Zero-gap continuity across the multi-segment chain: the old subtree's write
  // lands at its EXACT unchanged absolute path on the same stream. The strict
  // no-Rescan contract is pinned hermetically (see
  // `a_widening_replace_keeps_the_stream_and_dominates_nothing`); a signal-storm
  // kernel may escalate a dirty cold-read of the fresh ground to an honest
  // root-`[]` `Rescan` covering `post` — tolerated via `covers`. A misaddressed
  // delivery or a lost write covers `post` by neither and fails the deadline.
  let post = old.join("across.txt");
  std::fs::write(&post, b"x").expect("write across");
  let delivered = tokio::time::timeout(scaled(DEADLINE), async {
    while let Some(event) = w.next().await {
      if covers(&event, &post) {
        return true;
      }
    }
    false
  })
  .await
  .unwrap_or(false);
  assert!(
    delivered,
    "the adopted subtree delivers across the deep widen — at its exact path, or via an honest covering Rescan"
  );

  // The connecting chain and the fresh ground both armed.
  assert!(
    coverage_becomes_live(&mut w, &root.join("a").join("b"), "chain").await,
    "the connecting interior is covered"
  );
  assert!(
    coverage_becomes_live(&mut w, &root, "fresh").await,
    "the fresh ground is covered"
  );

  w.unwatch(handle).await.expect("unwatch");
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&root);
}

/// A DISJOINT replace stays on the stream-replace path: the commit bridges
/// with its covering Rescan and the new ground goes live on the new stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_disjoint_replace_stays_rescan_bridged() {
  let a = scratch_root("disjoint-a");
  let b = scratch_root("disjoint-b");
  let mut w = watcher();
  let handle = w.watch(&a, Interest::all()).await.expect("watch");
  assert!(coverage_becomes_live(&mut w, &a, "birth").await);

  w.replace_root(handle, &b).await.expect("the swap commits");
  assert_eq!(w.root_path(handle), Some(b.clone()));
  let covering = wait_for(&mut w, |e| e.is_rescan() && e.path() == b).await;
  assert!(
    covering.is_some(),
    "a disjoint replace bridges with a Rescan"
  );
  assert!(coverage_becomes_live(&mut w, &b, "new-ground").await);

  w.unwatch(handle).await.expect("unwatch");
  w.close().await.expect("close");
  let _ = std::fs::remove_dir_all(&a);
  let _ = std::fs::remove_dir_all(&b);
}

/// Suite 8 (privileged, CI: `linux-verify.sh inotify-priv`) — the kernel W1 of
/// docs/2026-07-19-d2-golden-root-binding.md, end to end: an ext4 loopback is
/// unmounted and remounted on the SAME loop device (identity-preserving —
/// `(dev, ino)` of the root survive the cycle while every inotify watch on the
/// superblock is destroyed) RACING a widening `replace_root` onto it. However
/// the widen and the cycle interleave, the witnessed-window commit gate
/// (INV-ROOT) forbids the one dishonest ending — a certified-live widen whose
/// root binding died silently — so once the widen has COMMITTED, a post-cycle
/// write under the old subtree must ALWAYS become observable: delivered by live
/// coverage, or covered by a `Rescan` (domination / the death funnel / the
/// tainted-window fallback bridge). Silence within the deadline is the
/// false-certification class and fails.
///
/// A widen the cycle beat to its own target is refused rather than certified,
/// which is the honest ending and not a sample of this one; such a round says so
/// and takes no further part (see the refusal guard in the loop).
///
/// The race is swept across jittered offsets: each iteration is one
/// interleaving sample, and EVERY sample must end honest.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn widen_over_unmount_rebind_is_never_silently_certified() {
  use std::process::Command;

  if !privileged_or_skip("widen_over_unmount_rebind_is_never_silently_certified") {
    return;
  }

  // A private ext4 loopback pinned to an EXPLICIT loop device, so the remount
  // preserves `st_dev` (an auto-allocated `-o loop` remount could land on a
  // different loop minor and mint a different identity — the W2 shape, not W1's
  // same-identity rebind). Acquired through the shared fixture builder: it is
  // RAII from the first releasable resource onward, so every refusal along the
  // way — and every unwind out of the asserting rounds below — releases the
  // mount, the loop device and the backing image instead of leaking them into
  // the rest of the binary and the VM.
  let Some(fixture) = loop_image("widen-w1", 16) else {
    return;
  };
  let loopdev = fixture.loopdev().to_owned();
  let mount = fixture.mount().to_path_buf();

  const OFFSETS_MS: [u64; 3] = [0, 15, 45];
  // A round STAGES only once the cycle has handed back a filesystem the round
  // can assert over. Counting that is what keeps the closing assertion's claim
  // true: this cell's whole subject is an ending it must OBSERVE, so a run in
  // which no round ever reached one has proven nothing and must not be green.
  let mut staged = 0usize;

  for (round, delay_ms) in OFFSETS_MS.into_iter().enumerate() {
    // Fresh layout per round, persisted on the image across the cycle.
    let root = mount.join(format!("w1-{round}"));
    let sub = root.join("sub");
    std::fs::create_dir_all(&sub).expect("layout");
    let mut w = watcher();
    let handle = w.watch(&sub, Interest::all()).await.expect("watch sub");
    assert!(coverage_becomes_live(&mut w, &sub, "birth").await);

    // The race: the widen onto `root` vs the identity-preserving mount cycle.
    let widen = w.replace_root(handle, &root);
    let cycle = {
      let loopdev = loopdev.clone();
      let mount = mount.clone();
      tokio::task::spawn_blocking(move || {
        std::thread::sleep(Duration::from_millis(delay_ms));
        // A busy umount (the watcher's fds do not pin it; scratch cwd could)
        // retries briefly; failure to cycle skips the round's race (the widen
        // then just commits normally — a valid, if uninteresting, sample).
        for _ in 0..50 {
          if Command::new("umount")
            .arg(&mount)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
          {
            break;
          }
          std::thread::sleep(Duration::from_millis(20));
        }
        // Reported rather than discarded: whether the superblock came back is
        // what decides that the round has an ending to demand at all, and a
        // re-mount the environment refused is the harness failing to stage the
        // experiment, not the product failing to keep its promise.
        Command::new("mount")
          .arg(&loopdev)
          .arg(&mount)
          .status()
          .map(|s| s.success())
          .unwrap_or(false)
      })
    };
    let widened = widen.await;
    let remounted = cycle.await.expect("mount cycle task");

    // A widen the cycle beat to its own target was REFUSED, and a refusal is the
    // opposite of the ending this cell hunts. The subject here is a widen that
    // REPORTED SUCCESS over a root binding that had already died — so when the
    // unmount removed the replacement root before the widen could resolve it,
    // nothing was certified and there is no certification to hold to account.
    //
    // What such a round is left holding is a DIFFERENT claim: the OLD root's own
    // coverage across an unmount of the filesystem it sits on. That claim rests
    // on a loss signal reaching the Monitor at all, which is exactly what
    // `overflow_swallowed_unmount_rebinds_or_dies_loudly` stages deliberately —
    // and demanding it here, off a cycle this round did not stage it for, would
    // report that scenario's silence as this cell's false certification.
    //
    // Only a target that VANISHED is absorbed. Every other refusal is unexplained
    // by the race this cell runs and still travels to the assertion below.
    let target_vanished = match &widened {
      Err(ReplaceRootError::NotFound { .. }) => true,
      Err(ReplaceRootError::Source(SourceError::RootUnavailable { source, .. })) => {
        source.kind() == std::io::ErrorKind::NotFound
      }
      _ => false,
    };
    if target_vanished {
      common::skip_notice(format_args!(
        "widen_over_unmount_rebind_is_never_silently_certified: round {round}: the cycle unmounted \
         the image before the widen could resolve {}, so the widen was refused ({widened:?}) and \
         this round certified nothing to hold to account",
        root.display()
      ));
      let _ = w.close().await;
      continue;
    }

    // The demand below is only honest over staging that actually happened, and
    // the re-mount's exit status does not establish that in either direction: a
    // cycle whose umount was refused leaves the re-mount failing over a
    // mountpoint that never stopped being mounted (the filesystem is there and
    // the round stands), while a re-mount that exited zero still says nothing
    // about the path this round writes. So the staging is read from what the
    // round actually depends on. The kernel's own table must show a filesystem
    // back at the mountpoint, so the probe lands on the image rather than on the
    // bare directory a mount shadows; and the probe write must itself succeed,
    // which is the only proof that its parent directory is present and accepts a
    // create. A round that cannot stage that has no ending to wait for — nothing
    // was ever created, so the wait can only run to its deadline — and asserting
    // there would report the harness's own missing filesystem as the product's
    // silence, which is indistinguishable from the defect this cell hunts.
    let probe = sub.join(format!("probe-{round}.txt"));
    if mount_state(&mount) != Some(true) {
      common::skip_notice(format_args!(
        "widen_over_unmount_rebind_is_never_silently_certified: round {round}: the cycle left \
         nothing mounted at {} (the re-mount reported success: {remounted}), so the round has no \
         filesystem to assert the widen's ending over",
        mount.display()
      ));
      let _ = w.close().await;
      continue;
    }
    if let Err(err) = std::fs::write(&probe, b"w1") {
      common::skip_notice(format_args!(
        "widen_over_unmount_rebind_is_never_silently_certified: round {round}: the probe under \
         the re-mounted subtree could not be created ({err}), so nothing was staged for the \
         stream to surface"
      ));
      let _ = w.close().await;
      continue;
    }
    staged += 1;

    // Whatever the interleaving produced, the ending must be observable: the
    // probe write under the (re-mounted) old subtree is delivered or covered
    // by a Rescan at it or any ancestor — never silence over dead coverage.
    let observed = wait_for(&mut w, |event| covers(event, &probe)).await;
    assert!(
      observed.is_some(),
      "round {round} (widen: {widened:?}): the mount cycle must surface — \
       delivered coverage or a covering Rescan, never silent false-certification"
    );

    let _ = w.close().await;
  }

  fixture.close();
  // A run whose every round lost its staging never put the commit gate under a
  // mount cycle at all, and a cell that asserted nothing must not report the
  // same green as one that asserted and held.
  assert!(
    staged > 0,
    "staged 0 of {} rounds: no round kept a usable filesystem across the mount cycle, so this run \
     established nothing about the widen and says nothing about false certification — see the SKIP \
     lines for which staging step failed",
    OFFSETS_MS.len()
  );
}

/// Whether `path` is a mount point right now, read from the kernel's own table
/// rather than inferred from a command's exit status: a cell whose bracket died
/// mid-cycle leaves nothing mounted, so a failing `umount` there is correct
/// rather than a cleanup failure worth reporting.
///
/// `None` is UNKNOWN, not "clean": a table that could not be read has proven
/// nothing either way. The residue verdict is the flag that decides whether the
/// fixture counts as released, so it must not read an unreadable table as an
/// absent mount — it treats `None` as residue.
fn mount_state(path: &Path) -> Option<bool> {
  let table = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
  let needle = path.to_string_lossy();
  Some(table.lines().any(|line| {
    // Field 5 is the mount point, with these four bytes octal-escaped.
    line.split(' ').nth(4).is_some_and(|field| {
      field
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
        == needle
    })
  }))
}

/// Whether `loopdev` still carries a backing file — the `loop/` attribute
/// directory exists only while the device is attached.
fn loop_attached(loopdev: &str) -> bool {
  let Some(name) = Path::new(loopdev).file_name() else {
    return false;
  };
  Path::new("/sys/block")
    .join(name)
    .join("loop/backing_file")
    .exists()
}

/// Runs one cleanup utility to completion within a wall-clock bound, terminating
/// its process GROUP if it outlives it. `Err` carries the residue line the caller
/// must record: nothing about the resource the utility was to release has been
/// proven, so it is presumed still held.
///
/// `status()` waits FOREVER, and the release below runs from `Drop`. An `umount`
/// on a superblock whose writeback is stuck, or a `losetup -d` the kernel will not
/// complete, therefore blocks the unwind out of a failing privileged assertion —
/// which hides that assertion's own diagnostic, leaves the residue verification
/// unrun, and reaches the CI timeout with the mount and the loop device still
/// attached. The retry COUNTS were bounded all along; the individual invocation
/// was not, and that is the one that runs while a failure report is waiting to be
/// printed.
///
/// Bounded with the bracket's own two helpers rather than a second mechanism: the
/// child is its own process GROUP so the kill reaches whatever it left in flight
/// ([`terminate_group`]), and the wait is POLLED rather than blocking
/// ([`wait_within`]) — the same [`StopBudget::call`]/[`StopBudget::grace`] pair
/// that bounds a step inside the helper, so this path scales with the one clock
/// too.
///
/// A bound per call is still not a bound on the RELEASE, which is what
/// [`cleanup_budget`] adds: a utility that keeps returning is affordable here every
/// time and unaffordable in aggregate.
fn cleanup_within(
  what: &str,
  command: &mut std::process::Command,
  budget: &StopBudget,
) -> Result<(), String> {
  use std::{os::unix::process::CommandExt, process::Stdio};
  let mut child = match command
    .stdin(Stdio::null())
    // Its own group, so a utility that left work of its own in flight is reaped
    // whole instead of outliving the kill aimed at it.
    .process_group(0)
    .spawn()
  {
    Ok(child) => child,
    Err(err) => return Err(format!("{what} could not be run at all: {err}")),
  };
  if wait_within(&mut child, budget.call).is_some() {
    // The exit STATUS is deliberately not consulted: `umount` legitimately fails
    // on a mount a dead bracket already took apart, and the residue check is what
    // decides whether the fixture came apart. Only never FINISHING is a fact about
    // the utility itself.
    return Ok(());
  }
  terminate_group(&child);
  // Bounded even here: the uninterruptible kernel work that wedged the utility is
  // exactly what a `SIGKILL` cannot cut short, so the reap of the killed child
  // must not be waited out either. A child that outlives this is left unreaped
  // rather than blocking the unwind.
  let reaped = wait_within(&mut child, budget.grace);
  Err(format!(
    "{what} exceeded its {:?} bound and was killed (reaped within the {:?} grace: {})",
    budget.call,
    budget.grace,
    reaped.is_some()
  ))
}

/// The ONE aggregate wall-clock bound on a fixture's whole release — every unmount
/// retry AND every outer [`Drop`] pass together — derived from the same scaled clock
/// as the per-call bound inside [`cleanup_within`].
///
/// The two bounds answer different questions, and neither implies the other.
/// [`cleanup_within`] deliberately does not consult a utility's exit STATUS: a
/// `umount` on a mount a dead bracket already took apart legitimately exits nonzero,
/// so only never FINISHING is a fact about the utility itself. A utility that keeps
/// failing FAST is therefore affordable on every single call and never marks the
/// fixture [`wedged`](LoopFixture::wedged) — while in aggregate it is not affordable
/// at all. The unmount retry permits 100 invocations, so a `umount` exiting nonzero
/// just inside its per-call bound spends that bound a hundred times over in ONE
/// release pass, and [`Drop`] may repeat the pass [`RELEASE_ATTEMPTS`] times: every
/// call returns, nothing is flagged, and the release outlives the failing assertion
/// it is unwinding out of — reaching the outer CI timeout before any residue is
/// reported, with the mount and the loop device still attached. No per-call bound can
/// see that shape; only one spanning the whole release can.
///
/// Sized against the two shapes it must not disturb, both of which stay well inside
/// it. A HEALTHY release unmounts on its first invocation and is done in
/// milliseconds. The most expensive HONEST pass is both utilities having to be
/// KILLED, `(call + grace) * 2` — which stays a wedged-utility diagnostic instead of
/// becoming this one, because six killed-utility bounds clear it three times over;
/// the same margin covers the retry loop's own ~2 s of `EBUSY` naps across all
/// [`RELEASE_ATTEMPTS`] passes twice over. What it does cut short is the pathology
/// above, which becomes a bounded, REPORTED failure instead of a slow one.
fn cleanup_budget(budget: &StopBudget) -> Duration {
  (budget.call + budget.grace) * 6
}

/// The kernel's own name for a live descriptor, in the form a CHILD process can
/// resolve: `/proc/<pid>/fd/<n>`.
///
/// `/proc/self/fd/<n>` would name the CHILD'S descriptor table — a different table
/// entirely, and for a `std` descriptor (every one of them `O_CLOEXEC`) an empty
/// slot in it. The numeric pid is THIS process's table, which the child may read
/// because it is this process's own child running as the same user, and the kernel
/// resolves the magic link to the object the descriptor holds instead of walking
/// the name it was opened under. So a utility handed this path operates on the
/// inode the fixture opened, whatever happened to the names on the way to it
/// since.
fn fd_path(fd: &impl AsRawFd) -> PathBuf {
  PathBuf::from(format!(
    "/proc/{}/fd/{}",
    std::process::id(),
    fd.as_raw_fd()
  ))
}

/// `fstat(2)` on a live descriptor — the identity of the object the fixture is
/// actually USING, which a path `stat` can only guess at.
fn fstat_of(fd: &impl AsRawFd) -> Option<libc::stat> {
  // SAFETY: `fd` is a live descriptor for the whole call, and `libc::stat` is
  // plain data the kernel fills in completely when it answers 0.
  unsafe {
    let mut st = std::mem::zeroed::<libc::stat>();
    (libc::fstat(fd.as_raw_fd(), &mut st) == 0).then_some(st)
  }
}

/// `fstatat(2)` with `AT_SYMLINK_NOFOLLOW`: what a NAME resolves to right now,
/// without following anything planted at it. Paired with [`fstat_of`] it answers
/// the only question a stored path can be held to — "does this name still refer to
/// the object this descriptor holds?".
fn fstatat_of(dirfd: &impl AsRawFd, name: &CStr) -> Option<libc::stat> {
  // SAFETY: live descriptor, live NUL-terminated name, and `libc::stat` is plain
  // data the kernel fills in completely when it answers 0.
  unsafe {
    let mut st = std::mem::zeroed::<libc::stat>();
    (libc::fstatat(
      dirfd.as_raw_fd(),
      name.as_ptr(),
      &mut st,
      libc::AT_SYMLINK_NOFOLLOW,
    ) == 0)
      .then_some(st)
  }
}

fn same_object(a: &libc::stat, b: &libc::stat) -> bool {
  a.st_dev == b.st_dev && a.st_ino == b.st_ino
}

/// Opens `path` as a directory and nothing else: `O_DIRECTORY` refuses a
/// non-directory and `O_NOFOLLOW` refuses a symlink at the final component.
fn open_dir(path: &Path) -> std::io::Result<File> {
  use std::os::unix::ffi::OsStrExt;

  let c = CString::new(path.as_os_str().as_bytes())
    .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
  // SAFETY: `c` is a live NUL-terminated C string for the duration of the call.
  let fd = unsafe {
    libc::open(
      c.as_ptr(),
      libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )
  };
  if fd < 0 {
    return Err(std::io::Error::last_os_error());
  }
  // SAFETY: `fd` is a fresh, valid descriptor this call owns, handed over once.
  Ok(unsafe { File::from_raw_fd(fd) })
}

/// [`open_dir`] relative to a retained directory descriptor — the same directory
/// the caller already verified, not a name resolved from the root a second time.
fn open_dir_at(dirfd: &impl AsRawFd, name: &CStr) -> std::io::Result<File> {
  // SAFETY: live descriptor, live NUL-terminated name.
  let fd = unsafe {
    libc::openat(
      dirfd.as_raw_fd(),
      name.as_ptr(),
      libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )
  };
  if fd < 0 {
    return Err(std::io::Error::last_os_error());
  }
  // SAFETY: `fd` is a fresh, valid descriptor this call owns, handed over once.
  Ok(unsafe { File::from_raw_fd(fd) })
}

/// `unlinkat(2)` relative to a retained directory descriptor: a removal that
/// cannot be pointed somewhere else by a name that changed under it. Best-effort,
/// exactly like the `remove_*` calls it replaces — the residue verification is
/// what reports whatever is still there.
fn unlink_at(dirfd: &impl AsRawFd, name: &CStr, flags: libc::c_int) {
  // SAFETY: live descriptor, live NUL-terminated name.
  let _ = unsafe { libc::unlinkat(dirfd.as_raw_fd(), name.as_ptr(), flags) };
}

/// The name the kernel currently reports for a descriptor, for diagnostics.
fn fd_name(fd: &impl AsRawFd) -> String {
  std::fs::read_link(fd_path(fd))
    .map(|path| path.display().to_string())
    .unwrap_or_else(|_| "<unnamed>".to_owned())
}

/// Whether a stored path THROUGH this directory can be redirected by another
/// user — the precondition [`loop_image`] refuses to build without.
///
/// `Some(reason)` names the first directory that fails, walking from `dirfd` up to
/// the filesystem root; `None` means no untrusted user can rename an entry
/// anywhere along the way, so a name resolved once here resolves to the same
/// object every later time.
///
/// # The two rules, and why they are the whole test
///
/// Renaming an entry out of a directory needs write permission on that directory,
/// and the kernel adds exactly one exception: under the STICKY bit (`S_ISVTX`) an
/// entry may be renamed or removed only by its own owner, the DIRECTORY's owner,
/// or root. So a directory is one a privileged fixture may be named in when
///
/// 1. it is owned by this process's uid or by root — any other owner is precisely
///    the user that sticky exception hands the power back to, so `1777` owned by
///    someone else is NOT safe; and
/// 2. it is not writable beyond its owner, OR it is sticky.
///
/// Both must hold at EVERY level up to the root: renaming a directory on the path
/// redirects everything under it exactly as renaming the leaf does.
///
/// This accepts every environment the suite runs in and refuses only the shape the
/// finding is about. The verify container mounts `TMPDIR` as a `1777` tmpfs —
/// world-writable and STICKY, owned by root — which rule 2's sticky arm accepts,
/// as it accepts `/tmp` on a CI runner; `/` and the rest of the walk are
/// root-owned `0755`. A world-writable `TMPDIR` WITHOUT the sticky bit is refused,
/// and so is one owned by a third uid, because in both the whole construction
/// below is forfeit: the exclusive `mkdir` still succeeds and the directory it
/// creates can still be renamed away a moment later.
///
/// Fails CLOSED. An ancestor that cannot be opened or `fstat`ed is reported
/// unsafe, because "could not tell" is not "safe".
fn hijackable_path(dirfd: &File) -> Option<String> {
  /// A `TMPDIR` deeper than this is a bug, not a temp directory — and the walk
  /// must terminate on a bound of its own rather than on `..` alone.
  const LEVELS: usize = 128;

  // SAFETY: `geteuid` reads this process's own credentials and cannot fail.
  let euid = unsafe { libc::geteuid() };
  let mut here = match dirfd.try_clone() {
    Ok(here) => here,
    Err(err) => {
      return Some(format!(
        "its descriptor could not be duplicated for the ancestor walk ({err})"
      ));
    }
  };
  for _ in 0..LEVELS {
    let Some(st) = fstat_of(&here) else {
      return Some(format!(
        "{} could not be fstat'd ({})",
        fd_name(&here),
        std::io::Error::last_os_error()
      ));
    };
    if st.st_uid != euid && st.st_uid != 0 {
      return Some(format!(
        "{} is owned by uid {} — neither this process's uid ({euid}) nor root — and a directory's \
         OWNER may rename ANY entry in it, sticky bit or not",
        fd_name(&here),
        st.st_uid
      ));
    }
    let mode = st.st_mode & 0o7777;
    if mode & (libc::S_IWGRP | libc::S_IWOTH) != 0 && mode & libc::S_ISVTX == 0 {
      return Some(format!(
        "{} is mode {mode:04o} — writable beyond its owner and NOT sticky, so any user who can \
         write it may rename this fixture's entries out of it",
        fd_name(&here)
      ));
    }
    // Upwards through the DESCRIPTOR, so the walk visits the directories this
    // fixture's path actually traverses (mount roots included, where `..` crosses
    // to the mount's parent exactly as a path resolution does) rather than a
    // second, independently-resolvable spelling of them.
    let up = match open_dir_at(&here, c"..") {
      Ok(up) => up,
      Err(err) => {
        return Some(format!(
          "the directory above {} could not be opened ({err})",
          fd_name(&here)
        ));
      }
    };
    let Some(up_st) = fstat_of(&up) else {
      return Some(format!(
        "the directory above {} could not be fstat'd ({})",
        fd_name(&here),
        std::io::Error::last_os_error()
      ));
    };
    // `..` of the filesystem root is the root itself: every level has answered.
    if same_object(&st, &up_st) {
      return None;
    }
    here = up;
  }
  Some(format!(
    "it is more than {LEVELS} levels below the filesystem root"
  ))
}

/// The privileged loop fixture, released on EVERY exit path.
///
/// Same reason as [`SysctlGuard`]: the cells holding one assert INSIDE their
/// rounds, so a release reached only on normal fallthrough is skipped by the
/// unwind a real defect causes — leaving the mount, the loop device and the
/// backing image attached for every later cell in the binary, and for the host
/// after a local `sudo` run.
struct LoopFixture {
  /// The private `0700` directory [`loop_image`] created for this fixture — the
  /// only place the image and the mountpoint are ever named. Released last, and
  /// with a NON-recursive remove, so it doubles as a residue check.
  home: PathBuf,
  /// The parent directory [`hijackable_path`] was decided ON, retained open. The
  /// fixture's own entry is created in and finally removed from THIS descriptor,
  /// never by resolving the parent's name a second time.
  parent_dir: File,
  /// The fixture's own entry name inside [`Self::parent_dir`].
  name: CString,
  /// [`Self::home`]'s own descriptor, retained open. The image and the mountpoint
  /// are created, used and removed `*at`-relative to it, so nothing inside the
  /// fixture is ever reached by re-resolving `home` — see [`loop_image`].
  home_dir: File,
  image: PathBuf,
  /// The image's entry name inside [`Self::home_dir`].
  image_name: CString,
  /// The image's own open descriptor, RETAINED from the exclusive create that
  /// made it. Sizing goes through this handle rather than a second path
  /// resolution, and `mkfs`/`losetup` are handed [`fd_path`] of it rather than the
  /// image's name, so there is no moment between the image's creation and its use
  /// at which a name could be pointing somewhere else; see [`loop_image`].
  ///
  /// Released before the image is unlinked, so the file's blocks are actually
  /// returned to the (memory-backed) test filesystem rather than pinned by this
  /// descriptor until the process exits.
  file: Option<File>,
  loopdev: String,
  mount: PathBuf,
  released: bool,
  /// A cleanup utility had to be KILLED for exceeding its bound (or could not be
  /// run at all). Sticky, and it retires [`Drop`]'s remaining passes: those exist
  /// for the `EBUSY` a just-dropped watcher is about to give back, which is a
  /// condition that clears in milliseconds — a wedged utility is not, so spending
  /// the same bound on it again would only stretch an unwind that is already
  /// carrying a failure report.
  wedged: bool,
  /// When the ONE aggregate cleanup bound ([`cleanup_budget`]) expires. Armed on the
  /// FIRST release pass and never re-armed, so the bound spans every unmount retry
  /// AND every outer [`Drop`] pass instead of restarting with each of them.
  ///
  /// Deliberately not armed at construction: the cell holding the fixture
  /// legitimately runs for minutes before releasing it (see [`CELL_BUDGET`]), and a
  /// bound already spent by the time cleanup starts would skip cleanup altogether —
  /// leaking the very mount, loop device and image the fixture exists to release.
  deadline: Option<std::time::Instant>,
  /// The aggregate bound above was exhausted. Sticky for the same reason
  /// [`Self::wedged`] is: it is what the NEXT pass reads, so no pass can hand itself a
  /// fresh budget, and a later one cannot quietly drop the fact that cleanup stopped
  /// short. It retires [`Drop`]'s remaining passes too — what each of them would
  /// spend is exactly what is already gone.
  overran: bool,
}

impl LoopFixture {
  fn loopdev(&self) -> &str {
    &self.loopdev
  }

  fn mount(&self) -> &Path {
    &self.mount
  }

  /// Creates the mountpoint inside the fixture's own directory DESCRIPTOR, so it
  /// lands in the directory this fixture created even if that directory's name has
  /// changed since.
  fn make_mountpoint(&self) -> std::io::Result<()> {
    // SAFETY: live descriptor, live NUL-terminated name.
    if unsafe { libc::mkdirat(self.home_dir.as_raw_fd(), c"mnt".as_ptr(), 0o700) } == 0 {
      Ok(())
    } else {
      Err(std::io::Error::last_os_error())
    }
  }

  /// `Some(reason)` when [`Self::home`] no longer names the directory this fixture
  /// created — someone renamed it away and another entry took the name.
  ///
  /// This is the DETECTOR for [`hijackable_path`]'s invariant, never a substitute
  /// for it: it cannot close the window (a rename could land one instruction after
  /// it answers), it can only make a substitution LOUD instead of silent at the two
  /// steps that have no descriptor form — `mount(8)`'s target and the release's
  /// `umount`/mountpoint removal. Under the precondition no untrusted user can
  /// perform that rename at all, so this must never fire.
  ///
  /// Fails CLOSED: an identity it cannot establish is reported as taken.
  fn home_taken(&self) -> Option<String> {
    let Some(held) = fstat_of(&self.home_dir) else {
      return Some(format!(
        "the fixture's retained directory descriptor could not be fstat'd ({})",
        std::io::Error::last_os_error()
      ));
    };
    match fstatat_of(&self.parent_dir, &self.name) {
      Some(named) if same_object(&held, &named) => None,
      Some(named) => Some(format!(
        "the name now resolves to dev {}:ino {} where the fixture's own directory is dev {}:ino {}",
        named.st_dev, named.st_ino, held.st_dev, held.st_ino
      )),
      None => Some(format!(
        "nothing resolves at the name any more ({})",
        std::io::Error::last_os_error()
      )),
    }
  }

  /// The release for a fixture whose directory NAME is not its own any more
  /// ([`Self::home_taken`] fired). It reaches everything it still can through the
  /// retained descriptors and touches the stolen name NOT ONCE: a
  /// `remove_dir_all` aimed at a stored path another user now owns is the same
  /// defect this hardening exists to remove, pointed at deletion instead of
  /// `mkfs`.
  ///
  /// It never marks the fixture released, so it reports on every [`Drop`] pass and
  /// [`close`](Self::close) turns it into the holding cell's failure. That is
  /// deliberate: under the [`hijackable_path`] precondition no untrusted user can
  /// rename this fixture's entry, so arriving here at all is a broken invariant and
  /// must be as loud as a failed assertion.
  ///
  /// Each utility keeps its own wall-clock bound ([`cleanup_within`]); the
  /// aggregate bound of [`Self::release_once`] is not threaded through because this
  /// path spawns at most two utilities per pass and [`RELEASE_ATTEMPTS`] bounds the
  /// passes.
  fn release_stolen(&mut self, why: String) -> Vec<String> {
    use std::process::Command;

    let budget = StopBudget::current();
    let mut residue = vec![format!(
      "the fixture's own directory {} was renamed out from under it and another entry holds that \
       name now ({why}) — the release worked through its retained descriptors only and left the \
       name alone",
      self.home.display()
    )];
    // The kernel's live answer for the retained descriptor is the only name for
    // this directory that is not the stolen one.
    let live = std::fs::read_link(fd_path(&self.home_dir)).ok();
    if let Some(mount) = live.as_ref().map(|home| home.join("mnt"))
      && mount_state(&mount) == Some(true)
      && let Err(failed) = cleanup_within(
        &format!("umount {}", mount.display()),
        Command::new("umount").arg(&mount),
        &budget,
      )
    {
      self.wedged = true;
      residue.push(failed);
    }
    if let Err(failed) = cleanup_within(
      &format!("losetup -d {}", self.loopdev),
      Command::new("losetup").arg("-d").arg(&self.loopdev),
      &budget,
    ) {
      self.wedged = true;
      residue.push(failed);
    }
    // Same order as the verified release: the retained descriptor goes before the
    // unlink, or the image's blocks stay charged to an invisible inode.
    self.file = None;
    unlink_at(&self.home_dir, &self.image_name, 0);
    unlink_at(&self.home_dir, c"mnt", libc::AT_REMOVEDIR);
    // A directory cannot be removed through its OWN descriptor, so its entry is the
    // one thing here that needs a name — and the live one is what it gets.
    if let Some(home) = &live {
      let _ = std::fs::remove_dir(home);
    }
    if loop_attached(&self.loopdev) {
      residue.push(format!("{} is still attached", self.loopdev));
    }
    if fstatat_of(&self.home_dir, &self.image_name).is_some() {
      residue.push(format!("{} still exists", self.image.display()));
    }
    if let Some(home) = live.filter(|home| home.exists()) {
      residue.push(format!(
        "the fixture's own directory still exists, now named {}",
        home.display()
      ));
    }
    residue
  }

  /// Whether the ONE aggregate cleanup bound ([`cleanup_budget`]) is spent, RECORDING
  /// it stickily the first time it is.
  ///
  /// Consulted BEFORE each utility rather than after: a call that returned is not a
  /// call the release could afford, and the whole point of the bound is that cleanup
  /// stops where it stands and REPORTS instead of spending a per-call bound it no
  /// longer has.
  fn out_of_budget(&mut self) -> bool {
    self.overran |= self
      .deadline
      .is_some_and(|deadline| std::time::Instant::now() >= deadline);
    self.overran
  }

  /// Unmounts, detaches and removes, then reports what is STILL attached.
  ///
  /// `released` records a VERIFIED release, so it is set only once the residue
  /// check comes back EMPTY. A fixture that would not come apart therefore stays
  /// unreleased and [`Drop`] gets a real second attempt; flagging it on entry
  /// would retire the retry along with the failed attempt. Re-entry is safe:
  /// unmounting what is not mounted, detaching what is detached and removing what
  /// is gone all fail harmlessly.
  ///
  /// Every utility runs under a wall-clock bound ([`cleanup_within`]) and a
  /// utility that had to be killed is recorded as a cleanup failure of its own
  /// rather than retried — so the residue verification below always runs, and
  /// always reports, even when the tools that were supposed to make it come back
  /// empty are the thing that failed.
  ///
  /// Those per-call bounds are not a bound on the release, so the whole of it —
  /// every retry here and every pass [`Drop`] makes — runs under ONE aggregate bound
  /// as well ([`cleanup_budget`]), read before each utility is spawned. Exhausting it
  /// is recorded exactly like a killed utility (stickily, in [`Self::overran`]) and
  /// ends cleanup at once: the residue verification runs and reports from where the
  /// release stood, rather than after another hundred individually affordable
  /// invocations.
  fn release_once(&mut self) -> Vec<String> {
    use std::process::Command;
    if self.released {
      return Vec::new();
    }
    // `umount`, the mountinfo lookup and the mountpoint's recursive removal are all
    // path-shaped and have no descriptor form, so the release asks FIRST whether the
    // stored name is still this fixture's own directory. It is what makes the
    // release safe to point at a stored path at all — see [`Self::release_stolen`].
    if let Some(why) = self.home_taken() {
      return self.release_stolen(why);
    }
    let budget = StopBudget::current();
    let aggregate = cleanup_budget(&budget);
    // Armed on the FIRST pass only: every later pass inherits this same instant,
    // which is what makes the bound aggregate rather than per-pass.
    if self.deadline.is_none() {
      self.deadline = Some(std::time::Instant::now() + aggregate);
    }
    // Recorded FIRST, so the report names the wedged UTILITY and not just the
    // residue it left: "umount was killed" and "the mount is still there" are
    // different diagnostics, and only the first one says where to look.
    let mut residue = Vec::new();
    // The order is forced: a live mount pins the loop device and an attached
    // device pins its backing file. The unmount retries briefly because on the
    // unwind path the watcher was never closed — its descent can still hold an
    // `O_PATH` anchor on the superblock, which is exactly `umount`'s `EBUSY` —
    // and the dropped watcher needs a moment to give those back.
    for _ in 0..100 {
      if mount_state(&self.mount) != Some(true) {
        break;
      }
      // Retrying is only worth a bound the release still HAS. A `umount` failing fast
      // is affordable on every call and unaffordable a hundred times over, so what
      // ends this loop when the retries have stopped being progress is the aggregate
      // bound — never a call's exit status, which says nothing about the mount.
      if self.out_of_budget() {
        break;
      }
      // A `umount` that never RETURNS is not a `umount` that failed: the retries
      // are for a mount that is momentarily busy, so spending another bound on a
      // utility that is already wedged would only lengthen the unwind. It ends the
      // loop and is reported.
      if let Err(failed) = cleanup_within(
        &format!("umount {}", self.mount.display()),
        Command::new("umount").arg(&self.mount),
        &budget,
      ) {
        self.wedged = true;
        residue.push(failed);
        break;
      }
      if mount_state(&self.mount) == Some(true) {
        std::thread::sleep(Duration::from_millis(20));
      }
    }
    // Skipped rather than merely bounded once the aggregate bound is gone: the release
    // has nothing left to spend on another utility, so it goes straight to verifying
    // and REPORTING what it is leaving behind.
    if !self.out_of_budget()
      && let Err(failed) = cleanup_within(
        &format!("losetup -d {}", self.loopdev),
        Command::new("losetup").arg("-d").arg(&self.loopdev),
        &budget,
      )
    {
      self.wedged = true;
      residue.push(failed);
    }
    // Recorded like a killed utility, and for the same reason: the report must name
    // WHY cleanup stopped and not only what it left. Pushed on every pass the flag is
    // set, so an exhausted budget cannot be silently reset by a later pass.
    if self.overran {
      residue.push(format!(
        "the release exhausted its {aggregate:?} aggregate cleanup bound and stopped where it \
         stood — every utility it ran RETURNED within its own bound, none of them made progress"
      ));
    }
    // The retained descriptor goes first: unlinking a file this process still
    // holds open removes only the NAME, leaving 64 MiB of the test filesystem
    // charged to an invisible inode for the rest of the binary.
    //
    // Unlinked `*at`-relative to the fixture's own directory descriptor, so the
    // removal lands on the entry this fixture created rather than on whatever the
    // image's stored path resolves to now.
    self.file = None;
    unlink_at(&self.home_dir, &self.image_name, 0);

    match mount_state(&self.mount) {
      Some(false) => {
        // Only once the mount is provably gone: a recursive remove aimed at a
        // still-mounted point walks INTO the live filesystem and deletes its
        // contents — destroying the evidence of the failure without being able
        // to remove the point itself.
        let _ = std::fs::remove_dir_all(&self.mount);
      }
      Some(true) => residue.push(format!("{} is still mounted", self.mount.display())),
      None => residue.push(format!(
        "{} mount state is UNVERIFIABLE (/proc/self/mountinfo unreadable)",
        self.mount.display()
      )),
    }
    // NON-recursive, deliberately: it succeeds only once the image and the
    // mountpoint are both provably gone, which makes it a residue check of its
    // own instead of a recursive delete that could walk into a point the unmount
    // above did not clear. Relative to the parent descriptor the precondition was
    // decided on, so it removes this fixture's own entry and nothing else.
    unlink_at(&self.parent_dir, &self.name, libc::AT_REMOVEDIR);
    if loop_attached(&self.loopdev) {
      residue.push(format!("{} is still attached", self.loopdev));
    }
    // Both existence checks go through the retained descriptors too: a residue
    // check that resolved the stored names afresh could be answered by an entry
    // this fixture never created.
    if fstatat_of(&self.home_dir, &self.image_name).is_some() {
      residue.push(format!("{} still exists", self.image.display()));
    }
    if fstatat_of(&self.parent_dir, &self.name).is_some() {
      residue.push(format!("{} still exists", self.home.display()));
    }
    if residue.is_empty() {
      self.released = true;
    }
    residue
  }

  /// The explicit normal close: releases and FAILS on residue. A fixture that
  /// would not come apart leaves a mount, a loop device and a backing image
  /// behind for every later cell in this binary — and, after a local `sudo` run,
  /// for the host — so the cell that could not clean up owns the failure instead
  /// of donating a mystery result to an unrelated one.
  fn close(mut self) {
    let residue = self.release_once();
    assert!(
      residue.is_empty(),
      "CLEANUP loop fixture: {}",
      residue.join("; ")
    );
  }
}

impl Drop for LoopFixture {
  fn drop(&mut self) {
    // Reports, never panics — see [`SysctlGuard::drop`]. Bounded retries,
    // because `released` stays clear until a release verifiably left nothing and
    // the usual reason a first pass fails is a descriptor the just-dropped
    // watcher has not handed back yet.
    let mut residue = Vec::new();
    let mut passes = 0;
    for _ in 0..RELEASE_ATTEMPTS {
      passes += 1;
      residue = self.release_once();
      if residue.is_empty() {
        return;
      }
      // Neither a killed utility nor a spent aggregate bound comes back within a pass
      // gap (see [`LoopFixture::wedged`] and [`LoopFixture::overran`]), so the
      // remaining passes are spent reporting instead of waiting.
      if self.wedged || self.overran {
        break;
      }
      std::thread::sleep(Duration::from_millis(20));
    }
    for left in residue {
      eprintln!("CLEANUP FAILED loop fixture (while unwinding, {passes} attempts): {left}");
    }
  }
}

/// A private ext4 loopback pinned to an explicit loop device (same `st_dev`
/// across remounts — the same-identity rebind shape), sized `mb` MiB. `None`
/// skips loudly.
///
/// # Why the parent directory is DECIDED on before anything is built
///
/// Every step below runs with whatever privilege the cell has, and these cells
/// are the ones that need `CAP_SYS_ADMIN` — so in practice `mkfs.ext4`, `losetup`
/// and `mount` all run as ROOT. A name built from a tag and the observable PID
/// inside a world-writable `TMPDIR` is a name a local user can occupy FIRST, and
/// one they can RENAME AWAY afterwards. The exclusive `mkdir(2)` at `0700` closes
/// only the first of those: a `0700` directory protects its CONTENTS, never its
/// own ENTRY in a writable parent. Rename the fixture's directory away, put
/// another directory (or a symlink) at that name, and every step that resolves a
/// STORED PATH afterwards is redirected — the privileged formatter onto a chosen
/// large file or block device, the loop device onto it, the real mount into a
/// directory the attacker owns, and the release's own recursive remove onto
/// whatever they leave at the name. `fs.protected_symlinks` is no answer: it
/// refuses only a follow whose link owner differs from the follower's, and only
/// inside a STICKY directory — and a hard link at the name needs no symlink at
/// all. Neither is re-checking the name before each step, because there is always
/// one more re-resolution after the check.
///
/// So the first thing this builds is a DECISION, not a directory:
/// [`hijackable_path`] refuses to go on unless no untrusted user can rename an
/// entry in the parent or in any directory above it. That is decided once, on the
/// descriptor everything below then works from, and — unlike a race — it stays
/// decided.
///
/// Behind that decision, whatever CAN be anchored to a descriptor is, so the
/// guarantee does not rest on the one check:
///
/// * the parent is opened ONCE (`O_DIRECTORY | O_NOFOLLOW`) and the fixture's
///   directory is created with `mkdirat` in it — still one atomic, exclusive
///   `mkdir` answering `EEXIST` for ANYTHING already at the name, a symlink
///   included, and never a recursive form, which reports success for a path that
///   is already a directory (a symlink another owner aimed at one included);
/// * that directory is then held OPEN, and the image (`O_EXCL | O_NOFOLLOW`) and
///   the mountpoint are created `*at`-relative to it, so they land inside the
///   directory this process created whatever its name says now;
/// * the image's descriptor is RETAINED: its size is set through that handle, and
///   `mkfs.ext4` and `losetup` are handed [`fd_path`] of it — `/proc/<pid>/fd/<n>`,
///   which the kernel resolves to the inode the descriptor holds — so the
///   privileged formatter and the loop attach cannot be pointed at anything else
///   even if every name on the way to the image changed since;
/// * the release unlinks the image and its own entry with `unlinkat` through those
///   same descriptors, and verifies residue with `fstatat` through them.
///
/// Two steps have no descriptor form and are not pretended otherwise. `mount(8)`
/// takes a target PATH, canonicalizes it and records it in the kernel's mount
/// table; the release's `umount` and its mountpoint removal are path-shaped for
/// the same reason. Both are preceded by [`LoopFixture::home_taken`], which does
/// not close that window — a rename could land one instruction after it answers —
/// and exists only so a substitution is LOUD rather than silent. What makes the
/// window empty is the precondition.
fn loop_image(tag: &str, mb: u32) -> Option<LoopFixture> {
  use std::process::Command;
  static SEQ: AtomicU32 = AtomicU32::new(0);

  let Ok(parent) = std::env::temp_dir().canonicalize() else {
    common::skip_notice(format_args!("{tag}: TMPDIR could not be canonicalized"));
    return None;
  };
  // Opened once, and held: the precondition is decided on THIS descriptor and the
  // fixture's own entry is created in it, so the check and the use are the same
  // directory rather than two resolutions of one name.
  let parent_dir = match open_dir(&parent) {
    Ok(dir) => dir,
    Err(err) => {
      common::skip_notice(format_args!(
        "{tag}: TMPDIR {} could not be opened as a directory ({err})",
        parent.display()
      ));
      return None;
    }
  };
  if let Some(why) = hijackable_path(&parent_dir) {
    common::skip_notice(format_args!(
      "{tag}: REFUSING to build the fixture — a root-run mkfs, losetup and mount must not be \
       named anywhere an untrusted user can rename entries, and {why}. Point TMPDIR at a directory \
       that is either not writable beyond its owner or STICKY, as /tmp is."
    ));
    return None;
  }
  let entry = format!(
    "tributary-fs-loop-{tag}-{}-{}",
    std::process::id(),
    SEQ.fetch_add(1, Ordering::Relaxed),
  );
  let home = parent.join(&entry);
  let name = CString::new(entry).expect("the fixture's own generated name contains no NUL");
  // SAFETY: live descriptor, live NUL-terminated name.
  if unsafe { libc::mkdirat(parent_dir.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
    let err = std::io::Error::last_os_error();
    common::skip_notice(format_args!(
      "{tag}: REFUSING to build the fixture — the private image directory {} could not be \
       created exclusively ({err}), so something this process did not create already holds that \
       name and a root-run image write must not proceed through it",
      home.display()
    ));
    return None;
  }
  let home_dir = match open_dir_at(&parent_dir, &name) {
    Ok(dir) => dir,
    Err(err) => {
      common::skip_notice(format_args!(
        "{tag}: REFUSING to build the fixture — the private image directory {} could not be \
         re-opened as a descriptor ({err}), and a fixture that cannot hold its own directory open \
         would have to reach everything inside it by name",
        home.display()
      ));
      unlink_at(&parent_dir, &name, libc::AT_REMOVEDIR);
      return None;
    }
  };

  let image = home.join(format!("{tag}.img"));
  let image_name =
    CString::new(format!("{tag}.img")).expect("the fixture's own generated name contains no NUL");
  // Every skip path from here on removes what it created, through the retained
  // descriptors: at most the image and the (empty) mountpoint, and then the
  // directory's own entry in the parent the precondition was decided on.
  let discard_home = || {
    unlink_at(&home_dir, &image_name, 0);
    unlink_at(&home_dir, c"mnt", libc::AT_REMOVEDIR);
    unlink_at(&parent_dir, &name, libc::AT_REMOVEDIR);
  };

  // SAFETY: live descriptor, live NUL-terminated name; `openat` takes the mode as
  // its variadic argument because `O_CREAT` is set.
  let fd = unsafe {
    libc::openat(
      home_dir.as_raw_fd(),
      image_name.as_ptr(),
      libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
      0o600 as libc::c_uint,
    )
  };
  if fd < 0 {
    let err = std::io::Error::last_os_error();
    common::skip_notice(format_args!(
      "{tag}: REFUSING to build the fixture — the backing image {} could not be created \
       exclusively ({err})",
      image.display()
    ));
    discard_home();
    return None;
  }
  // SAFETY: `fd` is a fresh, valid descriptor this call owns, handed over once.
  let file = unsafe { File::from_raw_fd(fd) };
  // Sized through the RETAINED handle. A fresh `dd of=<path>` would resolve the
  // name a second time, which is exactly the window the exclusive create above
  // closed — and the create is worth nothing if the very next step reopens by
  // name.
  if let Err(err) = file.set_len(u64::from(mb) * 1024 * 1024) {
    common::skip_notice(format_args!(
      "{tag}: the backing image could not be sized to {mb} MiB: {err}"
    ));
    drop(file);
    discard_home();
    return None;
  }
  // The formatter is handed the image's DESCRIPTOR, never its name: the kernel
  // resolves `/proc/<pid>/fd/<n>` to the inode this process holds open, so a
  // root-run `mkfs` cannot be redirected onto a victim file or a block device by
  // any name that changed since the image was created. The same path goes to
  // `losetup`, which reports the image's real backing path once attached.
  let image_fd = fd_path(&file);
  if !Command::new("mkfs.ext4")
    .args(["-q", "-F"])
    .arg(&image_fd)
    .status()
    .map(|s| s.success())
    .unwrap_or(false)
  {
    common::skip_notice(format_args!("{tag}: mkfs.ext4 unavailable"));
    drop(file);
    discard_home();
    return None;
  }
  let loopdev = match Command::new("losetup")
    .args(["-f", "--show"])
    .arg(&image_fd)
    .output()
  {
    Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
    _ => {
      common::skip_notice(format_args!("{tag}: losetup unavailable"));
      drop(file);
      discard_home();
      return None;
    }
  };
  // RAII from the moment there is anything to release, NOT from the moment the
  // mount reports success — and not from any point after which a step could
  // PANIC either. Everything between `losetup` and here is a pure path join, so
  // the guard now covers the mountpoint work as well: creating it used to run
  // before the fixture existed and to panic on failure, which walked straight
  // past the destructor and leaked the device and the image VM-globally for every
  // later run. Every failure after `losetup` — a refused mountpoint, a refused
  // mount, a mount that TOOK EFFECT before the utility answered nonzero, a detach
  // the kernel momentarily refuses — now routes through the one verified,
  // retrying release below.
  let mount = home.join("mnt");
  let fixture = LoopFixture {
    home: home.clone(),
    parent_dir,
    name,
    home_dir,
    image,
    image_name,
    file: Some(file),
    loopdev: loopdev.clone(),
    mount: mount.clone(),
    released: false,
    wedged: false,
    deadline: None,
    overran: false,
  };
  // The same exclusive, symlink-safe discipline as the directory above — and now
  // `mkdirat` in the fixture's own directory descriptor — returning THROUGH the
  // guard: dropping the fixture unmounts nothing (there is no mount yet), detaches
  // the device and removes the image and its directory, where a panic here would
  // have left all three behind.
  if let Err(err) = fixture.make_mountpoint() {
    common::skip_notice(format_args!(
      "{tag}: the mountpoint {} could not be created exclusively: {err}",
      mount.display()
    ));
    drop(fixture);
    return None;
  }
  // The one step no descriptor carries (see this function's header): `mount(8)`
  // takes a target PATH. Asking whether that path is still the fixture's own
  // directory cannot close the window — only the precondition above can — but it
  // turns a substitution into a refusal instead of a privileged mount into a
  // directory someone else owns.
  //
  // The ONE refusal here that is not a skip, deliberately. Every other refusal in
  // this builder reports an environment that cannot host the fixture, and skipping
  // is the honest answer; this one reports that the precondition ALREADY ACCEPTED
  // was violated — an untrusted rename in a directory where none is possible — and
  // a skip would hide it, because libtest captures a PASSING cell's stderr. So it
  // fails, after the guard has released what it can reach.
  if let Some(why) = fixture.home_taken() {
    drop(fixture);
    panic!(
      "REFUSING to mount for {tag}: {} is no longer the directory this fixture created ({why}). \
       Under a parent no untrusted user can rename entries in — which is what `hijackable_path` \
       accepted before anything was built — this cannot happen, so the precondition itself has \
       been violated and no privileged mount may proceed through the name",
      home.display()
    );
  }
  let mounted = Command::new("mount")
    .arg(&loopdev)
    .arg(&mount)
    .status()
    .map(|s| s.success())
    .unwrap_or(false);
  if !mounted {
    common::skip_notice(format_args!("{tag}: loop mount refused"));
    // Dropped, not `close`d: this is a skip path, and the release reports its own
    // residue loudly (`CLEANUP FAILED`) rather than converting a refused mount
    // into this cell's panic.
    drop(fixture);
    return None;
  }
  Some(fixture)
}

/// Length and an FNV-1a hash of a whole file: enough to witness "untouched" or
/// "overwritten" without taking a hash dependency, and a formatter cannot write a
/// superblock over a file without moving both.
fn file_digest(path: &Path) -> (usize, u64) {
  let bytes = std::fs::read(path).expect("read the file being witnessed");
  let mut hash = 0xcbf2_9ce4_8422_2325_u64;
  for byte in &bytes {
    hash ^= u64::from(*byte);
    hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
  }
  (bytes.len(), hash)
}

/// Whether the object this descriptor holds carries an ext4 superblock — the
/// `0xEF53` magic at offset `0x438`, which `mkfs.ext4` writes and nothing else in
/// these cells does.
fn has_ext4_superblock(file: &File) -> bool {
  use std::os::unix::fs::FileExt;

  let mut magic = [0_u8; 2];
  file.read_exact_at(&mut magic, 0x438).is_ok() && u16::from_le_bytes(magic) == 0xEF53
}

/// One arm of the pathname-replacement regression: stages a fixture directory and
/// image exactly the way [`loop_image`] does, plants a victim, has the directory's
/// NAME stolen, and then formats through the image's descriptor
/// (`by_descriptor`) or through the image's stored NAME — asserting the outcome
/// that path must have.
fn one_hijack_arm(scratch: &Path, parent_dir: &File, entry: &str, by_descriptor: bool) {
  use std::{os::unix::fs::MetadataExt, process::Command};

  const MB: u64 = 8;
  let name = CString::new(entry).expect("the arm's own generated name contains no NUL");
  // The victim is a file this cell owns, kept OUTSIDE the staged directory and
  // hashed before and after, so "untouched" is a measurement rather than an
  // assumption.
  let victim = scratch.join(format!("{entry}-victim.dat"));
  std::fs::write(&victim, vec![0x5A_u8; (MB * 1024 * 1024) as usize]).expect("victim payload");
  let before = file_digest(&victim);

  // The staging, in the fixture's own primitives: `mkdirat` in the verified
  // parent, `openat` inside the directory descriptor that returned, size set
  // through the retained handle.
  // SAFETY: live descriptor, live NUL-terminated name.
  assert_eq!(
    unsafe { libc::mkdirat(parent_dir.as_raw_fd(), name.as_ptr(), 0o700) },
    0,
    "mkdirat {entry}: {}",
    std::io::Error::last_os_error()
  );
  let home_dir = open_dir_at(parent_dir, &name).expect("open the staged directory");
  // SAFETY: live descriptor, live NUL-terminated name; `openat` takes the mode as
  // its variadic argument because `O_CREAT` is set.
  let fd = unsafe {
    libc::openat(
      home_dir.as_raw_fd(),
      c"image.img".as_ptr(),
      libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
      0o600 as libc::c_uint,
    )
  };
  assert!(
    fd >= 0,
    "openat the staged image: {}",
    std::io::Error::last_os_error()
  );
  // SAFETY: `fd` is a fresh, valid descriptor this call owns, handed over once.
  let image = unsafe { File::from_raw_fd(fd) };
  image
    .set_len(MB * 1024 * 1024)
    .expect("size the staged image through its retained handle");

  // The attack: the directory the fixture created is renamed AWAY and an attacker
  // directory takes its name, with the victim HARD-LINKED at the image's name — no
  // symlink, so `fs.protected_symlinks` and `O_NOFOLLOW` have nothing to catch.
  let stolen = scratch.join(format!("{entry}-stolen"));
  std::fs::rename(scratch.join(entry), &stolen).expect("rename the staged directory away");
  std::fs::create_dir(scratch.join(entry)).expect("attacker directory at the same name");
  let planted = scratch.join(entry).join("image.img");
  std::fs::hard_link(&victim, &planted).expect("plant the victim at the image's name");
  // The substitution is really in place before the formatter runs, so a clean
  // result below is a consequence of the anchoring and not of a failed attack.
  let (at_name, real) = (
    std::fs::metadata(&planted).expect("stat the planted name"),
    std::fs::metadata(&victim).expect("stat the victim"),
  );
  assert_eq!(
    (at_name.dev(), at_name.ino()),
    (real.dev(), real.ino()),
    "the image's stored name must resolve to the victim before the formatter runs, or this arm \
     proves nothing"
  );

  let target = if by_descriptor {
    fd_path(&image)
  } else {
    planted.clone()
  };
  assert!(
    Command::new("mkfs.ext4")
      .args(["-q", "-F"])
      .arg(&target)
      .status()
      .map(|status| status.success())
      .unwrap_or(false),
    "mkfs.ext4 refused {}",
    target.display()
  );
  let after = file_digest(&victim);
  if by_descriptor {
    assert_eq!(
      after, before,
      "the victim must be byte-for-byte untouched (length, FNV-1a) when the formatter is handed \
       the image's DESCRIPTOR: {before:?} became {after:?}"
    );
    assert!(
      has_ext4_superblock(&image),
      "the fixture's OWN image is what a descriptor-anchored mkfs must have formatted"
    );
  } else {
    assert_ne!(
      after, before,
      "the by-NAME control must actually be redirected onto the victim — if it is not, the \
       anchored arm above is a tautology and this regression witnesses nothing"
    );
    assert!(
      !has_ext4_superblock(&image),
      "the by-NAME control must have MISSED the fixture's own image, which is the whole defect"
    );
  }
}

/// Suite 12 (unprivileged): the pathname-replacement regression for
/// [`loop_image`] — its PRECONDITION and its descriptor-anchored image, pinned in
/// both directions.
///
/// This defect was closed once before by making the fixture's directory an
/// exclusive `mkdir` at `0700`, which stops an attacker from OCCUPYING the name
/// first and does nothing about the name being renamed AWAY afterwards: a `0700`
/// directory protects its contents, never its own entry in a writable parent. So
/// there are two claims to hold, and the second one has to be shown to be
/// non-vacuous:
///
/// 1. [`hijackable_path`] accepts exactly the parents where that rename is
///    impossible. The STICKY arm is load-bearing: the verify container's `TMPDIR`
///    and every `/tmp` are world-writable AND sticky, so a check that refused
///    world-writable outright would refuse every environment this suite runs in and
///    turn the privileged loop cells into permanent skips. The ambient `TMPDIR` is
///    asserted ACCEPTED for that reason — a fixture that always refuses is a silent
///    loss of the whole INV-BIND family, and it must be a failure here instead.
/// 2. A `mkfs.ext4` handed the image's DESCRIPTOR cannot be redirected by the
///    directory's name changing under it, while one handed the image's NAME is
///    redirected onto whatever answers to it now. Both arms run: the second is the
///    before-behaviour reproduced, and without it the first proves nothing. It
///    formats a file this cell planted for it and nothing else.
#[test]
fn the_loop_fixture_refuses_a_hijackable_parent_and_anchors_its_image() {
  use std::{fs::Permissions, os::unix::fs::PermissionsExt, process::Command};

  const CELL: &str = "the_loop_fixture_refuses_a_hijackable_parent_and_anchors_its_image";

  // The environment the privileged cells actually run in, decided on the very
  // descriptor `loop_image` decides on.
  let ambient = std::env::temp_dir()
    .canonicalize()
    .expect("canonicalize TMPDIR");
  let ambient_dir = open_dir(&ambient).expect("open TMPDIR as a directory");
  assert_eq!(
    hijackable_path(&ambient_dir),
    None,
    "TMPDIR {} must be ACCEPTED — the verify container mounts a sticky 1777 tmpfs there and CI's \
     /tmp is root-owned 1777, so a precondition that refuses it would skip every privileged loop \
     cell in this binary instead of protecting them",
    ambient.display()
  );

  let scratch = scratch_root("hijack");
  let parent_dir = open_dir(&scratch).expect("open the cell's scratch parent");

  // The decision table, on real directories with real modes — `1777` being both
  // `/tmp`'s shape and the container `TMPDIR`'s, and `0777` the one the finding is
  // about. `mkdir(2)` masks its mode with the umask, which would silently drop the
  // very group/other write bits under test, so each mode is `chmod`ed on
  // explicitly.
  for (mode, hijackable, why) in [
    (0o1777, false, "world-writable but sticky"),
    (0o1775, false, "group-writable but sticky"),
    (0o0755, false, "not writable beyond its owner"),
    (0o0700, false, "private to its owner"),
    (0o0777, true, "world-writable, NOT sticky"),
    (0o0775, true, "group-writable, NOT sticky"),
  ] {
    let dir = scratch.join(format!("mode-{mode:04o}"));
    std::fs::create_dir(&dir).expect("create the mode fixture");
    std::fs::set_permissions(&dir, Permissions::from_mode(mode)).expect("chmod the mode fixture");
    let dir_fd = open_dir(&dir).expect("open the mode fixture");
    let verdict = hijackable_path(&dir_fd);
    assert_eq!(
      verdict.is_some(),
      hijackable,
      "mode {mode:04o} ({why}) must be {}: hijackable_path said {verdict:?}",
      if hijackable { "REFUSED" } else { "ACCEPTED" }
    );
  }

  // Rule 1 — a directory's OWNER may rename any entry in it, which is exactly the
  // exemption the sticky bit grants — needs a directory owned by a third uid, and
  // only root can arrange one.
  // SAFETY: `geteuid` reads this process's own credentials and cannot fail.
  if unsafe { libc::geteuid() } == 0 {
    use std::os::unix::ffi::OsStrExt;

    let dir = scratch.join("owned-by-another-uid");
    std::fs::create_dir(&dir).expect("create the foreign-owner fixture");
    std::fs::set_permissions(&dir, Permissions::from_mode(0o1777)).expect("chmod it sticky 1777");
    let path = CString::new(dir.as_os_str().as_bytes()).expect("the path contains no NUL");
    // SAFETY: live NUL-terminated path.
    assert_eq!(
      unsafe { libc::chown(path.as_ptr(), 65534, 65534) },
      0,
      "chown the foreign-owner fixture: {}",
      std::io::Error::last_os_error()
    );
    let dir_fd = open_dir(&dir).expect("open the foreign-owner fixture");
    assert!(
      hijackable_path(&dir_fd).is_some(),
      "a STICKY 1777 directory owned by uid 65534 must be REFUSED: sticky exempts the directory's \
       own owner, so that uid may rename this fixture's entries out of it"
    );
  } else {
    eprintln!(
      "NOTE {CELL}: the foreign-owner arm needs root to chown a directory away; the mode table and \
       the anchoring arms below still run"
    );
  }

  if Command::new("mkfs.ext4").arg("-V").output().is_err() {
    eprintln!(
      "NOTE {CELL}: mkfs.ext4 is not on PATH, so the descriptor-anchoring arms are not attempted"
    );
    let _ = std::fs::remove_dir_all(&scratch);
    return;
  }
  one_hijack_arm(&scratch, &parent_dir, "anchored", true);
  one_hijack_arm(&scratch, &parent_dir, "by-name", false);

  let _ = std::fs::remove_dir_all(&scratch);
}

/// What the stream said about `at` after a loss window, accumulated across every
/// pass so no signal is lost between them.
///
/// The tallies answer opposite questions and must not be conflated. A COVERING
/// `Rescan` is a loud cover: the recovery admitted the gap at `at` or above it,
/// which is an honest ending even when nothing re-bound. Everything
/// [`retired`](Self::retired) counts is the opposite — evidence the Monitor was
/// TOLD what happened to `at`, so no teardown record was swallowed for it and the
/// round cannot be a sample of the swallow.
///
/// # What the public stream can and cannot say about a teardown
///
/// For a ROOT the teardown is loud by contract: `Monitor::on_ignored` emits an
/// unconditional `Rescan` and invalidates the root, which the unmount cell reads
/// straight off [`TokioWatcher::root_path`].
///
/// For a NON-ROOT it is SILENT by contract, and that is the gap
/// [`subject_deliveries`](Self::subject_deliveries) exists to close: a non-root
/// `IN_IGNORED` (and its `DeleteSelf` twin) routes to the Monitor's
/// `drop_subtree(.., CoveringRescan)`, which emits nothing at all unless the
/// dropped subtree carried a deficit — so "the teardown record was DELIVERED" has
/// no direct public expression, and the parent-side `Created`/`Removed` this
/// falsifier used to rely on alone are side effects of the rmdir and mkdir, not of
/// the teardown's delivery. What IS exposed, and what a delivered teardown
/// entails, is delivery from the SUBJECT'S OWN watch inside the teardown's own
/// queue window: `rm -rf` unlinks the directory's contents through that very watch
/// immediately before the kernel queues its `IN_DELETE_SELF`/`IN_IGNORED`, and an
/// inotify instance queues and delivers in FIFO order — so any of those child
/// records surfacing is proof the subject's watch was still delivering when its
/// teardown was generated, whether or not the parent-side verbs also landed.
#[derive(Debug, Default)]
struct LossSignals {
  /// `Rescan`s at `at` or at an ancestor (a rescan above obliges re-enumerating
  /// below it).
  covering_rescans: usize,
  /// Non-`Rescan` events located EXACTLY at `at` — the parent watch's own records
  /// for the subject's removal and (re)creation.
  told_about: usize,
  /// When set, deliveries from the subject's OWN watch also retire the round; the
  /// string is the file-name prefix of the round's verdict probes, the only writes
  /// this cell itself makes under the subject after the bracket, which must
  /// therefore not count as teardown-window traffic.
  subject_probe: Option<String>,
  /// Non-`Rescan` events located strictly BELOW `at` that are not this round's own
  /// verdict probes — see the type's header: records the subject's own watch
  /// delivered, which a swallowed teardown cannot produce.
  subject_deliveries: usize,
}

impl LossSignals {
  /// The falsifier for a NON-ROOT subject: also retire the round on any delivery
  /// from the subject's own watch, ignoring the round's own verdict probes.
  fn for_child_subject(probe_tag: &str) -> Self {
    Self {
      subject_probe: Some(probe_tag.to_owned()),
      ..Self::default()
    }
  }

  fn record(&mut self, event: &Event, at: &Path) {
    if event.is_rescan() {
      if at.starts_with(event.path()) {
        self.covering_rescans += 1;
      }
      return;
    }
    if event.path() == at {
      self.told_about += 1;
      return;
    }
    let Some(probe) = self.subject_probe.as_deref() else {
      return;
    };
    // Strictly below the subject, and not one of this round's verdict probes: a
    // record its own watch delivered. `strip_prefix` (never a byte-wise
    // `starts_with`) so a SIBLING whose name merely begins with the subject's
    // cannot be read as one of its children.
    if let Ok(rel) = event.path().strip_prefix(at)
      && !rel
        .components()
        .next()
        .and_then(|first| first.as_os_str().to_str())
        .is_some_and(|name| name.starts_with(probe))
    {
      self.subject_deliveries += 1;
    }
  }

  /// The covering `Rescan`s BEYOND the opening one — the loud covers a recovery
  /// may stand on. The opening `Rescan` is the loss ANNOUNCEMENT itself, so it
  /// can never also serve as the recovery's answer to it: "exactly one opening
  /// `Rescan` and then silence" is precisely the dark ending these cells refuse.
  fn loud_covers(&self) -> usize {
    self.covering_rescans.saturating_sub(1)
  }

  /// Everything that DISQUALIFIES the round as a sample of the swallow. Each arm
  /// stands on its own: either is enough, and neither needs the other's fate.
  fn retired(&self) -> usize {
    self.told_about + self.subject_deliveries
  }
}

/// Drains the stream until it stays quiet for a whole window, so every record the
/// round classifies afterwards was generated BY the bracket.
///
/// The falsifiers are about what the bracket's window delivered, and the liveness
/// handshakes that precede it leave residue behind: `std::fs::write` is a create, a
/// modify AND a close, [`coverage_becomes_live`] returns on the first of them to
/// land, and [`descent_releases_its_anchors`] reads no events at all — so without
/// this drain a straggling `Modified` for a pre-bracket probe file could be counted
/// as teardown-window traffic and retire a legitimate round. `false` means it never
/// went quiet, which is not a state a round can classify from.
async fn stream_goes_quiet(watcher: &mut TokioWatcher) -> bool {
  for _ in 0..80 {
    match tokio::time::timeout(scaled(Duration::from_millis(250)), watcher.next()).await {
      // Quiet for a whole window, or the stream ended: nothing is left to mistake
      // for the bracket's own traffic.
      Err(_) | Ok(None) => return true,
      Ok(Some(_)) => {}
    }
  }
  false
}

/// Waits (bounded) for the loss to SURFACE as a `Rescan` covering `at`, then
/// keeps draining for a settle window so the recovery's own later signals (a
/// closing `Rescan`, a death funnel's terminal cover) are counted too. Reports
/// whether the loss surfaced at all.
///
/// One accumulator across both passes: waiting twice with a fresh one would
/// discard the signals the second pass needs.
async fn observe_loss_at(
  watcher: &mut TokioWatcher,
  at: &Path,
  settle: Duration,
  signals: &mut LossSignals,
) -> bool {
  let surfaced = tokio::time::timeout(scaled(DEADLINE), async {
    while let Some(event) = watcher.next().await {
      signals.record(&event, at);
      if signals.covering_rescans > 0 {
        return true;
      }
    }
    false
  })
  .await
  .unwrap_or(false);
  if surfaced {
    let _ = tokio::time::timeout(scaled(settle), async {
      while let Some(event) = watcher.next().await {
        signals.record(&event, at);
      }
    })
    .await;
  }
  surfaced
}

/// The recovery verdict probe: writes fresh files under `dir` and waits for
/// each one's OWN event — the exact path, so only a genuinely re-bound watch
/// can witness liveness (an ancestor `Rescan` alone must NOT pass as the live
/// ending; it is the honest-DEATH signal instead). Everything else it sees folds
/// into `signals`, so a slow closing/terminal `Rescan` is not lost between the
/// collection window and the probes.
async fn probe_verdict(
  watcher: &mut TokioWatcher,
  dir: &Path,
  tag: &str,
  signals: &mut LossSignals,
) -> bool {
  for attempt in 0..40 {
    let probe = dir.join(format!("{tag}-{attempt}.txt"));
    if std::fs::write(&probe, b"x").is_err() {
      return false;
    }
    let delivered = tokio::time::timeout(scaled(Duration::from_millis(500)), async {
      while let Some(event) = watcher.next().await {
        if event.path() == probe {
          return true;
        }
        signals.record(&event, dir);
      }
      false
    })
    .await
    .unwrap_or(false);
    if delivered {
      return true;
    }
  }
  false
}

/// How many sibling directories the unmount bracket arms before the cycle.
///
/// `umount(2)` is its own storm: the kernel sends `IN_UNMOUNT` and then
/// `IN_IGNORED` for EVERY watch on the dying superblock, two records per watch,
/// and it walks the superblock's inode list in prepend order — newest inode
/// first — so the ROOT inode (instantiated at mount, before this tree) is the
/// storm's TAIL. With more than 8 watched children the queue is already full when
/// the walk reaches the root, so the root's two teardown records are the ones the
/// full queue discards. The width here is margin, not a threshold.
const UNMOUNT_STORM_DIRS: usize = 256;

/// Creates `count` sibling directories directly under `root`, returning the last
/// one (the settle probe's target). Built BEFORE the watch is armed, so the
/// descent arms the whole width and the unmount has that many watches to tear
/// down. `None` if the filesystem refused (out of inodes or space) — the caller
/// skips loudly rather than running a bracket that cannot overflow.
fn wide_tree(root: &Path, count: usize) -> Option<PathBuf> {
  let mut last = None;
  for i in 0..count {
    let dir = root.join(format!("d{i:06}"));
    match std::fs::create_dir(&dir) {
      Ok(()) => last = Some(dir),
      Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => last = Some(dir),
      Err(_) => return None,
    }
  }
  last
}

/// How many of this process's descriptors still point inside `mount`. The
/// descent's arms publish transient `O_PATH` anchors, and ANY descriptor into the
/// filesystem makes `umount(2)` answer `EBUSY` — so the bracket waits on this
/// reaching zero, which is the only real proof the crawl released everything. A
/// liveness handshake cannot substitute: ext4 hands out directory entries in hash
/// order, so a probe at the tree's last-created directory can be answered while
/// arms elsewhere in the width are still in flight.
fn descriptors_inside(mount: &Path) -> usize {
  let Ok(entries) = std::fs::read_dir("/proc/self/fd") else {
    return usize::MAX;
  };
  entries
    .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
    .filter(|target| target.starts_with(mount))
    .count()
}

/// Waits (bounded) until the descent has held no descriptor inside `mount` for a
/// SUSTAINED window. One zero sample does not settle it: the crawl is pipelined —
/// arms publish anchors, the enumerates consume them, the next level arms — so
/// between one batch's anchors draining and the next batch opening there is an
/// instant with none held, and a bracket that stops the process there finds the
/// mount busy the moment the next batch runs.
async fn descent_releases_its_anchors(mount: &Path) -> bool {
  let mut quiet = 0;
  for _ in 0..400 {
    if descriptors_inside(mount) == 0 {
      quiet += 1;
      if quiet >= 16 {
        return true;
      }
    } else {
      quiet = 0;
    }
    tokio::time::sleep(scaled(Duration::from_millis(25))).await;
  }
  false
}

/// The bracket helper's readiness token — its first write, sent once its own
/// resume path is installed.
const READY: &str = "READY";

/// The bracket helper's stop-OBSERVED token — written after the helper has read
/// every thread of this process out of `/proc` in state `T`, and BEFORE the
/// bracket's first step. It reports a fact the helper SAW, not one this side
/// inferred from a sampled instant: the reader was off the fd when the bracket
/// began. A helper that never observes the stop writes this token never and runs
/// no step.
const STOPPED: &str = "STOPPED";

/// The bracket helper's completion token — written after the bracket's LAST step
/// and BEFORE the resume it then sends. A token already in hand the moment the
/// stop lifts is therefore proof the whole bracket ran inside the stopped window.
const DONE: &str = "DONE";

/// How many creates the recreate bracket's storm makes before it frees the
/// directory's inode. The 16-slot queue nobody is draining is full after the
/// first handful; the rest is margin, and the round's own overflow check is the
/// proof rather than this number.
const STORM_WRITES: usize = 256;

/// Every bound in the reader-stopped device, derived from the ONE scaled clock
/// [`scaled`] provides — the shell helper's bounds included: the helper receives
/// its numbers as text computed from these fields instead of carrying constants
/// of its own.
///
/// A single unscaled constant in this device is a wedge, not a rounding error.
/// The predecessor gated a `scaled(10 s)` readiness wait with a fixed `sleep 20`
/// resume, so under the sanitizer lane's `TRIBUTARY_FS_TIMING_SCALE=6` the
/// readiness budget outgrew its guard: the guard's `SIGCONT` could be generated —
/// and silently DISCARDED, this process still running — before the stop it
/// existed to lift, and nothing was left to lift it afterwards.
#[derive(Debug, Clone, Copy)]
struct StopBudget {
  /// How long to wait for the helper's [`READY`].
  ready: Duration,
  /// Bound on the helper's stop HANDSHAKE: how long it may poll this process's
  /// per-thread state before giving up and running no step at all. It replaces
  /// the predecessor's fixed settle grace, whose whole job was to make a stop
  /// that landed "promptly" after `READY` *probably* precede the bracket.
  handshake: Duration,
  /// The handshake's poll cadence, and the helper's retry nap.
  poll: Duration,
  /// How long to wait for [`STOPPED`]/[`DONE`] after the stop lifts. Generous on
  /// purpose, and safely so: the tokens say WHAT the helper observed and that its
  /// work finished, while the resume's PROVENANCE is read out of the kernel's own
  /// signal state before the first token is looked at, so waiting longer for a
  /// token cannot manufacture a covered window.
  token: Duration,
  /// Wall-clock bound on ONE external command inside the helper.
  call: Duration,
  /// The hard-kill grace `timeout --kill-after` gives a command that ignores the
  /// `TERM` its wall-clock bound sends. Without it a TERM-resistant step is
  /// bounded by nothing.
  grace: Duration,
  /// Wall-clock bound on the helper's retry loop.
  work: Duration,
  /// When the guard FIRST expires, measured from the arm — the earliest instant a
  /// watchdog resume can end the stopped window. It is [`Self::tick`] in every
  /// production configuration, because nothing has happened by the arm that could
  /// make the first window want a different bound from the ones after it.
  ///
  /// It is a field of its own rather than a reuse of `tick` because the two are
  /// different instants and only one of them is the guard: `tick` is an interval
  /// this side chose, while the expiry is a moment in the kernel's timer. A cell
  /// that has to PRODUCE a watchdog-resumed window on demand moves this one
  /// inside the bracket and leaves the interval where it is — see
  /// [`a_watchdog_resumed_bracket_is_reported_and_never_staged`].
  guard: Duration,
  /// The self-resume interval — armed AT the stop and REPEATING, so it covers the
  /// whole stopped window however long readiness took and however often the stop
  /// is re-entered.
  tick: Duration,
  /// How long the helper may outlive the resume before its process group is
  /// terminated.
  reap: Duration,
}

impl StopBudget {
  fn current() -> Self {
    // The two primitives every derived bound below is built from.
    let call = scaled(Duration::from_secs(5));
    let work = scaled(Duration::from_secs(20));
    // A helper cannot outlast its handshake plus its retry bound plus its bounded
    // external calls, so the guard clears that by a further `call`: a HEALTHY
    // bracket is never cut short by its own guard, and a hung one is still resumed
    // within a bound. The relation holds at every scale because both sides scale
    // together — which is the entire reason the clock is shared.
    let tick = call + work + call * 3;
    Self {
      ready: scaled(Duration::from_secs(10)),
      handshake: call,
      poll: scaled(Duration::from_millis(50)),
      token: scaled(Duration::from_secs(2)),
      call,
      grace: call / 2,
      work,
      guard: tick,
      tick,
      reap: tick,
    }
  }
}

/// Whole seconds for the shell, never rounding a budget down to nothing.
fn shell_secs(d: Duration) -> u64 {
  d.as_secs().max(1)
}

/// Fractional seconds for the shell's sub-second sleeps.
fn shell_frac(d: Duration) -> String {
  format!("{:.3}", d.as_secs_f64())
}

/// The value the guard asks the kernel to deliver alongside its expiry, so the
/// instance dequeued after a stop can be identified as THIS timer's rather than
/// merely as some timer's.
const GUARD_TAG: usize = 0x7472_6962;

/// How many passes one drain of the pending `SIGCONT`s may take. At most one
/// instance of a standard signal is pending per queue and there are two (this
/// thread's private queue and the process' shared one), so a healthy drain ends
/// in three passes; the bound exists only so an `EINTR` storm cannot spin here.
const DRAIN_PASSES: usize = 8;

/// A repeating `SIGCONT` this process arms FOR ITSELF, so the stop it is about to
/// take cannot outlive it — and so that a resume the GUARD delivered can be told
/// from one the HELPER delivered by reading the kernel's own signal state.
///
/// A stopped process runs no code, so its resume must come from outside its
/// control flow — but not from outside the process. A POSIX interval timer keeps
/// counting while the process is stopped, and a generated `SIGCONT` continues a
/// stopped process even when that signal is blocked or ignored — POSIX puts the
/// continue action on the PROCESS and takes it when the signal is GENERATED, not
/// when it is delivered — so each expiry lifts the stop with no handler, no thread
/// and no helper involved.
///
/// # Why the expiry is EVIDENCE and not just a resume
///
/// A `SIGCONT` at its default disposition is discarded the moment it has
/// continued the process, which is why the predecessor had nothing to read and
/// inferred provenance from the window's LENGTH instead — comparing a window
/// measured from just before the stop against the interval the timer repeats on,
/// two quantities that are not the same instant and whose difference nothing
/// bounds. Two settings turn the expiry into a fact, and neither changes what the
/// guard does:
///
/// * `SIGCONT` is BLOCKED on this thread for the guard's whole lifetime. A
///   blocked signal is never "ignored", so the expiry is QUEUED instead of
///   discarded — while its continue action still lands, because that action does
///   not consult the mask.
/// * the timer is directed at THIS THREAD (`SIGEV_THREAD_ID`), so its expiry
///   lands on this thread's PRIVATE queue where no other thread can consume it,
///   and carries `si_code == SI_TIMER` plus [`GUARD_TAG`] — which is what tells it
///   apart from the helper's own `kill -CONT`, whose instance reads `SI_USER`.
///
/// Generating a stop signal FLUSHES every pending `SIGCONT` from the process, so
/// an expiry still queued once the stop lifts was necessarily generated after that
/// stop began: [`Self::resumed_the_stop`] reports THIS window and cannot inherit
/// an older tick.
///
/// Verified on this container class before being relied on: a self-stopped
/// process armed this way resumes at its expiry, repeatedly, with `SIGCONT`
/// blocked on the very thread that stopped — the group leader included, which is
/// what the harness gives a single-threaded test run; the expiry is pending
/// afterwards and reads `SI_TIMER`; and a bracket the helper resumed leaves either
/// nothing pending or the helper's own `SI_USER`, never an `SI_TIMER`.
///
/// This is also what makes the stop below safe to take at all. The predecessor's
/// guards all lived in the helper, so "a resume exists" could only ever mean "a
/// helper said so a moment ago"; this one is armed AT the stop, read back from
/// the kernel immediately before it, and REPEATS — so it cannot be spent early,
/// cannot be lost with the helper, and re-covers a window that is re-entered.
struct SelfResume {
  timer: libc::timer_t,
  /// Just `SIGCONT`: the set that is blocked while the guard lives and the set
  /// the drain waits on. Built once, at the arm, so neither path can fail on it
  /// afterwards.
  cont: libc::sigset_t,
  /// The mask to put back — `SIGCONT`'s blocked state from before the arm.
  restore: libc::sigset_t,
}

impl SelfResume {
  /// Arms a self-`SIGCONT` that first expires after `first` and repeats every
  /// `every`, with `SIGCONT` blocked on the calling thread so the expiry is
  /// observable. `None` when the kernel refused any step — in which case the
  /// caller must NOT stop, because it would then be stopping with neither a
  /// guard nor a way to tell who lifted the stop.
  fn arm(first: Duration, every: Duration) -> Option<Self> {
    // SAFETY: `sigset_t`, `sigevent` and `itimerspec` are plain C structs with no
    // invariant beyond the fields set here (each zeroed first, so union padding is
    // defined), and every out-parameter is an owned local of this frame.
    unsafe {
      let mut cont: libc::sigset_t = std::mem::zeroed();
      if libc::sigemptyset(&mut cont) != 0 || libc::sigaddset(&mut cont, libc::SIGCONT) != 0 {
        return None;
      }
      // Blocked BEFORE the timer is created, so no expiry can slip through
      // unqueued. On Linux the signal mask is per-thread (`sigprocmask(2)` is the
      // same `rt_sigprocmask` the pthread call makes), which is what confines this
      // to the one thread that is about to stop.
      let mut restore: libc::sigset_t = std::mem::zeroed();
      if libc::sigprocmask(libc::SIG_BLOCK, &cont, &mut restore) != 0 {
        return None;
      }
      let mut event: libc::sigevent = std::mem::zeroed();
      event.sigev_notify = libc::SIGEV_SIGNAL | libc::SIGEV_THREAD_ID;
      event.sigev_signo = libc::SIGCONT;
      event.sigev_value.sival_ptr = GUARD_TAG as *mut libc::c_void;
      event.sigev_notify_thread_id = libc::gettid();
      let mut timer: libc::timer_t = std::ptr::null_mut();
      if libc::timer_create(libc::CLOCK_MONOTONIC, &mut event, &mut timer) != 0 {
        libc::sigprocmask(libc::SIG_SETMASK, &restore, std::ptr::null_mut());
        return None;
      }
      let spec = libc::itimerspec {
        it_interval: timespec_of(every),
        it_value: timespec_of(first),
      };
      if libc::timer_settime(timer, 0, &spec, std::ptr::null_mut()) != 0 {
        libc::timer_delete(timer);
        libc::sigprocmask(libc::SIG_SETMASK, &restore, std::ptr::null_mut());
        return None;
      }
      Some(Self {
        timer,
        cont,
        restore,
      })
    }
  }

  /// Whether the guard is STILL armed, read back from the kernel: a countdown in
  /// progress AND an interval to re-arm it. Checked immediately before the stop,
  /// because "armed a moment ago" is exactly the assumption that wedged the
  /// predecessor.
  fn is_armed(&self) -> bool {
    // SAFETY: a live timer id of this process and an owned out-parameter.
    unsafe {
      let mut current: libc::itimerspec = std::mem::zeroed();
      if libc::timer_gettime(self.timer, &mut current) != 0 {
        return false;
      }
      let counting = current.it_value.tv_sec > 0 || current.it_value.tv_nsec > 0;
      let repeating = current.it_interval.tv_sec > 0 || current.it_interval.tv_nsec > 0;
      counting && repeating
    }
  }

  /// Whether the GUARD ended the stop that just lifted — accepted out of the
  /// kernel's pending-signal state, never computed from how long the window was.
  ///
  /// Every queued `SIGCONT` is dequeued here, guard's and helper's alike: leaving
  /// one behind would let it outlive the guard, and each one's origin is read off
  /// its own `si_code`. Nothing pending at all is the ordinary healthy answer —
  /// the helper resumed the process and the guard never reached its expiry.
  ///
  /// Must be called before the guard is disarmed and while `SIGCONT` is still
  /// blocked, which [`SelfResume`]'s lifetime is exactly what arranges.
  fn resumed_the_stop(&self) -> GuardResume {
    let mut seen = GuardResume::default();
    let idle = libc::timespec {
      tv_sec: 0,
      tv_nsec: 0,
    };
    for _ in 0..DRAIN_PASSES {
      let mut info: libc::siginfo_t =
        // SAFETY: `siginfo_t` is a plain C struct that `sigtimedwait` fills; all
        // zeroes is a valid starting value for it.
        unsafe { std::mem::zeroed() };
      // SAFETY: an owned signal set and `siginfo_t` out-parameter plus a zero
      // timeout, so this only polls what is already pending on this thread.
      let got = unsafe { libc::sigtimedwait(&self.cont, &mut info, &idle) };
      if got < 0 {
        // `EAGAIN` — nothing queued — is the expected end. `EINTR` means some
        // OTHER signal was handled mid-poll and says nothing about this queue, so
        // it must not be mistaken for an empty one.
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
          continue;
        }
        return seen;
      }
      seen.queued += 1;
      if info.si_code == libc::SI_TIMER {
        seen.by_guard = true;
        // SAFETY: `si_value` reads the union arm `SI_TIMER` selects, which is the
        // only branch this reads it under.
        seen.tagged = unsafe { info.si_value() }.sival_ptr as usize == GUARD_TAG;
      }
    }
    seen
  }
}

impl Drop for SelfResume {
  fn drop(&mut self) {
    // Disarmed, then drained, then the mask put back — in that order, so no expiry
    // of this guard can outlive it either as a timer or as a signal pending on
    // this thread. A tick that lands on a process which is running again is
    // harmless, but leaving one armed past its purpose would keep signalling for
    // the rest of the binary.
    // SAFETY: a live timer id of this process, disarmed with a zeroed spec, and
    // owned signal-set and `siginfo_t` locals.
    unsafe {
      let idle: libc::itimerspec = std::mem::zeroed();
      libc::timer_settime(self.timer, 0, &idle, std::ptr::null_mut());
      libc::timer_delete(self.timer);
      let now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
      };
      for _ in 0..DRAIN_PASSES {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        if libc::sigtimedwait(&self.cont, &mut info, &now) < 0 {
          break;
        }
      }
      libc::sigprocmask(libc::SIG_SETMASK, &self.restore, std::ptr::null_mut());
    }
  }
}

/// Where the resume that lifted a stop came from, as the kernel reported it.
#[derive(Debug, Default, Clone, Copy)]
struct GuardResume {
  /// An expiry of the guard was queued when the stop lifted, so the WATCHDOG
  /// ended that window and the helper still had work in flight.
  by_guard: bool,
  /// That expiry carried [`GUARD_TAG`], so it was this guard's own and not some
  /// other timer's. Reported rather than required: a `SI_TIMER` this side cannot
  /// attribute is still a watchdog resume, and treating it as one costs a round
  /// while mistaking it for the helper's would green one.
  tagged: bool,
  /// How many `SIGCONT` instances the drain accepted — the guard's expiry and the
  /// helper's own `kill -CONT` both land here.
  queued: usize,
}

fn timespec_of(d: Duration) -> libc::timespec {
  libc::timespec {
    tv_sec: d.as_secs() as libc::time_t,
    tv_nsec: libc::c_long::from(d.subsec_nanos() as i32),
  }
}

/// What one reader-stopped bracket actually achieved. Every field is a MEASURED
/// fact about this round, never a restatement of the device's intent.
#[derive(Debug)]
struct StoppedBracket {
  /// How long this process was provably off the CPU: `CLOCK_MONOTONIC` either
  /// side of the `SIGSTOP`, which keeps counting while the process does not.
  /// `None` when the device refused to stop at all.
  stopped_for: Option<Duration>,
  /// The helper read every thread of this process out of `/proc` in state `T` and
  /// said so ([`STOPPED`]) BEFORE its first step, so the reader was provably off
  /// the fd when the bracket began.
  stop_observed: bool,
  /// The GUARD ended the stopped window: an expiry of its own was queued on the
  /// stopping thread when the stop lifted ([`SelfResume::resumed_the_stop`]). The
  /// reader was therefore back on the fd while the helper still had work left, so
  /// such a bracket can never be [`Self::covered`] however well the helper then
  /// finished.
  guard_resumed: bool,
  /// The bracket ran strictly INSIDE the stopped window. Both ends rest on facts
  /// somebody SAW: the helper read every thread of this process out of `/proc` in
  /// state `T` before its first step ([`STOPPED`]), and no expiry of the guard was
  /// queued when the stop lifted, so the window ended on the helper's own
  /// post-work signal rather than on a watchdog tick.
  covered: bool,
  /// The helper's work reported success.
  work_ok: bool,
  /// The bracket's whole process GROUP is provably gone — verified by reading
  /// `/proc`, not assumed from a kill's return. A surviving `umount`/`mount` would
  /// race the fixture release that follows, so a round that cannot show the group
  /// empty is not a sample.
  group_clear: bool,
}

/// What one bracket produced — and when it produced no sample, WHOSE failure that
/// is.
///
/// The distinction is the difference between a bounded loud failure and a slow
/// quiet one. A round that does not stage because the KERNEL did not produce the
/// race — no overflow, a teardown delivered instead of swallowed, an inode the
/// allocator did not hand back — is an ordinary sampling miss, and sampling again
/// is exactly what the round loop is for. A round that does not stage because the
/// HARNESS could not run the experiment is not a miss at all: the watchdog put the
/// reader back on the fd mid-bracket, or the helper's work failed, or something of
/// the bracket outlived it. Retrying one of those samples nothing, and a later
/// round can then pass over an earlier round's `CLEANUP FAILED` group — while
/// twelve watchdog expiries spend eight minutes arriving at the zero-sample
/// failure that was certain from the first one.
#[derive(Debug)]
enum BracketOutcome {
  /// The reader was off the fd for the whole bracket, the bracket did its work,
  /// and nothing of it outlived the window.
  Staged,
  /// The device could not run the experiment. The string names every measured
  /// cause, so the failure the caller raises says which half of the harness broke
  /// rather than only that no round sampled anything.
  Infrastructure(String),
}

impl StoppedBracket {
  fn refused() -> Self {
    Self {
      stopped_for: None,
      stop_observed: false,
      guard_resumed: false,
      covered: false,
      work_ok: false,
      group_clear: false,
    }
  }

  /// The staging precondition: a round may claim a swallowed teardown only when
  /// the reader was off the fd for the WHOLE bracket, the bracket did its job, and
  /// nothing of the bracket outlived it.
  fn staged(&self) -> bool {
    self.stopped_for.is_some() && self.covered && self.work_ok && self.group_clear
  }

  /// The typed verdict: every way this bracket can fail to stage is the HARNESS
  /// failing, never the kernel declining to produce the race — the scenario is not
  /// sampled until after the bracket returns. So a non-staging bracket names its
  /// causes and the round fails on them at once.
  fn outcome(&self) -> BracketOutcome {
    if self.staged() {
      return BracketOutcome::Staged;
    }
    // A refusal never stopped this process, so nothing downstream is even
    // measured; the refusal's own SKIP line above says which precondition it was.
    if self.stopped_for.is_none() {
      return BracketOutcome::Infrastructure(
        "the device refused to take the stop at all, so no bracket ran".to_owned(),
      );
    }
    let mut causes = Vec::new();
    if self.guard_resumed {
      causes.push(
        "the WATCHDOG ended the stopped window, so the reader was back on the fd while the helper \
         still had work in flight — the teardown this round would have called swallowed may have \
         been drained instead"
          .to_owned(),
      );
    }
    if !self.stop_observed {
      causes.push(
        "the helper never read this process stopped, so it ran no step and the reader was never \
         provably off the fd"
          .to_owned(),
      );
    }
    if !self.work_ok {
      causes.push("the helper's own work did not report success".to_owned());
    }
    if !self.group_clear {
      causes.push(
        "the bracket's process group outlived it, so a surviving step races the fixture release \
         (see the CLEANUP FAILED line above)"
          .to_owned(),
      );
    }
    if causes.is_empty() {
      // Stopped, the helper saw it, its work succeeded and its group is gone — so
      // the only thing missing is the completion token, which the helper writes
      // after its LAST step. Its absence is this side's reading of the pipe having
      // lapsed, not a fact about the kernel.
      causes.push(
        "the helper's completion token never arrived, so the resume could not be placed after the \
         bracket's last step"
          .to_owned(),
      );
    }
    BracketOutcome::Infrastructure(causes.join("; "))
  }
}

/// The bracket helper's script: its resume trap, the readiness token, the
/// stop HANDSHAKE, `steps`, the completion token, the resume.
///
/// # The handshake is an OBSERVATION, not a delay
///
/// The predecessor slept a fixed settle grace and left this side to decide, from a
/// sampled instant, whether the stop had "probably" landed first. It had not
/// always: `READY` is written BEFORE the grace, while the instant it is measured
/// from is sampled only once the parent has read the token out of the pipe, so
/// pipe and scheduling delay were spent on the helper's clock and excluded from
/// the accounting — work long enough still satisfied the arithmetic, and the round
/// still called itself covered.
///
/// So the helper WAITS for the fact instead: it polls `/proc/<parent>/task/*/status`
/// until EVERY thread of the parent — the inotify reader among them — reads
/// `State: T`, reports that with [`STOPPED`], and only then takes its first step.
/// A helper that never observes it runs NO step and exits nonzero. The parent
/// still measures the window's far end (the resume was the helper's own, and the
/// completion token followed the last step), but the near end is no longer an
/// inference.
///
/// Per-thread, not just `/proc/<pid>/status`: a group stop is initiated for every
/// thread and each parks when it next reaches a signal check, so the leader can
/// read `T` while another thread is still in user space. The claim this device
/// makes is about the READER thread, so every thread is what it checks.
///
/// # Bounding what the steps launch
///
/// The device's numbers arrive as shell VARIABLES (`call`, `work`, `nap`, `flood`,
/// and the `tmo` command prefix) computed from [`StopBudget`], so a work snippet
/// holds no constants of its own and every bound inside the helper scales with
/// this binary's clock.
///
/// `tmo` is `timeout --foreground --kill-after=<grace> <call>`, and both flags are
/// load-bearing. Plain GNU `timeout` puts ITSELF in a NEW process group, so the
/// `umount`/`mount`/`rm` it supervises is not in the bracket's group at all and
/// [`terminate_group`]'s `kill(-pgid)` misses it — measured on this container
/// class: after killing the bracket's group, a plain-`timeout` child and its
/// TERM-ignoring grandchild both survived in their own group, while under
/// `--foreground` the same reap left nothing. `--kill-after` is the other half: a
/// command that ignores `TERM` is otherwise bounded by nothing at all.
///
/// The bracket's operands travel as `argv` (`$1`, `$2`), quoted at every use, so
/// `sh` sees one opaque word each whatever bytes they hold. Interpolated, a path
/// holding a quote would break the parse and cost the round its bracket, and one
/// holding `$(...)` would be EXECUTED by a privileged shell — an injection
/// vector, not merely a bug. Only integers this process read from the kernel or
/// computed from the budget are interpolated.
fn stopped_bracket_script(budget: &StopBudget, steps: &str) -> String {
  let pid = std::process::id();
  let call = shell_secs(budget.call);
  let grace = shell_secs(budget.grace);
  let work = shell_secs(budget.work);
  let handshake = shell_secs(budget.handshake);
  // A poll/retry cadence, derived like everything else: the wall-clock bounds are
  // what actually end the loops.
  let nap = shell_frac(budget.poll);
  let flood = STORM_WRITES;
  format!(
    r#"
call={call}
grace={grace}
work={work}
handshake={handshake}
nap={nap}
flood={flood}
tmo="timeout --foreground --kill-after=$grace $call"
rc=1
trap 'st=$?; kill -CONT {pid} 2>/dev/null; exit $st' EXIT HUP INT TERM
printf %s {READY}
observed=0
deadline=$(( $(date +%s) + handshake ))
while :; do
  all=1
  seen=0
  for t in /proc/{pid}/task/*; do
    [ -d "$t" ] || continue
    seen=1
    st=
    while read -r key value _rest; do
      if [ "$key" = "State:" ]; then st=$value; break; fi
    done < "$t/status" 2>/dev/null
    if [ "$st" != T ]; then all=0; break; fi
  done
  if [ $seen -eq 1 ] && [ $all -eq 1 ]; then observed=1; break; fi
  [ "$(date +%s)" -lt $deadline ] || break
  sleep $nap
done
if [ $observed -ne 1 ]; then exit 3; fi
printf %s {STOPPED}
{steps}
printf %s {DONE}
kill -CONT {pid} 2>/dev/null
exit $rc
"#
  )
}

/// Runs one bracket in a HELPER process while every thread of this one — the
/// inotify reader included — is stopped, and reports what the window actually
/// covered.
///
/// # Why the reader is stopped
///
/// Stopping the reader is what stages the swallow, and nothing softer can. The
/// teardown records are dropped only while the kernel queue is FULL, and a
/// running reader empties a 16-slot queue faster than the kernel walks the
/// superblock: measured against a raw inotify group over the same loopback, an
/// actively draining reader received the root's `IN_UNMOUNT`/`IN_IGNORED` as the
/// storm's last two records every single time, while a reader held off the fd
/// across the unmount received exactly 16 records plus the overflow sentinel and
/// never the root's — deterministically, at every tree width tried. The one
/// window a running reader has off the fd is a control batch, and that window is
/// unusable here BY CONSTRUCTION: every arm in flight holds an `O_PATH` anchor on
/// the superblock, which is precisely what makes `umount(2)` answer `EBUSY`. So
/// the reader is stopped instead — a real condition (a descheduled reader on a
/// loaded host, a stopped process) that reaches the kernel and driver state these
/// cells exist to test, with no test hook in the production path.
///
/// # Why no path here can outlive a bound
///
/// * The resume is [`SelfResume`]: armed at the stop, read back from the kernel
///   immediately before it, and repeating. A stop is therefore only ever taken
///   against a guard this process OWNS and has just proven live — not against a
///   helper's promise that may already have been spent.
/// * Readiness, the stop handshake, the completion token, the helper's retry loop,
///   its individual external commands, their hard-kill grace and the reap all bound
///   out of the same [`StopBudget`], so no unscaled constant can gate a scaled
///   wait.
/// * The helper is its own process GROUP and every step it launches stays in that
///   group (`timeout --foreground`), so a reap that has to force the issue
///   terminates the whole bracket rather than the shell alone — never leaving a
///   `umount` in flight against a fixture that is being released — and the reap
///   then VERIFIES the group is empty out of `/proc`
///   ([`bracket_group_cleared`]).
/// * Every refusal returns [`StoppedBracket::refused`] WITHOUT stopping, and
///   every stop is followed by a bounded reap. A stuck helper ends in a loud
///   skip; it can never end in a stopped process.
///
/// # What the report means
///
/// A stop proves nothing on its own — the predecessor's rounds counted a sample
/// whenever the helper merely reported success. [`StoppedBracket::covered`] is
/// what makes the window a witness, and BOTH of its ends are now facts somebody
/// read rather than arithmetic over a sampled instant:
///
/// 1. the helper read every thread of this process out of `/proc` in state `T` and
///    reported it with [`STOPPED`] BEFORE its first step — so the reader was
///    provably off the fd when the bracket began, whatever the pipe and the
///    scheduler cost in between;
/// 2. no expiry of the guard was QUEUED on the stopping thread when the stop
///    lifted — so the resume was the helper's own, not [`SelfResume`]'s. That is
///    the timer's own state answering for itself: the alternative, comparing the
///    window's length against the interval the guard repeats on, compares two
///    different instants (the guard expires a fixed time after the ARM, while the
///    window is measured from the later moment the stop was entered) and nothing
///    bounds the gap, so a window the WATCHDOG cut short could satisfy it. It also
///    pins WHICH stop the helper saw, since generating a stop signal flushes every
///    `SIGCONT` pending before it;
/// 3. the completion token is in hand, and the helper writes it only after its
///    LAST step — so that resume followed the whole bracket.
///
/// A window the guard had to lift, one the helper never saw, or one whose bracket
/// left a process behind is REPORTED rather than silently counted.
fn with_reader_stopped(cell: &str, steps: &str, args: &[&OsStr]) -> StoppedBracket {
  with_reader_stopped_within(cell, steps, args, StopBudget::current())
}

/// [`with_reader_stopped`] on a caller-supplied budget, so a cell can place the
/// guard's expiry relative to its own bracket instead of taking the production
/// relation between the two.
fn with_reader_stopped_within(
  cell: &str,
  steps: &str,
  args: &[&OsStr],
  budget: StopBudget,
) -> StoppedBracket {
  use std::{
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    time::Instant,
  };

  let mut helper = match Command::new("sh")
    .arg("-c")
    .arg(stopped_bracket_script(&budget, steps))
    .arg("reader-stopped-bracket")
    .args(args)
    .stdin(Stdio::null())
    // The token channel. Nothing else in the script writes to stdout, so a dying
    // shell closes this pipe promptly instead of holding it for the budget.
    .stdout(Stdio::piped())
    // Its own process group, so the reap can terminate the WHOLE bracket — the
    // shell and anything it left in flight — instead of the shell alone.
    .process_group(0)
    .spawn()
  {
    Ok(helper) => helper,
    Err(err) => {
      common::skip_notice(format_args!(
        "{cell}: the bracket helper would not spawn: {err}"
      ));
      return StoppedBracket::refused();
    }
  };

  // Readiness first: the helper's resume trap must EXIST before the stop lands,
  // and `spawn` returns the instant fork/exec succeeds — long before `sh` has
  // parsed the script and installed it.
  let ready = helper
    .stdout
    .as_mut()
    .is_some_and(|pipe| read_token(pipe, READY, budget.ready));
  let ready_at = Instant::now();
  if !ready {
    common::skip_notice(format_args!(
      "{cell}: the bracket helper never signalled readiness within {:?}, so the reader was \
       NOT stopped",
      budget.ready
    ));
    // Killed, not waited on: a helper that is alive but silent would otherwise
    // hold the reap for as long as it lives. Safe precisely because this process
    // did NOT stop, so no resume is owed.
    terminate_group(&helper);
    reap_bracket(cell, &mut helper, &budget);
    return StoppedBracket::refused();
  }

  // The resume this process OWNS, armed now and verified live below.
  let resume = match SelfResume::arm(budget.guard, budget.tick) {
    Some(resume) => resume,
    None => {
      common::skip_notice(format_args!(
        "{cell}: no self-resume timer could be armed, so this process must not stop itself"
      ));
      terminate_group(&helper);
      reap_bracket(cell, &mut helper, &budget);
      return StoppedBracket::refused();
    }
  };
  // The last three preconditions, each provable only immediately before the stop:
  // the guard is still counting; the helper has not already exited (its resume is
  // owed, not spent); and enough of the helper's handshake budget is left for it to
  // still be polling when the stop lands. That last one is a conservative REFUSAL,
  // not the covering claim — the claim is the helper's own observation below — so
  // spending the arithmetic here costs a round at worst and can never green one.
  let armed = resume.is_armed();
  let helper_live = matches!(helper.try_wait(), Ok(None));
  let slack = ready_at.elapsed();
  if !armed || !helper_live || slack >= budget.handshake / 2 {
    common::skip_notice(format_args!(
      "{cell}: refusing to stop — self-resume armed: {armed}, helper still running: \
       {helper_live}, handshake budget left: {:?} of {:?}",
      budget.handshake.saturating_sub(slack),
      budget.handshake
    ));
    terminate_group(&helper);
    reap_bracket(cell, &mut helper, &budget);
    return StoppedBracket::refused();
  }

  // The stop. `raise`, NOT `kill(getpid(), ...)`: a stop signal aimed at the
  // PROCESS is handled by whichever thread the kernel elects, so `kill` can
  // return with this thread still running in user space — and `Instant::now()` is
  // a vDSO read that never enters the kernel to notice the stop it just asked
  // for. That measured a 30 µs "stopped window" around a bracket the reader was
  // demonstrably not stopped for, and the round still called itself staged: the
  // exact shape this device exists to make impossible. `raise` targets the
  // CALLING thread, which must therefore handle the signal before returning to
  // user space, so the clock either side of it straddles the real stop. The
  // group-stop action is unchanged — every thread stops, the reader included.
  let entered = Instant::now();
  // SAFETY: a self-directed signal, whose only effect is this process' own job
  // control.
  let sent = unsafe { libc::raise(libc::SIGSTOP) };
  let stopped_for = entered.elapsed();
  // The resume's PROVENANCE, taken out of the kernel's pending-signal state before
  // this side does anything else — before the guard is disarmed, and before any
  // token is looked at, so nothing this process goes on to wait for can change the
  // answer.
  let resumed = resume.resumed_the_stop();
  drop(resume);
  if sent != 0 {
    common::skip_notice(format_args!(
      "{cell}: the self-stop was refused, so the reader stayed on the fd"
    ));
    terminate_group(&helper);
    reap_bracket(cell, &mut helper, &budget);
    return StoppedBracket::refused();
  }

  // Did the stopped window really COVER the bracket? The near end is a fact the
  // HELPER observed, the far end one the KERNEL reported, and neither is trusted
  // alone:
  //
  //  * the helper read every thread of this process in state `T` — reported as
  //    [`STOPPED`], written before its first step — so the reader was off the fd
  //    when the bracket began. The token is read only now, after the resume,
  //    because a stopped process cannot read a pipe;
  //  * no expiry of the guard was queued when the stop lifted, so the resume was
  //    the helper's own rather than [`SelfResume`]'s — the guard's own signal, not
  //    a window length standing in for it. That also pins WHICH stop the helper
  //    saw: a stop signal flushes every `SIGCONT` generated before it, so anything
  //    the drain found belonged to THIS window, and exactly one stop spanned this
  //    bracket;
  //  * the completion token is in hand, and the helper writes it only after its
  //    LAST step — so that resume followed the whole bracket.
  let stop_observed = helper
    .stdout
    .as_mut()
    .is_some_and(|pipe| read_token(pipe, STOPPED, budget.token));
  let helper_resumed = !resumed.by_guard;
  let done = stop_observed
    && helper
      .stdout
      .as_mut()
      .is_some_and(|pipe| read_token(pipe, DONE, budget.token));
  let covered = stop_observed && helper_resumed && done;
  if !covered {
    eprintln!(
      "NOTE {cell}: the stopped window did not cover the bracket (stopped for {stopped_for:?}, \
       {slack:?} after readiness, handshake budget {:?}, guard's first expiry {:?} repeating every \
       {:?}; the helper OBSERVED this process stopped before its first step: {stop_observed}, an \
       expiry of the guard was queued when the stop lifted: {} (carrying this guard's own tag: {}, \
       SIGCONT instances accepted: {}), completion token seen: {done}) — so this round stages \
       nothing",
      budget.handshake, budget.guard, budget.tick, resumed.by_guard, resumed.tagged, resumed.queued
    );
  }
  let reaped = reap_bracket(cell, &mut helper, &budget);
  StoppedBracket {
    stopped_for: Some(stopped_for),
    stop_observed,
    guard_resumed: resumed.by_guard,
    covered,
    work_ok: reaped.status.is_some_and(|status| status.success()),
    group_clear: reaped.group_clear,
  }
}

/// The bracket's `umount`/`mount` steps: cycle the SAME loop device's mount, so
/// the root's `(dev, ino)` survives while every inotify watch on the superblock
/// is destroyed. `$1` is the mount point, `$2` the loop device.
///
/// Bounded twice over: the retry loop ends at a wall-clock deadline rather than
/// after a guessed iteration count, and each attempt is itself bounded through
/// `$tmo` — which also keeps it inside the bracket's process group, so the reap
/// reaches it (see [`stopped_bracket_script`]) — so neither a permanently busy
/// mount nor a single `umount` that never returns can stretch the window the guard
/// is sized for or outlive the bracket.
const CYCLE_MOUNT_STEPS: &str = r#"
deadline=$(( $(date +%s) + work ))
while :; do
  if $tmo umount "$1"; then rc=0; break; fi
  [ "$(date +%s)" -lt $deadline ] || break
  sleep $nap
done
if [ $rc -eq 0 ]; then $tmo mount "$2" "$1" || rc=2; fi
"#;

/// The bracket's storm-and-swap steps: fill the 16-slot queue nobody is draining,
/// then free and re-take the mid-tree directory's inode inside that lossy window.
/// `$1` is the watched root, `$2` the mid-tree directory.
///
/// The storm is builtin-only (a redirect per create, no fork), so its cost is a
/// bounded number of syscalls, and each of the three external steps is bounded on
/// its own. Freeing the storm's inodes BEFORE the directory's leaves that
/// directory's inode as the lowest free one, which is what the allocator hands
/// back to the recreate.
const RECREATE_MIDTREE_STEPS: &str = r#"
i=0
while [ $i -lt $flood ]; do
  : > "$1/stormy-$i"
  i=$((i+1))
done
$tmo rm -f "$1"/stormy-* \
  && $tmo rm -rf "$2" \
  && $tmo mkdir "$2" \
  && rc=0
"#;

/// The provenance cell's bracket: ONE bounded step that occupies the window for
/// the helper's whole `work` bound and touches no filesystem at all, so the only
/// thing the round can be about is which resume ended the stop.
///
/// The stall arrives as a shell VARIABLE like every other bound in this device, so
/// the snippet holds no constant of its own and the cell can place it on either
/// side of the guard's first expiry. It is bounded twice over as usual — by `$tmo`
/// on the call and by `work` on the sleep itself — and exits zero, which is what
/// makes the watchdog leg's verdict rest on provenance alone rather than on a
/// helper that also happened to fail.
const STALL_ONE_STEP: &str = r#"
$tmo sleep $work && rc=0
"#;

/// Terminates the bracket helper's whole process GROUP.
///
/// `process_group(0)` made the child a group leader, so its pid IS the group id
/// and the negated pid reaches the shell AND every command it left in flight —
/// the difference between a reap that ends the bracket and one that leaves a
/// `umount` racing the fixture's release. Only ever called on an UNREAPED child,
/// so the group id still belongs to this bracket.
fn terminate_group(helper: &std::process::Child) {
  if let Ok(pid) = i32::try_from(helper.id()) {
    // SAFETY: a signal to a process group this process created and has not yet
    // reaped.
    unsafe {
      libc::kill(-pid, libc::SIGKILL);
    }
  }
}

/// Every process still in process group `pgid`, as `pid(comm)` — read out of
/// `/proc`, never inferred from a kill's return value.
///
/// `/proc/<pid>/stat`'s second field is `comm` in parentheses and may itself hold
/// spaces AND parentheses, so the fields after it are located from the LAST `)`
/// rather than by splitting the whole line: state, ppid, then pgrp.
fn group_members(pgid: i32) -> Vec<String> {
  let Ok(entries) = std::fs::read_dir("/proc") else {
    // An unreadable `/proc` has proven nothing; name that rather than reporting
    // an empty group, which is what the caller treats as success.
    return vec!["/proc is unreadable, so the group could not be verified".to_owned()];
  };
  let mut members = Vec::new();
  for entry in entries.flatten() {
    let name = entry.file_name();
    let Some(pid) = name.to_str().and_then(|n| n.parse::<i32>().ok()) else {
      continue;
    };
    let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
      continue;
    };
    let Some((head, tail)) = stat.rsplit_once(')') else {
      continue;
    };
    let comm = head.split_once('(').map_or("?", |(_, c)| c).to_owned();
    if tail.split_whitespace().nth(2).and_then(|f| f.parse().ok()) == Some(pgid) {
      members.push(format!("{pid}({comm})"));
    }
  }
  members
}

/// Verifies that NOTHING of the bracket outlived it, hard-killing by PID whatever
/// did, and reports what it could not clear.
///
/// The verification is the point, not the kill: a reap that only sends a signal has
/// proven nothing, and the fixture release that follows is about to unmount the
/// filesystem a surviving `umount`/`mount` is still working on. Killing by pid
/// rather than by group here is deliberate — the group LEADER has been reaped by
/// this point, so its pid (which is the group id) is no longer guaranteed to name
/// this bracket, while every pid enumerated above was read with `pgrp == pgid` a
/// moment earlier.
///
/// The scan is by process GROUP, which is exactly why the helper's steps run under
/// `timeout --foreground` (see [`stopped_bracket_script`]): a step that put itself
/// in its own group would be invisible here.
fn bracket_group_cleared(cell: &str, pgid: i32, budget: &StopBudget) -> bool {
  let mut residue = Vec::new();
  for _ in 0..CLEANUP_ATTEMPTS {
    residue = group_members(pgid);
    if residue.is_empty() {
      return true;
    }
    for member in &residue {
      if let Some(pid) = member
        .split_once('(')
        .and_then(|(pid, _)| pid.parse::<i32>().ok())
      {
        // SAFETY: a signal to a pid this process read out of `/proc` carrying the
        // bracket's own process group id.
        unsafe {
          libc::kill(pid, libc::SIGKILL);
        }
      }
    }
    std::thread::sleep(budget.poll);
  }
  eprintln!(
    "CLEANUP FAILED {cell}: the bracket's process group {pgid} still holds {} after \
     {CLEANUP_ATTEMPTS} kill passes — the fixture release that follows may race it: {}",
    residue.len(),
    residue.join(", ")
  );
  false
}

/// Reaps `helper` within `budget`, or `None` once the wait itself lapsed.
///
/// Polled rather than blocked: a `wait` on a helper that never finishes is the
/// same unbounded path as a stop with no resume, one step later.
fn wait_within(
  helper: &mut std::process::Child,
  budget: Duration,
) -> Option<std::process::ExitStatus> {
  use std::time::Instant;
  let deadline = Instant::now() + budget;
  // A polling cadence derived from the budget it polls, so it scales with it. The
  // floor only keeps the loop from spinning; the deadline is what bounds the wait.
  let cadence = (budget / 256).max(Duration::from_millis(1));
  loop {
    match helper.try_wait() {
      Ok(Some(status)) => return Some(status),
      Ok(None) => {}
      Err(_) => return None,
    }
    if Instant::now() >= deadline {
      return None;
    }
    std::thread::sleep(cadence);
  }
}

/// What one reap achieved: the helper's exit status when it could be reaped at all,
/// and whether the bracket's whole process GROUP is provably gone.
struct Reaped {
  status: Option<std::process::ExitStatus>,
  group_clear: bool,
}

/// Reaps the bracket helper, escalating to its process group, and VERIFIES that
/// nothing of the bracket remains — reporting loudly rather than blocking if even
/// that does not take.
///
/// The escalation and the verification both matter for the fixture, not just for
/// this round: the helper's steps hold the mount the caller is about to release, so
/// they must be provably gone — not merely signalled — before the release runs. A
/// group leader that exits while a supervised `umount` runs on is the shape that
/// leaves a mount racing its own teardown, and `wait` on the leader says nothing
/// about it.
fn reap_bracket(cell: &str, helper: &mut std::process::Child, budget: &StopBudget) -> Reaped {
  let pgid = i32::try_from(helper.id()).ok();
  let mut status = wait_within(helper, budget.reap);
  if status.is_none() {
    eprintln!(
      "NOTE {cell}: the bracket helper outlived its {:?} reap budget — terminating its process \
       group",
      budget.reap
    );
    terminate_group(helper);
    status = wait_within(helper, budget.call);
    if status.is_none() {
      eprintln!(
        "CLEANUP FAILED {cell}: the bracket helper could not be reaped even after its process \
         group was killed — left unreaped rather than blocking the suite, and the fixture release \
         that follows may race whatever it still holds"
      );
    }
  }
  // The leader is gone (or reported); now prove the same of everything it left
  // behind. A group id this side could not read is not a clean group.
  let group_clear = pgid.is_some_and(|pgid| bracket_group_cleared(cell, pgid, budget));
  Reaped {
    status,
    group_clear,
  }
}

/// Waits (bounded) for `token` on `pipe`.
///
/// Bounded by polling rather than a plain `read`, because a helper that is alive
/// but silent would block this side forever — trading the stopped-with-no-guard
/// wedge for a blocked-before-the-stop one. A closed pipe (the helper died) and
/// a lapsed budget both answer `false`.
fn read_token(pipe: &mut std::process::ChildStdout, token: &str, budget: Duration) -> bool {
  use std::{io::Read, os::fd::AsRawFd, time::Instant};

  let fd = pipe.as_raw_fd();
  let deadline = Instant::now() + budget;
  let mut seen = Vec::with_capacity(token.len());
  while seen.len() < token.len() {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
      return false;
    }
    let mut poll_fd = libc::pollfd {
      fd,
      events: libc::POLLIN,
      revents: 0,
    };
    // SAFETY: one initialized `pollfd` over a descriptor this process owns for
    // the whole call, with a matching count of 1.
    let waited = unsafe {
      libc::poll(
        &mut poll_fd,
        1,
        left.as_millis().min(i32::MAX as u128) as i32,
      )
    };
    if waited == 0 {
      return false;
    }
    if waited < 0 {
      if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
        continue;
      }
      return false;
    }
    let mut byte = [0u8; 1];
    match pipe.read(&mut byte) {
      // EOF: the helper is gone without having written this token.
      Ok(0) => return false,
      Ok(_) => seen.push(byte[0]),
      Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
      Err(_) => return false,
    }
  }
  seen == token.as_bytes()
}

/// Wall-clock ceiling on an INV-BIND cell's whole round loop, scaled with every
/// other budget here.
///
/// The rounds are samples of a race, so their COUNT is the wrong bound on the time
/// they may take: a round that ends in an ordinary miss costs seconds, while one
/// that has to wait out a bound costs a minute, and the difference is not visible
/// from the loop's head. A pathological run therefore has to become a loud BOUNDED
/// failure rather than a slow one — the whole reason an infrastructure failure
/// fails at once is that a run must not spend its budget arriving at a verdict
/// that was already certain, and this is the same rule applied to the misses.
///
/// Checked at the round BOUNDARY, so the real ceiling is this plus at most one
/// round: a round already in flight is never cut short, because a half-sampled
/// round is one nothing can be judged from. It can only ever shorten a run that is
/// going to FAIL — a run that stages and reaches the live ending leaves the loop
/// on its own — so no verdict here can turn green on the deadline.
///
/// A healthy privileged run stages in its first round and spends about four
/// seconds in the loop, so this is two orders of margin over the case it must not
/// disturb.
const CELL_BUDGET: Duration = Duration::from_secs(300);

/// Suite 12 (privileged): the overflow-swallowed unmount, INV-BIND's W1 arm. A
/// whole-superblock `umount(2)` over a wide watched tree is its own storm: two
/// teardown records per watch into a 16-slot queue NOBODY IS DRAINING (the reader
/// is stopped across the cycle — see [`with_reader_stopped`]), so the
/// queue overflows within the first handful and the root inode, the LAST one the
/// kernel walks, has its `IN_UNMOUNT`/`IN_IGNORED` dropped with everything else,
/// while the remount restores the SAME `(dev, ino)` at the path. Nothing tells
/// the Monitor its root watch died: the binding is RETAINED on a kernel-dead
/// watch, and only the overflow sentinel's covering loss says coverage was lost
/// at all.
///
/// That retained binding is exactly what the identity-sampling recovery of old
/// kept — a settleable barrier over a root that could never deliver again. The
/// acknowledged re-add must re-prove it: a root-level create after the recovery
/// is observed by its OWN event (only a re-bound kernel watch can produce one),
/// and a sync cookie's own event certifies only a world that also shows it.
/// Exactly ONE opening `Rescan` followed by silence over the live-looking root is
/// the dark ending this cell exists to refuse.
///
/// A round whose teardown records were NOT swallowed is a DIFFERENT scenario —
/// the root died loudly and the scope went terminal — so it is reported as a NOTE
/// and does not count as a sample of the swallow. It is still held to the honesty
/// invariant: a covering `Rescan` must stand for the gap either way.
///
/// The recycled-inode sibling of this arm is
/// `overflow_swallowed_recreate_rebinds_the_midtree_watch`, which swallows the
/// teardown of a MID-TREE watch instead of the root's.
///
/// wd-reuse aliasing (a recycled kernel `wd` fanning onto a stale anchor)
/// stays HERMETIC-ONLY: the cyclic idr makes a real trigger infeasible
/// (~2^31 arms), so that closure is pinned by the `WdTable` collision cells,
/// not here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overflow_swallowed_unmount_rebinds_or_dies_loudly() {
  if !privileged_or_skip("overflow_swallowed_unmount_rebinds_or_dies_loudly") {
    return;
  }
  // Wide enough for `UNMOUNT_STORM_DIRS` directories plus the rounds' probe
  // files: ext4's default bytes-per-inode leaves a 16 MiB image with ~1k inodes.
  // Both fixtures are RAII from the moment they are acquired: every assertion
  // below is inside a round, so the unwind a real defect causes must still
  // unmount, detach and put the sysctl back.
  let Some(fixture) = loop_image("inv-bind-w1", 64) else {
    return;
  };
  let loopdev = fixture.loopdev().to_owned();
  let mount = fixture.mount().to_path_buf();
  let Some(tail) = wide_tree(&mount, UNMOUNT_STORM_DIRS) else {
    common::skip_notice(format_args!(
      "overflow_swallowed_unmount_rebinds_or_dies_loudly: the loopback could not hold \
       {UNMOUNT_STORM_DIRS} directories"
    ));
    fixture.close();
    return;
  };
  let queue = SysctlGuard::swap("fs/inotify/max_queued_events", "16").expect("shrink queue");

  let mut honest = false;
  // A round STAGES only when the unmount's teardown really was swallowed: the
  // scope survived the cycle with its root binding intact. Distinguishing that
  // from a loudly-killed root is what keeps the closing assertion's claim true.
  let mut staged = 0usize;
  let mut live_rounds = 0usize;
  let mut loud_deaths = 0usize;
  let mut budget_spent = false;
  const ROUNDS: usize = 3;
  let deadline = std::time::Instant::now() + scaled(CELL_BUDGET);
  for round in 0..ROUNDS {
    if std::time::Instant::now() >= deadline {
      eprintln!(
        "NOTE overflow_swallowed_unmount_rebinds_or_dies_loudly: the cell's {:?} budget lapsed \
         with {round} of {ROUNDS} rounds run; the remaining rounds are not attempted",
        scaled(CELL_BUDGET)
      );
      budget_spent = true;
      break;
    }
    let mut w = inotify_watcher();
    let handle = match w.watch(&mount, Interest::all()).await {
      Ok(handle) => handle,
      Err(err) => {
        common::skip_notice(format_args!(
          "overflow_swallowed_unmount_rebinds_or_dies_loudly: round {round}: watch refused: {err:?}"
        ));
        continue;
      }
    };
    if !coverage_becomes_live(&mut w, &mount, &format!("birth-{round}")).await {
      common::skip_notice(format_args!(
        "overflow_swallowed_unmount_rebinds_or_dies_loudly: round {round}: coverage never became live"
      ));
      let _ = w.close().await;
      continue;
    }
    // The descent must have covered the width and released every anchor before
    // the cycle: an arm still in flight holds an `O_PATH` anchor on the
    // superblock, which makes `umount(2)` EBUSY and costs the round its bracket.
    if !coverage_becomes_live(&mut w, &tail, &format!("tail-{round}")).await {
      common::skip_notice(format_args!(
        "overflow_swallowed_unmount_rebinds_or_dies_loudly: round {round}: the descent never \
         reached the tree's tail"
      ));
      let _ = w.close().await;
      continue;
    }
    if !descent_releases_its_anchors(&mount).await {
      common::skip_notice(format_args!(
        "overflow_swallowed_unmount_rebinds_or_dies_loudly: round {round}: the descent still \
         holds anchors on the superblock"
      ));
      let _ = w.close().await;
      continue;
    }
    // Everything classified below must be the BRACKET's traffic, not the liveness
    // handshakes' residue.
    if !stream_goes_quiet(&mut w).await {
      common::skip_notice(format_args!(
        "overflow_swallowed_unmount_rebinds_or_dies_loudly: round {round}: the stream never went \
         quiet before the bracket"
      ));
      let _ = w.close().await;
      continue;
    }

    // The bracket: cycle the mount with the reader stopped. The unmount's own
    // per-watch teardown storm overflows the 16-slot queue nobody is draining,
    // the root's records drop with it, and the remount restores the same
    // identity before the reader resumes and the recovery's re-add can run.
    //
    // A bracket the stopped window did not COVER is not this scenario, and it is
    // not a sampling miss either: every way this bracket fails to stage is the
    // DEVICE failing to run the experiment (see [`BracketOutcome`]), so the round
    // closes the watcher — which is what unpins the mount for the fixture release
    // the unwind is about to run — and fails at once naming the cause, rather than
    // retrying until the rounds are spent and blaming the empty sample count.
    let bracket = with_reader_stopped(
      &format!("overflow_swallowed_unmount_rebinds_or_dies_loudly: round {round} mount cycle"),
      CYCLE_MOUNT_STEPS,
      &[mount.as_os_str(), OsStr::new(&loopdev)],
    );
    if let BracketOutcome::Infrastructure(cause) = bracket.outcome() {
      let _ = w.close().await;
      panic!(
        "round {round}: the reader-stopped mount cycle could not be run, so this cell's experiment \
         never happened — an infrastructure failure is not a sampling miss and retrying it would \
         only spend the remaining rounds arriving at a zero-sample verdict: {cause} ({bracket:?})"
      );
    }

    // The loss must have surfaced at all (the opening Rescan); a round whose
    // storm never overflowed is not a sample of this race. Everything the same
    // pass and the probes below see is classified into one accumulator, so the
    // recovery's own later signals (a closing Rescan, a death funnel's terminal
    // cover) are counted wherever they land.
    //
    // The plain accumulator here, not the child-subject one: this cell's subject IS
    // the root, whose teardown the public stream states outright (an unconditional
    // `Rescan` plus the root invalidation `retained` reads below), so it needs no
    // stand-in for a silent record — and its "own watch" spans the whole tree, whose
    // ordinary traffic is not teardown evidence.
    let mut signals = LossSignals::default();
    if !observe_loss_at(&mut w, &mount, Duration::from_secs(3), &mut signals).await {
      common::skip_notice(format_args!(
        "overflow_swallowed_unmount_rebinds_or_dies_loudly: round {round}: no overflow observed"
      ));
      let _ = w.close().await;
      continue;
    }
    // Which arm this round sampled. A RETAINED root binding is the swallow: no
    // teardown record ever reached the Monitor, so nothing invalidated the root
    // and the handle still reports it. A terminal scope means the teardown DID
    // arrive — the root died loudly, which is honest but is the other arm.
    let retained = w.root_path(handle) == Some(mount.clone());

    // The verdict probe: a root-level create after the recovery, witnessed by
    // its OWN delivered event — only a re-bound binding can produce it. A
    // loud cover (a closing/terminal Rescan, whenever it lands) is the dead
    // honest ending. Silence over exactly the opening Rescan is the dark
    // root.
    let live = probe_verdict(&mut w, &mount, &format!("verdict-{round}"), &mut signals).await;
    assert!(
      live || signals.loud_covers() > 0,
      "round {round}: the recovery neither re-bound the root nor stood a loud cover — \
       the overflow-swallowed unmount left a dark root"
    );
    if !retained {
      eprintln!(
        "NOTE round {round}: the unmount's teardown reached the Monitor and retired the root, so \
         the root died loudly and this round did not sample the swallow"
      );
      loud_deaths += 1;
      let _ = w.close().await;
      continue;
    }
    staged += 1;
    // The staging witness, symmetric with the loud-death NOTE above: the
    // bracket really did swallow the teardown (the root binding is RETAINED
    // across the cycle), and this is what the recovery then had to re-prove.
    // Reported with the window that made it possible — the reader was off the fd
    // for that long, and the cycle ran inside it.
    eprintln!(
      "NOTE round {round}: STAGED the swallow — root binding retained across the mount cycle \
       (reader off the fd for {:?}), live re-bind observed: {live}",
      bracket.stopped_for.unwrap_or_default()
    );

    if live {
      // The certification witness: a sync cookie's own event must ride the same
      // re-proven binding, so a certified barrier cannot stand over an
      // unobservable root. BOTH halves are REQUIRED — the barrier must be
      // admitted and resolve, and its cookie's own event must come back — and
      // `honest` is set only behind both. A barrier this cell could not certify
      // is this cell's failure; skipping past it would leave the round counted
      // green with no certification witness at all.
      //
      // The await is BOUNDED because the barrier parks on the coverage-settle
      // fence the binding re-proof is supposed to release: a barrier that never
      // resolves is precisely the defect under test, and an unbounded await
      // would wedge this single-threaded binary instead of reporting it.
      let (admission, _ticket) = w.mint_sync_ticket();
      let synced = tokio::time::timeout(
        scaled(DEADLINE),
        w.sync_root(
          handle,
          &mount,
          format!(".tributaries-sync-w1-{round}"),
          admission,
        ),
      )
      .await;
      let cookie = match synced {
        Ok(Ok(cookie)) => cookie,
        Ok(Err(denied)) => panic!(
          "round {round}: the barrier over the re-proven binding must be ADMITTED and write its \
           cookie — a rejection leaves the re-bind uncertified: {denied:?}"
        ),
        Err(_) => panic!(
          "round {round}: the barrier over the re-proven binding must RESOLVE within the \
           deadline — a barrier parked on a fence the re-proof never released is the very \
           false certification this cell exists to refuse"
        ),
      };
      assert!(
        wait_for(&mut w, |e| e.path() == cookie).await.is_some(),
        "round {round}: the sync cookie's event must come back through the re-proven binding"
      );
      w.request_remove_cookie(cookie);
      live_rounds += 1;
      honest = true;
    }
    let _ = w.close().await;
    if honest {
      break;
    }
  }

  queue.close();
  fixture.close();
  // Both endings stay failures — a run that staged nothing has lost this cell's
  // coverage, which must be loud, not silently green — but only one of them may
  // claim the recovery was exercised and came up short.
  let verdict = if staged == 0 {
    "no round staged the swallow, so this run lost the cell's coverage and says nothing about \
     the recovery — see the SKIP/NOTE lines for which precondition failed or which arm the \
     unmount took"
  } else {
    "the staged rounds stood only loud covers, never a live re-bound root — the recovery never \
     re-proved the retained binding"
  };
  assert!(
    honest,
    "staged {staged} of {ROUNDS} rounds ({loud_deaths} died loudly instead, cell budget lapsed: \
     {budget_spent}), {live_rounds} reached the live re-bound ending: {verdict}"
  );
}

/// `path`'s inode number, or `None` when it could not be read. Kept explicit
/// because the recycle test below compares two readings: comparing two
/// `Result`s' `ok()` would let a PAIR of failed reads (`None == None`) certify a
/// recycle that was never observed.
fn inode_of(path: &Path) -> Option<u64> {
  use std::os::unix::fs::MetadataExt;
  std::fs::metadata(path).ok().map(|m| m.ino())
}

/// Suite 13 (privileged): the recycled-inode sibling — a mid-tree directory
/// rmdir'd and recreated inside the overflow bracket. ext4's allocator hands
/// the freed inode back on a quiet filesystem, so the recovery's identity match
/// would have kept the OLD (kernel-dead) watch; the acknowledged re-add re-binds
/// it. Honest endings as in the unmount cell: the probe under the recreated
/// directory is observed, or a loud cover already stood.
///
/// # Why the bracket runs with the reader stopped
///
/// This cell takes the SAME shape as its unmount sibling, for the same reason.
/// With the reader live across the storm it drains the overflow, takes the
/// directory's teardown normally, and ordinary reconciliation restores coverage —
/// after which the exact-path probe passes and the inode still reads as recycled,
/// so the round LOOKS staged while never having exercised a retained binding at
/// all. So the storm, the removal and the recreate all run in a helper while
/// every thread of this process is stopped ([`with_reader_stopped`]): the queue is
/// full and undrained when the directory's `IN_DELETE_SELF`/`IN_IGNORED` are
/// generated, so the kernel destroys them and the Monitor is never told.
///
/// # The premise: there has to BE a child binding
///
/// Everything below re-proves a binding the recovery RETAINED, so the round's
/// first obligation is a positive observation that the binding EXISTS — the
/// directory's own kernel watch delivering an exact, non-`Rescan` event for a
/// fresh probe under it ([`child_watch_delivers`]).
///
/// An ancestor `Rescan` can never stand in for that, and not merely because it is
/// weaker. If the initial `AddWatch` for the directory FAILS, the Monitor's answer
/// is a located `Rescan` and a dropped subtree — so a covering `Rescan` is the
/// signal that the child watch is ABSENT. A prerequisite that accepted it would
/// pass exactly when the premise is false, and the whole round then reads as a
/// clean sample: with no child watch there is no teardown record for the overflow
/// to swallow, so nothing contradicts the swallow, the recovery's re-enumeration
/// discovers the directory for the FIRST time, and the verdict probe comes back
/// live off that fresh arm. Every fact the cell measures would agree, and none of
/// them would be about retained-binding reproof.
///
/// This is the third depth at which this property has been claimable without being
/// held — staging once counted a non-recycled inode, then a teardown that was
/// never swallowed, now a child that was never watched at all — so the guard is
/// placed at the PREMISE rather than added as another check at the perimeter.
///
/// # The retention witness
///
/// A child binding has no public accessor — [`TokioWatcher::root_path`] reports
/// the SCOPE's root, which this bracket never touches — so the witness the
/// unmount cell reads off one query is assembled here from facts the round
/// MEASURES (all of them presupposing the premise above):
///
/// 1. the bracket ran strictly inside the stopped window — the stop provably
///    landed before the storm's first write and the resume provably came from the
///    helper's own post-work signal ([`StoppedBracket::covered`]);
/// 2. the queue provably overflowed inside that window (the opening `Rescan`), and
///    a queue nobody drains never empties, so every record generated after it —
///    the directory's teardown among them — was destroyed;
/// 3. the SCOPE's own root binding is still retained across the loss window, so
///    the bindings this round reasons about still exist to be re-proven;
/// 4. the stream said NOTHING about the directory in the bracket's window — neither
///    a record located AT it (the parent watch's own removal/(re)creation verbs) nor
///    a record delivered BY it (its own watch's traffic). Either CONTRADICTS 1+2 —
///    it is the Monitor being told exactly what the swallow is supposed to have
///    destroyed — and either alone retires the round. The second arm is what covers
///    a delivered non-root `IN_IGNORED`, which the public stream does not state
///    outright; see [`LossSignals`] for why, and for what it is entailed by.
///
/// 1 ∧ 2 ∧ 3 is the same fact `root_path` stands for in the sibling: no teardown
/// record reached the Monitor, so the binding it holds for the directory is the
/// RETAINED, kernel-dead one the acknowledged re-add must re-prove. 4 is the
/// falsifier that keeps that a claim under test rather than an argued one, and the
/// round's stream is drained to quiet before the bracket
/// ([`stream_goes_quiet`]) so what it counts is the bracket's traffic and nothing
/// else.
///
/// A round only STAGES with all four AND the allocator really handing the inode
/// back. With a CHANGED inode the recovery's identity DIFF replaces the watch
/// through ordinary reconciliation — a live probe there is that other path's
/// result and says nothing about the retained binding — so such a round is
/// reported and dropped rather than counted. A run that stages nothing fails
/// loudly instead of certifying the unstaged arm's result.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overflow_swallowed_recreate_rebinds_the_midtree_watch() {
  if !privileged_or_skip("overflow_swallowed_recreate_rebinds_the_midtree_watch") {
    return;
  }
  // RAII from acquisition, as in the unmount cell: the per-round assertions
  // unwind past any manual cleanup placed after the loop.
  let Some(fixture) = loop_image("inv-bind-w2", 64) else {
    return;
  };
  let mount = fixture.mount().to_path_buf();
  let queue = SysctlGuard::swap("fs/inotify/max_queued_events", "16").expect("shrink queue");

  let mut honest = false;
  // A round STAGES only when the reader was off the fd for the WHOLE bracket, the
  // overflow swallowed the teardown, the scope's own binding survived the loss
  // window, nothing contradicted the swallow, AND the allocator handed the freed
  // inode back — the facts that together put the recovery on the identity-match
  // keep. Anything less is a different scenario, so the closing assertion can tell
  // lost coverage from a recovery that ran and came up short.
  let mut staged = 0usize;
  let mut live_rounds = 0usize;
  let mut identity_diffs = 0usize;
  let mut not_retained = 0usize;
  let mut budget_spent = false;
  const ROUNDS: usize = 12;
  // The subject directory sits one level BELOW the watched root, which is what
  // makes the recycle the allocator's ordinary answer instead of a coin flip:
  // ext4 places a TOP-LEVEL directory with the Orlov allocator's random group
  // spread, so a directory whose parent is the filesystem root lands in an
  // arbitrary group each time it is created — measured here as inode 12 before
  // the swap and 2049 after, on a 64 MiB image with eight groups. Under a
  // non-root parent the search starts from the parent's own group instead, and the
  // recreate is handed the lowest free inode there: the one the removal just
  // freed. Being a grandchild of the root also makes it a plainer MID-TREE watch.
  let tree = mount.join("tree");
  std::fs::create_dir_all(&tree).expect("subject parent");
  let deadline = std::time::Instant::now() + scaled(CELL_BUDGET);
  for round in 0..ROUNDS {
    if std::time::Instant::now() >= deadline {
      eprintln!(
        "NOTE overflow_swallowed_recreate_rebinds_the_midtree_watch: the cell's {:?} budget lapsed \
         with {round} of {ROUNDS} rounds run; the remaining rounds are not attempted",
        scaled(CELL_BUDGET)
      );
      budget_spent = true;
      break;
    }
    // Each round starts from a tree the previous one did not leave behind: the
    // directory it left holds the very inode this round's recreate must be handed
    // back, and its verdict probes sit above it.
    if round > 0 {
      let _ = std::fs::remove_dir_all(tree.join(format!("mid-{}", round - 1)));
    }
    let mid = tree.join(format!("mid-{round}"));
    std::fs::create_dir_all(&mid).expect("mid dir");
    let mut w = inotify_watcher();
    let handle = match w.watch(&mount, Interest::all()).await {
      Ok(handle) => handle,
      Err(err) => {
        common::skip_notice(format_args!(
          "overflow_swallowed_recreate_rebinds_the_midtree_watch: round {round}: watch refused: \
           {err:?}"
        ));
        continue;
      }
    };
    // The child's OWN watch must be provably DELIVERING before the loss window —
    // see this cell's header for why an ancestor `Rescan` may not stand in for
    // that, and [`child_watch_delivers`] for why only the exact path can say it.
    // A binding that never armed would be trivially "retained", and the round
    // would witness nothing.
    if !child_watch_delivers(&mut w, &mid, &format!("birth-{round}")).await {
      common::skip_notice(format_args!(
        "overflow_swallowed_recreate_rebinds_the_midtree_watch: round {round}: the directory's \
         own watch never delivered an exact event, so it has no binding for this round to retain"
      ));
      let _ = w.close().await;
      continue;
    }
    // The descent must have released its anchors before the swap: an `O_PATH`
    // anchor still held on `mid` keeps its inode allocated across the rmdir, so
    // the recreate is handed a DIFFERENT inode and the round samples the
    // identity-diff arm instead of the keep this cell is about.
    if !descent_releases_its_anchors(&mount).await {
      common::skip_notice(format_args!(
        "overflow_swallowed_recreate_rebinds_the_midtree_watch: round {round}: the descent still \
         holds anchors on the superblock"
      ));
      let _ = w.close().await;
      continue;
    }
    // The falsifier below reads deliveries from the subject's OWN watch as teardown
    // evidence, so the birth handshake's residue must be off the stream first.
    if !stream_goes_quiet(&mut w).await {
      common::skip_notice(format_args!(
        "overflow_swallowed_recreate_rebinds_the_midtree_watch: round {round}: the stream never \
         went quiet before the bracket"
      ));
      let _ = w.close().await;
      continue;
    }

    // The bracket, run with the reader OFF THE FD for all of it: storm the queue,
    // then swap the directory's inode inside the lossy window. The teardown
    // records are generated against a full queue nobody is draining, so the
    // kernel destroys them; the name persists, and the freed inode is the
    // allocator's next candidate.
    //
    // `rm -rf` rather than a bare rmdir because the liveness handshake above left
    // its probe files inside `mid`: a plain removal fails ENOTEMPTY, the recreate
    // then fails EEXIST, and every round skips without ever swapping an inode.
    // Those probes are incidental — freeing the directory's inode is the point.
    let ino_before = inode_of(&mid);
    let bracket = with_reader_stopped(
      &format!(
        "overflow_swallowed_recreate_rebinds_the_midtree_watch: round {round} storm-and-swap"
      ),
      RECREATE_MIDTREE_STEPS,
      &[mount.as_os_str(), mid.as_os_str()],
    );
    // Not a sampling miss: every way this bracket fails to stage is the DEVICE
    // failing to run the experiment (see [`BracketOutcome`]) — a watchdog-resumed
    // window may have let the reader drain the very teardown the round is about to
    // call swallowed, and a group that outlived the bracket is a surviving `rm`
    // racing the fixture release. So the round closes the watcher and fails at
    // once, instead of retrying an experiment that never ran until the rounds are
    // spent and the empty sample count takes the blame.
    if let BracketOutcome::Infrastructure(cause) = bracket.outcome() {
      let _ = w.close().await;
      panic!(
        "round {round}: the reader-stopped storm-and-swap could not be run, so this cell's \
         experiment never happened — an infrastructure failure is not a sampling miss and retrying \
         it would only spend the remaining rounds arriving at a zero-sample verdict: {cause} \
         ({bracket:?})"
      );
    }
    // Both readings must have SUCCEEDED and matched. A recycle is a positive
    // observation, never the absence of a contrary one.
    let ino_after = inode_of(&mid);
    let recycled = ino_before.is_some() && ino_after == ino_before;

    // The loss must have surfaced at all: a round whose storm never overflowed
    // never swallowed the teardown, so it is not a sample of this race.
    let verdict_tag = format!("verdict-{round}");
    let mut signals = LossSignals::for_child_subject(&verdict_tag);
    if !observe_loss_at(&mut w, &mid, Duration::from_secs(3), &mut signals).await {
      common::skip_notice(format_args!(
        "overflow_swallowed_recreate_rebinds_the_midtree_watch: round {round}: no overflow observed"
      ));
      let _ = w.close().await;
      continue;
    }

    let live = probe_verdict(&mut w, &mid, &verdict_tag, &mut signals).await;
    // The honesty invariant binds BOTH arms — recycled or not, the recreated
    // directory may never go dark.
    assert!(
      live || signals.loud_covers() > 0,
      "round {round} (inode recycled: {recycled}): the recreated directory is neither \
       re-bound nor loudly covered — a dark mid-tree watch"
    );

    // The retention witness (see this cell's header): the scope's own binding
    // survived the loss window, and nothing ever told the Monitor what happened to
    // `mid` — so the child binding it holds for `mid` is the retained, kernel-dead
    // one. A round that cannot show that stages nothing, whatever the probe said.
    let scope_live = w.root_path(handle) == Some(mount.clone());
    if !scope_live || signals.retired() > 0 {
      eprintln!(
        "NOTE round {round}: the child binding was NOT shown retained across the loss window \
         (scope binding live: {scope_live}, events delivered AT the directory: {}, records \
         delivered by the directory's OWN watch: {}), so nothing was swallowed for it and this \
         round did not sample the re-add",
        signals.told_about, signals.subject_deliveries
      );
      not_retained += 1;
      let _ = w.close().await;
      continue;
    }
    // Which arm this round sampled, symmetric with the unmount cell's loud-death
    // NOTE: only a recycled inode leaves the recovery holding a retained,
    // kernel-dead watch for the acknowledged re-add to re-prove.
    if !recycled {
      eprintln!(
        "NOTE round {round}: the allocator did not recycle the inode ({ino_before:?} → \
         {ino_after:?}), so the identity-match keep was never exercised — ordinary identity-diff \
         reconciliation replaces the watch and this round did not sample the re-add"
      );
      identity_diffs += 1;
      let _ = w.close().await;
      continue;
    }
    staged += 1;
    // The staging witness, symmetric with the NOTEs above: the reader was
    // provably off the fd across the whole bracket, the teardown was destroyed
    // with the overflow, and the allocator handed the freed inode back — which is
    // exactly the retained, kernel-dead binding the recovery then had to re-prove.
    eprintln!(
      "NOTE round {round}: STAGED the recycle — the recreated directory reused inode \
       {ino_before:?} across the overflow-swallowed teardown (reader off the fd for {:?}), \
       live re-bind observed: {live}",
      bracket.stopped_for.unwrap_or_default()
    );
    if live {
      live_rounds += 1;
      honest = true;
    }
    let _ = w.close().await;
    if honest {
      break;
    }
  }

  queue.close();
  fixture.close();
  // Both endings stay failures — a run that staged nothing has lost this cell's
  // coverage, which must be loud, not silently green — but only one of them may
  // claim the recovery was exercised and came up short.
  let verdict = if staged == 0 {
    "no round staged the recycle, so this run lost the cell's coverage and says nothing about \
     the recreated directory — see the SKIP/NOTE lines for which precondition failed or which \
     arm the allocator took"
  } else {
    "the staged rounds stood only loud covers, never a live re-bound mid-tree watch"
  };
  assert!(
    honest,
    "staged {staged} of {ROUNDS} rounds ({not_retained} could not show the child binding retained, \
     {identity_diffs} took the identity-diff arm instead, cell budget lapsed: {budget_spent}), \
     {live_rounds} reached the live re-bound ending: {verdict}"
  );
}

/// [`StopBudget::current`]'s shape for a bracket that is ONE bounded stall
/// ([`STALL_ONE_STEP`]): the stall is a `work` whose `call` bound clears it, and
/// the token wait clears the stall's REMAINDER, because a watchdog-resumed leg
/// reads its tokens from a process the guard put back on the fd mid-stall.
///
/// Every bound is scaled from the one clock, so the relations the legs depend on —
/// stall inside `call`, stall inside `token`, stall inside `reap` — hold under
/// `TRIBUTARY_FS_TIMING_SCALE` exactly as they do natively. `guard` is left at
/// `tick`, the production relation, for the caller to move.
fn one_stall_budget() -> StopBudget {
  let call = scaled(Duration::from_secs(10));
  let stall = scaled(Duration::from_secs(2));
  let tick = call + stall + call * 3;
  StopBudget {
    ready: scaled(Duration::from_secs(10)),
    handshake: call,
    poll: scaled(Duration::from_millis(50)),
    token: call,
    call,
    grace: call / 2,
    work: stall,
    guard: tick,
    tick,
    reap: tick,
  }
}

/// Suite 14: the reader-stopped device's own resume PROVENANCE, which is what both
/// INV-BIND cells' staging rests on.
///
/// A bracket the WATCHDOG had to cut short is not a covered window: the guard put
/// the reader back on the fd while the helper still had work in flight, so the
/// teardown records the round is about to claim were swallowed may have been
/// drained instead — and the helper, still running, goes on to write its completion
/// token and exit zero, so every other fact the round collects looks exactly like
/// a clean bracket's. Provenance is the only thing that separates them, and it
/// therefore may never be inferred: this cell holds the device to reading the
/// guard's own queued expiry.
///
/// One bracket, one set of steps, one stall, and ONE bound moved between the legs:
///
/// * the guard's first expiry INSIDE the stall — the watchdog resumes the reader
///   mid-bracket, and the round must be REPORTED and stage nothing, however
///   successfully the helper then finishes;
/// * the guard's first expiry past the stall — the helper's own post-work resume
///   ends the window, and the round must still STAGE, exactly as suites 12 and 13
///   depend on. A provenance rule that refused this leg would take their coverage
///   with it, which is a regression and not a fix.
///
/// Why the legs differ in the guard's EXPIRY rather than in its interval: the
/// predecessor compared the window's length against the interval, and the two are
/// not the same instant. The guard expires a fixed time after the ARM, while the
/// window is measured from the later moment the stop was entered, so the window a
/// watchdog resume produces is `interval - (arm-to-enter delay) + (wake delay)` —
/// and nothing bounds either correction: this thread may be descheduled between
/// arming and entering, and the expiry may land a scheduling quantum late.
/// Measured on this container class the first term is microseconds while the
/// second is about a jiffy, so with the two instants CONFLATED the arithmetic
/// happens to answer correctly by a few milliseconds of luck; it is one preemption
/// away from the opposite answer, and it never had a reason to be right. Moving the
/// expiry separates the instants outright, which is what makes this leg decide the
/// question rather than race it.
#[test]
fn a_watchdog_resumed_bracket_is_reported_and_never_staged() {
  let mut watchdog = one_stall_budget();
  // Ten handshake polls into the window: long enough that the helper has already
  // read this process stopped and started its stall, and far short of the stall's
  // end. Derived from the budget's own cadence, so it scales with it.
  watchdog.guard = watchdog.poll * 10;
  let cut_short = with_reader_stopped_within(
    "provenance: the guard cuts the bracket short",
    STALL_ONE_STEP,
    &[],
    watchdog,
  );
  let finished = with_reader_stopped_within(
    "provenance: the helper finishes the bracket",
    STALL_ONE_STEP,
    &[],
    one_stall_budget(),
  );
  eprintln!(
    "NOTE provenance: guard-cut leg {cut_short:?}; helper-finished leg {finished:?} (guard's first \
     expiry {:?} vs the stall's {:?})",
    watchdog.guard, watchdog.work
  );

  // The watchdog leg. The first two assertions are what make it a WITNESS rather
  // than a coincidence — the device really stopped, and the helper really read it
  // stopped — so that the only thing left to decide is who ended the window. A leg
  // that skipped its way past them would prove nothing and must not pass quietly.
  assert!(
    cut_short.stopped_for.is_some(),
    "the watchdog leg must actually stop this process, or it says nothing about provenance: \
     {cut_short:?}"
  );
  assert!(
    cut_short.stop_observed,
    "the watchdog leg's helper must have read this process stopped before its first step, or the \
     leg never had a bracket to attribute: {cut_short:?}"
  );
  assert!(
    cut_short.guard_resumed,
    "a guard whose first expiry lands inside the bracket must be OBSERVED to have ended the \
     window — its own expiry, queued on the stopping thread, is the only thing this device \
     accepts as provenance: {cut_short:?}"
  );
  assert!(
    !cut_short.covered,
    "a window the WATCHDOG ended can never be a covered one: the reader was back on the fd while \
     the helper still had work left, so a teardown this bracket is supposed to have swallowed may \
     have been drained instead: {cut_short:?}"
  );
  assert!(
    !cut_short.staged(),
    "a bracket the watchdog resumed must stage NOTHING, whatever the helper's own completion and \
     exit status then said: {cut_short:?}"
  );

  // The inverse, on the same steps and the same stall: the helper's own resume
  // ends the window and the round still stages.
  assert!(
    finished.stopped_for.is_some() && finished.stop_observed,
    "the helper leg must stop this process and be read stopped before the first step: {finished:?}"
  );
  assert!(
    !finished.guard_resumed,
    "a guard whose first expiry sits well past the bracket must NOT be found to have fired — a \
     provenance that answered yes here would retire both INV-BIND cells' staging: {finished:?}"
  );
  assert!(
    finished.covered && finished.staged(),
    "a bracket the helper finished inside the stopped window still stages: {finished:?}"
  );
}

/// One churn cycle's wait: probes `dir` until its OWN watch delivers (proof
/// its arm granted a `wd` — a pre-arm probe write is never re-delivered, so
/// each attempt writes a fresh probe), returning `Some(true)` as soon as a
/// root-located `Rescan` surfaces the renewal instead, `Some(false)` once the
/// dir proved armed, and `None` when neither landed in the budget (the arm
/// raced the cycle — it just costs the cycle its grant).
///
/// Only the probe's EXACT, non-`Rescan` event counts as that proof, for the
/// reason [`child_watch_delivers`] gives: a `Rescan` located at `dir` is the
/// Monitor's answer to an arm it could NOT make, so ranking it as coverage would
/// read a failed arm as the grant it is the denial of — and the cycle would be
/// counted against a descriptor cursor it never moved.
async fn armed_or_renewed(w: &mut TokioWatcher, root: &Path, dir: &Path) -> Option<bool> {
  for attempt in 0..4 {
    let probe = dir.join(format!("armed-{attempt}.txt"));
    if std::fs::write(&probe, b"x").is_err() {
      return None;
    }
    let saw = tokio::time::timeout(scaled(Duration::from_millis(250)), async {
      while let Some(event) = w.next().await {
        if event.is_rescan() && event.path() == root {
          return Some(true);
        }
        if delivered(&event, &probe) {
          return Some(false);
        }
      }
      None
    })
    .await
    .ok()
    .flatten();
    if saw.is_some() {
      return saw;
    }
  }
  None
}

/// Suite 21: descriptor-space renewal end to end through the public API. With
/// the reader's rebuild threshold lowered, directory churn drives the per-fd
/// `wd` cursor to the threshold and the reader swaps in a fresh inotify
/// instance mid-stream. The renewal must surface as a covering ROOT `Rescan`
/// (its whole-instance loss signal — churn at this volume cannot overflow the
/// kernel queue, the per-cycle waits keep the consumer channel far from lag,
/// and a failed child arm's Rescan is located at its slot, so a root-located
/// Rescan here is the renewal's); the pre-existing deep tree must STAY
/// watched across the swap (the loss's binding re-proof re-arms every
/// retained directory on the fresh fd); and a sync barrier issued after the
/// renewal must resolve — the cookie write parks on the coverage-settle
/// fence, so resolution proves the re-proof's acknowledgements landed and
/// released the barrier. With the renewal trigger disabled (the mutation this
/// cell exists to catch) no root Rescan ever arrives and the cell fails.
#[tokio::test]
async fn descriptor_renewal_keeps_the_tree_watched() {
  /// Restores the production threshold even on a panicking assert.
  struct Restore;
  impl Drop for Restore {
    fn drop(&mut self) {
      tributary_fs::override_rebuild_threshold_for_tests(None);
    }
  }
  tributary_fs::override_rebuild_threshold_for_tests(Some(24));
  let _restore = Restore;

  let root = scratch_root("renewal");
  let deep = root.join("deep/keep");
  std::fs::create_dir_all(&deep).unwrap();
  let mut w = inotify_watcher();
  let handle = w.watch(&root, Interest::all()).await.expect("watch");

  // The deep pre-existing directory holds its OWN watch before any churn. That
  // is what makes the post-renewal check below a RE-arm proof rather than a
  // restatement: only a directory that was armed can be re-armed, so a staging
  // step that settled for coverage would let the cell claim survival for a
  // watch that never existed. A covering `Rescan` cannot establish it either —
  // a `Rescan` at or above `deep` is what the Monitor emits when it could NOT
  // arm it. See [`child_watch_delivers`].
  assert!(
    child_watch_delivers(&mut w, &deep, "pre").await,
    "the deep directory's own kernel watch delivers before the churn"
  );

  // Churn: each cycle creates a fresh directory, WAITS for its own watch to
  // deliver (so its arm provably granted a `wd` — a dir removed before its
  // arm dispatches grants nothing), then removes it. The cursor climbs one
  // grant per proven cycle while the live tree stays far below the
  // threshold, so the renewal's own re-arms cannot re-trip it; the per-cycle
  // event consumption also keeps the consumer channel far from the lag
  // path, whose recovery would mint its own root Rescan and blunt this
  // cell's mutation detection.
  let mut renewed = false;
  for i in 0..48 {
    let dir = root.join(format!("churn-{i}"));
    std::fs::create_dir(&dir).unwrap();
    if armed_or_renewed(&mut w, &root, &dir).await == Some(true) {
      renewed = true;
      break;
    }
    std::fs::remove_dir_all(&dir).unwrap();
  }
  assert!(
    renewed,
    "the lowered threshold forces a renewal, surfaced as a root Rescan"
  );

  // The deep directory is STILL watched: the re-proof re-armed it on the fresh
  // fd (the retry loop absorbs the re-arm's asynchrony). The claim is about THIS
  // directory's own kernel watch, so only its probe's exact, non-`Rescan` event
  // can settle it. The renewal's own root `Rescan` covers `deep` by ancestry
  // while saying nothing about whether the re-proof ever reached it, and a
  // re-proof that dropped the subtree instead of re-arming it would announce
  // itself as precisely such a `Rescan` — accepting one would let the loss the
  // cell exists to forbid read as the survival it asserts. See
  // [`child_watch_delivers`].
  assert!(
    child_watch_delivers(&mut w, &deep, "post").await,
    "the pre-existing deep directory's own kernel watch still delivers across the swap"
  );

  // A barrier over the renewed tree resolves: the cookie write parks on the
  // coverage-settle fence, so resolving here proves the re-proof settled and
  // released it.
  let (admission, _ticket) = w.mint_sync_ticket();
  let cookie = tokio::time::timeout(
    scaled(DEADLINE),
    w.sync_root(handle, &root, ".tributaries-renewal-sync", admission),
  )
  .await
  .expect("the barrier resolves once the renewal's re-proof settles")
  .expect("the sync admits and writes its cookie");
  let _ = std::fs::remove_file(&cookie);
}

/// Collects every event as it arrives until one satisfies `pred` (or the
/// deadline lapses), so a cell can assert on the WHOLE stream rather than on
/// whichever event a wait happened to stop at.
///
/// The distinction matters for a negative claim: "nothing under the exclusion
/// arrived" is only checkable against events that were never discarded, and a
/// plain `wait_for` throws away everything it did not match.
async fn collect_until(
  watcher: &mut TokioWatcher,
  seen: &mut Vec<Event>,
  mut pred: impl FnMut(&Event) -> bool,
) -> bool {
  tokio::time::timeout(scaled(DEADLINE), async {
    while let Some(event) = watcher.next().await {
      let hit = pred(&event);
      seen.push(event);
      if hit {
        return true;
      }
    }
    false
  })
  .await
  .unwrap_or(false)
}

/// Suite 22: exclusions against a LIVE kernel on the DESCENDING backend,
/// measured as coverage rather than as a delivery preference.
///
/// A per-directory backend gives the assertion its teeth. inotify attributes a
/// create to the affected directory's OWN watch descriptor and never re-delivers
/// anything for a directory it never armed, so on this backend "no event from
/// inside an exclusion, after a marker in the reported half has drained" IS the
/// statement that the subtree carries no kernel watch — the same fact
/// `backend_stats().directories()` reads for fanotify, read through the only
/// instrument a descending backend exposes. On a kernel-recursive backend the
/// same silence would prove only suppression; here it proves the coverage was
/// never established, which is what the option promises.
///
/// TWO exclusions, because the two ways a directory enters coverage are two
/// different fences and only one shape reaches each:
///
/// - `<root>/pre` EXISTS when the watch is taken, so it can only be declined by
///   the cold enumerate's listing — nothing is ever created under a covered
///   parent for it;
/// - `<root>/post` does NOT exist yet, so its creation is announced by the ROOT's
///   own watch (which IS covered) and can only be declined by the lowering of
///   that live create. Reversed, this cell would pass with the live fence gone.
///
/// `<root>/pred` is the boundary neighbour — an exclusion covers a subtree, not a
/// name prefix — and doubles as the ordering marker, so the reads below are never
/// merely early.
#[tokio::test]
async fn live_exclusions_are_enforced_on_the_descending_backend() {
  let root = scratch_root("exclusions");
  let cold = root.join("pre");
  let live = root.join("post");
  let neighbour = root.join("pred");
  std::fs::create_dir_all(cold.join("deep")).unwrap();
  std::fs::create_dir_all(&neighbour).unwrap();

  let mut w = TokioWatcher::new(
    WatcherOptions::new()
      .with_backend(Backend::Inotify)
      .with_exclusions(vec![cold.clone(), live.clone()]),
  )
  .expect("build watcher");
  let _h = w.watch(&root, Interest::all()).await.expect("watch");

  // Staging, and the boundary claim in one: the NEIGHBOUR's own kernel watch must
  // be proven to deliver before a missing delivery from inside an exclusion can
  // be read as a missing watch rather than as a cold read still in flight. Only
  // the probe's exact, non-`Rescan` event settles that — see
  // [`child_watch_delivers`].
  assert!(
    child_watch_delivers(&mut w, &neighbour, "arm").await,
    "`pred` is not under the exclusion of `pre` — an exclusion covers a subtree, not \
     a name prefix — so its own watch must be live and delivering"
  );

  let mut seen: Vec<Event> = Vec::new();

  // The cold enumerate's half: a directory that existed when the watch was taken.
  std::fs::write(cold.join("deep/cold.txt"), b"x").unwrap();
  let first = neighbour.join("marker-cold.txt");
  std::fs::write(&first, b"x").unwrap();
  assert!(
    collect_until(&mut w, &mut seen, |e| delivered(e, &first)).await,
    "the reported half keeps flowing while the excluded half churns"
  );

  // The live create's half: an excluded directory that does not exist yet, so its
  // own creation is reported by the covered root and its arm is the core's to
  // decline. Everything below it follows only if that arm was made.
  std::fs::create_dir_all(live.join("deeper")).unwrap();
  std::fs::write(live.join("deeper/live.txt"), b"x").unwrap();
  let second = neighbour.join("marker-live.txt");
  std::fs::write(&second, b"x").unwrap();
  assert!(
    collect_until(&mut w, &mut seen, |e| delivered(e, &second)).await,
    "the reported half still flows after the live churn under the exclusion"
  );

  // A short tail so a straggler from an excluded half is caught rather than
  // outrunning the assertion.
  let _ = tokio::time::timeout(scaled(Duration::from_millis(500)), async {
    while let Some(event) = w.next().await {
      seen.push(event);
    }
  })
  .await;

  // `Path::starts_with` is component-wise, so `<root>/pred` is not caught here —
  // the same subtree-not-prefix rule the fence itself matches on.
  let leaked: Vec<String> = seen
    .iter()
    .filter(|e| e.path().starts_with(&cold) || e.path().starts_with(&live))
    .map(|e| format!("{:?} at {}", e.kind(), e.path().display()))
    .collect();
  assert!(
    leaked.is_empty(),
    "an excluded subtree was armed after all — nothing from inside one can be \
     delivered unless its own directories carry kernel watches: {leaked:?}"
  );
  assert!(
    seen.iter().any(|e| delivered(e, &first)),
    "staging check: the reported half's marker really was delivered"
  );
}

/// Converges on `dir` NO LONGER carrying its own kernel watch: churns a probe
/// there, writes a marker in the still-reported `witness` directory, and waits
/// for the marker; the round passes when the marker arrives and the probe never
/// did. Retries until a round passes, so a shed that is merely still in flight
/// does not read as one that never happened.
///
/// The paired marker is what makes the negative sound. A bare timeout would pass
/// on any slow round; requiring a delivery from a watch that IS live in the same
/// window says the stream was flowing while `dir` stayed silent — the same shape
/// [`live_exclusions_are_enforced_on_the_descending_backend`] uses, tightened
/// into a convergence loop because a shed is eventual where a decline is not.
async fn child_watch_goes_quiet(
  watcher: &mut TokioWatcher,
  dir: &Path,
  witness: &Path,
  tag: &str,
) -> bool {
  for attempt in 0..40 {
    let probe = dir.join(format!("{tag}-{attempt}.txt"));
    let marker = witness.join(format!("{tag}-marker-{attempt}.txt"));
    if std::fs::write(&probe, b"x").is_err() {
      return false;
    }
    if std::fs::write(&marker, b"x").is_err() {
      return false;
    }
    let mut leaked = false;
    let marked = tokio::time::timeout(scaled(Duration::from_millis(500)), async {
      while let Some(event) = watcher.next().await {
        if delivered(&event, &probe) {
          leaked = true;
        }
        if delivered(&event, &marker) {
          return true;
        }
      }
      false
    })
    .await
    .unwrap_or(false);
    if marked && !leaked {
      return true;
    }
  }
  false
}

/// Suite 22, the geometry half, OUT of the exclusion — the direction that loses
/// data.
///
/// `<root>/a/cache` is excluded, so the cold walk of `<root>/a` armed nothing
/// there. Renaming `<root>/a` to `<root>/b` moves that directory to the
/// perfectly reportable `<root>/b/cache`, and BOTH endpoints of the rename are
/// themselves reported — so the record-by-record fence preserves the pair and the
/// Monitor answers it by re-parenting the known watch subtree in place. Without
/// the geometry escalation that carry-over installs no watch for the newly
/// visible directory, and every change under it is lost for the life of the
/// watch.
///
/// The claim is COVERAGE, read through the only instrument a descending backend
/// exposes: inotify attributes a create to the affected directory's OWN watch
/// descriptor, so [`child_watch_delivers`] naming a file inside `<root>/b/cache`
/// is a positive observation that the directory carries a kernel watch — not
/// merely that something was announced. It is asserted at the moved subtree's TOP
/// and one level DEEPER, because the repair has to cascade rather than stop at
/// the first newly reportable name.
#[tokio::test]
async fn a_rename_out_of_an_exclusion_arms_the_newly_reportable_subtree() {
  let root = scratch_root("geometry-out");
  let excluded = root.join("a/cache");
  std::fs::create_dir_all(excluded.join("deep")).unwrap();
  std::fs::create_dir_all(root.join("a/keep")).unwrap();

  let mut w = TokioWatcher::new(
    WatcherOptions::new()
      .with_backend(Backend::Inotify)
      .with_exclusions(vec![excluded.clone()]),
  )
  .expect("build watcher");
  let _h = w.watch(&root, Interest::all()).await.expect("watch");

  // Staging: the reported sibling's own watch is live, so the cold walk has run
  // and a later silence from inside the exclusion is a missing watch rather than
  // a read still in flight.
  assert!(
    child_watch_delivers(&mut w, &root.join("a/keep"), "arm").await,
    "the reported sibling carries its own watch once the cold walk lands"
  );
  assert!(
    child_watch_goes_quiet(&mut w, &excluded, &root.join("a/keep"), "pre").await,
    "staging: while it is excluded, `a/cache` carries no watch of its own"
  );

  // The geometry change: both endpoints reported, an exclusion under the source.
  std::fs::rename(root.join("a"), root.join("b")).unwrap();

  assert!(
    child_watch_delivers(&mut w, &root.join("b/cache"), "post").await,
    "the directory the rename made reportable must now carry its OWN kernel \
     watch — a re-parent that skipped it leaves this subtree blind forever"
  );
  assert!(
    child_watch_delivers(&mut w, &root.join("b/cache/deep"), "deep").await,
    "and the repair cascades: the whole moved subtree is re-enumerated, not \
     just its first newly reportable name"
  );
}

/// Suite 22, the geometry half, INTO the exclusion — the direction that spends
/// what the option exists to save.
///
/// `<root>/a/cache` is excluded but `<root>/b/cache` is not, so it is covered.
/// Renaming `<root>/b` to `<root>/a` moves that whole subtree under the
/// exclusion; a bare re-parent would keep its kernel watches installed and keep
/// delivering from inside ground the caller asked never to hear about — holding
/// exactly the per-watch budget the exclusion was set to shed.
///
/// The reported sibling is the witness in every round, so the negative is read
/// against a stream that was demonstrably flowing.
#[tokio::test]
async fn a_rename_into_an_exclusion_sheds_the_subtree_it_no_longer_reports() {
  let root = scratch_root("geometry-in");
  std::fs::create_dir_all(root.join("b/cache/deep")).unwrap();
  std::fs::create_dir_all(root.join("b/keep")).unwrap();

  let mut w = TokioWatcher::new(
    WatcherOptions::new()
      .with_backend(Backend::Inotify)
      .with_exclusions(vec![root.join("a/cache")]),
  )
  .expect("build watcher");
  let _h = w.watch(&root, Interest::all()).await.expect("watch");

  // Staging: nothing excludes `<root>/b/cache`, so it is covered and delivering.
  assert!(
    child_watch_delivers(&mut w, &root.join("b/cache"), "arm").await,
    "before the rename the subtree is reported, so it carries its own watch"
  );

  std::fs::rename(root.join("b"), root.join("a")).unwrap();

  assert!(
    child_watch_goes_quiet(&mut w, &root.join("a/cache"), &root.join("a/keep"), "post").await,
    "the subtree the rename moved under the exclusion must stop being covered — \
     while the reported sibling in the same directory keeps delivering"
  );
}

/// Suite 22, the geometry half, INTO the exclusion, read as DELIVERY inside the
/// rename's OWN kernel read rather than as coverage after it settles.
///
/// [`a_rename_into_an_exclusion_sheds_the_subtree_it_no_longer_reports`] converges:
/// it retries until a round comes back quiet, which is the right shape for a shed
/// (eventual by nature) and precisely the wrong one for the leak here, which is a
/// FIRST-round event. The window is one read buffer. inotify queues the rename
/// pair and the descendant watch's own record in FIFO order, so a compile that
/// classifies the whole buffer before re-anchoring any of it judges the descendant
/// record at the path its watch was ARMED at — outside the exclusion — keeps it,
/// and delivers it after the re-parent under `<root>/a/cache`. Everything the
/// repair does afterwards is too late for a record already retained.
///
/// The three writes are adjacent syscalls with no await between them, which is how
/// the one-read shape is obtained without depending on a sleep: the kernel has all
/// three queued long before a woken reader copies any of them out. The marker in
/// the still-reported sibling is written LAST, so it is the stream-order fence for
/// the negative — receiving it proves the driver read past the leak's position,
/// and `collect_until` keeps every event it passed on the way rather than
/// discarding the ones it did not match.
///
/// Live coalescing is likely, not certain: measured against the defect this cell
/// caught it on four runs in five, the fifth having split the buffer. That is the
/// right split of duty — the claim is stated deterministically by the core cell of
/// the same name, which feeds one buffer by construction, and this cell is the
/// end-to-end proof that the whole watcher, real kernel included, honours it. Its
/// assertion is a NEGATIVE, so a split buffer can only cost it teeth, never turn
/// it flaky-red.
#[tokio::test]
async fn a_rename_into_an_exclusion_fences_the_rest_of_its_own_read() {
  let root = scratch_root("geometry-in-batch");
  std::fs::create_dir_all(root.join("b/cache")).unwrap();
  std::fs::create_dir_all(root.join("b/keep")).unwrap();

  let mut w = TokioWatcher::new(
    WatcherOptions::new()
      .with_backend(Backend::Inotify)
      .with_exclusions(vec![root.join("a/cache")]),
  )
  .expect("build watcher");
  let _h = w.watch(&root, Interest::all()).await.expect("watch");

  // Staging: the subtree about to move under the exclusion carries its OWN kernel
  // watch right now, which is what lets a record from inside it ride behind the
  // rename in the same read. Without this the cell could pass on a watch that was
  // never armed in the first place.
  assert!(
    child_watch_delivers(&mut w, &root.join("b/cache"), "arm").await,
    "before the rename the subtree is reported, so it carries its own watch"
  );

  let leak = root.join("a/cache/leak.txt");
  let marker = root.join("a/keep/marker.txt");
  std::fs::rename(root.join("b"), root.join("a")).unwrap();
  std::fs::write(&leak, b"x").unwrap();
  std::fs::write(&marker, b"x").unwrap();

  let mut seen: Vec<Event> = Vec::new();
  assert!(
    collect_until(&mut w, &mut seen, |e| delivered(e, &marker)).await,
    "the reported sibling's marker still arrives, so the stream was flowing \
     across the rename: {seen:?}"
  );
  // A short tail so a straggler cannot outrun the assertion.
  let _ = tokio::time::timeout(scaled(Duration::from_millis(500)), async {
    while let Some(event) = w.next().await {
      seen.push(event);
    }
  })
  .await;

  let excluded = root.join("a/cache");
  let leaked: Vec<String> = seen
    .iter()
    .filter(|e| e.path().starts_with(&excluded))
    .map(|e| format!("{:?} at {}", e.kind(), e.path().display()))
    .collect();
  assert!(
    leaked.is_empty(),
    "a record queued behind the rename must be classified against the path the \
     rename gave it, so nothing under the exclusion is delivered: {leaked:?}"
  );
}

/// Suite 22, the geometry half, driven PAST the parked-source bound.
///
/// The geometry pass defers each directory rename's source endpoint until its
/// destination half can use it, and a directory moved clean OUT of the watched
/// root never sends that second half — so the deferred set is bounded. At the
/// bound it refuses the source and stops classifying the read, dropping the
/// remainder behind a scope-wide rescan rather than evicting sources that can
/// still pair.
///
/// This cell drives a real kernel across that bound and then asks the same
/// question the unbounded cells ask: a burst of move-outs comfortably larger than
/// the bound, and only THEN the geometry-changing rename. Whichever side of the
/// bound that rename lands on, the answer must be the same — the moved subtree
/// stops being covered and nothing under the exclusion is ever delivered. The
/// two paths that can produce it are the located repair (the ordinary case) and
/// the barrier's scope-wide recovery (the over-bound case), and the point of the
/// cell is that the caller cannot tell them apart.
///
/// Asserted convergently, like the shed cell it mirrors: a shed is eventual by
/// nature, and after a scope-wide recovery it is eventual by an extra re-arm.
/// The reported sibling is the witness in every round, so the negative is read
/// against a stream that was demonstrably still flowing — which is also the
/// liveness half of the claim, since a barrier that wedged the scope would take
/// the marker with it.
#[tokio::test]
async fn a_rename_burst_past_the_geometry_bound_still_fences_the_exclusion() {
  let root = scratch_root("geometry-bound");
  // OUTSIDE the watched root: a rename into it reports a source half and no
  // destination half, which is exactly the residue the bound exists for.
  let away = scratch_root("geometry-bound-away");
  std::fs::create_dir_all(root.join("b/cache")).unwrap();
  std::fs::create_dir_all(root.join("b/keep")).unwrap();
  // Comfortably more than the deferred set's bound, so the burst spends it and
  // keeps spending it.
  const MOVE_OUTS: u32 = 96;
  for i in 0..MOVE_OUTS {
    std::fs::create_dir_all(root.join(format!("gone{i}"))).unwrap();
  }

  let mut w = TokioWatcher::new(
    WatcherOptions::new()
      .with_backend(Backend::Inotify)
      .with_exclusions(vec![root.join("a/cache")]),
  )
  .expect("build watcher");
  let _h = w.watch(&root, Interest::all()).await.expect("watch");

  // Staging: nothing excludes `<root>/b/cache` yet, so it is covered and
  // delivering — the subtree the rename is about to move under the exclusion
  // really does carry its own kernel watch.
  assert!(
    child_watch_delivers(&mut w, &root.join("b/cache"), "arm").await,
    "before the burst the subtree is reported, so it carries its own watch"
  );

  for i in 0..MOVE_OUTS {
    std::fs::rename(root.join(format!("gone{i}")), away.join(format!("gone{i}"))).unwrap();
  }
  std::fs::rename(root.join("b"), root.join("a")).unwrap();

  assert!(
    child_watch_goes_quiet(&mut w, &root.join("a/cache"), &root.join("a/keep"), "post").await,
    "past the bound the subtree the rename moved under the exclusion must still \
     stop being covered — while the reported sibling in the same directory keeps \
     delivering, so the barrier covered the read it dropped instead of wedging \
     the scope"
  );
}
