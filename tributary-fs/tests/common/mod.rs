//! The acceptance vocabulary the real-kernel integration suites share.
//!
//! One mutation admits two different questions, and they are not
//! interchangeable:
//!
//! * **Was this ground COVERED?** The watch reached it and nothing was lost in
//!   silence. A `Rescan` at or above the path answers this: it hands the
//!   consumer an obligation to re-enumerate, which ACCOUNTS for the ground
//!   without describing what happened on it.
//! * **Was this change DELIVERED?** A decoded verb arrived naming this exact
//!   object. A `Rescan` does not answer this, and must not be allowed to.
//!
//! Each suite used to carry its own copy of one predicate answering the first
//! question, and cells named for verb decoding, identity round-trips and
//! convergence all stood on it — so a backend that had stopped decoding
//! entirely, emitting one root `Rescan` per mutation, would have passed them.
//! [`covers`] and [`delivered`] are that predicate split along the seam, and
//! [`Inventory`] is the consumer that makes the split operational rather than
//! rhetorical: it APPLIES a delivered verb and DISCHARGES a `Rescan` by
//! re-reading the covered subtree from the real filesystem. A convergence claim
//! therefore stays satisfiable by a rescan-only backend — it genuinely does
//! converge, by re-reading everything — while every delivery claim stops being.

// Each binary reaches only the part of this vocabulary its platform's cells can
// ask for; the remainder is not dead, it is another binary's.
#![allow(dead_code)]

use std::{
  collections::BTreeSet,
  fmt, io,
  path::{Path, PathBuf},
  sync::atomic::{AtomicUsize, Ordering},
  time::Duration,
};

use tributary_fs::{Event, EventKind, TokioWatcher};

/// Writes one line straight to the process's own inherited stderr, bypassing
/// libtest's per-test output capture.
///
/// libtest captures a test's `stdout`/`stderr` and discards the capture
/// buffer unless that test FAILS or the run passes `--nocapture` — and the
/// integration jobs pass neither. A notice whose entire reason to exist is to
/// be seen on a run that stays green (a skip, or a measurement probe) cannot
/// go through `eprintln!` for that reason: it would be captured and thrown
/// away exactly when it matters, leaving a log that looks identical whether
/// the cell ran or silently skipped. Writing directly to the locked, inherited
/// handle sidesteps the capture entirely. Do not fold this back into a plain
/// `eprintln!` "for simplicity" — that reintroduces the exact invisibility
/// this function exists to prevent.
pub(crate) fn raw_stderr_line(args: fmt::Arguments<'_>) {
  use std::io::Write;
  let mut err = std::io::stderr().lock();
  let _ = writeln!(err, "{args}");
  let _ = err.flush();
}

/// How many cells (or cell branches) have skipped in this process so far.
///
/// Shared across every cell in the binary, because a per-cell count could
/// only ever say 0 or 1 and would lose exactly the information a reader
/// needs: how much of a "N passed" suite ran nothing at all.
static SKIP_COUNT: AtomicUsize = AtomicUsize::new(0);

/// The prefix every skip notice carries, common to all three integration
/// suites, so one `grep` over a CI log recovers every skip regardless of
/// which binary produced it.
const SKIP_PREFIX: &str = "TRIBUTARY-SKIP";

/// Announces that a cell (or one branch of it) is skipping because its
/// precondition is absent, in a form that survives libtest's capture on a
/// PASSING run.
///
/// A `SKIP` printed through `eprintln!` reads identically to a cell that ran
/// and passed once libtest's capture discards it — the run is green, so
/// nobody thinks to pass `--nocapture` and go looking. Routing every skip
/// through here instead of a bare `eprintln!` makes the notice land on the
/// inherited stderr handle ([`raw_stderr_line`]) under one shared,
/// greppable prefix with a running count, so a reader can tell a suite that
/// skipped most of its cells from one that actually exercised them.
///
/// `SKIP` stays adjacent to `reason` — every call site writes `reason`
/// starting with its own cell's name — because `ci.yml`'s vacuousness gate
/// greps for exactly that adjacency: `SKIP $cell` must appear as one
/// substring for the per-cell check to find a genuine skip, and the
/// aggregate `grep 'SKIP'` line must stay parseable as `SKIP <cell>: <why>`.
/// The running count moves to the END instead, so it adds information
/// without breaking either grep.
pub fn skip_notice(reason: fmt::Arguments<'_>) {
  let n = SKIP_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
  raw_stderr_line(format_args!("{SKIP_PREFIX} {reason}  (skip #{n})"));
}

/// Whether `event` SIGNALS COVERAGE of `path`: it names `path` outright, or it
/// is a `Rescan` at `path` or one of its ancestors — which obliges the consumer
/// to re-enumerate below it.
///
/// This is the right question for a claim about REACH: the watch is live over
/// this ground, a loss was signalled rather than swallowed, a re-arm has taken.
/// It is the wrong question for any claim about a decoded verb, an identity or a
/// pairing, because it is satisfied for every path under the root by a single
/// root `Rescan` that says nothing about any of them. When the cell's name says
/// what happened rather than merely that something did, ask [`delivered`].
pub fn covers(event: &Event, path: &Path) -> bool {
  event.path() == path || (event.is_rescan() && path.starts_with(event.path()))
}

/// Whether `event` is the DELIVERY of a concrete change at exactly `path`: a
/// decoded verb, never a `Rescan`.
///
/// A `Rescan` is refused outright rather than ranked below a concrete event, and
/// the reason is not that it is weaker evidence. For a delivery claim it is
/// evidence AGAINST: a located `Rescan` is precisely what a backend emits when
/// it LOST the ground it would otherwise have described, so admitting one
/// inverts the cell it appears in. Nothing weaker than the exact path entails
/// the claim, so nothing weaker is admitted.
///
/// The verb rides alongside — `delivered(e, &p) && e.kind().is_created()` — and
/// a cell that cannot name the verb it expects is asking [`covers`]'s question.
pub fn delivered(event: &Event, path: &Path) -> bool {
  !event.is_rescan() && event.path() == path
}

/// A reference consumer: the tree a correct consumer would be holding after
/// obeying the event stream, as absolute paths of everything below the watched
/// root (the root itself excluded).
///
/// The model exists so a convergence cell can assert what convergence actually
/// means — the consumer's view ends equal to the real tree — instead of
/// accepting the `Rescan` that merely told it to go look. Because a `Rescan`
/// here costs a re-enumeration rather than closing a wait, a rescan-only backend
/// still converges (correctly: it really does hand over enough to reconstruct
/// the tree) and still fails every [`delivered`] assertion beside it.
pub struct Inventory {
  root: PathBuf,
  entries: BTreeSet<PathBuf>,
  delivered: BTreeSet<PathBuf>,
  rescans: usize,
}

impl Inventory {
  /// Seeds the model from the tree as it stands — the listing a consumer takes
  /// when its watch is established, and the one read of the real filesystem no
  /// event obliged.
  pub fn seeded(root: &Path) -> Self {
    let mut entries = BTreeSet::new();
    inventory_subtree(root, &mut entries);
    Self {
      root: root.to_path_buf(),
      entries,
      delivered: BTreeSet::new(),
      rescans: 0,
    }
  }

  /// Folds one event into the model.
  ///
  /// A concrete verb is APPLIED: it says what changed, and the model changes to
  /// match. A `Rescan` is DISCHARGED: it says only that coverage below its path
  /// became uncertain, so the model drops that subtree and re-reads it. Reading
  /// a `Rescan` as satisfaction of whatever was awaited is the confusion this
  /// module exists to prevent, and here it is not expressible.
  pub fn apply(&mut self, event: &Event) {
    match event.kind() {
      EventKind::Rescan => {
        self.rescans += 1;
        self.reread(event.path());
      }
      EventKind::Removed => {
        self.record(event.path());
        self.forget(event.path());
      }
      EventKind::Moved(moved) => {
        self.record(moved.from());
        self.record(event.path());
        self.forget(moved.from());
        self.learn(event.path());
      }
      // `Created`, `Modified`, and whatever a later vocabulary adds: the object
      // is asserted to be present at this path.
      _ => {
        self.record(event.path());
        self.learn(event.path());
      }
    }
  }

  /// Whether some concrete (non-`Rescan`) event named exactly `path` — the
  /// [`delivered`] question asked of the whole consumed stream rather than of
  /// one event. A `Moved` answers it at both of its ends.
  pub fn delivered_at(&self, path: &Path) -> bool {
    self.delivered.contains(path)
  }

  /// How many `Rescan`s the model has discharged, for a cell that wants to say
  /// what the convergence did NOT cost.
  pub fn rescans(&self) -> usize {
    self.rescans
  }

  /// Where the model and the real tree disagree; empty exactly when the
  /// consumer has converged.
  ///
  /// Each line names one path and which side holds it, because the two failures
  /// are different defects: `unwitnessed` is a change the stream never accounted
  /// for at all, `stale` is one whose undoing it never accounted for.
  pub fn disagreement(&self) -> Vec<String> {
    let mut truth = BTreeSet::new();
    inventory_subtree(&self.root, &mut truth);
    let mut lines: Vec<String> = truth
      .difference(&self.entries)
      .map(|path| format!("unwitnessed {}", path.display()))
      .collect();
    lines.extend(
      self
        .entries
        .difference(&truth)
        .map(|path| format!("stale {}", path.display())),
    );
    lines
  }

  /// Records that a concrete event named `path`.
  fn record(&mut self, path: &Path) {
    self.delivered.insert(path.to_path_buf());
  }

  /// Notes `path` as present, together with whatever already sits below it.
  ///
  /// The subtree read is not slack. A directory can APPEAR already populated — a
  /// rename in from outside the root moves a whole tree in one operation, and no
  /// backend synthesizes a create per descendant — so a directory's appearance
  /// obliges reading it exactly as a `Rescan` over it would. An object already
  /// gone again by the time the event is folded in teaches the model nothing:
  /// inventing an entry for it would make the model diverge from a tree the
  /// stream is describing correctly.
  fn learn(&mut self, path: &Path) {
    if !self.inside(path) {
      return;
    }
    match std::fs::symlink_metadata(path) {
      Ok(meta) => {
        self.entries.insert(path.to_path_buf());
        if meta.is_dir() {
          model_subtree(path, &mut self.entries);
        }
      }
      Err(_) => self.forget(path),
    }
  }

  /// Drops `path` and everything the model held below it.
  fn forget(&mut self, path: &Path) {
    self.entries.retain(|entry| !entry.starts_with(path));
  }

  /// Discharges a `Rescan` over `at`: the covered subtree is dropped and re-read
  /// from the real filesystem, which is the whole of what the `Rescan` obliges
  /// and the whole of what it entitles the consumer to.
  fn reread(&mut self, at: &Path) {
    if !at.starts_with(&self.root) {
      // Coverage above the model's root: nothing the model claims is put in
      // doubt by it.
      return;
    }
    self.forget(at);
    if at == self.root {
      model_subtree(&self.root, &mut self.entries);
    } else {
      self.learn(at);
    }
  }

  /// Whether `path` is a proper descendant of the watched root.
  fn inside(&self, path: &Path) -> bool {
    path != self.root && path.starts_with(&self.root)
  }
}

/// Adds every path below `dir` to `out`, `dir` itself excluded, or PANICS
/// naming the enumeration that failed.
///
/// The panic is the point. This walk is what both the model's re-reads and the
/// independent truth calculation stand on, so an enumeration failure lowered to
/// "this directory was empty" would shrink BOTH sides by the same ground and
/// leave them agreeing — a convergence claim reported with no successful
/// inventory behind it. A test that cannot read the tree has no truth to compare
/// against and must say so.
fn inventory_subtree(dir: &Path, out: &mut BTreeSet<PathBuf>) {
  if let Err(err) = read_subtree(dir, out) {
    panic!("inventory: enumerating {} failed: {err}", dir.display());
  }
}

/// The same walk for the MODEL's own re-reads, absorbing a `dir` that has
/// already vanished.
///
/// The model folds events in behind a tree that is still moving, so a subtree
/// gone by the time its event is applied is described by a later event rather
/// than by this walk. Nothing else is absorbed: a re-read that fails for any
/// other reason is the same blind enumeration [`inventory_subtree`] refuses.
fn model_subtree(dir: &Path, out: &mut BTreeSet<PathBuf>) {
  match read_subtree(dir, out) {
    Ok(()) => {}
    Err(err) if err.kind() == io::ErrorKind::NotFound => {}
    Err(err) => panic!("inventory: re-reading {} failed: {err}", dir.display()),
  }
}

/// Adds every path below `dir` to `out`, `dir` itself excluded.
///
/// Symlinks are recorded but never followed: the model holds the tree the
/// backends watch, and a link pointing out of the root is one entry rather than
/// a subtree.
///
/// `NotFound` — and only `NotFound` — is absorbed: the real tree races this
/// walk, and an object that vanished mid-walk is a fact some later event carries
/// rather than a reason to abandon the model. Every other failure is the
/// enumeration itself breaking and travels to the caller.
fn read_subtree(dir: &Path, out: &mut BTreeSet<PathBuf>) -> io::Result<()> {
  for entry in std::fs::read_dir(dir)? {
    let entry = match entry {
      Ok(entry) => entry,
      Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
      Err(err) => return Err(err),
    };
    let path = entry.path();
    let is_dir = match entry.file_type() {
      Ok(kind) => kind.is_dir(),
      Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
      Err(err) => return Err(err),
    };
    out.insert(path.clone());
    if is_dir {
      match read_subtree(&path, out) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
      }
    }
  }
  Ok(())
}

/// Drives `inventory` off `watcher`'s stream until `settled` holds of the model,
/// or `deadline` lapses.
///
/// One drain, however many facts the cell is after: a second pass over the same
/// stream would be waiting for events the first pass already consumed. Cells
/// therefore ask for everything they need here and assert each fact SEPARATELY
/// afterwards, off the model, so a failure names which claim broke.
///
/// `settled` is tested before each await, so a stream that has already said
/// everything it owes settles the cell rather than waiting out the deadline on
/// an event nobody is going to produce.
pub async fn drive(
  watcher: &mut TokioWatcher,
  inventory: &mut Inventory,
  deadline: Duration,
  mut settled: impl FnMut(&Inventory) -> bool,
) -> bool {
  tokio::time::timeout(deadline, async {
    loop {
      if settled(inventory) {
        return true;
      }
      let Some(event) = watcher.next().await else {
        return false;
      };
      inventory.apply(&event);
    }
  })
  .await
  .unwrap_or(false)
}

/// Consumes the stream up to a point in the SOURCE'S OWN ORDER: mutates a fresh
/// sentinel inside `admitted_dir` — a directory the watch is known to still cover
/// — and reads until that sentinel is accounted for, handing every event consumed
/// on the way to `inspect`. `false` means the sentinel never surfaced within
/// `deadline`, which the caller must treat as a failure rather than a quiet
/// stream.
///
/// # What it is for
///
/// A cell that asserts an ABSENCE ("after this operation, nothing under X may be
/// reported") is only sound if the stream position where the window opens is
/// known. It is not known by default: an event describes the tree AS IT WAS WHEN
/// THE KERNEL RECORDED IT, and the queue between there and the consumer has
/// depth, so a delivery the cell's own setup provoked can still be in flight when
/// the window opens and be counted against the operation under test. That is not
/// a leak — the path it names was correct when it was recorded — but it is
/// indistinguishable from one once the window has opened over it.
///
/// One mutation can even produce SEVERAL such deliveries: `std::fs::write`
/// truncates and then writes, and Linux records a modification for each, which
/// reach the consumer merged only when the reader did not drain between them. So
/// "wait for the setup's event" leaves an unknown remainder queued, and the
/// remainder names exactly the path a leak would.
///
/// # Why a sentinel and not a pause
///
/// A sleep would be a guess about latency; this is a proof about ORDER. The
/// sentinel is mutated after everything the caller wants drained, the source's
/// queue is FIFO, and so every one of those deliveries precedes the sentinel's.
/// Reading through the sentinel therefore consumes all of them — with no timing
/// assumption, and no dependence on how the kernel chose to merge them.
///
/// The same argument runs the other way and CLOSES a window: mutate the sentinel
/// after the operation under test, and any breach the operation could produce is
/// ordered before the sentinel too — so the sentinel's arrival is the moment a
/// breach would already have been seen, and `inspect` has seen it. That replaces
/// a blind quiet-window timeout with a positive stopping condition.
///
/// [`covers`] is the acceptance, so a loss signal standing in for the sentinel
/// ends the barrier as well: the same loss dropped whatever else that buffer
/// held, so nothing is being waited on that can still arrive.
pub async fn barrier(
  watcher: &mut TokioWatcher,
  admitted_dir: &Path,
  tag: &str,
  deadline: Duration,
  mut inspect: impl FnMut(&Event),
) -> bool {
  use std::sync::atomic::{AtomicU32, Ordering};
  static COUNTER: AtomicU32 = AtomicU32::new(0);

  let sentinel = admitted_dir.join(format!(
    "barrier-{tag}-{}.txt",
    COUNTER.fetch_add(1, Ordering::Relaxed)
  ));
  std::fs::write(&sentinel, b"barrier").expect("write the barrier sentinel");
  tokio::time::timeout(deadline, async {
    while let Some(event) = watcher.next().await {
      if covers(&event, &sentinel) {
        return true;
      }
      inspect(&event);
    }
    false
  })
  .await
  .unwrap_or(false)
}

/// Drives `inventory` until the consumer's view equals the real tree — the
/// convergence claim stated as what it means. `false` means it never agreed, and
/// [`Inventory::disagreement`] says how.
///
/// The caller must have STOPPED mutating first: the model is compared against a
/// tree that has to hold still, and a convergence claim over a moving target is
/// not a claim about the watcher.
pub async fn reconcile(
  watcher: &mut TokioWatcher,
  inventory: &mut Inventory,
  deadline: Duration,
) -> bool {
  drive(watcher, inventory, deadline, |model| {
    model.disagreement().is_empty()
  })
  .await
}
