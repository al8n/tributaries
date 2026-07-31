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
  path::{Path, PathBuf},
  time::Duration,
};

use tributary_fs::{Event, EventKind, TokioWatcher};

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
    read_subtree(root, &mut entries);
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
    read_subtree(&self.root, &mut truth);
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
          read_subtree(path, &mut self.entries);
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
      read_subtree(&self.root, &mut self.entries);
    } else {
      self.learn(at);
    }
  }

  /// Whether `path` is a proper descendant of the watched root.
  fn inside(&self, path: &Path) -> bool {
    path != self.root && path.starts_with(&self.root)
  }
}

/// Adds every path below `dir` to `out`, `dir` itself excluded.
///
/// Symlinks are recorded but never followed: the model holds the tree the
/// backends watch, and a link pointing out of the root is one entry rather than
/// a subtree. A directory that cannot be read contributes nothing — the real
/// tree races this walk, and a directory that vanished mid-walk is a fact some
/// later event carries rather than a reason to abandon the model.
fn read_subtree(dir: &Path, out: &mut BTreeSet<PathBuf>) {
  let Ok(entries) = std::fs::read_dir(dir) else {
    return;
  };
  for entry in entries.flatten() {
    let path = entry.path();
    let is_dir = entry.file_type().is_ok_and(|kind| kind.is_dir());
    out.insert(path.clone());
    if is_dir {
      read_subtree(&path, out);
    }
  }
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
