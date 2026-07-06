//! The public async watcher and the machinery wiring one [`tributary_fs::Watcher`]
//! to the sans-I/O [`Subsumer`](crate::subsume::Subsumer), the
//! [`fan_out`](crate::route::fan_out) router, and the per-subscription
//! [`EpochLedger`](epoch::EpochLedger).
//!
//! All I/O lives here; the engines it drives (subsumption, routing, epoch rebasing)
//! are pure. A [`Tributaries`] owns exactly one `tributary-fs` watcher and subsumes
//! every caller subscription onto its disjoint roots, so N overlapping `watch` calls
//! collapse to one kernel watch (design §4); each raw event fans out to every
//! covering subscription (design §5), stamped in that subscription's own monotone
//! epoch space (design §8).

use std::{collections::VecDeque, hash::Hash, path::Path};

use agnostic_lite::RuntimeLite;
use tributary_fs::{Interest, RootHandle, Watcher, WatcherOptions};

use crate::{
  error::{BuildError, CloseError, UnwatchError, WatchError},
  event::Event,
  subscription::Subscription,
  subsume::{Subsumer, UnwatchOutcome, WatchOutcome},
};

use self::epoch::EpochLedger;

mod epoch;

#[cfg(all(test, feature = "tokio"))]
mod tests;

/// The seam the driver arms kernel watches through: the two operations the widen
/// re-point and the arm-failure unwind must sequence, factored out of the concrete
/// [`Watcher`] so those paths are testable with a fake that records call order and
/// can inject an arm failure.
///
/// This is a private *internal* seam — not the public `Source` trait (reserved for
/// M2). It is generic over its `Handle` (the fs root id) so a test fake can mint
/// trivial handles in place of the un-constructible [`RootHandle`]; production
/// implements it for [`Watcher`] with `Handle = RootHandle`. Methods take `&self`
/// (the watcher's `watch`/`unwatch` do), so the fake uses interior mutability.
pub(crate) trait RootArmer {
  /// The fs root id an arm yields (`RootHandle` in production).
  type Handle: Copy + Eq + Hash;

  /// Arms a kernel watch of `path` with `interest`, yielding its fresh handle.
  fn arm(
    &self,
    path: &Path,
    interest: Interest,
  ) -> impl Future<Output = Result<Self::Handle, WatchError>>;

  /// Releases the kernel watch named by `handle`.
  fn disarm(&self, handle: Self::Handle) -> impl Future<Output = Result<(), UnwatchError>>;
}

impl<R: RuntimeLite> RootArmer for Watcher<R> {
  type Handle = RootHandle;

  async fn arm(&self, path: &Path, interest: Interest) -> Result<RootHandle, WatchError> {
    Ok(self.watch(path.to_path_buf(), interest).await?)
  }

  async fn disarm(&self, handle: RootHandle) -> Result<(), UnwatchError> {
    Ok(self.unwatch(handle).await?)
  }
}

/// The public top-level watcher: overlapping subscriptions in, attributed events
/// out.
///
/// Wraps one [`tributary_fs::Watcher`] concretely (design call A) plus the
/// sans-I/O subsumption engine. Use the [`TokioTributaries`] / [`SmolTributaries`]
/// aliases, or any other [`RuntimeLite`].
///
/// # Watching means "changes from now on"
///
/// Like the layer below, registering a subscription delivers no initial inventory
/// — start the watch, then crawl. See [`tributary_fs::Watcher`].
///
/// # Loss is never silent
///
/// Every coverage gap surfaces as a [`Rescan`](tributary_fs::EventKind::Rescan)
/// whose [`epoch`](Event::epoch) dominates everything delivered before it, fanned
/// out to *every* subscriber of the affected root (design §5/§8). Widening a watch
/// (design §4) emits a synthetic dominating `Rescan` per re-pointed subscription so
/// a consumer re-enumerates against the new, wider root.
pub struct Tributaries<R: RuntimeLite> {
  watcher: Watcher<R>,
  subsumer: Subsumer<RootHandle>,
  /// Fanned-out events awaiting delivery: one raw event can produce several (one
  /// per covering subscriber), and `next` hands them out one per call.
  queue: VecDeque<Event>,
  /// The per-subscription monotone-epoch ledger (design §8): stamps every delivered
  /// event in its subscription's own epoch space (rebasing on each widen) so the raw
  /// per-`ScopeId` fs epoch — which restarts at `START` on every kernel arm — never
  /// leaks as a dominance order across a re-point.
  epochs: EpochLedger,
}

impl<R: RuntimeLite> core::fmt::Debug for Tributaries<R> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("Tributaries")
      .field("subsumer", &self.subsumer)
      .field("queued", &self.queue.len())
      .finish_non_exhaustive()
  }
}

impl<R: RuntimeLite> Tributaries<R> {
  /// Builds a watcher, spawning the underlying `tributary-fs` driver on `R`.
  ///
  /// # Errors
  ///
  /// [`BuildError::Fs`] when the underlying `tributary-fs` watcher cannot be built.
  pub fn new(options: WatcherOptions) -> Result<Self, BuildError> {
    Ok(Self {
      watcher: Watcher::new(options)?,
      subsumer: Subsumer::new(),
      queue: VecDeque::new(),
      epochs: EpochLedger::new(),
    })
  }

  /// Subscribes to `path` with `interest`, returning its [`Subscription`].
  ///
  /// Overlapping paths are accepted: they are subsumed onto a shared kernel watch
  /// (design §4), so this never surfaces the `Overlaps` the layer below rejects.
  /// Widening an existing watch re-points the subsumed subscriptions onto the new
  /// wider root and delivers each a synthetic dominating
  /// [`Rescan`](tributary_fs::EventKind::Rescan) (design §8).
  ///
  /// # Errors
  ///
  /// - [`WatchError::Canonicalize`] when `path` cannot be canonicalized;
  /// - [`WatchError::Fs`] when arming the kernel watch fails.
  pub async fn watch(
    &mut self,
    path: impl AsRef<Path>,
    interest: Interest,
  ) -> Result<Subscription, WatchError> {
    let supplied = path.as_ref();
    let canonical = std::fs::canonicalize(supplied).map_err(|source| WatchError::Canonicalize {
      path: supplied.to_path_buf(),
      source,
    })?;
    apply_watch(
      &mut self.subsumer,
      &mut self.epochs,
      &mut self.queue,
      &self.watcher,
      &canonical,
      interest,
    )
    .await
  }

  /// Drops `sub`, releasing its kernel watch once it was the last subscriber of its
  /// (possibly shared) root.
  ///
  /// # Errors
  ///
  /// - [`UnwatchError::UnknownSubscription`] when `sub` is not live;
  /// - [`UnwatchError::Fs`] when releasing the now-empty kernel watch fails.
  pub async fn unwatch(&mut self, sub: Subscription) -> Result<(), UnwatchError> {
    match self.subsumer.plan_unwatch(sub) {
      None => Err(UnwatchError::UnknownSubscription),
      Some(UnwatchOutcome::Dropped) => Ok(()),
      Some(UnwatchOutcome::RootEmptied { fs_root }) => self.watcher.disarm(fs_root).await,
    }
  }

  /// The next attributed event, or `None` once the watcher is closed and drained.
  ///
  /// Pulls from the underlying stream, resolves each raw event's root by its
  /// `root()` handle (O(1), not a radix walk), fans it out to every covering
  /// subscription (design §5), and hands the results out one per call.
  pub async fn next(&mut self) -> Option<Event> {
    loop {
      if let Some(event) = self.queue.pop_front() {
        return Some(event);
      }
      let raw = self.watcher.next().await?;
      // Disjoint field borrows: `subsumer` resolves the root/coverage, `epochs`
      // owns the per-subscription stamp state.
      let (subsumer, epochs, queue) = (&self.subsumer, &mut self.epochs, &mut self.queue);
      let Some(entry) = subsumer.entry(raw.root()) else {
        // The raw event's root has no live entry — its subscription(s) were
        // dropped between the kernel emitting it and us routing it. Nothing to
        // deliver; pull the next raw event.
        continue;
      };
      // Fan out to every covering subscriber and stamp each delivery in that
      // subscriber's own monotone epoch space (design §5/§8), rebasing away the raw
      // fs epoch (which restarts per kernel arm). `raw.epoch()` is the fs epoch of
      // this event on its current root; `set_epoch` binds the umbrella stamp.
      let raw_epoch = raw.epoch();
      let delivered = epochs.stamp_and_fan_out(
        &raw,
        raw_epoch,
        entry,
        |sub| subsumer.subscription_path(sub),
        Event::subscription,
        |mut event, stamp| {
          event.set_epoch(stamp);
          event
        },
      );
      queue.extend(delivered);
    }
  }

  /// Closes the watcher: tears the underlying `tributary-fs` watcher down and
  /// resolves once its driver has quiesced. Buffered attributed events are dropped.
  ///
  /// # Errors
  ///
  /// [`CloseError::Fs`] when the underlying watcher cannot confirm its shutdown.
  pub async fn close(self) -> Result<(), CloseError> {
    Ok(self.watcher.close().await?)
  }
}

/// Plans and applies one `watch` against `armer`, threading the outcome through the
/// sans-I/O [`Subsumer`]. Factored out of [`Tributaries::watch`] so the widen
/// ordering and the arm-failure unwind are testable with a fake [`RootArmer`].
///
/// The ordering contract (design §4): on a widen, arm the new wider root **before**
/// releasing the subsumed roots, so coverage never gaps. If any arm fails the plan
/// is aborted ([`Subsumer::abort_watch`]) so no pending reservation leaks. On a
/// successful widen, a synthetic dominating [`Rescan`](tributary_fs::EventKind::Rescan)
/// is queued for every re-pointed subscription (design §8).
async fn apply_watch<A: RootArmer>(
  subsumer: &mut Subsumer<A::Handle>,
  epochs: &mut EpochLedger,
  queue: &mut VecDeque<Event>,
  armer: &A,
  canonical: &Path,
  interest: Interest,
) -> Result<Subscription, WatchError> {
  let outcome = subsumer.plan_watch(canonical, interest);
  match &outcome {
    WatchOutcome::Covered { fs_root, sub } => {
      // Already covered by a live root: no kernel call, just adopt the sub.
      let (fs_root, sub) = (*fs_root, *sub);
      subsumer.commit_watch(&outcome, fs_root);
      Ok(sub)
    }
    WatchOutcome::Disjoint {
      root_path,
      interest,
      sub,
    } => {
      let sub = *sub;
      match armer.arm(root_path, *interest).await {
        Ok(fs_root) => {
          subsumer.commit_watch(&outcome, fs_root);
          Ok(sub)
        }
        Err(err) => {
          // Arm failed: abandon the plan so its pending reservation cannot leak.
          subsumer.abort_watch(&outcome);
          Err(err)
        }
      }
    }
    WatchOutcome::Widen {
      new_root_path,
      union_interest,
      repointed,
      unwatch,
      sub,
    } => {
      let sub = *sub;
      // Watch-new-before-unwatch-old (design §4): arm the wider root FIRST, so
      // coverage never gaps in the window where both are briefly armed.
      let fs_root = match armer.arm(new_root_path, *union_interest).await {
        Ok(fs_root) => fs_root,
        Err(err) => {
          // The wider root never came up: abandon the plan, leaving the subsumed
          // roots exactly as they were (untouched, still armed). No pending leak.
          subsumer.abort_watch(&outcome);
          return Err(err);
        }
      };

      // The wider root is live and adopts every re-pointed subscription — commit
      // the state transition before releasing the old roots so a concurrent event
      // routes against the new entry.
      let repointed = repointed.clone();
      subsumer.commit_watch(&outcome, fs_root);

      // Now release the subsumed roots. A failed disarm is benign: `unwatch` fails
      // only with `UnknownRoot` (the root is already dead) or `Closed` (the watcher
      // has stopped) — never on a still-live root — so nothing lingers live. The
      // wider root already covers these subtrees, so coverage is intact and the
      // subscription is established regardless.
      for old in unwatch {
        let _ = armer.disarm(*old).await;
      }

      // Rebase each re-pointed subscription onto the new wider root (design §8): emit
      // its synthetic dominating Rescan at its high-water `.next()` and set its
      // `epoch_base` to that same value, so the Rescan strictly dominates the
      // subscription's pre-widening stream while the new root's genuine events
      // (raw fs epoch 0, 1, …) stamp to hw.next()+0, +1, … — tie-or-exceeding it
      // (not dominated). Each subscription rebases from its own high-water.
      for moved in repointed {
        let rescan = epochs.repoint(moved);
        queue.push_back(Event::rescan(moved, new_root_path.clone(), rescan));
      }

      Ok(sub)
    }
  }
}

/// A [`Tributaries`] driven by the tokio runtime.
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub type TokioTributaries = Tributaries<agnostic_lite::tokio::TokioRuntime>;

/// A [`Tributaries`] driven by the smol runtime.
#[cfg(feature = "smol")]
#[cfg_attr(docsrs, doc(cfg(feature = "smol")))]
pub type SmolTributaries = Tributaries<agnostic_lite::smol::SmolRuntime>;
