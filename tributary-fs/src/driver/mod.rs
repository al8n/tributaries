//! The async driver task: a thin executor around [`DriverCore`].
//!
//! Every decision lives in the sans-I/O core; this loop only moves bytes —
//! it selects over the command channel, the core's one timer, the blocking
//! pool's results, and every root's OS batches, executes the core's
//! [`Effect`]s (stream spawn/teardown and probes on the blocking pool, event
//! delivery by `try_send`), and feeds each outcome straight back in.

use std::{
  collections::BTreeMap,
  num::NonZeroUsize,
  path::{Path, PathBuf},
  time::Duration,
};

use agnostic_lite::{RuntimeLite, time::Instant as _};
use futures_util::{FutureExt, StreamExt, stream::SelectAll};
use tributary_proto::{Change, Instant, Interest, ScopeId};

use crate::{
  core::{Delivery, DriverCore, Effect, ProbeId, ProbeOutcome, RootMeta},
  os::{Source, SourceChannels, SourceConfig, SourceError, SourceHandle, SourceMessage},
};

#[cfg(all(test, feature = "tokio"))]
mod tests;

/// The driver-side knobs a watcher hands its task.
#[derive(Debug, Clone)]
pub(crate) struct DriverConfig {
  /// The OS event-coalescing latency.
  pub(crate) latency: Duration,
  /// The requested rename-pairing window; the effective window never falls
  /// below what the latency makes physically necessary.
  pub(crate) move_window: Duration,
  /// Per-root capacity of the callback→driver channel, in batches.
  pub(crate) os_batch_capacity: NonZeroUsize,
  /// Load-shedding exclusion directories applied to every root.
  pub(crate) exclusions: Vec<PathBuf>,
}

impl DriverConfig {
  /// The rename window actually armed — the same total derivation the public
  /// options expose (see [`WatcherOptions::effective_move_window`]).
  ///
  /// [`WatcherOptions::effective_move_window`]: crate::WatcherOptions::effective_move_window
  pub(crate) fn effective_move_window(&self) -> Duration {
    crate::options::derive_move_window(self.move_window, self.latency)
  }
}

/// The reply channel of one `Command::Watch`: the scope plus the canonical
/// root path event paths will arrive under.
pub(crate) type WatchReply =
  futures_channel::oneshot::Sender<Result<(ScopeId, PathBuf), SourceError>>;

/// One command from the watcher facade to its driver task.
pub(crate) enum Command {
  /// Watch a new root; resolves once the native stream is live.
  Watch {
    /// The root to watch.
    root: PathBuf,
    /// The delivery interest for the new scope.
    interest: Interest,
    /// Resolved once the stream is live, with the scope handle and the
    /// canonical root path event paths will arrive under.
    reply: WatchReply,
  },
  /// Stop watching a root; resolves once its stream is torn down.
  Unwatch {
    /// The scope to stop.
    scope: ScopeId,
    /// Resolved with whether the scope existed.
    reply: futures_channel::oneshot::Sender<bool>,
  },
  /// Orderly shutdown; resolves when every stream is torn down.
  Close {
    /// Resolved when the driver has quiesced.
    reply: futures_channel::oneshot::Sender<()>,
  },
}

/// A spawned native source, as the blocking pool hands it back.
pub(crate) struct SpawnedSource<H> {
  /// The live stream handle.
  pub(crate) handle: H,
  /// The stream's data + control receivers.
  pub(crate) channels: SourceChannels,
  /// What the spawn learned about the root.
  pub(crate) meta: RootMeta,
}

/// The blocking-pool side of the platform: spawn, teardown, and stat. A
/// test implementation runs the whole driver loop against a fake filesystem.
pub(crate) trait FsOps: Clone + Send + Sync + 'static {
  /// The live-stream handle type.
  type Handle: SourceControl;

  /// Starts the native source (blocking).
  fn spawn_source(&self, config: SourceConfig) -> Result<SpawnedSource<Self::Handle>, SourceError>;

  /// `lstat`s one path (blocking).
  fn probe(&self, path: &Path) -> ProbeOutcome;
}

/// The control surface of a live stream handle.
pub(crate) trait SourceControl: Send + 'static {
  /// Acknowledges a processed in-band `Overflow`, re-arming the source's
  /// dedup so the next loss sends a fresh one.
  fn overflow_processed(&self);

  /// Quiesces and destroys the stream (blocking, bounded).
  fn shutdown(self);
}

impl SourceControl for SourceHandle {
  fn overflow_processed(&self) {
    SourceHandle::overflow_processed(self);
  }

  fn shutdown(self) {
    SourceHandle::shutdown(self);
  }
}

/// The real platform: `Source::spawn` + `lstat`.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RealFs;

impl FsOps for RealFs {
  type Handle = SourceHandle;

  fn spawn_source(&self, config: SourceConfig) -> Result<SpawnedSource<Self::Handle>, SourceError> {
    let (handle, channels) = Source::spawn(config)?;
    let root = handle.roots().first().cloned().unwrap_or_default();
    let root_dev = root_device(&root).map_err(|source| SourceError::RootUnavailable {
      root: root.clone(),
      source,
    })?;
    // Seed the device-boundary table from the LIVE mount table: an unseeded
    // table is blind to already-mounted volumes, and event-side identity
    // trust must never be presumed off blindness.
    let (mounts, mounts_authoritative) = match crate::os::mounts_under(&root) {
      Some(mounts) => (mounts, true),
      None => (Vec::new(), false),
    };
    Ok(SpawnedSource {
      handle,
      channels,
      meta: RootMeta {
        root,
        root_dev,
        mounts,
        mounts_authoritative,
      },
    })
  }

  fn probe(&self, path: &Path) -> ProbeOutcome {
    match std::fs::symlink_metadata(path) {
      Ok(meta) => {
        let file_type = meta.file_type();
        let kind = if file_type.is_dir() {
          tributary_proto::FileKind::Dir
        } else if file_type.is_file() {
          tributary_proto::FileKind::File
        } else if file_type.is_symlink() {
          tributary_proto::FileKind::Symlink
        } else {
          tributary_proto::FileKind::Other
        };
        let (file_id, dev) = inode_of(&meta);
        ProbeOutcome::Present { kind, file_id, dev }
      }
      Err(err) if err.kind() == std::io::ErrorKind::NotFound => ProbeOutcome::Missing,
      Err(_) => ProbeOutcome::Failed,
    }
  }
}

fn root_device(root: &Path) -> std::io::Result<u64> {
  let meta = std::fs::metadata(root)?;
  #[cfg(unix)]
  {
    use std::os::unix::fs::MetadataExt;
    Ok(meta.dev())
  }
  #[cfg(not(unix))]
  {
    let _ = meta;
    Ok(0)
  }
}

fn inode_of(meta: &std::fs::Metadata) -> (Option<std::num::NonZeroU64>, u64) {
  #[cfg(unix)]
  {
    use std::os::unix::fs::MetadataExt;
    (std::num::NonZeroU64::new(meta.ino()), meta.dev())
  }
  #[cfg(not(unix))]
  {
    let _ = meta;
    (None, 0)
  }
}

/// One blocking operation's result, shipped back to the select loop.
enum OpResult<H> {
  Spawned {
    scope: ScopeId,
    result: Result<SpawnedSource<H>, SourceError>,
  },
  Probed {
    probe: ProbeId,
    outcome: ProbeOutcome,
  },
  TornDown {
    scope: ScopeId,
  },
}

/// Runs one watcher's driver loop until `commands` closes or a `Close`
/// command arrives. Consumes the command receiver and the event sender; the
/// sender dropping is the consumer's end-of-stream.
pub(crate) async fn run<R, F>(
  config: DriverConfig,
  ops: F,
  commands: async_channel::Receiver<Command>,
  events: async_channel::Sender<(ScopeId, Change)>,
  on_scope_dead: impl Fn(ScopeId) + Send + Sync + 'static,
) where
  R: RuntimeLite,
  F: FsOps,
{
  let mut core = DriverCore::new(config.effective_move_window());
  let origin = R::now();
  let now = move || Instant::from_origin(R::now().duration_since(origin));
  // Unbounded so the blocking pool reports results with a plain `try_send`
  // (`send_blocking` does not exist on wasm builds, where async-channel has no
  // blocking API); the op volume is already bounded by outstanding operations
  // — one spawn/teardown per root plus one probe per parked batch item.
  let (op_tx, op_rx) = async_channel::unbounded::<OpResult<F::Handle>>();
  // `None` marks a source's receiver disconnecting — the end-of-stream fact
  // itself, which a dropped sender would otherwise erase silently.
  let mut os: SelectAll<
    futures_util::stream::BoxStream<'static, (ScopeId, Option<SourceMessage>)>,
  > = SelectAll::new();
  // The guard keeps the SelectAll from ever emptying: an empty SelectAll
  // reports termination, which would spin the loop's stream arm.
  os.push(futures_util::stream::pending().boxed());
  let mut handles: BTreeMap<ScopeId, F::Handle> = BTreeMap::new();
  let mut watch_replies: BTreeMap<ScopeId, WatchReply> = BTreeMap::new();
  let mut unwatch_replies: BTreeMap<ScopeId, futures_channel::oneshot::Sender<bool>> =
    BTreeMap::new();

  let close_reply = loop {
    execute_effects::<R, F>(
      &mut core,
      &ops,
      &config,
      &op_tx,
      &mut handles,
      &events,
      &mut unwatch_replies,
      &on_scope_dead,
      &now,
    );

    let deadline = core
      .poll_timeout()
      .map(|d| origin + d.elapsed_since_origin());
    let timer = async {
      match deadline {
        Some(at) => {
          R::sleep_until(at).await;
        }
        None => futures_util::future::pending::<()>().await,
      }
    }
    .fuse();
    futures_util::pin_mut!(timer);

    futures_util::select_biased! {
      cmd = commands.recv().fuse() => match cmd {
        Ok(Command::Watch { root, interest, reply }) => {
          let scope = core.on_watch(root, interest);
          watch_replies.insert(scope, reply);
        }
        Ok(Command::Unwatch { scope, reply }) => {
          if handles.contains_key(&scope) || watch_replies.contains_key(&scope) {
            unwatch_replies.insert(scope, reply);
            core.on_unwatch(scope);
          } else {
            let _ = reply.send(false);
          }
        }
        Ok(Command::Close { reply }) => break Some(reply),
        // The watcher facade dropped: same orderly teardown, nobody to tell.
        Err(_) => break None,
      },
      res = op_rx.recv().fuse() => {
        match res.expect("the driver holds a sender") {
          OpResult::Spawned { scope, result } => match result {
            Ok(spawned) => {
              let canonical_root = spawned.meta.root.clone();
              core.on_stream_spawned(scope, Ok(spawned.meta));
              handles.insert(scope, spawned.handle);
              os.push(
                spawned
                  .channels
                  .data
                  .map(move |msg| (scope, Some(msg)))
                  .chain(futures_util::stream::once(async move { (scope, None) }))
                  .boxed(),
              );
              // Control carries only Overflow/Fatal; its end needs no marker
              // (stream death is the DATA stream's end, and both close
              // together at teardown).
              os.push(
                spawned
                  .channels
                  .control
                  .map(move |msg| (scope, Some(msg)))
                  .boxed(),
              );
              let owned = watch_replies
                .remove(&scope)
                .is_some_and(|reply| reply.send(Ok((scope, canonical_root))).is_ok());
              if !owned {
                // The watch() future was cancelled: nobody holds the handle,
                // so the just-spawned stream would leak until close. Tear it
                // down as an immediate unwatch.
                core.on_unwatch(scope);
              }
            }
            Err(err) => {
              core.on_stream_spawned(scope, Err(clone_error(&err)));
              if let Some(reply) = watch_replies.remove(&scope) {
                let _ = reply.send(Err(err));
              }
            }
          },
          OpResult::Probed { probe, outcome } => core.on_probe_result(probe, outcome, now()),
          OpResult::TornDown { scope } => {
            if let Some(reply) = unwatch_replies.remove(&scope) {
              let _ = reply.send(true);
            }
          }
        }
      },
      _ = timer => core.on_timeout(now()),
      msg = os.next() => {
        if let Some((scope, msg)) = msg {
          match msg {
            Some(SourceMessage::Batch(events)) => core.on_batch(scope, events, now()),
            Some(SourceMessage::Overflow) => {
              // Acknowledge BEFORE acting: a loss racing the acknowledgement
              // either rides a fresh message or is covered by the rescan
              // this triggers.
              if let Some(handle) = handles.get(&scope) {
                handle.overflow_processed();
              }
              core.on_root_overflow(scope, now());
            }
            Some(SourceMessage::Fatal(_)) => core.on_source_fatal(scope, now()),
            // The data receiver disconnected while the stream should still
            // be live: the source died without managing to say so (its
            // sender dropped) — a dead stream, not a teardown of ours (that
            // path removes the handle before the disconnect can arrive).
            None => {
              if handles.contains_key(&scope) {
                core.on_source_fatal(scope, now());
              }
            }
          }
        }
      },
    }
  };

  // Orderly shutdown: quiesce every stream, drain what already arrived, and
  // deliver what fits — the final drain is documented best-effort (loss and
  // death signals are in-band messages, so anything undrained here is part
  // of that same best-effort remainder).
  let mut open: Vec<ScopeId> = handles.keys().copied().collect();
  for (scope, handle) in std::mem::take(&mut handles) {
    on_scope_dead(scope);
    let tx = op_tx.clone();
    R::spawn_blocking_detach(move || {
      handle.shutdown();
      let _ = tx.try_send(OpResult::TornDown { scope });
    });
  }
  let drain = async {
    while !open.is_empty() {
      match op_rx.recv().await {
        Ok(OpResult::TornDown { scope }) => {
          open.retain(|s| *s != scope);
          if let Some(reply) = unwatch_replies.remove(&scope) {
            let _ = reply.send(true);
          }
        }
        Ok(OpResult::Probed { probe, outcome }) => core.on_probe_result(probe, outcome, now()),
        Ok(OpResult::Spawned { .. }) => {}
        Err(_) => break,
      }
    }
  };
  let _ = R::timeout(Duration::from_secs(1), drain).await;
  execute_effects::<R, F>(
    &mut core,
    &ops,
    &config,
    &op_tx,
    &mut handles,
    &events,
    &mut unwatch_replies,
    &on_scope_dead,
    &now,
  );
  if let Some(reply) = close_reply {
    let _ = reply.send(());
  }
}

/// Executes the core's queued effects, feeding each outcome straight back.
#[allow(clippy::too_many_arguments)]
fn execute_effects<R, F>(
  core: &mut DriverCore,
  ops: &F,
  config: &DriverConfig,
  op_tx: &async_channel::Sender<OpResult<F::Handle>>,
  handles: &mut BTreeMap<ScopeId, F::Handle>,
  events: &async_channel::Sender<(ScopeId, Change)>,
  unwatch_replies: &mut BTreeMap<ScopeId, futures_channel::oneshot::Sender<bool>>,
  on_scope_dead: &(impl Fn(ScopeId) + Send + Sync),
  now: &impl Fn() -> Instant,
) where
  R: RuntimeLite,
  F: FsOps,
{
  while let Some(effect) = core.poll_effect() {
    match effect {
      Effect::SpawnStream { scope, root } => {
        let mut source_config = SourceConfig::new(vec![root]);
        source_config.exclusions = config.exclusions.clone();
        source_config.latency = config.latency;
        source_config.channel_capacity = config.os_batch_capacity;
        let ops = ops.clone();
        let tx = op_tx.clone();
        R::spawn_blocking_detach(move || {
          let result = ops.spawn_source(source_config);
          let _ = tx.try_send(OpResult::Spawned { scope, result });
        });
      }
      Effect::TeardownStream { scope } => {
        // Every scope end — explicit unwatch, root death, stream fatal —
        // funnels through this effect: tell the layer above, so a dead root
        // stops participating in its liveness checks.
        on_scope_dead(scope);
        if let Some(handle) = handles.remove(&scope) {
          let tx = op_tx.clone();
          R::spawn_blocking_detach(move || {
            handle.shutdown();
            let _ = tx.try_send(OpResult::TornDown { scope });
          });
        } else if let Some(reply) = unwatch_replies.remove(&scope) {
          // No stream ever existed (a failed spawn); the unwatch is complete.
          let _ = reply.send(true);
        }
      }
      Effect::Probe { probe, path } => {
        let ops = ops.clone();
        let tx = op_tx.clone();
        R::spawn_blocking_detach(move || {
          let outcome = ops.probe(&path);
          let _ = tx.try_send(OpResult::Probed { probe, outcome });
        });
      }
      Effect::Emit { scope, change } => match events.try_send((scope, change)) {
        Ok(()) => core.on_delivery(scope, Delivery::Accepted, now()),
        Err(async_channel::TrySendError::Full(_)) => {
          core.on_delivery(scope, Delivery::Refused, now());
        }
        // The consumer dropped its stream; shutdown arrives via the command
        // channel closing, so undeliverable changes are simply gone.
        Err(async_channel::TrySendError::Closed(_)) => {}
      },
    }
  }
}

/// Clones the driver-relevant shape of a spawn error: the core needs the
/// class, the caller keeps the original (io::Error is not Clone).
fn clone_error(err: &SourceError) -> SourceError {
  match err {
    SourceError::RootUnavailable { root, source } => SourceError::RootUnavailable {
      root: root.clone(),
      source: std::io::Error::new(source.kind(), source.kind().to_string()),
    },
    SourceError::Unsupported => SourceError::Unsupported,
    SourceError::NoRoots => SourceError::NoRoots,
    SourceError::TooManyExclusions { supplied } => SourceError::TooManyExclusions {
      supplied: *supplied,
    },
    SourceError::ExclusionRejected => SourceError::ExclusionRejected,
    SourceError::CreateFailed => SourceError::CreateFailed,
    SourceError::StartFailed => SourceError::StartFailed,
    SourceError::CallbackPanic => SourceError::CallbackPanic,
  }
}
