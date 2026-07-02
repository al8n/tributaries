use super::*;
use agnostic_lite::tokio::TokioRuntime;

/// A watcher wired to a command channel the test controls (no driver task, no
/// platform), so registration protocols are observable in isolation.
fn manual_watcher() -> (Watcher<TokioRuntime>, async_channel::Receiver<Command>) {
  let (command_tx, command_rx) = async_channel::bounded(16);
  let (_event_tx, event_rx) = async_channel::bounded::<(ScopeId, Change)>(4);
  (
    Watcher {
      commands: command_tx,
      events: futures_util::StreamExt::boxed(event_rx),
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
    .clone()
}

/// A real directory to canonicalize against (watch() stats its root before
/// anything else).
fn scratch_dir(tag: &str) -> PathBuf {
  let dir = std::env::temp_dir().join(format!("tributary-fs-watcher-{}-{tag}", std::process::id()));
  std::fs::create_dir_all(&dir).expect("scratch dir");
  dir
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
