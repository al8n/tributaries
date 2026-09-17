//! The root-coverage TRANSITIONS, end-to-end through the public [`Tributaries`] API
//! over a caller-supplied [`Source`] whose coverage state the cell controls.
//!
//! The laws a consumer asked for (issue #142): ONE notification per transition,
//! attributed to the root, never a terminal error for one root, and no periodic
//! reminder stream while coverage stays unproven — plus exactly one covering
//! [`Rescan`](EventKind::Rescan) when it is regained.
//!
//! The source here is in-memory on purpose. A real backend reaches the unproven state
//! only when every liveness-probe slot in its watcher is held, which is a race to
//! provoke and a wait to observe; the SEAM is what this suite is about, and driving it
//! directly is what makes each law a deterministic sequence rather than a timeout.

#![cfg(all(feature = "tokio", not(miri)))]

use std::{
  collections::HashMap,
  ffi::OsString,
  sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
  },
  time::Duration,
};

use tributaries::{
  Armed, Coverage, Epoch, Event, EventKind, Location, RootGlobs, Source, SourceEvent, Tributaries,
  TributariesOptions, WatchError, WatchOptions,
};

/// The one root every cell watches, in the umbrella's `OsString` component space.
fn root_key() -> Vec<OsString> {
  vec![OsString::from("/"), OsString::from("r")]
}

/// A key under the root.
fn child_key(name: &str) -> Vec<OsString> {
  let mut key = root_key();
  key.push(OsString::from(name));
  key
}

/// A source whose root-coverage answer the cell flips, and whose raw stream the cell
/// writes: the two halves of the seam the owner derives a transition from.
struct Probe {
  next_handle: u32,
  roots: HashMap<u32, Vec<OsString>>,
  /// The answer [`Source::coverage`] gives for every live root of this source.
  unproven: Arc<AtomicBool>,
  events: async_channel::Receiver<SourceEvent<OsString, u32>>,
}

impl Source<OsString> for Probe {
  type Handle = u32;

  fn canonicalize_key(&self, key: &[OsString]) -> Result<Vec<OsString>, WatchError> {
    Ok(key.to_vec())
  }

  async fn arm(
    &mut self,
    key: &[OsString],
    _globs: &RootGlobs,
  ) -> Result<Armed<OsString, u32>, WatchError> {
    self.next_handle += 1;
    let handle = self.next_handle;
    self.roots.insert(handle, key.to_vec());
    Ok(Armed::new(handle, key.to_vec()))
  }

  fn disarm(&mut self, handle: u32) {
    self.roots.remove(&handle);
  }

  async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
    self.events.recv().await.ok()
  }

  fn root_key(&self, handle: u32) -> Option<Vec<OsString>> {
    self.roots.get(&handle).cloned()
  }

  fn coverage(&self, handle: u32) -> Coverage {
    if self.roots.contains_key(&handle) && self.unproven.load(Ordering::SeqCst) {
      Coverage::Unproven
    } else {
      Coverage::Proven
    }
  }
}

/// The cell's end of a [`Probe`]: the stream it writes and the coverage answer it flips.
struct Pen {
  events: async_channel::Sender<SourceEvent<OsString, u32>>,
  unproven: Arc<AtomicBool>,
}

impl Pen {
  /// Writes one raw event onto the source's stream, in the shape a source mints it.
  async fn push(&self, key: Vec<OsString>, kind: EventKind<OsString>) {
    self
      .events
      .send(SourceEvent::new(
        1,
        key,
        kind,
        Location::new(),
        Epoch::START,
        None,
      ))
      .await
      .expect("the owner is still draining the source");
  }

  /// The covering `Rescan` a source stands at the root — what a refused liveness tick
  /// puts on the stream, and what the regaining probe puts there too.
  async fn root_rescan(&self) {
    self.push(root_key(), EventKind::Rescan).await;
  }

  /// A plain delta the cell reads as a fence: everything pushed before it has been
  /// consumed by the time it is delivered, so "nothing was delivered for those" is a
  /// deterministic assertion rather than a sleep.
  async fn fence(&self, name: &str) {
    self.push(child_key(name), EventKind::Modified).await;
  }

  fn set_unproven(&self, unproven: bool) {
    self.unproven.store(unproven, Ordering::SeqCst);
  }
}

fn assemble() -> (
  Tributaries<OsString, (), agnostic_lite::tokio::TokioRuntime, u32>,
  Pen,
) {
  let (tx, rx) = async_channel::unbounded();
  let unproven = Arc::new(AtomicBool::new(false));
  let source = Probe {
    next_handle: 0,
    roots: HashMap::new(),
    unproven: Arc::clone(&unproven),
    events: rx,
  };
  let watcher = Tributaries::with_source(source, TributariesOptions::new())
    .expect("the default capacities are in range");
  (
    watcher,
    Pen {
      events: tx,
      unproven,
    },
  )
}

/// The next delivery, or a panic naming what was being waited for — the suite's only
/// timeout, and it is a failure bound rather than a synchronization device.
async fn next_event(
  watcher: &mut Tributaries<OsString, (), agnostic_lite::tokio::TokioRuntime, u32>,
  expecting: &str,
) -> Event<OsString, ()> {
  match tokio::time::timeout(Duration::from_secs(5), watcher.next()).await {
    Ok(Some(event)) => event,
    Ok(None) => panic!("the stream ended while waiting for {expecting}"),
    Err(_) => panic!("nothing was delivered while waiting for {expecting}"),
  }
}

/// ONE `CoverageLost`, then SILENCE for every later tick of the same episode, then ONE
/// `CoverageRegained` followed by exactly ONE covering `Rescan` — and a root that loses
/// coverage again says so again.
#[tokio::test(flavor = "current_thread")]
async fn an_episode_is_two_notifications_and_one_rescan() {
  let (mut watcher, pen) = assemble();
  let sub = watcher
    .watch(root_key(), (), WatchOptions::new())
    .await
    .expect("the root arms");

  // THE LOSING EDGE. The source's covering `Rescan` is the event the owner reads the
  // state on, and the transition is what the consumer is told instead of it.
  pen.set_unproven(true);
  pen.root_rescan().await;
  let lost = next_event(&mut watcher, "the losing transition").await;
  assert_eq!(lost.subscription(), sub);
  assert_eq!(lost.kind(), &EventKind::CoverageLost);
  assert_eq!(lost.key(), root_key().as_slice());

  // NO REMINDER STREAM. Three more refused ticks stand three more instructions, and the
  // consumer — already told, already enumerating at its own cadence — is told nothing.
  // The fence is what proves it: it is delivered only after all three were consumed.
  for _ in 0..3 {
    pen.root_rescan().await;
  }
  pen.fence("after-the-repeats").await;
  let fenced = next_event(&mut watcher, "the fence past the repeated instructions").await;
  assert_eq!(
    fenced.kind(),
    &EventKind::Modified,
    "a repeated liveness instruction reaches no consumer"
  );
  assert_eq!(fenced.key(), child_key("after-the-repeats").as_slice());

  // A LOSS BELOW THE ROOT IS NOT THE EPISODE'S. It names other ground, so it is
  // delivered even while the root's own coverage is unproven.
  pen.push(child_key("elsewhere"), EventKind::Rescan).await;
  let below = next_event(&mut watcher, "a rescan below the root").await;
  assert_eq!(below.kind(), &EventKind::Rescan);
  assert_eq!(below.key(), child_key("elsewhere").as_slice());

  // THE REGAINING EDGE: the transition, then the ONE covering `Rescan`.
  pen.set_unproven(false);
  pen.root_rescan().await;
  let regained = next_event(&mut watcher, "the regaining transition").await;
  assert_eq!(regained.kind(), &EventKind::CoverageRegained);
  assert_eq!(regained.key(), root_key().as_slice());
  let covering = next_event(&mut watcher, "the covering rescan").await;
  assert_eq!(
    covering.kind(),
    &EventKind::Rescan,
    "the window nothing could account for is closed by re-enumerating it once"
  );
  assert_eq!(covering.key(), root_key().as_slice());

  pen.fence("after-the-regain").await;
  let fenced = next_event(&mut watcher, "the fence past the regain").await;
  assert_eq!(
    fenced.kind(),
    &EventKind::Modified,
    "and exactly one `Rescan` stood for it — nothing else follows the regain"
  );

  // AND AGAIN. A second episode is a second pair, never a state the first one latched.
  pen.set_unproven(true);
  pen.root_rescan().await;
  let lost_again = next_event(&mut watcher, "the second losing transition").await;
  assert_eq!(lost_again.kind(), &EventKind::CoverageLost);

  watcher.close().await.expect("the owner closes");
}

/// A root whose coverage is never in doubt produces no transition at all — the state
/// every source that does not report one answers, and the stream a consumer sees today.
#[tokio::test(flavor = "current_thread")]
async fn a_proven_root_reports_nothing() {
  let (mut watcher, pen) = assemble();
  let _sub = watcher
    .watch(root_key(), (), WatchOptions::new())
    .await
    .expect("the root arms");

  pen.root_rescan().await;
  let rescan = next_event(&mut watcher, "an ordinary root rescan").await;
  assert_eq!(
    rescan.kind(),
    &EventKind::Rescan,
    "a `Rescan` under a proven root is the loss it has always been"
  );

  pen.fence("plain").await;
  let fenced = next_event(&mut watcher, "the fence").await;
  assert_eq!(fenced.kind(), &EventKind::Modified);

  watcher.close().await.expect("the owner closes");
}
