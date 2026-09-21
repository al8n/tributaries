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
  num::NonZeroUsize,
  sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
  },
  time::Duration,
};

use tributaries::{
  Armed, Coverage, Epoch, Event, EventKind, FaultKind, Location, RootGlobs, Source, SourceEvent,
  SourceFault, Tributaries, TributariesOptions, WatchError, WatchOptions,
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

/// One instruction on the source's own stream: the coverage answer to adopt BEFORE the
/// event is handed over, and the event itself.
///
/// Carrying the flip ON the stream — rather than storing it from the cell's own task — is
/// what makes a BACKPRESSURE cell deterministic. The owner reads the coverage answer on
/// every event it processes, so a flip stored from outside could land before an earlier
/// event is processed and move the edge onto that one instead, against a channel in the
/// other state entirely.
struct Step {
  unproven: Option<bool>,
  event: SourceEvent<OsString, u32>,
}

/// A source whose root-coverage answer the cell flips, and whose raw stream the cell
/// writes: the two halves of the seam the owner derives a transition from.
struct Probe {
  next_handle: u32,
  roots: HashMap<u32, Vec<OsString>>,
  /// The answer [`Source::coverage`] gives for every live root of this source.
  unproven: Arc<AtomicBool>,
  /// Whether this source can widen a root IN PLACE. The two widen shapes reach the same
  /// commit by different routes — a preserved handle, or a released one and a fresh arm — and
  /// only a source that says yes here takes the first.
  in_place_widen: bool,
  events: async_channel::Receiver<Step>,
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

  /// The in-place retarget: the handle is PRESERVED and only its key moves, which is what
  /// leaves the umbrella with no source event to re-read the coverage state on.
  async fn replace(
    &mut self,
    handle: u32,
    new_key: &[OsString],
  ) -> Result<Armed<OsString, u32>, WatchError> {
    if !self.in_place_widen || !self.roots.contains_key(&handle) {
      return Err(WatchError::source(SourceFault::new(FaultKind::Unsupported)));
    }
    self.roots.insert(handle, new_key.to_vec());
    Ok(Armed::new(handle, new_key.to_vec()))
  }

  async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
    let step = self.events.recv().await.ok()?;
    if let Some(unproven) = step.unproven {
      self.unproven.store(unproven, Ordering::SeqCst);
    }
    Some(step.event)
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
  events: async_channel::Sender<Step>,
  unproven: Arc<AtomicBool>,
}

impl Pen {
  /// Writes one raw event onto the source's stream, in the shape a source mints it.
  async fn push(&self, key: Vec<OsString>, kind: EventKind<OsString>) {
    self.push_becoming(None, key, kind).await;
  }

  /// The same, with the coverage answer the source adopts as this event is handed over.
  async fn push_becoming(
    &self,
    unproven: Option<bool>,
    key: Vec<OsString>,
    kind: EventKind<OsString>,
  ) {
    self
      .events
      .send(Step {
        unproven,
        event: SourceEvent::new(1, key, kind, Location::new(), Epoch::START, None),
      })
      .await
      .expect("the owner is still draining the source");
  }

  /// The covering `Rescan` a source stands at the root, carrying the coverage flip that
  /// makes it the episode's own edge.
  async fn root_rescan_becoming(&self, unproven: bool) {
    self
      .push_becoming(Some(unproven), root_key(), EventKind::Rescan)
      .await;
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
  assemble_with(TributariesOptions::new())
}

/// The same rig under a chosen event capacity — one slot is what makes a refused offer a
/// deterministic step rather than a flood.
fn assemble_with(
  options: TributariesOptions,
) -> (
  Tributaries<OsString, (), agnostic_lite::tokio::TokioRuntime, u32>,
  Pen,
) {
  assemble_widening(options, false)
}

/// The same rig with the source's widen shape chosen: in place on a preserved handle, or
/// release-and-rearm onto a fresh one.
fn assemble_widening(
  options: TributariesOptions,
  in_place_widen: bool,
) -> (
  Tributaries<OsString, (), agnostic_lite::tokio::TokioRuntime, u32>,
  Pen,
) {
  let (tx, rx) = async_channel::unbounded();
  let unproven = Arc::new(AtomicBool::new(false));
  let source = Probe {
    next_handle: 0,
    roots: HashMap::new(),
    unproven: Arc::clone(&unproven),
    in_place_widen,
    events: rx,
  };
  let watcher =
    Tributaries::with_source(source, options).expect("the chosen capacities are in range");
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

/// A ONE-SLOT event channel, so a refused offer is a deterministic step rather than a
/// flood: one delta fills it, and whatever the owner offers next is refused.
fn one_slot() -> TributariesOptions {
  TributariesOptions::new().with_event_capacity(NonZeroUsize::new(1).expect("one is nonzero"))
}

/// A `CoverageLost` the channel had no room for is delivered at the first moment the
/// consumer can take anything — and AHEAD of the delta that made the room, because a
/// consumer must not apply changes still believing a coverage state its watch has left.
///
/// Revert witness: drop the refused notice and the episode is invisible; the consumer keeps
/// applying deltas under a coverage claim nothing is checking, and the eventual regain
/// arrives as a `CoverageRegained` for an episode it was never told about.
#[tokio::test(flavor = "current_thread")]
async fn a_refused_loss_is_delivered_before_the_next_delta() {
  let (mut watcher, pen) = assemble_with(one_slot());
  let sub = watcher
    .watch(root_key(), (), WatchOptions::new())
    .await
    .expect("the root arms");

  // Both writes ride the ONE source stream, so the owner processes them in this order: the
  // delta takes the only slot, and the covering `Rescan` behind it carries the flip — the
  // loss is therefore offered to a channel that is full by construction.
  pen.fence("filler").await;
  pen.root_rescan_becoming(true).await;

  let filler = next_event(&mut watcher, "the delta that fills the channel").await;
  assert_eq!(
    filler.kind(),
    &EventKind::Modified,
    "staging: the slot was taken by a delta, not by the edge"
  );

  pen.fence("after").await;
  let lost = next_event(&mut watcher, "the refused losing transition, retried").await;
  assert_eq!(lost.subscription(), sub);
  assert_eq!(
    lost.kind(),
    &EventKind::CoverageLost,
    "the edge is owed until it is RECEIVED, and it goes first"
  );
  let covering = next_event(&mut watcher, "the stand-in the full channel parked").await;
  assert_eq!(
    covering.kind(),
    &EventKind::Rescan,
    "with the conservative `Rescan` the refusal parked behind it"
  );

  watcher.close().await.expect("the owner closes");
}

/// An edge is DERIVED from the difference between what the source reports and what the
/// consumer received, never queued — so a loss the consumer never received, followed by a
/// regain, cancels to nothing. Replaying the pair would describe a picture the consumer
/// never held; the window itself is still closed, by the one covering `Rescan`.
#[tokio::test(flavor = "current_thread")]
async fn a_regain_cancels_a_loss_the_consumer_never_received() {
  let (mut watcher, pen) = assemble_with(one_slot());
  let _sub = watcher
    .watch(root_key(), (), WatchOptions::new())
    .await
    .expect("the root arms");

  pen.fence("filler").await;
  pen.root_rescan_becoming(true).await;
  pen.root_rescan_becoming(false).await;

  let filler = next_event(&mut watcher, "the delta that fills the channel").await;
  assert_eq!(filler.kind(), &EventKind::Modified, "staging");

  pen.fence("after").await;
  let closing = next_event(&mut watcher, "the covering rescan").await;
  assert_eq!(
    closing.kind(),
    &EventKind::Rescan,
    "no edge at all: the two cancel, and the window closes by re-enumeration"
  );

  pen.fence("drive").await;
  let fenced = next_event(&mut watcher, "the fence past the regain").await;
  assert_eq!(
    fenced.kind(),
    &EventKind::Modified,
    "and nothing else stands behind it"
  );

  watcher.close().await.expect("the owner closes");
}

/// A `CoverageRegained` the channel refused still reaches the consumer BEFORE the covering
/// `Rescan` that closes its episode: the `Rescan` is the re-enumeration the regain
/// licenses, and reading it first would have the consumer act on an instruction whose
/// premise it has not been told.
#[tokio::test(flavor = "current_thread")]
async fn a_refused_regain_still_precedes_its_covering_rescan() {
  let (mut watcher, pen) = assemble_with(one_slot());
  let _sub = watcher
    .watch(root_key(), (), WatchOptions::new())
    .await
    .expect("the root arms");

  pen.root_rescan_becoming(true).await;
  let lost = next_event(&mut watcher, "the losing transition").await;
  assert_eq!(
    lost.kind(),
    &EventKind::CoverageLost,
    "staging: this consumer HAS the loss, so the regain is genuinely owed to it"
  );

  pen.fence("filler").await;
  pen.root_rescan_becoming(false).await;

  let filler = next_event(&mut watcher, "the delta that fills the channel").await;
  assert_eq!(filler.kind(), &EventKind::Modified, "staging");

  pen.fence("after").await;
  let regained = next_event(&mut watcher, "the refused regaining transition, retried").await;
  assert_eq!(
    regained.kind(),
    &EventKind::CoverageRegained,
    "the edge the full channel refused is owed, and it goes first"
  );

  pen.fence("drive").await;
  let covering = next_event(&mut watcher, "the covering rescan").await;
  assert_eq!(
    covering.kind(),
    &EventKind::Rescan,
    "and its covering `Rescan` follows it, never the other way round"
  );

  watcher.close().await.expect("the owner closes");
}

/// A WORLD START is a reconcile point of its own. A wider watch subsumes a root whose
/// episode is open; the commit re-arms that ground and the source can prove it again, but
/// nothing lands on the root's stream to read the state on. The re-pointed subscriber is
/// still told `CoverageRegained` — and told it BEFORE the widen's own `Rescan`, which is
/// the episode's cover.
///
/// This is the release-and-rearm shape: the subsumed root is disarmed and a wider one is
/// armed in its place.
#[tokio::test(flavor = "current_thread")]
async fn a_widen_of_a_lost_root_regains_before_its_rescan() {
  let (mut watcher, pen) = assemble_widening(TributariesOptions::new(), false);
  let narrow = watcher
    .watch(child_key("a"), (), WatchOptions::new())
    .await
    .expect("the narrow root arms");

  pen.set_unproven(true);
  pen.push(child_key("a"), EventKind::Rescan).await;
  let lost = next_event(&mut watcher, "the losing transition").await;
  assert_eq!(lost.subscription(), narrow);
  assert_eq!(
    lost.kind(),
    &EventKind::CoverageLost,
    "staging: the subscriber holds an OPEN episode when the widen commits"
  );

  // The widen's own arm is the proof: the wider root was opened and armed, so the source
  // can account for this ground again.
  pen.set_unproven(false);
  let _wide = watcher
    .watch(root_key(), (), WatchOptions::new())
    .await
    .expect("the wider root subsumes it");

  let regained = next_event(&mut watcher, "the regaining transition at the widen").await;
  assert_eq!(regained.subscription(), narrow);
  assert_eq!(
    regained.kind(),
    &EventKind::CoverageRegained,
    "the commit moved the state, and the edge is published for it"
  );
  assert_eq!(regained.key(), child_key("a").as_slice());
  let repoint = next_event(&mut watcher, "the widen's re-point rescan").await;
  assert_eq!(repoint.subscription(), narrow);
  assert_eq!(
    repoint.kind(),
    &EventKind::Rescan,
    "and the widen's own `Rescan` is this regain's cover, never ahead of it"
  );

  watcher.close().await.expect("the owner closes");
}

/// The same law on the IN-PLACE shape, which is the one that had no reconcile point at all:
/// the handle is preserved, so no root leaves the lost set and no fresh arm re-reads the
/// state. Without the reconcile at the commit the subscriber takes the widen `Rescan` and
/// stays `CoverageLost` for as long as the root is quiet — which, on a root nothing is
/// changing, is forever.
#[tokio::test(flavor = "current_thread")]
async fn a_replace_of_a_lost_root_regains_before_its_rescan() {
  let (mut watcher, pen) = assemble_widening(TributariesOptions::new(), true);
  let narrow = watcher
    .watch(child_key("a"), (), WatchOptions::new())
    .await
    .expect("the narrow root arms");

  pen.set_unproven(true);
  pen.push(child_key("a"), EventKind::Rescan).await;
  let lost = next_event(&mut watcher, "the losing transition").await;
  assert_eq!(lost.subscription(), narrow);
  assert_eq!(
    lost.kind(),
    &EventKind::CoverageLost,
    "staging: the subscriber holds an OPEN episode when the retarget commits"
  );

  pen.set_unproven(false);
  let _wide = watcher
    .watch(root_key(), (), WatchOptions::new())
    .await
    .expect("the sole root is retargeted in place");

  let regained = next_event(&mut watcher, "the regaining transition at the retarget").await;
  assert_eq!(regained.subscription(), narrow);
  assert_eq!(
    regained.kind(),
    &EventKind::CoverageRegained,
    "a preserved handle still gets its state re-read at the commit"
  );
  assert_eq!(regained.key(), child_key("a").as_slice());
  let repoint = next_event(&mut watcher, "the retarget's re-point rescan").await;
  assert_eq!(repoint.subscription(), narrow);
  assert_eq!(
    repoint.kind(),
    &EventKind::Rescan,
    "with the retarget's own `Rescan` behind it"
  );

  watcher.close().await.expect("the owner closes");
}

/// A subscription that JOINS an open episode is owed its `CoverageLost` at once. The owed
/// edge is otherwise checked only when something is delivered to that subscriber, and a
/// root whose coverage cannot be proven is exactly the root nothing is arriving for — so a
/// newcomer would trust coverage the watch has withdrawn, indefinitely.
#[tokio::test(flavor = "current_thread")]
async fn a_watch_joining_an_open_episode_is_told_lost_first() {
  let (mut watcher, pen) = assemble();
  let first = watcher
    .watch(root_key(), (), WatchOptions::new())
    .await
    .expect("the root arms");

  pen.set_unproven(true);
  pen.root_rescan().await;
  let lost = next_event(&mut watcher, "the losing transition").await;
  assert_eq!(lost.subscription(), first);
  assert_eq!(lost.kind(), &EventKind::CoverageLost, "staging");

  // A covered newcomer under the same root. NOTHING is pushed on the source stream after
  // it: the episode's state is all the owner has to go on.
  let joiner = watcher
    .watch(child_key("joiner"), (), WatchOptions::new())
    .await
    .expect("the covered newcomer commits");

  let told = next_event(&mut watcher, "the newcomer's losing transition").await;
  assert_eq!(told.subscription(), joiner);
  assert_eq!(
    told.kind(),
    &EventKind::CoverageLost,
    "a watch committed under a lost root is told so before anything else"
  );
  assert_eq!(
    told.key(),
    child_key("joiner").as_slice(),
    "at its OWN key — the statement is about the ground it owns"
  );

  // And it is a genuine episode for the newcomer, not a one-off notice: the regain reaches
  // it too, ahead of the covering `Rescan`.
  pen.set_unproven(false);
  pen.root_rescan().await;
  let mut regained = 0_usize;
  for _ in 0..2 {
    let event = next_event(&mut watcher, "a regaining transition").await;
    assert_eq!(event.kind(), &EventKind::CoverageRegained);
    regained += 1;
  }
  assert_eq!(
    regained, 2,
    "both subscribers held the episode, both are told"
  );

  watcher.close().await.expect("the owner closes");
}
