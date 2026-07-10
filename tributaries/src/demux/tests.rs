use std::{
  collections::HashMap,
  ffi::OsString,
  num::NonZeroUsize,
  path::Path,
  sync::{Arc, Mutex},
  time::Duration,
};

use agnostic_lite::tokio::TokioRuntime;
use tributary_fs::{Epoch, Interest, Location};

use super::{CONTROL_CAPACITY, Demux, Lane};
use crate::{
  driver::Tributaries,
  error::WatchError,
  event::{Event, EventKind},
  filter::Filter,
  options::TributariesOptions,
  source::{Armed, Source, SourceEvent},
  subscription::Subscription,
};

/// A path's `OsString` components — the key form these tests watch and feed under.
fn key(path: &str) -> Vec<OsString> {
  Path::new(path)
    .components()
    .map(|c| c.as_os_str().to_os_string())
    .collect()
}

/// Generous ceiling for one expected observation: everything here is in-process (no
/// kernel), so this only bounds a wedged pipeline, not ordinary latency.
const DEADLINE: Duration = Duration::from_secs(10);

/// The bounded window a NEGATIVE assertion watches for traffic that must not arrive.
const STARVED: Duration = Duration::from_millis(300);

/// How long the stall test lets the pipeline settle into its stalled state: the actor's
/// parked-Rescan retry tick is 25ms, so this spans many ticks on any CI machine.
const QUIESCE: Duration = Duration::from_millis(500);

/// The armed-root registry a [`StreamSource`] shares with its test's [`Feed`], so the
/// feed can mint raw events carrying the right root handle for a watched key.
type Roots = Arc<Mutex<HashMap<Vec<OsString>, u32>>>;

/// A channel-fed [`Source`] over `u32` handles: `next()` yields exactly what the test's
/// [`Feed`] sends — staying pending while the feed is idle, and draining (ending the
/// stream) when the feed is dropped. Arm/disarm maintain the live-root registry the
/// driver's liveness checks read.
struct StreamSource {
  next_handle: u32,
  live: HashMap<u32, Vec<OsString>>,
  roots: Roots,
  events: async_channel::Receiver<SourceEvent<OsString, u32>>,
}

impl Source<OsString> for StreamSource {
  type Handle = u32;

  fn canonicalize_key(&self, k: &[OsString]) -> Result<Vec<OsString>, WatchError> {
    Ok(k.to_vec())
  }

  async fn arm(&mut self, key: &[OsString]) -> Result<Armed<OsString, u32>, WatchError> {
    self.next_handle += 1;
    let handle = self.next_handle;
    self.live.insert(handle, key.to_vec());
    self
      .roots
      .lock()
      .expect("roots registry")
      .insert(key.to_vec(), handle);
    Ok(Armed::new(handle, key.to_vec()))
  }

  fn disarm(&mut self, handle: u32) {
    if let Some(key) = self.live.remove(&handle) {
      self.roots.lock().expect("roots registry").remove(&key);
    }
  }

  async fn next(&mut self) -> Option<SourceEvent<OsString, u32>> {
    self.events.recv().await.ok()
  }

  fn root_key(&self, handle: u32) -> Option<Vec<OsString>> {
    self.live.get(&handle).cloned()
  }
}

/// The test's producer half: feeds raw `Modified` source events under an armed root,
/// with a per-root monotone raw epoch. Dropping it drains the source (ends the stream).
struct Feed {
  tx: async_channel::Sender<SourceEvent<OsString, u32>>,
  roots: Roots,
  epochs: HashMap<u32, u64>,
}

impl Feed {
  /// Feeds one raw `Modified` at `path` under the armed root keyed `root`.
  async fn modified(&mut self, root: &str, path: &str) {
    let handle = *self
      .roots
      .lock()
      .expect("roots registry")
      .get(&key(root))
      .expect("the root is armed");
    let epoch = self.epochs.entry(handle).or_insert(0);
    *epoch += 1;
    let event = SourceEvent::new(
      handle,
      key(path),
      EventKind::Modified,
      Location::new(),
      Epoch::new(*epoch),
      None,
    );
    self.tx.send(event).await.expect("the source is live");
  }
}

/// The watcher/feed pair every test drives: a real driver over a [`StreamSource`],
/// with the owner→consumer event channel bounded at `capacity`.
fn rig(capacity: usize) -> (Tributaries<OsString, (), TokioRuntime, u32>, Feed) {
  let (tx, rx) = async_channel::unbounded();
  let roots: Roots = Arc::default();
  let source = StreamSource {
    next_handle: 0,
    live: HashMap::new(),
    roots: roots.clone(),
    events: rx,
  };
  let options = TributariesOptions::new()
    .with_event_capacity(NonZeroUsize::new(capacity).expect("nonzero capacity"));
  let watcher = Tributaries::with_source(source, options);
  (
    watcher,
    Feed {
      tx,
      roots,
      epochs: HashMap::new(),
    },
  )
}

/// Watches `path` with all-admitting interest/filter.
async fn watch(w: &Tributaries<OsString, (), TokioRuntime, u32>, path: &str) -> Subscription {
  w.watch(key(path), (), Interest::all(), Filter::all())
    .await
    .expect("watch")
}

/// The next event on `lane`, bounded by [`DEADLINE`]; panics on timeout or stream end.
async fn recv(lane: &Lane<OsString, ()>) -> Event<OsString, ()> {
  tokio::time::timeout(DEADLINE, lane.recv())
    .await
    .expect("a lane delivery within the deadline")
    .expect("the stream is still open")
}

/// Events for two subscriptions arrive on their own lanes, each in per-sub order.
#[tokio::test]
async fn events_route_to_their_own_lanes_in_per_sub_order() {
  let (w, mut feed) = rig(1024);
  let sub_a = watch(&w, "/a").await;
  let sub_b = watch(&w, "/b").await;
  let (demux, _rest) = Demux::spawn(w.clone(), 16);
  // Registered before any event flows, so nothing can land on rest.
  let lane_a = demux.lane(sub_a, 16).await;
  let lane_b = demux.lane(sub_b, 16).await;

  for i in 0..3 {
    feed.modified("/a", &format!("/a/f{i}")).await;
    feed.modified("/b", &format!("/b/f{i}")).await;
  }

  for i in 0..3 {
    let a = recv(&lane_a).await;
    assert_eq!(a.subscription(), sub_a, "lane A carries only sub A");
    assert_eq!(
      a.key(),
      key(&format!("/a/f{i}")).as_slice(),
      "lane A preserves per-sub delivery order"
    );
    let b = recv(&lane_b).await;
    assert_eq!(b.subscription(), sub_b, "lane B carries only sub B");
    assert_eq!(
      b.key(),
      key(&format!("/b/f{i}")).as_slice(),
      "lane B preserves per-sub delivery order"
    );
  }
}

/// An unregistered subscription's events land on the rest lane; from registration
/// onward they go to the fresh lane instead.
#[tokio::test]
async fn unregistered_subscription_lands_on_rest_until_registered() {
  let (w, mut feed) = rig(1024);
  let sub_a = watch(&w, "/a").await;
  let sub_b = watch(&w, "/b").await;
  let (demux, rest) = Demux::spawn(w.clone(), 16);
  let lane_a = demux.lane(sub_a, 16).await;

  feed.modified("/b", "/b/one").await;
  feed.modified("/a", "/a/one").await;

  let unclaimed = recv(&rest).await;
  assert_eq!(
    unclaimed.subscription(),
    sub_b,
    "the unregistered sub's event lands on the rest lane"
  );
  assert_eq!(unclaimed.key(), key("/b/one").as_slice());
  let claimed = recv(&lane_a).await;
  assert_eq!(
    claimed.subscription(),
    sub_a,
    "the registered sub's event bypasses rest"
  );

  // Register B, THEN feed: the registration is queued before the event enters the
  // shared stream, and the routing loop applies control before pulling events, so the
  // post-registration event deterministically reaches the lane, not rest.
  let lane_b = demux.lane(sub_b, 16).await;
  feed.modified("/b", "/b/two").await;
  let routed = recv(&lane_b).await;
  assert_eq!(
    routed.key(),
    key("/b/two").as_slice(),
    "from registration onward the sub's events go to its lane"
  );
}

/// The load-bearing stall-not-shed proof, end to end through the real actor: a full,
/// undrained lane stalls the demux (its only backpressure move is to stop receiving);
/// the one-slot shared channel backs up behind it; and the ACTOR — never the demux —
/// sheds the affected subscriptions to parked, epoch-dominating Rescans that are
/// delivered on the lanes once the stalled lane drains. B's starvation while A is
/// undrained is latency; its loss accounting stays in the actor.
#[tokio::test]
async fn stalled_lane_backs_up_shared_channel_and_actor_sheds_to_rescans() {
  // A one-slot shared channel so the stall propagates to the actor promptly.
  let (w, mut feed) = rig(1);
  let sub_a = watch(&w, "/a").await;
  let sub_b = watch(&w, "/b").await;
  let (demux, _rest) = Demux::spawn(w.clone(), 4);
  // Lane A is full after ONE undrained event; lane B is roomy.
  let lane_a = demux.lane(sub_a, 1).await;
  let lane_b = demux.lane(sub_b, 4).await;

  // Saturate A well past everything the pipeline can hold undrained (lane A buffer 1 +
  // the demux's one stalled in-flight send + the shared slot 1): the actor's try_send
  // hits Full and sheds A to a parked dominating Rescan.
  for i in 0..6 {
    feed.modified("/a", &format!("/a/f{i}")).await;
  }
  // Let the pipeline settle into its stalled state: lane A holds its one buffered
  // event, the demux is parked on an awaited send into it, and the shared channel
  // holds (or the actor parks) the rest.
  tokio::time::sleep(QUIESCE).await;
  // B's traffic now finds the shared channel it cannot pass: at most one event fits
  // the shared slot, so at least one hits Full and the ACTOR parks B's dominating
  // Rescan. The demux drops nothing — it is merely not receiving.
  for i in 0..3 {
    feed.modified("/b", &format!("/b/g{i}")).await;
  }

  // Starvation is LATENCY, not loss: while lane A is undrained the demux is stalled,
  // so nothing can reach lane B.
  assert!(
    tokio::time::timeout(STARVED, lane_b.recv()).await.is_err(),
    "lane B starves while the demux is stalled on the full lane A (latency, not loss)"
  );

  // Drain lane A: its ordinary deltas (epoch-monotone, in order), then the actor's
  // dominating Rescan naming A's covered key.
  let mut last_ordinary: Option<Epoch> = None;
  let rescan_a = loop {
    let event = recv(&lane_a).await;
    assert_eq!(event.subscription(), sub_a, "lane A carries only sub A");
    if event.is_rescan() {
      break event;
    }
    if let Some(prior) = last_ordinary {
      assert!(
        event.epoch() > prior,
        "lane A's ordinary deltas arrive in epoch order"
      );
    }
    last_ordinary = Some(event.epoch());
  };
  assert_eq!(
    rescan_a.key(),
    key("/a").as_slice(),
    "the shed Rescan names A's covered key to re-enumerate"
  );
  if let Some(max) = last_ordinary {
    assert!(
      rescan_a.epoch() > max,
      "the actor-minted Rescan dominates every ordinary delivery before it"
    );
  }

  // With A drained the demux unstalls, and B's loss surfaces as the actor's parked
  // dominating Rescan on B's OWN lane (possibly after a delta that squeaked into the
  // shared slot before it filled) — loss accounting stayed in the actor.
  let mut b_ordinary: Option<Epoch> = None;
  let rescan_b = loop {
    let event = recv(&lane_b).await;
    assert_eq!(event.subscription(), sub_b, "lane B carries only sub B");
    if event.is_rescan() {
      break event;
    }
    b_ordinary = Some(event.epoch());
  };
  assert_eq!(
    rescan_b.key(),
    key("/b").as_slice(),
    "B was shed by the ACTOR: a genuine dominating Rescan naming B's covered key"
  );
  if let Some(max) = b_ordinary {
    assert!(
      rescan_b.epoch() > max,
      "B's Rescan dominates any delta delivered before it"
    );
  }
}

/// Dropping a lane's receiver mid-traffic retires its subscription: its events are
/// discarded (never rerouted to rest), other lanes keep flowing, and the demux does
/// not stall on the dead lane.
#[tokio::test]
async fn dropped_lane_releases_its_sub_to_rest_without_stalling_the_demux() {
  let (w, mut feed) = rig(1024);
  let sub_a = watch(&w, "/a").await;
  let sub_b = watch(&w, "/b").await;
  let (demux, rest) = Demux::spawn(w.clone(), 16);
  // Capacity 1: were the demux to keep buffering for the dropped lane, it would wedge.
  let lane_a = demux.lane(sub_a, 1).await;
  let lane_b = demux.lane(sub_b, 16).await;

  feed.modified("/a", "/a/before").await;
  let before = recv(&lane_a).await;
  assert_eq!(
    before.subscription(),
    sub_a,
    "lane A was live before the drop"
  );

  drop(lane_a);
  for i in 0..4 {
    feed.modified("/a", &format!("/a/after{i}")).await;
  }
  feed.modified("/b", "/b/alive").await;

  let alive = recv(&lane_b).await;
  assert_eq!(
    alive.subscription(),
    sub_b,
    "lane B keeps flowing past the dead lane (no stall on it)"
  );
  assert_eq!(alive.key(), key("/b/alive").as_slice());

  // The released sub reverted to UNCLAIMED (Codex R49): every post-drop /a event —
  // including one a send-time reclamation recovered — surfaces on rest, none is lost,
  // and the table entry is gone.
  drop(feed);
  let mut rest_a = 0;
  loop {
    let drained = tokio::time::timeout(DEADLINE, rest.recv())
      .await
      .expect("rest drains within the deadline");
    match drained {
      Some(event) => {
        if event.subscription() == sub_a {
          rest_a += 1;
        }
      }
      None => break,
    }
  }
  assert_eq!(
    rest_a, 4,
    "all post-release /a traffic flows to rest — the sub is unclaimed again, nothing lost"
  );
  assert_eq!(
    demux.tracked_lanes(),
    1,
    "the released sub's slot was reclaimed; only lane B remains tracked"
  );
}

/// Codex R49 F1: registration BACKPRESSURES while the routing task is stalled — the
/// bounded control queue absorbs [`CONTROL_CAPACITY`] registrations and the next one
/// parks until the stall clears; it can never grow an unbounded queue. Race-free
/// negative window: the parked routing task is the only control consumer, and this
/// test is lane A's only drainer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registration_backpressures_while_the_demux_is_stalled() {
  let (w, mut feed) = rig(1024);
  let sub_a = watch(&w, "/a").await;
  let (demux, _rest) = Demux::spawn(w.clone(), 16);
  let lane_a = demux.lane(sub_a, 1).await;

  // Stall the routing task: the first /a event fills lane A (capacity 1), the second
  // parks the task on the awaited lane send.
  feed.modified("/a", "/a/one").await;
  feed.modified("/a", "/a/two").await;

  // Fill the control queue past its bound from a side task: CONTROL_CAPACITY sends are
  // admitted queue-side; the next one must PARK (bounded backpressure), so the task
  // cannot finish while the demux is stalled.
  let demux = std::sync::Arc::new(demux);
  let registrar = {
    let demux = std::sync::Arc::clone(&demux);
    let w = w.clone();
    tokio::spawn(async move {
      for i in 0..=CONTROL_CAPACITY {
        let sub = watch(&w, &format!("/reg{i}")).await;
        demux.lane(sub, 1).await;
      }
    })
  };
  tokio::time::sleep(std::time::Duration::from_millis(300)).await;
  assert!(
    !registrar.is_finished(),
    "the registration past the control bound parks while the demux is stalled — \
     registration cannot outgrow the bounded queue (Codex R49)"
  );

  // Clear the stall: draining lane A resumes the routing task, which drains the
  // control queue (control-first bias) and unparks the registrar.
  assert_eq!(recv(&lane_a).await.key(), key("/a/one").as_slice());
  assert_eq!(recv(&lane_a).await.key(), key("/a/two").as_slice());
  tokio::time::timeout(DEADLINE, registrar)
    .await
    .expect("the registrar unparks once the stall clears")
    .expect("registrar task");
}

/// Codex R50: releases LOST to a full control queue cannot leak the table. The exact
/// repro: stall the router on a full lane, admit CONTROL_CAPACITY registrations (the
/// queue is now full), drop every one of those lanes — each drop-release try_send
/// finds the queue full and is LOST — then clear the stall. The queued registrations
/// arrive with already-closed receivers and are never installed; the next registration
/// sweeps anything dead. The table ends bounded by the live lanes, not by the sixteen
/// dead ones.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_releases_on_a_full_control_queue_cannot_leak_the_table() {
  let (w, mut feed) = rig(1024);
  let sub_a = watch(&w, "/a").await;
  let (demux, _rest) = Demux::spawn(w.clone(), 16);
  let lane_a = demux.lane(sub_a, 1).await;

  // Stall the routing task on lane A's awaited send.
  feed.modified("/a", "/a/one").await;
  feed.modified("/a", "/a/two").await;

  // Admit exactly CONTROL_CAPACITY registrations while the router is parked — filling
  // the control queue — then DROP them all: every drop-release try_send hits the full
  // queue and is lost (the R50 hole).
  let mut doomed = Vec::new();
  for i in 0..CONTROL_CAPACITY {
    let sub = watch(&w, &format!("/doomed{i}")).await;
    doomed.push(demux.lane(sub, 1).await);
  }
  drop(doomed);

  // Clear the stall: the router drains the queued registrations — each arrives with
  // an already-closed receiver and is never installed (and each processing sweeps).
  assert_eq!(recv(&lane_a).await.key(), key("/a/one").as_slice());
  assert_eq!(recv(&lane_a).await.key(), key("/a/two").as_slice());

  // One live probe registration; its event round-trip proves it was applied, and by
  // then every doomed entry is gone — the table holds exactly lane A and the probe.
  let probe_sub = watch(&w, "/probe").await;
  let probe = demux.lane(probe_sub, 4).await;
  feed.modified("/probe", "/probe/touch").await;
  assert_eq!(recv(&probe).await.subscription(), probe_sub);
  assert_eq!(
    demux.tracked_lanes(),
    2,
    "sixteen lost releases leaked nothing — the table is bounded by live lanes \
     (register-time sweep + dead registrations never installed; Codex R50)"
  );
}

/// Codex R51: a replacement registration admitted and DROPPED while the router is
/// stalled still DISPLACES the predecessor. Without unconditional displacement the
/// sweep keeps the (live) predecessor, skip-install leaves it routed, and the queued
/// release carries the replacement's generation — the superseded lane would keep
/// consuming forever. With it: the predecessor ends (drains then `None`) and the
/// subscription reverts to unclaimed, surfacing on rest.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_replacement_still_displaces_the_predecessor_lane() {
  let (w, mut feed) = rig(1024);
  let sub_a = watch(&w, "/a").await;
  let sub_x = watch(&w, "/x").await;
  let (demux, rest) = Demux::spawn(w.clone(), 16);
  let lane_a = demux.lane(sub_a, 1).await;
  let lane_x_old = demux.lane(sub_x, 4).await;

  // Prove the predecessor routes, then stall the router on lane A.
  feed.modified("/x", "/x/before").await;
  assert_eq!(recv(&lane_x_old).await.subscription(), sub_x);
  feed.modified("/a", "/a/one").await;
  feed.modified("/a", "/a/two").await;

  // While stalled: admit a REPLACEMENT lane for /x and drop it before the router can
  // process the registration — the claim-then-release the displacement rule covers.
  let lane_x_new = demux.lane(sub_x, 4).await;
  drop(lane_x_new);

  // Clear the stall; the router then processes the replacement registration.
  assert_eq!(recv(&lane_a).await.key(), key("/a/one").as_slice());
  assert_eq!(recv(&lane_a).await.key(), key("/a/two").as_slice());

  // The predecessor was displaced: its sender is gone, so it drains then ends...
  assert!(
    tokio::time::timeout(DEADLINE, lane_x_old.recv())
      .await
      .expect("predecessor settles within the deadline")
      .is_none(),
    "the superseded lane ends — it must not keep receiving (Codex R51)"
  );
  // ...and /x is unclaimed again: its traffic surfaces on rest.
  feed.modified("/x", "/x/after").await;
  loop {
    let event = tokio::time::timeout(DEADLINE, rest.recv())
      .await
      .expect("rest receives within the deadline")
      .expect("stream still live");
    if event.subscription() == sub_x {
      assert_eq!(event.key(), key("/x/after").as_slice());
      break;
    }
  }
}

/// Codex R49 F2: watch → lane → unwatch → drop churn leaves NO residue — the lane
/// table is bounded by concurrently live lanes, never by lifetime registrations. The
/// trailing probe registration is an awaited send on the FIFO control queue, so every
/// queued release is processed before it; the tracked count then reflects exactly the
/// probe.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lane_churn_leaves_no_tracked_residue() {
  let (w, mut feed) = rig(1024);
  let (demux, _rest) = Demux::spawn(w.clone(), 16);

  for i in 0..32 {
    let path = format!("/churn{i}");
    let sub = watch(&w, &path).await;
    let lane = demux.lane(sub, 4).await;
    feed.modified(&path, &format!("{path}/touch")).await;
    assert_eq!(recv(&lane).await.subscription(), sub);
    w.unwatch(sub).await.expect("unwatch churn sub");
    drop(lane);
  }

  let probe_sub = watch(&w, "/probe").await;
  let probe = demux.lane(probe_sub, 4).await;
  // Route one event through the probe: it can only arrive after the routing task
  // APPLIED the probe's registration (admission alone is queue-side), and the FIFO
  // control queue puts every churn release before it — so the count below is settled.
  feed.modified("/probe", "/probe/touch").await;
  assert_eq!(recv(&probe).await.subscription(), probe_sub);
  assert_eq!(
    demux.tracked_lanes(),
    1,
    "32 churn cycles left zero residue — only the live probe lane is tracked \
     (bounded by concurrent lanes, not lifetime registrations; Codex R49)"
  );
}

/// Closing the watcher through the caller's clone ends the shared stream: the routing
/// task exits and every lane drains its buffered tail, then yields `None` — while a
/// dropped `Demux` handle beforehand changes nothing about routing.
#[tokio::test]
async fn closed_watcher_ends_every_lane_after_draining_buffers() {
  let (w, mut feed) = rig(1024);
  let sub_a = watch(&w, "/a").await;
  let sub_m = watch(&w, "/m").await;
  let (demux, rest) = Demux::spawn(w.clone(), 16);
  let lane_a = demux.lane(sub_a, 16).await;

  feed.modified("/a", "/a/one").await;
  let one = recv(&lane_a).await;
  assert_eq!(one.key(), key("/a/one").as_slice());

  // Dropping the Demux handle only closes the control channel — routing continues.
  drop(demux);
  feed.modified("/a", "/a/two").await;
  let two = recv(&lane_a).await;
  assert_eq!(
    two.key(),
    key("/a/two").as_slice(),
    "routing survives the dropped Demux handle"
  );

  // Buffer one more event in lane A, unobserved. The unclaimed sub_m marker lands on
  // rest strictly AFTER /a/three was sent into lane A (the demux routes the shared
  // stream sequentially), so receiving it proves /a/three sits in lane A's buffer.
  feed.modified("/a", "/a/three").await;
  feed.modified("/m", "/m/marker").await;
  let marker = recv(&rest).await;
  assert_eq!(
    marker.subscription(),
    sub_m,
    "the marker proves /a/three is buffered"
  );

  // Close through the caller's clone: the stream ends, the routing task exits, and the
  // lane drains its buffered tail before reporting end-of-stream.
  w.close().await.expect("close");
  let three = tokio::time::timeout(DEADLINE, lane_a.recv())
    .await
    .expect("the buffered tail drains");
  assert_eq!(
    three
      .expect("the buffered event precedes end-of-stream")
      .key(),
    key("/a/three").as_slice(),
    "the lane drains its buffer before ending"
  );
  assert!(
    tokio::time::timeout(DEADLINE, lane_a.recv())
      .await
      .expect("the lane ends")
      .is_none(),
    "a drained lane yields None once the watcher is closed"
  );
  assert!(
    tokio::time::timeout(DEADLINE, rest.recv())
      .await
      .expect("rest ends")
      .is_none(),
    "the rest lane ends with the stream too"
  );
}

/// Unwatching a subscription while its delivered events sit undrained in its lane:
/// the queued stragglers still arrive carrying the retired subscription (tolerated,
/// never lost by the demux), and the demux keeps routing after the lane is dropped.
#[tokio::test]
async fn unwatch_stragglers_arrive_on_the_kept_lane() {
  let (w, mut feed) = rig(1024);
  let sub_a = watch(&w, "/a").await;
  let sub_m = watch(&w, "/m").await;
  let (demux, rest) = Demux::spawn(w.clone(), 16);
  let lane_a = demux.lane(sub_a, 16).await;

  // Queue stragglers, then a marker for the unclaimed sub_m: its arrival on rest
  // proves the /a events were already routed into lane A's buffer (sequential routing),
  // so they are queued-at-unwatch-time by construction.
  for i in 0..3 {
    feed.modified("/a", &format!("/a/s{i}")).await;
  }
  feed.modified("/m", "/m/marker").await;
  let marker = recv(&rest).await;
  assert_eq!(
    marker.subscription(),
    sub_m,
    "the stragglers are buffered in lane A"
  );

  w.unwatch(sub_a).await.expect("unwatch");

  // The stragglers still arrive, carrying the retired subscription — the demux routes
  // by the event's own token and never consults the watch-set, so a kept lane receives
  // its sub's queued tail across the unwatch.
  for i in 0..3 {
    let straggler = recv(&lane_a).await;
    assert_eq!(
      straggler.subscription(),
      sub_a,
      "a straggler still carries the retired subscription"
    );
    assert_eq!(straggler.key(), key(&format!("/a/s{i}")).as_slice());
  }

  // Dropping the lane afterwards discards silently (any residue for the sub would hit
  // the retired slot — exercised in the lane-drop test); the demux keeps routing.
  drop(lane_a);
  feed.modified("/m", "/m/after").await;
  let after = recv(&rest).await;
  assert_eq!(
    after.key(),
    key("/m/after").as_slice(),
    "the demux keeps routing after the retired sub's lane is dropped"
  );
}
