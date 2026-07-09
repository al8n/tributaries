//! The [`Source<C>`] binding seam (design §4) and its default local-filesystem
//! implementation over [`tributary_fs::Watcher`].
//!
//! The generic watch-set the umbrella maintains is source-agnostic: it plans
//! subsumption and fans events out purely in `Vec<C>` key space. A **source** is the
//! one place that knows how a key maps to a concrete watch, and how a raw change maps
//! back to a located key. For 0.1.0 the only source is [`FsSource`], binding
//! `C = OsString` (a path's components) to the local filesystem over one
//! [`tributary_fs::Watcher`]; a general remote-capable registry is M2.
//!
//! # The seam
//!
//! [`Source::arm`] maps a key to a concrete watch and reports the **canonical** key it
//! actually armed — a source may canonicalize (the filesystem adopts a root's real
//! path), so the umbrella keys its subsumption index on the coordinate the source
//! committed, not the one requested (design §4, the TOCTOU close). [`Source::disarm`]
//! synchronously **requests** release of a root, and [`Source::next`] yields the next raw change as a [`SourceEvent`]
//! carrying the owning root handle, the change's located key, its kind, and the metadata
//! the umbrella's fan-out and attribution consume.
//!
//! # Key ↔ path knowledge lives here only
//!
//! Rebuilding a path from key components and reversing a raw event's absolute path back
//! into components is the fs binding's private business. The umbrella never
//! re-implements it; it orchestrates subsumption and fan-out over `C` alone.

use std::{
  collections::{HashSet, VecDeque},
  ffi::OsString,
  path::PathBuf,
  vec::Vec,
};

use agnostic_lite::RuntimeLite;
use tributary_fs::{
  ChangeId, Epoch, Event as FsEvent, EventKind, Interest, Location, MovedEvent, RootHandle,
  WatchRootError, Watcher, WatcherOptions,
};

use crate::{
  error::{BuildError, WatchError},
  event::path_components,
};

#[cfg(test)]
mod tests;

/// The binding between the umbrella's generic `Vec<C>` key space and a concrete watcher
/// (design §4).
///
/// An implementor owns the source-specific knowledge of how a key maps to a real watch
/// and how a raw change maps back to a located key; the umbrella drives it as the single
/// writer and never re-implements that mapping. This is **static dispatch only** — a
/// `dyn`-compatible registry for heterogeneous remote sources is M2.
///
/// The default local-filesystem implementation is [`FsSource`].
///
/// # Robustness boundary — what the umbrella REQUIRES vs GUARANTEES
///
/// The umbrella drives a `Source` as its single writer and is hardened against one that
/// **misbehaves**. The line between what a conforming source must provide and what the umbrella
/// upholds regardless is drawn precisely here (cross-reference: driver-golden invariant II,
/// "Close-responsive").
///
/// **REQUIRED of a conforming `Source` (the umbrella relies on these):**
///
/// - **Generation-unique [`Handle`](Self::Handle)** — a handle value is never reused while any root
///   or not-yet-emitted event still carries it (the hard contract on [`Handle`](Self::Handle), Codex
///   R15). Makes handle ABA impossible; the umbrella routes strictly by handle rather than defending
///   against reuse.
/// - **Bounded [`arm`](Self::arm) / [`canonicalize_key`](Self::canonicalize_key)** — the umbrella
///   awaits [`arm`](Self::arm) and calls the synchronous [`canonicalize_key`](Self::canonicalize_key),
///   running each **to completion**, so both MUST make progress and resolve in **bounded time**.
///   [`arm`](Self::arm) is awaited only on a **caller-initiated** `watch`, running the reconcile to
///   completion (invariant I1); a wedged one blocks that one reconcile until the source honors the
///   contract (the caller may drop its own `watch` wait, but the umbrella still owns the in-flight
///   reconcile). A source that makes either **hang indefinitely** violates the contract; that is the
///   source's responsibility, not a bug the umbrella can `await`-around.
/// - **Synchronous, non-blocking [`disarm`](Self::disarm)** — release is a fire-and-forget
///   **request** the umbrella never awaits (see its docs): it returns at once, queuing any async
///   teardown inside the source, and applies the release no later than the next [`arm`](Self::arm) or
///   `Drop`. There is no `disarm` future to wedge the owner, so a slow transport release can never
///   block the mailbox — the reason Close-responsiveness holds *by construction* below.
/// - **Cancellation-safe [`next`](Self::next)** — dropping an in-flight [`next`](Self::next) future
///   loses and acknowledges no event (the hard contract on [`next`](Self::next)).
///
/// **GUARANTEED by the umbrella even against a misbehaving `Source`:**
///
/// - **A wedged [`next`](Self::next) never blocks command processing.** The owner drives
///   [`next`](Self::next) as one arm of a biased `select!`; a `next()` that never resolves is simply
///   a pending arm — the loop still services the command mailbox and the dedicated close signal.
/// - **Close-responsiveness against INTERNAL actions AND the command backlog, by construction
///   (invariant II).** `close` rides a **dedicated high-priority signal** — a separate channel the
///   owner checks at the TOP priority everywhere it selects (a non-blocking `try_recv` each iteration
///   AND the first `select!` arm, in both the run loop and the source-drain teardown), NOT the command
///   mailbox — so shutdown latency is **bounded independent of** how deep the unbounded `watch`/
///   `unwatch` backlog is (Codex R27). And the owner never awaits source I/O on any cleanup path:
///   owner actions that are *not* a caller-awaited `watch` — a `DropOrphan` from a dropped `watch`
///   grant, the send-failure / all-handles-gone orphan on the same path, and the source-drain teardown
///   — release an emptied root through the **synchronous** [`disarm`](Self::disarm). Because `disarm`
///   returns no future, no cleanup path can wedge the owner, so the close is serviced with no
///   scheduling discipline to get wrong. Dropping every handle tears the owner down and drops the
///   source, whose own `Drop` applies any still-pending releases.
/// - **No stranded or corrupt state.** A committed-but-unclaimed subscription is always reconciled
///   away (the `WatchGrant`, invariant I1); a subscription terminal-retired while unclaimed leaves no
///   lingering parked `Rescan` behind (Codex R20-F2); and a released-then-re-`watch`ed key never
///   surfaces the [`Overlaps`](tributary_fs::WatchRootError::Overlaps) the umbrella exists to subsume
///   away — a conforming source guarantees no arm surfaces an overlap caused by a released root
///   (contract clause 2), whether by pre-applying the release or by resolving the lower watcher's own
///   identity-aware `Overlaps` rejection and retrying, so the umbrella needs no flushing of its own.
///
/// **OPTIONAL of a source (a pure optimization, never relied on):**
///
/// - **In-place coverage reconcile** ([`set_cover`](Self::set_cover)), bidirectional (M2-B v2, Codex R36) — an opt-in, synchronous, fire-and-forget
///   request (the same non-blocking release-request shape as [`disarm`](Self::disarm)) to reclaim the
///   excess kernel coverage of a now-**over-broad** root — one that outlived the subscription whose key
///   equalled it, so it is broader than any live subscriber (design §5, M2-B). The umbrella issues it
///   from its single release primitive on the non-emptied unwatch path; a source that can prune below a
///   root (a per-directory descending backend) reclaims budget with **no gap and no re-crawl** — it
///   never releases survivor coverage — while a whole-subtree source (one stream / one recursive mark)
///   keeps the **default no-op**. Correctness NEVER depends on it: over-broadness is correctness-neutral
///   and self-healing, so a no-op, deferred, or partial reconcile is always conforming (the golden reason
///   the umbrella forwards it synchronously and moves on).
///
/// # `Send` bounds
///
/// **Both async methods return `Send` futures.** 0.1.0 targets tokio and smol, and the driver is a
/// single owned task spawned on their multi-threaded executors
/// ([`R::spawn_detach`](agnostic_lite::RuntimeLite::spawn_detach)) that drives arming and the event
/// pump inline in one `select!` loop — so *every* future the owner awaits must be able to cross
/// threads for `run(owner)` itself to be `Send`. The two awaited methods are [`arm`](Self::arm) and
/// [`next`](Self::next); [`disarm`](Self::disarm) is synchronous (it returns no future), and
/// [`canonicalize_key`](Self::canonicalize_key) / [`root_key`](Self::root_key) are synchronous
/// probes. The bounds are written explicitly on each return type (rather than left implicit by
/// `async fn`, whose futures carry no such bound), so a generic `S: Source<C>` owner is
/// structurally spawnable — every implementor's futures must satisfy them. This is now
/// unconditionally satisfiable for the fs source because [`tributary_fs::Watcher`] is
/// `Sync` (its `watch`/`unwatch` futures are `Send`). A fully `!Send` thread-per-core
/// (compio) variant — spawned via `spawn_local_detach` — is deferred to M2.
pub trait Source<C> {
  /// The armed-root token a successful [`arm`](Self::arm) yields, naming the concrete
  /// watch a later [`disarm`](Self::disarm) releases and an event's
  /// [`SourceEvent::handle`] identifies. `Copy + Eq + Hash` so the umbrella can key its
  /// per-root bookkeeping on it (the fs source uses [`RootHandle`]).
  ///
  /// # Generation-unique handle contract (hard requirement)
  ///
  /// A `Source` MUST mint a **generation-unique** handle on **every** [`arm`](Self::arm): a handle
  /// value is **never** reused for a new arm while any root **or** any not-yet-emitted event
  /// carrying that value is still live. Equivalently — no handle the umbrella has observed is ever
  /// reissued until the umbrella has **fully retired** the root it named (a [`disarm`](Self::disarm)
  /// whose retirement has reconciled, or a terminal event for which [`root_key`](Self::root_key) is
  /// `None`) **and** no further event can carry it. Unlike a weaker "never alias two *different*
  /// live roots" rule, this also forbids reusing a value for the **same** key right after a
  /// [`disarm`](Self::disarm): a re-arm always mints a *fresh* generation.
  ///
  /// This makes handle **ABA impossible**, and the umbrella relies on it rather than defending
  /// against ABA itself (Codex R15 — a defensive alias-detection was both incomplete and the wrong
  /// layer). Two consequences the umbrella depends on:
  ///
  /// - **An old-generation event never routes through a re-armed root.** A value the umbrella
  ///   released and re-armed names a *new* generation with a *new* handle, so any event still queued
  ///   from before the re-arm carries the **old, now-dead** handle. The umbrella routes strictly by
  ///   handle: [`root_key`](Self::root_key) is `None` for that dead handle (the source released it),
  ///   so the event falls to the dead-root retire/drain path — never onto the re-armed root. Were
  ///   the same value reused (ABA), that stale event would route through the live re-armed root
  ///   *after* the umbrella rebased its epochs, applying a stale change its restore
  ///   [`Rescan`](tributary_fs::EventKind::Rescan) no longer dominates (Codex R15-F1).
  /// - **A fresh arm's handle never aliases a live root.** The umbrella keys its reverse index
  ///   (handle → root) on this token; a generation-unique value is absent from that index at commit
  ///   time, so a fresh arm — including each one-at-a-time re-arm of a failed widen's disarmed
  ///   siblings, whose not-yet-restored siblings are **still recorded** — can never overwrite
  ///   another root's entry and strand it published-but-unroutable (Codex R15-F2).
  ///
  /// A conforming source therefore lets the umbrella rebind/commit onto the fresh handle
  /// unconditionally; a debug-only owner-level observed-handle `debug_assert` at the single arm
  /// choke point is the exhaustive tripwire for a contract-violating source (it catches reuse of a
  /// handle already retired out of the live index too, Codex R17), never a release-mode recovery.
  /// [`FsSource`] satisfies the contract structurally: its [`RootHandle`] carries a
  /// **monotonically-minted** `tributary_proto::ScopeId` never reissued for the life of the watcher.
  type Handle: Copy + Eq + core::hash::Hash;

  /// Canonicalizes the caller-supplied `key` into the source's own **canonical coordinate** —
  /// the single coordinate its events are located under — or reports why it cannot.
  ///
  /// The umbrella calls this at the **top** of every `watch` reconcile, **before** the key is
  /// classified against the watch-set, so *every* path commits the canonical coordinate — a
  /// fresh arm, a widen, and (critically) a subscription merely **covered** by an existing root,
  /// which arms nothing and so never adopts a canonical key at arm time. Without this, a covered
  /// non-canonical key would be committed verbatim and then silently miss every event, because
  /// real events arrive under the canonical coordinate its key never matches (design §4,
  /// invariant I2 — "one fs-canonical coordinate at one choke point").
  ///
  /// A source that canonicalizes (the filesystem resolves symlinks and `.`/`..`) returns the
  /// resolved key; a source whose key space is already canonical (a generic component key)
  /// returns `key` unchanged. This is a **synchronous** transform, mirroring
  /// [`root_key`](Self::root_key): [`FsSource`] resolves the path with the same canonicalization
  /// [`arm`](Self::arm) applies, so classification and the later arm agree on the coordinate.
  ///
  /// # Idempotence (hard contract)
  ///
  /// Canonicalizing an already-canonical key MUST return it unchanged, so re-canonicalizing at
  /// arm time (the [`Armed::canonical_key`] the umbrella re-keys onto) is a no-op — the umbrella
  /// relies on this to keep classification and commit in one coordinate.
  ///
  /// # Errors
  ///
  /// A [`WatchError`] when `key` cannot be canonicalized — for [`FsSource`], a
  /// [`WatchError::Canonicalize`] when the path does not exist or its metadata cannot be read.
  /// The umbrella surfaces it from `watch` rather than committing a key that would receive no
  /// events.
  fn canonicalize_key(&self, key: &[C]) -> Result<Vec<C>, WatchError>;

  /// Arms a concrete watch for `key`, returning the armed-root token plus the
  /// **canonical** key the source actually armed.
  ///
  /// A source may canonicalize the requested `key` (the filesystem adopts a root's real
  /// path), so it reports the coordinate it committed to via [`Armed::canonical_key`];
  /// the umbrella keys its subsumption index on that, not on the requested `key`, so
  /// subsequent events — reported in canonical coordinates — always route (design §4).
  ///
  /// # Errors
  ///
  /// A [`WatchError`] when the concrete watch cannot be armed.
  ///
  /// Returns a `Send` future (see the `Send` bounds note on the [trait](Self)).
  fn arm(
    &mut self,
    key: &[C],
  ) -> impl Future<Output = Result<Armed<C, Self::Handle>, WatchError>> + Send;

  /// Requests release of the root named by `handle`. Synchronous and non-blocking: this is a
  /// fire-and-forget release **request**, not an awaited teardown.
  ///
  /// The umbrella never observes a release's completion and always ignores its errors (there is no
  /// result), so `disarm` is *requested*, never *awaited*: the async boundary lives inside the
  /// source (which owns its transport and its own driver task), not on the owner's mailbox loop.
  /// This is what makes [`Close`](crate::Tributaries::close)-responsiveness hold **by construction**
  /// — no owner cleanup path can block on a release (driver-golden invariant II).
  ///
  /// # Hard contract
  ///
  /// 1. **Non-blocking.** `disarm` returns without performing blocking I/O or awaiting anything. A
  ///    source that needs async work to release (the fs source does) queues the request internally.
  /// 2. **No arm surfaces a released-root overlap (an OUTCOME clause), with per-arm release work
  ///    bounded by that arm's OWN overlapping conflicts.** A conforming source must guarantee that a
  ///    later [`arm`](Self::arm) never **surfaces** an
  ///    [`Overlaps`](tributary_fs::WatchRootError::Overlaps) rejection caused by a root whose release
  ///    was requested — this is what makes widen (release the narrow roots, arm the wider root) and
  ///    re-watch-after-orphan correct with **no** umbrella-side flushing. HOW it achieves this is the
  ///    source's own business, so long as the release work any *single* arm performs is bounded by
  ///    the releases that **overlap that arm's key** — never the whole (disjoint) backlog (Codex
  ///    R28/R29/R30). The overlapping-conflict set is the *caller's own*: an ancestor watch over N
  ///    roots the caller itself created and released legitimately resolves those N conflicts inside
  ///    that one caller-bounded `Watch` — invariant I1 run-to-completion — and a
  ///    [`close`](crate::Tributaries::close) queued behind it waits for that one reconcile, exactly
  ///    as it waits for any in-flight caller command (the RATIFIED semantics, Codex R33: close is
  ///    decoupled from *unrelated* backlogs — command floods, disjoint release queues — not from the
  ///    single caller reconcile it queued behind). Two conforming mechanisms:
  ///    - **pre-application** — apply queued releases before the watch; or
  ///    - **conflict-triggered application-and-retry** — as [`FsSource`] now does: attempt the arm,
  ///      and on the lower watcher's own `Overlaps` rejection apply the *named* conflicting release and
  ///      retry (plus a small bounded opportunistic pre-application to keep clause 5 eventual and cap
  ///      kernel-watch lingering). The lower watcher rejects by object/ancestor **identity** and names
  ///      the conflicting root, so this is **identity-aware by construction** — it catches case /
  ///      normalization aliases a byte-prefix overlap test would miss.
  ///
  ///    A release not needed to clear a given arm's conflicts is left queued and follows clause 5
  ///    (eventual — applied by a later arm's opportunistic or conflict-triggered application, or at
  ///    teardown): a disjoint kernel watch never conflicts with the arm, so leaving it briefly live
  ///    cannot cause an `Overlaps`.
  /// 3. **Logically dead immediately.** After `disarm(h)` returns, [`root_key`](Self::root_key)
  ///    answers `None`. The handle is retired from the umbrella's perspective the moment the request
  ///    is made; events still in flight carrying `h` fall to the dead-root drain exactly like any
  ///    post-retirement event.
  /// 4. **Idempotent / tolerant.** Releasing an unknown, dead, or already-released handle is a
  ///    no-op. Release errors are the source's own to absorb/log (there is no result), since a
  ///    released root's runtime conditions reach the umbrella in-band as events, not out of band
  ///    here.
  /// 5. **Eventual release.** A requested release is applied no later than the source's next
  ///    [`arm`](Self::arm) or its teardown (`Drop`). Between request and application the kernel watch
  ///    may briefly linger; any events it emits route to nothing (the subsumer entry is gone) —
  ///    correctness is unaffected.
  ///
  /// [`next`](Self::next) keeps its cancellation-safety contract unchanged, and [`arm`](Self::arm)
  /// keeps its caller-bounded liveness contract unchanged.
  fn disarm(&mut self, handle: Self::Handle);

  /// Requests that the root named by `handle` reconcile its ACTUAL coverage **in place** to the
  /// `retained` cover — the antichain of keys some live subscriber still needs — **bidirectionally**:
  /// reclaim the excess kernel coverage a now-over-broad root holds AND (re)arm any `retained` subtree
  /// the root is not currently covering. Synchronous and non-blocking: a fire-and-forget **request**,
  /// modeled exactly on [`disarm`](Self::disarm)'s contract style, never an awaited teardown.
  ///
  /// The umbrella issues this when a wide root outlives the subscription whose key equalled it — a
  /// `Widen` or a `Covered`-then-unwatch that leaves the armed root broader than any live subscriber
  /// (design §5, M2-B) — AND, re-issued on every `Covered` commit, when a survivor watches a subtree an
  /// EARLIER, narrower cover pruned (M2-B v2, Codex R36). Rather than release-and-rearm the whole root
  /// at the umbrella (which would move the survivors' coverage, forcing a gap-closing `Rescan`), the
  /// source reconciles the KERNEL coverage in place: it **never moves survivor coverage that is already
  /// correct**, so events under an unchanged `retained` key keep flowing with **no gap and no loss** —
  /// the property that keeps a reconcile-to-cover `Rescan`-free. This is the golden rationale:
  /// *reconcile-in-place at the source beats release-and-rearm at the umbrella because the survivors'
  /// coverage never moves.*
  ///
  /// # Hard contract (mirrors [`disarm`](Self::disarm))
  ///
  /// 1. **Non-blocking.** `set_cover` returns without blocking I/O or awaiting anything. A source that
  ///    needs async work to prune or re-arm (the fs source does) queues the request internally.
  /// 2. **Reconcile to the retained cover — never gap a retained-and-covered subtree.** The source
  ///    reconciles its actual coverage to `retained`: it MUST NOT reduce coverage below any `retained`
  ///    prefix it currently covers (every key under such a prefix keeps delivering with no gap), it MAY
  ///    reclaim coverage strictly outside every `retained` prefix, and it SHOULD (re)arm any `retained`
  ///    prefix it does not currently cover — one a previously-applied narrower cover pruned. Reconciling
  ///    UP re-establishes real coverage for a survivor that returned to a pruned subtree; the umbrella
  ///    separately parks a dominating bridging `Rescan` for that survivor to cover the request→apply
  ///    gap, so the re-arm itself owes no `Rescan` and emits none.
  /// 3. **Prompt when it can, eventual otherwise, or never.** A source SHOULD apply a requested
  ///    reconcile promptly and independently of any later call. [`FsSource`] does: it forwards the
  ///    cover to the watcher's control channel the instant `set_cover` is called, via a non-blocking
  ///    reply-less request, so the normal case — the channel has room — applies WITHOUT waiting for a
  ///    future [`arm`](Self::arm) or any other operation. This matters because a `Covered`-outside grow
  ///    arms nothing (clause 6): a source that applied only from `arm` would leave such a grow deferred
  ///    indefinitely, and the writes after the newcomer's re-crawl and before the grow would be lost
  ///    (Codex R37-F2). Only when the control channel is momentarily full does [`FsSource`] DEFER,
  ///    re-forwarding at the next source op that touches the watcher (another `set_cover`, a
  ///    [`disarm`](Self::disarm), or an [`arm`](Self::arm)). A **no-op is still conforming**: an
  ///    unreconciled root is merely over-broad or, for the grow half, briefly under-covered — both
  ///    correctness-neutral and self-healing (the umbrella's bridging `Rescan` and next re-issue
  ///    converge). After this promptness the umbrella's bridging-`Rescan` window for a grown newcomer is
  ///    bounded by control-channel availability rather than by an arbitrary later arm.
  /// 4. **Idempotent / tolerant.** Reconciling an unknown, dead, or already-released handle is a no-op.
  ///    A handle whose [`disarm`](Self::disarm) was already requested is logically dead, so its
  ///    set_cover is superseded by the release (the whole root is going away — nothing to reconcile in
  ///    place). There is no result; errors are the source's own to absorb.
  /// 5. **Purely an optimization.** Correctness MUST NEVER depend on set_cover. It reclaims and restores
  ///    budget (kernel watch descriptors); it changes no delivery the umbrella promises. The umbrella
  ///    keys, fans out, and attributes identically whether or not any set_cover is ever applied.
  /// 6. **Freshness by re-issue (the umbrella's guarantee, a queueing source's obligation).** A
  ///    `Covered` commit changes a root's membership **without** any `Source` call (it arms nothing),
  ///    so the umbrella RE-ISSUES this request with the recomputed retained cover on **every** such
  ///    membership change — and that fresh cover now INCLUDES the newcomer, which is exactly the grow
  ///    trigger. A source that QUEUES requests (rather than applying them inline) MUST therefore apply
  ///    the **LATEST** request per handle and **never** an older snapshot: a stale queued cover, applied
  ///    after a newcomer was covered under the root, would prune coverage that newcomer needs — and,
  ///    because set_cover emits no `Rescan` (clause 2), that loss would be silent. A re-issued
  ///    `retained` that includes the root's **own** key retains the whole root (its strictly-outside set
  ///    is empty), so it **cancels** any queued reconcile for that handle — the umbrella's
  ///    cancel-equivalent, sent when a subscriber re-pins the root at its own key. This obligation is
  ///    vacuous for an inline (non-queueing) or no-op source.
  ///
  /// The **default is a no-op**, so an implementor opts in only if it can reclaim/restore coverage
  /// below a root (a per-directory descending backend). A whole-subtree source (one stream / one
  /// recursive mark per root) has nothing to reconcile in place — its actual coverage never shrank —
  /// and keeps the default; a `Covered`-outside newcomer on it is served by the umbrella's one benign
  /// bridging `Rescan` alone.
  ///
  /// `retained` is a prefix-free antichain in the same `C` key space as [`arm`](Self::arm): every key
  /// lies under exactly one member, and no member descends from another.
  fn set_cover(&mut self, handle: Self::Handle, retained: &[Vec<C>]) {
    let _ = (handle, retained);
  }

  /// The next raw change as a [`SourceEvent`], or [`None`] once the source is closed and
  /// drained. Returns a `Send` future so the owner can pump the source's stream from its
  /// spawned task (see the `Send` bounds note on the [trait](Self)).
  ///
  /// # `next` MUST be cancellation-safe (hard contract)
  ///
  /// The owner drives `next()` as one arm of a [`select!`](futures_util::select_biased)
  /// loop, racing it against the command mailbox and the settle timer. When another arm
  /// wins, the in-flight `next()` future is **dropped before it resolves**. That drop
  /// **must lose no event and acknowledge none**: the very next `next()` call must still
  /// yield the change the dropped future would have. This is the cancellation-safety of
  /// [`async_channel::Receiver::recv`](async_channel::Receiver::recv) or a `Stream` poll —
  /// dropping the future only abandons the *wait*, never a dequeued item.
  ///
  /// Concretely, a source that **dequeues-then-acknowledges** an event MUST NOT acknowledge
  /// (or otherwise consume/drop) it until it has been *returned* from `next()`. A source
  /// that acks inside the future — before it resolves — silently loses the event on
  /// cancellation, and the owner parks **no** `Rescan` for it (it never saw the event), so
  /// the loss is silent. Model the dequeue as happening on the poll that *returns* `Ready`,
  /// not on an earlier poll.
  ///
  /// [`FsSource`] satisfies this: its `next` awaits [`tributary_fs::Watcher::next`], itself
  /// an `async_channel` receive, which is cancel-safe by construction.
  fn next(&mut self) -> impl Future<Output = Option<SourceEvent<C, Self::Handle>>> + Send;

  /// The **canonical key** of the root `handle` names, or [`None`] once that root is dead
  /// or retired — a **synchronous** liveness probe (mirroring
  /// [`tributary_fs::Watcher::root_path`], which reads a live registry snapshot without
  /// I/O).
  ///
  /// The owner uses it to tell a **terminal** coverage-loss signal (the root vanished —
  /// `root_key` is `None`, so the root is retired, freeing its index / filter / epoch
  /// state) from an **overflow** re-enumeration (the root is still live — `root_key` is
  /// `Some`, so the root is kept and the consumer re-enumerates). Because it is out of
  /// band, it never races the event stream the owner drives (design §4, I4).
  fn root_key(&self, handle: Self::Handle) -> Option<Vec<C>>;
}

/// The outcome of a successful [`Source::arm`]: the armed-root token plus the canonical
/// key the source committed to.
///
/// A plain owned data carrier. [`handle`](Self::handle) names the watch for a later
/// [`disarm`](Source::disarm); [`canonical_key`](Self::canonical_key) is the coordinate
/// the umbrella keys its subsumption index on (see [`Source::arm`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Armed<C, H> {
  handle: H,
  canonical_key: Vec<C>,
}

impl<C, H> Armed<C, H> {
  /// Builds the [`arm`](Source::arm) outcome from the armed-root `handle` and the
  /// `canonical_key` the source committed to — the constructor an out-of-tree [`Source`]
  /// uses to report what it armed.
  pub fn new(handle: H, canonical_key: Vec<C>) -> Self {
    Self {
      handle,
      canonical_key,
    }
  }

  /// The armed-root token, naming this watch for [`disarm`](Source::disarm) and matching
  /// an event's [`SourceEvent::handle`].
  #[inline]
  #[must_use]
  pub const fn handle(&self) -> H
  where
    H: Copy,
  {
    self.handle
  }

  /// The canonical key the source actually armed — the coordinate the umbrella keys its
  /// subsumption index on, since a source may canonicalize the requested key. Its
  /// components are in the same `C` space events are located in.
  #[inline]
  #[must_use]
  pub fn canonical_key(&self) -> &[C] {
    &self.canonical_key
  }
}

/// One raw change from a [`Source`] — a plain owned data carrier of everything the
/// umbrella's fan-out and attribution consume to build a delivered
/// [`Event`](crate::Event) with no information loss.
///
/// A source produces these; the umbrella resolves the owning root by
/// [`handle`](Self::handle), fans the change out to every subscription whose key covers
/// [`key`](Self::key), and (for a move) decomposes it per subscriber using
/// [`from`](Self::from). The [`kind`](Self::kind) reuses the filesystem event vocabulary
/// [`EventKind`] unchanged — a source converts into it at the binding rather than
/// inventing a parallel enum.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SourceEvent<C, H> {
  handle: H,
  key: Vec<C>,
  kind: EventKind,
  from: Option<Vec<C>>,
  location: Location,
  epoch: Epoch,
  change_id: ChangeId,
}

impl<C, H> SourceEvent<C, H> {
  /// Builds a source event from its parts — the constructor an out-of-tree [`Source`]
  /// uses to report a raw change in its own `C` key space.
  ///
  /// `handle` is the armed root the change belongs to; `key` its full located key;
  /// `kind` what happened (in the [`EventKind`] vocabulary); `from` the move-source key
  /// for a [`Moved`](EventKind::Moved) (`None` for every single-endpoint kind);
  /// `location` the change's root-relative location; `epoch` the raw source epoch; and
  /// `change_id` the change's unique id.
  pub fn new(
    handle: H,
    key: Vec<C>,
    kind: EventKind,
    from: Option<Vec<C>>,
    location: Location,
    epoch: Epoch,
    change_id: ChangeId,
  ) -> Self {
    Self {
      handle,
      key,
      kind,
      from,
      location,
      epoch,
      change_id,
    }
  }

  /// The armed root this change belongs to — the token [`Source::arm`] returned for it.
  #[inline]
  #[must_use]
  pub const fn handle(&self) -> H
  where
    H: Copy,
  {
    self.handle
  }

  /// The change's full located key: its components in `C` space (for the fs source, the
  /// change path's components). Coverage and coalescing key on this.
  #[inline]
  #[must_use]
  pub fn key(&self) -> &[C] {
    &self.key
  }

  /// What happened, in the filesystem event vocabulary. A [`Moved`](EventKind::Moved)
  /// still carries its [`MovedEvent`] payload, so a whole-move delivery stays lossless.
  #[inline]
  #[must_use]
  pub fn kind(&self) -> &EventKind {
    &self.kind
  }

  /// The move **source** key, present only for a [`Moved`](EventKind::Moved) — the second
  /// endpoint the umbrella decomposes and the coalescer keys on. `None` for every
  /// single-endpoint kind.
  #[inline]
  #[must_use]
  pub fn from(&self) -> Option<&[C]> {
    self.from.as_deref()
  }

  /// The change's location relative to its armed root — the metadata the umbrella carries
  /// onto the delivered event.
  #[inline]
  #[must_use]
  pub fn location(&self) -> &Location {
    &self.location
  }

  /// The raw source epoch this change was emitted under. The umbrella rebases it into
  /// each subscription's own monotone space at delivery (design §8); it is never
  /// delivered raw.
  #[inline]
  #[must_use]
  pub const fn epoch(&self) -> Epoch {
    self.epoch
  }

  /// The change's unique id (monotonic per source).
  #[inline]
  #[must_use]
  pub const fn change_id(&self) -> ChangeId {
    self.change_id
  }

  /// Whether this is a [`Rescan`](EventKind::Rescan) — the coverage-loss signal the
  /// umbrella fans out to every subscriber, bypassing coverage and filtering.
  #[inline]
  #[must_use]
  pub const fn is_rescan(&self) -> bool {
    self.kind.is_rescan()
  }

  /// The rename payload, if this is a [`Moved`](EventKind::Moved).
  #[inline]
  #[must_use]
  pub const fn moved(&self) -> Option<&MovedEvent> {
    self.kind.moved()
  }
}

/// The default source: the local filesystem, over one [`tributary_fs::Watcher`].
///
/// Binds `C = OsString` (a path's [components](std::path::Path::components)) to real
/// kernel watches. This is the only place the crate maps a key to a path and reverses a
/// raw filesystem event back into a key.
pub struct FsSource<R: RuntimeLite> {
  watcher: Watcher<R>,
  /// Roots whose release was requested (via the synchronous [`disarm`](Source::disarm)) but not yet
  /// applied to the [`Watcher`], each paired with the released root's **canonical path** captured at
  /// `disarm` time (while it was still live in the registry). [`arm`](Source::arm) applies these two
  /// ways (contract clause 2, Codex R29): (1) **opportunistically** it pops and unwatches at most
  /// [`OPPORTUNISTIC_RELEASES`] of the OLDEST entries per arm — keeping clause 5 eventual (every queued
  /// release is applied within a bounded number of subsequent arms) and capping how long a
  /// released-but-lingering kernel watch survives — and (2) **on demand** it resolves any
  /// [`Overlaps`](tributary_fs::WatchRootError::Overlaps) the watch attempt reports by unwatching the
  /// entry the watcher *named* as the conflict (identity-aware — it catches case/normalization aliases)
  /// and retrying. Either way the release work a single arm awaits is **bounded independent of the
  /// queue depth**, so a caller-bounded `Watch`, and any [`close`](crate::Tributaries::close) queued
  /// behind it, never waits on the whole backlog (Codex R28/R29). A `None` path means the root was
  /// already torn down when disarmed; it can never be the *named* conflict, so it is applied only
  /// opportunistically (or at `Drop`, where the [`Watcher`]'s own teardown releases every live root).
  /// Bounded in practice by the live-root count: each generation-unique handle is released at most once.
  pending_releases: VecDeque<(RootHandle, Option<PathBuf>)>,
  /// Mirror of [`pending_releases`](Self::pending_releases) for O(1)
  /// [`root_key`](Source::root_key) liveness answers — contract clause 3: a requested release is
  /// logically dead **immediately**, before the transport teardown is applied.
  pending_set: HashSet<RootHandle>,
  /// Roots whose in-place coverage reconcile was requested (via the synchronous
  /// [`set_cover`](Source::set_cover)) but DEFERRED because the watcher's control channel was
  /// momentarily full, each paired with the **retained cover** as canonical paths. The normal path
  /// does NOT queue: [`set_cover`](Source::set_cover) forwards the cover PROMPTLY through
  /// [`Watcher::request_set_cover`](tributary_fs::Watcher::request_set_cover) (a non-blocking
  /// try_send), so a `Covered`-outside grow applies WITHOUT waiting for a later `arm` (Codex R37-F2:
  /// a `Covered` commit arms nothing, so a queue-only cover would otherwise wait forever). Only when
  /// that channel is full does an entry land here, to be re-forwarded through the prompt path at the
  /// next source op that touches the watcher — [`drain_pending_set_covers`](Self::drain_pending_set_covers),
  /// run at the START of every [`set_cover`](Source::set_cover) and [`disarm`](Source::disarm) — and,
  /// as a bounded belt, by [`arm`](Source::arm)'s opportunistic drain of at most
  /// [`OPPORTUNISTIC_SET_COVERS`] entries via [`Watcher::set_cover`](tributary_fs::Watcher::set_cover).
  /// A set_cover is a pure optimization, so nothing is on the correctness path: an entry left queued
  /// (or dropped at `Drop`, where the [`Watcher`] tears every root down anyway) merely leaves the root
  /// briefly over-broad or under-covered. **Superseded by release**: a set_cover for a handle whose
  /// [`disarm`](Source::disarm) was requested is moot (the whole root is going away), so
  /// [`disarm`](Source::disarm) drops any queued entry for its handle and both
  /// [`set_cover`](Source::set_cover) and the drain refuse to apply one for a pending-release handle.
  /// **At most one entry per handle (LATEST-WINS)**: a newer request for a handle replaces its older
  /// queued cover, so the umbrella's freshness re-issue on a `Covered` commit (contract clause 6, Codex
  /// R35/R36) is applied — never an older snapshot — which carries both the shrink-newer-cover AND the
  /// grow (a re-issued cover that once again includes a previously-pruned survivor subtree). A re-issued
  /// cover that pins the root's OWN registry path is the **cancel-equivalent**: the latest-wins drop
  /// discards any stale narrower snapshot, and the prompt forward reconciles the core back to FULL
  /// coverage (its broadening delta re-arms everything the narrower cover pruned).
  pending_set_covers: VecDeque<(RootHandle, Vec<PathBuf>)>,
}

impl<R: RuntimeLite> core::fmt::Debug for FsSource<R> {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_struct("FsSource")
      .field("watcher", &self.watcher)
      .finish()
  }
}

impl<R: RuntimeLite> FsSource<R> {
  /// Builds a local-filesystem source, spawning the underlying `tributary-fs` watcher on
  /// `R`.
  ///
  /// # Errors
  ///
  /// [`BuildError::Fs`] when the underlying `tributary-fs` watcher cannot be built.
  pub fn new(options: WatcherOptions) -> Result<Self, BuildError> {
    Ok(Self {
      watcher: Watcher::new(options)?,
      pending_releases: VecDeque::new(),
      pending_set: HashSet::new(),
      pending_set_covers: VecDeque::new(),
    })
  }

  /// Flushes queued in-place coverage reconciles through the reply-less PROMPT path (Codex
  /// R37-F2): each pending cover is forwarded via
  /// [`Watcher::request_set_cover`](tributary_fs::Watcher::request_set_cover) and dropped on
  /// success, or dropped outright when its handle's release was since requested (superseded). Only
  /// the covers the control channel could not accept (momentarily full, or closed) stay queued.
  /// Called at every `FsSource` op that already touches the watcher ([`set_cover`](Source::set_cover),
  /// [`disarm`](Source::disarm)), so a sustained-full channel is the sole deferral case and any later
  /// source activity drains the backlog. Each entry costs one non-blocking `try_send`; the queue is
  /// bounded by the live-root count.
  fn drain_pending_set_covers(&mut self) {
    let watcher = &self.watcher;
    let pending_set = &self.pending_set;
    self.pending_set_covers.retain(|(handle, retained)| {
      // Superseded by a requested release — drop (the whole root is going away).
      if pending_set.contains(handle) {
        return false;
      }
      // Keep iff the prompt request could NOT be enqueued (channel full/closed); a success applies
      // it, so drop it.
      !watcher.request_set_cover(*handle, retained.clone())
    });
  }
}

/// How many of the OLDEST queued releases each [`arm`](Source::arm) applies **opportunistically**
/// (unwatched up front, regardless of overlap) before attempting the watch. Keeps the release queue
/// draining under a bounded per-arm cost so clause 5 stays eventual (every queued release is applied
/// within a bounded number of subsequent arms) and a released-but-lingering kernel watch is torn down
/// promptly, while HARD-BOUNDING the release work any single arm awaits (Codex R29). Small: the common
/// case is one queued release (a re-watch of a just-released key), and the correctness path — never
/// surfacing an `Overlaps` for a released root — is the conflict-triggered retry, not this.
const OPPORTUNISTIC_RELEASES: usize = 2;

/// How many of the OLDEST queued in-place coverage reconciles each [`arm`](Source::arm) forwards to
/// [`Watcher::set_cover`](tributary_fs::Watcher::set_cover), alongside the release application. Bounds
/// the per-arm reconcile cost exactly as [`OPPORTUNISTIC_RELEASES`] bounds releases, keeping the queue
/// draining eventually while a caller-bounded `Watch` never awaits the whole set_cover backlog. Small: a
/// set_cover is a pure budget optimization, so promptness is a nicety, not a correctness need.
const OPPORTUNISTIC_SET_COVERS: usize = 2;

impl<R: RuntimeLite> Source<OsString> for FsSource<R> {
  type Handle = RootHandle;

  fn canonicalize_key(&self, key: &[OsString]) -> Result<Vec<OsString>, WatchError> {
    // Resolve the path with the SAME canonicalization `arm` applies (via
    // `tributary_fs::Watcher::watch`, which `std::fs::canonicalize`s its root before spawning the
    // stream), so the umbrella classifies and commits on the coordinate events arrive under. A
    // non-existent or unreadable path fails here — the umbrella refuses to commit a key backed by
    // no real location, rather than accepting it silently and then never delivering an event.
    // Idempotent on an already-canonical path (`canonicalize` is a fixed point there), as the
    // trait's idempotence contract requires.
    let supplied = key_to_path(key);
    let canonical =
      std::fs::canonicalize(&supplied).map_err(|source| WatchError::Canonicalize {
        path: supplied,
        source,
      })?;
    Ok(path_components(&canonical))
  }

  async fn arm(&mut self, key: &[OsString]) -> Result<Armed<OsString, RootHandle>, WatchError> {
    // (a) OPPORTUNISTIC bounded application: unwatch the OLDEST few queued releases up front,
    // regardless of overlap. This keeps clause 5 eventual (every queued release is applied within a
    // bounded number of subsequent arms) and caps how long a released-but-lingering kernel watch
    // survives, while HARD-BOUNDING the release work this arm awaits — the R29 decoupling of a
    // caller-bounded `Watch` (and any `close` queued behind it) from the whole release backlog. Each
    // is a bounded(16)-channel send + driver ack (`Watcher::unwatch` awaits it); the result is ignored
    // (release is best-effort). This is NOT the correctness mechanism — (c) below is — so applying an
    // unrelated release here is harmless (it was going to be released anyway, clause 5).
    for _ in 0..OPPORTUNISTIC_RELEASES {
      let Some((released, _)) = self.pending_releases.pop_front() else {
        break;
      };
      let _ = self.watcher.unwatch(released).await;
      self.pending_set.remove(&released);
    }
    // (a') OPPORTUNISTIC bounded set_cover application: forward the OLDEST few queued in-place
    // coverage reconciles to `Watcher::set_cover`, alongside the release drain above. This is only a
    // BELT now — `set_cover`/`disarm` already drain the whole (bounded) backlog through the prompt
    // path, so the queue is normally empty here (Codex R37-F2) — but it keeps the queue draining even
    // across a run of arms with no other source op. Same bounded-per-arm cost model (a
    // bounded(16)-channel send + driver ack), and — like releases — off the correctness path: a
    // set_cover is a pure budget optimization (design M2-B, `Source::set_cover`), so the result is
    // ignored. A handle whose release was requested since the set_cover was queued is skipped: the
    // release supersedes (the whole root is going away, so there is nothing to reconcile in place).
    for _ in 0..OPPORTUNISTIC_SET_COVERS {
      let Some((handle, retained)) = self.pending_set_covers.pop_front() else {
        break;
      };
      if self.pending_set.contains(&handle) {
        continue;
      }
      let _ = self.watcher.set_cover(handle, retained).await;
    }
    // (b)+(c) Arm the root, resolving on demand any `Overlaps` the watcher reports against a
    // released-but-still-lingering root. Roots are always armed `Interest::all` (design §4): the kernel
    // watch never narrows what it collects, so a covered subscription can ask for any kind and the root
    // already carries it (interest becomes a pure fan-out gate at the umbrella).
    //
    // The correctness guarantee — a conforming source never SURFACES an `Overlaps` for a root whose
    // release was requested (disarm contract clause 2) — is upheld here by construction: the WATCHER
    // itself names the conflicting `existing` root (it rejects by object/ancestor IDENTITY, so it
    // catches case/normalization aliases a byte-prefix overlap test would miss — Codex R29-F2). Retry
    // is a **structural progress bound** (Codex R30-F2), not a fixed cap: continue ONLY while the named
    // `existing` EXACT-matches a still-pending (released) entry — remove exactly it, unwatch, and
    // re-attempt. Each retry strictly SHRINKS the pending queue (one exact-matched entry removed), so
    // the loop terminates in ≤ pending-queue-length retries with no arbitrary ceiling (the common case
    // is ≤1; an ancestor arm over N released descendants is bounded by the N the watcher names one at a
    // time — however large N is). A rejection whose named conflict is NOT a pending entry — a genuine
    // LIVE conflict (an umbrella-side disjointness bug), never a lingering released root — surfaces the
    // overlap IMMEDIATELY: there is no index-0 fallback, so we never unwatch an unrelated pending root
    // to mask a real conflict.
    let arm_path = key_to_path(key);
    // Progress tripwire (debug-only): the exact-match retry can run at most one more iteration than the
    // pending queue was deep, since pending strictly shrinks each retry and a non-matching rejection
    // exits immediately.
    #[cfg(debug_assertions)]
    let initial_pending = self.pending_releases.len();
    #[cfg(debug_assertions)]
    let mut iterations = 0usize;
    let handle = loop {
      #[cfg(debug_assertions)]
      {
        iterations += 1;
        debug_assert!(
          iterations <= initial_pending + 1,
          "FsSource::arm conflict-retry exceeded pending+1 iterations — pending must strictly shrink \
           each retry (structural progress bound, Codex R30-F2)"
        );
      }
      match self.watcher.watch(arm_path.clone(), Interest::all()).await {
        Ok(handle) => break handle,
        Err(WatchRootError::Overlaps { path, existing }) => {
          // Continue ONLY while the named conflict EXACT-matches a pending entry; otherwise surface it.
          let Some(index) = self
            .pending_releases
            .iter()
            .position(|(_, stored)| stored.as_deref() == Some(existing.as_path()))
          else {
            return Err(WatchError::Fs(WatchRootError::Overlaps { path, existing }));
          };
          let (released, _) = self
            .pending_releases
            .remove(index)
            .expect("index in bounds");
          let _ = self.watcher.unwatch(released).await;
          self.pending_set.remove(&released);
        }
        Err(err) => return Err(err.into()),
      }
    };
    // Adopt the filesystem-authoritative canonical path as the committed key (design §4, the
    // TOCTOU close): events are reported in canonical coordinates, so the index must key on
    // them. A `None` here means the root was already torn down (deleted between the request and
    // this arm completing) — a dead-on-arrival handle backing no live watch. Do NOT fall back
    // and report it armed: best-effort release it and fail, so the source never claims a dead
    // handle armed. Belt-and-suspenders under the driver's own arm-choke-point liveness check
    // (invariant I2), which guarantees this for every `Source` impl regardless.
    let Some(path) = self.watcher.root_path(handle) else {
      let _ = self.watcher.unwatch(handle).await;
      return Err(WatchError::DeadOnArrival);
    };
    Ok(Armed::new(handle, path_components(&path)))
  }

  fn disarm(&mut self, handle: RootHandle) {
    // Synchronous, non-blocking release REQUEST (contract clauses 1 & 3). The `Watcher`'s `unwatch`
    // awaits a bounded(16) command-channel ack, so the actual teardown cannot run inline here; queue
    // it — paired with the released root's canonical path captured NOW, while the root is still live
    // in the registry (the release is only queued, never applied inline), so a later `arm` can match
    // this entry against the conflict the watcher NAMES and apply exactly it (contract clause 2, Codex
    // R29). A `None` path means the root is already gone (`root_path` answers `None`): it can never be
    // the named conflict, so it is only applied opportunistically (or at `Drop`). Applied at a
    // subsequent `arm` (opportunistically as one of the oldest, or on demand when it blocks that arm)
    // or at `Drop` (the `Watcher`'s own teardown releases every live root). The `pending_set` mirror
    // makes the handle logically dead the instant this returns — `root_key` answers `None`. Idempotent
    // by the set: re-requesting an already-pending (or unknown/dead) handle is a no-op.
    if self.pending_set.insert(handle) {
      let root_path = self.watcher.root_path(handle);
      self.pending_releases.push_back((handle, root_path));
    }
    // A pending in-place reconcile for this handle is now moot — the whole root is being released, so
    // there is nothing to reconcile in place. The release supersedes it (contract clause 4).
    self
      .pending_set_covers
      .retain(|(pending, _)| *pending != handle);
    // (Codex R37-F2) A disarm is a source op that reaches the watcher, so it drains the set-cover
    // backlog for OTHER handles through the prompt path — this handle's own cover was just dropped,
    // and the drain skips a pending-release handle — so a deferred grow never waits indefinitely for
    // an unrelated arm.
    self.drain_pending_set_covers();
  }

  fn set_cover(&mut self, handle: RootHandle, retained: &[Vec<OsString>]) {
    // Superseded by a requested release (contract clause 4): the whole root is going away, so there
    // is nothing to reconcile in place. The `pending_set` mirror makes the handle logically dead.
    if self.pending_set.contains(&handle) {
      return;
    }
    // LATEST-WINS per handle (contract clause 6): drop any older QUEUED cover for this handle FIRST,
    // so neither the drain below nor a later application ever trails a stale snapshot behind the
    // fresh one. The umbrella re-issues the current retained cover on every membership change that
    // runs no `Source` call — a `Covered` commit (design §5, Codex R35/R36) — relying on the source
    // to apply the LATEST request per handle and never an older one; this drop is where that
    // guarantee is honored, and it is also what lets a re-issued GROW cover (one that once again
    // includes a previously-pruned survivor subtree) supersede a stale narrower snapshot rather than
    // trail behind it.
    self
      .pending_set_covers
      .retain(|(pending, _)| *pending != handle);
    // (Codex R37-F2) A set_cover is a source op that reaches the watcher, so it also drains any
    // PREVIOUSLY-DEFERRED covers (for other handles) through the prompt path — a sustained-full
    // control channel is then the only case a cover stays deferred, and any later source activity
    // drains it. This handle's own stale entry was just dropped above, so the drain never re-applies
    // it before the fresh cover below.
    self.drain_pending_set_covers();
    // Rebuild each retained key into its canonical path — the coordinate `Watcher::set_cover`
    // reconciles against — captured now, while the root is still live.
    let paths: Vec<PathBuf> = retained.iter().map(|key| key_to_path(key)).collect();
    // (Codex R37-F2) PROMPT path FIRST: forward the fresh cover via the NON-BLOCKING reply-less
    // request. On success the driver applies it AT ONCE — WITHOUT waiting for a later `arm` (the fix:
    // a `Covered`-outside grow arms nothing, so a queue-only cover would wait for an unrelated arm
    // forever). The core grows a previously-narrowed root back to this cover via its own broadening
    // delta — a subtree cover to that subtree, and a root-key cover (the cancel-equivalent) to FULL
    // coverage, whose stale queued snapshot the latest-wins drop above already discarded (Codex R35).
    // A cover of an already-full root is a core no-op. Only on a full/closed channel fall back to
    // QUEUING for a later drain.
    if self.watcher.request_set_cover(handle, paths.clone()) {
      return;
    }
    self.pending_set_covers.push_back((handle, paths));
  }

  async fn next(&mut self) -> Option<SourceEvent<OsString, RootHandle>> {
    let raw = self.watcher.next().await?;
    Some(SourceEvent::from_fs(&raw))
  }

  fn root_key(&self, handle: RootHandle) -> Option<Vec<OsString>> {
    // A requested release is logically dead immediately (contract clause 3), even while its
    // transport teardown is still queued: answer `None` for a pending handle before consulting the
    // live registry, so a re-`watch` of a just-released key classifies it as gone.
    if self.pending_set.contains(&handle) {
      return None;
    }
    // `tributary_fs::Watcher::root_path` reads its live-root registry synchronously and
    // answers `None` for a torn-down handle, so a terminal `Rescan` (whose root fs has
    // forgotten) reports `None` here — exactly the dead/retired signal the owner needs.
    self
      .watcher
      .root_path(handle)
      .map(|path| path_components(&path))
  }
}

impl SourceEvent<OsString, RootHandle> {
  /// Reverses a raw `tributary-fs` event into a source event: its absolute path back into
  /// key components, and — for a move — its source path likewise. The one place a raw
  /// filesystem event's key is extracted (mirroring [`Event::from_fs`] one layer up).
  ///
  /// [`Event::from_fs`]: crate::Event
  fn from_fs(event: &FsEvent) -> Self {
    let key = path_components(event.path());
    let from = event
      .kind()
      .moved()
      .map(|moved| path_components(moved.from()));
    Self::new(
      event.root(),
      key,
      event.kind().clone(),
      from,
      event.location().clone(),
      event.epoch(),
      event.change_id(),
    )
  }
}

/// Rebuilds a filesystem path from key components — the reverse of
/// [`path_components`](crate::event::path_components), and the only key → path conversion
/// the fs binding performs. `[a, b, c]` becomes `a/b/c`; an absolute key round-trips
/// through its leading root component.
fn key_to_path(key: &[OsString]) -> PathBuf {
  key.iter().collect()
}
