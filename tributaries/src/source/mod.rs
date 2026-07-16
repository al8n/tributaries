//! The [`Source<C>`]/[`LocalSource<C>`] binding seam (design §4). Its default
//! local-filesystem implementation, `FsSource`, lives in the `fs` submodule behind
//! the crate's default `fs` feature.
//!
//! The generic watch-set the umbrella maintains is source-agnostic: it plans
//! subsumption and fans events out purely in `Vec<C>` key space. A **source** is the
//! one place that knows how a key maps to a concrete watch, and how a raw change maps
//! back to a located key. For 0.1.0 the only in-tree source is `FsSource`, binding
//! `C = OsString` (a path's components) to the local filesystem over one `tributary-fs`
//! watcher; a general remote-capable registry is future work.
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
//! The seam comes in two flavors sharing one contract: [`LocalSource`] is the **base**
//! (the same items, futures with no `Send` requirement — hosting genuinely thread-local
//! sources via [`Tributaries::parts_local`](crate::Tributaries::parts_local)), and
//! [`Source`] is the **multithread-spawnable** variant (its three async methods promise
//! `Send` futures). Every `Source` is a `LocalSource` through the crate's blanket
//! forwarding impl, so a type implements exactly one of the two.
//!
//! # Key ↔ path knowledge lives with the binding only
//!
//! Rebuilding a path from key components and reversing a raw event's absolute path back
//! into components is the fs binding's private business (the `fs` submodule). The
//! umbrella never re-implements it; it orchestrates subsumption and fan-out over `C`
//! alone.

use std::vec::Vec;

use tributary_proto::{ChangeId, Epoch, Location};

use crate::{
  error::{SyncError, WatchError},
  event::EventKind,
};

#[cfg(feature = "fs")]
mod fs;
#[cfg(feature = "fs")]
#[cfg_attr(docsrs, doc(cfg(feature = "fs")))]
pub use fs::FsSource;

#[cfg(test)]
mod tests;

/// The binding between the umbrella's generic `Vec<C>` key space and a concrete watcher
/// (design §4) — the **base seam**, whose async methods return futures with **no `Send`
/// requirement**.
///
/// An implementor owns the source-specific knowledge of how a key maps to a real watch
/// and how a raw change maps back to a located key; the umbrella drives it as the single
/// writer and never re-implements that mapping. This is **static dispatch only** — a
/// `dyn`-compatible registry for heterogeneous remote sources is future work.
///
/// # Two traits, one seam
///
/// [`Source`] declares the same eight items under the same contracts, differing ONLY in its
/// three async methods ([`arm`](Self::arm), [`grow`](Self::grow), [`next`](Self::next))
/// promising `Send` futures. Every contract in this trait's documentation — the robustness
/// boundary, the cancellation clause, each item's hard contract — binds [`Source`]
/// implementors identically; the text lives here because this is the base trait the
/// umbrella's owner loop is written against. A type implements exactly ONE of the two:
///
/// - A source whose futures can cross threads implements [`Source`] — almost every source,
///   the default local-filesystem `FsSource` and any channel-fronted transport included —
///   and receives `LocalSource` **for free** through the crate's blanket forwarding impl
///   (which is also why coherence forbids implementing both). It constructs through
///   [`Tributaries::with_source`](crate::Tributaries::with_source) or
///   [`Tributaries::parts`](crate::Tributaries::parts), and equally through
///   [`parts_local`](crate::Tributaries::parts_local).
/// - A **genuinely thread-local** source — `Rc`/`RefCell` state or a completion ring's
///   handles captured by its futures — cannot promise `Send`, so it implements
///   `LocalSource` directly and constructs through
///   [`Tributaries::parts_local`](crate::Tributaries::parts_local), whose returned driver
///   future must then be polled on the thread that owns the source.
///
/// The two traits are deliberately **independent**: [`Source`] is NOT declared
/// `Source: LocalSource`; the blanket impl alone relates them (see [`Source`]'s docs for
/// why a supertrait relation is off the table).
///
/// # Robustness boundary — what the umbrella REQUIRES vs GUARANTEES
///
/// The umbrella drives a source as its single writer and is hardened against one that
/// **misbehaves**. The line between what a conforming source must provide and what the umbrella
/// upholds regardless is drawn precisely here (cross-reference: driver-golden invariant II,
/// "Close-responsive").
///
/// **REQUIRED of a conforming source (the umbrella relies on these):**
///
/// - **Generation-unique [`Handle`](Self::Handle)** — a handle value is never reused while any root
///   or not-yet-emitted event still carries it (the hard contract on [`Handle`](Self::Handle)). Makes handle ABA impossible; the umbrella routes strictly by handle rather than defending
///   against reuse.
/// - **Bounded [`arm`](Self::arm) / [`grow`](Self::grow) / [`canonicalize_key`](Self::canonicalize_key)**
///   — the umbrella awaits [`arm`](Self::arm) and [`grow`](Self::grow) and calls the synchronous
///   [`canonicalize_key`](Self::canonicalize_key), running each **to completion**, so all MUST make
///   progress and resolve in **bounded time**. Both awaited methods run **only inside a
///   caller-initiated** `watch` reconcile, to completion (invariant I1); a wedged one blocks that one
///   reconcile until the source honors the contract (the caller may drop its own `watch` wait, but the
///   umbrella still owns the in-flight reconcile) — never any unrelated backlog or a queued `close`,
///   which ride their own paths. A source that makes any **hang indefinitely** violates the contract;
///   that is the source's responsibility, not a bug the umbrella can `await`-around.
/// - **Synchronous, non-blocking [`disarm`](Self::disarm)** — release is a fire-and-forget
///   **request** the umbrella never awaits (see its docs): it returns at once, queuing any async
///   teardown inside the source, and applies the release no later than the next [`arm`](Self::arm) or
///   `Drop`. There is no `disarm` future to wedge the owner, so a slow transport release can never
///   block the mailbox — the reason Close-responsiveness holds *by construction* below.
/// - **Cancellation-safe [`next`](Self::next)** — dropping an in-flight [`next`](Self::next) future
///   loses and acknowledges no event (the hard contract on [`next`](Self::next)).
///
/// **GUARANTEED by the umbrella even against a misbehaving source:**
///
/// - **A wedged [`next`](Self::next) never blocks command processing.** The owner drives
///   [`next`](Self::next) as one arm of a biased `select!`; a `next()` that never resolves is simply
///   a pending arm — the loop still services the command mailbox and the dedicated close signal.
/// - **Close-responsiveness against INTERNAL actions AND the command backlog, by construction
///   (invariant II).** `close` rides a **dedicated high-priority signal** — a separate channel the
///   owner checks at the TOP priority everywhere it selects (a non-blocking `try_recv` each iteration
///   AND the first `select!` arm, in both the run loop and the source-drain teardown), NOT the command
///   mailbox — so shutdown latency is **bounded independent of** how deep the unbounded `watch`/
///   `unwatch` backlog is. And the owner never awaits source I/O on any cleanup path:
///   owner actions that are *not* a caller-awaited `watch` — a `DropOrphan` from a dropped `watch`
///   grant, the send-failure / all-handles-gone orphan on the same path, and the source-drain teardown
///   — release an emptied root through the **synchronous** [`disarm`](Self::disarm). Because `disarm`
///   returns no future, no cleanup path can wedge the owner, so the close is serviced with no
///   scheduling discipline to get wrong. Dropping every handle tears the owner down and drops the
///   source, whose own `Drop` applies any still-pending releases.
/// - **No stranded or corrupt state.** A committed-but-unclaimed subscription is always reconciled
///   away (the `WatchGrant`, invariant I1); a subscription terminal-retired while unclaimed leaves no
///   lingering parked `Rescan` behind; and a released-then-re-`watch`ed key never
///   surfaces the overlap rejection the umbrella exists to subsume
///   away — a conforming source guarantees no arm surfaces an overlap caused by a released root
///   (contract clause 2), whether by pre-applying the release or by resolving the lower watcher's own
///   identity-aware `Overlaps` rejection and retrying, so the umbrella needs no flushing of its own.
///
/// **OPTIONAL of a source (in-place coverage reconcile — never relied on for delivery correctness):**
///
/// A source may reclaim (and, when a survivor returns to a pruned region, restore) the kernel
/// coverage of a root that outlived the subscription whose key equalled it (design §5, set-cover). It
/// has two halves, split by their correctness role:
///
/// - [`set_cover`](Self::set_cover), the **PRUNE** half — an opt-in, synchronous, fire-and-forget
///   request (the same non-blocking shape as [`disarm`](Self::disarm)) to narrow a now-**over-broad**
///   root's coverage toward the retained cover, reclaiming the excess kernel budget. The umbrella
///   issues it from its single release primitive on the non-emptied unwatch path. A source that can
///   prune below a root (a per-directory descending backend) reclaims budget with **no gap and no
///   re-crawl** — it never releases survivor coverage — while a whole-subtree source (one stream / one
///   recursive mark) keeps the **default no-op**. Correctness NEVER depends on it: over-broadness is
///   correctness-neutral and self-healing, so a no-op, deferred, or partial prune is always conforming
///   (the golden reason the umbrella forwards it synchronously and moves on).
/// - [`grow`](Self::grow), the **GROW** half — the **awaited** re-arm of a retained subtree a
///   `Covered` newcomer landed under but an earlier prune had removed. Unlike the prune it is a
///   correctness counterpart: a source that actually narrows coverage via `set_cover` MUST implement
///   `grow`, or a newcomer under a pruned region would silently receive nothing. A source that keeps
///   the default no-op `set_cover` (its coverage never narrows) keeps the default `Ok(())` `grow`
///   too. `grow` is awaited inside the caller-bounded reconcile and **applied before its `Ok`**, so
///   the newcomer's coverage is live before `watch()` returns — closing the request→apply window a
///   fire-and-forget re-issue left open (set-cover), with no bridging `Rescan` needed. On its `Err`
///   the umbrella refuses the commit instead (the record stays exact and the watch fails retryably —
///   see the method's errors section), so a `Covered` subscription is never published over a
///   coverage hole.
///
/// # Cancellation and `Drop` reclamation
///
/// With [`Tributaries::parts`](crate::Tributaries::parts) or
/// [`parts_local`](crate::Tributaries::parts_local) the owner future is
/// caller-owned and **may be dropped at any await point** — including mid-[`arm`](Self::arm)
/// or mid-[`grow`](Self::grow). The run-to-completion wording on those methods describes what the
/// owner does while polled; it is NOT a promise a source may lean on for external
/// consistency. The obligation is therefore on the implementor's `Drop`: **dropping the
/// source must reclaim every external effect it ever initiated, including an arm or
/// grow cancelled mid-flight whose handle was never returned.** A source that submits
/// an external watch request and awaits the acknowledgement must tear that watch down
/// through its own teardown path (its internal driver's shutdown, its transport's
/// `Drop`) when the source itself drops — never rely on the caller having received a
/// handle to disarm. A channel-fronted source (the dedicated-transport-thread shape
/// described in [`Source`]'s `Send` bounds note) satisfies this structurally: the
/// dropped frontend closes its channels, and the transport driver behind them tears
/// down every live watch as it exits — exactly what `FsSource` inherits from
/// the `tributary-fs` watcher's drop semantics.
pub trait LocalSource<C> {
  /// The armed-root token a successful [`arm`](Self::arm) yields, naming the concrete
  /// watch a later [`disarm`](Self::disarm) releases and an event's
  /// [`SourceEvent::handle`] identifies. `Copy + Eq + Hash` so the umbrella can key its
  /// per-root bookkeeping on it (the fs source uses its watcher's `RootHandle`).
  ///
  /// # Generation-unique handle contract (hard requirement)
  ///
  /// A source MUST mint a **generation-unique** handle on **every** [`arm`](Self::arm): a handle
  /// value is **never** reused for a new arm while any root **or** any not-yet-emitted event
  /// carrying that value is still live. Equivalently — no handle the umbrella has observed is ever
  /// reissued until the umbrella has **fully retired** the root it named (a [`disarm`](Self::disarm)
  /// whose retirement has reconciled, or a terminal event for which [`root_key`](Self::root_key) is
  /// `None`) **and** no further event can carry it. Unlike a weaker "never alias two *different*
  /// live roots" rule, this also forbids reusing a value for the **same** key right after a
  /// [`disarm`](Self::disarm): a re-arm always mints a *fresh* generation.
  ///
  /// This makes handle **ABA impossible**, and the umbrella relies on it rather than defending
  /// against ABA itself (a defensive alias-detection was both incomplete and the wrong
  /// layer). Two consequences the umbrella depends on:
  ///
  /// - **An old-generation event never routes through a re-armed root.** A value the umbrella
  ///   released and re-armed names a *new* generation with a *new* handle, so any event still queued
  ///   from before the re-arm carries the **old, now-dead** handle. The umbrella routes strictly by
  ///   handle: [`root_key`](Self::root_key) is `None` for that dead handle (the source released it),
  ///   so the event falls to the dead-root retire/drain path — never onto the re-armed root. Were
  ///   the same value reused (ABA), that stale event would route through the live re-armed root
  ///   *after* the umbrella rebased its epochs, applying a stale change its restore
  ///   [`Rescan`](EventKind::Rescan) no longer dominates.
  /// - **A fresh arm's handle never aliases a live root.** The umbrella keys its reverse index
  ///   (handle → root) on this token; a generation-unique value is absent from that index at commit
  ///   time, so a fresh arm — including each one-at-a-time re-arm of a failed widen's disarmed
  ///   siblings, whose not-yet-restored siblings are **still recorded** — can never overwrite
  ///   another root's entry and strand it published-but-unroutable.
  ///
  /// A conforming source therefore lets the umbrella rebind/commit onto the fresh handle
  /// unconditionally; a debug-only owner-level observed-handle `debug_assert` at the single arm
  /// choke point is the exhaustive tripwire for a contract-violating source (it catches reuse of a
  /// handle already retired out of the live index too), never a release-mode recovery.
  /// `FsSource` satisfies the contract structurally: its `RootHandle` carries a
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
  /// [`root_key`](Self::root_key): `FsSource` resolves the path with the same canonicalization
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
  /// A [`WatchError`] when `key` cannot be canonicalized — for `FsSource`, a
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
  /// The returned future carries no `Send` requirement; [`Source::arm`] is the
  /// `Send`-promising twin.
  fn arm(&mut self, key: &[C]) -> impl Future<Output = Result<Armed<C, Self::Handle>, WatchError>>;

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
  ///    later [`arm`](Self::arm) never **surfaces** an overlap
  ///    rejection caused by a root whose release
  ///    was requested — this is what makes widen (release the narrow roots, arm the wider root) and
  ///    re-watch-after-orphan correct with **no** umbrella-side flushing. HOW it achieves this is the
  ///    source's own business, so long as the release work any *single* arm performs is bounded by
  ///    the releases that **overlap that arm's key** — never the whole (disjoint) backlog.
  ///    The overlapping-conflict set is the *caller's own*: an ancestor watch over N
  ///    roots the caller itself created and released legitimately resolves those N conflicts inside
  ///    that one caller-bounded `Watch` — invariant I1 run-to-completion — and a
  ///    [`close`](crate::Tributaries::close) queued behind it waits for that one reconcile, exactly
  ///    as it waits for any in-flight caller command (the RATIFIED semantics: close is
  ///    decoupled from *unrelated* backlogs — command floods, disjoint release queues — not from the
  ///    single caller reconcile it queued behind). Two conforming mechanisms:
  ///    - **pre-application** — apply queued releases before the watch; or
  ///    - **conflict-triggered application-and-retry** — as `FsSource` now does: attempt the arm,
  ///      and on the lower watcher's own `Overlaps` rejection AWAIT the *named* conflicting release's
  ///      teardown and retry (plus a NON-BLOCKING opportunistic hand-off that AWAITS NOTHING — a
  ///      reply-less release request per queued entry when the control channel has room — to keep
  ///      clause 5 eventual and cap kernel-watch lingering without coupling a disjoint arm to any
  ///      teardown latency). The lower watcher rejects by object/ancestor **identity** and names the
  ///      conflicting root, so this is **identity-aware by construction** — it catches case /
  ///      normalization aliases a byte-prefix overlap test would miss.
  ///
  ///    A release not needed to clear a given arm's conflicts is never AWAITED by that arm — it is
  ///    handed over by the non-blocking request (or left queued when the channel is momentarily full)
  ///    and follows clause 5 (eventual): a disjoint kernel watch never conflicts with the arm, so
  ///    leaving it briefly live cannot cause an `Overlaps`.
  /// 3. **Logically dead immediately.** After `disarm(h)` returns, [`root_key`](Self::root_key)
  ///    answers `None`. The handle is retired from the umbrella's perspective the moment the request
  ///    is made; events still in flight carrying `h` fall to the dead-root drain exactly like any
  ///    post-retirement event.
  /// 4. **Idempotent / tolerant.** Releasing an unknown, dead, or already-released handle is a
  ///    no-op. Release errors are the source's own to absorb/log (there is no result), since a
  ///    released root's runtime conditions reach the umbrella in-band as events, not out of band
  ///    here.
  /// 5. **Eventual release.** A requested release is applied no later than the source's next
  ///    [`arm`](Self::arm) or its teardown (`Drop`), by one of three routes: a **non-blocking request**
  ///    when the control channel has room (the normal path — it awaits nothing), the
  ///    **conflict-triggered** teardown when a later arm's key overlaps the release (the only route that
  ///    AWAITS, and only for that arm's OWN overlapping conflicts), or **teardown** (`Drop`). Between
  ///    request and application the kernel watch may briefly linger; any events it emits route to
  ///    nothing (the subsumer entry is gone) — correctness is unaffected.
  ///
  /// [`next`](Self::next) keeps its cancellation-safety contract unchanged, and [`arm`](Self::arm)
  /// keeps its caller-bounded liveness contract unchanged.
  fn disarm(&mut self, handle: Self::Handle);

  /// Grows the root named by `handle` so its ACTUAL coverage INCLUDES every key in `retained` — the
  /// prefix-free antichain of keys some live subscriber still needs — reconciling the source's kernel
  /// coverage UP **in place**, and reports whether that coverage is live. **Awaited**, and awaited
  /// **only inside a caller-bounded `watch` reconcile** (the ratified fence — invariant I1 — covers it
  /// exactly like [`arm`](Self::arm)): the umbrella runs the reconcile to completion, so a wedged
  /// `grow` blocks that one reconcile until the source honors the contract, exactly as a wedged
  /// [`arm`](Self::arm) does, and never any unrelated backlog or a queued
  /// [`close`](crate::Tributaries::close).
  ///
  /// The umbrella issues this when a `Covered` newcomer lands OUTSIDE a root's already-narrowed
  /// coverage (design §5, set-cover): the newcomer arms nothing, so without a grow the source would not
  /// back its subtree. Rather than release-and-rearm the whole root at the umbrella (which would move
  /// the survivors' coverage, forcing a gap-closing [`Rescan`](EventKind::Rescan)), the
  /// source re-arms only the missing subtree in place — survivor coverage never moves, so events under
  /// an unchanged `retained` key keep flowing with **no gap and no loss**. It is the awaited GROW
  /// counterpart of the fire-and-forget [`set_cover`](Self::set_cover) PRUNE.
  ///
  /// # Hard contract
  ///
  /// 1. **`Ok` = applied, not enqueued — coverage is live on return.** When `grow` returns `Ok(())`,
  ///    the source's ACTUAL coverage MUST already include every key in `retained` (the re-armed
  ///    subtrees are live), NOT merely have the request queued. This is what lets the umbrella commit
  ///    a `Covered`-outside newcomer with **no bridging `Rescan`**: a watch is "changes from now on",
  ///    and because coverage is live before `watch()` returns there is no request→apply window in
  ///    which a write could be silently lost — the exact loss a deferred fire-and-forget re-issue
  ///    behind an already-flushed bridge could leak. (For the fs binding this is the watcher's
  ///    effect-completion fence: the ack resolves at watch-live, never at effect-queue time.)
  /// 2. **Never moves survivor coverage.** A `retained` prefix the source already covers is left
  ///    untouched (no re-crawl, no gap); only a prefix it does not yet cover is (re-)armed. This
  ///    holds on `Err` too — a failed grow may leave a missing subtree missing, never un-cover a
  ///    covered one.
  /// 3. **Idempotent.** Growing to a `retained` the source already fully covers is a no-op `Ok`.
  /// 4. **A no-op is conforming only for a source whose coverage never narrows.** The **default
  ///    returns `Ok(())` without doing anything**, correct for a whole-subtree source (one stream /
  ///    one recursive mark per root) whose actual coverage never shrank below a root — there is
  ///    nothing to grow back. A source that can prune below a root (a per-directory descending
  ///    backend, whose [`set_cover`](Self::set_cover) actually narrows coverage) MUST implement
  ///    `grow`, or a `Covered`-outside newcomer under a pruned region would silently receive nothing.
  ///
  /// `retained` is a prefix-free antichain in the same `C` key space as [`arm`](Self::arm): every key
  /// lies under exactly one member, and no member descends from another.
  ///
  /// # Errors
  ///
  /// An `Err` means coverage may NOT include some `retained` key — the grow could not be
  /// applied (a re-arm failed or was lost to a degraded window, or the root died concurrently).
  /// A source that reports `Err` MUST already have emitted an in-band dominating
  /// [`Rescan`](EventKind::Rescan) to the root's current subscribers wherever one is owed (the fs
  /// binding's Monitor does this for every failed or degraded re-arm), so the loss is never silent
  /// for anyone already subscribed. The umbrella then does NOT broaden its coverage record — the
  /// next newcomer under the pruned region classifies outside-cover and re-issues the grow
  /// (self-healing) — and fails the caller's `watch` retryably
  /// ([`WatchError::CoverageIncomplete`] from the fs binding's degraded fence, or whatever honest
  /// error the source classified) rather than commit a subscription whose subtree has no backing
  /// and no retry owner (ratified R1, grow-before-commit).
  ///
  /// One of the three awaited methods, alongside [`arm`](Self::arm) and [`next`](Self::next);
  /// the returned future carries no `Send` requirement here ([`Source::grow`] is the
  /// `Send`-promising twin).
  fn grow(
    &mut self,
    handle: Self::Handle,
    retained: &[Vec<C>],
  ) -> impl Future<Output = Result<(), WatchError>> {
    let _ = (handle, retained);
    async { Ok(()) }
  }

  /// Requests that the root named by `handle` PRUNE its ACTUAL coverage toward the `retained` cover —
  /// the antichain of keys some live subscriber still needs — reclaiming the excess kernel coverage a
  /// now-**over-broad** root holds. Synchronous and non-blocking: a fire-and-forget **request**,
  /// modeled exactly on [`disarm`](Self::disarm)'s contract style, never an awaited teardown.
  ///
  /// This is the **PRUNE** half of coverage reconcile; the **GROW** half — (re)arming a `retained`
  /// subtree the root does not currently cover — is [`grow`](Self::grow)'s job (awaited, applied
  /// before return). `set_cover` may **only ever narrow** actual coverage toward `retained`; it owes
  /// no grow. A source MAY treat a `retained` broader than its actual coverage as a no-op, or grow
  /// too (harmless) — the umbrella never relies on either, because it never sends a broadening cover
  /// here (a broaden goes through [`grow`](Self::grow)).
  ///
  /// The umbrella issues this when a drop leaves a wide root broader than any live subscriber — an
  /// over-broad `unwatch` (the departing subscription's key equalled the root's), or a non-root
  /// `unwatch` that shrinks an already-narrowed cover (design §5, set-cover). Rather than release-and-
  /// rearm the whole root at the umbrella (which would move the survivors' coverage, forcing a
  /// gap-closing [`Rescan`](EventKind::Rescan)), the source reclaims the KERNEL coverage
  /// in place: it **never moves survivor coverage that is already correct**, so events under an
  /// unchanged `retained` key keep flowing with **no gap and no loss**.
  ///
  /// # Hard contract (mirrors [`disarm`](Self::disarm))
  ///
  /// 1. **Non-blocking.** `set_cover` returns without blocking I/O or awaiting anything. A source that
  ///    needs async work to prune (the fs source does) queues the request internally.
  /// 2. **Prune toward the retained cover — never gap a retained-and-covered subtree.** The source
  ///    MUST NOT reduce coverage below any `retained` prefix it currently covers (every key under such
  ///    a prefix keeps delivering with no gap); it MAY reclaim coverage strictly outside every
  ///    `retained` prefix. It never re-arms here — that is [`grow`](Self::grow)'s job — so it emits no
  ///    `Rescan`.
  /// 3. **Prompt when it can, eventual otherwise, or never.** A source SHOULD apply a requested prune
  ///    promptly. `FsSource` forwards it to the watcher's control channel the instant `set_cover` is
  ///    called, via a non-blocking reply-less request; only when that channel is momentarily full does
  ///    it DEFER, re-forwarding at the next source op that touches the watcher (another `set_cover`, a
  ///    [`grow`](Self::grow), a [`disarm`](Self::disarm), or an [`arm`](Self::arm)). A **no-op is
  ///    still conforming**: an unreconciled root is merely over-broad — correctness-neutral and
  ///    self-healing.
  /// 4. **Idempotent / tolerant.** Pruning an unknown, dead, or already-released handle is a no-op. A
  ///    handle whose [`disarm`](Self::disarm) was already requested is logically dead, so its prune is
  ///    superseded by the release (the whole root is going away). There is no result; errors are the
  ///    source's own to absorb.
  /// 5. **Purely an optimization.** Correctness MUST NEVER depend on `set_cover`. It reclaims budget
  ///    (kernel watch descriptors); it changes no delivery the umbrella promises. The pending queue a
  ///    queueing source keeps is a **prune-only full-channel fallback** — losslessness is NOT required
  ///    (a dropped prune merely leaves the root over-broad, self-healing).
  /// 6. **Latest-wins per handle for a queueing source.** A source that QUEUES prunes MUST apply the
  ///    **LATEST** request per handle, never an older snapshot — and a subsequent [`grow`](Self::grow)
  ///    for the handle **supersedes** any queued prune (the grow's fresh cover is newer, and its
  ///    applied coverage is authoritative). This obligation is vacuous for an inline (non-queueing) or
  ///    no-op source.
  ///
  /// The **default is a no-op**, so an implementor opts in only if it can reclaim coverage below a
  /// root (a per-directory descending backend). A whole-subtree source (one stream / one recursive
  /// mark per root) has nothing to prune — its actual coverage never shrank — and keeps the default;
  /// over-broadness on it is self-healing (a re-installed key is `Covered` under the still-armed wide
  /// root — design §5). A source that keeps this default keeps the default no-op [`grow`](Self::grow)
  /// too.
  ///
  /// `retained` is a prefix-free antichain in the same `C` key space as [`arm`](Self::arm): every key
  /// lies under exactly one member, and no member descends from another.
  fn set_cover(&mut self, handle: Self::Handle, retained: &[Vec<C>]) {
    let _ = (handle, retained);
  }

  /// The next raw change as a [`SourceEvent`], or [`None`] once the source is closed and
  /// drained — the event pump the owner drives as one arm of its `select!` loop. The
  /// returned future carries no `Send` requirement; [`Source::next`] is the
  /// `Send`-promising twin.
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
  /// `FsSource` satisfies this: its `next` awaits the `tributary-fs` watcher's own
  /// `next`, itself an `async_channel` receive, which is cancel-safe by construction.
  fn next(&mut self) -> impl Future<Output = Option<SourceEvent<C, Self::Handle>>>;

  /// Retargets an armed root **in place** — the same `handle`, a new (necessarily WIDER)
  /// key — returning the handle unchanged alongside the key the source committed to.
  ///
  /// This is the gapless alternative to release-and-rearm. The umbrella's widen would
  /// otherwise [`disarm`](Self::disarm) the subsumed roots and [`arm`](Self::arm) a wider
  /// one, which drops kernel coverage for the window between them — a gap the re-pointed
  /// subscribers' dominating `Rescan` covers but cannot un-lose. A source that can widen
  /// its own root make-before-break (the fs binding does: `Watcher::replace_root` brings the
  /// replacement stream up BEFORE retiring the old one) offers it here instead.
  ///
  /// **The handle is PRESERVED, deliberately** — this is the one sanctioned exception to the
  /// generation-unique [`Handle`](Self::Handle) contract, and it is sound precisely because
  /// no fresh handle is minted: nothing can alias, and the umbrella re-keys its record in
  /// place rather than dropping and re-inserting.
  ///
  /// **Atomic on failure**: every error MUST leave the old root's coverage exactly as it was,
  /// because the umbrella falls back to the release-and-rearm path on ANY error — including
  /// the default's [`FaultKind::Unsupported`](crate::FaultKind::Unsupported), which is simply
  /// "this source cannot widen in place; do it the old way". A source that cannot promise
  /// atomicity must not implement this method.
  fn replace(
    &mut self,
    handle: Self::Handle,
    new_key: &[C],
  ) -> impl Future<Output = Result<Armed<C, Self::Handle>, WatchError>> {
    let _ = (handle, new_key);
    async {
      Err(WatchError::Source(crate::error::SourceFault::new(
        crate::error::FaultKind::Unsupported,
      )))
    }
  }

  /// Places a **sync-barrier cookie** under `dir_key` for the root `handle`, returning the
  /// cookie's canonical key. AWAITED, and it resolves at **write-complete — never at
  /// observe**: the cookie's event arrives through the very [`next`](Self::next) pump the
  /// owner would otherwise be blocking, so awaiting the observation here would deadlock by
  /// construction. Observation is the owner's funnel-driven business.
  ///
  /// The cookie's whole purpose is the kernel event its creation mints: that event rides the
  /// root's ordered queue BEHIND every change the backend reported before the write, so
  /// observing it proves those changes have already exited the pipeline. A source whose
  /// backend cannot report an in-band marker cannot offer the barrier and keeps the default
  /// ([`SyncError::Unsupported`]) — an honest refusal, never a pretend barrier.
  ///
  /// `token` identifies the sync (instance + pid + seq); the binding renders it into whatever
  /// a marker is called in its namespace, and must ensure [`is_sync_artifact`](Self::is_sync_artifact)
  /// answers `true` for the key it returns. A source that must park the write behind its own
  /// coverage-settle machinery does so INSIDE this await (the fs binding parks on the
  /// per-directory re-arm fence), which is exactly why the initiation is awaited and bounded
  /// like [`grow`](Self::grow).
  fn begin_sync(
    &mut self,
    handle: Self::Handle,
    dir_key: &[C],
    token: SyncToken,
  ) -> impl Future<Output = Result<Vec<C>, SyncError>> {
    let _ = (handle, dir_key, token);
    async { Err(SyncError::Unsupported) }
  }

  /// Reaps a cookie [`begin_sync`](Self::begin_sync) placed — SYNCHRONOUS, non-blocking,
  /// fire-and-forget, in the [`disarm`](Self::disarm) mold. Idempotent (a cookie already gone
  /// is success) and eventual (the unlink need not have landed when this returns).
  ///
  /// The unlink mints its own event; that event is suppressed by the reserved-namespace rule
  /// ([`is_sync_artifact`](Self::is_sync_artifact)), NOT by any pending-sync bookkeeping — by
  /// the time it arrives, the sync it belonged to is already resolved and forgotten.
  fn end_sync(&mut self, handle: Self::Handle, cookie_key: &[C]) {
    let _ = (handle, cookie_key);
  }

  /// Abandons the sync identified by `token` — SYNCHRONOUS, non-blocking, fire-and-forget, in the
  /// [`end_sync`](Self::end_sync)/[`disarm`](Self::disarm) mold. Called when the owner abandons an
  /// IN-FLIGHT [`begin_sync`](Self::begin_sync) (the caller timed out, or a close won the owner's
  /// race): the owner never learned the cookie's key — only a completed `begin_sync` returns it — but
  /// it still knows the `token` it minted, and the binding recovers the sync's identity from it.
  ///
  /// The binding must ensure a cookie this sync ALREADY created — even one whose completion the owner
  /// never read — is eventually removed, and that a write still in flight leaves no cookie behind when
  /// it lands. Idempotent; a token whose sync already fully resolved is a no-op. Best-effort on an
  /// abnormal teardown, exactly like `end_sync`.
  fn cancel_sync(&mut self, handle: Self::Handle, token: SyncToken) {
    let _ = (handle, token);
  }

  /// Whether `key` names an artifact of the sync-barrier machinery — a cookie, whoever wrote
  /// it. A SYNCHRONOUS classify probe in the [`root_key`](Self::root_key) mold.
  ///
  /// The umbrella suppresses every matching event from consumer streams, before fan-out and
  /// before the coalescer, and uses the match to resolve pending syncs. The suppression is
  /// **namespace-total, not own-pending-only**: two watcher instances may legitimately watch
  /// one tree, and instance A's cookies must never surface as user files on instance B's
  /// stream — nor must our own already-resolved cookies' unlink events, nor a crashed
  /// process's leftovers.
  ///
  /// A `Rescan` is NEVER suppressed, whatever its key: the umbrella checks that first, because
  /// a Rescan is coverage information and is structurally unmaskable.
  fn is_sync_artifact(&self, key: &[C]) -> bool {
    let _ = key;
    false
  }

  /// The **canonical key** of the root `handle` names, or [`None`] once that root is dead
  /// or retired — a **synchronous** liveness probe (mirroring the `tributary-fs`
  /// watcher's `root_path`, which reads a live registry snapshot without I/O).
  ///
  /// The owner uses it to tell a **terminal** coverage-loss signal (the root vanished —
  /// `root_key` is `None`, so the root is retired, freeing its index / filter / epoch
  /// state) from an **overflow** re-enumeration (the root is still live — `root_key` is
  /// `Some`, so the root is kept and the consumer re-enumerates). Because it is out of
  /// band, it never races the event stream the owner drives (design §4, I4).
  fn root_key(&self, handle: Self::Handle) -> Option<Vec<C>>;
}

// Deliberately NOT `pub trait Source<C>: LocalSource<C>`, even though every `Source` is a
// `LocalSource` through the blanket forwarding impl below. With a supertrait relation the
// `Send` promise `Tributaries::parts` makes for a generic `S: Source` becomes unprovable
// on stable Rust: proving `run(owner)`'s future `Send` normalizes the opaque futures of
// `<S as LocalSource>`, and the where-clause candidate elaborated from the supertrait
// (`S: LocalSource`) shadows the blanket impl during that normalization — a where-clause
// candidate carries no hidden type to leak `Send` from, so the proof fails with "future
// cannot be sent between threads safely" (empirically reproduced). Independence keeps the
// blanket impl the ONLY `LocalSource` candidate for a generic `S: Source`, whose hidden
// types are this trait's `+ Send` opaques. Coherence forbidding one type from
// implementing both traits is the desirable corollary, not the motivation.
/// The **multithread-spawnable** variant of the source seam: the same eight items as
/// [`LocalSource`], with the three async methods ([`arm`](Self::arm), [`grow`](Self::grow),
/// [`next`](Self::next)) promising `Send` futures.
///
/// This is the trait (almost) every source implements — the default local-filesystem
/// implementation is `FsSource`. **Every contract on [`LocalSource`] applies verbatim**:
/// the seam description, the robustness boundary (what the umbrella REQUIRES vs
/// GUARANTEES), the cancellation / `Drop`-reclamation clause, and each item's hard contract
/// are written once there, and this trait adds exactly one thing — the `Send` promise
/// below, which is what makes a generic owner over it spawnable on a multi-threaded
/// executor ([`Tributaries::with_source`](crate::Tributaries::with_source),
/// [`Tributaries::parts`](crate::Tributaries::parts)).
///
/// Implementing `Source` grants [`LocalSource`] for free through the crate's blanket
/// forwarding impl — so a `Source` also constructs via
/// [`Tributaries::parts_local`](crate::Tributaries::parts_local) — and coherence therefore
/// forbids implementing both traits: a source either promises `Send` futures here, or is
/// genuinely thread-local and implements [`LocalSource`] alone. The two traits are
/// deliberately independent (no supertrait relation): relating them by supertrait would
/// stop the compiler from proving the blanket impl's `Send` leakage for a generic
/// `S: Source`, which is exactly the proof [`Tributaries::parts`](crate::Tributaries::parts)
/// stands on.
///
/// # `Send` bounds
///
/// **All three async methods return `Send` futures.** The stock hosting path spawns the driver as
/// a single owned task on a multi-threaded tokio or smol executor
/// ([`R::spawn_detach`](agnostic_lite::RuntimeLite::spawn_detach)) that drives arming and the event
/// pump inline in one `select!` loop — so *every* future the owner awaits must be able to cross
/// threads for `run(owner)` itself to be `Send`. The three awaited methods are [`arm`](Self::arm),
/// [`grow`](Self::grow), and [`next`](Self::next); [`disarm`](Self::disarm) and
/// [`set_cover`](Self::set_cover) are synchronous (they return no future), and
/// [`canonicalize_key`](Self::canonicalize_key) / [`root_key`](Self::root_key) are synchronous
/// probes. The bounds are written explicitly on each return type (rather than left implicit by
/// `async fn`, whose futures carry no such bound), so a generic `S: Source<C>` owner is
/// structurally spawnable — every implementor's futures must satisfy them. This is
/// unconditionally satisfiable for the fs source because the `tributary-fs` watcher is
/// `Sync` (its `watch`/`unwatch` futures are `Send`).
///
/// **A completion-based / `!Send` transport (io_uring via compio, or any thread-per-core
/// ring) has two conforming shapes.** It can implement THIS trait by running its ring on a
/// dedicated thread behind channels — exactly the shape the in-tree fs stack already uses
/// one layer down (the inotify/fanotify reader threads, and `FsSource`'s watcher-backed
/// release queue); the `Send` bounds here are then satisfied by the CHANNEL futures (a
/// `recv` is `Send` and cancel-safe by construction, meeting the [`next`](Self::next)
/// contract for free), never by the ring internals, which stay pinned to their own thread.
/// Or it can implement [`LocalSource`] directly — the same items with no `Send` promise —
/// and construct through [`Tributaries::parts_local`](crate::Tributaries::parts_local),
/// polling the returned driver future on the thread that owns the source. Neither shape
/// waits on unstable syntax: return-type notation (the per-bound-site `S::arm(..): Send`
/// clause that would let ONE trait serve both) remains unstabilized with no owner or
/// timeline upstream, and the [`LocalSource`] split is its stable equivalent — `Source` IS
/// `LocalSource` plus the `Send` promise, which is exactly what RTN would spell at the
/// bound sites.
pub trait Source<C> {
  /// The armed-root token a successful [`arm`](Self::arm) yields, naming the concrete
  /// watch a later [`disarm`](Self::disarm) releases and an event's
  /// [`SourceEvent::handle`] identifies. Contract-identical to [`LocalSource::Handle`],
  /// whose **generation-unique handle contract** (a hard requirement) applies verbatim: a
  /// handle value is never reused while any root or not-yet-emitted event still carries
  /// it, making handle ABA impossible.
  type Handle: Copy + Eq + core::hash::Hash;

  /// Canonicalizes the caller-supplied `key` into the source's own **canonical
  /// coordinate**, or reports why it cannot. Contract-identical to
  /// [`LocalSource::canonicalize_key`] — the single-choke-point rationale and the
  /// idempotence hard contract there apply verbatim (the method is synchronous, so the two
  /// traits' signatures coincide exactly).
  ///
  /// # Errors
  ///
  /// A [`WatchError`] when `key` cannot be canonicalized (see
  /// [`LocalSource::canonicalize_key`]).
  fn canonicalize_key(&self, key: &[C]) -> Result<Vec<C>, WatchError>;

  /// Arms a concrete watch for `key`, returning the armed-root token plus the
  /// **canonical** key the source actually armed. Contract-identical to
  /// [`LocalSource::arm`] (canonical-key adoption, caller-bounded liveness); the future
  /// here additionally promises `Send` (see the `Send` bounds note on the [trait](Self)).
  ///
  /// # Errors
  ///
  /// A [`WatchError`] when the concrete watch cannot be armed.
  fn arm(
    &mut self,
    key: &[C],
  ) -> impl Future<Output = Result<Armed<C, Self::Handle>, WatchError>> + Send;

  /// Requests release of the root named by `handle` — synchronous, non-blocking,
  /// fire-and-forget, never awaited. Contract-identical to [`LocalSource::disarm`], whose
  /// five-clause hard contract (non-blocking; no arm surfaces a released-root overlap;
  /// logically dead immediately; idempotent/tolerant; eventual release) applies verbatim.
  fn disarm(&mut self, handle: Self::Handle);

  /// Grows the root named by `handle` so its actual coverage includes every key in
  /// `retained` — the **awaited GROW half** of in-place coverage reconcile.
  /// Contract-identical to [`LocalSource::grow`] (`Ok` = applied-before-return, never
  /// moves survivor coverage, idempotent, a no-op `Ok` conforming only for a source
  /// whose coverage never narrows — the default body); the future here additionally
  /// promises `Send` (see the `Send` bounds note on the [trait](Self)).
  ///
  /// # Errors
  ///
  /// See [`LocalSource::grow`]: `Err` = coverage may not include some `retained` key,
  /// with the dominating in-band loss signal already emitted where one is owed; the
  /// umbrella keeps its record unbroadened and fails the caller's watch retryably.
  fn grow(
    &mut self,
    handle: Self::Handle,
    retained: &[Vec<C>],
  ) -> impl Future<Output = Result<(), WatchError>> + Send {
    let _ = (handle, retained);
    async { Ok(()) }
  }

  /// Requests that the root named by `handle` PRUNE its actual coverage toward the
  /// `retained` cover — synchronous, fire-and-forget, purely an optimization.
  /// Contract-identical to [`LocalSource::set_cover`], whose six-clause hard contract
  /// applies verbatim (the default no-op is conforming; a source that actually narrows
  /// coverage MUST pair it with a real [`grow`](Self::grow)).
  fn set_cover(&mut self, handle: Self::Handle, retained: &[Vec<C>]) {
    let _ = (handle, retained);
  }

  /// The next raw change as a [`SourceEvent`], or [`None`] once the source is closed and
  /// drained. Contract-identical to [`LocalSource::next`] — in particular its
  /// **cancellation-safety hard contract** (dropping an in-flight `next()` future loses
  /// and acknowledges no event) applies verbatim; the future here additionally promises
  /// `Send`, so the owner can pump the stream from its spawned task (see the `Send` bounds
  /// note on the [trait](Self)).
  fn next(&mut self) -> impl Future<Output = Option<SourceEvent<C, Self::Handle>>> + Send;

  /// Retargets an armed root **in place** — the same `handle`, a new (necessarily WIDER)
  /// key — returning the handle unchanged alongside the key the source committed to.
  ///
  /// This is the gapless alternative to release-and-rearm. The umbrella's widen would
  /// otherwise [`disarm`](Self::disarm) the subsumed roots and [`arm`](Self::arm) a wider
  /// one, which drops kernel coverage for the window between them — a gap the re-pointed
  /// subscribers' dominating `Rescan` covers but cannot un-lose. A source that can widen
  /// its own root make-before-break (the fs binding does: `Watcher::replace_root` brings the
  /// replacement stream up BEFORE retiring the old one) offers it here instead.
  ///
  /// **The handle is PRESERVED, deliberately** — this is the one sanctioned exception to the
  /// generation-unique [`Handle`](Self::Handle) contract, and it is sound precisely because
  /// no fresh handle is minted: nothing can alias, and the umbrella re-keys its record in
  /// place rather than dropping and re-inserting.
  ///
  /// **Atomic on failure**: every error MUST leave the old root's coverage exactly as it was,
  /// because the umbrella falls back to the release-and-rearm path on ANY error — including
  /// the default's [`FaultKind::Unsupported`](crate::FaultKind::Unsupported), which is simply
  /// "this source cannot widen in place; do it the old way". A source that cannot promise
  /// atomicity must not implement this method.
  fn replace(
    &mut self,
    handle: Self::Handle,
    new_key: &[C],
  ) -> impl Future<Output = Result<Armed<C, Self::Handle>, WatchError>> + Send {
    let _ = (handle, new_key);
    async {
      Err(WatchError::Source(crate::error::SourceFault::new(
        crate::error::FaultKind::Unsupported,
      )))
    }
  }

  /// Places a **sync-barrier cookie** under `dir_key` for the root `handle`, returning the
  /// cookie's canonical key. AWAITED, and it resolves at **write-complete — never at
  /// observe**: the cookie's event arrives through the very [`next`](Self::next) pump the
  /// owner would otherwise be blocking, so awaiting the observation here would deadlock by
  /// construction. Observation is the owner's funnel-driven business.
  ///
  /// The cookie's whole purpose is the kernel event its creation mints: that event rides the
  /// root's ordered queue BEHIND every change the backend reported before the write, so
  /// observing it proves those changes have already exited the pipeline. A source whose
  /// backend cannot report an in-band marker cannot offer the barrier and keeps the default
  /// ([`SyncError::Unsupported`]) — an honest refusal, never a pretend barrier.
  ///
  /// `token` identifies the sync (instance + pid + seq); the binding renders it into whatever
  /// a marker is called in its namespace, and must ensure [`is_sync_artifact`](Self::is_sync_artifact)
  /// answers `true` for the key it returns. A source that must park the write behind its own
  /// coverage-settle machinery does so INSIDE this await (the fs binding parks on the
  /// per-directory re-arm fence), which is exactly why the initiation is awaited and bounded
  /// like [`grow`](Self::grow).
  fn begin_sync(
    &mut self,
    handle: Self::Handle,
    dir_key: &[C],
    token: SyncToken,
  ) -> impl Future<Output = Result<Vec<C>, SyncError>> + Send {
    let _ = (handle, dir_key, token);
    async { Err(SyncError::Unsupported) }
  }

  /// Reaps a cookie [`begin_sync`](Self::begin_sync) placed — SYNCHRONOUS, non-blocking,
  /// fire-and-forget, in the [`disarm`](Self::disarm) mold. Idempotent (a cookie already gone
  /// is success) and eventual (the unlink need not have landed when this returns).
  ///
  /// The unlink mints its own event; that event is suppressed by the reserved-namespace rule
  /// ([`is_sync_artifact`](Self::is_sync_artifact)), NOT by any pending-sync bookkeeping — by
  /// the time it arrives, the sync it belonged to is already resolved and forgotten.
  fn end_sync(&mut self, handle: Self::Handle, cookie_key: &[C]) {
    let _ = (handle, cookie_key);
  }

  /// Abandons the sync identified by `token` — SYNCHRONOUS, non-blocking, fire-and-forget, in the
  /// [`end_sync`](Self::end_sync)/[`disarm`](Self::disarm) mold. Called when the owner abandons an
  /// IN-FLIGHT [`begin_sync`](Self::begin_sync) (the caller timed out, or a close won the owner's
  /// race): the owner never learned the cookie's key — only a completed `begin_sync` returns it — but
  /// it still knows the `token` it minted, and the binding recovers the sync's identity from it.
  ///
  /// The binding must ensure a cookie this sync ALREADY created — even one whose completion the owner
  /// never read — is eventually removed, and that a write still in flight leaves no cookie behind when
  /// it lands. Idempotent; a token whose sync already fully resolved is a no-op. Best-effort on an
  /// abnormal teardown, exactly like `end_sync`.
  fn cancel_sync(&mut self, handle: Self::Handle, token: SyncToken) {
    let _ = (handle, token);
  }

  /// Whether `key` names an artifact of the sync-barrier machinery — a cookie, whoever wrote
  /// it. A SYNCHRONOUS classify probe in the [`root_key`](Self::root_key) mold.
  ///
  /// The umbrella suppresses every matching event from consumer streams, before fan-out and
  /// before the coalescer, and uses the match to resolve pending syncs. The suppression is
  /// **namespace-total, not own-pending-only**: two watcher instances may legitimately watch
  /// one tree, and instance A's cookies must never surface as user files on instance B's
  /// stream — nor must our own already-resolved cookies' unlink events, nor a crashed
  /// process's leftovers.
  ///
  /// A `Rescan` is NEVER suppressed, whatever its key: the umbrella checks that first, because
  /// a Rescan is coverage information and is structurally unmaskable.
  fn is_sync_artifact(&self, key: &[C]) -> bool {
    let _ = key;
    false
  }

  /// The **canonical key** of the root `handle` names, or [`None`] once that root is dead
  /// or retired — a synchronous liveness probe. Contract-identical to
  /// [`LocalSource::root_key`].
  /// The **canonical key** of the root `handle` names, or [`None`] once that root is dead
  /// or retired — a **synchronous** liveness probe (mirroring the `tributary-fs`
  /// watcher's `root_path`, which reads a live registry snapshot without I/O).
  ///
  /// The owner uses it to tell a **terminal** coverage-loss signal (the root vanished —
  /// `root_key` is `None`, so the root is retired, freeing its index / filter / epoch
  /// state) from an **overflow** re-enumeration (the root is still live — `root_key` is
  /// `Some`, so the root is kept and the consumer re-enumerates). Because it is out of
  /// band, it never races the event stream the owner drives (design §4, I4).
  fn root_key(&self, handle: Self::Handle) -> Option<Vec<C>>;
}

/// Every [`Source`] is a [`LocalSource`]: the forwarding blanket impl wraps each of
/// [`Source`]'s (unnameable) `+ Send` opaque futures in a fresh opaque that simply does
/// not re-state the `Send` promise. The hidden types still ARE the `Send` futures, so
/// auto-trait leakage keeps the owner future `Send` for a generic `S: Source` — the proof
/// [`Tributaries::parts`](crate::Tributaries::parts) stands on. Every item forwards
/// explicitly — including the defaulted [`grow`](Source::grow) /
/// [`set_cover`](Source::set_cover) — so an implementor's overrides are never shadowed by
/// [`LocalSource`]'s own defaults.
impl<C, T: Source<C>> LocalSource<C> for T {
  type Handle = <T as Source<C>>::Handle;

  fn canonicalize_key(&self, key: &[C]) -> Result<Vec<C>, WatchError> {
    <T as Source<C>>::canonicalize_key(self, key)
  }

  fn arm(&mut self, key: &[C]) -> impl Future<Output = Result<Armed<C, Self::Handle>, WatchError>> {
    <T as Source<C>>::arm(self, key)
  }

  fn disarm(&mut self, handle: Self::Handle) {
    <T as Source<C>>::disarm(self, handle)
  }

  fn grow(
    &mut self,
    handle: Self::Handle,
    retained: &[Vec<C>],
  ) -> impl Future<Output = Result<(), WatchError>> {
    <T as Source<C>>::grow(self, handle, retained)
  }

  fn set_cover(&mut self, handle: Self::Handle, retained: &[Vec<C>]) {
    <T as Source<C>>::set_cover(self, handle, retained)
  }

  fn next(&mut self) -> impl Future<Output = Option<SourceEvent<C, Self::Handle>>> {
    <T as Source<C>>::next(self)
  }

  fn root_key(&self, handle: Self::Handle) -> Option<Vec<C>> {
    <T as Source<C>>::root_key(self, handle)
  }

  fn replace(
    &mut self,
    handle: Self::Handle,
    new_key: &[C],
  ) -> impl Future<Output = Result<Armed<C, Self::Handle>, WatchError>> {
    <T as Source<C>>::replace(self, handle, new_key)
  }

  fn begin_sync(
    &mut self,
    handle: Self::Handle,
    dir_key: &[C],
    token: SyncToken,
  ) -> impl Future<Output = Result<Vec<C>, SyncError>> {
    <T as Source<C>>::begin_sync(self, handle, dir_key, token)
  }

  fn end_sync(&mut self, handle: Self::Handle, cookie_key: &[C]) {
    <T as Source<C>>::end_sync(self, handle, cookie_key)
  }

  fn cancel_sync(&mut self, handle: Self::Handle, token: SyncToken) {
    <T as Source<C>>::cancel_sync(self, handle, token)
  }

  fn is_sync_artifact(&self, key: &[C]) -> bool {
    <T as Source<C>>::is_sync_artifact(self, key)
  }
}

/// The identity of one sync barrier, minted by the owner: unique across
/// concurrent syncs (`seq`), across watcher instances in one process
/// (`instance`), and across processes (`pid`).
///
/// The umbrella is generic over the key component `C` and cannot know what a
/// path looks like, so it hands this token to the binding and the BINDING
/// renders the cookie's name from it (the fs binding:
/// `.tributaries-sync-<instance>-<pid>-<seq>`). That keeps the reserved
/// namespace — and its suppression rule — at the layer that owns path shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyncToken {
  instance: u64,
  pid: u32,
  seq: u64,
  nonce: u64,
}

impl SyncToken {
  /// Mints a token from the owner's instance brand, the process id, a
  /// per-owner monotonic sequence number, and an **unguessable per-sync
  /// nonce**.
  ///
  /// The nonce is load-bearing, not decoration: without it the cookie's name
  /// is a deterministic function of `(instance, pid, seq)`, so another writer
  /// under the same tree could predict the next name, create-then-delete it,
  /// and leave a stale event that a later sync would match — falsely
  /// completing the barrier ahead of a real pre-call change. An owner-secret
  /// nonce makes the name unpredictable, so the only event ever carrying a
  /// sync's key is that sync's own cookie create — which per-source FIFO
  /// places after every change that happened before it.
  pub const fn new(instance: u64, pid: u32, seq: u64, nonce: u64) -> Self {
    Self {
      instance,
      pid,
      seq,
      nonce,
    }
  }

  /// The owner's process-global instance brand.
  pub const fn instance(&self) -> u64 {
    self.instance
  }

  /// The process that minted the cookie. A crashed prior process's leftovers
  /// carry a dead pid, so they collide with nothing.
  pub const fn pid(&self) -> u32 {
    self.pid
  }

  /// The per-owner monotonic sequence number: unique across concurrent syncs.
  pub const fn seq(&self) -> u64 {
    self.seq
  }

  /// The unguessable per-sync nonce — the component an external writer cannot
  /// predict, so it cannot pre-create a colliding marker.
  pub const fn nonce(&self) -> u64 {
    self.nonce
  }
}

/// How a [`sync`](crate::Tributaries::sync) barrier was met.
///
/// Both variants are success — the promise is *deliverable-or-dominated*, and
/// this only says which arm satisfied it, so a caller that must distinguish
/// "I can read my deltas" from "I must re-enumerate" need not inspect the
/// stream to find out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SyncOutcome {
  /// The cookie's own event was observed: every change that happened before
  /// the sync call has been emitted to the stream (subject to the
  /// subscription's interest and filter gates).
  Delivered,
  /// A covering `Rescan` stood in for the cookie — a loss ate the cookie's
  /// event, or the root died — so the barrier is met by re-enumeration
  /// instead of by delivery. The `Rescan` is on the stream (or durably parked
  /// ahead of every later delta), so the caller's obligation is to re-read,
  /// not to worry.
  Dominated,
}

impl SyncOutcome {
  /// Whether the cookie itself was observed.
  #[inline]
  pub const fn is_delivered(&self) -> bool {
    matches!(self, Self::Delivered)
  }

  /// Whether a covering `Rescan` stood in for the cookie.
  #[inline]
  pub const fn is_dominated(&self) -> bool {
    matches!(self, Self::Dominated)
  }
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
  /// `canonical_key` the source committed to — the constructor an out-of-tree source
  /// ([`Source`] or [`LocalSource`]) uses to report what it armed.
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
/// [`key`](Self::key), and (for a move) decomposes it per subscriber using the
/// [`Moved`](EventKind::Moved) kind's in-kind source key. The [`kind`](Self::kind) is
/// the umbrella-owned **source-neutral** vocabulary [`EventKind`]: the umbrella owns it,
/// and every source — the fs binding included — maps its raw kinds into it at its
/// binding (see the [source-honesty contract](EventKind#source-honesty-the-binding-contract)),
/// rather than any source's own enum leaking through the seam.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SourceEvent<C, H> {
  handle: H,
  key: Vec<C>,
  kind: EventKind<C>,
  location: Location,
  epoch: Epoch,
  change_id: Option<ChangeId>,
}

impl<C, H> SourceEvent<C, H> {
  /// Builds a source event from its parts — the constructor an out-of-tree source
  /// ([`Source`] or [`LocalSource`]) uses to report a raw change in its own `C` key space.
  ///
  /// `handle` is the armed root the change belongs to; `key` its full located key;
  /// `kind` what happened (in the neutral [`EventKind`] vocabulary — a
  /// [`Moved`](EventKind::Moved) carries its source key in-kind); `location` the
  /// change's root-relative location; `epoch` the raw source epoch; and `change_id` the
  /// change's unique id, when the source mints one (a source with no ids passes `None`
  /// rather than counterfeiting them — the fs binding passes `Some`).
  pub fn new(
    handle: H,
    key: Vec<C>,
    kind: EventKind<C>,
    location: Location,
    epoch: Epoch,
    change_id: Option<ChangeId>,
  ) -> Self {
    Self {
      handle,
      key,
      kind,
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

  /// What happened, in the umbrella's source-neutral [`EventKind`] vocabulary. A
  /// [`Moved`](EventKind::Moved) carries its source key in-kind, so a whole-move
  /// delivery stays lossless.
  #[inline]
  #[must_use]
  pub fn kind(&self) -> &EventKind<C> {
    &self.kind
  }

  /// The move **source** key, present only for a [`Moved`](EventKind::Moved) — the second
  /// endpoint the umbrella decomposes and the coalescer keys on. `None` for every
  /// single-endpoint kind. Delegates to the kind's in-kind payload
  /// ([`EventKind::moved_from`]).
  #[inline]
  #[must_use]
  pub fn move_from(&self) -> Option<&[C]> {
    self.kind.moved_from()
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

  /// The change's unique id (monotonic per source), when the source mints one; `None`
  /// for a source with no ids (the fs binding always supplies `Some`).
  #[inline]
  #[must_use]
  pub const fn change_id(&self) -> Option<ChangeId> {
    self.change_id
  }

  /// Whether this is a [`Rescan`](EventKind::Rescan) — the coverage-loss signal the
  /// umbrella fans out to every subscriber, bypassing coverage and filtering.
  #[inline]
  #[must_use]
  pub const fn is_rescan(&self) -> bool {
    self.kind.is_rescan()
  }
}
