//! The [`Source<C>`]/[`LocalSource<C>`] binding seam (design §4) and its default
//! local-filesystem implementation over [`tributary_fs::Watcher`].
//!
//! The generic watch-set the umbrella maintains is source-agnostic: it plans
//! subsumption and fans events out purely in `Vec<C>` key space. A **source** is the
//! one place that knows how a key maps to a concrete watch, and how a raw change maps
//! back to a located key. For 0.1.0 the only source is [`FsSource`], binding
//! `C = OsString` (a path's components) to the local filesystem over one
//! [`tributary_fs::Watcher`]; a general remote-capable registry is future work.
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
  Event as FsEvent, EventKind as FsEventKind, RootHandle, SourceError, WatchRootError, Watcher,
  WatcherOptions,
};
use tributary_proto::{ChangeId, Epoch, Interest, Location};

use crate::{
  error::{BuildError, FaultKind, SourceFault, WatchError},
  event::{EventKind, path_components},
};

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
///   the default local-filesystem [`FsSource`] and any channel-fronted transport included —
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
///   surfaces the [`Overlaps`](tributary_fs::WatchRootError::Overlaps) the umbrella exists to subsume
///   away — a conforming source guarantees no arm surfaces an overlap caused by a released root
///   (contract clause 2), whether by pre-applying the release or by resolving the lower watcher's own
///   identity-aware `Overlaps` rejection and retrying, so the umbrella needs no flushing of its own.
///
/// **OPTIONAL of a source (in-place coverage reconcile — never relied on for delivery correctness):**
///
/// A source may reclaim (and, when a survivor returns to a pruned region, restore) the kernel
/// coverage of a root that outlived the subscription whose key equalled it (design §5, set-cover ). It
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
///   the default no-op `set_cover` (its coverage never narrows) keeps the default no-op `grow` too.
///   `grow` is awaited inside the caller-bounded reconcile and **applied before return**, so the
///   newcomer's coverage is live before `watch()` returns — closing the request→apply window a
///   fire-and-forget re-issue left open (set-cover ), with no bridging `Rescan` needed.
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
/// down every live watch as it exits — exactly what [`FsSource`] inherits from
/// [`tributary_fs::Watcher`]'s drop semantics.
pub trait LocalSource<C> {
  /// The armed-root token a successful [`arm`](Self::arm) yields, naming the concrete
  /// watch a later [`disarm`](Self::disarm) releases and an event's
  /// [`SourceEvent::handle`] identifies. `Copy + Eq + Hash` so the umbrella can key its
  /// per-root bookkeeping on it (the fs source uses [`RootHandle`]).
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
  ///    later [`arm`](Self::arm) never **surfaces** an
  ///    [`Overlaps`](tributary_fs::WatchRootError::Overlaps) rejection caused by a root whose release
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
  ///    - **conflict-triggered application-and-retry** — as [`FsSource`] now does: attempt the arm,
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
  /// coverage UP **in place**. **Awaited**, and awaited **only inside a caller-bounded `watch`
  /// reconcile** (the ratified fence — invariant I1 — covers it exactly like [`arm`](Self::arm)): the
  /// umbrella runs the reconcile to completion, so a wedged `grow` blocks that one reconcile until the
  /// source honors the contract, exactly as a wedged [`arm`](Self::arm) does, and never any unrelated
  /// backlog or a queued [`close`](crate::Tributaries::close).
  ///
  /// The umbrella issues this when a `Covered` newcomer lands OUTSIDE a root's already-narrowed
  /// coverage (design §5, set-cover ): the newcomer arms nothing, so without a grow the source would not
  /// back its subtree. Rather than release-and-rearm the whole root at the umbrella (which would move
  /// the survivors' coverage, forcing a gap-closing [`Rescan`](EventKind::Rescan)), the
  /// source re-arms only the missing subtree in place — survivor coverage never moves, so events under
  /// an unchanged `retained` key keep flowing with **no gap and no loss**. It is the awaited GROW
  /// counterpart of the fire-and-forget [`set_cover`](Self::set_cover) PRUNE.
  ///
  /// # Hard contract
  ///
  /// 1. **Applied, not enqueued — coverage is live on return.** When `grow` returns, the source's
  ///    ACTUAL coverage MUST already include every key in `retained` (the re-armed subtrees are live),
  ///    NOT merely have the request queued. This is what lets the umbrella commit a `Covered`-outside
  ///    newcomer with **no bridging `Rescan`**: a watch is "changes from now on", and because coverage
  ///    is live before `watch()` returns there is no request→apply window in which a write could be
  ///    silently lost — the exact loss a deferred fire-and-forget re-issue behind an already-flushed
  ///    bridge could leak.
  /// 2. **Never moves survivor coverage.** A `retained` prefix the source already covers is left
  ///    untouched (no re-crawl, no gap); only a prefix it does not yet cover is (re-)armed.
  /// 3. **Idempotent.** Growing to a `retained` the source already fully covers is a no-op.
  /// 4. **A no-op is conforming only for a source whose coverage never narrows.** The **default is a
  ///    no-op**, correct for a whole-subtree source (one stream / one recursive mark per root) whose
  ///    actual coverage never shrank below a root — there is nothing to grow back. A source that can
  ///    prune below a root (a per-directory descending backend, whose [`set_cover`](Self::set_cover)
  ///    actually narrows coverage) MUST implement `grow`, or a `Covered`-outside newcomer under a
  ///    pruned region would silently receive nothing.
  ///
  /// `retained` is a prefix-free antichain in the same `C` key space as [`arm`](Self::arm): every key
  /// lies under exactly one member, and no member descends from another.
  ///
  /// One of the three awaited methods, alongside [`arm`](Self::arm) and [`next`](Self::next);
  /// the returned future carries no `Send` requirement here ([`Source::grow`] is the
  /// `Send`-promising twin).
  fn grow(&mut self, handle: Self::Handle, retained: &[Vec<C>]) -> impl Future<Output = ()> {
    let _ = (handle, retained);
    async {}
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
  /// `unwatch` that shrinks an already-narrowed cover (design §5, set-cover ). Rather than release-and-
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
  ///    promptly. [`FsSource`] forwards it to the watcher's control channel the instant `set_cover` is
  ///    called, via a non-blocking reply-less request; only when that channel is momentarily full does
  ///    it DEFER, re-forwarding at the next source op that touches the watcher (another `set_cover`, a
  ///    [`disarm`](Self::disarm), or an [`arm`](Self::arm)). A **no-op is still conforming**: an
  ///    unreconciled root is merely over-broad — correctness-neutral and self-healing.
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
  /// [`FsSource`] satisfies this: its `next` awaits [`tributary_fs::Watcher::next`], itself
  /// an `async_channel` receive, which is cancel-safe by construction.
  fn next(&mut self) -> impl Future<Output = Option<SourceEvent<C, Self::Handle>>>;

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
/// implementation is [`FsSource`]. **Every contract on [`LocalSource`] applies verbatim**:
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
/// unconditionally satisfiable for the fs source because [`tributary_fs::Watcher`] is
/// `Sync` (its `watch`/`unwatch` futures are `Send`).
///
/// **A completion-based / `!Send` transport (io_uring via compio, or any thread-per-core
/// ring) has two conforming shapes.** It can implement THIS trait by running its ring on a
/// dedicated thread behind channels — exactly the shape the in-tree fs stack already uses
/// one layer down (the inotify/fanotify reader threads, and [`FsSource`]'s watcher-backed
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
  /// Contract-identical to [`LocalSource::grow`] (applied-before-return, never moves
  /// survivor coverage, idempotent, a no-op conforming only for a source whose coverage
  /// never narrows — the default body); the future here additionally promises `Send` (see
  /// the `Send` bounds note on the [trait](Self)).
  fn grow(&mut self, handle: Self::Handle, retained: &[Vec<C>]) -> impl Future<Output = ()> + Send {
    let _ = (handle, retained);
    async {}
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

  /// The **canonical key** of the root `handle` names, or [`None`] once that root is dead
  /// or retired — a synchronous liveness probe. Contract-identical to
  /// [`LocalSource::root_key`].
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

  fn grow(&mut self, handle: Self::Handle, retained: &[Vec<C>]) -> impl Future<Output = ()> {
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

/// The default source: the local filesystem, over one [`tributary_fs::Watcher`].
///
/// Binds `C = OsString` (a path's [components](std::path::Path::components)) to real
/// kernel watches. This is the only place the crate maps a key to a path and reverses a
/// raw filesystem event back into a key.
pub struct FsSource<R: RuntimeLite> {
  watcher: Watcher<R>,
  /// Roots whose release was requested (via the synchronous [`disarm`](Source::disarm)) but not yet
  /// handed to the [`Watcher`]'s control channel, each paired with the released root's **canonical
  /// path** captured at `disarm` time (while it was still live in the registry). [`arm`](Source::arm)
  /// drains this queue two ways (contract clause 2): (1) **opportunistically** it walks
  /// the queue and hands each entry to the watcher via the NON-BLOCKING, reply-less
  /// [`request_unwatch`](tributary_fs::Watcher::request_unwatch) — moving it to the in-flight
  /// [`enqueued`](Self::enqueued) sidecar — so the arm AWAITS NOTHING for a release that does not
  /// overlap it (keeping clause 5 eventual: every queued release is enqueued the moment the control
  /// channel has room), and (2) **on demand** it resolves any
  /// [`Overlaps`](tributary_fs::WatchRootError::Overlaps) the watch attempt reports by AWAITING an
  /// [`unwatch`](tributary_fs::Watcher::unwatch) of the entry the watcher *named* as the conflict
  /// (identity-aware — it catches case/normalization aliases) and retrying. The only release work a
  /// single arm AWAITS is (2) — bounded by that arm's OWN overlapping conflicts, never the (disjoint)
  /// backlog — so a caller-bounded `Watch`, and any [`close`](crate::Tributaries::close) queued behind
  /// it, never waits on unrelated teardown latency. A `None` path means the root
  /// was already torn down when disarmed; it can never be the *named* conflict, so it is applied only
  /// opportunistically (or at `Drop`, where the [`Watcher`]'s own teardown releases every live root).
  /// Bounded in practice by the live-root count: each generation-unique handle is released at most once.
  pending_releases: VecDeque<(RootHandle, Option<PathBuf>)>,
  /// Requested releases whose reply-less [`request_unwatch`](tributary_fs::Watcher::request_unwatch)
  /// the control channel ACCEPTED but the watcher registry may not yet reflect — the **in-flight**
  /// releases. Kept so a conflicting later arm can still resolve an
  /// [`Overlaps`](tributary_fs::WatchRootError::Overlaps) the watcher NAMES against a release whose
  /// fire-and-forget teardown has not landed yet: the entry is no longer in
  /// [`pending_releases`](Self::pending_releases), so without this sidecar the exact-match would miss
  /// and the arm would wrongly surface the overlap. On such a match the arm AWAITS an
  /// [`unwatch`](tributary_fs::Watcher::unwatch) of the named handle — which, enqueued after the
  /// reply-less request on the one FIFO channel, forces the teardown to land — then retries. Pruned at
  /// each arm's top of every entry the watcher has since applied
  /// ([`root_path`](tributary_fs::Watcher::root_path) `None`) — once the registry has forgotten a root
  /// it can never NAME it — so it is bounded by the in-flight (requested-but-unapplied) release count,
  /// never the watcher's lifetime.
  enqueued: Vec<(RootHandle, Option<PathBuf>)>,
  /// Union mirror of the requested releases — queued in [`pending_releases`](Self::pending_releases)
  /// AND in-flight in [`enqueued`](Self::enqueued) — for O(1) [`root_key`](Source::root_key) liveness
  /// answers (contract clause 3: a requested release is logically dead **immediately**, before its
  /// teardown lands). A handle stays dead-marked here exactly while the watcher still reports its root
  /// live; the same top-of-arm prune drops the mark the instant
  /// [`root_path`](tributary_fs::Watcher::root_path) takes over answering `None`, so the invariant
  /// "`root_key` is `None` from `disarm` until the handle is fully gone" holds unbroken while the set
  /// stays bounded by in-flight releases.
  pending_set: HashSet<RootHandle>,
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
  /// [`BuildError::Source`] when the underlying `tributary-fs` watcher cannot be built.
  pub fn new(options: WatcherOptions) -> Result<Self, BuildError> {
    // The only fs build failure is a configuration bound (too many exclusion paths); it
    // has no dedicated neutral kind, so it folds to `Other` with the whole fs error
    // preserved in the box for `BuildError::as_fs` recovery.
    let watcher = Watcher::new(options)
      .map_err(|err| BuildError::Source(SourceFault::new(FaultKind::Other).with_source(err)))?;
    Ok(Self {
      watcher,
      pending_releases: VecDeque::new(),
      enqueued: Vec::new(),
      pending_set: HashSet::new(),
    })
  }
}

/// How many pending releases one `arm` hands to the watcher's control channel via the
/// reply-less [`Watcher::request_unwatch`] — the HARD per-arm opportunistic budget (
/// ). A channel-full stop is not a bound (the driver drains concurrently, so `try_send`
/// can keep succeeding), and every reply-less `Unwatch` handed off here is processed BEFORE this
/// arm's own `watch` command on the same FIFO control channel — so an unbounded walk would couple
/// the caller (and any close behind it) to the entire unrelated release backlog. A fixed few per
/// arm keeps that pre-watch FIFO work O(1) while preserving clause 5's eventual application
/// (later arms, the conflict-triggered path, or `Drop` take the rest).
const OPPORTUNISTIC_RELEASE_HANDOFFS: usize = 2;

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
    let canonical = std::fs::canonicalize(&supplied).map_err(|source| {
      // Classify by the io error's kind — the two cases a caller can act on distinctly
      // (a missing path vs a permission wall) — and fold the rest to `Other`; the whole
      // io error is preserved in the box either way. The key's display form is this
      // binding's own rendering (the neutral error is not path-typed).
      let kind = match source.kind() {
        std::io::ErrorKind::NotFound => FaultKind::NotFound,
        std::io::ErrorKind::PermissionDenied => FaultKind::PermissionDenied,
        _ => FaultKind::Other,
      };
      WatchError::canonicalize(
        supplied.display().to_string(),
        SourceFault::new(kind).with_source(source),
      )
    })?;
    Ok(path_components(&canonical))
  }

  async fn arm(&mut self, key: &[OsString]) -> Result<Armed<OsString, RootHandle>, WatchError> {
    // (0) MAINTENANCE: drop every in-flight release the watcher has SINCE applied, and its dead-mark.
    // Once the watcher's registry has forgotten a root, it can never NAME it as a conflict again, and
    // `root_path` now answers the same `None` the mirror did — so pruning here keeps both the in-flight
    // sidecar and `pending_set` bounded by the in-flight (requested-but-unapplied) release count (never
    // the watcher's lifetime), while preserving the clause-3 invariant: a handle stays dead-marked in
    // `pending_set` exactly while the watcher still reports its root live, and the prune drops the mark
    // the instant `root_path` takes over answering `None`. Split-borrow: `watcher` is a shared reborrow
    // so each `retain` can mutate a DIFFERENT field.
    {
      let watcher = &self.watcher;
      self
        .enqueued
        .retain(|(handle, _)| watcher.root_path(*handle).is_some());
      self
        .pending_set
        .retain(|handle| watcher.root_path(*handle).is_some());
    }

    // (a) OPPORTUNISTIC NON-BLOCKING application: hand a HARD-BOUNDED few pending releases to the
    // watcher's control channel via the reply-less `request_unwatch` (a `try_send`). On acceptance
    // the entry moves from the queue to the in-flight `enqueued` sidecar and STAYS dead-marked in
    // `pending_set` (it is logically dead until its teardown lands, clause 3). This AWAITS NOTHING — a
    // disjoint arm is decoupled from every release's teardown latency. The bound is a
    // FIXED per-arm handoff budget, NOT the channel-full stop: on a multi-threaded
    // runtime the driver drains the channel concurrently, so try_send could keep succeeding and an
    // unbounded walk would enqueue the ENTIRE unrelated backlog ahead of this arm's own watch
    // command on the same FIFO channel — coupling the caller (and any close behind it) to unrelated
    // release processing. At most a fixed few per arm keeps that pre-watch FIFO work O(1); the rest
    // stay queued for later arms, the conflict-triggered path (c), or `Drop` (clause 5's three
    // routes unchanged). This is NOT the correctness mechanism — (c) is — so enqueuing an unrelated
    // release here is harmless (it was going to be released anyway).
    for _ in 0..OPPORTUNISTIC_RELEASE_HANDOFFS {
      let Some(entry) = self.pending_releases.pop_front() else {
        break;
      };
      // `entry.0` is `Copy` (a `RootHandle`), so the try_send borrows nothing of `entry`.
      if self.watcher.request_unwatch(entry.0) {
        self.enqueued.push(entry);
      } else {
        // Channel full/closed: return the entry to the FRONT (FIFO preserved) and stop.
        self.pending_releases.push_front(entry);
        break;
      }
    }
    // (b)+(c) Arm the root, resolving on demand any `Overlaps` the watcher reports against a
    // released-but-still-lingering root. Roots are always armed `Interest::all` (design §4): the kernel
    // watch never narrows what it collects, so a covered subscription can ask for any kind and the root
    // already carries it (interest becomes a pure fan-out gate at the umbrella).
    //
    // The correctness guarantee — a conforming source never SURFACES an `Overlaps` for a root whose
    // release was requested, QUEUED or IN-FLIGHT (disarm contract clause 2) — is upheld here by
    // construction: the WATCHER itself names the conflicting `existing` root (it rejects by
    // object/ancestor IDENTITY, so it catches case/normalization aliases a byte-prefix overlap test
    // would miss). While the watcher's registry still reports a requested release live
    // (so it can name it), that release is in `pending_releases` (not yet handed over) OR in `enqueued`
    // (handed over, teardown not landed) — never neither — so the named `existing` EXACT-matches one of
    // the two. Retry is a **structural progress bound**, not a fixed cap: on a match
    // remove exactly that entry, AWAIT its `unwatch`, and re-attempt. An `enqueued` match awaits an
    // acked `unwatch` that — enqueued after the earlier reply-less request on the one FIFO channel —
    // resolves only once the driver has processed that teardown and reclaimed the registry entry, so
    // the retry sees the root gone. Each retry strictly SHRINKS `pending_releases` + `enqueued` (one
    // exact-matched entry removed, neither grows in the loop), so it terminates in ≤ (queued + in-flight)
    // retries with no arbitrary ceiling (the common case is ≤1; an ancestor arm over N released
    // descendants is bounded by the N the watcher names one at a time — however large N is). A rejection
    // whose named conflict is in NEITHER set — a genuine LIVE conflict (an umbrella-side disjointness
    // bug), never a lingering released root — surfaces the overlap IMMEDIATELY: there is no index-0
    // fallback, so we never unwatch an unrelated pending root to mask a real conflict.
    let arm_path = key_to_path(key);
    // Progress tripwire (debug-only): the exact-match retry can run at most one more iteration than the
    // queued-plus-in-flight release count was deep, since that total strictly shrinks each retry and a
    // non-matching rejection exits immediately.
    #[cfg(debug_assertions)]
    let initial_pending = self.pending_releases.len() + self.enqueued.len();
    #[cfg(debug_assertions)]
    let mut iterations = 0usize;
    let handle = loop {
      #[cfg(debug_assertions)]
      {
        iterations += 1;
        debug_assert!(
          iterations <= initial_pending + 1,
          "FsSource::arm conflict-retry exceeded (queued + in-flight)+1 iterations — the queued and \
           in-flight release sets must strictly shrink each retry (structural progress bound)"
        );
      }
      match self.watcher.watch(arm_path.clone(), Interest::all()).await {
        Ok(handle) => break handle,
        Err(WatchRootError::Overlaps { path, existing }) => {
          // Resolve ONLY a conflict the watcher NAMES against a release we requested — QUEUED (not yet
          // handed to the channel) or IN-FLIGHT (handed over, teardown not landed). Await its teardown
          // and retry; a named conflict in neither set is a genuine live overlap, surfaced as-is.
          if let Some(index) = self
            .pending_releases
            .iter()
            .position(|(_, stored)| stored.as_deref() == Some(existing.as_path()))
          {
            let (released, _) = self
              .pending_releases
              .remove(index)
              .expect("index in bounds");
            let _ = self.watcher.unwatch(released).await;
            self.pending_set.remove(&released);
          } else if let Some(index) = self
            .enqueued
            .iter()
            .position(|(_, stored)| stored.as_deref() == Some(existing.as_path()))
          {
            let (released, _) = self.enqueued.remove(index);
            let _ = self.watcher.unwatch(released).await;
            self.pending_set.remove(&released);
          } else {
            return Err(watch_error_from_fs(WatchRootError::Overlaps {
              path,
              existing,
            }));
          }
        }
        Err(err) => return Err(watch_error_from_fs(err)),
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
    // Synchronous, non-blocking release REQUEST (contract clauses 1 & 3): queue it — paired with the
    // released root's canonical path captured NOW, while the root is still live in the registry — never
    // apply it inline. A later `arm` hands it to the watcher via the NON-BLOCKING `request_unwatch`
    // (the common path, which awaits nothing), or — if that arm's key overlaps this release — resolves
    // the conflict the watcher NAMES by awaiting exactly its `unwatch` (contract clause 2); `Drop` releases whatever is left (the `Watcher`'s own teardown reclaims every live
    // root). A `None` path means the root is already gone (`root_path` answers `None`): it can never be
    // the named conflict, so it is only applied opportunistically. The `pending_set` mirror makes the
    // handle logically dead the instant this returns — `root_key` answers `None`. Idempotent by the
    // set: re-requesting an already-pending (or unknown/dead) handle is a no-op.
    if self.pending_set.insert(handle) {
      let root_path = self.watcher.root_path(handle);
      self.pending_releases.push_back((handle, root_path));
    }
  }

  /// **Deferred no-op safe-disable.** The awaited GROW half of in-place coverage
  /// reconcile is disabled for the fs source. `grow`'s hard contract is met **vacuously** here:
  /// [`arm`](Self::arm) arms every root `Interest::all` over its **whole subtree** and this source's
  /// actual coverage never narrows below a root (its [`set_cover`](Self::set_cover) is the matching
  /// no-op), so every `retained` key already lies inside a live root's coverage — there is nothing to
  /// grow back, and clause 1 ("coverage is live on return") holds trivially.
  ///
  /// # Why disabled, not merely defaulted
  ///
  /// The awaited, now crate-internal `Watcher::set_cover` this method used to drive
  /// does NOT provide the correctness fence clause 1 demands: it returns when the fs core has
  /// **QUEUED** the re-arm effects onto its driver, not when the kernel watches backing `retained` are
  /// **live** — so a write between the ack and the effect landing could still be missed — and a failed
  /// grow was silently swallowed (its result ignored). A correctness-grade `grow` needs an
  /// **effect-completion token** the fs core does not yet mint; wiring that fence is deferred to a
  /// dedicated follow-up. Until then the fs source stays on its self-healing whole-subtree coverage,
  /// where the no-op is provably correct. The [`Source`] contract, the umbrella semantics, and the
  /// [`Watcher`] plumbing all remain correct and tested — only this binding defers.
  async fn grow(&mut self, handle: RootHandle, retained: &[Vec<OsString>]) {
    let _ = (handle, retained);
  }

  /// **Deferred no-op safe-disable.** The PRUNE half of in-place coverage reconcile is
  /// disabled for the fs source. A no-op is a **conforming** `set_cover` (contract clause 5, "purely
  /// an optimization" — correctness never depends on it): leaving a root at full-subtree coverage
  /// merely keeps it over-broad, which is correctness-neutral and self-healing, so this source
  /// reclaims no kernel budget for now but loses no event.
  ///
  /// # Why disabled, not merely defaulted
  ///
  /// It stands down together with its awaited GROW counterpart [`grow`](Self::grow): the prune cannot
  /// be safely restored until the fs core mints an **effect-completion token** for the acked
  /// `Watcher::set_cover` (now crate-internal; it returns at effect-QUEUE time, not
  /// when the kernel watches are live), so both halves defer rather than pruning coverage
  /// a not-yet-correct `grow` could not restore. Deferred to a dedicated follow-up. The [`Source`]
  /// contract, the umbrella semantics, and the [`Watcher`] plumbing all remain correct and tested —
  /// only this binding defers.
  fn set_cover(&mut self, handle: RootHandle, retained: &[Vec<OsString>]) {
    let _ = (handle, retained);
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
  /// Reverses a raw `tributary-fs` event into a source event — **the** fs-to-neutral
  /// map: its absolute path back into key components, and its
  /// [`tributary_fs::EventKind`] into the umbrella's source-neutral [`EventKind`]
  /// (a move's source path becomes the [`Moved`](EventKind::Moved) kind's in-kind
  /// source key). The one place the fs vocabulary and a raw filesystem event's key are
  /// converted at this binding.
  fn from_fs(event: &FsEvent) -> Self {
    let kind = match event.kind() {
      FsEventKind::Created => EventKind::Created,
      FsEventKind::Modified => EventKind::Modified,
      FsEventKind::Removed => EventKind::Removed,
      FsEventKind::Moved(moved) => EventKind::Moved {
        from: path_components(moved.from()),
      },
      FsEventKind::Rescan => EventKind::Rescan,
      // The fs enum is #[non_exhaustive]: an unknown future kind degrades to the
      // conservative re-read signal at this binding, exactly as fs itself folds
      // unknown proto kinds (the source-honesty contract).
      _ => EventKind::Rescan,
    };
    Self::new(
      event.root(),
      path_components(event.path()),
      kind,
      event.location().clone(),
      event.epoch(),
      Some(event.change_id()),
    )
  }
}

/// Maps a raw `tributary-fs` watch-root error into the umbrella's neutral error
/// vocabulary — the error half of the fs-to-neutral binding (its event half is
/// [`SourceEvent::from_fs`]), and the one place the fs error enum crosses the seam.
///
/// Classification is honest-and-conservative, mirroring the source-honesty contract on
/// [`EventKind`]: each fs case maps to its neutral [`FaultKind`], an unknown future case
/// degrades to [`Other`](FaultKind::Other), and a closed watcher maps to the umbrella's
/// own [`WatchError::Closed`] (the uniform "the stack is closed" signal). The whole fs
/// error is always preserved in the fault's box, so [`WatchError::as_fs`] recovers full
/// fidelity.
fn watch_error_from_fs(err: WatchRootError) -> WatchError {
  let kind = match &err {
    WatchRootError::NotFound { .. } => FaultKind::NotFound,
    WatchRootError::NotADirectory { .. } => FaultKind::NotADirectory,
    WatchRootError::Overlaps { .. } => FaultKind::Conflict,
    WatchRootError::Source(source) => match source {
      SourceError::Unsupported => FaultKind::Unsupported,
      SourceError::InstanceLimit => FaultKind::Capacity,
      _ => FaultKind::Other,
    },
    WatchRootError::Closed => return WatchError::Closed,
    _ => FaultKind::Other,
  };
  WatchError::source(SourceFault::new(kind).with_source(err))
}

/// Rebuilds a filesystem path from key components — the reverse of
/// [`path_components`](crate::event::path_components), and the only key → path conversion
/// the fs binding performs. `[a, b, c]` becomes `a/b/c`; an absolute key round-trips
/// through its leading root component.
fn key_to_path(key: &[OsString]) -> PathBuf {
  key.iter().collect()
}
