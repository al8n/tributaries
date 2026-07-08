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
//! releases a root, and [`Source::next`] yields the next raw change as a [`SourceEvent`]
//! carrying the owning root handle, the change's located key, its kind, and the metadata
//! the umbrella's fan-out and attribution consume.
//!
//! # Key ↔ path knowledge lives here only
//!
//! Rebuilding a path from key components and reversing a raw event's absolute path back
//! into components is the fs binding's private business. The umbrella never
//! re-implements it; it orchestrates subsumption and fan-out over `C` alone.

use std::{ffi::OsString, path::PathBuf, vec::Vec};

use agnostic_lite::RuntimeLite;
use tributary_fs::{
  ChangeId, Epoch, Event as FsEvent, EventKind, Interest, Location, MovedEvent, RootHandle,
  Watcher, WatcherOptions,
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
/// - **Liveness of [`arm`](Self::arm) / [`disarm`](Self::disarm) / [`canonicalize_key`](Self::canonicalize_key)**
///   — the umbrella awaits [`arm`](Self::arm)/[`disarm`](Self::disarm) (and calls the synchronous
///   [`canonicalize_key`](Self::canonicalize_key)) while processing a **caller-initiated**
///   `watch`/`unwatch`, running each reconcile to completion (invariant I1). These MUST make
///   progress and resolve. A source that makes one **hang indefinitely** violates this liveness
///   expectation: because the caller's `watch`/`unwatch` future is *also* awaiting, the caller may
///   drop it to cancel its own wait, but the umbrella still owns the in-flight reconcile — so a
///   wedged caller-initiated `arm`/`disarm` blocks the owner until the source honors the contract.
///   This is the source's responsibility, not a bug the umbrella can defend against.
/// - **Cancellation-safe [`next`](Self::next)** — dropping an in-flight [`next`](Self::next) future
///   loses and acknowledges no event (the hard contract on [`next`](Self::next)).
///
/// **GUARANTEED by the umbrella even against a misbehaving `Source`:**
///
/// - **A wedged [`next`](Self::next) never blocks command processing.** The owner drives
///   [`next`](Self::next) as one arm of a biased `select!`; a `next()` that never resolves is simply
///   a pending arm — the loop still services the command mailbox and `Close`.
/// - **Close-responsiveness against INTERNAL actions (invariant II).** Owner actions that are *not*
///   a caller-awaited `watch`/`unwatch` — a `DropOrphan` from a dropped `watch` grant (Codex
///   R20-F1), and the source-drain teardown (Codex R19) — MUST NEVER block `Close` on source I/O.
///   The umbrella never awaits their [`disarm`](Self::disarm) inline: it **defers** an orphan's
///   last-subscriber disarm and drains it only while racing the command mailbox (so a `Close` always
///   wins), and the source-drain teardown purges orphans synchronously. A wedged
///   [`disarm`](Self::disarm) of an orphaned root therefore delays only that deferred cleanup, never
///   `Close`. (Caller-initiated `arm`/`disarm` are the other half of the split above — bounded by
///   the source liveness contract, not by the umbrella.)
/// - **No stranded or corrupt state.** A committed-but-unclaimed subscription is always reconciled
///   away (the `WatchGrant`, invariant I1); a subscription terminal-retired while unclaimed leaves no
///   lingering parked `Rescan` behind (Codex R20-F2); and a deferred orphan-disarm that has not run
///   before a re-`watch` of the same key is flushed at the arm choke point, so the umbrella never
///   surfaces the `Overlaps` it exists to subsume away.
///
/// # `Send` bounds
///
/// **All three async methods return `Send` futures.** 0.1.0 targets tokio and smol, and
/// the driver is a single owned task spawned on their multi-threaded executors
/// ([`R::spawn_detach`](agnostic_lite::RuntimeLite::spawn_detach)) that drives arming,
/// disarming, and the event pump inline in one `select!` loop — so *every* future the
/// owner awaits must be able to cross threads for `run(owner)` itself to be `Send`. The
/// bounds are written explicitly on each return type (rather than left implicit by
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

  /// Releases the root named by `handle`.
  ///
  /// Best-effort: a source that cannot confirm the release (already closed, root already
  /// gone) absorbs it rather than surfacing an error, since a released root's runtime
  /// conditions reach the umbrella in-band as events, not out of band here.
  ///
  /// Returns a `Send` future (see the `Send` bounds note on the [trait](Self)).
  fn disarm(&mut self, handle: Self::Handle) -> impl Future<Output = ()> + Send;

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
    })
  }
}

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
    // Roots are always armed `Interest::all` (design §4): the kernel watch never narrows
    // what it collects, so a covered subscription can ask for any kind and the root
    // already carries it (interest becomes a pure fan-out gate at the umbrella).
    let handle = self
      .watcher
      .watch(key_to_path(key), Interest::all())
      .await?;
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

  async fn disarm(&mut self, handle: RootHandle) {
    // Best-effort: an already-closed watcher or an already-dead root cannot be unwatched,
    // and the umbrella treats those as in-band conditions, not errors (mirrors the
    // driver's widen-path disarms).
    let _ = self.watcher.unwatch(handle).await;
  }

  async fn next(&mut self) -> Option<SourceEvent<OsString, RootHandle>> {
    let raw = self.watcher.next().await?;
    Some(SourceEvent::from_fs(&raw))
  }

  fn root_key(&self, handle: RootHandle) -> Option<Vec<OsString>> {
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
