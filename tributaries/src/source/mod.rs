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
/// # `Send` bounds
///
/// [`next`](Self::next) — the event pump — returns a `Send` future: 0.1.0 targets tokio
/// and smol, and the driver may pump a generic source's stream from a task spawned on
/// their multi-threaded executors, so that future must be able to cross threads. The
/// bound is written explicitly on the return type (rather than left implicit by
/// `async fn`, whose futures carry no such bound), so a generic `S: Source<C>` pump is
/// structurally spawnable — every implementor's `next` future must satisfy it.
/// [`arm`](Self::arm) and [`disarm`](Self::disarm) run on the driver's single-writer
/// control path, never the spawned pump, so they carry no `Send` bound (mirroring the
/// crate's internal armer seam, and letting a source arm a watch it holds by shared
/// reference). A fully `!Send` thread-per-core (compio) variant — pump included — is
/// deferred to M2.
pub trait Source<C> {
  /// The armed-root token a successful [`arm`](Self::arm) yields, naming the concrete
  /// watch a later [`disarm`](Self::disarm) releases and an event's
  /// [`SourceEvent::handle`] identifies. `Copy + Eq + Hash` so the umbrella can key its
  /// per-root bookkeeping on it (the fs source uses [`RootHandle`]).
  type Handle: Copy + Eq + core::hash::Hash;

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
  fn arm(&mut self, key: &[C]) -> impl Future<Output = Result<Armed<C, Self::Handle>, WatchError>>;

  /// Releases the root named by `handle`.
  ///
  /// Best-effort: a source that cannot confirm the release (already closed, root already
  /// gone) absorbs it rather than surfacing an error, since a released root's runtime
  /// conditions reach the umbrella in-band as events, not out of band here.
  fn disarm(&mut self, handle: Self::Handle) -> impl Future<Output = ()>;

  /// The next raw change as a [`SourceEvent`], or [`None`] once the source is closed and
  /// drained. Returns a `Send` future so the driver can pump a generic source's stream
  /// on a spawned task (see the `Send` bounds note on the [trait](Self)).
  fn next(&mut self) -> impl Future<Output = Option<SourceEvent<C, Self::Handle>>> + Send;
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

  async fn arm(&mut self, key: &[OsString]) -> Result<Armed<OsString, RootHandle>, WatchError> {
    // Roots are always armed `Interest::all` (design §4): the kernel watch never narrows
    // what it collects, so a covered subscription can ask for any kind and the root
    // already carries it (interest becomes a pure fan-out gate at the umbrella).
    let handle = self
      .watcher
      .watch(key_to_path(key), Interest::all())
      .await?;
    // Adopt the filesystem-authoritative canonical path as the committed key (design §4,
    // the TOCTOU close): events are reported in canonical coordinates, so the index must
    // key on them. If fs cannot report one (the handle raced a teardown) fall back to the
    // requested key — a later event under a now-dead root routes to nothing regardless.
    let canonical_key = self
      .watcher
      .root_path(handle)
      .map(|path| path_components(&path))
      .unwrap_or_else(|| key.to_vec());
    Ok(Armed::new(handle, canonical_key))
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
