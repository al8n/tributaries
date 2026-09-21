use super::Source;
use crate::options::RootGlobs;

/// Compile-time proof that the **two** async [`Source`] futures — [`arm`](Source::arm) and the event
/// pump [`next`](Source::next) — are `Send`, so the owner (which drives them inline in one `select!`
/// loop) can be spawned via [`R::spawn_detach`](agnostic_lite::RuntimeLite::spawn_detach) on a
/// multi-threaded tokio or smol executor. [`disarm`](Source::disarm) is synchronous (it returns no
/// future). Never invoked — it only has to type-check: a regression that dropped a `Send` bound would
/// stop `needs_send` from accepting that future and fail this build. The generic bound is the
/// guarantee, so this holds for every implementor (including an out-of-tree custom source), not just
/// [`FsSource`].
#[allow(dead_code)]
fn assert_source_futures_send<C, S: Source<C>>(
  s: &mut S,
  key: &[C],
  globs: &RootGlobs,
  handle: S::Handle,
) {
  fn needs_send<F: Send>(_: F) {}
  needs_send(s.arm(key, globs));
  needs_send(s.next());
  // `disarm` is synchronous — no future to prove `Send`; the call keeps `handle` exercised.
  s.disarm(handle);
}

/// The blanket forwarding impl (`impl<C, T: Source<C>> LocalSource<C> for T`) forwards
/// EVERY item — including the defaulted [`grow`](Source::grow) /
/// [`set_cover`](Source::set_cover) — so a [`Source`] implementor's overrides are reached
/// when the owner drives it through [`LocalSource`](super::LocalSource). Fail-on-old: a
/// blanket impl that leaned on the base trait's own defaults for the two defaulted items
/// would silently swallow an implementor's coverage reconcile.
#[test]
fn blanket_local_source_forwards_every_item() {
  use futures_util::{FutureExt, StreamExt};

  use super::{Armed, BoxListing, Coverage, ListItem, LocalSource, RootLister, SourceEvent};
  use crate::error::{ListError, WatchError};

  #[derive(Default)]
  struct Probe {
    calls: Vec<&'static str>,
  }

  impl Source<u8> for Probe {
    type Handle = u8;

    fn canonicalize_key(&self, key: &[u8]) -> Result<Vec<u8>, WatchError> {
      Ok(key.to_vec())
    }

    fn arm(
      &mut self,
      key: &[u8],
      _globs: &RootGlobs,
    ) -> impl Future<Output = Result<Armed<u8, u8>, WatchError>> + Send {
      self.calls.push("arm");
      let canonical = key.to_vec();
      async move { Ok(Armed::new(7, canonical)) }
    }

    fn disarm(&mut self, _handle: u8) {
      self.calls.push("disarm");
    }

    fn grow(
      &mut self,
      _handle: u8,
      _retained: &[Vec<u8>],
    ) -> impl Future<Output = Result<(), WatchError>> + Send {
      self.calls.push("grow");
      async { Ok(()) }
    }

    fn set_cover(&mut self, _handle: u8, _retained: &[Vec<u8>]) {
      self.calls.push("set_cover");
    }

    fn next(&mut self) -> impl Future<Output = Option<SourceEvent<u8, u8>>> + Send {
      self.calls.push("next");
      async { None }
    }

    fn root_key(&self, _handle: u8) -> Option<Vec<u8>> {
      Some(vec![1])
    }

    fn coverage(&self, _handle: u8) -> Coverage {
      Coverage::Unproven
    }

    fn list(
      &self,
      _handle: u8,
      _globs: &RootGlobs,
    ) -> impl futures_util::Stream<Item = ListItem<u8>> {
      // Deliberately NOT the default's `Unsupported`: the two are distinguishable, so a
      // blanket impl that fell through to the base trait's default would be caught.
      futures_util::stream::once(core::future::ready(Err(ListError::UnknownRoot)))
    }

    fn lister(&self) -> Option<std::sync::Arc<dyn RootLister<u8, u8>>> {
      Some(std::sync::Arc::new(ProbeLister))
    }
  }

  /// The probe's enumerator: it answers one `Io` so a forwarded lister is told apart
  /// from a forwarded `list` (`UnknownRoot`) and from the default (`Unsupported`).
  struct ProbeLister;

  impl RootLister<u8, u8> for ProbeLister {
    fn list(
      &self,
      _root: u8,
      _from: &[u8],
      _globs: &RootGlobs,
      _cover: Option<&[Vec<u8>]>,
    ) -> BoxListing<u8> {
      Box::pin(futures_util::stream::once(core::future::ready(Err(
        ListError::Io {
          key: vec![9],
          source: std::io::Error::other("the probe's listing"),
        },
      ))))
    }
  }

  let mut probe = Probe::default();

  // Drive every item through the LocalSource seam (fully qualified, exactly as the
  // owner's generic `S: LocalSource` bound resolves them) and assert the implementor's
  // overrides answer.
  assert_eq!(
    LocalSource::canonicalize_key(&probe, &[1u8]).expect("canonicalize_key forwards"),
    vec![1u8],
  );
  let armed = LocalSource::arm(&mut probe, &[1u8], &RootGlobs::new())
    .now_or_never()
    .expect("the forwarded arm future is ready")
    .expect("arm forwards");
  assert_eq!(armed.handle(), 7, "the implementor's arm answered");
  LocalSource::grow(&mut probe, 7, &[])
    .now_or_never()
    .expect("the forwarded grow future is ready")
    .expect("the implementor's grow answered Ok");
  LocalSource::set_cover(&mut probe, 7, &[]);
  assert!(
    LocalSource::next(&mut probe)
      .now_or_never()
      .expect("the forwarded next future is ready")
      .is_none(),
    "the implementor's next answered"
  );
  LocalSource::disarm(&mut probe, 7);
  assert_eq!(
    LocalSource::root_key(&probe, 7),
    Some(vec![1u8]),
    "root_key forwards"
  );
  assert_eq!(
    LocalSource::coverage(&probe, 7),
    Coverage::Unproven,
    "the coverage STATE forwards — the owner reads the transition off this answer, so a \
     blanket impl that answered the default `Proven` would report no episode at all"
  );
  let listed = LocalSource::list(&probe, 7, &RootGlobs::new())
    .collect::<Vec<_>>()
    .now_or_never()
    .expect("the forwarded listing is ready");
  assert!(
    matches!(listed.as_slice(), [Err(err)] if err.is_unknown_root()),
    "the implementor's own listing forwards, not the base trait's `Unsupported`: {listed:?}"
  );
  let listing = LocalSource::lister(&probe)
    .expect("the implementor's lister forwards")
    .list(7, &[1u8], &RootGlobs::new(), None)
    .collect::<Vec<_>>()
    .now_or_never()
    .expect("the forwarded lister's listing is ready");
  assert!(
    matches!(listing.as_slice(), [Err(ListError::Io { key, .. })] if key == &vec![9u8]),
    "and it is the implementor's OWN lister: {listing:?}"
  );

  assert_eq!(
    probe.calls,
    vec!["arm", "grow", "set_cover", "next", "disarm"],
    "every recording item reached the implementor — the defaulted grow/set_cover were \
     forwarded, not shadowed by the base trait's own defaults"
  );
}

// The key ↔ path round-trip is portable (no runtime, no kernel watch, miri-clean), but
// it exercises the fs binding's private `key_to_path`, so it rides the `fs` feature.
#[cfg(feature = "fs")]
mod round_trip {
  use std::ffi::OsString;

  use super::super::fs::key_to_path;
  use crate::event::path_components;

  /// Asserts a component sequence round-trips: rebuilding a path from key components and
  /// re-decomposing it yields the original components. This is the fs binding's key ↔ path
  /// contract — events are located by re-decomposing a canonical path, so the two
  /// directions must be exact inverses on canonical component sequences.
  fn assert_round_trips(components: &[&str]) {
    let key: Vec<OsString> = components.iter().map(OsString::from).collect();
    let path = key_to_path(&key);
    assert_eq!(
      path_components(&path),
      key,
      "key ↔ path round-trip of {components:?}"
    );
  }

  #[test]
  fn round_trips_multi_component() {
    assert_round_trips(&["a", "b", "c"]);
  }

  #[test]
  fn round_trips_single_component() {
    assert_round_trips(&["only"]);
  }

  // The absolute cases pivot on the leading root component, whose spelling is
  // platform-specific; the crate's real backends are unix, and miri runs on the unix host.
  #[cfg(unix)]
  #[test]
  fn round_trips_absolute_multi_component() {
    // `/usr/local` decomposes to `["/", "usr", "local"]` and rebuilds back.
    assert_round_trips(&["/", "usr", "local"]);
  }

  #[cfg(unix)]
  #[test]
  fn round_trips_root() {
    assert_round_trips(&["/"]);
  }
}

/// The three items a source may leave alone answer what they promise, and each answer is
/// a STATEMENT rather than an absence.
///
/// `coverage` says `Proven` — a source that cannot lose coverage claims the one state it
/// can honestly claim, and the owner then delivers no transition at all. `list` says
/// `Unsupported` in ONE item — never an empty stream, because "this backend cannot tell
/// you what this root holds" and "this root holds nothing" are opposite instructions to a
/// consumer reconciling a tree against the answer. `lister` says `None`, which the
/// umbrella's own door reports as that same `Unsupported`.
#[test]
fn the_untouched_items_answer_what_they_promise() {
  use futures_util::{FutureExt, StreamExt};

  use super::{Armed, Coverage, LocalSource, SourceEvent};
  use crate::error::WatchError;

  struct Bare;

  impl Source<u8> for Bare {
    type Handle = u8;

    fn canonicalize_key(&self, key: &[u8]) -> Result<Vec<u8>, WatchError> {
      Ok(key.to_vec())
    }

    fn arm(
      &mut self,
      key: &[u8],
      _globs: &RootGlobs,
    ) -> impl Future<Output = Result<Armed<u8, u8>, WatchError>> + Send {
      let canonical = key.to_vec();
      async move { Ok(Armed::new(1, canonical)) }
    }

    fn disarm(&mut self, _handle: u8) {}

    fn next(&mut self) -> impl Future<Output = Option<SourceEvent<u8, u8>>> + Send {
      async { None }
    }

    fn root_key(&self, _handle: u8) -> Option<Vec<u8>> {
      Some(vec![1])
    }
  }

  let bare = Bare;
  assert_eq!(Source::coverage(&bare, 1), Coverage::Proven);
  assert_eq!(LocalSource::coverage(&bare, 1), Coverage::Proven);
  assert!(
    Source::lister(&bare).is_none(),
    "a source that hands out no enumerator says so"
  );

  for listed in [
    Source::list(&bare, 1, &RootGlobs::new())
      .collect::<Vec<_>>()
      .now_or_never()
      .expect("the default listing is ready"),
    LocalSource::list(&bare, 1, &RootGlobs::new())
      .collect::<Vec<_>>()
      .now_or_never()
      .expect("the forwarded default listing is ready"),
  ] {
    assert!(
      matches!(listed.as_slice(), [Err(err)] if err.is_unsupported()),
      "ONE refusal, never an empty root: {listed:?}"
    );
  }
}

/// The coverage STATE's own vocabulary: the two answers, their stable names, and the
/// predicates a consumer branches on.
#[test]
fn the_coverage_states_name_themselves() {
  use super::Coverage;

  assert_eq!(Coverage::Proven.as_str(), "proven");
  assert_eq!(Coverage::Unproven.as_str(), "unproven");
  assert_eq!(Coverage::Proven.to_string(), "proven");
  assert_eq!(Coverage::Unproven.to_string(), "unproven");
  assert!(Coverage::Proven.is_proven() && !Coverage::Proven.is_unproven());
  assert!(Coverage::Unproven.is_unproven() && !Coverage::Unproven.is_proven());
}

/// What a listing says about ONE entry: its class, its size, and the modification time it
/// reports only where the source read one.
///
/// `None` is the honest third answer for the time, not an epoch-zero default: a consumer
/// reconciling on it must be able to tell "unchanged since I last looked" from "nothing
/// told me when this changed".
#[test]
fn an_entry_reports_what_was_read_for_it() {
  use std::time::{Duration, SystemTime};

  use super::{EntryKind, Metadata};

  let file = Metadata::new(EntryKind::File, 11);
  assert_eq!(file.kind(), EntryKind::File);
  assert_eq!(file.len(), 11);
  assert!(!file.is_empty() && !file.is_dir());
  assert_eq!(
    file.modified(),
    None,
    "nothing read a time, so none is claimed"
  );

  let when = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
  assert_eq!(file.clone().with_modified(when).modified(), Some(when));

  let dir = Metadata::new(EntryKind::Dir, 0);
  assert!(dir.is_dir() && dir.is_empty());

  // A symlink is NOT a directory for the descend test, whatever it points at — following
  // one is how a walk leaves the root it was asked about.
  let link = Metadata::new(EntryKind::Symlink, 4);
  assert!(!link.is_dir() && link.kind().is_symlink());

  for (kind, name) in [
    (EntryKind::File, "file"),
    (EntryKind::Dir, "dir"),
    (EntryKind::Symlink, "symlink"),
    (EntryKind::Other, "other"),
  ] {
    assert_eq!(kind.as_str(), name);
    assert_eq!(kind.to_string(), name);
  }
  assert!(EntryKind::File.is_file() && !EntryKind::Dir.is_file());
  assert!(EntryKind::Dir.is_dir() && !EntryKind::Other.is_dir());
}
