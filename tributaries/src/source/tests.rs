use super::Source;

/// Compile-time proof that the **two** async [`Source`] futures — [`arm`](Source::arm) and the event
/// pump [`next`](Source::next) — are `Send`, so the owner (which drives them inline in one `select!`
/// loop) can be spawned via [`R::spawn_detach`](agnostic_lite::RuntimeLite::spawn_detach) on a
/// multi-threaded tokio or smol executor. [`disarm`](Source::disarm) is synchronous (it returns no
/// future). Never invoked — it only has to type-check: a regression that dropped a `Send` bound would
/// stop `needs_send` from accepting that future and fail this build. The generic bound is the
/// guarantee, so this holds for every implementor (including an out-of-tree custom source), not just
/// [`FsSource`].
#[allow(dead_code)]
fn assert_source_futures_send<C, S: Source<C>>(s: &mut S, key: &[C], handle: S::Handle) {
  fn needs_send<F: Send>(_: F) {}
  needs_send(s.arm(key));
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
  use futures_util::FutureExt;

  use super::{Armed, LocalSource, SourceEvent};
  use crate::error::WatchError;

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
  }

  let mut probe = Probe::default();

  // Drive every item through the LocalSource seam (fully qualified, exactly as the
  // owner's generic `S: LocalSource` bound resolves them) and assert the implementor's
  // overrides answer.
  assert_eq!(
    LocalSource::canonicalize_key(&probe, &[1u8]).expect("canonicalize_key forwards"),
    vec![1u8],
  );
  let armed = LocalSource::arm(&mut probe, &[1u8])
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
