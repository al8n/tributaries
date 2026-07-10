use super::{FaultKind, SourceFault, WatchError};

/// The fs-off smoke check: with the `fs` feature disabled the neutral error surface
/// stays fully constructible and matchable — a custom source classifies into
/// [`SourceFault`], the concrete error round-trips through the box, and the native
/// lifecycle variants (here [`WatchError::Closed`]) pattern-match with no fs type in
/// sight. This module compiles only under `not(feature = "fs")`, so the default
/// (fs-on) build cannot mask a neutral-surface regression that bit-rots the fs-off
/// path.
#[test]
fn neutral_error_surface_stands_alone_without_fs() {
  let fault = SourceFault::new(FaultKind::NotFound)
    .with_source(std::io::Error::from(std::io::ErrorKind::NotFound));
  assert!(fault.kind().is_not_found());
  assert!(
    fault.downcast_ref::<std::io::Error>().is_some(),
    "the concrete source error survives in the box"
  );

  let err = WatchError::source(fault);
  assert!(err.is_source());
  let carried = err.fault().expect("a Source error carries its fault");
  assert!(carried.kind().is_not_found());

  assert!(
    matches!(WatchError::Closed, WatchError::Closed),
    "the native lifecycle variant matches directly"
  );
  assert!(WatchError::Closed.is_closed());
  assert!(WatchError::Closed.fault().is_none());
}
