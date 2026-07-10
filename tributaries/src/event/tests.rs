use core::num::NonZeroU64;
use std::{ffi::OsString, path::Path};

use tributary_proto::{Epoch, Location, ScopeId};

use super::{Event, EventKind};
use crate::subscription::Subscription;

/// The delivered-event type these tests dispatch on: the fs `C = OsString`, `V = ()`.
type Ev = Event<OsString, ()>;

/// A subscription with the given non-zero id.
fn sub(id: u64) -> Subscription {
  Subscription::for_test(ScopeId::new(NonZeroU64::new(id).expect("nonzero id")))
}

/// A path's `OsString` components — the located-key form the fs source keys on.
fn key(path: &str) -> Vec<OsString> {
  Path::new(path)
    .components()
    .map(|c| c.as_os_str().to_os_string())
    .collect()
}

/// A synthetic event of `kind` at `path` — [`Event::reaches`] reads only the key and
/// the kind, so the epoch/location are inert fixtures.
fn ev(path: &str, kind: EventKind<OsString>) -> Ev {
  Event::synthetic(sub(1), key(path), Location::new(), kind, Epoch::new(1))
}

#[test]
fn reaches_the_exactly_named_key_for_any_kind() {
  let modified = ev("/a/b/file", EventKind::Modified);
  assert!(
    modified.reaches(&key("/a/b/file")),
    "an event reaches the key it names exactly, whatever its kind"
  );
  assert!(
    !modified.reaches(&key("/a/b/other")),
    "a sibling key is not reached"
  );
}

#[test]
fn rescan_at_an_ancestor_reaches_the_descendant_key() {
  let rescan = ev("/a/b", EventKind::Rescan);
  assert!(
    rescan.reaches(&key("/a/b/deep/file")),
    "a Rescan obliges re-enumeration of everything below its key"
  );
}

#[test]
fn rescan_at_the_key_itself_reaches_it() {
  let rescan = ev("/a/b", EventKind::Rescan);
  assert!(
    rescan.reaches(&key("/a/b")),
    "a Rescan at the key is both the exact match and its own ancestor"
  );
}

#[test]
fn non_rescan_at_an_ancestor_does_not_reach() {
  let removed = ev("/a/b", EventKind::Removed);
  assert!(
    !removed.reaches(&key("/a/b/deep/file")),
    "only a Rescan propagates down from an ancestor; an ordinary delta does not"
  );
}

#[test]
fn rescan_at_a_descendant_does_not_reach_the_ancestor_key() {
  let rescan = ev("/a/b/deep", EventKind::Rescan);
  assert!(
    !rescan.reaches(&key("/a/b")),
    "a Rescan re-enumerates below its key, never above it"
  );
}
