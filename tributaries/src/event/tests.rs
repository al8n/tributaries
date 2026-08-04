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

/// A whole move has TWO affected endpoints. Asking about the source — the only key a
/// tracker of the moved-away object knows — must answer `true`, or that tracker is never
/// told its file left and stays silently stale forever.
#[test]
fn a_whole_move_reaches_its_source_endpoint() {
  let moved = ev(
    "/a/new",
    EventKind::Moved {
      from: key("/a/old"),
    },
  );
  assert!(
    moved.reaches(&key("/a/new")),
    "the destination is the event's own key"
  );
  assert!(
    moved.reaches(&key("/a/old")),
    "the move SOURCE is an affected endpoint: the object left that key"
  );
  assert!(
    !moved.reaches(&key("/a/unrelated")),
    "a key that is neither endpoint is not reached"
  );
}

/// The source endpoint is an EXACT-key fact, not a subtree one: a move of `/a/old` does
/// not oblige anything about `/a/old/child` (the whole subtree moved with it and is
/// reported under the destination), so the endpoint test must not start behaving like a
/// rescan.
#[test]
fn a_whole_move_does_not_reach_below_either_endpoint() {
  let moved = ev(
    "/a/new",
    EventKind::Moved {
      from: key("/a/old"),
    },
  );
  assert!(
    !moved.reaches(&key("/a/old/child")),
    "only a Rescan propagates downward; a move endpoint is exact"
  );
  assert!(
    !moved.reaches(&key("/a/new/child")),
    "the destination endpoint is exact too"
  );
}

/// The single-endpoint projections a move decomposes into carry no source key, so they
/// reach only the key they name — the property that keeps `reaches` honest for a
/// subscriber that saw only half the rename.
#[test]
fn a_move_projection_reaches_only_the_key_it_names() {
  let move_out = ev("/a/old", EventKind::Removed);
  assert!(move_out.reaches(&key("/a/old")));
  assert!(
    !move_out.reaches(&key("/a/new")),
    "a move-out projection knows nothing of the destination"
  );
  let move_in = ev("/a/new", EventKind::Created);
  assert!(move_in.reaches(&key("/a/new")));
  assert!(
    !move_in.reaches(&key("/a/old")),
    "a move-in projection knows nothing of the source"
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
