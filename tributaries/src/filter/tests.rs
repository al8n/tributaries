use core::num::NonZeroU64;
use std::{ffi::OsString, path::Path};

use tributary_proto::{Epoch, Location, ScopeId};

use super::{Filter, FilterInput};
use crate::{
  event::{Event, EventKind},
  subscription::Subscription,
};

/// A subscription with the given non-zero id, under the fixed test instance brand.
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

/// Whether `f` admits a change of `kind` at `path`, built as the pre-delivery
/// [`FilterInput`] a filter actually inspects (key/kind/location — never an epoch or value, which
/// a filter cannot observe, design §7). A synthetic [`Event`] owns the borrowed parts; the filter
/// reads only its public pre-delivery accessors, so this stand-in exercises it without any real
/// source's private event constructor.
fn admits(f: &Filter<OsString>, path: &str, kind: EventKind<OsString>) -> bool {
  let ev: Event<OsString, ()> =
    Event::synthetic(sub(1), key(path), Location::new(), kind, Epoch::new(1));
  f.admits(&FilterInput::new(ev.key(), ev.kind(), ev.location()))
}

#[test]
fn all_admits_everything() {
  let f = Filter::all();
  assert!(admits(&f, "/a/f.rs", EventKind::Created));
  assert!(admits(&f, "/a/f.txt", EventKind::Removed));
  assert!(admits(&f, "/a", EventKind::Rescan));
}

#[test]
fn filter_excludes_non_matching() {
  // Admit only Rust sources — a filter reads the pre-delivery path/kind, not epoch/value.
  let f = Filter::new(|input| input.path().extension().is_some_and(|ext| ext == "rs"));
  assert!(
    admits(&f, "/a/lib.rs", EventKind::Modified),
    "a .rs is admitted"
  );
  assert!(
    !admits(&f, "/a/notes.txt", EventKind::Modified),
    "a non-matching path is excluded"
  );
}

#[test]
fn filter_gates_on_the_projected_kind() {
  // A filter observing `kind` sees the (already-projected) delivery kind (design §5/§7): here it
  // admits only removals, proving the kind reaches the predicate correctly.
  let f = Filter::new(|input: &FilterInput<'_, OsString>| input.kind().is_removed());
  assert!(
    admits(&f, "/a/gone", EventKind::Removed),
    "a Removed is admitted"
  );
  assert!(
    !admits(&f, "/a/new", EventKind::Created),
    "a Created is excluded by a removals-only filter"
  );
}

#[test]
fn admits_is_a_pure_predicate_not_a_rescan_special_case() {
  // `admits` does NOT special-case a Rescan — the unconditional bypass lives in `fan_out`, one
  // level up (design §7/§8). A predicate that rejects everything therefore rejects a Rescan too
  // when asked directly; the driver never asks.
  let reject_all = Filter::new(|_| false);
  assert!(
    !admits(&reject_all, "/a", EventKind::Rescan),
    "admits is pure: the Rescan bypass is enforced in fan_out, not here"
  );
}

#[test]
fn live_swap_takes_effect() {
  // Start admitting everything, prove it, then hot-swap to a stricter predicate and prove the
  // change is observed on the very next admission — no re-watch.
  let f = Filter::all();
  assert!(
    admits(&f, "/a/notes.txt", EventKind::Modified),
    "the initial filter admits the .txt"
  );

  f.swap(|input| input.path().extension().is_some_and(|ext| ext == "rs"));
  assert!(
    !admits(&f, "/a/notes.txt", EventKind::Modified),
    "after the swap the .txt is excluded — the new predicate is live"
  );
  assert!(
    admits(&f, "/a/lib.rs", EventKind::Modified),
    "…and the new predicate still admits a .rs"
  );
}

#[test]
fn a_clone_shares_the_swappable_slot() {
  // The driver holds one handle and the caller another; a swap through either must be seen by both
  // (that is the whole point of the shared slot).
  let held_by_driver = Filter::all();
  let held_by_caller = held_by_driver.clone();

  assert!(
    admits(&held_by_driver, "/a/notes.txt", EventKind::Modified),
    "both start admitting"
  );

  // The caller re-scopes their subscription live.
  held_by_caller.swap(|input| input.path().extension().is_some_and(|ext| ext == "rs"));

  assert!(
    !admits(&held_by_driver, "/a/notes.txt", EventKind::Modified),
    "the driver's handle observes the caller's swap (shared slot)"
  );
}
