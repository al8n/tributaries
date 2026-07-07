use core::num::NonZeroU64;
use std::{ffi::OsString, path::Path};

use tributary_fs::{Epoch, EventKind, Location};
use tributary_proto::ScopeId;

use super::Filter;
use crate::{event::Event, subscription::Subscription};

/// A subscription with the given non-zero id.
fn sub(id: u64) -> Subscription {
  Subscription::new(ScopeId::new(NonZeroU64::new(id).expect("nonzero id")))
}

/// A path's `OsString` components — the located-key form the fs source keys on.
fn key(path: &str) -> Vec<OsString> {
  Path::new(path)
    .components()
    .map(|c| c.as_os_str().to_os_string())
    .collect()
}

/// A synthetic event of `kind` at `path` for subscription 1, keyed on `OsString`
/// components (the fs `C`). A `Filter` reads only the public accessors of the concrete
/// [`Event`], so a synthetic stand-in exercises it without the private
/// `tributary_fs::Event` constructor.
fn ev(path: &str, kind: EventKind) -> Event<OsString, ()> {
  Event::synthetic(sub(1), key(path), Location::new(), kind, Epoch::new(1))
}

#[test]
fn all_admits_everything() {
  let f = Filter::all();
  assert!(f.admits(&ev("/a/f.rs", EventKind::Created)));
  assert!(f.admits(&ev("/a/f.txt", EventKind::Removed)));
  assert!(f.admits(&ev("/a", EventKind::Rescan)));
}

#[test]
fn filter_excludes_non_matching() {
  // Admit only Rust sources.
  let f = Filter::new(|e| e.path().extension().is_some_and(|ext| ext == "rs"));
  assert!(
    f.admits(&ev("/a/lib.rs", EventKind::Modified)),
    "a .rs is admitted"
  );
  assert!(
    !f.admits(&ev("/a/notes.txt", EventKind::Modified)),
    "a non-matching path is excluded"
  );
}

#[test]
fn admits_is_a_pure_predicate_not_a_rescan_special_case() {
  // `admits` does NOT special-case a Rescan — the unconditional bypass lives in
  // `fan_out`, one level up (design §7/§8). A predicate that rejects everything
  // therefore rejects a Rescan too when asked directly; the driver never asks.
  let reject_all = Filter::new(|_| false);
  assert!(
    !reject_all.admits(&ev("/a", EventKind::Rescan)),
    "admits is pure: the Rescan bypass is enforced in fan_out, not here"
  );
}

#[test]
fn live_swap_takes_effect() {
  // Start admitting everything, prove it, then hot-swap to a stricter predicate and
  // prove the change is observed on the very next admission — no re-watch.
  let f = Filter::all();
  let txt = ev("/a/notes.txt", EventKind::Modified);
  assert!(f.admits(&txt), "the initial filter admits the .txt");

  f.swap(|e| e.path().extension().is_some_and(|ext| ext == "rs"));
  assert!(
    !f.admits(&txt),
    "after the swap the .txt is excluded — the new predicate is live"
  );
  assert!(
    f.admits(&ev("/a/lib.rs", EventKind::Modified)),
    "…and the new predicate still admits a .rs"
  );
}

#[test]
fn a_clone_shares_the_swappable_slot() {
  // The driver holds one handle and the caller another; a swap through either must be
  // seen by both (that is the whole point of the shared slot).
  let held_by_driver = Filter::all();
  let held_by_caller = held_by_driver.clone();

  let txt = ev("/a/notes.txt", EventKind::Modified);
  assert!(held_by_driver.admits(&txt), "both start admitting");

  // The caller re-scopes their subscription live.
  held_by_caller.swap(|e| e.path().extension().is_some_and(|ext| ext == "rs"));

  assert!(
    !held_by_driver.admits(&txt),
    "the driver's handle observes the caller's swap (shared slot)"
  );
}
