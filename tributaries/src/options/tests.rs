use std::ffi::OsString;

use super::{Debounce, DebounceConfig, WatchOptions};
use crate::{
  event::EventKind,
  filter::{Filter, FilterInput},
  interest::Interest,
};

use tributary_proto::Location;

#[test]
fn debounce_default_is_inherit() {
  assert_eq!(Debounce::default(), Debounce::Inherit);
  assert!(Debounce::default().is_inherit());
}

#[test]
fn debounce_predicates_match_their_variants() {
  let custom = Debounce::Custom(DebounceConfig::new());
  for (debounce, inherit, off, is_custom) in [
    (Debounce::Inherit, true, false, false),
    (Debounce::Off, false, true, false),
    (custom, false, false, true),
  ] {
    assert_eq!(debounce.is_inherit(), inherit, "{debounce:?}");
    assert_eq!(debounce.is_off(), off, "{debounce:?}");
    assert_eq!(debounce.is_custom(), is_custom, "{debounce:?}");
  }
}

#[test]
fn debounce_as_custom_projects_only_the_custom_payload() {
  let config = DebounceConfig::new().with_max_buffered(7);
  assert_eq!(Debounce::Custom(config).as_custom(), Some(&config));
  assert_eq!(Debounce::Inherit.as_custom(), None);
  assert_eq!(Debounce::Off.as_custom(), None);
}

#[test]
fn watch_options_new_is_the_deliver_everything_default() {
  let options: WatchOptions<OsString> = WatchOptions::new();
  assert!(options.interest().is_all(), "every kind delivered");
  assert!(options.debounce().is_inherit(), "watcher-global debounce");
  let (key, kind, location) = ([OsString::from("f")], EventKind::Created, Location::new());
  let input = FilterInput::new(&key, &kind, &location);
  assert!(options.filter().admits(&input), "every change admitted");
  // `Default` delegates to `new()`.
  let defaulted: WatchOptions<OsString> = WatchOptions::default();
  assert_eq!(defaulted.interest(), options.interest());
  assert_eq!(defaulted.debounce(), options.debounce());
}

#[test]
fn watch_options_builders_round_trip() {
  let narrowed = Interest::none().with_created();
  let mut options: WatchOptions<OsString> = WatchOptions::new()
    .with_interest(narrowed)
    .with_debounce(Debounce::Off)
    .with_filter(Filter::new(|_| false));
  assert_eq!(options.interest(), narrowed);
  assert!(options.debounce().is_off());
  let (key, kind, location) = ([OsString::from("f")], EventKind::Created, Location::new());
  let input = FilterInput::new(&key, &kind, &location);
  assert!(!options.filter().admits(&input), "the custom filter rides");

  let custom = Debounce::Custom(DebounceConfig::new());
  options
    .set_interest(Interest::all())
    .set_debounce(custom)
    .set_filter(Filter::all());
  assert!(options.interest().is_all());
  assert_eq!(options.debounce(), custom);
  assert!(options.filter().admits(&input));
}

/// Cloning shares the `Filter`'s swappable slot (the documented contract): a `swap`
/// through the clone is observed through the original.
#[test]
fn watch_options_clone_shares_the_filter_slot() {
  let original: WatchOptions<OsString> = WatchOptions::new().with_filter(Filter::new(|_| true));
  let cloned = original.clone();
  let (key, kind, location) = ([OsString::from("f")], EventKind::Created, Location::new());
  let input = FilterInput::new(&key, &kind, &location);
  assert!(original.filter().admits(&input));

  cloned.filter().swap(|_| false);
  assert!(
    !original.filter().admits(&input),
    "a swap through the clone re-scopes the original — one shared slot"
  );
}
