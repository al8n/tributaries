use core::num::NonZeroUsize;
use std::ffi::OsString;

use super::{Debounce, DebounceConfig, RootGlobs, TributariesOptions, WatchOptions};
use crate::{
  event::EventKind,
  filter::{Filter, FilterInput},
  interest::Interest,
};

use tributary_proto::{Location, glob::Glob};

/// One validated pattern — the vocabulary is `tributary-proto`'s, so a cell here only
/// has to be able to name one.
fn glob(pattern: &str) -> Glob {
  pattern.parse().expect("a valid pattern compiles")
}

/// The patterns a seat carries, as their source text — what a cell can compare against a
/// literal list.
fn texts(patterns: &[Glob]) -> Vec<&str> {
  patterns.iter().map(Glob::as_str).collect()
}

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

/// Both capacities are bounded, and the CEILINGS THEMSELVES are inside the bound: a
/// household set to either maximum validates, while a capacity no allocator could serve
/// is a typed refusal rather than an allocation-size panic inside the channel.
#[test]
fn the_capacities_are_bounded_and_their_maxima_are_in_range() {
  let at_ceiling = TributariesOptions::new()
    .with_event_capacity(TributariesOptions::MAX_EVENT_CAPACITY)
    .with_command_capacity(TributariesOptions::MAX_COMMAND_CAPACITY);
  assert!(
    at_ceiling.validate().is_ok(),
    "a documented maximum is a value the household can hold, not one it stops short of"
  );
  assert!(TributariesOptions::new().validate().is_ok());

  let err = TributariesOptions::new()
    .with_event_capacity(NonZeroUsize::MAX)
    .validate()
    .expect_err("an event channel nothing could allocate is refused");
  assert!(err.is_event_capacity_too_large(), "got {err:?}");
  assert!(!err.is_command_capacity_too_large());

  let err = TributariesOptions::new()
    .with_command_capacity(NonZeroUsize::MAX)
    .validate()
    .expect_err("a mailbox nothing could allocate is refused");
  assert!(err.is_command_capacity_too_large(), "got {err:?}");

  // One past each ceiling: the bound is the documented value itself.
  for (options, over) in [
    (
      TributariesOptions::new().with_event_capacity(
        TributariesOptions::MAX_EVENT_CAPACITY
          .checked_add(1)
          .expect("one past the ceiling is representable"),
      ),
      "event",
    ),
    (
      TributariesOptions::new().with_command_capacity(
        TributariesOptions::MAX_COMMAND_CAPACITY
          .checked_add(1)
          .expect("one past the ceiling is representable"),
      ),
      "command",
    ),
  ] {
    assert!(
      options.validate().is_err(),
      "{over} capacity, one past its ceiling"
    );
  }
}

/// The coalescer's buffered-entry cap is bounded, and BOTH households that can
/// carry a policy refuse an unbounded one: the watcher-global default, and a
/// subscription's own [`Debounce::Custom`] override. The cap is the structural
/// memory bound in front of the bounded event channel, so a value no burst can
/// reach does not describe a large settle buffer — it removes the bound, and the
/// overflow-to-`Rescan` shedding that answers a full buffer never engages.
///
/// The ceiling itself is in range, like every other maximum here.
///
/// Revert witness: drop the `check_max_buffered` call from either `validate` and
/// a `usize::MAX` cap sails through the one door every constructor goes past.
#[test]
fn the_buffered_cap_is_bounded_on_every_household_and_its_maximum_is_in_range() {
  let at_ceiling = DebounceConfig::new().with_max_buffered(DebounceConfig::MAX_BUFFERED_ENTRIES);
  assert!(
    TributariesOptions::new()
      .debounce(at_ceiling)
      .validate()
      .is_ok(),
    "the documented maximum is a value the household can hold"
  );
  assert!(
    WatchOptions::<OsString>::new()
      .with_debounce(Debounce::Custom(at_ceiling))
      .validate()
      .is_ok()
  );

  let unbounded = DebounceConfig::new().with_max_buffered(usize::MAX);
  let err = TributariesOptions::new()
    .debounce(unbounded)
    .validate()
    .expect_err("a settle buffer nothing bounds is refused");
  assert!(err.is_max_buffered_too_large(), "got {err:?}");
  assert!(!err.is_event_capacity_too_large());

  let err = WatchOptions::<OsString>::new()
    .with_debounce(Debounce::Custom(unbounded))
    .validate()
    .expect_err("a per-subscription override is judged by the same number");
  assert!(err.is_max_buffered_too_large(), "got {err:?}");

  // One past the ceiling: the bound is the documented value itself.
  assert!(
    TributariesOptions::new()
      .debounce(DebounceConfig::new().with_max_buffered(DebounceConfig::MAX_BUFFERED_ENTRIES + 1))
      .validate()
      .is_err()
  );

  // A household with no policy at all has no cap to judge.
  assert!(TributariesOptions::new().validate().is_ok());
  assert!(WatchOptions::<OsString>::new().validate().is_ok());
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

  // Both glob seats start unengaged, which is what asks a source for exactly the
  // coverage and delivery it had before the seats existed.
  assert!(options.prune().is_empty(), "nothing pruned");
  assert!(
    options.include().is_none(),
    "the ABSENT seat, not an empty list"
  );
  assert_eq!(options.root_globs(), RootGlobs::new());
  assert!(options.root_globs().is_unengaged());
}

/// The unengaged [`RootGlobs`] is the words every source had before the seats existed,
/// and each seat is set, replaced and cleared independently of the other.
#[test]
fn root_globs_default_is_unengaged_and_each_seat_moves_alone() {
  let unengaged = RootGlobs::new();
  assert_eq!(unengaged, RootGlobs::default());
  assert!(unengaged.is_unengaged());
  assert!(unengaged.prune().is_empty());
  assert!(unengaged.include().is_none());

  let pruned = RootGlobs::new().with_prune([glob("**/node_modules"), glob("**/.git")]);
  assert_eq!(texts(pruned.prune()), ["**/node_modules", "**/.git"]);
  assert!(pruned.include().is_none(), "the other seat is untouched");
  assert!(!pruned.is_unengaged());

  let narrowed = pruned.clone().with_include([glob("**/*.mp4")]);
  assert_eq!(texts(narrowed.prune()), ["**/node_modules", "**/.git"]);
  assert_eq!(
    narrowed.include().map(texts),
    Some(std::vec!["**/*.mp4"]),
    "the include seat is engaged"
  );

  // An EMPTY include list is the engaged seat admitting no file — not the absent one.
  let none_admitted = RootGlobs::new().with_include([]);
  assert_eq!(none_admitted.include(), Some(&[][..]));
  assert!(!none_admitted.is_unengaged());
  assert!(
    none_admitted.clone().without_include().include().is_none(),
    "clearing gives the ABSENT seat back"
  );

  let mut mutated = RootGlobs::new();
  mutated
    .set_prune([glob("**/target")])
    .set_include([glob("**/*.mov")]);
  assert_eq!(texts(mutated.prune()), ["**/target"]);
  assert_eq!(mutated.include().map(texts), Some(std::vec!["**/*.mov"]));
  mutated.clear_include();
  assert!(mutated.include().is_none());
  assert_eq!(texts(mutated.prune()), ["**/target"], "prune is untouched");
}

/// The two seats round-trip through both builder forms, and
/// [`root_globs`](WatchOptions::root_globs) extracts exactly what they hold — the words
/// the driver hands `Source::arm`.
#[test]
fn watch_options_glob_seats_round_trip() {
  let mut options: WatchOptions<OsString> = WatchOptions::new()
    .with_prune([glob("**/node_modules"), glob("**/.git")])
    .with_include([glob("**/*.{mp4,mov}")]);
  assert_eq!(texts(options.prune()), ["**/node_modules", "**/.git"]);
  assert_eq!(
    options.include().map(texts),
    Some(std::vec!["**/*.{mp4,mov}"])
  );
  assert_eq!(
    options.root_globs(),
    RootGlobs::new()
      .with_prune([glob("**/node_modules"), glob("**/.git")])
      .with_include([glob("**/*.{mp4,mov}")]),
    "the extracted words are the seats verbatim"
  );

  // A clone carries them, like every other knob (the filter slot aside).
  let cloned = options.clone();
  assert_eq!(texts(cloned.prune()), texts(options.prune()));
  assert_eq!(cloned.include().map(texts), options.include().map(texts));

  options.set_prune([glob("**/Caches")]).set_include([]);
  assert_eq!(texts(options.prune()), ["**/Caches"]);
  assert_eq!(
    options.include(),
    Some(&[][..]),
    "an empty list is the engaged seat"
  );

  options.clear_include();
  assert!(options.include().is_none());
  let widened = options.clone().without_include();
  assert!(widened.include().is_none());
  assert_eq!(
    texts(widened.prune()),
    ["**/Caches"],
    "clearing one seat leaves the other"
  );
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

/// The `serde` face on the umbrella's own option households.
#[cfg(feature = "serde")]
mod serde_face {
  use core::{num::NonZeroUsize, time::Duration};

  use super::{
    super::{Debounce, DebounceConfig, RootGlobs, TributariesOptions, WatchOptions},
    glob, texts,
  };
  use crate::{
    event::EventKind,
    filter::{Filter, FilterInput},
    interest::Interest,
  };
  use std::ffi::OsString;
  use tributary_proto::Location;

  #[test]
  fn every_household_round_trips_its_default() {
    let json = serde_json::to_string(&DebounceConfig::new()).unwrap();
    assert_eq!(
      serde_json::from_str::<DebounceConfig>(&json).unwrap(),
      DebounceConfig::new()
    );
    let json = serde_json::to_string(&TributariesOptions::new()).unwrap();
    assert_eq!(
      serde_json::from_str::<TributariesOptions>(&json).unwrap(),
      TributariesOptions::new()
    );
    let options: WatchOptions<OsString> = WatchOptions::new();
    let json = serde_json::to_string(&options).unwrap();
    let parsed: WatchOptions<OsString> = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.interest(), options.interest());
    assert_eq!(parsed.debounce(), options.debounce());
  }

  /// A document naming ONE key leaves every other knob at the value `new()` gives it.
  #[test]
  fn a_partial_document_defaults_every_absent_key() {
    let parsed: DebounceConfig = serde_json::from_str(r#"{"quiet_window": "250ms"}"#).unwrap();
    assert_eq!(
      parsed,
      DebounceConfig::new().with_quiet_window(Duration::from_millis(250))
    );

    let parsed: TributariesOptions = serde_json::from_str(r#"{"event_capacity": 4096}"#).unwrap();
    assert_eq!(
      parsed,
      TributariesOptions::new().with_event_capacity(NonZeroUsize::new(4096).unwrap())
    );
    assert_eq!(
      parsed.debounce_config(),
      None,
      "the coalescer stays opt-in: an absent key is not an enabled one"
    );

    let parsed: WatchOptions<OsString> = serde_json::from_str(r#"{"debounce": "off"}"#).unwrap();
    assert!(parsed.debounce().is_off());
    assert!(
      parsed.interest().is_all(),
      "an absent interest is the deliver-everything default, not the empty gate"
    );
  }

  /// Forward compatibility: no `deny_unknown_fields` on any household.
  #[test]
  fn an_unknown_key_is_accepted() {
    let parsed: DebounceConfig = serde_json::from_str(r#"{"some_future_knob": 7}"#).unwrap();
    assert_eq!(parsed, DebounceConfig::new());
    let parsed: TributariesOptions = serde_json::from_str(r#"{"some_future_knob": 7}"#).unwrap();
    assert_eq!(parsed, TributariesOptions::new());
    let parsed: WatchOptions<OsString> =
      serde_json::from_str(r#"{"some_future_knob": 7}"#).unwrap();
    assert!(parsed.interest().is_all());
  }

  /// The capacities are non-zero TYPES, so a zero is refused by the format.
  #[test]
  fn a_zero_capacity_is_refused() {
    for document in [r#"{"event_capacity": 0}"#, r#"{"command_capacity": 0}"#] {
      assert!(
        serde_json::from_str::<TributariesOptions>(document).is_err(),
        "{document}"
      );
    }
  }

  /// A capacity past its ceiling is refused where the DOCUMENT is read, with the same
  /// verdict `validate` gives the builders — the channel is allocated eagerly, so a
  /// number a document can write but no allocator can serve must die at the key.
  #[test]
  fn an_out_of_range_capacity_is_a_document_error() {
    for document in [
      std::format!(r#"{{"event_capacity": {}}}"#, usize::MAX),
      std::format!(r#"{{"command_capacity": {}}}"#, usize::MAX),
    ] {
      assert!(
        serde_json::from_str::<TributariesOptions>(&document).is_err(),
        "{document}"
      );
    }

    // The ceilings themselves load.
    let document = std::format!(
      r#"{{"event_capacity": {}, "command_capacity": {}}}"#,
      TributariesOptions::MAX_EVENT_CAPACITY,
      TributariesOptions::MAX_COMMAND_CAPACITY
    );
    let parsed: TributariesOptions = serde_json::from_str(&document).unwrap();
    assert_eq!(
      parsed.event_capacity(),
      TributariesOptions::MAX_EVENT_CAPACITY
    );
    assert_eq!(
      parsed.command_capacity(),
      TributariesOptions::MAX_COMMAND_CAPACITY
    );
  }

  /// The per-root words a custom source is armed with carry the same document shape the
  /// subscription's own seats do: two lists of plain strings, an ABSENT `include` being
  /// the absent seat rather than an empty one.
  #[test]
  fn the_root_words_round_trip_as_lists_of_plain_strings() {
    let words = RootGlobs::new()
      .with_prune([glob("**/node_modules"), glob("**/.git")])
      .with_include([glob("*.mp4")]);
    let json = serde_json::to_string(&words).unwrap();
    assert_eq!(
      json,
      r#"{"prune":["**/node_modules","**/.git"],"include":["*.mp4"]}"#
    );
    assert_eq!(serde_json::from_str::<RootGlobs>(&json).unwrap(), words);

    let bare: RootGlobs = serde_json::from_str("{}").unwrap();
    assert!(
      bare.is_unengaged(),
      "an empty document is the unengaged household"
    );
    let empty: RootGlobs = serde_json::from_str(r#"{"include": []}"#).unwrap();
    assert_eq!(
      empty.include().map(texts),
      Some(std::vec![]),
      "an EMPTY include is a seat admitting no file, not the absent seat"
    );
    assert!(
      serde_json::from_str::<RootGlobs>(r#"{"prune": ["[unclosed"]}"#).is_err(),
      "an uncompilable pattern is a document error"
    );
  }

  /// The same clamp the builders apply: `0` buffered entries is a buffer nothing can
  /// be admitted to, and every door reads it as `1`.
  #[test]
  fn a_zero_buffered_cap_is_clamped_exactly_as_the_builder_clamps_it() {
    let parsed: DebounceConfig = serde_json::from_str(r#"{"max_buffered": 0}"#).unwrap();
    assert_eq!(parsed.max_buffered(), 1);
    assert_eq!(parsed, DebounceConfig::new().with_max_buffered(0));
  }

  /// And the other end of the same rule: a cap past the ceiling dies at the KEY,
  /// with the verdict `validate` gives the builders. A document is exactly where an
  /// unbounded settle buffer would otherwise be written — the number is a plain
  /// integer, and nothing downstream of the key ever looks at it again until the
  /// coalescer is already growing.
  #[test]
  fn an_out_of_range_buffered_cap_is_a_document_error() {
    let document = std::format!(r#"{{"max_buffered": {}}}"#, usize::MAX);
    assert!(serde_json::from_str::<DebounceConfig>(&document).is_err());
    // Through the households that nest the policy, too.
    let global = std::format!(r#"{{"debounce": {{"max_buffered": {}}}}}"#, usize::MAX);
    assert!(serde_json::from_str::<TributariesOptions>(&global).is_err());
    let custom = std::format!(
      r#"{{"debounce": {{"custom": {{"max_buffered": {}}}}}}}"#,
      usize::MAX
    );
    assert!(serde_json::from_str::<WatchOptions<OsString>>(&custom).is_err());

    // The ceiling itself loads.
    let document = std::format!(
      r#"{{"max_buffered": {}}}"#,
      DebounceConfig::MAX_BUFFERED_ENTRIES
    );
    let parsed: DebounceConfig = serde_json::from_str(&document).unwrap();
    assert_eq!(parsed.max_buffered(), DebounceConfig::MAX_BUFFERED_ENTRIES);
  }

  /// Durations are humantime TEXT in both directions.
  #[test]
  fn durations_are_humantime_text() {
    let json = serde_json::to_value(DebounceConfig::new()).unwrap();
    assert_eq!(json["quiet_window"], serde_json::json!("50ms"));
    assert_eq!(json["max_hold"], serde_json::json!("500ms"));

    let parsed: DebounceConfig =
      serde_json::from_str(r#"{"quiet_window": "250ms", "max_hold": "2s"}"#).unwrap();
    assert_eq!(parsed.quiet_window(), Duration::from_millis(250));
    assert_eq!(parsed.max_hold(), Duration::from_secs(2));
  }

  /// The three-way posture keeps all three states across the wire.
  #[test]
  fn every_debounce_posture_spells_itself() {
    assert_eq!(
      serde_json::to_value(Debounce::Inherit).unwrap(),
      serde_json::json!("inherit")
    );
    assert_eq!(
      serde_json::to_value(Debounce::Off).unwrap(),
      serde_json::json!("off")
    );
    for posture in [
      Debounce::Inherit,
      Debounce::Off,
      Debounce::Custom(DebounceConfig::new().with_max_buffered(7)),
    ] {
      let json = serde_json::to_string(&posture).unwrap();
      assert_eq!(
        serde_json::from_str::<Debounce>(&json).unwrap(),
        posture,
        "{posture:?}"
      );
    }
    let parsed: Debounce = serde_json::from_str(r#"{"custom": {}}"#).unwrap();
    assert_eq!(parsed, Debounce::Custom(DebounceConfig::new()));
  }

  /// The watcher-global debounce is an opt-in `Option`: absent and `null` are off, an
  /// object turns the coalescer on.
  #[test]
  fn the_global_debounce_keeps_absent_null_and_configured_apart() {
    let absent: TributariesOptions = serde_json::from_str("{}").unwrap();
    assert_eq!(absent.debounce_config(), None);
    let null: TributariesOptions = serde_json::from_str(r#"{"debounce": null}"#).unwrap();
    assert_eq!(null.debounce_config(), None);
    let configured: TributariesOptions =
      serde_json::from_str(r#"{"debounce": {"quiet_window": "250ms"}}"#).unwrap();
    assert_eq!(
      configured.debounce_config(),
      Some(DebounceConfig::new().with_quiet_window(Duration::from_millis(250)))
    );
  }

  /// The filter is on neither face: skipped on the way out, accept-all on the way
  /// back — a caller's closure is not something a document can name.
  #[test]
  fn the_filter_is_skipped_and_comes_back_accept_all() {
    let options: WatchOptions<OsString> = WatchOptions::new().with_filter(Filter::new(|_| false));
    let json = serde_json::to_value(&options).unwrap();
    assert_eq!(json.get("filter"), None, "the closure is not on the wire");

    let parsed: WatchOptions<OsString> = serde_json::from_value(json).unwrap();
    let (key, kind, location) = ([OsString::from("f")], EventKind::Created, Location::new());
    let input = FilterInput::new(&key, &kind, &location);
    assert!(
      parsed.filter().admits(&input),
      "a loaded subscription admits everything its interest admits"
    );
  }

  /// The two glob seats are lists of plain strings, both ways.
  #[test]
  fn the_glob_seats_are_lists_of_plain_strings() {
    let options: WatchOptions<OsString> = WatchOptions::new()
      .with_prune([glob("**/node_modules"), glob("**/.git")])
      .with_include([glob("**/*.mp4")]);
    let json = serde_json::to_value(&options).unwrap();
    assert_eq!(
      json["prune"],
      serde_json::json!(["**/node_modules", "**/.git"])
    );
    assert_eq!(json["include"], serde_json::json!(["**/*.mp4"]));

    let parsed: WatchOptions<OsString> = serde_json::from_value(json).unwrap();
    assert_eq!(texts(parsed.prune()), texts(options.prune()));
    assert_eq!(parsed.include().map(texts), options.include().map(texts));
  }

  /// "One root, one set of words" is a REFUSAL, not a knob: it added nothing a document can
  /// state. The subscription's face is exactly the four keys it always had — the rule lives in
  /// the planner and surfaces as `WatchError::RootWordsConflict`, so a document written for the
  /// previous version still means precisely what it meant.
  #[test]
  fn the_per_root_words_rule_added_no_key_to_the_document() {
    let json = serde_json::to_value(WatchOptions::<OsString>::new()).unwrap();
    let mut keys: Vec<&str> = json
      .as_object()
      .expect("the subscription is one object")
      .keys()
      .map(String::as_str)
      .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["debounce", "include", "interest", "prune"]);
  }

  /// A document naming NEITHER seat leaves both at the default — the absent `include` is
  /// the ABSENT seat (every file), which is what an empty list is not.
  #[test]
  fn a_document_naming_neither_seat_leaves_both_defaulted() {
    let parsed: WatchOptions<OsString> = serde_json::from_str(r#"{"debounce": "off"}"#).unwrap();
    assert!(parsed.debounce().is_off(), "the key it DID name landed");
    assert!(parsed.prune().is_empty());
    assert!(parsed.include().is_none());

    let engaged: WatchOptions<OsString> = serde_json::from_str(r#"{"include": []}"#).unwrap();
    assert_eq!(
      engaged.include(),
      Some(&[][..]),
      "an empty list is the engaged seat, not the absent one"
    );
  }

  /// An uncompilable pattern is refused by the DOCUMENT, so a seat never carries a value
  /// that would silently match nothing at every later delivery.
  #[test]
  fn an_invalid_pattern_is_a_document_error() {
    for document in [
      r#"{"prune": ["[unclosed"]}"#,
      r#"{"include": ["[unclosed"]}"#,
    ] {
      let err = serde_json::from_str::<WatchOptions<OsString>>(document).unwrap_err();
      assert!(
        err.to_string().contains("invalid glob"),
        "{document}: {err}"
      );
    }
  }

  /// A seat past the ceiling is a DOCUMENT error, on BOTH households that carry
  /// the words — and refused mid-list rather than collected whole and measured
  /// afterwards.
  ///
  /// The bound is a resource bound, so a face that reads an untrusted length to
  /// the end before judging it has already paid what the bound exists to refuse:
  /// every pattern in the list compiles on the way in. The element that would take
  /// the seat past the ceiling is where the read stops.
  ///
  /// Revert witness: derive the four fields plainly and a 257-entry document
  /// parses into a household `validate` — and `watch` — then have to catch, after
  /// compiling every one of them.
  #[test]
  fn a_document_past_the_pattern_ceiling_is_refused() {
    let cap = RootGlobs::MAX_SEAT_PATTERNS;
    let list = |count: usize| {
      (0..count)
        .map(|n| std::format!("\"**/w{n}\""))
        .collect::<Vec<_>>()
        .join(",")
    };
    let names_the_ceiling = |err: serde_json::Error| {
      assert!(
        err.to_string().contains(&std::format!("{cap}")),
        "the refusal names the ceiling: {err}"
      );
    };

    // The ceiling itself is honoured, on both seats of both households.
    let full: RootGlobs =
      serde_json::from_str(&std::format!(r#"{{"prune": [{}]}}"#, list(cap))).expect("at the cap");
    assert_eq!(full.prune().len(), cap);
    let full: WatchOptions<OsString> =
      serde_json::from_str(&std::format!(r#"{{"include": [{}]}}"#, list(cap))).expect("at the cap");
    assert_eq!(full.include().map(|seat| seat.len()), Some(cap));

    for seat in ["prune", "include"] {
      let document = std::format!(r#"{{"{seat}": [{}]}}"#, list(cap + 1));
      names_the_ceiling(
        serde_json::from_str::<RootGlobs>(&document).expect_err("one past the cap is refused"),
      );
      names_the_ceiling(
        serde_json::from_str::<WatchOptions<OsString>>(&document)
          .expect_err("the subscription household carries the same ceiling"),
      );
    }

    // The include seat's other two shapes are untouched: absent is the absent
    // seat, and an explicit empty list is the engaged one that admits nothing.
    assert_eq!(
      serde_json::from_str::<RootGlobs>(r#"{}"#)
        .expect("an empty document parses")
        .include(),
      None
    );
    assert_eq!(
      serde_json::from_str::<RootGlobs>(r#"{"include": []}"#)
        .expect("an empty seat parses")
        .include(),
      Some(&[][..])
    );
    assert_eq!(
      serde_json::from_str::<RootGlobs>(r#"{"include": null}"#)
        .expect("an explicit null parses")
        .include(),
      None
    );
  }

  /// Neither face constrains `C`: the only field mentioning it is skipped.
  #[test]
  fn neither_face_constrains_the_component_parameter() {
    struct NotSerde;

    let options: WatchOptions<NotSerde> = WatchOptions::new()
      .with_interest(Interest::none())
      .with_prune([glob("**/node_modules")])
      .with_include([glob("**/*.mp4")]);
    let json = serde_json::to_string(&options).unwrap();
    let parsed: WatchOptions<NotSerde> = serde_json::from_str(&json).unwrap();
    assert!(parsed.interest().is_none());
    assert_eq!(texts(parsed.prune()), ["**/node_modules"]);
    assert_eq!(parsed.include().map(texts), Some(std::vec!["**/*.mp4"]));
  }
}

/// The `clap` face on the umbrella's own option households.
#[cfg(feature = "clap")]
mod clap_face {
  use core::{num::NonZeroUsize, time::Duration};

  use super::{
    super::{DebounceConfig, RootGlobs, TributariesOptions, WatchOptions},
    glob, texts,
  };
  use crate::{
    event::EventKind,
    filter::{Filter, FilterInput},
    interest::Interest,
  };
  use clap::{CommandFactory as _, FromArgMatches as _, Parser as _};
  use std::ffi::OsString;
  use tributary_proto::Location;

  /// One non-zero capacity — a cell only has to be able to name one.
  fn nonzero(capacity: usize) -> NonZeroUsize {
    NonZeroUsize::new(capacity).expect("a non-zero capacity")
  }

  #[derive(clap::Parser)]
  struct DebounceCli {
    #[command(flatten)]
    config: DebounceConfig,
  }

  #[derive(clap::Parser)]
  struct WatcherCli {
    #[command(flatten)]
    options: TributariesOptions,
  }

  #[derive(clap::Parser)]
  struct WatchCli {
    #[command(flatten)]
    options: WatchOptions<OsString>,
  }

  #[derive(clap::Parser)]
  struct GlobsCli {
    #[command(flatten)]
    globs: RootGlobs,
  }

  fn args<'a>(rest: &'a [&'a str]) -> impl Iterator<Item = &'a str> {
    std::iter::once("app").chain(rest.iter().copied())
  }

  /// The `ArgMatches` an UPDATE reads: one household's own group, augmented the way
  /// clap augments a command for update, parsed from `rest`.
  fn update_matches<A: clap::Args>(rest: &[&str]) -> clap::ArgMatches {
    A::augment_args_for_update(clap::Command::new("app")).get_matches_from(args(rest))
  }

  #[test]
  fn no_flags_is_the_default_household() {
    assert_eq!(
      DebounceCli::parse_from(args(&[])).config,
      DebounceConfig::new()
    );
    assert_eq!(
      WatcherCli::parse_from(args(&[])).options,
      TributariesOptions::new()
    );
    let watch = WatchCli::parse_from(args(&[])).options;
    assert!(watch.interest().is_all());
    assert!(watch.debounce().is_inherit());
  }

  /// Each long flag sets EXACTLY its own knob.
  #[test]
  fn every_flag_sets_exactly_its_own_knob() {
    /// One flag (with its value) and the knob it is expected to set.
    type DebounceCase = (
      &'static [&'static str],
      fn(DebounceConfig) -> DebounceConfig,
    );
    type WatcherCase = (
      &'static [&'static str],
      fn(TributariesOptions) -> TributariesOptions,
    );

    let debounce: [DebounceCase; 3] = [
      (&["--quiet-window", "250ms"], |c| {
        c.with_quiet_window(Duration::from_millis(250))
      }),
      (&["--max-hold", "2s"], |c| {
        c.with_max_hold(Duration::from_secs(2))
      }),
      (&["--max-buffered", "4096"], |c| c.with_max_buffered(4096)),
    ];
    for (flags, expected) in debounce {
      assert_eq!(
        DebounceCli::parse_from(args(flags)).config,
        expected(DebounceConfig::new()),
        "{flags:?}"
      );
    }

    let watcher: [WatcherCase; 2] = [
      (&["--event-capacity", "4096"], |o| {
        o.with_event_capacity(NonZeroUsize::new(4096).unwrap())
      }),
      (&["--command-capacity", "8"], |o| {
        o.with_command_capacity(NonZeroUsize::new(8).unwrap())
      }),
    ];
    for (flags, expected) in watcher {
      assert_eq!(
        WatcherCli::parse_from(args(flags)).options,
        expected(TributariesOptions::new()),
        "{flags:?}"
      );
    }
  }

  /// The coalescer is opt-in on the command line exactly as it is in a document: it
  /// stays off until one of the flattened debounce flags is actually given.
  #[test]
  fn the_global_debounce_turns_on_only_when_one_of_its_flags_is_given() {
    assert_eq!(
      WatcherCli::parse_from(args(&["--event-capacity", "4096"]))
        .options
        .debounce_config(),
      None,
      "a capacity flag is not a request for settling"
    );
    assert_eq!(
      WatcherCli::parse_from(args(&["--quiet-window", "250ms"]))
        .options
        .debounce_config(),
      Some(DebounceConfig::new().with_quiet_window(Duration::from_millis(250))),
      "one debounce flag turns it on, with every other knob at its default"
    );
  }

  /// The same clamp the builders apply, at the flag.
  #[test]
  fn a_zero_buffered_cap_is_clamped_exactly_as_the_builder_clamps_it() {
    assert_eq!(
      DebounceCli::parse_from(args(&["--max-buffered", "0"]))
        .config
        .max_buffered(),
      1
    );
  }

  /// And the ceiling, at the same flag: a cap past it is refused where the number
  /// is written rather than at the settle buffer it would grow without bound.
  #[test]
  fn an_out_of_range_buffered_cap_flag_is_refused() {
    let err = DebounceCli::try_parse_from(args(&["--max-buffered", "18446744073709551615"]))
      .err()
      .expect("a cap above its ceiling is refused");
    assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);

    // The ceiling itself parses.
    assert_eq!(
      DebounceCli::parse_from(args(&[
        "--max-buffered",
        &DebounceConfig::MAX_BUFFERED_ENTRIES.to_string(),
      ]))
      .config
      .max_buffered(),
      DebounceConfig::MAX_BUFFERED_ENTRIES
    );
  }

  #[test]
  fn a_zero_capacity_flag_is_refused() {
    for flags in [["--event-capacity", "0"], ["--command-capacity", "0"]] {
      assert!(
        WatcherCli::try_parse_from(args(&flags)).is_err(),
        "{flags:?}"
      );
    }
  }

  /// A capacity past its ceiling is refused at the FLAG, where the number is written,
  /// rather than at the channel it could never open.
  #[test]
  fn an_out_of_range_capacity_flag_is_refused() {
    for flags in [
      ["--event-capacity", "18446744073709551615"],
      ["--command-capacity", "18446744073709551615"],
    ] {
      let err = WatcherCli::try_parse_from(args(&flags))
        .err()
        .unwrap_or_else(|| std::panic!("{flags:?} is above its ceiling"));
      assert_eq!(
        err.kind(),
        clap::error::ErrorKind::ValueValidation,
        "{flags:?}"
      );
    }

    // The ceilings themselves parse.
    let options = WatcherCli::parse_from(args(&[
      "--event-capacity",
      &TributariesOptions::MAX_EVENT_CAPACITY.to_string(),
      "--command-capacity",
      &TributariesOptions::MAX_COMMAND_CAPACITY.to_string(),
    ]))
    .options;
    assert_eq!(
      options.event_capacity(),
      TributariesOptions::MAX_EVENT_CAPACITY
    );
    assert_eq!(
      options.command_capacity(),
      TributariesOptions::MAX_COMMAND_CAPACITY
    );
  }

  /// The per-root words a custom source is armed with flatten onto a command of their
  /// own, with the very flags a subscription spells them with.
  #[test]
  fn the_root_words_flatten_onto_a_command() {
    GlobsCli::command().debug_assert();

    let globs = GlobsCli::parse_from(args(&[
      "--prune",
      "**/node_modules",
      "--prune",
      "**/.git",
      "--include",
      "*.mp4",
    ]))
    .globs;
    assert_eq!(texts(globs.prune()), ["**/node_modules", "**/.git"]);
    assert_eq!(globs.include().map(texts), Some(std::vec!["*.mp4"]));

    let bare = GlobsCli::parse_from(args(&[])).globs;
    assert!(
      bare.is_unengaged(),
      "no flag at all is the unengaged household — an absent include is no seat"
    );

    let err = GlobsCli::try_parse_from(args(&["--prune", "[unclosed"]))
      .err()
      .expect("an uncompilable pattern is refused at the flag");
    assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
  }

  /// A seat past its ceiling is refused at the FLAG, on BOTH households that carry
  /// the shared flags, and refused WITHOUT compiling the patterns it carries.
  ///
  /// The count is a property of the list, not of any pattern in it, so it can be
  /// answered before a single automaton exists — and it has to be, because a
  /// `parse_from` takes an arbitrarily long iterator and every value compiled on the
  /// way past is memory the ceiling was written to refuse.
  ///
  /// The pattern that would fail to compile sits AFTER the 256th, so the refusal this
  /// asserts can only be the count: a face that compiled as it parsed would answer with
  /// that pattern's own error instead, which is precisely the work this cell says never
  /// happens. `RootGlobs` and `WatchOptions` share one definition of the flags, so both
  /// are pinned here.
  ///
  /// Revert witness: parse the seats as `Vec<Glob>` again and each over-full row is
  /// refused for its unclosed bracket rather than for its length.
  #[test]
  fn an_over_full_seat_is_refused_before_it_compiles() {
    let cap = RootGlobs::MAX_SEAT_PATTERNS;
    let flags = |flag: &str, count: usize, tail: Option<&str>| {
      std::iter::once("app".to_owned())
        .chain((0..count).flat_map(|n| [flag.to_owned(), std::format!("**/w{n}")]))
        .chain(
          tail
            .into_iter()
            .flat_map(|tail| [flag.to_owned(), tail.to_owned()]),
        )
        .collect::<std::vec::Vec<_>>()
    };

    // The ceiling itself parses, and compiles every one of its patterns.
    assert_eq!(
      GlobsCli::try_parse_from(flags("--prune", cap, None))
        .expect("the ceiling itself is honoured")
        .globs
        .prune()
        .len(),
      cap
    );
    assert_eq!(
      WatchCli::try_parse_from(flags("--include", cap, None))
        .expect("the other household honours it too")
        .options
        .include()
        .map(<[_]>::len),
      Some(cap)
    );

    // One past it, with the uncompilable pattern in that last position: the refusal
    // is the COUNT, and the pattern was never compiled.
    for over_full in [
      GlobsCli::try_parse_from(flags("--prune", cap, Some("[unclosed"))).err(),
      WatchCli::try_parse_from(flags("--prune", cap, Some("[unclosed"))).err(),
    ] {
      let err = over_full.expect("one past the ceiling is refused");
      assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
      let rendered = err.render().to_string();
      assert!(
        rendered.contains(&std::format!("{cap}")),
        "the refusal names the ceiling: {rendered}"
      );
      assert!(
        !rendered.contains("invalid glob"),
        "and the pattern past the ceiling was never compiled: {rendered}"
      );
    }
  }

  /// An UPDATE applies what the COMMAND LINE carried and nothing else — the rule every
  /// household on this face follows.
  ///
  /// A derived update cannot tell a flag's DEFAULT from a value someone gave, so it
  /// writes every default over the household it was handed: one `--event-capacity` would
  /// reset the command mailbox, switch settling on, and re-open an interest a caller had
  /// deliberately narrowed. Each household is pinned here on its own.
  #[test]
  fn an_update_changes_only_what_the_command_line_carried() {
    // The watcher household: one capacity moves, and nothing else does — the mailbox
    // keeps its configured value and the coalescer stays off.
    let mut options = TributariesOptions::new().with_command_capacity(nonzero(8));
    options
      .update_from_arg_matches(&update_matches::<TributariesOptions>(&[
        "--event-capacity",
        "4096",
      ]))
      .expect("the update applies");
    assert_eq!(options.event_capacity(), nonzero(4096));
    assert_eq!(
      options.command_capacity(),
      nonzero(8),
      "an unrelated capacity flag does not reapply the mailbox default"
    );
    assert_eq!(
      options.debounce_config(),
      None,
      "nor does it switch settling on with a household nobody asked for"
    );

    // A configured policy survives an unrelated update, and is updated KNOB BY KNOB
    // when the command line names one.
    let mut options = TributariesOptions::new().debounce(
      DebounceConfig::new()
        .with_max_buffered(7)
        .with_max_hold(Duration::from_secs(9)),
    );
    options
      .update_from_arg_matches(&update_matches::<TributariesOptions>(&[
        "--event-capacity",
        "4096",
      ]))
      .expect("the update applies");
    assert_eq!(
      options.debounce_config(),
      Some(
        DebounceConfig::new()
          .with_max_buffered(7)
          .with_max_hold(Duration::from_secs(9))
      ),
      "an unrelated flag leaves the settle policy exactly as it stood"
    );
    options
      .update_from_arg_matches(&update_matches::<TributariesOptions>(&[
        "--quiet-window",
        "250ms",
      ]))
      .expect("the update applies");
    assert_eq!(
      options.debounce_config(),
      Some(
        DebounceConfig::new()
          .with_max_buffered(7)
          .with_max_hold(Duration::from_secs(9))
          .with_quiet_window(Duration::from_millis(250))
      ),
      "the named knob moves; the other two keep their configured values"
    );

    // The policy household on its own.
    let mut config = DebounceConfig::new().with_max_buffered(7);
    config
      .update_from_arg_matches(&update_matches::<DebounceConfig>(&[
        "--quiet-window",
        "250ms",
      ]))
      .expect("the update applies");
    assert_eq!(
      config,
      DebounceConfig::new()
        .with_max_buffered(7)
        .with_quiet_window(Duration::from_millis(250))
    );

    // The subscription household: the interest gate is the field a derived update would
    // silently BROADEN, since no interest flag given is what spells the deliver-everything
    // default. An unrelated `--prune` must leave even the empty gate empty.
    let mut watch: WatchOptions<OsString> = WatchOptions::new()
      .with_interest(Interest::none())
      .with_include([glob("*.mp4")])
      .with_debounce(crate::options::Debounce::Off);
    watch
      .update_from_arg_matches(&update_matches::<WatchOptions<OsString>>(&[
        "--prune",
        "**/node_modules",
      ]))
      .expect("the update applies");
    assert_eq!(texts(watch.prune()), ["**/node_modules"]);
    assert!(
      watch.interest().is_none(),
      "an unrelated seat does not re-open a gate the caller closed"
    );
    assert_eq!(
      watch.include().map(texts),
      Some(std::vec!["*.mp4"]),
      "the seat nobody named keeps its patterns"
    );
    assert!(
      watch.debounce().is_off(),
      "a posture on no face is not something an update writes over"
    );

    // And a named interest flag narrows exactly its own bit.
    watch
      .update_from_arg_matches(&update_matches::<WatchOptions<OsString>>(&[
        "--created=true",
      ]))
      .expect("the update applies");
    assert_eq!(watch.interest(), Interest::none().with_created());

    // The per-root words on their own: neither flag carries a default, so the seat the
    // command line did not name is left as it stood.
    let mut globs = RootGlobs::new().with_include([glob("*.mp4")]);
    globs
      .update_from_arg_matches(&update_matches::<RootGlobs>(&["--prune", "**/.git"]))
      .expect("the update applies");
    assert_eq!(texts(globs.prune()), ["**/.git"]);
    assert_eq!(globs.include().map(texts), Some(std::vec!["*.mp4"]));
  }

  /// `--prune` and `--include` repeat, once per pattern; an `--include` given no times
  /// at all is the ABSENT seat, which is what makes a seat's absence expressible from a
  /// command line.
  #[test]
  fn the_glob_flags_repeat_and_an_absent_include_is_the_absent_seat() {
    let options =
      WatchCli::parse_from(args(&["--prune", "**/node_modules", "--prune", "**/.git"])).options;
    assert_eq!(texts(options.prune()), ["**/node_modules", "**/.git"]);
    assert!(options.include().is_none(), "no `--include` is no seat");

    let options = WatchCli::parse_from(args(&["--include", "**/*.mp4"])).options;
    assert_eq!(options.include().map(texts), Some(std::vec!["**/*.mp4"]));
    assert!(options.prune().is_empty());

    let bare = WatchCli::parse_from(args(&[])).options;
    assert!(bare.prune().is_empty());
    assert!(bare.include().is_none());

    // An uncompilable pattern is refused at the FLAG, by kind — this crate takes clap
    // with `default-features = false`, so the rendering carries no source context.
    let err = WatchCli::try_parse_from(args(&["--prune", "[unclosed"]))
      .err()
      .expect("an uncompilable pattern is refused at the flag");
    assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
  }

  /// `--include` spells ALL THREE of the seat's states, on both households that carry it.
  ///
  /// The seat is `Option<Vec<Glob>>` and its three states mean three different policies:
  /// absent delivers every file, engaged-and-EMPTY delivers none (directories and `Rescan`s
  /// only), and engaged with patterns delivers what they name. A plain repeatable flag
  /// requires a value per occurrence, so the middle one — a documented policy the serde face
  /// and the programmatic builder can both express — had NO spelling at all here: omitting
  /// the flag gave the absent seat, `--include` with no value was a parse error, and every
  /// successful occurrence produced a non-empty list. `num_args = 0..=1` is what closes that,
  /// and appending is unchanged, so a bare `--include` is the empty seat while
  /// `--include a --include b` still carries both.
  ///
  /// An UPDATE keeps the command-line-only rule: the seat a command line did not name is left
  /// as it stood, and a bare `--include` on an update SETS the empty seat rather than reading
  /// as "nothing given".
  ///
  /// Revert witness: drop `num_args` and the bare rows below fail at the parse itself.
  #[test]
  fn the_include_flag_spells_all_three_seat_states() {
    let globs = |rest: &[&str]| GlobsCli::parse_from(args(rest)).globs;
    let watch = |rest: &[&str]| WatchCli::parse_from(args(rest)).options;

    // ABSENT — every file.
    assert_eq!(globs(&[]).include(), None);
    assert_eq!(watch(&[]).include(), None);

    // EMPTY — no file; directories and Rescans only.
    assert_eq!(
      globs(&["--include"]).include().map(texts),
      Some(std::vec![]),
      "a bare --include is the engaged-but-EMPTY seat, not the absent one"
    );
    assert_eq!(
      watch(&["--include"]).include().map(texts),
      Some(std::vec![])
    );

    // NON-EMPTY — occurrences still append, in order.
    assert_eq!(
      globs(&["--include", "*.mp4", "--include", "*.mov"])
        .include()
        .map(texts),
      Some(std::vec!["*.mp4", "*.mov"])
    );
    assert_eq!(
      watch(&["--include", "*.mp4", "--include", "*.mov"])
        .include()
        .map(texts),
      Some(std::vec!["*.mp4", "*.mov"])
    );

    // The empty seat is engaged ground, not the unengaged household.
    assert!(
      !globs(&["--include"]).is_unengaged(),
      "an empty include seat is a policy the household carries, not the absence of one"
    );

    // UPDATE — the command-line-only rule, in all three directions.
    let mut kept = RootGlobs::new().with_include([glob("*.mp4")]);
    kept
      .update_from_arg_matches(&update_matches::<RootGlobs>(&["--prune", "**/.git"]))
      .expect("the update applies");
    assert_eq!(
      kept.include().map(texts),
      Some(std::vec!["*.mp4"]),
      "an unrelated flag leaves the seat exactly as it stood"
    );

    let mut emptied = RootGlobs::new().with_include([glob("*.mp4")]);
    emptied
      .update_from_arg_matches(&update_matches::<RootGlobs>(&["--include"]))
      .expect("the update applies");
    assert_eq!(
      emptied.include().map(texts),
      Some(std::vec![]),
      "a bare --include on an update SETS the empty seat"
    );

    let mut watch_emptied = WatchOptions::<OsString>::new().with_include([glob("*.mp4")]);
    watch_emptied
      .update_from_arg_matches(&update_matches::<WatchOptions<OsString>>(&["--include"]))
      .expect("the update applies");
    assert_eq!(watch_emptied.include().map(texts), Some(std::vec![]));

    // OPTIONAL FLATTEN — a bare --include is a value source, so the household is present.
    #[derive(clap::Parser)]
    struct OptionalGlobsCli {
      #[command(flatten)]
      globs: Option<RootGlobs>,
    }

    #[derive(clap::Parser)]
    struct OptionalWatchCli {
      #[command(flatten)]
      watch: Option<WatchOptions<OsString>>,
    }

    OptionalGlobsCli::command().debug_assert();
    OptionalWatchCli::command().debug_assert();
    assert_eq!(
      OptionalGlobsCli::parse_from(args(&["--include"]))
        .globs
        .expect("a bare --include makes the optional household present")
        .include()
        .map(texts),
      Some(std::vec![])
    );
    assert_eq!(
      OptionalWatchCli::parse_from(args(&["--include"]))
        .watch
        .expect("a bare --include makes the optional household present")
        .include()
        .map(texts),
      Some(std::vec![])
    );
  }

  /// Every household composes as an OPTIONAL flatten, which is the one shape that
  /// needs a real arg group underneath it.
  ///
  /// clap decides `Some` from `None` by asking whether the household's `ArgGroup`
  /// was matched, and it asks for that group's id while BUILDING the command —
  /// panicking outright when there is none. Leaving the group to the derive would
  /// not do either: clap's derive leaves it EMPTY for any struct containing a
  /// nested flatten, and an empty group is never present, so every flag would parse
  /// and then be discarded.
  ///
  /// Both halves are asserted per household: `None` when the caller spelled nothing
  /// of it, and `Some` — carrying the value — after ANY of its arguments, the
  /// NESTED ones included.
  ///
  /// Revert witness: forward a derived `group_id` and the two households with a
  /// nested flatten come back `None` from a command line that named their flags.
  #[test]
  fn an_optional_flatten_is_present_exactly_when_a_flag_was_given() {
    #[derive(clap::Parser)]
    struct OptionalCli {
      #[arg(long)]
      unrelated: bool,
      #[command(flatten)]
      watcher: Option<TributariesOptions>,
    }

    #[derive(clap::Parser)]
    struct OptionalWatchCli {
      #[arg(long)]
      unrelated: bool,
      #[command(flatten)]
      watch: Option<WatchOptions<OsString>>,
    }

    #[derive(clap::Parser)]
    struct OptionalGlobsCli {
      #[arg(long)]
      unrelated: bool,
      #[command(flatten)]
      globs: Option<RootGlobs>,
    }

    // The whole-command audit runs on each: an `ArgGroup` naming an id no argument
    // carries is exactly what it catches.
    OptionalCli::command().debug_assert();
    OptionalWatchCli::command().debug_assert();
    OptionalGlobsCli::command().debug_assert();

    // The watcher household — a DIRECT flag, then a NESTED one.
    let watcher = |rest: &[&str]| OptionalCli::parse_from(args(rest)).watcher;
    assert!(
      watcher(&[]).is_none(),
      "nothing of the household was spelled"
    );
    assert!(
      watcher(&["--unrelated"]).is_none(),
      "and another argument entirely does not conjure one"
    );
    assert_eq!(
      watcher(&["--event-capacity", "4096"])
        .expect("a direct flag makes it present")
        .event_capacity(),
      nonzero(4096)
    );
    assert_eq!(
      watcher(&["--quiet-window", "250ms"])
        .expect("a nested debounce flag makes it present too")
        .debounce_config(),
      Some(DebounceConfig::new().with_quiet_window(Duration::from_millis(250))),
      "the half a derived group would have lost"
    );

    // The subscription household — a seat, then an interest flag.
    let watch = |rest: &[&str]| OptionalWatchCli::parse_from(args(rest)).watch;
    assert!(watch(&[]).is_none());
    assert!(watch(&["--unrelated"]).is_none());
    assert_eq!(
      texts(
        watch(&["--prune", "**/node_modules"])
          .expect("a seat flag makes it present")
          .prune()
      ),
      ["**/node_modules"]
    );
    assert_eq!(
      watch(&["--include", "*.mp4"])
        .expect("the other seat too")
        .include()
        .map(texts),
      Some(std::vec!["*.mp4"])
    );
    assert_eq!(
      watch(&["--moved=false"])
        .expect("a nested interest flag makes it present")
        .interest(),
      *Interest::all().clear_moved()
    );

    // The words on their own: two direct flags, and nothing else.
    let globs = |rest: &[&str]| OptionalGlobsCli::parse_from(args(rest)).globs;
    assert!(globs(&[]).is_none());
    assert!(globs(&["--unrelated"]).is_none());
    assert_eq!(
      texts(
        globs(&["--prune", "**/.git"])
          .expect("a seat flag makes it present")
          .prune()
      ),
      ["**/.git"]
    );
    assert_eq!(
      globs(&["--include", "*.mkv"])
        .expect("the other seat too")
        .include()
        .map(texts),
      Some(std::vec!["*.mkv"])
    );
  }

  /// The subscription's flags are the interest's own; the filter is skipped and comes
  /// back accept-all.
  #[test]
  fn a_subscription_narrows_through_the_interest_flags() {
    let options = WatchCli::parse_from(args(&["--moved=false", "--removed=false"])).options;
    assert_eq!(
      options.interest(),
      *Interest::all().clear_moved().clear_removed()
    );
    let (key, kind, location) = ([OsString::from("f")], EventKind::Created, Location::new());
    let input = FilterInput::new(&key, &kind, &location);
    assert!(options.filter().admits(&input));
    // The skipped slot is a fresh accept-all `Filter`, not one shared with a caller's.
    let mine: Filter<OsString> = Filter::new(|_| false);
    assert!(!mine.admits(&input));
    assert!(options.filter().admits(&input));
  }
}

/// The shape a consumer configuring the WHOLE stack has: all three households
/// flattened onto one `clap::Command`. It is the reason `WatcherOptions` yields the
/// unqualified `--event-capacity` to `TributariesOptions` — clap refuses a duplicate
/// argument id, so without that one exception this command could not even be built.
#[cfg(all(feature = "clap", feature = "fs"))]
mod clap_whole_stack {
  use core::num::NonZeroUsize;
  use std::ffi::OsString;

  use super::super::{DebounceConfig, TributariesOptions, WatchOptions};
  use crate::WatcherOptions;
  use clap::{CommandFactory as _, Parser as _};

  #[derive(clap::Parser)]
  struct Cli {
    #[command(flatten)]
    watcher: WatcherOptions,
    #[command(flatten)]
    tributaries: TributariesOptions,
    #[command(flatten)]
    watch: WatchOptions<OsString>,
  }

  #[test]
  fn all_three_households_flatten_onto_one_command() {
    // clap's own whole-command audit: no two arguments (or groups) across the three
    // households share an id or a long form. It fires with no command line at all.
    Cli::command().debug_assert();

    let cli = Cli::parse_from([
      "app",
      "--watcher-event-capacity",
      "2048",
      "--event-capacity",
      "4096",
      "--command-capacity",
      "8",
      "--os-batch-capacity",
      "16",
      "--max-buffered",
      "512",
      "--moved=false",
    ]);

    // Each capacity landed in ITS OWN household — the two `event_capacity` knobs are
    // one level apart and stay apart.
    assert_eq!(
      cli.watcher.event_capacity(),
      NonZeroUsize::new(2048).unwrap()
    );
    assert_eq!(
      cli.tributaries.event_capacity(),
      NonZeroUsize::new(4096).unwrap()
    );
    assert_eq!(
      cli.tributaries.command_capacity(),
      NonZeroUsize::new(8).unwrap()
    );
    assert_eq!(
      cli.watcher.os_batch_capacity(),
      NonZeroUsize::new(16).unwrap()
    );
    assert_eq!(
      cli.tributaries.debounce_config(),
      Some(DebounceConfig::new().with_max_buffered(512)),
      "a flattened debounce flag turns the coalescer on from inside the outer group"
    );
    assert!(!cli.watch.interest().moved());

    // Every knob no flag named stayed at its own household's default.
    assert_eq!(cli.watcher.latency(), WatcherOptions::DEFAULT_LATENCY);
    assert!(cli.watch.interest().created());
    assert!(cli.watch.debounce().is_inherit());
  }
}
