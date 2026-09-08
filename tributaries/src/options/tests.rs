use std::ffi::OsString;

use super::{Debounce, DebounceConfig, RootGlobs, WatchOptions};
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
    super::{Debounce, DebounceConfig, TributariesOptions, WatchOptions},
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

  /// The same clamp the builders apply: `0` buffered entries is a buffer nothing can
  /// be admitted to, and every door reads it as `1`.
  #[test]
  fn a_zero_buffered_cap_is_clamped_exactly_as_the_builder_clamps_it() {
    let parsed: DebounceConfig = serde_json::from_str(r#"{"max_buffered": 0}"#).unwrap();
    assert_eq!(parsed.max_buffered(), 1);
    assert_eq!(parsed, DebounceConfig::new().with_max_buffered(0));
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
    super::{DebounceConfig, TributariesOptions, WatchOptions},
    texts,
  };
  use crate::{
    event::EventKind,
    filter::{Filter, FilterInput},
    interest::Interest,
  };
  use clap::Parser as _;
  use std::ffi::OsString;
  use tributary_proto::Location;

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

  fn args<'a>(rest: &'a [&'a str]) -> impl Iterator<Item = &'a str> {
    std::iter::once("app").chain(rest.iter().copied())
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

  #[test]
  fn a_zero_capacity_flag_is_refused() {
    for flags in [["--event-capacity", "0"], ["--command-capacity", "0"]] {
      assert!(
        WatcherCli::try_parse_from(args(&flags)).is_err(),
        "{flags:?}"
      );
    }
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
