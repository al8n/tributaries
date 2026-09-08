use std::num::NonZeroU32;

use super::*;

#[test]
fn default_delegates_to_new() {
  assert_eq!(WatcherOptions::default(), WatcherOptions::new());
  let opts = WatcherOptions::new();
  assert_eq!(opts.latency(), WatcherOptions::DEFAULT_LATENCY);
  assert_eq!(opts.move_window(), WatcherOptions::DEFAULT_MOVE_WINDOW);
  assert_eq!(
    opts.event_capacity(),
    WatcherOptions::DEFAULT_EVENT_CAPACITY
  );
  assert_eq!(
    opts.os_batch_capacity(),
    WatcherOptions::DEFAULT_OS_BATCH_CAPACITY
  );
  assert_eq!(
    opts.os_buffer_bytes(),
    WatcherOptions::DEFAULT_OS_BUFFER_BYTES
  );
  assert!(opts.exclusions_slice().is_empty());
  assert_eq!(opts.backend(), WatcherOptions::DEFAULT_BACKEND);
  assert_eq!(opts.backend(), Backend::Auto);
  assert_eq!(
    opts.root_liveness_interval(),
    WatcherOptions::DEFAULT_ROOT_LIVENESS_INTERVAL
  );
  assert_eq!(opts.root_liveness_interval(), Duration::from_secs(30));
  assert_eq!(
    opts.max_map_directories(),
    WatcherOptions::DEFAULT_MAX_MAP_DIRECTORIES
  );
  assert_eq!(
    opts.max_map_directories(),
    Some(1_000_000),
    "the map cap is FINITE by default: registration's memory must not be a \
     function of whatever tree the caller names"
  );
  opts.validate().expect("the defaults are in range");
}

#[test]
fn builders_and_setters_agree() {
  let built = WatcherOptions::new()
    .with_latency(Duration::from_millis(20))
    .with_move_window(Duration::from_millis(300))
    .with_event_capacity(NonZeroUsize::new(8).unwrap())
    .with_os_batch_capacity(NonZeroUsize::new(4).unwrap())
    .with_os_buffer_bytes(NonZeroU32::new(8 * 1024).unwrap())
    .with_exclusions(vec![PathBuf::from("/tmp/skip")])
    .with_backend(Backend::Fanotify)
    .with_root_liveness_interval(Duration::from_secs(5))
    .with_max_map_directories(Some(100_000));

  let mut set = WatcherOptions::new();
  set
    .set_latency(Duration::from_millis(20))
    .set_move_window(Duration::from_millis(300))
    .set_event_capacity(NonZeroUsize::new(8).unwrap())
    .set_os_batch_capacity(NonZeroUsize::new(4).unwrap())
    .set_os_buffer_bytes(NonZeroU32::new(8 * 1024).unwrap())
    .set_exclusions(vec![PathBuf::from("/tmp/skip")])
    .set_backend(Backend::Fanotify)
    .set_root_liveness_interval(Duration::from_secs(5))
    .set_max_map_directories(Some(100_000));

  assert_eq!(built, set);
  assert_eq!(built.exclusions_slice().len(), 1);
  assert_eq!(built.backend(), Backend::Fanotify);
  assert_eq!(built.root_liveness_interval(), Duration::from_secs(5));
  assert_eq!(built.max_map_directories(), Some(100_000));
}

#[test]
fn root_liveness_interval_zero_disables_the_tick() {
  let opts = WatcherOptions::new().with_root_liveness_interval(Duration::ZERO);
  assert_eq!(
    opts.root_liveness_interval(),
    Duration::ZERO,
    "ZERO is a legal disabling value"
  );
}

#[test]
fn effective_move_window_never_falls_below_the_latency_floor() {
  // The default window already dominates the default latency's floor.
  let opts = WatcherOptions::new();
  assert_eq!(opts.effective_move_window(), opts.move_window());

  // A large latency raises the floor above the requested window.
  let opts = WatcherOptions::new().with_latency(Duration::from_millis(100));
  assert_eq!(opts.effective_move_window(), Duration::from_millis(250));

  // A generous window stands as requested.
  let opts = opts.with_move_window(Duration::from_secs(1));
  assert_eq!(opts.effective_move_window(), Duration::from_secs(1));
}

#[test]
fn effective_move_window_is_total_for_extreme_inputs() {
  let extreme = WatcherOptions::new().with_latency(Duration::MAX);
  assert_eq!(
    extreme.effective_move_window(),
    MAX_MOVE_WINDOW,
    "the derivation saturates and caps instead of panicking"
  );

  let huge_window = WatcherOptions::new().with_move_window(Duration::MAX);
  assert_eq!(huge_window.effective_move_window(), MAX_MOVE_WINDOW);

  let sane = WatcherOptions::new()
    .with_latency(Duration::from_millis(100))
    .with_move_window(Duration::from_millis(10));
  assert_eq!(
    sane.effective_move_window(),
    Duration::from_millis(250),
    "the floor stays 2 x latency + 50ms for ordinary inputs"
  );
}

/// Every ceiling refuses at construction rather than letting the value reach
/// the use site that has no answer for it.
///
/// The `os_batch_capacity` case is the 32-bit one: the native buffer used to be
/// this count multiplied by 1024, so `usize::MAX` there was an overflow —
/// panicking in debug and WRAPPING to a tiny buffer in release, on a 32-bit
/// target at any capacity above 4 Mi. The multiplication is gone (the buffer has
/// its own byte-valued knob) and the count is bounded on top of that.
#[test]
fn every_out_of_range_value_is_a_typed_refusal() {
  let huge = NonZeroUsize::new(usize::MAX).unwrap();

  assert_eq!(
    WatcherOptions::new()
      .with_exclusions(vec![
        PathBuf::from("/x");
        WatcherOptions::MAX_EXCLUSIONS + 1
      ])
      .validate(),
    Err(OptionsError::TooManyExclusions {
      supplied: WatcherOptions::MAX_EXCLUSIONS + 1
    })
  );
  assert_eq!(
    WatcherOptions::new().with_latency(Duration::MAX).validate(),
    Err(OptionsError::LatencyTooLarge {
      supplied: Duration::MAX
    })
  );
  assert_eq!(
    WatcherOptions::new().with_event_capacity(huge).validate(),
    Err(OptionsError::EventCapacityTooLarge { supplied: huge }),
    "usize::MAX slots is not a large channel, it is an allocation-size overflow"
  );
  assert_eq!(
    WatcherOptions::new()
      .with_os_batch_capacity(huge)
      .validate(),
    Err(OptionsError::OsBatchCapacityTooLarge { supplied: huge })
  );
  let too_big = NonZeroU32::new(u32::MAX).unwrap();
  assert_eq!(
    WatcherOptions::new()
      .with_os_buffer_bytes(too_big)
      .validate(),
    Err(OptionsError::OsBufferBytesOutOfRange { supplied: too_big })
  );
  let too_small = NonZeroU32::new(1).unwrap();
  assert_eq!(
    WatcherOptions::new()
      .with_os_buffer_bytes(too_small)
      .validate(),
    Err(OptionsError::OsBufferBytesOutOfRange {
      supplied: too_small
    }),
    "a buffer that cannot hold one record makes no progress"
  );
  assert_eq!(
    WatcherOptions::new()
      .with_root_liveness_interval(Duration::MAX)
      .validate(),
    Err(OptionsError::RootLivenessIntervalTooLarge {
      supplied: Duration::MAX
    }),
    "a saturating deadline that never fires would disable fanotify's only \
     unmount detector while looking configured"
  );
}

/// Each ceiling is itself admissible: the range is inclusive, so a caller can
/// name the documented maximum.
#[test]
fn the_documented_maxima_are_themselves_in_range() {
  WatcherOptions::new()
    .with_latency(WatcherOptions::MAX_LATENCY)
    .with_event_capacity(WatcherOptions::MAX_EVENT_CAPACITY)
    .with_os_batch_capacity(WatcherOptions::MAX_OS_BATCH_CAPACITY)
    .with_os_buffer_bytes(WatcherOptions::MAX_OS_BUFFER_BYTES)
    .with_root_liveness_interval(WatcherOptions::MAX_ROOT_LIVENESS_INTERVAL)
    .with_exclusions(vec![PathBuf::from("/x"); WatcherOptions::MAX_EXCLUSIONS])
    .validate()
    .expect("the maxima are admissible");
  WatcherOptions::new()
    .with_os_buffer_bytes(WatcherOptions::MIN_OS_BUFFER_BYTES)
    .with_root_liveness_interval(Duration::ZERO)
    .validate()
    .expect("the minima are admissible; ZERO still disables the tick");
}

/// The `serde` face: one object keyed by the field names, every key optional.
#[cfg(feature = "serde")]
mod serde_face {
  use super::*;

  #[test]
  fn default_round_trips() {
    let json = serde_json::to_string(&WatcherOptions::new()).unwrap();
    assert_eq!(
      serde_json::from_str::<WatcherOptions>(&json).unwrap(),
      WatcherOptions::new()
    );
  }

  #[test]
  fn a_fully_overridden_household_round_trips() {
    let options = WatcherOptions::new()
      .with_latency(Duration::from_millis(250))
      .with_move_window(Duration::from_secs(2))
      .with_event_capacity(NonZeroUsize::new(4096).unwrap())
      .with_os_batch_capacity(NonZeroUsize::new(8).unwrap())
      .with_os_buffer_bytes(NonZeroU32::new(8 * 1024).unwrap())
      .with_exclusions(vec![PathBuf::from("/repo/target")])
      .with_backend(Backend::Fanotify)
      .with_root_liveness_interval(Duration::from_secs(5))
      .with_max_map_directories(Some(250_000));
    let json = serde_json::to_string(&options).unwrap();
    assert_eq!(
      serde_json::from_str::<WatcherOptions>(&json).unwrap(),
      options
    );
  }

  /// A document naming ONE key leaves every other knob at the value `new()` gives
  /// it — the struct-level `#[serde(default)]`.
  #[test]
  fn a_partial_document_defaults_every_absent_key() {
    let parsed: WatcherOptions = serde_json::from_str(r#"{"latency": "250ms"}"#).unwrap();
    assert_eq!(parsed.latency(), Duration::from_millis(250));
    assert_eq!(parsed, WatcherOptions::new().with_latency(parsed.latency()));
  }

  /// Forward compatibility: no `deny_unknown_fields`.
  #[test]
  fn an_unknown_key_is_accepted() {
    let parsed: WatcherOptions =
      serde_json::from_str(r#"{"latency": "250ms", "some_future_knob": 7}"#).unwrap();
    assert_eq!(parsed, WatcherOptions::new().with_latency(parsed.latency()));
  }

  /// The capacities are non-zero TYPES, so a zero is refused by the format rather
  /// than normalized into a channel nobody can push through.
  #[test]
  fn a_zero_capacity_is_refused() {
    for document in [
      r#"{"event_capacity": 0}"#,
      r#"{"os_batch_capacity": 0}"#,
      r#"{"os_buffer_bytes": 0}"#,
    ] {
      assert!(
        serde_json::from_str::<WatcherOptions>(document).is_err(),
        "{document}"
      );
    }
  }

  /// Durations are humantime TEXT in both directions.
  #[test]
  fn durations_are_humantime_text() {
    let json = serde_json::to_value(WatcherOptions::new()).unwrap();
    assert_eq!(json["latency"], serde_json::json!("10ms"));
    assert_eq!(json["move_window"], serde_json::json!("150ms"));
    assert_eq!(json["root_liveness_interval"], serde_json::json!("30s"));

    let parsed: WatcherOptions = serde_json::from_str(
      r#"{"latency": "250ms", "move_window": "2s", "root_liveness_interval": "0s"}"#,
    )
    .unwrap();
    assert_eq!(parsed.latency(), Duration::from_millis(250));
    assert_eq!(parsed.move_window(), Duration::from_secs(2));
    assert_eq!(parsed.root_liveness_interval(), Duration::ZERO);
  }

  /// The map cap keeps all three of its states: absent is the finite default,
  /// `null` is the caller opting INTO the unbounded map, an integer is a cap.
  #[test]
  fn the_map_cap_keeps_absent_null_and_capped_apart() {
    let absent: WatcherOptions = serde_json::from_str("{}").unwrap();
    assert_eq!(
      absent.max_map_directories(),
      WatcherOptions::DEFAULT_MAX_MAP_DIRECTORIES
    );
    let uncapped: WatcherOptions =
      serde_json::from_str(r#"{"max_map_directories": null}"#).unwrap();
    assert_eq!(uncapped.max_map_directories(), None);
    let capped: WatcherOptions =
      serde_json::from_str(r#"{"max_map_directories": 250000}"#).unwrap();
    assert_eq!(capped.max_map_directories(), Some(250_000));
  }

  /// `Backend` reads and writes exactly the tag `as_str` reports.
  #[test]
  fn every_backend_spells_itself_as_its_own_tag() {
    for backend in [
      Backend::Auto,
      Backend::Inotify,
      Backend::Fanotify,
      Backend::Rdcw,
      Backend::UsnJournal,
    ] {
      let json = serde_json::to_value(backend).unwrap();
      assert_eq!(json, serde_json::json!(backend.as_str()), "{backend:?}");
      assert_eq!(
        serde_json::from_value::<Backend>(json).unwrap(),
        backend,
        "{backend:?}"
      );
    }
    assert!(
      serde_json::from_str::<Backend>(r#""usn_journal""#).is_err(),
      "one tag per variant: the stable spelling is the kebab one"
    );
  }

  /// Loading is exactly as unchecked as the builders are: an out-of-range knob
  /// loads and is refused by the one explicit step, `validate`.
  #[test]
  fn deserializing_does_not_validate() {
    let parsed: WatcherOptions = serde_json::from_str(r#"{"latency": "10min"}"#).unwrap();
    assert_eq!(parsed.latency(), Duration::from_secs(600));
    assert_eq!(
      parsed.validate(),
      Err(OptionsError::LatencyTooLarge {
        supplied: Duration::from_secs(600)
      })
    );
  }
}

/// The `clap` face: one `--<field>` flag per knob, defaulted from the same
/// constants `new()` reads.
#[cfg(feature = "clap")]
mod clap_face {
  use super::*;
  use clap::Parser as _;

  #[derive(clap::Parser)]
  struct Cli {
    #[command(flatten)]
    options: WatcherOptions,
  }

  fn parse(args: &[&str]) -> WatcherOptions {
    Cli::parse_from(std::iter::once("app").chain(args.iter().copied())).options
  }

  /// The flag defaults are rendered from the `DEFAULT_*` constants themselves, so
  /// this also pins that they cannot drift apart.
  #[test]
  fn no_flags_is_the_default_household() {
    assert_eq!(parse(&[]), WatcherOptions::new());
  }

  /// Each long flag sets EXACTLY its own knob.
  #[test]
  fn every_flag_sets_exactly_its_own_knob() {
    /// One flag (with its value) and the knob it is expected to set.
    type Case = (
      &'static [&'static str],
      fn(WatcherOptions) -> WatcherOptions,
    );

    let cases: [Case; 9] = [
      (&["--latency", "250ms"], |o| {
        o.with_latency(Duration::from_millis(250))
      }),
      (&["--move-window", "2s"], |o| {
        o.with_move_window(Duration::from_secs(2))
      }),
      (&["--watcher-event-capacity", "4096"], |o| {
        o.with_event_capacity(NonZeroUsize::new(4096).unwrap())
      }),
      (&["--os-batch-capacity", "8"], |o| {
        o.with_os_batch_capacity(NonZeroUsize::new(8).unwrap())
      }),
      (&["--os-buffer-bytes", "8192"], |o| {
        o.with_os_buffer_bytes(NonZeroU32::new(8192).unwrap())
      }),
      (&["--exclusions", "/repo/target"], |o| {
        o.with_exclusions(vec![PathBuf::from("/repo/target")])
      }),
      (&["--backend", "fanotify"], |o| {
        o.with_backend(Backend::Fanotify)
      }),
      (&["--root-liveness-interval", "5s"], |o| {
        o.with_root_liveness_interval(Duration::from_secs(5))
      }),
      (&["--max-map-directories", "250000"], |o| {
        o.with_max_map_directories(Some(250_000))
      }),
    ];
    for (args, expected) in cases {
      assert_eq!(parse(args), expected(WatcherOptions::new()), "{args:?}");
    }
  }

  /// The exclusions flag repeats, once per path.
  #[test]
  fn exclusions_repeat() {
    assert_eq!(
      parse(&["--exclusions", "/a", "--exclusions", "/b"]).exclusions_slice(),
      [PathBuf::from("/a"), PathBuf::from("/b")]
    );
  }

  /// Every `Backend` variant is reachable under the tag `as_str` reports.
  #[test]
  fn every_backend_value_parses_to_its_variant() {
    for backend in [
      Backend::Auto,
      Backend::Inotify,
      Backend::Fanotify,
      Backend::Rdcw,
      Backend::UsnJournal,
    ] {
      assert_eq!(
        parse(&["--backend", backend.as_str()]).backend(),
        backend,
        "{backend:?}"
      );
    }
    assert!(
      Cli::try_parse_from(["app", "--backend", "usn_journal"]).is_err(),
      "one tag per variant: the stable spelling is the kebab one"
    );
  }

  /// The one flag that is not its field's name: this household's `event_capacity`
  /// is `--watcher-event-capacity`, so it can sit on one command line beside the
  /// umbrella's own `--event-capacity` one level up (see the type docs). The plain
  /// spelling is NOT this household's — a command line that used it would be
  /// configuring the other channel.
  #[test]
  fn the_event_capacity_flag_is_the_watcher_scoped_one() {
    assert_eq!(
      parse(&["--watcher-event-capacity", "4096"]).event_capacity(),
      NonZeroUsize::new(4096).unwrap()
    );
    assert!(
      Cli::try_parse_from(["app", "--event-capacity", "4096"]).is_err(),
      "the unqualified flag belongs to the outer household, not this one"
    );
  }

  /// A zero for a non-zero knob is refused at the flag, not normalized.
  #[test]
  fn a_zero_capacity_flag_is_refused() {
    for args in [
      ["--watcher-event-capacity", "0"],
      ["--os-batch-capacity", "0"],
      ["--os-buffer-bytes", "0"],
    ] {
      assert!(
        Cli::try_parse_from(["app", args[0], args[1]]).is_err(),
        "{args:?}"
      );
    }
  }

  /// An UPDATE applies what the COMMAND LINE carried, and nothing else.
  ///
  /// Every knob here but `--exclusions` has a flag default, and a derived update
  /// cannot tell a default from a value someone gave — so one `--latency` used to
  /// reset the backend selection, the native buffer size, both capacities, the
  /// liveness interval and the map cap to what a flagless command line means,
  /// silently discarding whatever a configuration layer had loaded.
  #[test]
  fn an_update_changes_only_the_knobs_the_command_line_carried() {
    use clap::{CommandFactory as _, FromArgMatches as _};

    fn matches(args: &[&str]) -> clap::ArgMatches {
      Cli::command_for_update().get_matches_from(std::iter::once("app").chain(args.iter().copied()))
    }

    let configured = WatcherOptions::new()
      .with_backend(Backend::Inotify)
      .with_event_capacity(NonZeroUsize::new(4096).unwrap())
      .with_os_batch_capacity(NonZeroUsize::new(16).unwrap())
      .with_os_buffer_bytes(NonZeroU32::new(128 * 1024).unwrap())
      .with_move_window(Duration::from_millis(750))
      .with_root_liveness_interval(Duration::from_secs(90))
      .with_max_map_directories(Some(250_000))
      .with_exclusions(std::vec![PathBuf::from("/repo/target")]);

    let mut options = configured.clone();
    options
      .update_from_arg_matches(&matches(&["--latency", "25ms"]))
      .expect("the update applies");
    assert_eq!(
      options,
      configured.clone().with_latency(Duration::from_millis(25)),
      "the named knob moves and every other one stands"
    );

    // An update naming nothing of this group changes nothing at all.
    let mut options = configured.clone();
    options
      .update_from_arg_matches(&matches(&[]))
      .expect("the update applies");
    assert_eq!(options, configured);

    // The repeatable seat REPLACES the list it updates, and only when it is named.
    let mut options = configured.clone();
    options
      .update_from_arg_matches(&matches(&["--exclusions", "/a", "--exclusions", "/b"]))
      .expect("the update applies");
    assert_eq!(
      options.exclusions_slice(),
      [PathBuf::from("/a"), PathBuf::from("/b")],
      "a named list is the whole list — there is no spelling for appending one path"
    );
    assert_eq!(
      options.backend(),
      Backend::Inotify,
      "and it carries nothing else with it"
    );
  }
}

/// The per-ROOT household: its defaults, its builders and its two faces.
mod root_options {
  use super::*;

  fn glob(pattern: &str) -> Glob {
    Glob::new(pattern).expect("a valid pattern compiles")
  }

  fn patterns(globs: &[Glob]) -> Vec<&str> {
    globs.iter().map(Glob::as_str).collect()
  }

  /// The defaults are the behaviour the interest-only shorthand always had:
  /// deliver everything, prune nothing, include everything.
  #[test]
  fn default_delegates_to_new() {
    assert_eq!(RootOptions::default(), RootOptions::new());
    let opts = RootOptions::new();
    assert_eq!(opts.interest(), RootOptions::DEFAULT_INTEREST);
    assert_eq!(opts.interest(), Interest::all());
    assert!(opts.prune().is_empty());
    assert_eq!(
      opts.include(),
      None,
      "an ABSENT include seat delivers every file; an empty one would deliver none"
    );
  }

  #[test]
  fn builders_and_setters_agree() {
    let built = RootOptions::new()
      .with_interest(Interest::new().with_created())
      .with_prune([glob("**/node_modules"), glob("**/.git")])
      .with_include([glob("**/*.mp4")]);

    let mut set = RootOptions::new();
    set
      .set_interest(Interest::new().with_created())
      .set_prune([glob("**/node_modules"), glob("**/.git")])
      .set_include([glob("**/*.mp4")]);

    assert_eq!(built, set);
    assert_eq!(patterns(built.prune()), ["**/node_modules", "**/.git"]);
    assert_eq!(
      built.include().map(patterns),
      Some(std::vec!["**/*.mp4"]),
      "the include seat keeps the patterns it was given"
    );
  }

  /// The include seat has THREE states and the API keeps them apart: absent
  /// (every file), empty (no file), and populated.
  #[test]
  fn the_include_seat_keeps_absent_and_empty_apart() {
    let engaged = RootOptions::new().with_include([glob("**/*.mp4")]);
    assert!(engaged.include().is_some());

    let empty = RootOptions::new().with_include(std::iter::empty());
    assert_eq!(
      empty.include(),
      Some(&[][..]),
      "an empty seat is ENGAGED and admits no file"
    );
    assert_ne!(empty, RootOptions::new());

    assert_eq!(engaged.without_include(), RootOptions::new());
    let mut cleared = empty;
    cleared.clear_include();
    assert_eq!(cleared, RootOptions::new());
  }

  /// Each pattern is bounded on its own; this is the bound on the SET, and it is
  /// what keeps the fence's worst case a number. A set the matcher refuses to
  /// union degrades to asking every pattern in turn, and the prune fence asks a
  /// set once per directory prefix of every event — so an unbounded list buys
  /// `patterns × depth` automaton passes per event, decided by a document rather
  /// than by this crate.
  ///
  /// Both seats, both sides of the boundary, and the refusal names how many were
  /// supplied so a person can act on it.
  #[test]
  fn a_seat_past_the_pattern_cap_is_a_typed_refusal() {
    let many = |count: usize| {
      (0..count)
        .map(|n| glob(&std::format!("**/w{n}")))
        .collect::<std::vec::Vec<_>>()
    };
    let cap = RootOptions::MAX_SEAT_PATTERNS;

    assert!(
      RootOptions::new().with_prune(many(cap)).validate().is_ok(),
      "the ceiling itself is honoured"
    );
    assert_eq!(
      RootOptions::new().with_prune(many(cap + 1)).validate(),
      Err(OptionsError::TooManyPrunePatterns { supplied: cap + 1 }),
      "and one past it is refused, naming what was supplied"
    );
    assert_eq!(
      RootOptions::new().with_include(many(cap + 1)).validate(),
      Err(OptionsError::TooManyIncludePatterns { supplied: cap + 1 }),
      "the include seat carries the same ceiling"
    );
    assert!(
      RootOptions::new()
        .with_prune(many(cap + 1))
        .validate()
        .is_err_and(|err| err.is_too_many_prune_patterns()),
      "and the refusal is readable without a match"
    );

    // The default household is nowhere near any of this.
    assert!(RootOptions::new().validate().is_ok());
  }

  /// The `serde` face: one object keyed by the field names, the seats lists of
  /// plain strings, every key optional.
  #[cfg(feature = "serde")]
  mod serde_face {
    use super::*;

    #[test]
    fn default_round_trips() {
      let json = serde_json::to_string(&RootOptions::new()).unwrap();
      assert_eq!(
        serde_json::from_str::<RootOptions>(&json).unwrap(),
        RootOptions::new()
      );
    }

    #[test]
    fn a_fully_overridden_household_round_trips() {
      let options = RootOptions::new()
        .with_interest(Interest::new().with_created().with_moved())
        .with_prune([glob("**/node_modules"), glob("**/.git")])
        .with_include([glob("**/*.{mp4,mov}")]);
      let json = serde_json::to_string(&options).unwrap();
      assert_eq!(serde_json::from_str::<RootOptions>(&json).unwrap(), options);
    }

    /// The seats are lists of STRINGS, in both directions.
    #[test]
    fn the_seats_are_lists_of_strings() {
      let options = RootOptions::new()
        .with_prune([glob("**/node_modules")])
        .with_include([glob("**/*.mp4")]);
      let json = serde_json::to_value(&options).unwrap();
      assert_eq!(json["prune"], serde_json::json!(["**/node_modules"]));
      assert_eq!(json["include"], serde_json::json!(["**/*.mp4"]));

      let parsed: RootOptions =
        serde_json::from_str(r#"{"prune": ["**/Caches"], "include": ["**/*.mkv"]}"#).unwrap();
      assert_eq!(patterns(parsed.prune()), ["**/Caches"]);
      assert_eq!(parsed.include().map(patterns), Some(std::vec!["**/*.mkv"]));
    }

    /// A document naming ONE key leaves every other knob at the value `new()`
    /// gives it — the struct-level `#[serde(default)]`.
    #[test]
    fn a_partial_document_defaults_every_absent_key() {
      let parsed: RootOptions = serde_json::from_str(r#"{"prune": ["**/target"]}"#).unwrap();
      assert_eq!(
        parsed,
        RootOptions::new().with_prune([glob("**/target")]),
        "the absent interest is Interest::all() and the absent include is None"
      );
      assert_eq!(parsed.include(), None);
    }

    /// `null` and an absent key are the same absent seat; an empty LIST is the
    /// engaged-but-empty one.
    #[test]
    fn the_include_seat_survives_the_round_trip_in_all_three_states() {
      let absent: RootOptions = serde_json::from_str("{}").unwrap();
      assert_eq!(absent.include(), None);
      let null: RootOptions = serde_json::from_str(r#"{"include": null}"#).unwrap();
      assert_eq!(null.include(), None);
      let empty: RootOptions = serde_json::from_str(r#"{"include": []}"#).unwrap();
      assert_eq!(empty.include(), Some(&[][..]));
    }

    /// Forward compatibility: no `deny_unknown_fields`.
    #[test]
    fn an_unknown_key_is_accepted() {
      let parsed: RootOptions =
        serde_json::from_str(r#"{"prune": [], "some_future_seat": 7}"#).unwrap();
      assert_eq!(parsed, RootOptions::new());
    }

    /// An invalid pattern is refused by the DOCUMENT, not carried as a seat that
    /// silently matches nothing.
    #[test]
    fn an_invalid_pattern_is_a_document_error() {
      assert!(serde_json::from_str::<RootOptions>(r#"{"prune": ["[unclosed"]}"#).is_err());
    }
  }

  /// The `clap` face: repeatable `--prune` / `--include` flags, and an absent
  /// `--include` is the absent seat.
  #[cfg(feature = "clap")]
  mod clap_face {
    use super::*;
    use clap::Parser as _;

    #[derive(Debug, clap::Parser)]
    struct Cli {
      #[command(flatten)]
      options: RootOptions,
    }

    fn parse(args: &[&str]) -> RootOptions {
      Cli::parse_from(std::iter::once("app").chain(args.iter().copied())).options
    }

    /// `--prune` repeats, once per pattern, in the order given.
    #[test]
    fn the_prune_flag_repeats() {
      let parsed = parse(&["--prune", "**/node_modules", "--prune", "**/.git"]);
      assert_eq!(patterns(parsed.prune()), ["**/node_modules", "**/.git"]);
      assert!(parse(&[]).prune().is_empty());
    }

    /// `--include` repeats too — and given no times at all it is the ABSENT seat
    /// (every file), which is what makes the seat's absence expressible from a
    /// command line rather than collapsing into an empty list that admits none.
    #[test]
    fn an_absent_include_flag_is_the_absent_seat() {
      assert_eq!(parse(&[]).include(), None);
      let parsed = parse(&["--include", "**/*.mp4", "--include", "**/*.mov"]);
      assert_eq!(
        parsed.include().map(patterns),
        Some(std::vec!["**/*.mp4", "**/*.mov"])
      );
    }

    /// A FLAGLESS command line is the default household — the same value
    /// `RootOptions::new()` and an absent serde document hand back.
    ///
    /// The standalone `Interest` group's clap face reads a flagless parse as the
    /// EMPTY mask, and flattening it here made `--prune '**/x'` alone build a root
    /// subscribed to nothing: no creates, no modifications, no removals, no moves,
    /// only the unmaskable `Rescan`s — while every other face of the same household
    /// meant every kind. The proxy reinterprets only the flagless case.
    ///
    /// Revert witness: flatten the protocol `Interest` group back into
    /// `RootOptions` and the first row parses to `Interest::new()`.
    #[test]
    fn a_flagless_command_line_is_the_default_household() {
      assert_eq!(parse(&[]), RootOptions::new());
      assert_eq!(parse(&[]).interest(), RootOptions::DEFAULT_INTEREST);
      // A seat flag is not an interest flag: the household still defaults.
      assert_eq!(
        parse(&["--prune", "**/node_modules"]).interest(),
        RootOptions::DEFAULT_INTEREST
      );
    }

    /// ANY interest flag narrows to exactly the ones given — the opt-in act the
    /// household's docs promise, with no bit riding along from the default.
    #[test]
    fn one_interest_flag_narrows_to_exactly_that_kind() {
      assert_eq!(
        parse(&["--created"]).interest(),
        Interest::new().with_created()
      );
      assert_eq!(
        parse(&["--created", "--moved"]).interest(),
        Interest::new().with_created().with_moved()
      );
      assert_eq!(parse(&["--ondir"]).interest(), Interest::new().with_ondir());
    }

    /// The standalone `Interest` group keeps ITS face: a flagless parse there is
    /// still the empty mask, because there the flags are the whole value rather than
    /// one field of a household with a deliver-everything default.
    #[test]
    fn the_standalone_interest_group_still_defaults_empty() {
      #[derive(Debug, clap::Parser)]
      struct Bare {
        #[command(flatten)]
        interest: Interest,
      }

      assert_eq!(
        Bare::parse_from(["app"]).interest,
        Interest::new(),
        "flattening `Interest` on its own is untouched by the household's proxy"
      );
    }

    /// An invalid pattern is refused at the FLAG, with the type's own message.
    #[test]
    fn an_invalid_pattern_is_refused_at_the_flag() {
      let err = Cli::try_parse_from(["app", "--prune", "[unclosed"]).unwrap_err();
      assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
      assert!(
        err.render().to_string().contains("invalid glob"),
        "the type's own message reaches the command line: {}",
        err.render()
      );
    }

    /// An UPDATE changes only what the command line carried. The interest is the
    /// field that could not survive the proxy on its own: no flag given means
    /// every kind, so round-tripping an EXISTING interest through those flags
    /// erases the empty one, and an unrelated `--prune` would silently broaden
    /// what the caller subscribed to. The flags are consulted instead of the
    /// value.
    ///
    /// Revert witness: rebuild the household from the proxy unconditionally and
    /// the first assertion reads `Interest::all()`.
    #[test]
    fn an_update_leaves_an_interest_the_command_line_never_mentioned() {
      let update = |mut options: RootOptions, args: &[&str]| {
        let matches = <Cli as clap::CommandFactory>::command_for_update()
          .try_get_matches_from(std::iter::once("app").chain(args.iter().copied()))
          .expect("the command line parses");
        clap::FromArgMatches::update_from_arg_matches(&mut options, &matches)
          .expect("the update applies");
        options
      };

      let empty = RootOptions::new().with_interest(Interest::new());
      let updated = update(empty.clone(), &["--prune", "**/node_modules"]);
      assert_eq!(
        updated.interest(),
        Interest::new(),
        "an explicit EMPTY interest survives an unrelated seat update"
      );
      assert_eq!(patterns(updated.prune()), ["**/node_modules"]);

      // A narrowed interest survives the same way — the update is not free to
      // widen it back to the household default either.
      let narrow = RootOptions::new().with_interest(Interest::new().with_created());
      assert_eq!(
        update(narrow, &["--include", "**/*.mp4"]).interest(),
        Interest::new().with_created()
      );

      // And a seat the command line did not mention keeps its value, while the
      // one it did mention is replaced.
      let seated = RootOptions::new()
        .with_prune([glob("**/.git")])
        .with_include([glob("**/*.mov")]);
      let updated = update(seated, &["--prune", "**/node_modules"]);
      assert_eq!(patterns(updated.prune()), ["**/node_modules"]);
      assert_eq!(
        updated.include().map(patterns),
        Some(std::vec!["**/*.mov"]),
        "the untouched seat is untouched"
      );

      // An interest flag that IS on the command line still narrows, so nothing
      // above is a claim that updates cannot reach the interest at all.
      assert_eq!(
        update(empty, &["--moved"]).interest(),
        Interest::new().with_moved()
      );
    }
  }
}
