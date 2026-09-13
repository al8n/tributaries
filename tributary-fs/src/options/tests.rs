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
}
