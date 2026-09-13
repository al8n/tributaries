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
  assert_eq!(
    opts.cookie_global_cap(),
    WatcherOptions::DEFAULT_COOKIE_GLOBAL_CAP
  );
  assert_eq!(
    opts.cookie_global_cap().get(),
    if cfg!(target_os = "macos") { 64 } else { 128 },
    "the sync-marker ceiling is sized against the HOST's descriptor budget: \
     macOS defaults to a 256 soft limit and holds a target and reserved pin per \
     barrier in flight, where a descending lowering releases both at its door"
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
  let over_long = "/".repeat(WatcherOptions::MAX_EXCLUSION_LEN + 1);
  assert_eq!(
    WatcherOptions::new()
      .with_exclusions(vec![PathBuf::from(&over_long)])
      .validate(),
    Err(OptionsError::ExclusionTooLong {
      supplied: WatcherOptions::MAX_EXCLUSION_LEN + 1
    }),
    "the length bound is the builders' backstop for what the faces refuse as they parse"
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
  assert_eq!(
    WatcherOptions::new()
      .with_cookie_global_cap(huge)
      .validate(),
    Err(OptionsError::CookieGlobalCapTooLarge { supplied: huge }),
    "the cap the door's own descriptor arithmetic is sized against is bounded \
     the same way every other capacity knob is"
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
    .with_cookie_global_cap(WatcherOptions::MAX_COOKIE_GLOBAL_CAP)
    .with_exclusions(vec![
      PathBuf::from(
        "/".repeat(WatcherOptions::MAX_EXCLUSION_LEN)
      );
      WatcherOptions::MAX_EXCLUSIONS
    ])
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

  /// The default the SERDE face hands back for an omitted key is the host
  /// platform's, not a number frozen into the format.
  ///
  /// A document names only what it overrides, so a household written on one
  /// platform and read on another must take the reader's ceiling — the descriptor
  /// budget the cap is sized against belongs to the host doing the watching.
  #[test]
  fn an_omitted_cookie_cap_takes_the_host_platform_default() {
    let absent: WatcherOptions = serde_json::from_str("{}").unwrap();
    assert_eq!(
      absent.cookie_global_cap(),
      WatcherOptions::DEFAULT_COOKIE_GLOBAL_CAP
    );
    assert_eq!(
      absent.cookie_global_cap().get(),
      if cfg!(target_os = "macos") { 64 } else { 128 }
    );

    let named: WatcherOptions = serde_json::from_str(r#"{"cookie_global_cap": 7}"#).unwrap();
    assert_eq!(
      named.cookie_global_cap().get(),
      7,
      "and a document that names it is honoured"
    );
    assert!(
      serde_json::from_str::<WatcherOptions>(r#"{"cookie_global_cap": 0}"#).is_err(),
      "zero is not a ceiling: a watcher that may hold no obligation admits no sync"
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

  /// Every bounded key is judged WHERE IT IS READ: the bound itself parses, and one
  /// step past it is refused by the document.
  ///
  /// A face that only PARSES an out-of-range number defers the refusal to
  /// `Watcher::new`, and an application then cannot read a successful load as
  /// acceptance — the configuration layer reports the document as read, and the
  /// watcher refuses it later with nothing left pointing at the key that was
  /// wrong. The rule each key is judged by is the very one
  /// [`WatcherOptions::validate`] asks, so the two can never come to mean
  /// different things by the same number.
  ///
  /// Revert witness: drop a key's `deserialize_with` and its over-bound document
  /// parses into a household `validate` then has to catch.
  #[test]
  fn every_bounded_key_accepts_its_bound_and_refuses_one_step_past_it() {
    /// A key's name, a document naming its exact bound, the household that
    /// document means, a document one step past the bound, and the words the
    /// refusal must carry.
    type Case = (
      &'static str,
      &'static str,
      fn(WatcherOptions) -> WatcherOptions,
      &'static str,
      &'static str,
    );

    let cases: [Case; 7] = [
      (
        "latency",
        r#"{"latency": "60s"}"#,
        |o| o.with_latency(WatcherOptions::MAX_LATENCY),
        r#"{"latency": "61s"}"#,
        "exceeds",
      ),
      (
        "event_capacity",
        r#"{"event_capacity": 1048576}"#,
        |o| o.with_event_capacity(WatcherOptions::MAX_EVENT_CAPACITY),
        r#"{"event_capacity": 1048577}"#,
        "exceeds",
      ),
      (
        "os_batch_capacity",
        r#"{"os_batch_capacity": 65536}"#,
        |o| o.with_os_batch_capacity(WatcherOptions::MAX_OS_BATCH_CAPACITY),
        r#"{"os_batch_capacity": 65537}"#,
        "exceeds",
      ),
      (
        "os_buffer_bytes at its ceiling",
        r#"{"os_buffer_bytes": 1048576}"#,
        |o| o.with_os_buffer_bytes(WatcherOptions::MAX_OS_BUFFER_BYTES),
        r#"{"os_buffer_bytes": 1048577}"#,
        "outside",
      ),
      (
        "os_buffer_bytes at its floor",
        r#"{"os_buffer_bytes": 4096}"#,
        |o| o.with_os_buffer_bytes(WatcherOptions::MIN_OS_BUFFER_BYTES),
        r#"{"os_buffer_bytes": 4095}"#,
        "outside",
      ),
      (
        "root_liveness_interval",
        r#"{"root_liveness_interval": "24h"}"#,
        |o| o.with_root_liveness_interval(WatcherOptions::MAX_ROOT_LIVENESS_INTERVAL),
        r#"{"root_liveness_interval": "25h"}"#,
        "exceeds",
      ),
      (
        "cookie_global_cap",
        r#"{"cookie_global_cap": 1024}"#,
        |o| o.with_cookie_global_cap(WatcherOptions::MAX_COOKIE_GLOBAL_CAP),
        r#"{"cookie_global_cap": 1025}"#,
        "exceeds",
      ),
    ];

    for (key, at_bound, expected, past_bound, words) in cases {
      let parsed = serde_json::from_str::<WatcherOptions>(at_bound)
        .unwrap_or_else(|err| panic!("{key}: the bound itself is admissible, got {err}"));
      assert_eq!(parsed, expected(WatcherOptions::new()), "{key}");
      parsed
        .validate()
        .unwrap_or_else(|err| panic!("{key}: and the household it builds validates, got {err}"));

      // And the value the document carried survives a round trip unchanged — the
      // range rule is a gate, never a rewrite.
      let json = serde_json::to_string(&parsed).unwrap();
      assert_eq!(
        serde_json::from_str::<WatcherOptions>(&json).unwrap(),
        parsed,
        "{key} round-trips"
      );

      let refusal = serde_json::from_str::<WatcherOptions>(past_bound)
        .map(|_| ())
        .expect_err(key)
        .to_string();
      assert!(
        refusal.contains(words),
        "{key}: the refusal names the bound, got {refusal}"
      );
    }
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

  /// The exclusion list past its ceiling is a DOCUMENT error, refused mid-list
  /// rather than read whole and measured afterwards.
  ///
  /// The bound is a resource bound — the OS honours eight per root — so a face
  /// that reads an untrusted length to the end before judging it has already
  /// allocated everything the bound exists to refuse: a streaming document naming
  /// millions of exclusions costs the process its memory before the caller ever
  /// holds a value to validate. The element that would take the set past the
  /// ceiling is where the read stops.
  ///
  /// Revert witness: derive the field plainly and a nine-entry document parses
  /// into a household `validate` then has to catch — after allocating every path.
  #[test]
  fn a_document_past_the_exclusion_ceiling_is_refused() {
    let cap = WatcherOptions::MAX_EXCLUSIONS;
    let list = |count: usize| {
      (0..count)
        .map(|n| format!("\"/x{n}\""))
        .collect::<Vec<_>>()
        .join(",")
    };

    let full: WatcherOptions =
      serde_json::from_str(&format!(r#"{{"exclusions": [{}]}}"#, list(cap)))
        .expect("the ceiling itself is honoured");
    assert_eq!(full.exclusions_slice().len(), cap);
    full.validate().expect("and it is an admissible household");

    let err =
      serde_json::from_str::<WatcherOptions>(&format!(r#"{{"exclusions": [{}]}}"#, list(cap + 1)))
        .expect_err("one past it is a document error");
    assert!(
      err.to_string().contains(&format!("{cap}")),
      "the refusal names the ceiling: {err}"
    );

    // The empty list is untouched: no exclusion is the default household.
    assert!(
      serde_json::from_str::<WatcherOptions>(r#"{"exclusions": []}"#)
        .expect("an empty list parses")
        .exclusions_slice()
        .is_empty()
    );
  }

  /// The per-path LENGTH ceiling, judged on the bytes the format is holding
  /// rather than after a `PathBuf` has been built out of them.
  ///
  /// The count ceiling above bounds nothing on its own: eight entries is a small
  /// number, and one of them can be as long as an untrusted document cares to make
  /// it. Deserializing straight into `PathBuf` handed the document one allocation
  /// of its own choosing per entry, paid in full before the household existed to
  /// run `validate` on.
  ///
  /// The refusal is asserted through its SHAPE — it names the length it measured
  /// and the ceiling — which is what a caller sees instead of an allocation.
  ///
  /// Revert witness: read the element as a plain `PathBuf` and the over-long first
  /// exclusion is owned before anything measures it; only `validate` would catch
  /// it, and only after the fact.
  #[test]
  fn an_over_long_exclusion_is_refused_before_its_path_is_built() {
    let cap = WatcherOptions::MAX_EXCLUSION_LEN;

    let full: WatcherOptions =
      serde_json::from_str(&format!(r#"{{"exclusions": ["{}"]}}"#, "x".repeat(cap)))
        .expect("the ceiling itself is honoured");
    assert_eq!(full.exclusions_slice()[0].as_os_str().len(), cap);
    full.validate().expect("and it is an admissible household");

    let err = serde_json::from_str::<WatcherOptions>(&format!(
      r#"{{"exclusions": ["{}"]}}"#,
      "x".repeat(cap + 1)
    ))
    .expect_err("one byte past it is a document error");
    let message = err.to_string();
    assert!(
      message.contains(&format!("{}", cap + 1)) && message.contains(&format!("{cap}")),
      "the refusal names the length it measured and the ceiling: {err}"
    );
  }

  /// The element past the SEAT is refused by its count, and is never read as a
  /// path at all — so an enormous ninth entry costs the refusal and nothing else.
  ///
  /// The two bounds are independent, and the order they are asked in is what makes
  /// the second one free: a count check taken after deserializing the ninth
  /// element still allocates the one entry the seat is certain to refuse. The
  /// ninth here is far past the LENGTH ceiling too, so whichever message comes
  /// back says which check ran.
  ///
  /// Revert witness: check the count after `next_element::<Exclusion>` and the
  /// refusal flips to the length message — the ninth path was read before anyone
  /// counted it.
  #[test]
  fn an_over_long_ninth_exclusion_is_refused_by_count() {
    let cap = WatcherOptions::MAX_EXCLUSIONS;
    let mut list = (0..cap).map(|n| format!("\"/x{n}\"")).collect::<Vec<_>>();
    list.push(format!(
      "\"{}\"",
      "x".repeat(WatcherOptions::MAX_EXCLUSION_LEN * 4)
    ));

    let err =
      serde_json::from_str::<WatcherOptions>(&format!(r#"{{"exclusions": [{}]}}"#, list.join(",")))
        .expect_err("the ninth element is refused");
    assert!(
      err.to_string().contains(&format!("limit of {cap}")),
      "the refusal is the seat's count, taken without reading the element as a path: {err}"
    );
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

  /// A bounded knob is refused BY THE DOCUMENT, not left for `validate` to catch —
  /// the value the builders would take is exactly the value a key will.
  ///
  /// This is the claim the key-by-key cell above makes for every bounded field;
  /// stated once here on the field whose out-of-range value used to load.
  #[test]
  fn deserializing_a_bounded_key_validates_it() {
    let refusal = serde_json::from_str::<WatcherOptions>(r#"{"latency": "10min"}"#)
      .map(|_| ())
      .expect_err("a ten-minute latency is past the ceiling and the key says so");
    assert!(
      refusal.to_string().contains("exceeds"),
      "the document names the ceiling: {refusal}"
    );
    // And the builder that would carry the same value still reaches the same
    // verdict through `validate` — one rule, both doors.
    assert_eq!(
      WatcherOptions::new()
        .with_latency(Duration::from_secs(600))
        .validate(),
      Err(OptionsError::LatencyTooLarge {
        supplied: Duration::from_secs(600)
      })
    );
  }

  /// The one knob a document may carry to any value is the one that HAS no range:
  /// `move_window`'s derivation saturates and caps for every input, so nothing
  /// judges its key and nothing needs to.
  #[test]
  fn the_unbounded_key_loads_whatever_it_names() {
    let parsed: WatcherOptions =
      serde_json::from_str(r#"{"move_window": "10min"}"#).expect("no rule refuses it");
    assert_eq!(parsed.move_window(), Duration::from_secs(600));
    parsed
      .validate()
      .expect("and validation has no opinion on it either");
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

  /// The default the CLAP face renders is the host platform's, taken from the
  /// same constant the constructor uses so the flag and the builder cannot drift.
  #[test]
  fn the_cookie_cap_flag_defaults_to_the_host_platform() {
    assert_eq!(
      parse(&[]).cookie_global_cap(),
      WatcherOptions::DEFAULT_COOKIE_GLOBAL_CAP
    );
    assert_eq!(
      parse(&[]).cookie_global_cap().get(),
      if cfg!(target_os = "macos") { 64 } else { 128 }
    );
    assert_eq!(
      parse(&["--cookie-global-cap", "7"])
        .cookie_global_cap()
        .get(),
      7,
      "and the flag is honoured when given"
    );
    assert!(
      Cli::try_parse_from(["app", "--cookie-global-cap", "0"]).is_err(),
      "zero is refused at the flag, as it is in the document"
    );
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

  /// Every bounded flag is judged WHERE THE VALUE IS WRITTEN: the bound itself
  /// parses, and one step past it is the flag's own `ValueValidation`.
  ///
  /// A flag with an unrestricted parser defers the refusal to `Watcher::new`, so a
  /// command line hears about the ceiling at the watcher rather than at the
  /// argument that carried it — and an application cannot read a successful parse
  /// as acceptance. The rule each flag is judged by is the very one
  /// [`WatcherOptions::validate`] asks.
  ///
  /// Revert witness: drop a flag's `value_parser` and its over-bound value parses
  /// into a household `validate` then has to catch.
  #[test]
  fn every_bounded_flag_accepts_its_bound_and_refuses_one_step_past_it() {
    /// A flag at its exact bound, the household that means, the same flag one step
    /// past the bound, and the words the refusal must carry.
    type Case = (
      &'static [&'static str],
      fn(WatcherOptions) -> WatcherOptions,
      &'static [&'static str],
      &'static str,
    );

    let cases: [Case; 7] = [
      (
        &["--latency", "60s"],
        |o| o.with_latency(WatcherOptions::MAX_LATENCY),
        &["--latency", "61s"],
        "exceeds",
      ),
      (
        &["--watcher-event-capacity", "1048576"],
        |o| o.with_event_capacity(WatcherOptions::MAX_EVENT_CAPACITY),
        &["--watcher-event-capacity", "1048577"],
        "exceeds",
      ),
      (
        &["--os-batch-capacity", "65536"],
        |o| o.with_os_batch_capacity(WatcherOptions::MAX_OS_BATCH_CAPACITY),
        &["--os-batch-capacity", "65537"],
        "exceeds",
      ),
      (
        &["--os-buffer-bytes", "1048576"],
        |o| o.with_os_buffer_bytes(WatcherOptions::MAX_OS_BUFFER_BYTES),
        &["--os-buffer-bytes", "1048577"],
        "outside",
      ),
      (
        &["--os-buffer-bytes", "4096"],
        |o| o.with_os_buffer_bytes(WatcherOptions::MIN_OS_BUFFER_BYTES),
        &["--os-buffer-bytes", "4095"],
        "outside",
      ),
      (
        &["--root-liveness-interval", "24h"],
        |o| o.with_root_liveness_interval(WatcherOptions::MAX_ROOT_LIVENESS_INTERVAL),
        &["--root-liveness-interval", "25h"],
        "exceeds",
      ),
      (
        &["--cookie-global-cap", "1024"],
        |o| o.with_cookie_global_cap(WatcherOptions::MAX_COOKIE_GLOBAL_CAP),
        &["--cookie-global-cap", "1025"],
        "exceeds",
      ),
    ];

    for (at_bound, expected, past_bound, words) in cases {
      let parsed = parse(at_bound);
      assert_eq!(parsed, expected(WatcherOptions::new()), "{at_bound:?}");
      parsed
        .validate()
        .unwrap_or_else(|err| panic!("{at_bound:?}: and it validates, got {err}"));

      let err = Cli::try_parse_from(std::iter::once("app").chain(past_bound.iter().copied()))
        .err()
        .unwrap_or_else(|| panic!("{past_bound:?} is refused"));
      assert_eq!(
        err.kind(),
        clap::error::ErrorKind::ValueValidation,
        "{past_bound:?}"
      );
      let rendered = err.render().to_string();
      assert!(
        rendered.contains(words),
        "{past_bound:?}: the refusal names the bound, got {rendered}"
      );
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

  /// And the ceiling, at the same flag: the occurrence past
  /// [`WatcherOptions::MAX_EXCLUSIONS`] is refused before the household is built.
  ///
  /// `--exclusions` repeats, and a programmatic `parse_from` can hand it an
  /// arbitrarily long iterator, so a face that reads the values into an owned list
  /// and measures it afterwards has already built what the bound exists to refuse.
  /// The count is asked of the matches, which own the values either way.
  ///
  /// Revert witness: drop the count check and the nine-flag row parses into a
  /// household `validate` then has to catch.
  #[test]
  fn an_over_full_exclusions_flag_is_refused() {
    let cap = WatcherOptions::MAX_EXCLUSIONS;
    let flags = |count: usize| {
      (0..count)
        .flat_map(|n| ["--exclusions".to_owned(), format!("/x{n}")])
        .collect::<Vec<_>>()
    };

    let full = Cli::parse_from(std::iter::once("app".to_owned()).chain(flags(cap))).options;
    assert_eq!(full.exclusions_slice().len(), cap, "the ceiling parses");
    full.validate().expect("and it is an admissible household");

    let err = Cli::try_parse_from(std::iter::once("app".to_owned()).chain(flags(cap + 1)))
      .err()
      .expect("one occurrence past the ceiling is refused");
    assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    assert!(
      err.render().to_string().contains(&format!("{cap}")),
      "the refusal names the ceiling: {}",
      err.render()
    );

    // An UPDATE is judged by the same rule, and by the same number.
    let matches = |rest: Vec<String>| {
      <WatcherOptions as clap::Args>::augment_args_for_update(clap::Command::new("app"))
        .try_get_matches_from(std::iter::once("app".to_owned()).chain(rest))
        .expect("the parse itself accepts repeated flags")
    };
    let mut options = WatcherOptions::new();
    assert!(
      clap::FromArgMatches::update_from_arg_matches(&mut options, &matches(flags(cap + 1)))
        .is_err(),
      "an over-full update is refused before it writes the household"
    );
    assert!(
      options.exclusions_slice().is_empty(),
      "and the household it refused is left exactly as it stood"
    );
  }

  /// The per-value LENGTH ceiling, at the same flag: a value longer than
  /// [`WatcherOptions::MAX_EXCLUSION_LEN`] is refused as the parse reads it,
  /// before any path is built and long before the household collects one.
  ///
  /// The occurrence count above bounds the number of paths, not their size, and a
  /// `parse_from` can hand this flag a value of any length at all. The refusal is
  /// the flag's own `ValueValidation`, naming the length it measured.
  ///
  /// Revert witness: drop the `value_parser` and the over-long value parses into a
  /// household `validate` then has to catch — after the path has been built.
  #[test]
  fn an_over_long_exclusion_value_is_refused() {
    let cap = WatcherOptions::MAX_EXCLUSION_LEN;

    let full = Cli::parse_from(["app", "--exclusions", &"x".repeat(cap)]).options;
    assert_eq!(
      full.exclusions_slice()[0].as_os_str().len(),
      cap,
      "the ceiling itself parses"
    );
    full.validate().expect("and it is an admissible household");

    let err = Cli::try_parse_from(["app", "--exclusions", &"x".repeat(cap + 1)])
      .err()
      .expect("one byte past the ceiling is refused");
    assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
    assert!(
      err.render().to_string().contains(&format!("{cap}")),
      "the refusal names the ceiling: {}",
      err.render()
    );

    // An UPDATE is judged at the same door, and one door EARLIER than the
    // occurrence count is: the value parser runs inside the parse, so an over-long
    // value never reaches the matches an update would read, let alone the
    // household it would have been written into.
    let refused =
      <WatcherOptions as clap::Args>::augment_args_for_update(clap::Command::new("app"))
        .try_get_matches_from(["app", "--exclusions", &"x".repeat(cap + 1)]);
    assert_eq!(
      refused
        .expect_err("an over-long update value is refused by the parse itself")
        .kind(),
      clap::error::ErrorKind::ValueValidation
    );
  }

  /// The full seat of in-range values is accepted on this face: eight paths, each
  /// at the length ceiling.
  ///
  /// Without it the two refusals above could be satisfied by a face that refuses
  /// everything.
  #[test]
  fn a_full_seat_of_in_range_exclusions_parses() {
    let value = "x".repeat(WatcherOptions::MAX_EXCLUSION_LEN);
    let mut args = vec!["app".to_owned()];
    for _ in 0..WatcherOptions::MAX_EXCLUSIONS {
      args.push("--exclusions".to_owned());
      args.push(value.clone());
    }

    let options = Cli::parse_from(args).options;
    assert_eq!(
      options.exclusions_slice().len(),
      WatcherOptions::MAX_EXCLUSIONS
    );
    options
      .validate()
      .expect("both ceilings are inclusive on every face");
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
    // One compiled pattern, cloned: the ceiling counts entries, not distinct
    // automatons, and cloning is an `Arc` pointer copy — 257 SEPARATELY
    // compiled globs cross 32-bit Miri's address-space limit.
    let many = |count: usize| {
      let pattern = glob("**/w");
      std::iter::repeat_n(pattern, count).collect::<std::vec::Vec<_>>()
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

  /// The programmatic face's own bound.
  ///
  /// The setters take `impl IntoIterator`, which is a caller's own iterator and
  /// need not terminate — so the ceiling cannot be enforced by measuring the seat
  /// after collecting it: `std::iter::repeat` would grow the crate-owned `Vec`
  /// until the process died, with `validate` never reached and the documented cap
  /// protecting nothing on the one face that has no document to refuse mid-read.
  ///
  /// So the setters take one item past the ceiling and stop. The three shapes that
  /// pins: the ceiling itself survives whole and validates; a finite over-cap list
  /// is refused exactly as before; and a non-terminating iterator RETURNS,
  /// retaining the same over-cap witness and earning the same refusal.
  ///
  /// Revert witness: collect the iterator plainly and the `repeat` legs never
  /// return.
  #[test]
  fn a_programmatic_seat_is_bounded_at_collection() {
    let cap = RootOptions::MAX_SEAT_PATTERNS;
    // One compiled pattern, cloned: the ceiling counts entries, not distinct
    // automatons, and cloning is an `Arc` pointer copy — 257 SEPARATELY
    // compiled globs cross 32-bit Miri's address-space limit.
    let many = |count: usize| {
      let pattern = glob("**/w");
      std::iter::repeat_n(pattern, count).collect::<std::vec::Vec<_>>()
    };
    let over = || std::iter::repeat(glob("**/w"));

    // The ceiling itself: kept whole, and legal.
    let full = RootOptions::new().with_prune(many(cap));
    assert_eq!(full.prune().len(), cap);
    assert_eq!(full.validate(), Ok(()), "the ceiling itself is honoured");

    // A finite list one past it: the refusal it always had.
    assert_eq!(
      RootOptions::new().with_prune(many(cap + 1)).validate(),
      Err(OptionsError::TooManyPrunePatterns { supplied: cap + 1 })
    );
    assert_eq!(
      RootOptions::new().with_include(many(cap + 1)).validate(),
      Err(OptionsError::TooManyIncludePatterns { supplied: cap + 1 })
    );

    // And an iterator that never ends: the setter RETURNS, holding one pattern
    // past the ceiling — the witness the same refusal is taken on.
    for (seat, options) in [
      ("prune", RootOptions::new().with_prune(over())),
      ("prune/set", {
        let mut options = RootOptions::new();
        options.set_prune(over());
        options
      }),
      ("include", RootOptions::new().with_include(over())),
      ("include/set", {
        let mut options = RootOptions::new();
        options.set_include(over());
        options
      }),
    ] {
      assert!(
        options.prune().len() <= cap + 1
          && options.include().is_none_or(|seat| seat.len() <= cap + 1),
        "{seat}: the seat is bounded whatever the iterator yields"
      );
      assert!(
        options.validate().is_err(),
        "{seat}: and the over-cap witness is refused where every other over-cap \
         seat is"
      );
    }
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

    /// A seat past the ceiling is a DOCUMENT error, refused mid-list rather than
    /// collected whole and measured afterwards.
    ///
    /// The bound is a resource bound, so a face that reads an untrusted length to
    /// the end before judging it has already paid what the bound exists to
    /// refuse: every pattern in the list compiles an automaton on the way in. The
    /// element that would take the seat past the ceiling is where the read stops.
    ///
    /// Revert witness: derive the two fields plainly and a 257-entry document
    /// parses into a household `validate` then has to catch — after compiling
    /// every one of them.
    #[test]
    fn a_document_past_the_pattern_ceiling_is_refused() {
      let cap = RootOptions::MAX_SEAT_PATTERNS;
      let list = |count: usize| {
        (0..count)
          .map(|n| std::format!("\"**/w{n}\""))
          .collect::<std::vec::Vec<_>>()
          .join(",")
      };

      let full: RootOptions =
        serde_json::from_str(&std::format!(r#"{{"prune": [{}]}}"#, list(cap)))
          .expect("the ceiling itself is honoured");
      assert_eq!(full.prune().len(), cap);

      let err =
        serde_json::from_str::<RootOptions>(&std::format!(r#"{{"prune": [{}]}}"#, list(cap + 1)))
          .expect_err("one past it is a document error");
      assert!(
        err.to_string().contains(&std::format!("{cap}")),
        "the refusal names the ceiling: {err}"
      );

      let err =
        serde_json::from_str::<RootOptions>(&std::format!(r#"{{"include": [{}]}}"#, list(cap + 1)))
          .expect_err("the include seat carries the same ceiling");
      assert!(err.to_string().contains(&std::format!("{cap}")), "{err}");

      // The seat's other two shapes are untouched: absent is the absent seat,
      // and an explicit empty list is the engaged one that admits nothing.
      assert_eq!(
        serde_json::from_str::<RootOptions>(r#"{}"#)
          .expect("an empty document parses")
          .include(),
        None
      );
      assert_eq!(
        serde_json::from_str::<RootOptions>(r#"{"include": []}"#)
          .expect("an empty seat parses")
          .include(),
        Some(&[][..])
      );
      assert_eq!(
        serde_json::from_str::<RootOptions>(r#"{"include": null}"#)
          .expect("an explicit null parses")
          .include(),
        None
      );
    }

    /// A WORD past the per-pattern length ceiling stops the seat at that word,
    /// before it collects — and before anything the size of the word is owned.
    ///
    /// The seat's own bound is on the COUNT, and it cannot see this one: a single
    /// first element is one element whatever its length. The per-pattern ceiling is
    /// the element's own face's, measured on the bytes the format is holding, and
    /// this is what says the seat inherits it rather than reading the list first.
    ///
    /// The word after it cannot compile, so the refusal proves WHERE the read
    /// stopped: a seat that had gone on would answer with that word's syntax error
    /// instead.
    ///
    /// Revert witness: deserialize each element through `String` first and the same
    /// refusal arrives after an allocation the document decided the size of.
    #[test]
    fn a_seat_word_past_the_length_ceiling_is_refused_at_the_word() {
      let over = "?".repeat(tributary_proto::glob::MAX_GLOB_LEN * 1024);
      let err = serde_json::from_str::<RootOptions>(&std::format!(
        r#"{{"prune": ["{over}", "[unclosed"]}}"#
      ))
      .expect_err("the first word is past the length ceiling");
      let rendered = err.to_string();
      assert!(
        rendered.contains(&std::format!(
          "over the {}-byte limit",
          tributary_proto::glob::MAX_GLOB_LEN
        )),
        "the refusal is the WORD's length: {rendered}"
      );
      assert!(
        !rendered.contains("unclosed"),
        "and the seat never reached the word after it: {rendered}"
      );
      assert!(
        rendered.len() < over.len() / 1024,
        "nothing the size of the word survives the refusal: {rendered}"
      );

      let err = serde_json::from_str::<RootOptions>(&std::format!(r#"{{"include": ["{over}"]}}"#))
        .expect_err("the include seat carries the same per-word ceiling");
      assert!(
        err.to_string().contains(&std::format!(
          "over the {}-byte limit",
          tributary_proto::glob::MAX_GLOB_LEN
        )),
        "{err}"
      );
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

    /// `--include` spells ALL THREE of the seat's states.
    ///
    /// The seat is `Option<Vec<Glob>>` and its three states mean three different
    /// policies: absent delivers every file, engaged-and-EMPTY delivers none
    /// (directories and `Rescan`s only), and engaged with patterns delivers what
    /// they name. A plain repeatable flag requires a value per occurrence, so the
    /// middle one — a documented policy the serde face and the programmatic builder
    /// can both express — had NO spelling at all here: omitting the flag gave the
    /// absent seat, `--include` with no value was a parse error, and every
    /// successful occurrence produced a non-empty list. `num_args = 0..=1` closes
    /// that, and appending is unchanged.
    ///
    /// An UPDATE keeps the command-line-only rule: a seat the command line did not
    /// name is left as it stood, and a bare `--include` SETS the empty seat rather
    /// than reading as "nothing given".
    ///
    /// Revert witness: drop `num_args` and the bare rows below fail at the parse.
    #[test]
    fn the_include_flag_spells_all_three_seat_states() {
      // ABSENT — every file.
      assert_eq!(parse(&[]).include(), None);

      // EMPTY — no file; directories and Rescans only.
      assert_eq!(
        parse(&["--include"]).include().map(patterns),
        Some(std::vec![]),
        "a bare --include is the engaged-but-EMPTY seat, not the absent one"
      );

      // NON-EMPTY — occurrences still append, in order.
      assert_eq!(
        parse(&["--include", "*.mp4", "--include", "*.mov"])
          .include()
          .map(patterns),
        Some(std::vec!["*.mp4", "*.mov"])
      );

      // UPDATE — the command-line-only rule, in both directions.
      let matches = |rest: &[&str]| {
        <RootOptions as clap::Args>::augment_args_for_update(clap::Command::new("app"))
          .get_matches_from(std::iter::once("app").chain(rest.iter().copied()))
      };
      let mut kept = RootOptions::new().with_include([glob("*.mp4")]);
      clap::FromArgMatches::update_from_arg_matches(&mut kept, &matches(&["--prune", "**/.git"]))
        .expect("the update applies");
      assert_eq!(
        kept.include().map(patterns),
        Some(std::vec!["*.mp4"]),
        "an unrelated flag leaves the seat exactly as it stood"
      );

      let mut emptied = RootOptions::new().with_include([glob("*.mp4")]);
      clap::FromArgMatches::update_from_arg_matches(&mut emptied, &matches(&["--include"]))
        .expect("the update applies");
      assert_eq!(
        emptied.include().map(patterns),
        Some(std::vec![]),
        "a bare --include on an update SETS the empty seat"
      );

      // OPTIONAL FLATTEN — a bare --include is a value source, so the household is
      // present.
      #[derive(Debug, clap::Parser)]
      struct OptionalCli {
        #[command(flatten)]
        options: Option<RootOptions>,
      }

      <OptionalCli as clap::CommandFactory>::command().debug_assert();
      assert_eq!(
        OptionalCli::parse_from(["app", "--include"])
          .options
          .expect("a bare --include makes the optional household present")
          .include()
          .map(patterns),
        Some(std::vec![])
      );
      assert!(
        OptionalCli::parse_from(["app"]).options.is_none(),
        "and nothing spelled is still no household"
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

    /// A seat past its ceiling is refused at the FLAG, and refused WITHOUT
    /// compiling the patterns it carries.
    ///
    /// The count is a property of the list, not of any pattern in it, so it can be
    /// answered before a single automaton exists — and it has to be, because a
    /// `parse_from` takes an arbitrarily long iterator and every value clap
    /// compiled on the way past is memory the ceiling was written to refuse.
    ///
    /// The pattern that would fail to compile sits AFTER the 256th, so the refusal
    /// this asserts can only be the count: a face that compiled as it parsed would
    /// answer with that pattern's own error instead, which is precisely the work
    /// this cell says never happens.
    ///
    /// Revert witness: parse the seats as `Vec<Glob>` again and the row below is
    /// refused for the unclosed bracket rather than for its length.
    #[test]
    fn an_over_full_seat_is_refused_before_it_compiles() {
      let cap = RootOptions::MAX_SEAT_PATTERNS;
      let flags = |flag: &str, count: usize, tail: Option<&str>| {
        (0..count)
          .flat_map(|n| [flag.to_owned(), std::format!("**/w{n}")])
          .chain(
            tail
              .into_iter()
              .flat_map(|tail| [flag.to_owned(), tail.to_owned()]),
          )
          .collect::<Vec<_>>()
      };
      let run =
        |args: Vec<String>| Cli::try_parse_from(std::iter::once("app".to_owned()).chain(args));

      // The ceiling itself parses, and compiles every one of its patterns.
      assert_eq!(
        run(flags("--prune", cap, None))
          .expect("the ceiling itself is honoured")
          .options
          .prune()
          .len(),
        cap
      );

      let err =
        run(flags("--prune", cap, Some("[unclosed"))).expect_err("one past the ceiling is refused");
      assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
      let rendered = err.render().to_string();
      assert!(
        rendered.contains(&std::format!("{cap}")),
        "the refusal is the COUNT, naming the ceiling: {rendered}"
      );
      assert!(
        !rendered.contains("invalid glob"),
        "and the pattern past the ceiling was never compiled: {rendered}"
      );

      // The include seat carries the same ceiling, through the same helper.
      let err =
        run(flags("--include", cap + 1, None)).expect_err("the include seat is bounded too");
      assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
      assert_eq!(
        run(flags("--include", cap, None))
          .expect("its ceiling is honoured too")
          .options
          .include()
          .map(<[Glob]>::len),
        Some(cap)
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

    /// The household composes as an OPTIONAL flatten, which is the one shape that
    /// needs a real arg group underneath it.
    ///
    /// clap decides `Some` from `None` by asking whether this household's
    /// `ArgGroup` was matched, and it asks for the group's id while BUILDING the
    /// command — panicking outright when there is none. Forwarding the proxy's own
    /// derived group would not do either: clap's derive leaves that group empty for
    /// any struct containing a nested flatten, and an empty group is never present,
    /// so every flag would parse and then be discarded.
    ///
    /// Both halves are asserted: the household is `None` when the caller spelled
    /// nothing of it, and `Some` — carrying the value — after ANY of its arguments,
    /// the nested interest flags included.
    ///
    /// Revert witness: drop `group_id` and this cell panics before it parses a
    /// single argument.
    #[test]
    fn an_optional_flatten_is_present_exactly_when_a_flag_was_given() {
      #[derive(Debug, clap::Parser)]
      struct Optional {
        #[arg(long)]
        unrelated: bool,
        #[command(flatten)]
        root: Option<RootOptions>,
      }

      let parse = |args: &[&str]| {
        Optional::parse_from(std::iter::once("app").chain(args.iter().copied())).root
      };

      assert_eq!(parse(&[]), None, "nothing of the household was spelled");
      assert_eq!(
        parse(&["--unrelated"]),
        None,
        "and another argument entirely does not conjure one"
      );

      // A direct argument.
      let pruned = parse(&["--prune", "**/node_modules"]).expect("a seat flag makes it present");
      assert_eq!(patterns(pruned.prune()), ["**/node_modules"]);
      assert_eq!(
        pruned.interest(),
        RootOptions::DEFAULT_INTEREST,
        "and the rest of the household is still its own default"
      );

      let included = parse(&["--include", "**/*.mp4"]).expect("the other seat too");
      assert_eq!(
        included.include().map(patterns),
        Some(std::vec!["**/*.mp4"])
      );

      // A NESTED argument — the half a forwarded derived group would have lost.
      for flag in [
        "--created",
        "--removed",
        "--modified",
        "--moved",
        "--attrib",
        "--ondir",
      ] {
        let narrowed =
          parse(&[flag]).unwrap_or_else(|| panic!("{flag} is a member of the household's group"));
        assert_ne!(
          narrowed.interest(),
          RootOptions::DEFAULT_INTEREST,
          "{flag} both makes the household present and narrows it"
        );
      }
      assert_eq!(
        parse(&["--created", "--moved"]).map(|root| root.interest()),
        Some(Interest::new().with_created().with_moved())
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
