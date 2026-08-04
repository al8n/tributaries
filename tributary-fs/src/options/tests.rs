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
