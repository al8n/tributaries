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
  assert_eq!(opts.max_map_directories(), None, "uncapped by default");
}

#[test]
fn builders_and_setters_agree() {
  let built = WatcherOptions::new()
    .with_latency(Duration::from_millis(20))
    .with_move_window(Duration::from_millis(300))
    .with_event_capacity(NonZeroUsize::new(8).unwrap())
    .with_os_batch_capacity(NonZeroUsize::new(4).unwrap())
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
