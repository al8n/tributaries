use super::*;

#[test]
fn new_clears_everything() {
  let c = Capabilities::new();
  assert!(!c.supports_push());
  assert!(!c.atomic_create());
  assert!(!c.native_move());
  assert!(!c.versioned());
  assert!(!c.needs_poll());
  assert!(!c.kernel_recursive());
}

#[test]
fn default_equals_new() {
  assert_eq!(Capabilities::default(), Capabilities::new());
}

#[test]
fn inotify_like_profile() {
  let c = Capabilities::new().with_supports_push().with_native_move();
  assert!(c.supports_push());
  assert!(c.native_move());
  assert!(!c.kernel_recursive());
}

#[test]
fn fsevents_like_profile() {
  let c = Capabilities::new()
    .with_supports_push()
    .with_native_move()
    .with_kernel_recursive();
  assert!(c.kernel_recursive());
  assert!(c.supports_push());
}

#[test]
fn set_chains_in_place() {
  let mut c = Capabilities::new();
  c.set_supports_push().set_kernel_recursive();
  assert!(c.supports_push());
  assert!(c.kernel_recursive());
}

#[test]
fn update_and_maybe_assign_raw() {
  let mut c = Capabilities::new();
  c.update_needs_poll(true);
  assert!(c.needs_poll());
  let c = Capabilities::new()
    .maybe_versioned(true)
    .maybe_atomic_create(false);
  assert!(c.versioned());
  assert!(!c.atomic_create());
}

#[test]
fn clear_resets() {
  let mut c = Capabilities::new().with_kernel_recursive();
  c.clear_kernel_recursive();
  assert!(!c.kernel_recursive());
}
