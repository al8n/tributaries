use super::*;

const fn ms(n: u64) -> Duration {
  Duration::from_millis(n)
}

#[test]
fn origin_is_zero() {
  assert_eq!(Instant::ORIGIN.elapsed_since_origin(), Duration::ZERO);
  assert_eq!(Instant::from_origin(Duration::ZERO), Instant::ORIGIN);
}

#[test]
fn from_origin_round_trips() {
  let t = Instant::from_origin(ms(250));
  assert_eq!(t.elapsed_since_origin(), ms(250));
}

#[test]
fn duration_since_in_order() {
  let a = Instant::from_origin(ms(100));
  let b = Instant::from_origin(ms(175));
  assert_eq!(b.duration_since(a), ms(75));
}

#[test]
fn duration_since_out_of_order_saturates() {
  let a = Instant::from_origin(ms(100));
  let b = Instant::from_origin(ms(40));
  assert_eq!(b.duration_since(a), Duration::ZERO);
}

#[test]
fn add_advances() {
  let a = Instant::from_origin(ms(100));
  assert_eq!((a + ms(50)).elapsed_since_origin(), ms(150));
}

#[test]
fn add_saturates_at_max() {
  let a = Instant::from_origin(Duration::MAX);
  assert_eq!((a + ms(1)).elapsed_since_origin(), Duration::MAX);
}

#[test]
fn reached_is_inclusive() {
  let deadline = Instant::from_origin(ms(100));
  assert!(!Instant::from_origin(ms(99)).reached(deadline));
  assert!(Instant::from_origin(ms(100)).reached(deadline));
  assert!(Instant::from_origin(ms(101)).reached(deadline));
}

#[test]
fn ordering_matches_elapsed() {
  let a = Instant::from_origin(ms(1));
  let b = Instant::from_origin(ms(2));
  assert!(a < b);
  assert_eq!(a.min(b), a);
}
