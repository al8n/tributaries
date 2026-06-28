use super::*;

const fn nz(n: u64) -> NonZeroU64 {
  NonZeroU64::new(n).expect("non-zero test value")
}

#[test]
fn new_get_as_u64_round_trip() {
  let id = WatchId::new(nz(42));
  assert_eq!(id.get(), nz(42));
  assert_eq!(id.as_u64(), 42);
}

#[test]
fn distinct_id_types_do_not_unify() {
  let w = WatchId::new(nz(1));
  let r = ReqId::new(nz(1));
  assert_eq!(w.as_u64(), r.as_u64());
}

#[test]
fn display_matches_inner() {
  use std::string::ToString;
  assert_eq!(ChangeId::new(nz(7)).to_string(), "7");
  assert_eq!(ScopeId::new(nz(99)).to_string(), "99");
}

#[test]
fn move_cookie_holds_value() {
  let c = MoveCookie::new(nz(0xDEAD_BEEF));
  assert_eq!(c.as_u64(), 0xDEAD_BEEF);
}

#[test]
fn sequence_starts_at_one_and_is_monotonic() {
  let mut seq = Sequence::new();
  assert_eq!(seq.mint().get(), 1);
  assert_eq!(seq.mint().get(), 2);
  assert_eq!(seq.mint().get(), 3);
}

#[test]
fn sequence_default_equals_new() {
  let mut a = Sequence::new();
  let mut b = Sequence::default();
  assert_eq!(a.mint(), b.mint());
}

#[test]
fn sequence_never_yields_zero() {
  let mut seq = Sequence::new();
  for _ in 0..1000 {
    assert!(seq.mint().get() != 0);
  }
}
