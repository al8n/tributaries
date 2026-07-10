use super::Interest;
use crate::event::EventKind;

#[test]
fn new_equals_all_equals_default() {
  assert_eq!(Interest::new(), Interest::all());
  assert_eq!(Interest::default(), Interest::new());
  let i = Interest::new();
  assert!(i.is_all());
  assert!(!i.is_none());
  assert!(i.created() && i.modified() && i.removed() && i.moved());
}

#[test]
fn none_is_the_explicit_empty() {
  let i = Interest::none();
  assert!(i.is_none());
  assert!(!i.is_all());
  assert!(!i.created() && !i.modified() && !i.removed() && !i.moved());
}

/// `is_all` / `is_none` track every bit: flipping any single bit off `all()` (resp. on
/// `none()`) leaves a mask that is neither.
#[test]
fn is_all_and_is_none_track_every_bit() {
  let one_off = [
    Interest::all().maybe_created(false),
    Interest::all().maybe_modified(false),
    Interest::all().maybe_removed(false),
    Interest::all().maybe_moved(false),
  ];
  for i in one_off {
    assert!(!i.is_all(), "one bit cleared is no longer all: {i:?}");
    assert!(!i.is_none(), "three bits still set is not none: {i:?}");
  }
  let one_on = [
    Interest::none().with_created(),
    Interest::none().with_modified(),
    Interest::none().with_removed(),
    Interest::none().with_moved(),
  ];
  for i in one_on {
    assert!(!i.is_none(), "one bit set is no longer none: {i:?}");
    assert!(!i.is_all(), "one bit set is not all: {i:?}");
  }
}

#[test]
fn with_builders_chain() {
  let i = Interest::none().with_created().with_modified();
  assert!(i.created());
  assert!(i.modified());
  assert!(!i.removed());
  assert!(!i.moved());
}

#[test]
fn set_builders_chain_in_place() {
  let mut i = Interest::none();
  i.set_removed().set_moved();
  assert!(i.removed() && i.moved());
  assert!(!i.created() && !i.modified());
}

#[test]
fn update_and_maybe_assign_raw() {
  let mut i = Interest::all();
  i.update_created(false).update_moved(false);
  assert!(!i.created());
  assert!(!i.moved());
  assert!(i.modified() && i.removed());

  let i = Interest::none().maybe_modified(true).maybe_removed(false);
  assert!(i.modified());
  assert!(!i.removed());
}

#[test]
fn clear_resets() {
  let mut i = Interest::all();
  i.clear_created()
    .clear_modified()
    .clear_removed()
    .clear_moved();
  assert!(i.is_none());
}

/// Each maskable kind is admitted by exactly its own bit (design §5): a single-bit
/// interest admits its kind and rejects the other three — the whole `Moved` rides the
/// `moved` bit, never its endpoints' bits — while `all()` admits everything and
/// `none()` admits no maskable kind.
#[test]
fn admits_gates_each_maskable_kind_by_its_own_bit() {
  let kinds: [EventKind<u8>; 4] = [
    EventKind::Created,
    EventKind::Modified,
    EventKind::Removed,
    EventKind::Moved { from: vec![0] },
  ];
  let single_bit = [
    Interest::none().with_created(),
    Interest::none().with_modified(),
    Interest::none().with_removed(),
    Interest::none().with_moved(),
  ];
  for (i, interest) in single_bit.iter().enumerate() {
    for (k, kind) in kinds.iter().enumerate() {
      assert_eq!(
        interest.admits(kind),
        i == k,
        "single-bit interest {interest:?} vs kind {kind}: admitted iff its own bit"
      );
    }
  }
  for kind in &kinds {
    assert!(Interest::all().admits(kind), "all() admits {kind}");
    assert!(!Interest::none().admits(kind), "none() rejects {kind}");
  }
}

/// A `Rescan` is structurally unmaskable: no bit exists for it and even the empty
/// interest admits it — a coverage-loss signal is never narrowed away (design §5/§7/§8).
#[test]
fn rescan_is_always_admitted() {
  assert!(Interest::none().admits(&EventKind::<u8>::Rescan));
  assert!(Interest::all().admits(&EventKind::<u8>::Rescan));
  assert!(
    Interest::none()
      .with_created()
      .admits(&EventKind::<u8>::Rescan)
  );
}
