use super::*;

#[test]
fn new_is_empty() {
  let i = Interest::new();
  assert!(i.is_empty());
  assert!(!i.created());
  assert!(!i.removed());
  assert!(!i.modified());
  assert!(!i.moved());
  assert!(!i.attrib());
  assert!(!i.ondir());
}

#[test]
fn default_equals_new() {
  assert_eq!(Interest::default(), Interest::new());
}

#[test]
fn all_subscribes_to_everything() {
  let i = Interest::all();
  assert!(!i.is_empty());
  assert!(i.created() && i.removed() && i.modified() && i.moved() && i.attrib() && i.ondir());
}

#[test]
fn with_builders_chain() {
  let i = Interest::new().with_created().with_modified().with_ondir();
  assert!(i.created());
  assert!(i.modified());
  assert!(i.ondir());
  assert!(!i.removed());
}

#[test]
fn set_builders_chain_in_place() {
  let mut i = Interest::new();
  i.set_created().set_removed().set_moved();
  assert!(i.created() && i.removed() && i.moved());
  assert!(!i.modified());
}

#[test]
fn update_and_maybe_assign_raw() {
  let mut i = Interest::all();
  i.update_created(false).update_attrib(false);
  assert!(!i.created());
  assert!(!i.attrib());

  let i = Interest::new().maybe_modified(true).maybe_moved(false);
  assert!(i.modified());
  assert!(!i.moved());
}

#[test]
fn clear_resets() {
  let mut i = Interest::all();
  i.clear_created()
    .clear_removed()
    .clear_modified()
    .clear_moved()
    .clear_attrib();
  assert!(i.is_empty());
  i.clear_ondir();
  assert!(!i.ondir());
}

#[test]
fn ondir_does_not_affect_is_empty() {
  let i = Interest::new().with_ondir();
  assert!(i.is_empty());
  assert!(i.ondir());
}
