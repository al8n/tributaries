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

/// The `serde` face: a plain object of the field names, every key optional.
#[cfg(all(feature = "serde", feature = "std"))]
mod serde_face {
  use super::Interest;

  #[test]
  fn default_round_trips() {
    let json = serde_json::to_string(&Interest::default()).unwrap();
    assert_eq!(
      serde_json::from_str::<Interest>(&json).unwrap(),
      Interest::default()
    );
    let json = serde_json::to_string(&Interest::all()).unwrap();
    assert_eq!(
      serde_json::from_str::<Interest>(&json).unwrap(),
      Interest::all()
    );
  }

  /// A document naming ONE key leaves every other bit at the type's own default
  /// (the empty mask) — the struct-level `#[serde(default)]`.
  #[test]
  fn a_partial_document_defaults_every_absent_key() {
    let parsed: Interest = serde_json::from_str(r#"{"created": true}"#).unwrap();
    assert_eq!(parsed, Interest::new().with_created());
    assert!(parsed.created());
    assert!(!parsed.removed() && !parsed.modified() && !parsed.moved());
    assert!(!parsed.attrib() && !parsed.ondir());
  }

  /// Forward compatibility: no `deny_unknown_fields`, so a document written for a
  /// later vocabulary still loads.
  #[test]
  fn an_unknown_key_is_accepted() {
    let parsed: Interest =
      serde_json::from_str(r#"{"created": true, "some_future_kind": true}"#).unwrap();
    assert_eq!(parsed, Interest::new().with_created());
  }

  #[test]
  fn the_wire_names_are_the_field_names() {
    let json = serde_json::to_value(Interest::all()).unwrap();
    for key in ["created", "removed", "modified", "moved", "attrib", "ondir"] {
      assert_eq!(json.get(key), Some(&serde_json::Value::Bool(true)), "{key}");
    }
  }
}

/// The `clap` face: one `--<field>` flag per bit, each defaulting to `false`.
#[cfg(feature = "clap")]
mod clap_face {
  use super::Interest;
  use clap::Parser as _;

  #[derive(clap::Parser)]
  struct Cli {
    #[command(flatten)]
    interest: Interest,
  }

  fn parse(args: &[&str]) -> Interest {
    Cli::parse_from(std::iter::once("app").chain(args.iter().copied())).interest
  }

  #[test]
  fn no_flags_is_the_default() {
    assert_eq!(parse(&[]), Interest::default());
  }

  /// Each long flag sets EXACTLY its own bit.
  #[test]
  fn every_flag_sets_exactly_its_own_bit() {
    /// One flag and the bit it is expected to set.
    type Case = (&'static str, fn(Interest) -> Interest);

    let cases: [Case; 6] = [
      ("--created", |i| i.with_created()),
      ("--removed", |i| i.with_removed()),
      ("--modified", |i| i.with_modified()),
      ("--moved", |i| i.with_moved()),
      ("--attrib", |i| i.with_attrib()),
      ("--ondir", |i| i.with_ondir()),
    ];
    for (flag, expected) in cases {
      assert_eq!(parse(&[flag]), expected(Interest::new()), "{flag}");
    }
  }

  #[test]
  fn flags_compose() {
    assert_eq!(
      parse(&["--created", "--moved", "--ondir"]),
      Interest::new().with_created().with_moved().with_ondir()
    );
  }
}
