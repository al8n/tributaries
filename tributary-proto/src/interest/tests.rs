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

  /// A misspelled or future kind name is refused rather than silently ignored — a
  /// typo must not parse as the EMPTY mask for the kind it meant to admit. The key
  /// is short enough to stay inside the bounded identifier visitor's own ceiling
  /// (the longest legal field name, `modified` at 8 bytes), so this is the JUNK
  /// KEY INSIDE THE BOUND cell: the vocabulary answers, naming it.
  #[test]
  fn an_unknown_key_is_refused() {
    let err = serde_json::from_str::<Interest>(r#"{"created": true, "future": true}"#)
      .expect_err("an unknown key is refused");
    assert!(
      err.to_string().contains("future"),
      "the error names the unknown key: {err}"
    );
  }

  /// The struct-key twin of the umbrella's own bounded delivery-kind tag: a
  /// rejected key past the bounded identifier visitor's ceiling costs a FIXED
  /// message and never an allocation proportional to its own size.
  #[test]
  fn an_over_long_unknown_key_is_refused_without_echoing_it() {
    let key: String = core::iter::repeat_n('z', 1024 * 1024).collect();
    let document = format!(r#"{{"{key}": true}}"#);
    let refusal = serde_json::from_str::<Interest>(&document)
      .expect_err("a key past the longest field name is refused")
      .to_string();

    assert!(
      refusal.contains("8-byte bound"),
      "the refusal names the bound: {refusal}"
    );
    assert!(
      refusal.contains(&key.len().to_string()),
      "and the length it measured: {refusal}"
    );
    assert!(
      !refusal.contains(&"z".repeat(9)),
      "and none of the key itself: {refusal}"
    );
  }

  /// A repeated key is refused rather than silently taking the last (or first)
  /// value — the same `duplicate_field` verdict the derive would give.
  #[test]
  fn a_duplicate_key_is_refused() {
    let err = serde_json::from_str::<Interest>(r#"{"created": true, "created": false}"#)
      .expect_err("a duplicate key is refused");
    assert!(err.to_string().contains("duplicate field"), "{err}");
  }

  #[test]
  fn the_wire_names_are_the_field_names() {
    let json = serde_json::to_value(Interest::all()).unwrap();
    for key in ["created", "removed", "modified", "moved", "attrib", "ondir"] {
      assert_eq!(json.get(key), Some(&serde_json::Value::Bool(true)), "{key}");
    }
  }

  /// The derived `Serialize` writes a non-self-describing format's struct as a
  /// plain SEQUENCE, not the map this face otherwise documents — the six
  /// fields' own values, read out of a self-describing document in their
  /// declaration order and driven through serde_json's array deserializer,
  /// exercise that same `visit_seq` arm a non-self-describing format's decoder
  /// would.
  #[test]
  fn a_full_value_round_trips_through_the_sequence_form() {
    const FIELDS: &[&str] = &["created", "removed", "modified", "moved", "attrib", "ondir"];

    fn round_trips(mask: Interest) {
      let json = serde_json::to_value(&mask).unwrap();
      let values: Vec<serde_json::Value> = FIELDS
        .iter()
        .map(|field| json.get(field).unwrap().clone())
        .collect();
      let parsed = serde_json::from_value::<Interest>(serde_json::Value::Array(values)).unwrap();
      assert_eq!(parsed, mask);
    }

    round_trips(Interest::all());
    round_trips(Interest::new().with_created().with_moved());
  }

  /// Postcard's own struct decoding has no length prefix to shorten (a short
  /// buffer is an EOF error, never a clean end of sequence), so the tail-default
  /// rule `visit_seq` carries is pinned directly against it through a
  /// hand-written `SeqAccess` that yields one element and then ends.
  #[test]
  fn a_short_sequence_defaults_the_tail() {
    /// Yields exactly one element (deserialized through `serde_json::Value`, so
    /// any field's shape can be produced without a second wire format) and then
    /// `None` for every call after.
    struct OneThenDone(Option<serde_json::Value>);

    impl<'de> serde::de::SeqAccess<'de> for OneThenDone {
      type Error = serde_json::Error;

      fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
      where
        T: serde::de::DeserializeSeed<'de>,
      {
        match self.0.take() {
          Some(value) => seed.deserialize(value).map(Some),
          None => Ok(None),
        }
      }
    }

    /// The one door back to the struct visitor's private `visit_seq`: every
    /// other `Deserializer` method is unreachable, since `Interest::deserialize`
    /// calls `deserialize_struct` directly and nothing it reads recurses back
    /// into a top-level deserializer.
    struct StructAsSeq(OneThenDone);

    impl<'de> serde::Deserializer<'de> for StructAsSeq {
      type Error = serde_json::Error;

      fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
      ) -> Result<V::Value, Self::Error>
      where
        V: serde::de::Visitor<'de>,
      {
        visitor.visit_seq(self.0)
      }

      fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
      where
        V: serde::de::Visitor<'de>,
      {
        unreachable!("this fixture only exercises deserialize_struct")
      }

      serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map enum identifier ignored_any
      }
    }

    let deserializer = StructAsSeq(OneThenDone(Some(serde_json::json!(true))));
    let parsed: Interest = serde::Deserialize::deserialize(deserializer).unwrap();
    assert_eq!(parsed, Interest::new().with_created());
  }
}

/// The `clap` face: one `--<field>` flag per bit, each defaulting to `false` and
/// each also taking an explicit boolean value (`--created`, `--created=true`,
/// `--created=false`).
#[cfg(feature = "clap")]
mod clap_face {
  use super::Interest;
  use clap::Parser as _;

  #[derive(Debug, clap::Parser)]
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

  /// `--<field>=true` is the same as the bare flag.
  #[test]
  fn an_explicit_true_value_sets_exactly_its_own_bit() {
    type Case = (&'static str, fn(Interest) -> Interest);

    let cases: [Case; 6] = [
      ("--created=true", |i| i.with_created()),
      ("--removed=true", |i| i.with_removed()),
      ("--modified=true", |i| i.with_modified()),
      ("--moved=true", |i| i.with_moved()),
      ("--attrib=true", |i| i.with_attrib()),
      ("--ondir=true", |i| i.with_ondir()),
    ];
    for (flag, expected) in cases {
      assert_eq!(parse(&[flag]), expected(Interest::new()), "{flag}");
    }
  }

  /// `--<field>=false` on a PARSE leaves that bit false, same as the flag being
  /// absent — and leaves every other bit false too, since the parse's value is
  /// the whole mask.
  #[test]
  fn an_explicit_false_value_leaves_the_bit_false_on_a_parse() {
    for flag in [
      "--created=false",
      "--removed=false",
      "--modified=false",
      "--moved=false",
      "--attrib=false",
      "--ondir=false",
    ] {
      assert_eq!(parse(&[flag]), Interest::new(), "{flag}");
    }
  }

  /// A bare flag followed by a separate token does not swallow that token as the
  /// value — `require_equals` makes only the `--flag=value` spelling attach a
  /// value, so a bare `--created` ahead of an unrelated flag parses both.
  #[test]
  fn a_bare_flag_does_not_consume_a_following_token_as_its_value() {
    assert_eq!(
      parse(&["--created", "--moved"]),
      Interest::new().with_created().with_moved()
    );
  }

  /// An UPDATE writes only the bits the command line NAMED.
  ///
  /// The flags are the whole value on a parse — what they do not name is the mask's
  /// `false` — but an update is handed a mask that already means something, and a
  /// derived one cannot tell a flag's own `false` default from a `false` someone asked
  /// for. So `--attrib` alone used to unsubscribe every other kind, and an update for
  /// an argument belonging to some other group in the same command emptied the mask
  /// outright.
  #[test]
  fn an_update_writes_only_the_bits_the_command_line_named() {
    use clap::{CommandFactory as _, FromArgMatches as _};

    fn matches(args: &[&str]) -> clap::ArgMatches {
      Cli::command_for_update().get_matches_from(std::iter::once("app").chain(args.iter().copied()))
    }

    // One named bit joins the mask; the five nobody named keep their values.
    let mut interest = Interest::new().with_created().with_moved();
    interest
      .update_from_arg_matches(&matches(&["--attrib"]))
      .expect("the update applies");
    assert_eq!(
      interest,
      Interest::new().with_created().with_moved().with_attrib()
    );

    // An update carrying no flag of this group at all leaves the mask untouched.
    interest
      .update_from_arg_matches(&matches(&[]))
      .expect("the update applies");
    assert_eq!(
      interest,
      Interest::new().with_created().with_moved().with_attrib(),
      "a flagless update is not the flagless PARSE — it states nothing, so it changes nothing"
    );

    // And the full mask survives one, bit for bit.
    let mut all = Interest::all();
    all
      .update_from_arg_matches(&matches(&[]))
      .expect("the update applies");
    assert_eq!(all, Interest::all());
  }

  /// `--<field>=false` on an UPDATE clears a bit a previous parse had set — the
  /// defect this group's flags were rewritten to fix — and leaves the bits the
  /// command line did not name exactly as they stood.
  #[test]
  fn an_update_with_an_explicit_false_clears_a_previously_set_bit() {
    use clap::{CommandFactory as _, FromArgMatches as _};

    fn matches(args: &[&str]) -> clap::ArgMatches {
      Cli::command_for_update().get_matches_from(std::iter::once("app").chain(args.iter().copied()))
    }

    let mut interest = Interest::all();
    interest
      .update_from_arg_matches(&matches(&["--created=false"]))
      .expect("the update applies");
    assert_eq!(
      interest,
      Interest::all().maybe_created(false),
      "created is cleared; every other bit stands"
    );
    assert!(!interest.created());
    assert!(
      interest.removed()
        && interest.modified()
        && interest.moved()
        && interest.attrib()
        && interest.ondir()
    );

    // Two explicit values in one update land on exactly those two bits.
    let mut interest = Interest::all();
    interest
      .update_from_arg_matches(&matches(&["--created=false", "--moved=false"]))
      .expect("the update applies");
    assert!(!interest.created());
    assert!(!interest.moved());
    assert!(interest.removed() && interest.modified() && interest.attrib() && interest.ondir());
  }

  /// The PARSE rule is unchanged: no flag at all is the empty mask, which is what
  /// makes the group's flags the whole value they are.
  #[test]
  fn the_flagless_parse_is_still_the_empty_mask() {
    assert_eq!(parse(&[]), Interest::new());
    assert!(parse(&[]).is_empty());
  }

  /// The value-taking rewrite (`ArgAction::Set`, `num_args = 0..=1`,
  /// `require_equals`) keeps the derived command structurally valid — ids,
  /// groups and conflicts all resolve. `--help` itself is not asserted here:
  /// this crate's `clap` dependency deliberately enables only `["std",
  /// "derive"]`, no `help` feature, since a library crate leaves help
  /// rendering to the binary that flattens its args in — asking this
  /// standalone `Cli` for `--help` fails with `UnknownArgument`, not
  /// `DisplayHelp`.
  #[test]
  fn the_derived_command_validates() {
    use clap::CommandFactory as _;

    Cli::command().debug_assert();
  }
}
