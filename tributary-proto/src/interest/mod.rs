//! The per-watch subscription mask.

/// What kinds of change a watch subscribes to.
///
/// The core hands an `Interest` to the driver in an
/// [`Action::Watch`](crate::Action::Watch); the driver lowers it to the
/// backend's native flags (`IN_*` for inotify, `FAN_*` for fanotify, the
/// FSEvents stream flags). A field set to `false` means "do not subscribe", but
/// note that some backends cannot mask individual kinds — the driver may deliver
/// a superset, which the core's delivery filter then narrows.
///
/// # Configuration faces
///
/// With the `serde` feature the mask is a plain object of its own field names,
/// every key optional and defaulted from [`Interest::new`] (the EMPTY mask), so a
/// document names only what it subscribes to. Unknown keys are rejected — a
/// misspelled kind name (`modifed` for `modified`) must not silently parse as
/// the EMPTY mask for that kind and drop the deliveries it was meant to admit.
///
/// ```json
/// { "created": true, "removed": true, "moved": true }
/// ```
///
/// It is deliberately NOT a list of kind names: [`ondir`](Self::ondir) is a
/// target-class modifier rather than an event subscription (see
/// [`is_empty`](Self::is_empty)), so a flat set of names would misrepresent it as a
/// kind.
///
/// With the `clap` feature it is a `clap::Args` group of one `--<field>` flag per
/// bit. Every bit defaults to `false`, so a bare flag SETS it and the flagless
/// command line is [`Interest::new`]. Each flag also takes an explicit boolean
/// value — bare `--created` (equivalent to `--created=true`) or `--created=false` —
/// so the mask can be spelled either way on a PARSE:
///
/// ```text
/// $ app --created --removed --moved --attrib=false
/// ```
///
/// An UPDATE (`clap::FromArgMatches::update_from_arg_matches`) sets each bit to the
/// value the command line actually named — true OR false — and leaves every other
/// one as it stood: a household updated for an unrelated argument keeps the
/// subscription it was carrying, and `--created=false` now reaches an existing
/// mask and clears that bit rather than being unreachable. That is not what the
/// flags mean on a PARSE — there they are the whole value, and the ones absent are
/// the mask's `false`s — but an update is handed an existing mask, and writing
/// `false` over a bit nobody mentioned would silently unsubscribe it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Interest {
  created: bool,
  removed: bool,
  modified: bool,
  moved: bool,
  attrib: bool,
  ondir: bool,
}

/// The `serde` face's `Deserialize` half, kept by hand rather than derived: a
/// document's KEY is read through a bounded identifier visitor, measured
/// against the longest legal field name before it is matched against this
/// household's own fields or echoed into an `unknown_field` refusal.
///
/// The identifier visitor `derive(Deserialize)` would otherwise generate hands
/// the WHOLE rejected key to that refusal's formatter, so an untrusted key of
/// unbounded length cost an allocation proportional to its own size — live at
/// the same instant as the copy the format made to read it — before the
/// six-word vocabulary it was about to fail was ever consulted. So the ceiling
/// is judged first, on the bytes the format is already holding: a key past it
/// is refused with a FIXED message naming the bound and the length, never the
/// key itself; a key within it is matched, or refused by `unknown_field`
/// exactly as the derive would. Every key is optional, defaulted from
/// [`Interest::new`] (the struct-level default the derive's own `default`
/// attribute read), and a repeated key is refused with `duplicate_field`.
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Interest {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    const FIELDS: &[&str] = &["created", "removed", "modified", "moved", "attrib", "ondir"];

    const MAX_FIELD_LEN: usize = {
      let mut longest = 0;
      let mut index = 0;
      while index < FIELDS.len() {
        if FIELDS[index].len() > longest {
          longest = FIELDS[index].len();
        }
        index += 1;
      }
      longest
    };

    enum Field {
      Created,
      Removed,
      Modified,
      Moved,
      Attrib,
      Ondir,
    }

    impl<'de> serde::Deserialize<'de> for Field {
      fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
      where
        D: serde::Deserializer<'de>,
      {
        struct FieldVisitor;

        impl serde::de::Visitor<'_> for FieldVisitor {
          type Value = Field;

          fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "a field name of at most {MAX_FIELD_LEN} bytes")
          }

          /// The one door, and the one every other text arm reaches:
          /// `visit_borrowed_str` and `visit_string` are serde's own forwards
          /// to it, so a key the format borrows out of its input is measured
          /// without being copied at all, and one the format already owns is
          /// measured before this face does anything with it.
          fn visit_str<E>(self, name: &str) -> Result<Self::Value, E>
          where
            E: serde::de::Error,
          {
            if name.len() > MAX_FIELD_LEN {
              // The length, never the value: an over-long key is exactly the
              // input whose echo is the hazard.
              return Err(E::custom(format_args!(
                "field name longer than the {MAX_FIELD_LEN}-byte bound ({} bytes)",
                name.len()
              )));
            }
            match name {
              "created" => Ok(Field::Created),
              "removed" => Ok(Field::Removed),
              "modified" => Ok(Field::Modified),
              "moved" => Ok(Field::Moved),
              "attrib" => Ok(Field::Attrib),
              "ondir" => Ok(Field::Ondir),
              _ => Err(E::unknown_field(name, FIELDS)),
            }
          }

          /// The bytes-identifier door a format reads when its key comes as
          /// raw bytes rather than `str` — bounded and echoed the same way
          /// [`visit_str`](Self::visit_str) is.
          fn visit_bytes<E>(self, name: &[u8]) -> Result<Self::Value, E>
          where
            E: serde::de::Error,
          {
            if name.len() > MAX_FIELD_LEN {
              return Err(E::custom(format_args!(
                "field name longer than the {MAX_FIELD_LEN}-byte bound ({} bytes)",
                name.len()
              )));
            }
            match name {
              b"created" => Ok(Field::Created),
              b"removed" => Ok(Field::Removed),
              b"modified" => Ok(Field::Modified),
              b"moved" => Ok(Field::Moved),
              b"attrib" => Ok(Field::Attrib),
              b"ondir" => Ok(Field::Ondir),
              // Fully qualified: this crate is `no_std` without the `std`
              // feature, and aliases `alloc` to the `std` name at the crate
              // root for exactly this reason (see `lib.rs`) rather than
              // bringing `String` into scope unqualified.
              _ => Err(E::unknown_field(
                &std::string::String::from_utf8_lossy(name),
                FIELDS,
              )),
            }
          }

          /// The identifier door a NON-self-describing format answers with —
          /// the field's declaration-order INDEX.
          fn visit_u64<E>(self, index: u64) -> Result<Self::Value, E>
          where
            E: serde::de::Error,
          {
            match index {
              0 => Ok(Field::Created),
              1 => Ok(Field::Removed),
              2 => Ok(Field::Modified),
              3 => Ok(Field::Moved),
              4 => Ok(Field::Attrib),
              5 => Ok(Field::Ondir),
              _ => Err(E::invalid_value(
                serde::de::Unexpected::Unsigned(index),
                &"a field index within Interest",
              )),
            }
          }
        }

        deserializer.deserialize_identifier(FieldVisitor)
      }
    }

    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
      type Value = Interest;

      fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("struct Interest")
      }

      fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
      where
        A: serde::de::MapAccess<'de>,
      {
        use serde::de::Error as _;

        let mut created = None;
        let mut removed = None;
        let mut modified = None;
        let mut moved = None;
        let mut attrib = None;
        let mut ondir = None;

        while let Some(key) = map.next_key::<Field>()? {
          match key {
            Field::Created => {
              if created.is_some() {
                return Err(A::Error::duplicate_field("created"));
              }
              created = Some(map.next_value()?);
            }
            Field::Removed => {
              if removed.is_some() {
                return Err(A::Error::duplicate_field("removed"));
              }
              removed = Some(map.next_value()?);
            }
            Field::Modified => {
              if modified.is_some() {
                return Err(A::Error::duplicate_field("modified"));
              }
              modified = Some(map.next_value()?);
            }
            Field::Moved => {
              if moved.is_some() {
                return Err(A::Error::duplicate_field("moved"));
              }
              moved = Some(map.next_value()?);
            }
            Field::Attrib => {
              if attrib.is_some() {
                return Err(A::Error::duplicate_field("attrib"));
              }
              attrib = Some(map.next_value()?);
            }
            Field::Ondir => {
              if ondir.is_some() {
                return Err(A::Error::duplicate_field("ondir"));
              }
              ondir = Some(map.next_value()?);
            }
          }
        }

        let default = Interest::default();
        Ok(Interest {
          created: created.unwrap_or(default.created),
          removed: removed.unwrap_or(default.removed),
          modified: modified.unwrap_or(default.modified),
          moved: moved.unwrap_or(default.moved),
          attrib: attrib.unwrap_or(default.attrib),
          ondir: ondir.unwrap_or(default.ondir),
        })
      }
    }

    deserializer.deserialize_struct("Interest", FIELDS, Visitor)
  }
}

/// The `clap` face of [`Interest`]: the same six flags the mask derived before,
/// kept in a proxy so the UPDATE can be written by hand. The group id is pinned to
/// the type's own name, so a command that flattens the group is unchanged.
///
/// Each flag takes an optional boolean value (`ArgAction::Set`, `num_args =
/// 0..=1`, `default_missing_value = "true"`), so `--created`, `--created=true` and
/// `--created=false` all parse; `require_equals` is set so the value, when given,
/// must be attached with `=` — a following bare token is never swallowed as the
/// flag's value, so `--created` ahead of an unrelated positional is unambiguous.
/// A value-taking flag with a parse default still always has a value present in
/// `ArgMatches`, which is why the derived update could not be kept: it asks
/// `contains_id`, and a default satisfies that exactly as a given flag does — the
/// hand-written update below reads the value's SOURCE instead.
#[cfg(feature = "clap")]
#[derive(Debug, Clone, clap::Args)]
#[group(id = "Interest")]
struct InterestArgs {
  #[arg(
    long,
    value_name = "BOOL",
    action = clap::ArgAction::Set,
    num_args = 0..=1,
    require_equals = true,
    default_missing_value = "true",
    default_value_t = false
  )]
  created: bool,
  #[arg(
    long,
    value_name = "BOOL",
    action = clap::ArgAction::Set,
    num_args = 0..=1,
    require_equals = true,
    default_missing_value = "true",
    default_value_t = false
  )]
  removed: bool,
  #[arg(
    long,
    value_name = "BOOL",
    action = clap::ArgAction::Set,
    num_args = 0..=1,
    require_equals = true,
    default_missing_value = "true",
    default_value_t = false
  )]
  modified: bool,
  #[arg(
    long,
    value_name = "BOOL",
    action = clap::ArgAction::Set,
    num_args = 0..=1,
    require_equals = true,
    default_missing_value = "true",
    default_value_t = false
  )]
  moved: bool,
  #[arg(
    long,
    value_name = "BOOL",
    action = clap::ArgAction::Set,
    num_args = 0..=1,
    require_equals = true,
    default_missing_value = "true",
    default_value_t = false
  )]
  attrib: bool,
  #[arg(
    long,
    value_name = "BOOL",
    action = clap::ArgAction::Set,
    num_args = 0..=1,
    require_equals = true,
    default_missing_value = "true",
    default_value_t = false
  )]
  ondir: bool,
}

#[cfg(feature = "clap")]
impl From<InterestArgs> for Interest {
  fn from(args: InterestArgs) -> Self {
    let InterestArgs {
      created,
      removed,
      modified,
      moved,
      attrib,
      ondir,
    } = args;
    Self {
      created,
      removed,
      modified,
      moved,
      attrib,
      ondir,
    }
  }
}

/// Whether the COMMAND LINE is where an argument's value came from — the one
/// question `ArgMatches::get_flag` cannot answer, since a boolean argument reads
/// `false` both when it was given as `false` and when it was never given at all.
#[cfg(feature = "clap")]
fn given_on_command_line(matches: &clap::ArgMatches, id: &str) -> bool {
  matches.value_source(id) == Some(clap::parser::ValueSource::CommandLine)
}

#[cfg(feature = "clap")]
impl clap::FromArgMatches for Interest {
  fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
    InterestArgs::from_arg_matches(matches).map(Into::into)
  }

  /// Sets each bit to the value the COMMAND LINE named — true or false — and
  /// leaves every other one as it stood — one list of flags, so a bit added to
  /// the mask cannot be forgotten here, and `--created=false` clears a bit an
  /// earlier parse had set.
  fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) -> Result<(), clap::Error> {
    for (flag, bit) in [
      ("created", &mut self.created),
      ("removed", &mut self.removed),
      ("modified", &mut self.modified),
      ("moved", &mut self.moved),
      ("attrib", &mut self.attrib),
      ("ondir", &mut self.ondir),
    ] {
      if given_on_command_line(matches, flag) {
        *bit = matches.get_flag(flag);
      }
    }
    Ok(())
  }
}

#[cfg(feature = "clap")]
impl clap::Args for Interest {
  fn group_id() -> Option<clap::Id> {
    InterestArgs::group_id()
  }

  fn augment_args(cmd: clap::Command) -> clap::Command {
    InterestArgs::augment_args(cmd)
  }

  fn augment_args_for_update(cmd: clap::Command) -> clap::Command {
    InterestArgs::augment_args_for_update(cmd)
  }
}

impl Interest {
  /// An empty interest: subscribed to nothing.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn new() -> Self {
    Self {
      created: false,
      removed: false,
      modified: false,
      moved: false,
      attrib: false,
      ondir: false,
    }
  }

  /// An interest subscribed to every change kind, including directory targets.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn all() -> Self {
    Self {
      created: true,
      removed: true,
      modified: true,
      moved: true,
      attrib: true,
      ondir: true,
    }
  }

  /// Whether create events are wanted.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn created(&self) -> bool {
    self.created
  }

  /// Whether remove events are wanted.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn removed(&self) -> bool {
    self.removed
  }

  /// Whether modify (content / data) events are wanted.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn modified(&self) -> bool {
    self.modified
  }

  /// Whether move / rename events are wanted.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn moved(&self) -> bool {
    self.moved
  }

  /// Whether attribute / metadata events are wanted.
  ///
  /// Maps to inotify `IN_ATTRIB`; without it chmod / chown / utime / xattr /
  /// link-count changes are silently dropped.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn attrib(&self) -> bool {
    self.attrib
  }

  /// Whether events whose target is a directory are wanted.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn ondir(&self) -> bool {
    self.ondir
  }

  /// Whether this interest subscribes to no events.
  ///
  /// [`ondir`](Self::ondir) is deliberately excluded: it is a target-class
  /// modifier (directory-vs-file routing), not an event subscription, so an
  /// interest with only `ondir` set still subscribes to nothing and is empty.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub const fn is_empty(&self) -> bool {
    !(self.created || self.removed || self.modified || self.moved || self.attrib)
  }
}

macro_rules! interest_flag {
  ($field:ident, $set:ident, $with:ident, $update:ident, $maybe:ident, $clear:ident) => {
    #[doc = concat!("Subscribes to `", stringify!($field), "` events (sets it true).")]
    #[cfg_attr(not(tarpaulin), inline(always))]
    pub const fn $set(&mut self) -> &mut Self {
      self.$field = true;
      self
    }

    #[doc = concat!("Returns this interest subscribed to `", stringify!($field), "` events.")]
    #[cfg_attr(not(tarpaulin), inline(always))]
    #[must_use]
    pub const fn $with(mut self) -> Self {
      self.$field = true;
      self
    }

    #[doc = concat!("Sets the `", stringify!($field), "` subscription to `value`.")]
    #[cfg_attr(not(tarpaulin), inline(always))]
    pub const fn $update(&mut self, value: bool) -> &mut Self {
      self.$field = value;
      self
    }

    #[doc = concat!("Returns this interest with the `", stringify!($field), "` subscription set to `value`.")]
    #[cfg_attr(not(tarpaulin), inline(always))]
    #[must_use]
    pub const fn $maybe(mut self, value: bool) -> Self {
      self.$field = value;
      self
    }

    #[doc = concat!("Clears the `", stringify!($field), "` subscription (sets it false).")]
    #[cfg_attr(not(tarpaulin), inline(always))]
    pub const fn $clear(&mut self) -> &mut Self {
      self.$field = false;
      self
    }
  };
}

impl Interest {
  interest_flag!(
    created,
    set_created,
    with_created,
    update_created,
    maybe_created,
    clear_created
  );
  interest_flag!(
    removed,
    set_removed,
    with_removed,
    update_removed,
    maybe_removed,
    clear_removed
  );
  interest_flag!(
    modified,
    set_modified,
    with_modified,
    update_modified,
    maybe_modified,
    clear_modified
  );
  interest_flag!(
    moved,
    set_moved,
    with_moved,
    update_moved,
    maybe_moved,
    clear_moved
  );
  interest_flag!(
    attrib,
    set_attrib,
    with_attrib,
    update_attrib,
    maybe_attrib,
    clear_attrib
  );
  interest_flag!(
    ondir,
    set_ondir,
    with_ondir,
    update_ondir,
    maybe_ondir,
    clear_ondir
  );
}

impl Default for Interest {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(test)]
mod tests;
