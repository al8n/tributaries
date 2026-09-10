//! The per-subscription fan-out [`Interest`] mask — the umbrella-owned delivery gate
//! over the source-neutral [`EventKind`] vocabulary.

use crate::event::EventKind;

#[cfg(test)]
mod tests;

/// Which delivered [`EventKind`]s a subscription wants — the umbrella's **own**
/// per-subscription fan-out gate (design §5), one bit per maskable kind.
///
/// The umbrella owns this vocabulary exactly as it owns [`EventKind`]: it is
/// source-neutral, so a fully generic consumer never imports source-flavored flags.
/// Roots are always armed by the source's own **widest** policy (design §4) — an
/// interest narrows what is *delivered* to its subscription, never the underlying
/// source watch.
///
/// # Deliver-everything default
///
/// [`new`](Self::new) equals [`all`](Self::all): a watch delivers everything, and
/// **narrowing is the opt-in act** — matching [`Filter::all`](crate::Filter::all) as
/// the filter default. [`none`](Self::none) is the explicit empty gate (a Rescan-only
/// subscription).
///
/// # The gate applies to the PROJECTED kind
///
/// A [`Moved`](EventKind::Moved) is decomposed per subscriber *before* this gate runs
/// (design §5): a subscriber covering only the move's source sees a move-out — a
/// synthesized [`Removed`](EventKind::Removed), gated by [`removed`](Self::removed);
/// one covering only the destination sees a move-in — a synthesized
/// [`Created`](EventKind::Created), gated by [`created`](Self::created); only a
/// subscriber covering both endpoints sees the whole `Moved`, gated by
/// [`moved`](Self::moved). Endpoint semantics ride the projection, not extra bits.
///
/// # A [`Rescan`](EventKind::Rescan) is structurally unmaskable
///
/// There is no rescan bit: a coverage-loss signal must never be narrowed away, so
/// [`admits`](Self::admits) always admits it (and fan-out bypasses the gate for it
/// entirely, design §5/§7/§8). Even a [`none`](Self::none) subscription still receives
/// its `Rescan`s.
///
/// # Configuration faces
///
/// With the `serde` feature the mask is the **list of the kinds it admits** — a set,
/// spelled as the set it is, rather than four booleans a reader has to add up:
///
/// ```json
/// ["created", "modified", "removed", "moved"]
/// ```
///
/// A present list is exhaustive: what it does not name is gated away, so `[]` is
/// [`none`](Self::none) (Rescan-only) and the full list is [`all`](Self::all). An
/// ABSENT list is not the empty one — where an `Interest` is a field of a larger
/// household ([`WatchOptions`](crate::WatchOptions)) the household's own
/// `#[serde(default)]` supplies [`all`](Self::all), the deliver-everything default.
/// A name outside the vocabulary is an error rather than a silent no-op: a
/// misspelled kind would otherwise quietly stop being delivered.
///
/// With the `clap` feature it is a `clap::Args` group of one `--<kind>` flag per
/// bit. Every bit defaults to `true`, so the flagless command line is
/// [`all`](Self::all) and NARROWING is what a flag does — which is why each takes an
/// explicit value:
///
/// ```text
/// $ app --moved=false --removed=false
/// ```
///
/// An UPDATE (`clap::FromArgMatches::update_from_arg_matches`) narrows only the
/// bits the command line actually carried: updating an unrelated argument leaves
/// the mask as it stood, `--moved=false` alone clears exactly `moved`, and a
/// [`none`](Self::none) mask survives both — the flag defaults are what a PARSE
/// falls back to, never something an update writes over a caller's own gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Interest {
  created: bool,
  modified: bool,
  removed: bool,
  moved: bool,
}

/// The `clap` face of [`Interest`]: the same four flags the mask derived before,
/// kept in a proxy so the UPDATE can be written by hand. Every bit defaults to
/// `true`, which is what makes a flagless parse [`Interest::all`] — and exactly
/// what a derived update would write over an existing mask, since a defaulted
/// argument is indistinguishable there from a given one.
#[cfg(feature = "clap")]
#[derive(Debug, Clone, clap::Args)]
#[group(id = "Interest")]
struct InterestArgs {
  #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value_t = true)]
  created: bool,
  #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value_t = true)]
  modified: bool,
  #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value_t = true)]
  removed: bool,
  #[arg(long, action = clap::ArgAction::Set, num_args = 0..=1, require_equals = true, default_missing_value = "true", default_value_t = true)]
  moved: bool,
}

#[cfg(feature = "clap")]
impl Interest {
  /// The flag names, in field order — the ONE list, so a bit added to the mask
  /// cannot be forgotten by the update rule, nor by the arg group of a household
  /// that flattens these flags (an outer group must name every nested id, or the
  /// flag cannot make an optional household present).
  pub(crate) const FLAGS: [&'static str; 4] = ["created", "modified", "removed", "moved"];
}

#[cfg(feature = "clap")]
impl From<InterestArgs> for Interest {
  fn from(args: InterestArgs) -> Self {
    let InterestArgs {
      created,
      modified,
      removed,
      moved,
    } = args;
    Self {
      created,
      modified,
      removed,
      moved,
    }
  }
}

#[cfg(feature = "clap")]
impl clap::FromArgMatches for Interest {
  fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
    InterestArgs::from_arg_matches(matches).map(Into::into)
  }

  /// Sets each bit the COMMAND LINE actually spelled, and leaves every other one
  /// as it stood — one list of flags, so a bit added to the mask cannot be
  /// forgotten here.
  fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) -> Result<(), clap::Error> {
    for (flag, bit) in Self::FLAGS.into_iter().zip([
      &mut self.created,
      &mut self.modified,
      &mut self.removed,
      &mut self.moved,
    ]) {
      if let Some(given) = crate::options::command_line_value(matches, flag) {
        *bit = given;
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

/// The kind names the `serde` face spells an [`Interest`] with, in emission order —
/// the field order, which is also the order [`EventKind`] declares them in.
#[cfg(feature = "serde")]
const KIND_NAMES: [&str; 4] = ["created", "modified", "removed", "moved"];

/// The longest name in [`KIND_NAMES`], in bytes — the ceiling a tag is measured
/// against before anything is done with it. Derived from the vocabulary itself, so
/// a renamed or added kind moves it rather than leaving a stale literal behind.
#[cfg(feature = "serde")]
const MAX_KIND_NAME_LEN: usize = {
  let mut longest = 0;
  let mut index = 0;
  while index < KIND_NAMES.len() {
    if KIND_NAMES[index].len() > longest {
      longest = KIND_NAMES[index].len();
    }
    index += 1;
  }
  longest
};

/// Which bit one tag names — the seed's answer, so the `visit_seq` loop below sets
/// bits and this door does nothing but read names.
#[cfg(feature = "serde")]
enum KindBit {
  Created,
  Modified,
  Removed,
  Moved,
}

/// One tag, read as BORROWED text and measured before it is copied, compared or
/// echoed — in the mold of [`Glob`](crate::Glob)'s own pattern visitor.
///
/// A tag is a configuration value from an untrusted document, and this vocabulary
/// is four names of at most [`MAX_KIND_NAME_LEN`] bytes. Asking the format for an
/// owned `String` (a `Cow<'_, str>` is one: serde's blanket implementation always
/// builds the owned half) hands the document one allocation per tag before the
/// vocabulary it is about to fail is ever consulted — and formatting the tag into
/// an `unknown_variant` error then hands it a second one of the same size, live at
/// the same instant. A single megabyte-long unknown tag is therefore two megabytes
/// of live allocation to say "that is not one of four words".
///
/// So the ceiling is judged first, on the bytes the format is already holding, and
/// a tag past it is refused with a FIXED message naming the bound and the length —
/// never the value. What reaches `unknown_variant` is by construction at most
/// [`MAX_KIND_NAME_LEN`] bytes, so the echo it formats is bounded too.
///
/// What this does not bound is the FORMAT's own reading: a format that must
/// allocate to hand over a string — one unescaping `\u0041`, or reading from a
/// stream rather than a slice — allocates before any visitor is called, which is
/// its contract rather than something a `Deserialize` implementation can decline.
/// A document whose SIZE must be bounded is bounded by a limited reader on the
/// caller's side.
#[cfg(feature = "serde")]
struct KindName;

#[cfg(feature = "serde")]
impl<'de> serde::de::DeserializeSeed<'de> for KindName {
  type Value = KindBit;

  /// `deserialize_str` rather than `deserialize_string`: this door needs to READ
  /// the tag, not to own it, and the hint is what lets a format borrow straight out
  /// of its input instead of allocating a copy it would only be measured against.
  fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    deserializer.deserialize_str(self)
  }
}

#[cfg(feature = "serde")]
impl serde::de::Visitor<'_> for KindName {
  type Value = KindBit;

  fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    write!(
      f,
      "a delivery-kind name of at most {MAX_KIND_NAME_LEN} bytes"
    )
  }

  /// The one door, and the one every other arm reaches: `visit_borrowed_str` and
  /// `visit_string` are serde's own forwards to it, so text the format borrows out
  /// of its input is measured without being copied at all, and text the format
  /// already owns is measured before this face does anything with it.
  fn visit_str<E>(self, name: &str) -> Result<Self::Value, E>
  where
    E: serde::de::Error,
  {
    if name.len() > MAX_KIND_NAME_LEN {
      // The length, never the value: an over-long tag is exactly the input whose
      // echo is the hazard.
      return Err(E::custom(format_args!(
        "a delivery-kind name is at most {MAX_KIND_NAME_LEN} bytes, and this one is {}",
        name.len()
      )));
    }
    match name {
      "created" => Ok(KindBit::Created),
      "modified" => Ok(KindBit::Modified),
      "removed" => Ok(KindBit::Removed),
      "moved" => Ok(KindBit::Moved),
      other => Err(E::unknown_variant(other, &KIND_NAMES)),
    }
  }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Interest {
  /// The list of admitted kind names (see the type docs) — a set as a set.
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    use serde::ser::SerializeSeq as _;

    let bits = [self.created, self.modified, self.removed, self.moved];
    let mut seq = serializer.serialize_seq(Some(bits.iter().filter(|bit| **bit).count()))?;
    for (name, admitted) in KIND_NAMES.iter().zip(bits) {
      if admitted {
        seq.serialize_element(name)?;
      }
    }
    seq.end()
  }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Interest {
  /// A list of kind names, exhaustively: every kind it does not name is gated away.
  /// A name outside the vocabulary is refused rather than ignored.
  ///
  /// Each tag is read through a bounded borrowed-string visitor, which measures it
  /// against the longest name in the vocabulary on the bytes the format is already
  /// holding — before the tag is copied and before any error formats it. So an
  /// unknown tag costs a fixed message and nothing proportional to its size, and the
  /// `unknown_variant` echo this face does emit is over a value bounded by that
  /// ceiling.
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    struct KindList;

    impl<'de> serde::de::Visitor<'de> for KindList {
      type Value = Interest;

      fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("a list of delivery-kind names")
      }

      fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
      where
        A: serde::de::SeqAccess<'de>,
      {
        let mut interest = Interest::none();
        // `next_element_seed` rather than `next_element`: the seed is what carries
        // the bounded string visitor into the element, where `next_element` would
        // pick a `Deserialize` implementation (a `Cow<'_, str>`'s always owns) and
        // copy the tag before this face could measure it. See [`KindName`].
        while let Some(bit) = seq.next_element_seed(KindName)? {
          match bit {
            KindBit::Created => interest.set_created(),
            KindBit::Modified => interest.set_modified(),
            KindBit::Removed => interest.set_removed(),
            KindBit::Moved => interest.set_moved(),
          };
        }
        Ok(interest)
      }
    }

    deserializer.deserialize_seq(KindList)
  }
}

impl Interest {
  /// An interest subscribed to every kind — identical to [`all`](Self::all).
  ///
  /// The umbrella's posture is deliver-everything: narrowing is the opt-in act,
  /// matching [`Filter::all`](crate::Filter::all) as the filter default.
  #[inline]
  pub const fn new() -> Self {
    Self::all()
  }

  /// An interest subscribed to every kind.
  #[inline]
  pub const fn all() -> Self {
    Self {
      created: true,
      modified: true,
      removed: true,
      moved: true,
    }
  }

  /// The explicit empty interest: subscribed to no maskable kind — a **Rescan-only**
  /// subscription.
  ///
  /// Accepted, not rejected: the subscription still holds coverage and still receives
  /// every [`Rescan`](EventKind::Rescan) (which no interest can mask); every other
  /// kind is gated away.
  #[inline]
  pub const fn none() -> Self {
    Self {
      created: false,
      modified: false,
      removed: false,
      moved: false,
    }
  }

  /// Whether [`Created`](EventKind::Created) deliveries are wanted — including the
  /// synthesized move-IN projection of a [`Moved`](EventKind::Moved) whose destination
  /// alone the subscription covers (design §5).
  #[inline]
  pub const fn created(&self) -> bool {
    self.created
  }

  /// Whether [`Modified`](EventKind::Modified) deliveries are wanted.
  #[inline]
  pub const fn modified(&self) -> bool {
    self.modified
  }

  /// Whether [`Removed`](EventKind::Removed) deliveries are wanted — including the
  /// synthesized move-OUT projection of a [`Moved`](EventKind::Moved) whose source
  /// alone the subscription covers (design §5).
  #[inline]
  pub const fn removed(&self) -> bool {
    self.removed
  }

  /// Whether whole [`Moved`](EventKind::Moved) deliveries — both endpoints covered —
  /// are wanted (design §5).
  #[inline]
  pub const fn moved(&self) -> bool {
    self.moved
  }

  /// Whether this interest subscribes to every maskable kind ([`all`](Self::all)).
  #[inline]
  pub const fn is_all(&self) -> bool {
    self.created && self.modified && self.removed && self.moved
  }

  /// Whether this interest subscribes to no maskable kind ([`none`](Self::none)) — a
  /// Rescan-only subscription.
  #[inline]
  pub const fn is_none(&self) -> bool {
    !(self.created || self.modified || self.removed || self.moved)
  }

  /// Whether this interest admits a delivery of `kind` — the per-subscription fan-out
  /// gate (design §5). Every umbrella root is armed with the source's widest interest
  /// (design §4), so this narrows *delivery* only, never the source watch.
  ///
  /// The kind it sees is the already-**projected** one (projection happens before the
  /// gate, design §5): a move-out is a synthesized [`Removed`](EventKind::Removed)
  /// gated by [`removed`](Self::removed), a move-in a synthesized
  /// [`Created`](EventKind::Created) gated by [`created`](Self::created), and only a
  /// whole [`Moved`](EventKind::Moved) is gated by [`moved`](Self::moved).
  ///
  /// A [`Rescan`](EventKind::Rescan) is always admitted (though in practice it never
  /// reaches this gate — fan-out bypasses coverage, interest, and filter for a
  /// coverage-loss signal), and an unknown future kind is admitted conservatively
  /// rather than silently dropped.
  pub fn admits<C>(&self, kind: &EventKind<C>) -> bool {
    match kind {
      EventKind::Created => self.created,
      EventKind::Modified => self.modified,
      EventKind::Removed => self.removed,
      EventKind::Moved { .. } => self.moved,
      EventKind::Rescan => true,
      // `EventKind` is #[non_exhaustive]: a future variant must default to conservative
      // admission here, not a silent drop. Unreachable today only because the defining
      // crate matches its own enum exhaustively — the arm is the forward-compat default.
      #[allow(unreachable_patterns)]
      _ => true,
    }
  }
}

macro_rules! interest_flag {
  ($field:ident, $set:ident, $with:ident, $update:ident, $maybe:ident, $clear:ident) => {
    #[doc = concat!("Subscribes to `", stringify!($field), "` deliveries (sets it true).")]
    #[inline]
    pub const fn $set(&mut self) -> &mut Self {
      self.$field = true;
      self
    }

    #[doc = concat!("Returns this interest subscribed to `", stringify!($field), "` deliveries.")]
    #[inline]
    #[must_use]
    pub const fn $with(mut self) -> Self {
      self.$field = true;
      self
    }

    #[doc = concat!("Sets the `", stringify!($field), "` subscription to `value`.")]
    #[inline]
    pub const fn $update(&mut self, value: bool) -> &mut Self {
      self.$field = value;
      self
    }

    #[doc = concat!("Returns this interest with the `", stringify!($field), "` subscription set to `value`.")]
    #[inline]
    #[must_use]
    pub const fn $maybe(mut self, value: bool) -> Self {
      self.$field = value;
      self
    }

    #[doc = concat!("Clears the `", stringify!($field), "` subscription (sets it false).")]
    #[inline]
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
    modified,
    set_modified,
    with_modified,
    update_modified,
    maybe_modified,
    clear_modified
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
    moved,
    set_moved,
    with_moved,
    update_moved,
    maybe_moved,
    clear_moved
  );
}

impl Default for Interest {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}
