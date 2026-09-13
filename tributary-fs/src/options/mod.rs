//! Configuration for a [`Watcher`](crate::Watcher).

use std::{
  num::{NonZeroU32, NonZeroUsize},
  path::PathBuf,
  time::Duration,
};

use tributary_proto::{
  Interest,
  glob::{Glob, Globs},
};

use crate::os::Backend;

#[cfg(test)]
mod tests;

/// The FIXED message every face refuses an empty or relative exclusion with —
/// never the value itself, in the same mold as the duration-text faces.
#[cfg(any(feature = "serde", feature = "clap"))]
const EXCLUSION_NOT_ABSOLUTE_MESSAGE: &str =
  "an exclusion directory must be a non-empty absolute path";

/// Why a [`WatcherOptions`] value cannot be honored.
///
/// Every knob is a bounded quantity: an out-of-range value reaches unchecked
/// arithmetic, an eager allocation, or a cadence that silently never fires.
/// [`WatcherOptions::validate`] converts each such value into one of these
/// BEFORE a watcher exists, so a legal-but-extreme setting is a typed refusal at
/// construction rather than a panic (or a wrap) at some later use site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OptionsError {
  /// More exclusion paths than the OS honors.
  #[error(
    "{supplied} exclusion paths exceed the OS limit of {}",
    crate::os::MAX_EXCLUSIONS
  )]
  TooManyExclusions {
    /// How many exclusion paths the options carried.
    supplied: usize,
  },
  /// One exclusion path is longer than
  /// [`WatcherOptions::MAX_EXCLUSION_LEN`] bytes.
  #[error(
    "an exclusion path of {supplied} bytes exceeds the {}-byte ceiling",
    WatcherOptions::MAX_EXCLUSION_LEN
  )]
  ExclusionTooLong {
    /// How many bytes the offending path carried.
    supplied: usize,
  },
  /// One exclusion path is empty or not absolute
  /// ([`Path::is_absolute`](std::path::Path::is_absolute)).
  ///
  /// The driver's own exclusion test is a PREFIX test on lexically folded
  /// paths: an empty (or `.`-shaped) exclusion folds to the empty path, which
  /// is a prefix of every directory, so one stray value silently suppresses
  /// the whole root.
  #[error("exclusion at index {index} is empty or not absolute")]
  ExclusionNotAbsolute {
    /// The index of the offending exclusion within the list.
    index: usize,
  },
  /// The OS event-coalescing latency exceeds
  /// [`WatcherOptions::MAX_LATENCY`].
  #[error(
    "a coalescing latency of {supplied:?} exceeds the {:?} ceiling",
    WatcherOptions::MAX_LATENCY
  )]
  LatencyTooLarge {
    /// The latency the options carried.
    supplied: Duration,
  },
  /// The consumer event-channel capacity exceeds
  /// [`WatcherOptions::MAX_EVENT_CAPACITY`].
  #[error(
    "an event capacity of {supplied} exceeds the {} ceiling",
    WatcherOptions::MAX_EVENT_CAPACITY
  )]
  EventCapacityTooLarge {
    /// The capacity the options carried.
    supplied: NonZeroUsize,
  },
  /// The per-root OS-callback capacity exceeds
  /// [`WatcherOptions::MAX_OS_BATCH_CAPACITY`].
  #[error(
    "an OS batch capacity of {supplied} exceeds the {} ceiling",
    WatcherOptions::MAX_OS_BATCH_CAPACITY
  )]
  OsBatchCapacityTooLarge {
    /// The capacity the options carried.
    supplied: NonZeroUsize,
  },
  /// The native read-buffer size falls outside
  /// [`WatcherOptions::MIN_OS_BUFFER_BYTES`]`..=`[`WatcherOptions::MAX_OS_BUFFER_BYTES`].
  #[error(
    "an OS buffer of {supplied} bytes is outside {}..={}",
    WatcherOptions::MIN_OS_BUFFER_BYTES,
    WatcherOptions::MAX_OS_BUFFER_BYTES
  )]
  OsBufferBytesOutOfRange {
    /// The buffer size the options carried.
    supplied: NonZeroU32,
  },
  /// The root-liveness interval exceeds
  /// [`WatcherOptions::MAX_ROOT_LIVENESS_INTERVAL`].
  #[error(
    "a root-liveness interval of {supplied:?} exceeds the {:?} ceiling",
    WatcherOptions::MAX_ROOT_LIVENESS_INTERVAL
  )]
  RootLivenessIntervalTooLarge {
    /// The interval the options carried.
    supplied: Duration,
  },
  /// The unremoved-sync-marker ceiling exceeds
  /// [`WatcherOptions::MAX_COOKIE_GLOBAL_CAP`].
  #[error(
    "a cookie global cap of {supplied} exceeds the {} ceiling",
    WatcherOptions::MAX_COOKIE_GLOBAL_CAP
  )]
  CookieGlobalCapTooLarge {
    /// The cap the options carried.
    supplied: NonZeroUsize,
  },
  /// The per-root [`prune`](RootOptions::prune) seat carries more patterns than
  /// [`RootOptions::MAX_SEAT_PATTERNS`].
  #[error(
    "{supplied} prune patterns exceed the per-seat limit of {}",
    RootOptions::MAX_SEAT_PATTERNS
  )]
  TooManyPrunePatterns {
    /// How many patterns the seat carried — which a programmatic setter bounds
    /// at [`RootOptions::MAX_SEAT_PATTERNS`] + 1, so it is the length
    /// held rather than the length of whatever iterator was handed in.
    supplied: usize,
  },
  /// The per-root [`include`](RootOptions::include) seat carries more patterns
  /// than [`RootOptions::MAX_SEAT_PATTERNS`].
  #[error(
    "{supplied} include patterns exceed the per-seat limit of {}",
    RootOptions::MAX_SEAT_PATTERNS
  )]
  TooManyIncludePatterns {
    /// How many patterns the seat carried — which a programmatic setter bounds
    /// at [`RootOptions::MAX_SEAT_PATTERNS`] + 1, so it is the length
    /// held rather than the length of whatever iterator was handed in.
    supplied: usize,
  },
}

impl OptionsError {
  /// Whether this is [`TooManyExclusions`](Self::TooManyExclusions).
  #[inline]
  pub const fn is_too_many_exclusions(&self) -> bool {
    matches!(self, Self::TooManyExclusions { .. })
  }

  /// Whether this is [`ExclusionTooLong`](Self::ExclusionTooLong).
  #[inline]
  pub const fn is_exclusion_too_long(&self) -> bool {
    matches!(self, Self::ExclusionTooLong { .. })
  }

  /// Whether this is [`ExclusionNotAbsolute`](Self::ExclusionNotAbsolute).
  #[inline]
  pub const fn is_exclusion_not_absolute(&self) -> bool {
    matches!(self, Self::ExclusionNotAbsolute { .. })
  }

  /// Whether this is [`TooManyPrunePatterns`](Self::TooManyPrunePatterns).
  #[inline]
  pub const fn is_too_many_prune_patterns(&self) -> bool {
    matches!(self, Self::TooManyPrunePatterns { .. })
  }

  /// Whether this is [`TooManyIncludePatterns`](Self::TooManyIncludePatterns).
  #[inline]
  pub const fn is_too_many_include_patterns(&self) -> bool {
    matches!(self, Self::TooManyIncludePatterns { .. })
  }
}

/// The ceiling on the derived rename-pairing window. Deadline arithmetic
/// downstream (`now + window`) must stay finite for the process lifetime, and
/// a pairing window beyond a day is a configuration mistake, not a wish to be
/// honored.
pub(crate) const MAX_MOVE_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// The one derivation of the armed rename-pairing window, shared by the
/// public options and the driver config so the two can never drift: at least
/// `2 × latency + 50 ms`, saturating on extreme inputs, capped at
/// [`MAX_MOVE_WINDOW`].
pub(crate) fn derive_move_window(move_window: Duration, latency: Duration) -> Duration {
  move_window
    .max(
      latency
        .saturating_mul(2)
        .saturating_add(Duration::from_millis(50)),
    )
    .min(MAX_MOVE_WINDOW)
}

/// The ONE range rule behind every face of [`WatcherOptions::latency`]: a builder
/// is checked by [`validate`](WatcherOptions::validate) at construction, a document
/// by its deserializer, a flag by its parser — and all three ask this, so no door
/// can admit what another refuses.
///
/// A face that only PARSES an out-of-range value defers the refusal to
/// [`Watcher::new`](crate::Watcher::new), which means an application cannot read a
/// successful parse as acceptance: the configuration layer reports the document as
/// loaded and the watcher refuses it afterwards, with nothing left pointing at the
/// key that was wrong. Each checker below closes that gap for one knob.
const fn check_latency(latency: Duration) -> Result<Duration, OptionsError> {
  if latency.as_nanos() > WatcherOptions::MAX_LATENCY.as_nanos() {
    return Err(OptionsError::LatencyTooLarge { supplied: latency });
  }
  Ok(latency)
}

/// The same one rule for [`WatcherOptions::event_capacity`].
const fn check_event_capacity(capacity: NonZeroUsize) -> Result<NonZeroUsize, OptionsError> {
  if capacity.get() > WatcherOptions::MAX_EVENT_CAPACITY.get() {
    return Err(OptionsError::EventCapacityTooLarge { supplied: capacity });
  }
  Ok(capacity)
}

/// The same one rule for [`WatcherOptions::os_batch_capacity`].
const fn check_os_batch_capacity(capacity: NonZeroUsize) -> Result<NonZeroUsize, OptionsError> {
  if capacity.get() > WatcherOptions::MAX_OS_BATCH_CAPACITY.get() {
    return Err(OptionsError::OsBatchCapacityTooLarge { supplied: capacity });
  }
  Ok(capacity)
}

/// The same one rule for [`WatcherOptions::os_buffer_bytes`] — a RANGE rather than
/// a ceiling, so a buffer too small for one kernel record is refused at the same
/// door as one too large to allocate per root.
const fn check_os_buffer_bytes(bytes: NonZeroU32) -> Result<NonZeroU32, OptionsError> {
  if bytes.get() < WatcherOptions::MIN_OS_BUFFER_BYTES.get()
    || bytes.get() > WatcherOptions::MAX_OS_BUFFER_BYTES.get()
  {
    return Err(OptionsError::OsBufferBytesOutOfRange { supplied: bytes });
  }
  Ok(bytes)
}

/// The same one rule for [`WatcherOptions::root_liveness_interval`].
const fn check_root_liveness_interval(interval: Duration) -> Result<Duration, OptionsError> {
  if interval.as_nanos() > WatcherOptions::MAX_ROOT_LIVENESS_INTERVAL.as_nanos() {
    return Err(OptionsError::RootLivenessIntervalTooLarge { supplied: interval });
  }
  Ok(interval)
}

/// The same one rule for [`WatcherOptions::cookie_global_cap`].
const fn check_cookie_global_cap(cap: NonZeroUsize) -> Result<NonZeroUsize, OptionsError> {
  if cap.get() > WatcherOptions::MAX_COOKIE_GLOBAL_CAP.get() {
    return Err(OptionsError::CookieGlobalCapTooLarge { supplied: cap });
  }
  Ok(cap)
}

/// Configuration for a [`Watcher`](crate::Watcher).
///
/// [`new`](Self::new) returns the defaults; every knob has a `with_*` builder,
/// a `set_*` mutator, and a read accessor.
///
/// # Every knob is bounded
///
/// The builders are `const` and infallible, so a chain of them composes
/// anywhere; the range check is one explicit step, [`validate`](Self::validate),
/// which [`Watcher::new`](crate::Watcher::new) runs before it spawns anything.
/// Each ceiling names a value no downstream use site can carry — an eager
/// channel allocation, a native buffer length, a cadence that would never come
/// round — and a typed refusal at construction is the only honest answer to one.
///
/// A knob that is PARSED is judged where it is written rather than at the
/// watcher: every bounded field's `serde` key and `clap` flag ask the same range
/// rule [`validate`](Self::validate) asks, so a document or a command line that
/// parses is a household that constructs. Deferring the refusal would leave an
/// application unable to read a successful parse as acceptance — the
/// configuration layer would report the document loaded and the watcher would
/// refuse it afterwards, with nothing left pointing at the key that was wrong.
/// ([`move_window`](Self::move_window) is the one unbounded knob, for the reason
/// [`validate`](Self::validate) gives.)
///
/// # Configuration faces
///
/// With the `serde` feature the household is one object keyed by the field names.
/// Every key is optional: an absent one takes the value [`new`](Self::new) gives
/// it, so a document names only what it overrides, and an unknown key is rejected
/// (a typo in a key name must not silently drop the knob it was meant to set).
/// Durations are humantime text (`"10ms"`, `"2s"`), the capacities plain integers
/// (a `0` is refused — they are non-zero types), the exclusions plain paths,
/// `cookie_global_cap` a non-zero integer whose omitted default is the host
/// platform's, and `max_map_directories` either an integer cap or `null` for
/// uncapped.
///
/// ```json
/// {
///   "latency": "25ms",
///   "event_capacity": 4096,
///   "backend": "fanotify",
///   "exclusions": ["/repo/target"],
///   "max_map_directories": 250000
/// }
/// ```
///
/// The exclusion list and the duration keys (`latency`, `move_window`,
/// `root_liveness_interval`) carry ceilings of their own on this face, and all
/// bind WHILE the document is read rather than after it:
/// [`MAX_EXCLUSIONS`](Self::MAX_EXCLUSIONS) paths,
/// refused at the element past it, [`MAX_EXCLUSION_LEN`](Self::MAX_EXCLUSION_LEN)
/// bytes per path, and a duration's own byte ceiling, each refused on the bytes
/// the format is holding before a path or a value is built out of them. The
/// element past the exclusion-count ceiling is refused by its COUNT without
/// being read as a path at all, and an over-long duration is refused with a
/// fixed message naming the bound and the length before humantime ever parses
/// it. So neither an enormous entry nor an enormous list, nor an enormous
/// duration spelling, can spend the process's memory on a key no watcher would
/// accept.
///
/// Deserializing is otherwise exactly as unchecked as the builders are: it never
/// runs [`validate`](Self::validate). A configuration layer that wants a bad setting
/// refused where the setting is READ calls it on the loaded value — the same one
/// explicit step [`Watcher::new`](crate::Watcher::new) runs.
///
/// With the `clap` feature it is a `clap::Args` group of one `--<field>` flag
/// per knob, each defaulting to the same value [`new`](Self::new) gives it, so a
/// flagless command line is the default household. `--exclusions` repeats, once
/// per path, and carries both of the serde face's ceilings at the same door: a
/// value longer than [`MAX_EXCLUSION_LEN`](Self::MAX_EXCLUSION_LEN) bytes is
/// refused as the parse reads it, and the occurrence past
/// [`MAX_EXCLUSIONS`](Self::MAX_EXCLUSIONS) is refused before the household is
/// built. Every duration flag (`--latency`, `--move-window`,
/// `--root-liveness-interval`) carries the same byte ceiling the serde face
/// judges duration text against, refused with the same fixed message before
/// the value is parsed.
///
/// ```text
/// $ app --latency 25ms --watcher-event-capacity 4096 --backend fanotify \
///       --exclusions /repo/target --max-map-directories 250000
/// $ app --max-map-directories-unbounded      # no ceiling on the map
/// ```
///
/// ## The one flag that is not its field's name
///
/// [`event_capacity`](Self::event_capacity) is `--watcher-event-capacity`.
///
/// This household and the umbrella's own `TributariesOptions` both carry an
/// `event_capacity` — two different channels one level apart — and a command line
/// that flattens both (the shape a consumer configuring the whole stack has) cannot
/// carry the same flag twice: clap refuses a duplicate argument id outright. The
/// INNER, OS-layer household yields, so the flag a reader reaches for first,
/// `--event-capacity`, still means the outer channel it is named after.
///
/// The `serde` key is **unchanged** — a document nests the two households under
/// their own keys, so nothing there ever collides, and this exception is the CLI's
/// alone.
///
/// Uncapped (`max_map_directories = None`) has its own flag,
/// `--max-map-directories-unbounded`, conflicting with `--max-map-directories`
/// since a request for no ceiling and a request for a specific one cannot both
/// stand; a document format without a null literal still cannot express it, and
/// a caller on such a format says so in code.
///
/// The empty exclusion list has its own flag too, `--exclusions-none`,
/// conflicting with `--exclusions`: the latter requires a value per occurrence,
/// so no spelling of it names zero, and the empty list is otherwise reachable
/// only in code.
///
/// `--cookie-global-cap` is the one flag whose printed default is the HOST's rather
/// than a constant of this crate: 64 where the watcher is built for macOS and 128
/// elsewhere, because the descriptor budget a sync obligation is drawn against differs
/// by platform ([`DEFAULT_COOKIE_GLOBAL_CAP`](Self::DEFAULT_COOKIE_GLOBAL_CAP) carries
/// the arithmetic). The flag itself, and the range it accepts, are the same everywhere.
///
/// An UPDATE (`clap::FromArgMatches::update_from_arg_matches`) changes only the
/// knobs the command line actually carried: `--latency` alone leaves the backend,
/// the buffer size, the exclusions and both capacities exactly as they stood.
/// `--exclusions` REPLACES the list it updates — the flag repeats to spell a whole
/// list, and there is no spelling for "add one to what is already there" — so an
/// update that names it states the complete set of exclusion paths, and one that
/// does not name it leaves the existing set alone. `--exclusions-none` on the
/// command line clears the list to empty the same way; naming neither it nor
/// `--exclusions` leaves the existing list exactly as it stood.
/// `--max-map-directories-unbounded` on the command line clears an existing
/// cap; naming neither it nor `--max-map-directories` leaves the existing one
/// exactly as it stood.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, deny_unknown_fields))]
pub struct WatcherOptions {
  // The bounded durations keep humantime's SERIALIZER and take a deserializer
  // that reads the same text and then asks the shared range rule — `with` would
  // replace both halves, and the text form is not what is changing here.
  #[cfg_attr(
    feature = "serde",
    serde(
      serialize_with = "humantime_serde::serialize",
      deserialize_with = "de_latency"
    )
  )]
  latency: Duration,
  #[cfg_attr(
    feature = "serde",
    serde(
      serialize_with = "humantime_serde::serialize",
      deserialize_with = "de_move_window"
    )
  )]
  move_window: Duration,
  #[cfg_attr(feature = "serde", serde(deserialize_with = "de_event_capacity"))]
  event_capacity: NonZeroUsize,
  #[cfg_attr(feature = "serde", serde(deserialize_with = "de_os_batch_capacity"))]
  os_batch_capacity: NonZeroUsize,
  #[cfg_attr(feature = "serde", serde(deserialize_with = "de_os_buffer_bytes"))]
  os_buffer_bytes: NonZeroU32,
  #[cfg_attr(feature = "serde", serde(deserialize_with = "deserialize_exclusions"))]
  exclusions: Vec<PathBuf>,
  backend: Backend,
  #[cfg_attr(
    feature = "serde",
    serde(
      serialize_with = "humantime_serde::serialize",
      deserialize_with = "de_root_liveness_interval"
    )
  )]
  root_liveness_interval: Duration,
  max_map_directories: Option<usize>,
  #[cfg_attr(feature = "serde", serde(deserialize_with = "de_cookie_global_cap"))]
  cookie_global_cap: NonZeroUsize,
}

/// ONE exclusion path, read through a STRING VISITOR so
/// [`WatcherOptions::MAX_EXCLUSION_LEN`] is judged on the bytes the format is
/// already holding rather than after a `PathBuf` of the document's own choosing
/// has been built.
///
/// The distinction is the whole point of that ceiling, and it is the same one the
/// glob vocabulary draws ([`Glob`]'s own face): asking the format for an owned
/// path first hands the document control of one allocation per rejected entry — a
/// first exclusion of a few hundred megabytes costs exactly that before the bound
/// it is about to fail is ever consulted. The visitor takes the borrowed text and
/// measures it, so a refusal costs the typed message and nothing proportional to
/// the input.
///
/// What it does NOT bound is the FORMAT's own reading: a format that must allocate
/// to hand over a string — one unescaping `\u0041`, or reading from a stream
/// rather than a slice — still allocates the source once, before any visitor is
/// called. That is the format's contract; a document whose SIZE must be bounded is
/// bounded by a limited reader on the caller's side.
#[cfg(feature = "serde")]
struct Exclusion(PathBuf);

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Exclusion {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    struct Directory;

    impl serde::de::Visitor<'_> for Directory {
      type Value = Exclusion;

      fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
          f,
          "an exclusion directory of at most {} bytes",
          WatcherOptions::MAX_EXCLUSION_LEN
        )
      }

      /// The one door, and the one every other arm reaches: `visit_borrowed_str`
      /// and `visit_string` are serde's own forwards to it, so text the format
      /// borrows out of its input is measured without being copied at all, and
      /// text the format already owns is measured before a path is made of it.
      fn visit_str<E>(self, path: &str) -> Result<Self::Value, E>
      where
        E: serde::de::Error,
      {
        if path.len() > WatcherOptions::MAX_EXCLUSION_LEN {
          return Err(E::custom(format!(
            "an exclusion directory of {} bytes is over the {}-byte limit",
            path.len(),
            WatcherOptions::MAX_EXCLUSION_LEN
          )));
        }
        let path = PathBuf::from(path);
        if !path.is_absolute() {
          return Err(E::custom(EXCLUSION_NOT_ABSOLUTE_MESSAGE));
        }
        Ok(Exclusion(path))
      }
    }

    // `deserialize_str` rather than `deserialize_string`: this face needs to READ
    // the text, not to own it, and the hint is what lets a format borrow straight
    // out of its input instead of allocating a copy it would only be measured
    // against.
    deserializer.deserialize_str(Directory)
  }
}

/// Reads the exclusion set, refusing the element past
/// [`WatcherOptions::MAX_EXCLUSIONS`] rather than the list after it, and each
/// element's own length before the path is owned ([`Exclusion`]).
///
/// The refusal has to happen mid-sequence to mean anything: a document is an
/// untrusted length, and reading it whole so the count can be checked afterwards
/// has already allocated every path the bound exists to refuse — a streaming
/// document naming millions of exclusions costs the process its memory before the
/// caller has a value to run [`WatcherOptions::validate`] on. So the element that
/// would take the set past the ceiling is where this stops, with at most the
/// ceiling's worth of paths ever held.
///
/// And the ninth element is refused by COUNT, without being read as a path at all:
/// once the seat is full the sequence is probed with
/// [`IgnoredAny`](serde::de::IgnoredAny), which asks the format whether anything
/// follows and lets it skip whatever does. A count check taken AFTER deserializing
/// the ninth element would still allocate it — the one entry the bound is certain
/// to refuse, and the one an untrusted document would make enormous.
///
/// [`validate`](WatcherOptions::validate) keeps both checks for the programmatic
/// builders, which are the one face that hands a whole list over at once and can
/// therefore only be judged after it exists.
#[cfg(feature = "serde")]
fn deserialize_exclusions<'de, D>(deserializer: D) -> Result<Vec<PathBuf>, D::Error>
where
  D: serde::Deserializer<'de>,
{
  struct Exclusions;

  impl<'de> serde::de::Visitor<'de> for Exclusions {
    type Value = Vec<PathBuf>;

    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
      write!(
        f,
        "at most {} exclusion directories of at most {} bytes each",
        WatcherOptions::MAX_EXCLUSIONS,
        WatcherOptions::MAX_EXCLUSION_LEN
      )
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
      A: serde::de::SeqAccess<'de>,
    {
      use serde::de::Error as _;

      // The hint is a document's own claim, so it steers the allocation and never
      // the bound: capped at the ceiling, it cannot be used to ask for a
      // reservation nothing will fill.
      let hint = seq
        .size_hint()
        .unwrap_or(0)
        .min(WatcherOptions::MAX_EXCLUSIONS);
      let mut exclusions = Vec::with_capacity(hint);
      while exclusions.len() < WatcherOptions::MAX_EXCLUSIONS {
        let Some(exclusion) = seq.next_element::<Exclusion>()? else {
          return Ok(exclusions);
        };
        exclusions.push(exclusion.0);
      }
      if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
        return Err(A::Error::custom(format!(
          "more exclusion directories than the limit of {}",
          WatcherOptions::MAX_EXCLUSIONS
        )));
      }
      Ok(exclusions)
    }
  }

  deserializer.deserialize_seq(Exclusions)
}

/// The LENGTH bound on the command line, asked of each value as the parse reads it
/// — before a `PathBuf` is made of it and long before the household collects one.
///
/// `--exclusions` repeats, and a `parse_from` can hand it values of any length at
/// all, so a face that builds every path and measures the list afterwards has
/// already paid what the ceiling exists to refuse. A `value_parser` is where clap
/// lets a value be judged on the bytes it arrived as; the refusal it produces is
/// the flag's own [`ValueValidation`](clap::error::ErrorKind::ValueValidation),
/// naming the value the caller must shorten.
///
/// It measures the `OsString` rather than a `String` because a path need not be
/// UTF-8 on either platform, and requiring it here would refuse perfectly ordinary
/// directories the rest of this crate handles.
#[cfg(feature = "clap")]
fn bounded_exclusion() -> impl clap::builder::TypedValueParser<Value = PathBuf> {
  use clap::builder::TypedValueParser as _;

  clap::builder::OsStringValueParser::new().try_map(|value: std::ffi::OsString| {
    if value.len() > WatcherOptions::MAX_EXCLUSION_LEN {
      return Err(format!(
        "an exclusion directory of {} bytes is over the {}-byte limit",
        value.len(),
        WatcherOptions::MAX_EXCLUSION_LEN
      ));
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
      return Err(EXCLUSION_NOT_ABSOLUTE_MESSAGE.to_string());
    }
    Ok(path)
  })
}

/// The byte ceiling every duration TEXT is measured against before humantime
/// ever sees it — [`deserialize_bounded_duration`] on the serde face,
/// [`parse_bounded_duration`] on the clap face, both refusing anything past it
/// with a FIXED message naming the bound and the length, never the text.
///
/// Derived from the longest spelling these faces' durations plausibly need: a
/// value up to a day — the ceiling both [`WatcherOptions::MAX_ROOT_LIVENESS_INTERVAL`]
/// and [`MAX_MOVE_WINDOW`] hold to — spelled with every unit humantime knows
/// down to nanoseconds (`"23h 59m 59s 999ms 999us 999ns"`, under 30 bytes)
/// leaves more than double that as margin. 64 bytes is generous for any
/// legitimate value these faces admit and small enough that a rejected one
/// costs nothing worth measuring.
#[cfg(any(feature = "serde", feature = "clap"))]
const MAX_DURATION_TEXT_LEN: usize = 64;

/// The serde face of a bounded duration: reads the text through
/// `deserialize_str` — the door BORROWED text reaches without being copied,
/// and owned text reaches before anything is done with it (`visit_borrowed_str`
/// and `visit_string` are serde's own forwards to `visit_str`) — refuses
/// anything past [`MAX_DURATION_TEXT_LEN`] bytes with a fixed message naming
/// the bound and the length, never the text, and otherwise hands the (bounded)
/// text to `humantime::parse_duration`.
///
/// # Errors
///
/// The fixed over-length message past [`MAX_DURATION_TEXT_LEN`] bytes;
/// humantime's own error for text within the bound that is not a legal
/// duration spelling.
#[cfg(feature = "serde")]
fn deserialize_bounded_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
  D: serde::Deserializer<'de>,
{
  struct BoundedDuration;

  impl serde::de::Visitor<'_> for BoundedDuration {
    type Value = Duration;

    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
      write!(f, "duration text of at most {MAX_DURATION_TEXT_LEN} bytes")
    }

    fn visit_str<E>(self, text: &str) -> Result<Self::Value, E>
    where
      E: serde::de::Error,
    {
      if text.len() > MAX_DURATION_TEXT_LEN {
        return Err(E::custom(format_args!(
          "duration text longer than the {MAX_DURATION_TEXT_LEN}-byte bound ({} bytes)",
          text.len()
        )));
      }
      humantime::parse_duration(text).map_err(E::custom)
    }
  }

  deserializer.deserialize_str(BoundedDuration)
}

/// The clap face of the same bound: judged on the `&str` clap already holds,
/// before `humantime::parse_duration` is asked to read any of it. The bound
/// covers only what this crate owns — humantime's copy of the unknown unit
/// and the parse itself; clap's own `ValueValidation` diagnostic still
/// renders the offending value verbatim, and that echo, over argv clap
/// already holds, is out of reach of this bound.
///
/// # Errors
///
/// The fixed over-length message past [`MAX_DURATION_TEXT_LEN`] bytes;
/// humantime's own error for text within the bound that is not a legal
/// duration spelling.
#[cfg(feature = "clap")]
fn parse_bounded_duration(
  text: &str,
) -> Result<Duration, Box<dyn core::error::Error + Send + Sync>> {
  if text.len() > MAX_DURATION_TEXT_LEN {
    return Err(
      format!(
        "duration text longer than the {MAX_DURATION_TEXT_LEN}-byte bound ({} bytes)",
        text.len()
      )
      .into(),
    );
  }
  Ok(humantime::parse_duration(text)?)
}

/// The COUNT bound on the command line, asked of the OCCURRENCE COUNT before a
/// single path is taken out of the parse and into this crate's own list.
///
/// `--exclusions` repeats, so the count is taken over the matches clap has
/// already built: one pass over BORROWED values that clones nothing, which is
/// what lets the ninth occurrence be refused before the [`WatcherOptions`] this
/// parse is building holds any of them.
///
/// # What this bounds, and what nothing here can
///
/// It bounds what the CRATE owns: the household's own `Vec<PathBuf>`, and every
/// per-exclusion cost the watcher pays afterwards (the driver's copy of the list,
/// and the lexical prefix test each event and each walked directory is measured
/// against). That is the resource this ceiling exists for, and it is refused
/// before a single one of those is paid.
///
/// It does NOT bound clap's own retention, and no face of this kind can. clap 4
/// has no per-argument occurrence cap, and an [`Args`](clap::Args) implementation
/// never sees the raw iterator — only the caller's own
/// [`Command`](clap::Command) does — so by the time any hook of ours runs, the
/// matches already hold whatever argv the caller handed
/// [`parse_from`](clap::Parser::parse_from). For a real command line that is
/// bounded by the operating system (`ARG_MAX`); for a programmatic iterator it is
/// the caller's own memory, spent by the caller, before this crate is reached.
/// The `latency` key: a document is refused where the key is READ, with the same
/// verdict the builders get from [`WatcherOptions::validate`]. The humantime text
/// is parsed first (it is the key's spelling), then measured.
#[cfg(feature = "serde")]
fn de_latency<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
  D: serde::Deserializer<'de>,
{
  use serde::de::Error as _;

  check_latency(deserialize_bounded_duration(deserializer)?).map_err(D::Error::custom)
}

/// The `move_window` key: bounded the same way every other duration key is —
/// its TEXT is judged before humantime ever parses it — but with no range
/// rule after: [`validate`](WatcherOptions::validate) deliberately carries none
/// for this knob, since [`derive_move_window`] saturates and caps for every
/// input, so no value of it is out of range.
#[cfg(feature = "serde")]
fn de_move_window<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
  D: serde::Deserializer<'de>,
{
  deserialize_bounded_duration(deserializer)
}

/// The same, for the `root_liveness_interval` key.
#[cfg(feature = "serde")]
fn de_root_liveness_interval<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
  D: serde::Deserializer<'de>,
{
  use serde::de::Error as _;

  check_root_liveness_interval(deserialize_bounded_duration(deserializer)?)
    .map_err(D::Error::custom)
}

/// The same, for the `event_capacity` key.
#[cfg(feature = "serde")]
fn de_event_capacity<'de, D>(deserializer: D) -> Result<NonZeroUsize, D::Error>
where
  D: serde::Deserializer<'de>,
{
  use serde::{Deserialize as _, de::Error as _};

  check_event_capacity(NonZeroUsize::deserialize(deserializer)?).map_err(D::Error::custom)
}

/// The same, for the `os_batch_capacity` key.
#[cfg(feature = "serde")]
fn de_os_batch_capacity<'de, D>(deserializer: D) -> Result<NonZeroUsize, D::Error>
where
  D: serde::Deserializer<'de>,
{
  use serde::{Deserialize as _, de::Error as _};

  check_os_batch_capacity(NonZeroUsize::deserialize(deserializer)?).map_err(D::Error::custom)
}

/// The same, for the `os_buffer_bytes` key.
#[cfg(feature = "serde")]
fn de_os_buffer_bytes<'de, D>(deserializer: D) -> Result<NonZeroU32, D::Error>
where
  D: serde::Deserializer<'de>,
{
  use serde::{Deserialize as _, de::Error as _};

  check_os_buffer_bytes(NonZeroU32::deserialize(deserializer)?).map_err(D::Error::custom)
}

/// The same, for the `cookie_global_cap` key.
#[cfg(feature = "serde")]
fn de_cookie_global_cap<'de, D>(deserializer: D) -> Result<NonZeroUsize, D::Error>
where
  D: serde::Deserializer<'de>,
{
  use serde::{Deserialize as _, de::Error as _};

  check_cookie_global_cap(NonZeroUsize::deserialize(deserializer)?).map_err(D::Error::custom)
}

/// The `--latency` parser: the flag refuses out of range what
/// [`WatcherOptions::validate`] refuses at construction, so a command line hears
/// the ceiling where the value is written rather than at the watcher. The refusal
/// is the flag's own [`ValueValidation`](clap::error::ErrorKind::ValueValidation),
/// naming the argument that carried it.
#[cfg(feature = "clap")]
fn parse_latency(text: &str) -> Result<Duration, Box<dyn core::error::Error + Send + Sync>> {
  Ok(check_latency(parse_bounded_duration(text)?)?)
}

/// The same, for `--root-liveness-interval`.
#[cfg(feature = "clap")]
fn parse_root_liveness_interval(
  text: &str,
) -> Result<Duration, Box<dyn core::error::Error + Send + Sync>> {
  Ok(check_root_liveness_interval(parse_bounded_duration(text)?)?)
}

/// The same, for `--watcher-event-capacity`.
#[cfg(feature = "clap")]
fn parse_event_capacity(
  text: &str,
) -> Result<NonZeroUsize, Box<dyn core::error::Error + Send + Sync>> {
  Ok(check_event_capacity(text.parse()?)?)
}

/// The same, for `--os-batch-capacity`.
#[cfg(feature = "clap")]
fn parse_os_batch_capacity(
  text: &str,
) -> Result<NonZeroUsize, Box<dyn core::error::Error + Send + Sync>> {
  Ok(check_os_batch_capacity(text.parse()?)?)
}

/// The same, for `--os-buffer-bytes`.
#[cfg(feature = "clap")]
fn parse_os_buffer_bytes(
  text: &str,
) -> Result<NonZeroU32, Box<dyn core::error::Error + Send + Sync>> {
  Ok(check_os_buffer_bytes(text.parse()?)?)
}

/// The same, for `--cookie-global-cap`.
#[cfg(feature = "clap")]
fn parse_cookie_global_cap(
  text: &str,
) -> Result<NonZeroUsize, Box<dyn core::error::Error + Send + Sync>> {
  Ok(check_cookie_global_cap(text.parse()?)?)
}

#[cfg(feature = "clap")]
fn refuse_over_full_exclusions(matches: &clap::ArgMatches) -> Result<(), clap::Error> {
  let supplied = matches
    .get_many::<PathBuf>("exclusions")
    .map_or(0, Iterator::count);
  if supplied > WatcherOptions::MAX_EXCLUSIONS {
    return Err(clap::Error::raw(
      clap::error::ErrorKind::ValueValidation,
      format!(
        "more --exclusions directories than the limit of {}\n",
        WatcherOptions::MAX_EXCLUSIONS
      ),
    ));
  }
  Ok(())
}

/// The `clap` face of [`WatcherOptions`]: the same ten flags the household derived
/// before, kept in a proxy so the UPDATE can be written by hand (see
/// [`command_line_value`]). The group id is pinned to the household's own name, so a
/// command that flattens the group is unchanged.
#[cfg(feature = "clap")]
#[derive(Debug, Clone, clap::Args)]
#[group(id = "WatcherOptions")]
struct WatcherOptionsArgs {
  #[arg(
    long,
    value_parser = parse_latency,
    default_value = clap_duration_default(WatcherOptions::DEFAULT_LATENCY),
  )]
  latency: Duration,
  #[arg(
    long,
    value_parser = parse_bounded_duration,
    default_value = clap_duration_default(WatcherOptions::DEFAULT_MOVE_WINDOW),
  )]
  move_window: Duration,
  // The ONE flag that is not its field's name — see the type docs. Both the id and
  // the long form move: clap rejects a duplicate ID, so renaming only the long form
  // would leave the very collision this avoids.
  #[arg(
    id = "watcher_event_capacity",
    long = "watcher-event-capacity",
    value_parser = parse_event_capacity,
    default_value_t = WatcherOptions::DEFAULT_EVENT_CAPACITY,
  )]
  event_capacity: NonZeroUsize,
  #[arg(
    long,
    value_parser = parse_os_batch_capacity,
    default_value_t = WatcherOptions::DEFAULT_OS_BATCH_CAPACITY,
  )]
  os_batch_capacity: NonZeroUsize,
  #[arg(
    long,
    value_parser = parse_os_buffer_bytes,
    default_value_t = WatcherOptions::DEFAULT_OS_BUFFER_BYTES,
  )]
  os_buffer_bytes: NonZeroU32,
  #[arg(long, value_parser = bounded_exclusion())]
  exclusions: Vec<PathBuf>,
  /// The empty exclusion list — the one household value `--exclusions` cannot
  /// reach: it requires a value per occurrence, and there is no spelling of it
  /// that names zero. Conflicts with `--exclusions`, since a request for no
  /// exclusions and a request for specific ones cannot both stand.
  #[arg(long, conflicts_with = "exclusions")]
  exclusions_none: bool,
  #[arg(long, value_enum, default_value_t = WatcherOptions::DEFAULT_BACKEND)]
  backend: Backend,
  #[arg(
    long,
    value_parser = parse_root_liveness_interval,
    default_value = clap_duration_default(WatcherOptions::DEFAULT_ROOT_LIVENESS_INTERVAL),
  )]
  root_liveness_interval: Duration,
  #[arg(long, default_value = clap_default_max_map_directories())]
  max_map_directories: Option<usize>,
  /// No ceiling on the directories the map may hold — the kernel-recursive
  /// spawns take the tree as it is.
  ///
  /// The one household value `--max-map-directories` cannot reach: a cap is
  /// always a `Some`, so uncapped needs its own flag. Conflicts with
  /// `--max-map-directories`, since a request for no ceiling and a request for
  /// a specific one cannot both stand.
  #[arg(long, conflicts_with = "max_map_directories")]
  max_map_directories_unbounded: bool,
  #[arg(
    long,
    value_parser = parse_cookie_global_cap,
    default_value = clap_default(WatcherOptions::DEFAULT_COOKIE_GLOBAL_CAP.to_string()),
  )]
  cookie_global_cap: NonZeroUsize,
}

/// The value an argument carried, but ONLY when the COMMAND LINE is where it came
/// from — the one question `ArgMatches::get_one` cannot answer, because a DEFAULTED
/// argument reads there exactly like a given one.
///
/// It is what the hand-written updates in this module stand on. A derived update
/// asks `contains_id`, which a default satisfies, so it writes every flag default
/// over whatever the caller had already configured.
#[cfg(feature = "clap")]
fn command_line_value<T>(matches: &clap::ArgMatches, id: &str) -> Option<T>
where
  T: Clone + Send + Sync + 'static,
{
  if matches.value_source(id) != Some(clap::parser::ValueSource::CommandLine) {
    return None;
  }
  matches.get_one::<T>(id).cloned()
}

/// The same, for a repeatable argument: every value it carried, when the command
/// line is where they came from. A named list REPLACES the one it updates (see the
/// type docs).
#[cfg(feature = "clap")]
fn command_line_values<T>(matches: &clap::ArgMatches, id: &str) -> Option<Vec<T>>
where
  T: Clone + Send + Sync + 'static,
{
  if matches.value_source(id) != Some(clap::parser::ValueSource::CommandLine) {
    return None;
  }
  Some(
    matches
      .get_many::<T>(id)
      .into_iter()
      .flatten()
      .cloned()
      .collect(),
  )
}

#[cfg(feature = "clap")]
impl From<WatcherOptionsArgs> for WatcherOptions {
  fn from(args: WatcherOptionsArgs) -> Self {
    let WatcherOptionsArgs {
      latency,
      move_window,
      event_capacity,
      os_batch_capacity,
      os_buffer_bytes,
      exclusions,
      exclusions_none,
      backend,
      root_liveness_interval,
      max_map_directories,
      max_map_directories_unbounded,
      cookie_global_cap,
    } = args;
    Self {
      latency,
      move_window,
      event_capacity,
      os_batch_capacity,
      os_buffer_bytes,
      exclusions: if exclusions_none {
        Vec::new()
      } else {
        exclusions
      },
      backend,
      root_liveness_interval,
      max_map_directories: if max_map_directories_unbounded {
        None
      } else {
        max_map_directories
      },
      cookie_global_cap,
    }
  }
}

#[cfg(feature = "clap")]
impl clap::FromArgMatches for WatcherOptions {
  fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
    refuse_over_full_exclusions(matches)?;
    WatcherOptionsArgs::from_arg_matches(matches).map(Into::into)
  }

  /// Applies only what the COMMAND LINE said, leaving every other knob of the
  /// existing household exactly as it stood.
  ///
  /// Every knob here but `--exclusions` carries a flag default, and a derived
  /// update cannot tell a default from a given value: one `--latency` would reset
  /// the backend selection, the native buffer size, both capacities and the
  /// liveness interval to what a flagless command line means, silently discarding
  /// whatever the configuration layer had loaded.
  fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) -> Result<(), clap::Error> {
    refuse_over_full_exclusions(matches)?;
    if let Some(latency) = command_line_value(matches, "latency") {
      self.latency = latency;
    }
    if let Some(move_window) = command_line_value(matches, "move_window") {
      self.move_window = move_window;
    }
    if let Some(event_capacity) = command_line_value(matches, "watcher_event_capacity") {
      self.event_capacity = event_capacity;
    }
    if let Some(os_batch_capacity) = command_line_value(matches, "os_batch_capacity") {
      self.os_batch_capacity = os_batch_capacity;
    }
    if let Some(os_buffer_bytes) = command_line_value(matches, "os_buffer_bytes") {
      self.os_buffer_bytes = os_buffer_bytes;
    }
    // `--exclusions-none` and `--exclusions` conflict, so at most one of them is
    // ever given; naming neither leaves the existing list exactly as it stood.
    if command_line_value::<bool>(matches, "exclusions_none") == Some(true) {
      self.exclusions = Vec::new();
    } else if let Some(exclusions) = command_line_values(matches, "exclusions") {
      self.exclusions = exclusions;
    }
    if let Some(backend) = command_line_value(matches, "backend") {
      self.backend = backend;
    }
    if let Some(interval) = command_line_value(matches, "root_liveness_interval") {
      self.root_liveness_interval = interval;
    }
    // `--max-map-directories-unbounded` and `--max-map-directories` conflict, so
    // at most one of them is ever given; naming neither leaves the existing cap
    // exactly as it stood.
    if command_line_value::<bool>(matches, "max_map_directories_unbounded") == Some(true) {
      self.max_map_directories = None;
    } else if let Some(cap) = command_line_value::<usize>(matches, "max_map_directories") {
      self.max_map_directories = Some(cap);
    }
    if let Some(cap) = command_line_value::<NonZeroUsize>(matches, "cookie_global_cap") {
      self.cookie_global_cap = cap;
    }
    Ok(())
  }
}

#[cfg(feature = "clap")]
impl clap::Args for WatcherOptions {
  fn group_id() -> Option<clap::Id> {
    WatcherOptionsArgs::group_id()
  }

  fn augment_args(cmd: clap::Command) -> clap::Command {
    WatcherOptionsArgs::augment_args(cmd)
  }

  fn augment_args_for_update(cmd: clap::Command) -> clap::Command {
    WatcherOptionsArgs::augment_args_for_update(cmd)
  }
}

/// A flag default rendered from the constant it mirrors, so the flag and the
/// constructor can never drift.
#[cfg(feature = "clap")]
fn clap_default(text: String) -> clap::builder::OsStr {
  clap::builder::Str::from(text).into()
}

/// The humantime text of a `Duration` default — what a `--<duration-flag>` falls
/// back to, in the same spelling its `value_parser` reads.
#[cfg(feature = "clap")]
fn clap_duration_default(duration: Duration) -> clap::builder::OsStr {
  clap_default(humantime::format_duration(duration).to_string())
}

/// The clap default for [`WatcherOptions::max_map_directories`], derived from
/// [`WatcherOptions::DEFAULT_MAX_MAP_DIRECTORIES`] itself: a cap becomes the flag's
/// default text, and an uncapped default would leave the flag with no default at
/// all.
#[cfg(feature = "clap")]
fn clap_default_max_map_directories() -> clap::builder::Resettable<clap::builder::OsStr> {
  match WatcherOptions::DEFAULT_MAX_MAP_DIRECTORIES {
    Some(cap) => clap::builder::Resettable::Value(clap_default(cap.to_string())),
    None => clap::builder::Resettable::Reset,
  }
}

impl WatcherOptions {
  /// The default OS event-coalescing latency (10 ms — watchman's shipped
  /// default; raising it trades delivery lag for fewer kernel drops under
  /// churn).
  pub const DEFAULT_LATENCY: Duration = Duration::from_millis(10);

  /// The default rename-pairing window (comfortably above what the default
  /// latency makes physically necessary; see
  /// [`effective_move_window`](Self::effective_move_window)).
  pub const DEFAULT_MOVE_WINDOW: Duration = Duration::from_millis(150);

  /// The largest OS event-coalescing latency a watcher will start with (60 s).
  ///
  /// The latency is a coalescing window, not a timeout: past a minute it stops
  /// describing any delivery regime a consumer could want and only lifts the
  /// derived rename-pairing floor (`2 × latency + 50 ms`) toward the
  /// [`effective_move_window`](Self::effective_move_window) cap. Four orders of
  /// magnitude above [`DEFAULT_LATENCY`](Self::DEFAULT_LATENCY) is the widest
  /// setting that still names a real trade.
  pub const MAX_LATENCY: Duration = Duration::from_secs(60);

  /// The default capacity of the event channel handed to the consumer, in
  /// events.
  pub const DEFAULT_EVENT_CAPACITY: NonZeroUsize = NonZeroUsize::new(1024).unwrap();

  /// The largest consumer event-channel capacity (2^20 events).
  ///
  /// The channel is allocated EAGERLY at [`Watcher::new`](crate::Watcher::new),
  /// one slot per event: at 2^20 slots that is already a hundreds-of-megabytes
  /// buffer, and a capacity near `usize::MAX` is not a large buffer but an
  /// allocation-size overflow — a panic on 64-bit and an immediate one on the
  /// 32-bit targets.
  pub const MAX_EVENT_CAPACITY: NonZeroUsize = NonZeroUsize::new(1 << 20).unwrap();

  /// The default per-root capacity of the OS-callback channel, in callback
  /// batches.
  pub const DEFAULT_OS_BATCH_CAPACITY: NonZeroUsize = NonZeroUsize::new(64).unwrap();

  /// The largest per-root OS-callback capacity (2^16 batches).
  ///
  /// This budget is the ONLY memory bound on the source's unbounded queue, so a
  /// value large enough to never bind removes the bound rather than raising it:
  /// 2^16 in-flight batches of a full native buffer is already gigabytes per
  /// root.
  pub const MAX_OS_BATCH_CAPACITY: NonZeroUsize = NonZeroUsize::new(1 << 16).unwrap();

  /// The default native read-buffer size (64 KiB).
  pub const DEFAULT_OS_BUFFER_BYTES: NonZeroU32 = NonZeroU32::new(64 * 1024).unwrap();

  /// The smallest native read-buffer size (4 KiB) — below it a single
  /// variable-length record carrying a long name may not fit, and a buffer that
  /// cannot hold one record makes no progress.
  pub const MIN_OS_BUFFER_BYTES: NonZeroU32 = NonZeroU32::new(4 * 1024).unwrap();

  /// The largest native read-buffer size (1 MiB). The buffer is pinned for the
  /// kernel across every outstanding read — twice over on the double-buffered
  /// `ReadDirectoryChangesW` pump — so this ceiling is the largest per-root
  /// kernel-pinned footprint the crate will commit to.
  pub const MAX_OS_BUFFER_BYTES: NonZeroU32 = NonZeroU32::new(1024 * 1024).unwrap();

  /// The most exclusion directories the OS honors per root
  /// (`FSEventStreamSetExclusionPaths` accepts at most eight).
  ///
  /// The one constant every face measures against: the serde list stops at the
  /// element past it, the `--exclusions` flag at the occurrence past it, and
  /// [`validate`](Self::validate) at a list handed over whole.
  pub const MAX_EXCLUSIONS: usize = crate::os::MAX_EXCLUSIONS;

  /// The longest exclusion path this household will carry, in BYTES — `PATH_MAX`
  /// on every platform the crate supports, so a longer one names nothing any
  /// filesystem could resolve and no exclusion could ever match.
  ///
  /// The ceiling is a MEMORY bound rather than a taste one, and it is measured
  /// where the bytes arrive. An exclusion is a caller's configuration value,
  /// reachable from a JSON document or a command line, and eight of them is a
  /// small enough count that the COUNT alone bounds nothing: one entry of a few
  /// hundred megabytes costs exactly that, paid in full before a household exists
  /// to run [`validate`](Self::validate) on. So the serde face measures the bytes
  /// the format is holding before it builds a `PathBuf` out of them, the
  /// `--exclusions` flag refuses an over-long value before the household collects
  /// it, and `validate` keeps the same bound for a list assembled in code.
  pub const MAX_EXCLUSION_LEN: usize = 4096;

  /// The default per-root backend selection: [`Backend::Auto`] — resolved to
  /// the host's own primitive at the spawn barrier (Linux probes for
  /// fanotify-FILESYSTEM and falls back to inotify).
  pub const DEFAULT_BACKEND: Backend = Backend::Auto;

  /// The default periodic root-liveness interval (30 s) — the detection-latency
  /// bound for a root death no in-band signal reports in time. A
  /// `FAN_MARK_FILESYSTEM`-watched superblock unmounted out from under the watch
  /// emits NO kernel signal (the L4.1 finding), and an inotify root's
  /// `IN_DELETE_SELF` is queued only once the last reference to it drops, so a
  /// periodic root re-stat is what bounds both. FSEvents' `RootChanged` and both
  /// Windows backends' own fatal-source-error report on a lost root or volume
  /// arrive regardless of anything this crate holds, so those ignore this knob.
  /// See [`root_liveness_interval`](Self::root_liveness_interval).
  pub const DEFAULT_ROOT_LIVENESS_INTERVAL: Duration = Duration::from_secs(30);

  /// The largest periodic root-liveness interval (one day).
  ///
  /// The interval is armed as a deadline (`now + interval`) whose arithmetic
  /// SATURATES, so an enormous one does not crash — it silently arms a deadline
  /// that never fires, disabling the Linux profiles' out-of-band root-death
  /// detector while looking configured. [`Duration::ZERO`](Duration::ZERO) is
  /// how a caller says
  /// "disabled"; anything past a day is the accidental spelling of it, and gets
  /// a typed refusal instead. One day is also the ceiling
  /// [`effective_move_window`](Self::effective_move_window) stands on: deadline
  /// arithmetic stays meaningful only while it stays finite.
  pub const MAX_ROOT_LIVENESS_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

  /// The default fanotify/USN admission-map directory cap: one million
  /// directories. See [`max_map_directories`](Self::max_map_directories) for
  /// what exceeding it does and for the memory table it is derived from.
  pub const DEFAULT_MAX_MAP_DIRECTORIES: Option<usize> = Some(1_000_000);

  /// The default ceiling on unremoved sync markers across every root of one
  /// watcher — **64 on macOS, 128 everywhere else**.
  ///
  /// It bounds ADMISSION: at most this many sync obligations exist at once, and
  /// a [`sync_root`](crate::Watcher::sync_root) past it is refused
  /// `CleanupBacklog` until the cleanup drains. What makes it worth sizing per
  /// platform is that each obligation is also DESCRIPTORS, and the budget for
  /// those is not the same everywhere: macOS defaults to a 256-descriptor soft
  /// limit against 1024 elsewhere, and a kernel-recursive lowering (FSEvents) is
  /// the one that holds a target and a reserved-directory pin per barrier in
  /// flight, where a descending lowering (inotify) releases both at its door and
  /// keeps only the marker pin plus the obligation's OWN `CookieDir` descriptor
  /// — never a descriptor shared across obligations: a cache reused across
  /// syncs would answer for an earlier admission's `Replaced`/`CrossesMount`
  /// reading rather than this one's, so each obligation opens and holds its
  /// own, bounded by the per-scope backlog cap of 8.
  ///
  /// The watcher's sync door is sized from this in turn — at most `min(cap, 8)`
  /// concurrent samplings on macOS and `min(cap, 32)` elsewhere — so raising the
  /// cap widens both terms. Raise it only with the descriptor budget of the host
  /// in mind; lowering it is always safe and costs only admission throughput.
  #[cfg(target_os = "macos")]
  pub const DEFAULT_COOKIE_GLOBAL_CAP: NonZeroUsize = NonZeroUsize::new(64).unwrap();
  /// The default ceiling on unremoved sync markers across every root of one
  /// watcher — **64 on macOS, 128 everywhere else**.
  ///
  /// It bounds ADMISSION: at most this many sync obligations exist at once, and
  /// a [`sync_root`](crate::Watcher::sync_root) past it is refused
  /// `CleanupBacklog` until the cleanup drains. What makes it worth sizing per
  /// platform is that each obligation is also DESCRIPTORS, and the budget for
  /// those is not the same everywhere: macOS defaults to a 256-descriptor soft
  /// limit against 1024 elsewhere, and a kernel-recursive lowering (FSEvents) is
  /// the one that holds a target and a reserved-directory pin per barrier in
  /// flight, where a descending lowering (inotify) releases both at its door and
  /// keeps only the marker pin plus the obligation's OWN `CookieDir` descriptor
  /// — never a descriptor shared across obligations: a cache reused across
  /// syncs would answer for an earlier admission's `Replaced`/`CrossesMount`
  /// reading rather than this one's, so each obligation opens and holds its
  /// own, bounded by the per-scope backlog cap of 8.
  ///
  /// The watcher's sync door is sized from this in turn — at most `min(cap, 8)`
  /// concurrent samplings on macOS and `min(cap, 32)` elsewhere — so raising the
  /// cap widens both terms. Raise it only with the descriptor budget of the host
  /// in mind; lowering it is always safe and costs only admission throughput.
  #[cfg(not(target_os = "macos"))]
  pub const DEFAULT_COOKIE_GLOBAL_CAP: NonZeroUsize = NonZeroUsize::new(128).unwrap();

  /// The largest [`cookie_global_cap`](Self::cookie_global_cap) this crate
  /// accepts on any face.
  ///
  /// Sized against the same descriptor arithmetic the default is (the
  /// driver's own `sync_door_allowance` doc carries the full derivation):
  /// `cap`'s own dominant peak term is `cap × 2`
  /// on a descending profile, and that term alone must stay comfortably under
  /// the common 4096-descriptor budget most hosts carry, leaving room for the
  /// door's `× 4` and the walk term rather than consuming the whole table by
  /// itself. `1024 × 2 = 2048` — half of 4096 — is that room; nothing routes a
  /// value past this ceiling without a typed refusal
  /// ([`OptionsError::CookieGlobalCapTooLarge`]).
  pub const MAX_COOKIE_GLOBAL_CAP: NonZeroUsize = NonZeroUsize::new(1024).unwrap();

  /// The default options.
  #[inline]
  pub const fn new() -> Self {
    Self {
      latency: Self::DEFAULT_LATENCY,
      move_window: Self::DEFAULT_MOVE_WINDOW,
      event_capacity: Self::DEFAULT_EVENT_CAPACITY,
      os_batch_capacity: Self::DEFAULT_OS_BATCH_CAPACITY,
      os_buffer_bytes: Self::DEFAULT_OS_BUFFER_BYTES,
      exclusions: Vec::new(),
      backend: Self::DEFAULT_BACKEND,
      root_liveness_interval: Self::DEFAULT_ROOT_LIVENESS_INTERVAL,
      max_map_directories: Self::DEFAULT_MAX_MAP_DIRECTORIES,
      cookie_global_cap: Self::DEFAULT_COOKIE_GLOBAL_CAP,
    }
  }

  /// Checks every knob against its documented ceiling.
  ///
  /// [`Watcher::new`](crate::Watcher::new) runs this before it allocates or
  /// spawns anything, so a caller normally never calls it; it is public so a
  /// configuration layer can reject a bad setting where the setting is read,
  /// with the same verdict the watcher would give. A household that came from a
  /// document or a command line has already been judged by these very rules —
  /// each face asks the shared checker below — so this is a re-check there and
  /// the first check only for a programmatic builder.
  ///
  /// [`move_window`](Self::move_window) is deliberately absent: its derivation
  /// saturates and caps for EVERY input (see
  /// [`effective_move_window`](Self::effective_move_window)), so no value of it
  /// is out of range.
  ///
  /// # Errors
  ///
  /// The first knob found outside its range, as an [`OptionsError`].
  pub fn validate(&self) -> Result<(), OptionsError> {
    if self.exclusions.len() > Self::MAX_EXCLUSIONS {
      return Err(OptionsError::TooManyExclusions {
        supplied: self.exclusions.len(),
      });
    }
    if let Some(exclusion) = self
      .exclusions
      .iter()
      .find(|exclusion| exclusion.as_os_str().len() > Self::MAX_EXCLUSION_LEN)
    {
      return Err(OptionsError::ExclusionTooLong {
        supplied: exclusion.as_os_str().len(),
      });
    }
    if let Some(index) = self
      .exclusions
      .iter()
      .position(|exclusion| !exclusion.is_absolute())
    {
      return Err(OptionsError::ExclusionNotAbsolute { index });
    }
    // Each range rule is asked of the SHARED checker, which the serde
    // deserializers and the clap value parsers ask too — so a document or a
    // command line is refused where the value is written, and this validation and
    // those faces can never come to mean different things by the same number.
    check_latency(self.latency)?;
    check_event_capacity(self.event_capacity)?;
    check_os_batch_capacity(self.os_batch_capacity)?;
    check_os_buffer_bytes(self.os_buffer_bytes)?;
    check_root_liveness_interval(self.root_liveness_interval)?;
    check_cookie_global_cap(self.cookie_global_cap)?;
    Ok(())
  }

  /// The OS event-coalescing latency.
  #[inline]
  pub const fn latency(&self) -> Duration {
    self.latency
  }

  /// Returns these options with the OS event-coalescing latency set.
  #[inline]
  #[must_use]
  pub const fn with_latency(mut self, latency: Duration) -> Self {
    self.latency = latency;
    self
  }

  /// Sets the OS event-coalescing latency.
  #[inline]
  pub const fn set_latency(&mut self, latency: Duration) -> &mut Self {
    self.latency = latency;
    self
  }

  /// The requested rename-pairing window. The window actually armed is
  /// [`effective_move_window`](Self::effective_move_window).
  #[inline]
  pub const fn move_window(&self) -> Duration {
    self.move_window
  }

  /// Returns these options with the rename-pairing window set.
  #[inline]
  #[must_use]
  pub const fn with_move_window(mut self, move_window: Duration) -> Self {
    self.move_window = move_window;
    self
  }

  /// Sets the rename-pairing window.
  #[inline]
  pub const fn set_move_window(&mut self, move_window: Duration) -> &mut Self {
    self.move_window = move_window;
    self
  }

  /// The rename-pairing window actually armed: the two halves of one rename
  /// can legally arrive one latency window apart, so the effective window
  /// never falls below `2 × latency + 50 ms` of scheduling margin.
  ///
  /// Total for every input: the derivation saturates instead of overflowing,
  /// and the result is capped at one day — deadline arithmetic downstream
  /// must stay finite, and a pairing window beyond that is a configuration
  /// mistake, not a wish to be honored.
  #[inline]
  pub fn effective_move_window(&self) -> Duration {
    derive_move_window(self.move_window, self.latency)
  }

  /// The capacity of the event channel handed to the consumer, in events.
  ///
  /// A full channel never blocks the driver: the affected scope's epoch is
  /// bumped and a single dominating `Rescan` is parked until it fits (see
  /// [`Event::epoch`](crate::Event::epoch) for the consumer contract).
  #[inline]
  pub const fn event_capacity(&self) -> NonZeroUsize {
    self.event_capacity
  }

  /// Returns these options with the consumer event-channel capacity set.
  #[inline]
  #[must_use]
  pub const fn with_event_capacity(mut self, event_capacity: NonZeroUsize) -> Self {
    self.event_capacity = event_capacity;
    self
  }

  /// Sets the consumer event-channel capacity.
  #[inline]
  pub const fn set_event_capacity(&mut self, event_capacity: NonZeroUsize) -> &mut Self {
    self.event_capacity = event_capacity;
    self
  }

  /// The per-root capacity of the OS-callback channel, in callback batches —
  /// how MANY producer batches may be in flight at once, and nothing else.
  ///
  /// A full channel never blocks the OS callback: the batch is dropped and
  /// surfaces as a `Rescan` through the overflow machinery. The budget covers a
  /// batch's whole retention (queue residency plus whatever the core parks), so
  /// it is the one bound on an otherwise unbounded queue.
  ///
  /// Sizing the kernel's own read buffer is a separate question with a separate
  /// knob, [`os_buffer_bytes`](Self::os_buffer_bytes): a count of batches and a
  /// count of bytes answer to different limits, and deriving one from the other
  /// makes both wrong.
  #[inline]
  pub const fn os_batch_capacity(&self) -> NonZeroUsize {
    self.os_batch_capacity
  }

  /// Returns these options with the per-root OS-callback capacity set.
  #[inline]
  #[must_use]
  pub const fn with_os_batch_capacity(mut self, os_batch_capacity: NonZeroUsize) -> Self {
    self.os_batch_capacity = os_batch_capacity;
    self
  }

  /// Sets the per-root OS-callback capacity.
  #[inline]
  pub const fn set_os_batch_capacity(&mut self, os_batch_capacity: NonZeroUsize) -> &mut Self {
    self.os_batch_capacity = os_batch_capacity;
    self
  }

  /// The per-source native read buffer, in BYTES: how much of one kernel read
  /// the backend can take at a time.
  ///
  /// The buffer holds variable-length kernel records, so its size trades
  /// resident (kernel-pinned) memory for how much a single read can drain
  /// before the queue is consulted again. It never bounds delivery: a buffer too
  /// small for what the kernel has queued produces the backend's own overflow
  /// signal, which surfaces as a covering
  /// [`Rescan`](crate::EventKind::Rescan) like any other loss.
  ///
  /// Honored by every backend that reads kernel records into user space —
  /// inotify, fanotify, `ReadDirectoryChangesW`, and the USN journal. FSEvents
  /// hands the callback a decoded batch and owns its own buffering, so the knob
  /// is inert on macOS.
  ///
  /// A `NonZeroU32` because it is a native buffer length (the Windows APIs take
  /// a `DWORD`), which also puts the whole legal range inside a 32-bit `usize`.
  #[inline]
  pub const fn os_buffer_bytes(&self) -> NonZeroU32 {
    self.os_buffer_bytes
  }

  /// Returns these options with the per-source native read-buffer size set.
  #[inline]
  #[must_use]
  pub const fn with_os_buffer_bytes(mut self, os_buffer_bytes: NonZeroU32) -> Self {
    self.os_buffer_bytes = os_buffer_bytes;
    self
  }

  /// Sets the per-source native read-buffer size.
  #[inline]
  pub const fn set_os_buffer_bytes(&mut self, os_buffer_bytes: NonZeroU32) -> &mut Self {
    self.os_buffer_bytes = os_buffer_bytes;
    self
  }

  /// The load-shedding exclusion directories applied to every root, as a
  /// slice.
  ///
  /// Purely an optimization (at most [`MAX_EXCLUSIONS`](Self::MAX_EXCLUSIONS) of
  /// them, each at most [`MAX_EXCLUSION_LEN`](Self::MAX_EXCLUSION_LEN) bytes, both
  /// enforced by the two configuration faces as they parse and by
  /// [`Watcher::new`](crate::Watcher::new) for a list assembled in code);
  /// correctness never depends on them. Subtracting ground you do not care about
  /// is how you keep a build cache's churn from costing you watches, map entries
  /// and deliveries.
  ///
  /// # What an exclusion guarantees
  ///
  /// The reported tree is the root MINUS these subtrees, on EVERY backend:
  ///
  /// - no change at or under an exclusion is delivered; and
  /// - no coverage is established there — a per-directory backend never arms or
  ///   descends into an excluded directory, so excluded churn cannot consume the
  ///   watch, node or admission-map budget the rest of the tree is competing for.
  ///
  /// Matching is a SUBTREE test on the paths as supplied, not a name-prefix one:
  /// an exclusion of `/r/cache` covers `/r/cache` and everything below it, and
  /// leaves `/r/cached` fully reported.
  ///
  /// Where a backend can decide the whole subtree itself it does — macOS hands
  /// the set to the OS, Linux fanotify fences it out of its admission map — and
  /// where it cannot, the enforcement lives one layer up, in front of the
  /// coverage bookkeeping every remaining backend shares. The USN journal also
  /// keeps its own admission map and fences exclusions out of it, the same way
  /// fanotify does, but that is a budget optimization, not a stand-down: the
  /// final delivery call for it still comes from the shared layer, alongside
  /// inotify and RDCW. Which one resolved is not something a caller has to
  /// know.
  ///
  /// # The three carve-outs
  ///
  /// - The watched root's own death is never suppressed, even by an exclusion
  ///   covering the root itself: silencing the one signal that says the watch is
  ///   over would strand the caller.
  /// - A rename CROSSING the boundary is still reported. The object left (or
  ///   joined) the reported tree, and that is a real change to it: you always get
  ///   the half that lies inside the reported tree — as a rename where the
  ///   backend pairs the crossing atomically, otherwise as the removal or
  ///   creation the crossing amounts to from inside.
  /// - [`sync_root`](crate::Watcher::sync_root) refuses a cookie directory covered
  ///   by an exclusion ahead of writing anything, on every backend: a barrier
  ///   whose completion depends on an event this option forbids is a hang waiting
  ///   to happen.
  #[inline]
  pub fn exclusions_slice(&self) -> &[PathBuf] {
    self.exclusions.as_slice()
  }

  /// Returns these options with the exclusion directories set.
  ///
  /// Not checked here: an empty or relative element is refused only when
  /// [`validate`](Self::validate) runs (every [`Watcher`](crate::Watcher)
  /// constructor calls it before spawning anything), as
  /// [`OptionsError::ExclusionNotAbsolute`].
  #[inline]
  #[must_use]
  pub fn with_exclusions(mut self, exclusions: Vec<PathBuf>) -> Self {
    self.exclusions = exclusions;
    self
  }

  /// Sets the exclusion directories.
  ///
  /// Not checked here: an empty or relative element is refused only when
  /// [`validate`](Self::validate) runs (every [`Watcher`](crate::Watcher)
  /// constructor calls it before spawning anything), as
  /// [`OptionsError::ExclusionNotAbsolute`].
  #[inline]
  pub fn set_exclusions(&mut self, exclusions: Vec<PathBuf>) -> &mut Self {
    self.exclusions = exclusions;
    self
  }

  /// The per-root backend selection.
  ///
  /// [`Backend::Auto`] (the default) resolves to the host's own primitive
  /// inside the pre-start barrier — on Linux it probes for fanotify-FILESYSTEM
  /// per root and falls back to inotify at the first failing probe. An explicit
  /// variant pins one platform's primitive: forced-and-failing preconditions
  /// surface as a typed
  /// [`WatchRootError::Source`](crate::WatchRootError::Source) (never a silent
  /// fallback), and forcing a variant on a platform that does not own it fails
  /// the same way with [`SourceError::ForeignBackend`](crate::SourceError::ForeignBackend)
  /// (never a silent ignore).
  #[inline]
  pub const fn backend(&self) -> Backend {
    self.backend
  }

  /// Returns these options with the per-root backend selection set.
  #[inline]
  #[must_use]
  pub const fn with_backend(mut self, backend: Backend) -> Self {
    self.backend = backend;
    self
  }

  /// Sets the per-root backend selection.
  #[inline]
  pub const fn set_backend(&mut self, backend: Backend) -> &mut Self {
    self.backend = backend;
    self
  }

  /// The periodic root-liveness interval — the detection-latency bound for a
  /// root death the backend's own signal does not report in time.
  ///
  /// The driver re-stats such a root on this cadence and lowers its death (a
  /// terminal [`Rescan`](crate::EventKind::Rescan) and registry reclamation)
  /// when the path no longer names the watched object. This is the WORST-CASE
  /// latency: a death is also caught immediately by any loss signal (which
  /// already re-reads the mount table), so the tick only bounds the quiet case.
  ///
  /// Both Linux backends consult it, for two different reasons:
  ///
  /// - **fanotify** (`FAN_MARK_FILESYSTEM`) unmounted out from under the watch
  ///   delivers no kernel signal at all — the mark holds the superblock alive
  ///   and the fd goes quiet (the L4.1 finding).
  /// - **inotify**'s `IN_DELETE_SELF` for a removed root is queued only once the
  ///   last reference to it drops, and this crate itself holds references: a
  ///   [`sync`](crate::Watcher::sync_root)'s admission pins the objects it
  ///   ordered against for as long as the write that owns them takes, which on a
  ///   stalled filesystem has no bound. The tick is the observation that does not
  ///   wait on them.
  ///
  /// FSEvents (`RootChanged`) and both Windows backends (a fatal source error the
  /// moment the root or its volume is gone) report root death through their own
  /// streams, with nothing this crate holds able to postpone it, so they never
  /// arm the tick and the knob is inert for them.
  ///
  /// [`Duration::ZERO`] DISABLES the tick: such a death is then observed only at
  /// the next loss-triggered refresh (or never, if none occurs) — the pre-L4.2
  /// behavior, quiet-but-alive with the root observably gone on re-access.
  #[inline]
  pub const fn root_liveness_interval(&self) -> Duration {
    self.root_liveness_interval
  }

  /// Returns these options with the periodic root-liveness interval set.
  #[inline]
  #[must_use]
  pub const fn with_root_liveness_interval(mut self, root_liveness_interval: Duration) -> Self {
    self.root_liveness_interval = root_liveness_interval;
    self
  }

  /// Sets the periodic root-liveness interval.
  #[inline]
  pub const fn set_root_liveness_interval(
    &mut self,
    root_liveness_interval: Duration,
  ) -> &mut Self {
    self.root_liveness_interval = root_liveness_interval;
    self
  }

  /// The admission-map directory cap — the ceiling on directories the per-root
  /// map holds. [`None`] is uncapped; the default is
  /// [`DEFAULT_MAX_MAP_DIRECTORIES`](Self::DEFAULT_MAX_MAP_DIRECTORIES) —
  /// **one million**.
  ///
  /// The map is O(LIVE directories): roughly ~250 bytes per directory, so ~2.5–4
  /// GB at 10 million directories (and a seed walk taking minutes) — the
  /// huge-dedicated-tree archetype that wants either a tuned cap or inotify
  /// (which carries its own per-directory kernel costs). A default of `None`
  /// makes registration's memory a function of whatever tree the caller names,
  /// which on an adversarial or accidentally-huge tree is an OOM at
  /// `watch()` — so the default is finite and the caller opts INTO the
  /// unbounded map.
  ///
  /// One million is where the footprint stops being defensible without being
  /// asked for: ~250 MB of map, ~2 orders of magnitude above a large monorepo
  /// (~10^5 directories) and one below the 10-million archetype above. Under
  /// [`Backend::Auto`] exceeding it is not even an error — the barrier falls
  /// back to inotify, whose per-directory kernel cost is one the operator can
  /// see and tune (`fs.inotify.max_user_watches`) — so the default trades an
  /// invisible multi-gigabyte blow-up for a bounded map and a visible fallback.
  ///
  /// Setting the cap trades coverage of a tree past it for that bounded
  /// footprint:
  ///
  /// - at SEED/reseed WALK time a tree exceeding the cap makes the mapped
  ///   backend unviable — under [`Backend::Auto`] the barrier falls back to
  ///   the platform's unmapped backend (inotify on Linux, RDCW on Windows),
  ///   under a forced [`Backend::Fanotify`] or [`Backend::UsnJournal`] it is a
  ///   typed [`WatchRootError::Source`](crate::WatchRootError::Source);
  /// - at LIVE learn time a create/move-in growing the map past the cap ends the
  ///   scope with a terminal [`Rescan`](crate::EventKind::Rescan) — a capped map
  ///   that silently stopped learning would drop events under the unlearned
  ///   directories forever, so the honest terminal is death, never silent loss.
  ///
  /// A cap of `Some(0)` means the map may never hold even the root anchor, so the
  /// seed walk is unviable for ANY root: under [`Backend::Auto`] this effectively
  /// forces inotify (the fall-back path), and under a forced [`Backend::Fanotify`]
  /// every root is the typed viability error. It is never silently normalized to a
  /// live one-node map.
  ///
  /// Ignored by inotify, RDCW, and macOS (none of the three keeps a
  /// fanotify-style admission map); the Windows USN journal reads the same cap
  /// fanotify does, for the same reason.
  #[inline]
  pub const fn max_map_directories(&self) -> Option<usize> {
    self.max_map_directories
  }

  /// Returns these options with the admission-map directory cap set.
  #[inline]
  #[must_use]
  pub const fn with_max_map_directories(mut self, max_map_directories: Option<usize>) -> Self {
    self.max_map_directories = max_map_directories;
    self
  }

  /// Sets the admission-map directory cap.
  #[inline]
  pub const fn set_max_map_directories(&mut self, max_map_directories: Option<usize>) -> &mut Self {
    self.max_map_directories = max_map_directories;
    self
  }

  /// The ceiling on unremoved sync markers across every root of this watcher —
  /// by default 64 on macOS and 128 elsewhere, for the descriptor-budget reason
  /// [`DEFAULT_COOKIE_GLOBAL_CAP`](Self::DEFAULT_COOKIE_GLOBAL_CAP) gives.
  #[inline]
  #[must_use]
  pub const fn cookie_global_cap(&self) -> NonZeroUsize {
    self.cookie_global_cap
  }

  /// Returns these options with the unremoved-sync-marker ceiling set.
  #[inline]
  #[must_use]
  pub const fn with_cookie_global_cap(mut self, cookie_global_cap: NonZeroUsize) -> Self {
    self.cookie_global_cap = cookie_global_cap;
    self
  }

  /// Sets the unremoved-sync-marker ceiling.
  #[inline]
  pub const fn set_cookie_global_cap(&mut self, cookie_global_cap: NonZeroUsize) -> &mut Self {
    self.cookie_global_cap = cookie_global_cap;
    self
  }
}

impl Default for WatcherOptions {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

/// Per-ROOT configuration for one [`Watcher::watch_with`](crate::Watcher::watch_with).
///
/// [`WatcherOptions`] configures the watcher; this configures a single root
/// armed on it, and every knob here rides that root alone. [`new`](Self::new)
/// returns the defaults — deliver everything, prune nothing, include
/// everything — which is exactly the behaviour
/// [`Watcher::watch`](crate::Watcher::watch) has always had.
///
/// # The two glob seats
///
/// The seats speak for different things, and each is matched against a
/// different string. Patterns are case-insensitive and a `*` never crosses a `/`
/// (see [`Glob`](tributary_proto::glob::Glob)).
///
/// - [`prune`](Self::prune) subtracts SUBTREES, and it is matched against a
///   **root-relative DIRECTORY path**: the segments between the watched root and
///   a directory, joined with `/`, never with a leading separator. A directory
///   whose path — or any ancestor's, below the root — matches is never
///   enumerated, never armed, never descended, and nothing at or under it is
///   delivered. The root itself is the empty path and matches nothing, so a
///   pattern can never silence the root it is configured on.
///
///   It speaks for directories ONLY. A plain FILE whose own name matches a
///   prune pattern is not dropped by it — narrowing which files arrive is
///   `include`'s seat — so `**/.*`, written to skip dot-directories, does not
///   silently ban every dotfile in the tree. Only an already-pruned directory
///   ABOVE a file takes the file with it. Because the separator is literal,
///   `**/node_modules` matches `node_modules` at any depth while `a/cache` names
///   one place.
///
///   It is the per-root, glob-shaped twin of
///   [`WatcherOptions::exclusions_slice`], and unlike that option it is enforced
///   on EVERY backend: no OS API takes a glob, so the enforcement never stands
///   down to one.
///
///   "Never enumerated, never armed" is a resource promise as much as a delivery
///   one, and where a backend can spend resources on a subtree the seat is
///   enforced at ITS boundary too. A descending backend simply never asks for a
///   watch below a pruned directory. The two kernel-recursive backends that keep
///   their own admission map — fanotify and the Windows change journal — consult
///   the seat in their seed and reseed walks, in every moved-in subtree walk,
///   before every live directory learn, and ahead of bounded transport admission,
///   so a pruned subtree costs them no map entry and its churn cannot exhaust the
///   directory cap. FSEvents (whose stream is the OS's own) and
///   `ReadDirectoryChangesW` (which keeps no map) have nothing under a pruned
///   name to spend, so for them the common layer's fence is the whole
///   enforcement.
/// - [`include`](Self::include) narrows DELIVERY, and it is matched against the
///   object's **NAME** — the last segment of its path, alone. So `*.mp4` and
///   `**/*.mp4` are the same seat here, and a pattern containing a `/` matches
///   nothing at all: there is no `/` in a name to match it against. [`None`] —
///   the default — delivers everything. It never changes coverage: the tree is
///   watched exactly as it would be without it, so a pattern can be widened
///   later without re-arming anything.
///
/// A directory change is never silenced by `include`, and neither is a
/// [`Rescan`](crate::EventKind::Rescan) or a change whose object class the
/// source did not prove — the seat fails OPEN, because a moved or removed folder
/// the consumer never hears about is a hole in its view, while an extra event is
/// one it can drop. A rename is admitted when EITHER end matches, so a media
/// file renamed to a non-media name is still reported.
///
/// Neither seat can reach the watcher's own sync cookie: `prune` never covers
/// the reserved cookie directory and `include` always admits what is inside it,
/// so a `sync` barrier resolves whatever the patterns say. A cookie directory a
/// seat WOULD have pruned is refused before anything is created
// The refusal's type only exists behind the `sync` feature, so the link is only
// spelled as one where it resolves.
#[cfg_attr(
  feature = "sync",
  doc = "([`SyncRootError::DirPruned`](crate::SyncRootError::DirPruned)) — judged on the"
)]
#[cfg_attr(
  not(feature = "sync"),
  doc = "(`SyncRootError::DirPruned`, behind the `sync` feature) — judged on the"
)]
/// CANONICAL directory the write resolves, so a symlink into a pruned subtree is
/// refused and a file target whose parent is reportable is not.
///
/// # Configuration faces
///
/// Both seats are BOUNDED, on every face: one pattern is bounded by
/// [`Glob::new`](tributary_proto::glob::Glob::new) (length and alternation
/// nesting) and one seat by [`MAX_SEAT_PATTERNS`](Self::MAX_SEAT_PATTERNS), which
/// [`validate`](Self::validate) checks and
/// [`watch_with`](crate::Watcher::watch_with) refuses on before any coverage
/// exists. The `serde` face refuses an over-full seat mid-document and the `clap`
/// face at the occurrence past the ceiling, so on neither of them does a list past
/// it ever compile; the programmatic setters keep the same list bounded AT
/// COLLECTION — they retain one pattern past the ceiling and no more, whatever the
/// iterator handed to them goes on to yield, so `validate` is always reachable and
/// always sees the over-cap witness; and beneath every one of those the matcher's
/// own constructor carries the same bound, so a seat this household never saw is
/// bounded too.
///
/// With the `serde` feature the household is one object keyed by the field
/// names, every key optional and defaulted from [`new`](Self::new); the two glob
/// seats are lists of plain strings, and an invalid pattern — or a list longer
/// than the ceiling — is a document error.
///
/// ```json
/// { "prune": ["**/node_modules", "**/.git"], "include": ["**/*.{mp4,mov}"] }
/// ```
///
/// With the `clap` feature it is a `clap::Args` group whose `--prune` and
/// `--include` flags repeat, once per pattern, up to the ceiling — the occurrence
/// past it is a parse refusal, taken before the seat is compiled. `--include`
/// spells all THREE of the seat's states: given no times at all it is [`None`]
/// (deliver everything); given once with NO VALUE it is the engaged-but-empty
/// seat (deliver no file — directories and `Rescan`s only); given with values it
/// carries them.
///
/// ```text
/// $ app --prune '**/node_modules' --prune '**/.git' --include '**/*.mp4'
/// $ app --include                       # directories and Rescans only
/// ```
///
/// `--prune` requires a value per occurrence and `include = None` is spelled
/// only by omitting `--include`, so on an UPDATE — where omission means
/// preserve — neither flag alone can return an already-pruning or
/// already-narrowed household to the empty/absent seat. `--prune-none`
/// (conflicts with `--prune`) and `--include-all` (conflicts with `--include`)
/// are the two reset flags that reach those states:
///
/// ```text
/// $ app --prune-none                    # prune nothing, whatever stood before
/// $ app --include-all                   # deliver every file again
/// ```
///
/// The interest flags are `--created`, `--removed`, `--modified`, `--moved`,
/// `--attrib` and `--ondir`, and a command line that gives NONE of them parses to
/// [`new`](Self::new) — every kind, the same household the serde face and
/// [`Watcher::watch`](crate::Watcher::watch) hand back. Giving any of them narrows
/// to exactly those. `--interest-none` spells the one household value the six
/// together cannot reach — the EMPTY interest, subscribing to no event kind so
/// the root delivers only coverage `Rescan`s — and conflicts with all six, since a
/// request for no event kind and a request for a specific one cannot both stand:
///
/// ```text
/// $ app --prune '**/node_modules'            # every kind, node_modules pruned
/// $ app --created --moved                    # creates and moves alone
/// $ app --interest-none                      # no event kind, Rescans only
/// ```
///
/// This is deliberately NOT the standalone [`Interest`] group's own clap face,
/// where a flagless parse is itself the EMPTY mask. There, the flags ARE the
/// whole value and an empty one is the flagless spelling; here they are one field
/// of a household whose every OTHER face defaults to
/// [`Interest::all`](tributary_proto::Interest::all), so a flagless `RootOptions`
/// keeps meaning every kind and the empty mask needs its own explicit flag to
/// mean anything on this face.
///
/// An UPDATE (`clap::FromArgMatches::update_from_arg_matches`) changes only what
/// the command line actually carried: updating `--prune` alone leaves the
/// existing interest exactly as it was, the empty one included; `--interest-none`
/// on the command line empties it. The two seats follow the same rule through
/// their own reset flags: naming neither `--prune` nor `--prune-none` leaves
/// the prune seat exactly as it stood, and likewise for `--include` /
/// `--include-all`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, deny_unknown_fields))]
pub struct RootOptions {
  interest: Interest,
  #[cfg_attr(feature = "serde", serde(deserialize_with = "deserialize_seat"))]
  prune: Vec<Glob>,
  #[cfg_attr(
    feature = "serde",
    serde(deserialize_with = "deserialize_optional_seat")
  )]
  include: Option<Vec<Glob>>,
}

/// Reads ONE glob seat, refusing the element past
/// [`RootOptions::MAX_SEAT_PATTERNS`] rather than the list after it.
///
/// Each ELEMENT is read through [`Glob`]'s own face, which measures a pattern
/// against [`MAX_GLOB_LEN`](tributary_proto::glob::MAX_GLOB_LEN) on the bytes the
/// format is holding — before the pattern is copied or compiled, and so before
/// this seat ever takes it. The two bounds are therefore both enforced mid-stream:
/// an over-long word refuses at the word, an over-long list at the element past
/// the ceiling, and neither waits for a document that a caller controls the length
/// of to end.
///
/// The refusal has to happen mid-sequence to mean anything: a document is an
/// untrusted length, and collecting it whole so the count can be checked
/// afterwards has already compiled — and kept — every automaton the bound exists
/// to refuse. So the element that would take the seat past the ceiling is where
/// this stops, with at most the ceiling's worth of patterns ever built.
#[cfg(feature = "serde")]
fn deserialize_seat<'de, D>(deserializer: D) -> Result<Vec<Glob>, D::Error>
where
  D: serde::Deserializer<'de>,
{
  struct Seat;

  impl<'de> serde::de::Visitor<'de> for Seat {
    type Value = Vec<Glob>;

    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
      write!(
        f,
        "at most {} glob patterns",
        RootOptions::MAX_SEAT_PATTERNS
      )
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
      A: serde::de::SeqAccess<'de>,
    {
      use serde::de::Error as _;

      // The hint is a document's own claim, so it steers the allocation and
      // never the bound: capped at the ceiling, it cannot be used to ask for a
      // reservation nothing will fill.
      let hint = seq
        .size_hint()
        .unwrap_or(0)
        .min(RootOptions::MAX_SEAT_PATTERNS);
      let mut patterns = Vec::with_capacity(hint);
      while let Some(glob) = seq.next_element::<Glob>()? {
        if patterns.len() == RootOptions::MAX_SEAT_PATTERNS {
          return Err(A::Error::custom(std::format!(
            "more glob patterns than the per-seat limit of {}",
            RootOptions::MAX_SEAT_PATTERNS
          )));
        }
        patterns.push(glob);
      }
      Ok(patterns)
    }
  }

  deserializer.deserialize_seq(Seat)
}

/// The [`include`](RootOptions::include) seat: the same bound, through the
/// [`None`] this one field can also be.
#[cfg(feature = "serde")]
fn deserialize_optional_seat<'de, D>(deserializer: D) -> Result<Option<Vec<Glob>>, D::Error>
where
  D: serde::Deserializer<'de>,
{
  struct Engaged;

  impl<'de> serde::de::Visitor<'de> for Engaged {
    type Value = Option<Vec<Glob>>;

    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
      write!(
        f,
        "null, or at most {} glob patterns",
        RootOptions::MAX_SEAT_PATTERNS
      )
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
      E: serde::de::Error,
    {
      Ok(None)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
      E: serde::de::Error,
    {
      Ok(None)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
      D: serde::Deserializer<'de>,
    {
      deserialize_seat(deserializer).map(Some)
    }
  }

  deserializer.deserialize_option(Engaged)
}

/// The `clap` face of [`RootOptions`], and the one place the two households differ.
///
/// A derived `clap::Args` reads each boolean as "given or not given", so flattening
/// the protocol [`Interest`] group straight into [`RootOptions`] made a flagless
/// parse the EMPTY interest while every other face of the same type defaults to
/// [`Interest::all`](tributary_proto::Interest::all). The proxy keeps the flags
/// identical, reinterprets the flagless case, and adds one flag of its own,
/// `--interest-none`, so the household value the six kind flags cannot reach —
/// the empty interest — still has a spelling; the standalone group's own face is
/// untouched.
#[cfg(feature = "clap")]
#[derive(Debug, Clone, clap::Args)]
struct RootOptionsArgs {
  #[command(flatten)]
  interest: RootInterestArgs,
  /// Held as the STRINGS the command line carried, not as compiled patterns, and
  /// compiled only once the count has been judged ([`compile_seat`]). A
  /// `value_parser` builds one automaton per occurrence as the parse walks the
  /// arguments, so a `parse_from` handed an arbitrarily long iterator has compiled
  /// — and is holding — every one of them before any face can count them, which is
  /// exactly the work [`RootOptions::MAX_SEAT_PATTERNS`] exists to bound.
  #[arg(long)]
  prune: Vec<String>,
  /// `num_args = 0..=1` is what gives the seat all THREE of its states a command
  /// line can otherwise only spell two of. The seat is `Option<Vec<Glob>>`: absent
  /// (deliver every file), engaged-and-EMPTY (deliver no file — directories and
  /// `Rescan`s only), or engaged with patterns. A plain repeatable flag requires a
  /// value per occurrence, so the empty seat — a legitimate, documented policy
  /// every other face can express — had no spelling at all here, and no parse could
  /// produce it. Taking zero values makes a bare `--include` exactly that seat,
  /// while occurrences still append, so `--include a --include b` is unchanged.
  ///
  /// Raw strings for `prune`'s reason, and bounded the same way.
  #[arg(long, num_args = 0..=1)]
  include: Option<Vec<String>>,
  /// Reset the prune seat to empty: the one household value `--prune` cannot
  /// reach on an UPDATE, since `--prune` requires a value per occurrence and an
  /// update naming neither flag preserves whatever prune seat already stood.
  /// Conflicts with `--prune`.
  #[arg(long, conflicts_with = "prune")]
  prune_none: bool,
  /// Reset the include seat to absent (deliver every file): the one household
  /// value `--include` cannot reach on an UPDATE, since `include = None` is
  /// spelled only by omitting `--include` entirely and an update reads
  /// omission as preserve. Conflicts with `--include`.
  #[arg(long, conflicts_with = "include")]
  include_all: bool,
}

/// Collects ONE glob seat from a caller's iterator, taking at most
/// [`RootOptions::MAX_SEAT_PATTERNS`] + 1 items — the door every programmatic
/// setter of this household goes through.
///
/// The setters are infallible, and that is a statement about their SIGNATURE, not
/// a licence to do unbounded work on the way to one: `impl IntoIterator` is a
/// caller's own iterator, which need not terminate, and a plain `collect` grows
/// the crate-owned `Vec` for as long as it yields — so the ceiling this type
/// documents is reached by nothing, [`validate`](RootOptions::validate) is never
/// asked, and the process dies holding a seat nobody ever validated.
///
/// Taking ONE item past the ceiling is what keeps the refusal exact rather than
/// merely bounded: a seat that fills the ceiling is legal and survives intact,
/// and the extra item is the over-cap witness `validate` refuses on — the same
/// verdict, in the same place, a finite over-cap list has always got. What a
/// non-terminating iterator loses is only the true count in the refusal's
/// `supplied`, which is a number nobody could have read without doing the
/// unbounded work.
///
/// The shape is [`Globs::new`](tributary_proto::Globs::new)'s, deliberately: that
/// constructor is the floor beneath every seat, and a household bounded by a
/// different rule than the matcher below it would be a second opinion about one
/// number.
fn collect_seat(patterns: impl IntoIterator<Item = Glob>) -> Vec<Glob> {
  patterns
    .into_iter()
    .take(RootOptions::MAX_SEAT_PATTERNS + 1)
    .collect()
}

/// Compiles ONE glob seat off the command line, refusing a list longer than
/// [`RootOptions::MAX_SEAT_PATTERNS`] BEFORE it compiles anything.
///
/// The order is the whole point. A seat past the ceiling is refused for a resource
/// reason — every pattern in it is an automaton the fence then asks per directory
/// prefix of every event — so a face that compiles first and counts afterwards has
/// already paid what the bound exists to refuse. The count is a property of the
/// list, not of any pattern in it, so it can be answered without touching one.
///
/// A pattern the matcher cannot compile is still the flag's own refusal, carrying
/// the type's message, so the value a person mistyped is the one they are told
/// about.
#[cfg(feature = "clap")]
fn compile_seat(patterns: Vec<String>, flag: &str) -> Result<Vec<Glob>, clap::Error> {
  if patterns.len() > RootOptions::MAX_SEAT_PATTERNS {
    return Err(clap::Error::raw(
      clap::error::ErrorKind::ValueValidation,
      format!(
        "more {flag} patterns than the per-seat limit of {}\n",
        RootOptions::MAX_SEAT_PATTERNS
      ),
    ));
  }
  patterns
    .iter()
    .map(|pattern| {
      Glob::new(pattern).map_err(|err| {
        clap::Error::raw(
          clap::error::ErrorKind::ValueValidation,
          format!("invalid value for {flag}: {err}\n"),
        )
      })
    })
    .collect()
}

/// One `--<field>` flag per [`Interest`] bit, read as "narrow to exactly these".
#[cfg(feature = "clap")]
#[derive(Debug, Clone, clap::Args)]
struct RootInterestArgs {
  #[arg(long)]
  created: bool,
  #[arg(long)]
  removed: bool,
  #[arg(long)]
  modified: bool,
  #[arg(long)]
  moved: bool,
  #[arg(long)]
  attrib: bool,
  #[arg(long)]
  ondir: bool,
  /// Subscribe to no event kind: the root delivers only coverage `Rescan`s.
  ///
  /// The one household value the six kind flags above cannot reach: narrowing
  /// to none of them is exactly the flagless case, which reads back as
  /// [`RootOptions::DEFAULT_INTEREST`]. Conflicts with all six, since a request
  /// for no event kind and a request for a specific one cannot both stand.
  #[arg(
    long,
    conflicts_with_all = ["created", "removed", "modified", "moved", "attrib", "ondir"]
  )]
  interest_none: bool,
}

#[cfg(feature = "clap")]
impl RootInterestArgs {
  /// The flag names, in the order [`Interest`] reads them, plus
  /// `interest_none` — the ONE list, so a flag added to the group cannot be
  /// forgotten by the update rule.
  const FLAGS: [&'static str; 7] = [
    "created",
    "removed",
    "modified",
    "moved",
    "attrib",
    "ondir",
    "interest_none",
  ];

  /// Whether the parse actually SAW an interest flag on the command line.
  ///
  /// `ArgMatches::get_flag` cannot answer this: a boolean argument is `false`
  /// both when it was not given and when it defaulted, and the two mean opposite
  /// things to an update. The value SOURCE separates them, which is what lets an
  /// update of an unrelated argument leave an existing interest — the empty one
  /// included — untouched.
  fn given_on_command_line(matches: &clap::ArgMatches) -> bool {
    Self::FLAGS
      .iter()
      .any(|flag| matches.value_source(flag) == Some(clap::parser::ValueSource::CommandLine))
  }
}

#[cfg(feature = "clap")]
impl From<RootInterestArgs> for Interest {
  /// NO flag given is the DEFAULT household ([`Interest::all`]); `--interest-none`
  /// yields the EMPTY interest; any kind flag given narrows to exactly the ones
  /// that were.
  fn from(args: RootInterestArgs) -> Self {
    let RootInterestArgs {
      created,
      removed,
      modified,
      moved,
      attrib,
      ondir,
      interest_none,
    } = args;
    if interest_none {
      return Interest::new();
    }
    if !(created || removed || modified || moved || attrib || ondir) {
      return RootOptions::DEFAULT_INTEREST;
    }
    Interest::new()
      .maybe_created(created)
      .maybe_removed(removed)
      .maybe_modified(modified)
      .maybe_moved(moved)
      .maybe_attrib(attrib)
      .maybe_ondir(ondir)
  }
}

#[cfg(feature = "clap")]
impl From<Interest> for RootInterestArgs {
  /// The inverse, for `update_from_arg_matches`: the flags an already-built
  /// household would have been spelled with. The EMPTY interest spells as
  /// `interest_none: true`, so it round-trips like every other value instead of
  /// reading back as [`Interest::all`].
  fn from(interest: Interest) -> Self {
    Self {
      created: interest.created(),
      removed: interest.removed(),
      modified: interest.modified(),
      moved: interest.moved(),
      attrib: interest.attrib(),
      ondir: interest.ondir(),
      interest_none: interest.is_empty(),
    }
  }
}

#[cfg(feature = "clap")]
impl RootOptionsArgs {
  /// The household these arguments spell — the one site the two seats are compiled
  /// at, and only after [`compile_seat`] has judged their length.
  ///
  /// `prune_none`/`include_all` win over whatever `prune`/`include` carry: the
  /// two pairs conflict at the parse, so at most one of each pair is ever set,
  /// and the reset flag is the one spelling that can return an update to the
  /// empty/absent seat a plain omission cannot reach.
  fn into_options(self) -> Result<RootOptions, clap::Error> {
    let prune = if self.prune_none {
      Vec::new()
    } else {
      compile_seat(self.prune, "--prune")?
    };
    let include = if self.include_all {
      None
    } else {
      self
        .include
        .map(|include| compile_seat(include, "--include"))
        .transpose()?
    };
    Ok(RootOptions {
      interest: self.interest.into(),
      prune,
      include,
    })
  }
}

#[cfg(feature = "clap")]
impl From<&RootOptions> for RootOptionsArgs {
  /// The way back, for an UPDATE: a compiled seat renders to the patterns it was
  /// compiled from, which is the spelling the flags carry. The empty prune seat
  /// spells as `prune_none: true` and the absent include seat as
  /// `include_all: true`, so each round-trips like every other value instead of
  /// reading back as a bare omission an update would then leave untouched.
  fn from(options: &RootOptions) -> Self {
    Self {
      interest: options.interest.into(),
      prune: options.prune.iter().map(seat_pattern).collect(),
      include: options
        .include
        .as_ref()
        .map(|include| include.iter().map(seat_pattern).collect()),
      prune_none: options.prune.is_empty(),
      include_all: options.include.is_none(),
    }
  }
}

/// One compiled pattern as the string a command line spells it with.
#[cfg(feature = "clap")]
fn seat_pattern(glob: &Glob) -> String {
  glob.as_str().to_owned()
}

#[cfg(feature = "clap")]
impl clap::FromArgMatches for RootOptions {
  fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
    RootOptionsArgs::from_arg_matches(matches)?.into_options()
  }

  /// Applies only what the COMMAND LINE said, leaving every other field of the
  /// existing household exactly as it stood.
  ///
  /// The interest is the field that cannot be updated through the proxy, and the
  /// reason is the proxy's own rule: no interest flag given, `--interest-none`
  /// included, means [`Interest::all`], which is what makes a flagless
  /// `RootOptions` the default household. Rebuilding the proxy's flags from
  /// whatever the command line parsed to and reading them back unconditionally
  /// would therefore erase an EXISTING narrowed or empty interest — an update of
  /// an unrelated `--prune` would silently broaden what the caller subscribed to.
  ///
  /// So the flags are consulted rather than the value: the interest changes only
  /// when at least one of the seven — the six kind flags or `--interest-none` —
  /// came from the command line, and otherwise the existing one is kept whatever
  /// it says. That is the same rule the two glob seats already get from clap's
  /// own update — a repeatable argument nobody gave has no values, so it leaves
  /// the field alone.
  fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) -> Result<(), clap::Error> {
    let mut args = RootOptionsArgs::from(&*self);
    args.update_from_arg_matches(matches)?;
    let updated = args.into_options()?;
    if RootInterestArgs::given_on_command_line(matches) {
      self.interest = updated.interest;
    }
    self.prune = updated.prune;
    self.include = updated.include;
    Ok(())
  }
}

/// The stable [`clap::ArgGroup`] id this household answers to, and the arguments
/// it holds — every one of them, direct and nested alike.
///
/// It exists because an OPTIONAL flatten (`#[command(flatten)] root:
/// Option<RootOptions>`) is decided entirely by this group: clap asks
/// [`clap::Args::group_id`] when it builds the command — panicking outright if
/// there is none — and then reads `ArgMatches::contains_id` on that group to
/// decide `Some` from `None`. A group is marked present only by an EXPLICIT
/// value source, so membership is exactly "the caller spelled one of these",
/// which is what the optional flatten means.
///
/// Forwarding the proxy's own derived group would not do, and the reason is a
/// documented limitation rather than an oversight: clap's derive leaves the
/// generated group EMPTY for any struct that itself contains a `#[command(flatten)]`
/// — nested arg groups are not validated yet — and [`RootOptionsArgs`] flattens
/// the interest flags. An empty group is never present, so every flag would be
/// parsed and then silently discarded.
///
/// So the members are named here, and named EXHAUSTIVELY: the seven interest
/// flags (the six kind flags and `--interest-none`) come from
/// [`RootInterestArgs::FLAGS`] — the one list a new flag must be added to — and
/// the four seat flags (`--prune`, `--include`, `--prune-none`,
/// `--include-all`) are spelled beside them. A flag missing from this group is
/// a flag whose presence cannot turn an optional household `Some`.
#[cfg(feature = "clap")]
impl RootOptions {
  /// The group's id, stable across releases: a downstream `ArgGroup` that names
  /// this household refers to it by this string.
  const GROUP_ID: &'static str = "RootOptions";

  /// The arguments the group holds — the two seats and their reset flags, plus
  /// every interest flag.
  fn group_members() -> impl Iterator<Item = clap::Id> {
    ["prune", "include", "prune_none", "include_all"]
      .into_iter()
      .chain(RootInterestArgs::FLAGS)
      .map(clap::Id::from)
  }

  /// [`augment_args`](clap::Args::augment_args) and its update twin differ only
  /// in which proxy augmentation they run, so the group is added in one place.
  fn with_group(cmd: clap::Command) -> clap::Command {
    cmd.group(
      clap::ArgGroup::new(Self::GROUP_ID)
        .multiple(true)
        .args(Self::group_members()),
    )
  }
}

#[cfg(feature = "clap")]
impl clap::Args for RootOptions {
  fn group_id() -> Option<clap::Id> {
    Some(clap::Id::from(Self::GROUP_ID))
  }

  fn augment_args(cmd: clap::Command) -> clap::Command {
    Self::with_group(RootOptionsArgs::augment_args(cmd))
  }

  fn augment_args_for_update(cmd: clap::Command) -> clap::Command {
    Self::with_group(RootOptionsArgs::augment_args_for_update(cmd))
  }
}

impl RootOptions {
  /// The default per-root delivery interest: [`Interest::all`] — narrowing is
  /// the opt-in act, matching the shorthand
  /// [`Watcher::watch`](crate::Watcher::watch) took before this household
  /// existed.
  pub const DEFAULT_INTEREST: Interest = Interest::all();

  /// The most patterns EITHER glob seat may carry — the VOCABULARY's own bound,
  /// [`tributary_proto::glob::MAX_SEAT_PATTERNS`], named here because this is the
  /// household a caller configures the seats through.
  ///
  /// It is not restated here, and deliberately: the matcher's own constructor
  /// enforces it, so a direct caller and another crate's seat are bounded by the
  /// same number this household refuses on. See the constant's own documentation
  /// for what the number buys.
  pub const MAX_SEAT_PATTERNS: usize = tributary_proto::glob::MAX_SEAT_PATTERNS;

  /// The default options: deliver every kind, prune nothing, include
  /// everything.
  #[inline]
  pub const fn new() -> Self {
    Self {
      interest: Self::DEFAULT_INTEREST,
      prune: Vec::new(),
      include: None,
    }
  }

  /// The root's delivery interest.
  #[inline]
  pub const fn interest(&self) -> Interest {
    self.interest
  }

  /// Returns these options with the delivery interest set.
  #[inline]
  #[must_use]
  pub const fn with_interest(mut self, interest: Interest) -> Self {
    self.interest = interest;
    self
  }

  /// Sets the delivery interest.
  #[inline]
  pub const fn set_interest(&mut self, interest: Interest) -> &mut Self {
    self.interest = interest;
    self
  }

  /// The subtrees this root never descends into, as a slice. Empty is the
  /// default — nothing is pruned. Matched against root-relative DIRECTORY paths;
  /// see the type docs for what a match subtracts and what it does not.
  #[inline]
  pub fn prune(&self) -> &[Glob] {
    self.prune.as_slice()
  }

  /// Returns these options with the pruned subtrees set.
  ///
  /// Retains at most [`MAX_SEAT_PATTERNS`](Self::MAX_SEAT_PATTERNS) + 1 patterns,
  /// whatever the iterator goes on to yield; a seat that reaches that length is
  /// refused by [`validate`](Self::validate).
  #[inline]
  #[must_use]
  pub fn with_prune(mut self, prune: impl IntoIterator<Item = Glob>) -> Self {
    self.prune = collect_seat(prune);
    self
  }

  /// Sets the pruned subtrees.
  ///
  /// Retains at most [`MAX_SEAT_PATTERNS`](Self::MAX_SEAT_PATTERNS) + 1 patterns,
  /// whatever the iterator goes on to yield; a seat that reaches that length is
  /// refused by [`validate`](Self::validate).
  #[inline]
  pub fn set_prune(&mut self, prune: impl IntoIterator<Item = Glob>) -> &mut Self {
    self.prune = collect_seat(prune);
    self
  }

  /// The file patterns delivery is narrowed to, or [`None`] — the default — for
  /// every file. Matched against the object's NAME alone, so a pattern carrying
  /// a `/` admits nothing. An EMPTY list is not the same thing as [`None`]: it
  /// is a seat that admits no file at all (directories and `Rescan`s still
  /// deliver).
  #[inline]
  pub fn include(&self) -> Option<&[Glob]> {
    self.include.as_deref()
  }

  /// Returns these options with delivery narrowed to the given file patterns.
  ///
  /// Retains at most [`MAX_SEAT_PATTERNS`](Self::MAX_SEAT_PATTERNS) + 1 patterns,
  /// whatever the iterator goes on to yield; a seat that reaches that length is
  /// refused by [`validate`](Self::validate).
  #[inline]
  #[must_use]
  pub fn with_include(mut self, include: impl IntoIterator<Item = Glob>) -> Self {
    self.include = Some(collect_seat(include));
    self
  }

  /// Sets the file patterns delivery is narrowed to.
  ///
  /// Retains at most [`MAX_SEAT_PATTERNS`](Self::MAX_SEAT_PATTERNS) + 1 patterns,
  /// whatever the iterator goes on to yield; a seat that reaches that length is
  /// refused by [`validate`](Self::validate).
  #[inline]
  pub fn set_include(&mut self, include: impl IntoIterator<Item = Glob>) -> &mut Self {
    self.include = Some(collect_seat(include));
    self
  }

  /// Returns these options delivering every file again — the [`None`] seat.
  #[inline]
  #[must_use]
  pub fn without_include(mut self) -> Self {
    self.include = None;
    self
  }

  /// Clears the include seat, delivering every file again.
  #[inline]
  pub fn clear_include(&mut self) -> &mut Self {
    self.include = None;
    self
  }

  /// Checks the bounded quantities this household carries — one per glob seat.
  ///
  /// Asked by [`watch_with`](crate::Watcher::watch_with) before a scope exists,
  /// the way [`WatcherOptions::validate`] is asked before a watcher does: a
  /// legal-but-extreme configuration becomes a typed refusal at the door rather
  /// than a per-event cost nothing bounds.
  ///
  /// # Errors
  ///
  /// [`OptionsError::TooManyPrunePatterns`] /
  /// [`OptionsError::TooManyIncludePatterns`] when a seat carries more than
  /// [`MAX_SEAT_PATTERNS`](Self::MAX_SEAT_PATTERNS) patterns.
  pub fn validate(&self) -> Result<(), OptionsError> {
    if self.prune.len() > Self::MAX_SEAT_PATTERNS {
      return Err(OptionsError::TooManyPrunePatterns {
        supplied: self.prune.len(),
      });
    }
    if let Some(include) = &self.include
      && include.len() > Self::MAX_SEAT_PATTERNS
    {
      return Err(OptionsError::TooManyIncludePatterns {
        supplied: include.len(),
      });
    }
    Ok(())
  }

  /// The compiled seats this household names, in the shape the driver stores
  /// them on a scope: the pruned subtrees and, when the seat is engaged, the
  /// included files.
  ///
  /// Fallible for the one reason [`Globs::new`](tributary_proto::glob::Globs::new)
  /// is — a seat past [`MAX_SEAT_PATTERNS`](Self::MAX_SEAT_PATTERNS) — and it
  /// says which SEAT carried it, which the matcher's own refusal cannot know.
  /// [`validate`](Self::validate) answers the same question one step earlier, at
  /// the door, so a household that passed it compiles; this arm is the floor
  /// beneath that, not a second gate a caller has to remember.
  ///
  /// # Errors
  ///
  /// [`OptionsError::TooManyPrunePatterns`] /
  /// [`OptionsError::TooManyIncludePatterns`].
  pub(crate) fn compile(&self) -> Result<(Globs, Option<Globs>), OptionsError> {
    let prune =
      Globs::new(self.prune.iter().cloned()).map_err(|err| OptionsError::TooManyPrunePatterns {
        supplied: err.supplied(),
      })?;
    let include = match &self.include {
      None => None,
      Some(include) => Some(Globs::new(include.iter().cloned()).map_err(|err| {
        OptionsError::TooManyIncludePatterns {
          supplied: err.supplied(),
        }
      })?),
    };
    Ok((prune, include))
  }
}

impl Default for RootOptions {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}
