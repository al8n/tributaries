//! Root-relative glob patterns and the compiled sets a watcher matches with.
//!
//! A pattern here is always read against a **root-relative** path: the segments
//! between a watched root and the object, joined with `/`, never with a leading
//! separator. The root itself is the EMPTY string, and the empty string never
//! matches anything ([`Globs::is_match`]), so no pattern can ever name the root
//! it is configured on.
//!
//! Two compile options are fixed for every pattern this module builds, and both
//! are part of the vocabulary's meaning rather than a tunable:
//!
//! - **case-insensitive**. The seats these patterns serve name real directories
//!   (`node_modules`, `Caches`) and real extensions (`.MP4` off a camera), on
//!   filesystems that are themselves case-insensitive on two of the three
//!   supported platforms. A pattern that matched on Linux and missed on macOS
//!   would be a portability trap.
//! - **`literal_separator`**. A `*` never crosses a `/`, so `*.mp4` matches
//!   `a.mp4` and not `deep/a.mp4`; `**/` spans any depth INCLUDING zero, so
//!   `**/*.mp4` matches both, and `**/node_modules` matches `node_modules` as
//!   well as `a/b/node_modules`. Without it every `*` would silently be a
//!   subtree wildcard and a pattern could never name one path component.

use std::sync::Arc;

/// Why a pattern is not a valid [`Glob`].
///
/// Carries the offending pattern and the underlying matcher's own message; the
/// two are formatted together by [`Display`](core::fmt::Display), so a
/// configuration layer can surface the refusal verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GlobError {
  pattern: String,
  message: String,
}

impl GlobError {
  /// The pattern text that could not be compiled.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn pattern(&self) -> &str {
    &self.pattern
  }

  /// The matcher's own explanation of the refusal.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn message(&self) -> &str {
    &self.message
  }
}

impl core::fmt::Display for GlobError {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    write!(f, "invalid glob `{}`: {}", self.pattern, self.message)
  }
}

impl core::error::Error for GlobError {}

/// ONE validated glob pattern, compiled once at construction.
///
/// Construction is the only fallible step: a `Glob` that exists has compiled,
/// so every set built from `Glob`s ([`Globs::new`]) is infallible.
///
/// [`Display`](core::fmt::Display) and [`as_str`](Self::as_str) both give back
/// the SOURCE text, unchanged — a pattern round-trips through any format that
/// carries a string.
///
/// # Configuration faces
///
/// With the `serde` feature a `Glob` is a plain string, in both directions, and
/// deserializing runs the same compile [`FromStr`](core::str::FromStr) does — an
/// invalid pattern is a document error, not a value that fails later.
///
/// With the `clap` feature a `Glob`-valued flag parses through that same
/// `FromStr`, so a `Vec<Glob>` field is a REPEATABLE flag:
///
/// ```text
/// $ app --prune '**/node_modules' --prune '**/.git'
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
#[cfg_attr(docsrs, doc(cfg(feature = "glob")))]
pub struct Glob {
  inner: globset::Glob,
}

impl Glob {
  /// Compiles `pattern` under this module's fixed options (case-insensitive,
  /// `literal_separator`).
  ///
  /// # Errors
  ///
  /// [`GlobError`] when the matcher cannot compile the pattern — an unclosed
  /// `[`, a stray `\` at the end, a malformed alternation.
  pub fn new(pattern: &str) -> Result<Self, GlobError> {
    globset::GlobBuilder::new(pattern)
      .case_insensitive(true)
      .literal_separator(true)
      .build()
      .map(|inner| Self { inner })
      .map_err(|err| GlobError {
        pattern: pattern.to_owned(),
        message: err.to_string(),
      })
  }

  /// The pattern's source text, exactly as it was supplied.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn as_str(&self) -> &str {
    self.inner.glob()
  }
}

impl core::fmt::Debug for Glob {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_tuple("Glob").field(&self.as_str()).finish()
  }
}

impl core::fmt::Display for Glob {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.write_str(self.as_str())
  }
}

impl core::str::FromStr for Glob {
  type Err = GlobError;

  /// Compiles `pattern` — see [`Glob::new`].
  ///
  /// # Errors
  ///
  /// [`GlobError`] when the matcher cannot compile the pattern.
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn from_str(pattern: &str) -> Result<Self, Self::Err> {
    Self::new(pattern)
  }
}

impl TryFrom<&str> for Glob {
  type Error = GlobError;

  /// Compiles `pattern` — see [`Glob::new`].
  ///
  /// # Errors
  ///
  /// [`GlobError`] when the matcher cannot compile the pattern.
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn try_from(pattern: &str) -> Result<Self, Self::Error> {
    Self::new(pattern)
  }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "glob", feature = "serde"))))]
impl serde::Serialize for Glob {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_str(self.as_str())
  }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "glob", feature = "serde"))))]
impl<'de> serde::Deserialize<'de> for Glob {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    use serde::de::Error as _;

    let pattern = std::string::String::deserialize(deserializer)?;
    Self::new(&pattern).map_err(D::Error::custom)
  }
}

/// The compiled SET a seat matches with: many [`Glob`]s, one matcher.
///
/// Cheap to clone (the compiled set sits behind an [`Arc`]), so a driver can
/// hand one to every scope that needs it. Built infallibly from already-valid
/// patterns ([`Globs::new`]).
///
/// Matching input is a root-relative path whose segments are joined with `/`,
/// never with a leading separator; the root itself is the empty string and never
/// matches (see the [module docs](self)).
#[derive(Clone, Default)]
#[cfg_attr(docsrs, doc(cfg(feature = "glob")))]
pub struct Globs {
  inner: Option<Arc<Compiled>>,
}

struct Compiled {
  patterns: Vec<Glob>,
  set: globset::GlobSet,
}

impl Globs {
  /// Compiles `patterns` into one matcher.
  ///
  /// Infallible: every [`Glob`] compiled at ITS construction, and a set is the
  /// union of compiled patterns.
  ///
  /// # Panics
  ///
  /// Only if the matcher refuses a union of patterns it individually accepted —
  /// a matcher-internal limit no caller can name from this API.
  pub fn new(patterns: impl IntoIterator<Item = Glob>) -> Self {
    let patterns: Vec<Glob> = patterns.into_iter().collect();
    if patterns.is_empty() {
      return Self { inner: None };
    }
    let mut builder = globset::GlobSetBuilder::new();
    for glob in &patterns {
      builder.add(glob.inner.clone());
    }
    let set = builder
      .build()
      .expect("every pattern compiled at its own construction");
    Self {
      inner: Some(Arc::new(Compiled { patterns, set })),
    }
  }

  /// Whether `path` — a root-relative path, `/`-joined and without a leading
  /// separator — matches any pattern in this set.
  ///
  /// The EMPTY path never matches: it names the root itself, which no seat may
  /// ever cover. An empty set never matches either.
  pub fn is_match(&self, path: &str) -> bool {
    if path.is_empty() {
      return false;
    }
    self
      .inner
      .as_ref()
      .is_some_and(|compiled| compiled.set.is_match(path))
  }

  /// The patterns this set was built from, in the order they were given.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn patterns(&self) -> &[Glob] {
    match &self.inner {
      Some(compiled) => &compiled.patterns,
      None => &[],
    }
  }

  /// Whether this set carries no patterns — the seat is unconfigured, and
  /// [`is_match`](Self::is_match) answers `false` for every path.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn is_empty(&self) -> bool {
    self.inner.is_none()
  }
}

impl core::fmt::Debug for Globs {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_list().entries(self.patterns()).finish()
  }
}

impl FromIterator<Glob> for Globs {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn from_iter<T: IntoIterator<Item = Glob>>(patterns: T) -> Self {
    Self::new(patterns)
  }
}

#[cfg(test)]
mod tests;
