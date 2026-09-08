//! Root-relative glob patterns and the compiled sets a watcher matches with.
//!
//! A pattern here is always read against a **root-relative** path: the segments
//! between a watched root and the object, joined with `/`, never with a leading
//! separator. The root itself is the EMPTY string, and the empty string never
//! matches anything ([`Globs::is_match`]), so no pattern can ever name the root
//! it is configured on.
//!
//! Three compile options are fixed for every pattern this module builds, and all
//! three are part of the vocabulary's meaning rather than a tunable:
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
//! - **backslash escapes**. `\*` is a literal asterisk, and a `\` at the very end
//!   is a refusal. The matcher's own default for this is the HOST's — escapes on
//!   Unix, a path separator on Windows — which would make `foo\*` mean the
//!   literal name `foo*` on one platform and `foo/*` on the other, so one
//!   serialized configuration would subtract different ground depending on where
//!   it was read. Patterns here are `/`-joined on every platform, so the
//!   backslash has no separator meaning to preserve.
//!
//! # Bounded input
//!
//! A pattern is a caller's configuration value, reachable from a JSON document or
//! a command line, and [`Glob::new`] is the one door it comes through. Two
//! ceilings are enforced there, before the matcher ever sees the text —
//! [`MAX_GLOB_LEN`] and [`MAX_GLOB_NESTING`] — so no pattern any face accepts can
//! exhaust the stack or the automaton budget. A SET of already-valid patterns is
//! bounded in turn by the seat that carries it (see [`Globs::new`], and
//! `tributary_fs::RootOptions::MAX_SEAT_PATTERNS` for the seat that does it).
//!
//! # Unicode: one canonical form on both sides
//!
//! A filesystem does not agree with a keyboard about how a name is SPELLED. The
//! same `é` is one code point in the composed form (NFC) an editor and a JSON
//! document produce, and two in the decomposed form (NFD) HFS+ stores and
//! FSEvents reports. Comparing those two byte strings answers `false`, so a
//! perfectly ordinary `**/Café.mp4` would silently match nothing on one of the
//! three supported platforms — and a seat that fails by silence is exactly the
//! failure this vocabulary exists to avoid.
//!
//! Both sides are therefore normalized to NFC before they ever meet: a pattern
//! compiles from the NFC form of the caller's text, and a candidate path is
//! normalized on its way into [`Globs::is_match`]. The caller's OWN text is
//! still what [`Glob::as_str`], [`Display`](core::fmt::Display) and the serde
//! face give back — a pattern round-trips byte for byte through any format that
//! carries a string; only the matching runs in the canonical form.
//! Already-normalized text — every ASCII path, which is nearly all of them — is
//! borrowed rather than rebuilt.

use std::{borrow::Cow, sync::Arc};

use unicode_normalization::UnicodeNormalization as _;

/// The longest pattern [`Glob::new`] will compile, in BYTES of the caller's own
/// text.
///
/// A prune word names a directory and an include word names a file, and neither
/// vocabulary has anything to say at four figures: the longest pattern this
/// crate's own documentation ever shows is under thirty bytes. What the ceiling
/// is for is the other end — a pattern is a caller's CONFIGURATION VALUE,
/// reachable from a JSON document or a command line, and every cost the matcher
/// pays grows with its length. Refusing here is a typed error a configuration
/// layer can report; discovering the same limit inside the automaton builder is,
/// at best, an opaque message and, at worst, a resource the process already
/// spent.
pub const MAX_GLOB_LEN: usize = 1024;

/// How deeply [`Glob::new`] will let alternations (`{a,{b,c}}`) nest.
///
/// This one is a SAFETY limit rather than a taste one. Alternation is the only
/// recursive construct in the vocabulary, and the matcher parses and renders it
/// recursively: a balanced, syntactically perfect `{{{{…a…}}}}` of a few
/// thousand levels overflows the process stack inside the builder — before any
/// automaton exists for the size limit to catch, and with no value left to report
/// it as. A caller's configuration value must never be able to end the process,
/// so the depth is counted here, in a flat scan, before the pattern is handed
/// over.
///
/// Eight is far above anything the vocabulary needs — `**/*.{mp4,mov,{a,b}}` is
/// three — and far below anything a parser has to think about.
pub const MAX_GLOB_NESTING: usize = 8;

/// `text` in NFC, borrowed when it is already there.
///
/// The quick check is what keeps this within the fence's budget: an ASCII path
/// is normalized by construction, so the common case costs one scan and no
/// allocation.
fn nfc(text: &str) -> Cow<'_, str> {
  if unicode_normalization::is_nfc(text) {
    Cow::Borrowed(text)
  } else {
    Cow::Owned(text.nfc().collect())
  }
}

/// The alternation nesting depth `pattern` reaches, if that is more than
/// [`MAX_GLOB_NESTING`] — the flat scan that stands in for the recursive parse.
///
/// Backslash escapes are honoured because [`Glob::new`] compiles with them
/// enabled on every host, so `\{` is a literal brace here exactly as it is to the
/// matcher. A brace inside a character class is counted anyway: the vocabulary
/// has no use for eight nested `[{]`, and a count that over-refuses at that depth
/// is cheaper to be sure of than one that has to know where a class begins.
fn over_nested(pattern: &str) -> Option<usize> {
  let mut depth = 0usize;
  let mut escaped = false;
  for byte in pattern.bytes() {
    if escaped {
      escaped = false;
      continue;
    }
    match byte {
      b'\\' => escaped = true,
      b'{' => {
        depth += 1;
        if depth > MAX_GLOB_NESTING {
          return Some(depth);
        }
      }
      b'}' => depth = depth.saturating_sub(1),
      _ => {}
    }
  }
  None
}

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
/// Construction is the only fallible step: a `Glob` that exists has compiled
/// AND has proven it can be matched with, so every set built from `Glob`s
/// ([`Globs::new`]) is infallible and no later step can fail on it.
///
/// [`Display`](core::fmt::Display) and [`as_str`](Self::as_str) both give back
/// the SOURCE text, unchanged — a pattern round-trips through any format that
/// carries a string. Matching happens against the text's NFC form (see the
/// [module docs](self)), so two `Glob`s are equal exactly when their source
/// texts are.
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
#[derive(Clone)]
#[cfg_attr(docsrs, doc(cfg(feature = "glob")))]
pub struct Glob {
  /// Everything about the pattern, behind ONE pointer. A `Glob` is cloned
  /// freely — into every set, out of every getter, into a typed refusal a
  /// `Result` carries — and none of what it holds is worth copying: two strings
  /// and an automaton. Sharing them makes a clone a refcount bump and keeps the
  /// value itself pointer-sized, which is what lets an error variant name a
  /// pattern without becoming a large `Err`.
  inner: Arc<Compiled>,
}

/// One pattern's compiled form.
struct Compiled {
  /// The caller's own text, byte for byte — the face every format sees.
  source: String,
  /// The pattern parsed from `source`'s NFC form, kept so a [`Globs`] union can
  /// be built from it without re-parsing.
  glob: globset::Glob,
  /// That one pattern's OWN compiled set, built at construction. It is what
  /// makes this type's promise — a `Glob` that exists can be matched with —
  /// true rather than merely likely, and it is what the [`Globs`] fallback arm
  /// asks.
  set: globset::GlobSet,
}

impl Glob {
  /// Compiles `pattern` under this module's fixed options (case-insensitive,
  /// `literal_separator`, backslash escapes), from its NFC form.
  ///
  /// Compilation is THREE steps, and every one of them is fallible HERE rather
  /// than deferred: the input is measured against this module's own ceilings,
  /// then parsed, then built into the automaton that actually answers a match. A
  /// pattern this constructor accepted can therefore never fail, or panic, or
  /// overflow the stack, at match time.
  ///
  /// The ceilings come first because the two steps after them are where a
  /// caller's configuration value can cost the process something it cannot
  /// report: the parse RECURSES on alternations, so deep nesting overflows the
  /// stack ([`MAX_GLOB_NESTING`]), and the build has a size limit the parse does
  /// not, so a syntactically perfect pattern of a few hundred thousand wildcards
  /// parses and then exceeds it ([`MAX_GLOB_LEN`] keeps that cost bounded, and
  /// the build's own refusal is still reported as a value below).
  ///
  /// # Errors
  ///
  /// [`GlobError`] when the pattern is longer than [`MAX_GLOB_LEN`] bytes or
  /// nests alternations deeper than [`MAX_GLOB_NESTING`]; when the matcher
  /// cannot parse it — an unclosed `[`, a stray `\` at the end, a malformed
  /// alternation — or cannot build an automaton for it within its own size
  /// limit.
  pub fn new(pattern: &str) -> Result<Self, GlobError> {
    let refuse = |message: String| GlobError {
      pattern: pattern.to_owned(),
      message,
    };
    if pattern.len() > MAX_GLOB_LEN {
      return Err(refuse(format!(
        "the pattern is {} bytes, over the {MAX_GLOB_LEN}-byte limit",
        pattern.len()
      )));
    }
    if let Some(depth) = over_nested(pattern) {
      return Err(refuse(format!(
        "alternations nest at least {depth} deep, over the limit of {MAX_GLOB_NESTING}"
      )));
    }
    let glob = globset::GlobBuilder::new(&nfc(pattern))
      .case_insensitive(true)
      .literal_separator(true)
      // Stated rather than inherited, because the DEFAULT is the host's: a
      // backslash escapes on Unix and is a path SEPARATOR on Windows, so `foo\*`
      // would mean the literal name `foo*` on one host and `foo/*` on the other,
      // and the same serialized word would subtract different ground depending on
      // where it was read. This vocabulary joins with `/` on every platform (see
      // the module docs), so the backslash has no separator meaning to preserve —
      // and enabling escapes is what makes the documented dangling-escape refusal
      // a refusal on every host too.
      .backslash_escape(true)
      .build()
      .map_err(|err| refuse(err.to_string()))?;
    let mut builder = globset::GlobSetBuilder::new();
    builder.add(glob.clone());
    let set = builder.build().map_err(|err| refuse(err.to_string()))?;
    Ok(Self {
      inner: Arc::new(Compiled {
        source: pattern.to_owned(),
        glob,
        set,
      }),
    })
  }

  /// The pattern's source text, exactly as it was supplied.
  #[cfg_attr(not(tarpaulin), inline(always))]
  pub fn as_str(&self) -> &str {
    &self.inner.source
  }

  /// Whether this ONE pattern matches an ALREADY-NFC candidate.
  ///
  /// The normalization is the caller's ([`Globs`] does it once for a whole set
  /// rather than once per pattern), which is why this is private: a public
  /// entry point that took raw text and skipped the fold would be the exact
  /// silent-miss this module normalizes to avoid.
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn matches_nfc(&self, path: &str) -> bool {
    self.inner.set.is_match(path)
  }
}

/// Equality is the SOURCE text's: the compile options are fixed for every
/// pattern this module builds, so the text is the whole of a pattern's identity
/// — and it is the half a caller can see, serialize and print.
impl PartialEq for Glob {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn eq(&self, other: &Self) -> bool {
    Arc::ptr_eq(&self.inner, &other.inner) || self.as_str() == other.as_str()
  }
}

impl Eq for Glob {}

impl core::hash::Hash for Glob {
  #[cfg_attr(not(tarpaulin), inline(always))]
  fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
    self.as_str().hash(state);
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
  inner: Option<Arc<CompiledSet>>,
}

struct CompiledSet {
  patterns: Vec<Glob>,
  matcher: Matcher,
}

impl CompiledSet {
  /// Whether some pattern matches an ALREADY-NFC candidate.
  fn is_match(&self, path: &str) -> bool {
    match &self.matcher {
      Matcher::Set(set) => set.is_match(path),
      Matcher::Each => self.patterns.iter().any(|glob| glob.matches_nfc(path)),
    }
  }
}

/// How a non-empty [`Globs`] answers — the union automaton when the matcher
/// could build one, each pattern's OWN automaton when it could not (see
/// [`Globs::new`]). The two are answer-identical; only the cost differs.
enum Matcher {
  /// Every pattern in ONE automaton: a single pass over the path, whatever the
  /// pattern count. The ordinary arm.
  Set(globset::GlobSet),
  /// Ask each pattern in turn, through the automaton it built at ITS own
  /// construction ([`Glob::new`]). The fallback arm holds no state of its own
  /// precisely because there is nothing left to compile: every matcher it needs
  /// was already proven when the caller's pattern became a [`Glob`], so falling
  /// back cannot fail and cannot panic.
  Each,
}

impl Globs {
  /// Compiles `patterns` into one matcher.
  ///
  /// Infallible **by construction**, in two steps: every [`Glob`] compiled at
  /// ITS own construction, so no pattern here can be malformed; and the union
  /// of those patterns is attempted but never *required*.
  ///
  /// # Why the union can be refused
  ///
  /// A set is compiled into ONE automaton, and that automaton has a size limit
  /// the individual patterns do not: a large or pathological pattern set — each
  /// pattern of it perfectly valid — can exceed it. That is a caller's
  /// configuration value, and a configuration value must never panic the
  /// process. So a refused union falls back to a matcher per pattern, asked in
  /// turn.
  ///
  /// The fallback answers **identically**: a path matches the set exactly when
  /// some pattern matches it, which is what both arms compute. Only the cost
  /// differs — one pass over the path becomes one pass per pattern — and only
  /// for the pattern sets that could not be unioned in the first place.
  ///
  /// It also compiles NOTHING. Every pattern carries the automaton it proved at
  /// its own construction ([`Glob::new`]), so the fallback merely asks them in
  /// turn; a matcher built lazily here would be a second place the same size
  /// limit could be met, with no value left to report it as.
  ///
  /// # The fallback's worst case, and who bounds it
  ///
  /// The fallback costs one automaton pass PER PATTERN, and a prune fence asks a
  /// set once per directory prefix of every event — so the whole worst case is
  /// `patterns × prefix depth` passes per event, on the pattern sets large enough
  /// to have refused a union in the first place. That is a real cost and it is
  /// bounded where the patterns are ADMITTED rather than here: a seat carries at
  /// most `tributary_fs::RootOptions::MAX_SEAT_PATTERNS` (256) of them, refused
  /// with a typed configuration error, so the worst case is 256 passes per
  /// prefix and not "as many as a document happened to list". Bounding it here
  /// instead would mean refusing a `Globs` — an infallible constructor whose
  /// whole promise is that a set of valid patterns always builds.
  pub fn new(patterns: impl IntoIterator<Item = Glob>) -> Self {
    let patterns: Vec<Glob> = patterns.into_iter().collect();
    if patterns.is_empty() {
      return Self { inner: None };
    }
    let mut builder = globset::GlobSetBuilder::new();
    for glob in &patterns {
      builder.add(glob.inner.glob.clone());
    }
    let matcher = match builder.build() {
      Ok(set) => Matcher::Set(set),
      Err(_) => Matcher::Each,
    };
    Self {
      inner: Some(Arc::new(CompiledSet { patterns, matcher })),
    }
  }

  /// The same set on the [`Matcher::Each`] arm, whatever the union would have
  /// done — so the fallback can be asked the very fixtures the union is asked,
  /// rather than only the pattern sets big enough to refuse a union (which no
  /// cell can build in reasonable time).
  #[cfg(test)]
  fn each(patterns: impl IntoIterator<Item = Glob>) -> Self {
    let patterns: Vec<Glob> = patterns.into_iter().collect();
    if patterns.is_empty() {
      return Self { inner: None };
    }
    Self {
      inner: Some(Arc::new(CompiledSet {
        patterns,
        matcher: Matcher::Each,
      })),
    }
  }

  /// Whether `path` — a root-relative path, `/`-joined and without a leading
  /// separator — matches any pattern in this set.
  ///
  /// `path` is folded to NFC on the way in, so a pattern spelled one way matches
  /// a filesystem that spells the same name the other (see the
  /// [module docs](self)).
  ///
  /// The EMPTY path never matches: it names the root itself, which no seat may
  /// ever cover. An empty set never matches either.
  pub fn is_match(&self, path: &str) -> bool {
    if path.is_empty() {
      return false;
    }
    let Some(compiled) = self.inner.as_ref() else {
      return false;
    };
    compiled.is_match(&nfc(path))
  }

  /// WHICH pattern `path` matches — the first one in configuration order, or
  /// [`None`] when the set does not match it at all.
  ///
  /// Answers exactly what [`is_match`](Self::is_match) answers, and exists for
  /// the one caller that must NAME the pattern rather than merely obey it: a
  /// refusal a person has to act on ("this directory is pruned by `**/.cache`")
  /// is only actionable if it says which word did the pruning.
  ///
  /// Deliberately walks the patterns rather than asking the union automaton for
  /// its match set: it is asked once per refusal, never per record, and walking
  /// avoids allocating the index vector a set query would return.
  pub fn matched(&self, path: &str) -> Option<&Glob> {
    if path.is_empty() {
      return None;
    }
    let compiled = self.inner.as_ref()?;
    let path = nfc(path);
    compiled
      .patterns
      .iter()
      .find(|glob| glob.matches_nfc(&path))
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
