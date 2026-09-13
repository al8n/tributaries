use super::*;

fn glob(pattern: &str) -> Glob {
  Glob::new(pattern).expect("a valid pattern compiles")
}

fn globs(patterns: &[&str]) -> Globs {
  Globs::new(patterns.iter().copied().map(glob))
}

/// A valid pattern compiles through every constructor, and each keeps the
/// SOURCE text — which is what makes a pattern round-trip through any format
/// that carries a string.
#[test]
fn a_pattern_keeps_its_source_text() {
  let pattern = "**/*.{mp4,mov}";
  let parsed: Glob = pattern.parse().expect("FromStr compiles");
  assert_eq!(parsed.as_str(), pattern);
  assert_eq!(parsed.to_string(), pattern);
  assert_eq!(Glob::try_from(pattern).expect("TryFrom compiles"), parsed);
  assert_eq!(glob(pattern), parsed);
  assert_eq!(std::format!("{parsed:?}"), r#"Glob("**/*.{mp4,mov}")"#);
}

/// An uncompilable pattern is a typed refusal naming both the pattern and the
/// matcher's own reason, never a value that fails later at match time.
#[test]
fn an_invalid_pattern_is_a_typed_refusal() {
  let err = Glob::new("[unclosed").expect_err("an unclosed class is refused");
  assert_eq!(err.pattern(), "[unclosed");
  assert!(!err.message().is_empty());
  let rendered = err.to_string();
  assert!(
    rendered.starts_with("invalid glob `[unclosed`: "),
    "{rendered}"
  );
  assert!("[unclosed".parse::<Glob>().is_err());
  assert!(Glob::try_from("[unclosed").is_err());
}

/// Matching ignores case in both directions: the seats name real directories and
/// real extensions, on filesystems that are themselves case-insensitive on two of
/// the three supported platforms.
#[test]
fn matching_is_case_insensitive() {
  let set = globs(&["**/*.mp4", "**/Caches"]);
  assert!(set.is_match("a/B.MP4"));
  assert!(set.is_match("a/b.mp4"));
  assert!(set.is_match("deep/caches"));
  assert!(set.is_match("deep/CACHES"));
}

/// `literal_separator`: a `*` never crosses a `/`, and `**/` spans any depth
/// INCLUDING zero. Without it every `*` would silently be a subtree wildcard.
#[test]
fn a_star_never_crosses_a_separator_and_double_star_spans_any_depth() {
  let shallow = globs(&["*.mp4"]);
  assert!(shallow.is_match("a.mp4"));
  assert!(!shallow.is_match("a/b.mp4"));

  let deep = globs(&["**/*.mp4"]);
  assert!(deep.is_match("a.mp4"));
  assert!(deep.is_match("a/b.mp4"));
  assert!(deep.is_match("a/b/c/d.mp4"));

  let dirs = globs(&["**/node_modules"]);
  assert!(dirs.is_match("node_modules"), "zero depth");
  assert!(dirs.is_match("a/node_modules"));
  assert!(dirs.is_match("a/b/node_modules"));
  assert!(
    !dirs.is_match("node_modules_old"),
    "a whole component, not a name prefix"
  );
}

/// The empty path names the ROOT, and no seat may ever cover the root it is
/// configured on — so it never matches, whatever the patterns say.
#[test]
fn the_empty_path_never_matches() {
  assert!(!globs(&["**", "*", "**/*"]).is_match(""));
  assert!(!Globs::default().is_match(""));
}

/// An empty set is the unconfigured seat: it carries no patterns and admits
/// nothing.
#[test]
fn an_empty_set_matches_nothing() {
  let empty = Globs::new(Vec::new());
  assert!(empty.is_empty());
  assert!(empty.patterns().is_empty());
  assert!(!empty.is_match("anything/at/all"));
  assert!(Globs::default().is_empty());
}

/// The set keeps the patterns it was built from, in order, and prints them.
#[test]
fn a_set_reports_the_patterns_it_was_built_from() {
  let set = globs(&["**/node_modules", "**/.git"]);
  assert!(!set.is_empty());
  assert_eq!(
    set.patterns().iter().map(Glob::as_str).collect::<Vec<_>>(),
    ["**/node_modules", "**/.git"]
  );
  assert_eq!(
    std::format!("{set:?}"),
    r#"[Glob("**/node_modules"), Glob("**/.git")]"#
  );
  let collected: Globs = set.patterns().iter().cloned().collect();
  assert_eq!(collected.patterns(), set.patterns());
}

/// The compiled set is shared, not copied: a clone answers identically without
/// recompiling.
#[test]
fn a_clone_shares_the_compiled_set() {
  let set = globs(&["**/target"]);
  let clone = set.clone();
  assert!(clone.is_match("a/target"));
  assert_eq!(clone.patterns(), set.patterns());
}

/// The union automaton has a size limit the individual patterns do not, so a
/// large or pathological — but perfectly VALID — pattern set can be refused;
/// [`Globs::new`] answers that with a matcher per pattern rather than a panic on
/// a caller's configuration value.
///
/// The refusal itself takes a pattern set no cell can build in reasonable time,
/// so the fallback arm is constructed directly and asked the very fixtures the
/// union cells above are asked: same patterns, same paths, same answers — the
/// only difference the two arms are allowed is speed.
#[test]
fn the_per_pattern_fallback_answers_what_the_union_answers() {
  let patterns = [
    "**/*.mp4",
    "**/Caches",
    "*.mp4",
    "**/node_modules",
    "**/.git",
    "**/*.{mp4,mov}",
  ];
  let union = globs(&patterns);
  let each = Globs::each(patterns.iter().copied().map(glob));

  assert!(!each.is_empty());
  assert_eq!(each.patterns(), union.patterns());
  assert_eq!(std::format!("{each:?}"), std::format!("{union:?}"));

  for path in [
    "",
    "a.mp4",
    "a/b.mp4",
    "a/B.MP4",
    "a/b/c/d.mp4",
    "deep/caches",
    "deep/CACHES",
    "node_modules",
    "a/node_modules",
    "node_modules_old",
    ".git",
    "a/b/.git",
    "a/b.mov",
    "notes.txt",
    "a/b/notes.txt",
    "mp4",
  ] {
    assert_eq!(each.is_match(path), union.is_match(path), "{path}");
  }

  // The agreed answers are the RIGHT ones, not merely equal to each other.
  assert!(each.is_match("a/B.MP4"), "case-insensitive");
  assert!(each.is_match("node_modules"), "`**/` spans zero depth");
  assert!(!each.is_match("node_modules_old"), "a whole component");
  assert!(!each.is_match("notes.txt"), "no pattern names it");
  assert!(!each.is_match(""), "the root is never matched");

  // Cheap to clone on this arm too — the matchers sit behind the same `Arc`.
  let clone = each.clone();
  assert!(clone.is_match("a/node_modules"));
  assert_eq!(clone.patterns(), each.patterns());

  // And the empty set is the empty set on either arm.
  assert!(Globs::each(Vec::new()).is_empty());
}

/// The `serde` face: a plain string, in both directions, compiled on the way in.
#[cfg(feature = "serde")]
mod serde_face {
  use super::*;

  #[test]
  fn a_glob_is_a_plain_string_both_ways() {
    let pattern = glob("**/*.mkv");
    let json = serde_json::to_string(&pattern).unwrap();
    assert_eq!(json, r#""**/*.mkv""#);
    assert_eq!(serde_json::from_str::<Glob>(&json).unwrap(), pattern);
  }

  /// A list of patterns is a list of strings — the shape both option seats carry.
  #[test]
  fn a_list_of_patterns_round_trips() {
    let patterns = std::vec![glob("**/node_modules"), glob("**/.git")];
    let json = serde_json::to_string(&patterns).unwrap();
    assert_eq!(json, r#"["**/node_modules","**/.git"]"#);
    assert_eq!(serde_json::from_str::<Vec<Glob>>(&json).unwrap(), patterns);
  }

  /// An invalid pattern is refused by the DOCUMENT, not carried as a value that
  /// fails later.
  #[test]
  fn an_invalid_pattern_is_a_document_error() {
    let err = serde_json::from_str::<Glob>(r#""[unclosed""#).unwrap_err();
    assert!(err.to_string().contains("invalid glob"), "{err}");
  }

  /// Escapes survive: the string the format decodes is the pattern that compiles.
  #[test]
  fn an_escaped_string_decodes_before_it_compiles() {
    let parsed: Glob = serde_json::from_str(r#""**/a*b""#).unwrap();
    assert_eq!(parsed.as_str(), "**/a*b");
  }
}

/// The `clap` face rides `FromStr`, which is what makes a `Vec<Glob>` field a
/// repeatable flag.
#[cfg(feature = "clap")]
mod clap_face {
  use super::*;
  use clap::Parser as _;

  #[derive(Debug, clap::Parser)]
  struct Cli {
    #[arg(long)]
    prune: Vec<Glob>,
  }

  #[test]
  fn a_glob_flag_repeats() {
    let cli = Cli::parse_from(["app", "--prune", "**/node_modules", "--prune", "**/.git"]);
    assert_eq!(
      cli.prune.iter().map(Glob::as_str).collect::<Vec<_>>(),
      ["**/node_modules", "**/.git"]
    );
    assert!(Cli::parse_from(["app"]).prune.is_empty());
  }

  /// An invalid pattern is refused at the FLAG — a value validation, the same
  /// verdict [`FromStr`](core::str::FromStr) gave — rather than reaching the
  /// program as a pattern that matches nothing.
  ///
  /// The refusal is asserted by KIND rather than by text: this crate takes clap
  /// with `default-features = false`, so the rendered message carries no source
  /// context to read the pattern's own explanation out of.
  #[test]
  fn an_invalid_pattern_is_refused_at_the_flag() {
    let err = Cli::try_parse_from(["app", "--prune", "[unclosed"]).unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
  }
}
