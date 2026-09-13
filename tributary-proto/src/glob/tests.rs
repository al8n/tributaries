use super::*;

fn glob(pattern: &str) -> Glob {
  Glob::new(pattern).expect("a valid pattern compiles")
}

fn globs(patterns: &[&str]) -> Globs {
  Globs::new(patterns.iter().copied().map(glob)).expect("a bounded set compiles")
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
  let empty = Globs::new(Vec::new()).expect("an empty set compiles");
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
  // `TryFrom` rather than `collect`: the set's own bound has no infallible
  // spelling, by design.
  let rebuilt = Globs::try_from(set.patterns().to_vec()).expect("a bounded set rebuilds");
  assert_eq!(rebuilt.patterns(), set.patterns());
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

/// A SET is bounded too, and the bound lives HERE rather than at a
/// configuration household above: a direct caller reaches the matcher without
/// passing any household, and an unbounded set buys `patterns × prefix depth`
/// automaton passes per event on the arm that could not union.
///
/// The refusal names how many were supplied, so a person reading it can act on
/// it — and the ceiling itself is legal, only the step past it is not.
#[test]
fn a_set_past_the_pattern_ceiling_is_a_typed_refusal() {
  let many = |count: usize| {
    (0..count)
      .map(|n| glob(&std::format!("**/w{n}")))
      .collect::<std::vec::Vec<_>>()
  };

  let full = Globs::new(many(MAX_SEAT_PATTERNS)).expect("the ceiling itself is honoured");
  assert_eq!(full.patterns().len(), MAX_SEAT_PATTERNS);
  assert!(full.is_match("a/w0"));

  let err = Globs::new(many(MAX_SEAT_PATTERNS + 1)).expect_err("one past it is refused");
  assert_eq!(err.supplied(), MAX_SEAT_PATTERNS + 1);
  let rendered = err.to_string();
  assert!(
    rendered.contains(&std::format!("{}", MAX_SEAT_PATTERNS + 1))
      && rendered.contains(&std::format!("{MAX_SEAT_PATTERNS}")),
    "{rendered}"
  );

  // The `TryFrom` spelling is the same door, and there is no `collect` that
  // could have walked around it.
  assert_eq!(
    Globs::try_from(many(MAX_SEAT_PATTERNS + 1)).unwrap_err(),
    err
  );

  // A source that knows its own length reports the TRUE total rather than the
  // ceiling it stopped reading at.
  let far_past = Globs::new(many(MAX_SEAT_PATTERNS * 2)).expect_err("well past it is refused too");
  assert_eq!(far_past.supplied(), MAX_SEAT_PATTERNS * 2);
}

/// An over-long pattern is a typed refusal, and it is refused BEFORE the
/// matcher is asked. It parses perfectly — the syntax is a few hundred thousand
/// single-character wildcards — and every step after this one is priced by its
/// length, up to and including an automaton the builder would have refused from
/// a place with no value to report it as.
///
/// Every face of this type comes through here, so a configuration file, a
/// command line, or a programmatic build of such a pattern all refuse the same
/// way instead of spending the process's memory on it.
///
/// Built as a string rather than by looping the compiler: the cell is about ONE
/// pattern's cost, and the refusal is reached before a single compile.
#[test]
fn a_pattern_over_the_length_limit_is_a_typed_refusal() {
  let huge = "?".repeat(300_000);
  let err = Glob::new(&huge).expect_err("a pattern past the length limit is refused");
  // The refusal reports the TRUE length of what it refused, in the message —
  // it just never pays to copy that much of it into the error value itself.
  assert!(
    err.message().contains(&huge.len().to_string()),
    "the true length is reported: {}",
    err.message()
  );
  assert!(
    err.pattern().len() <= 64,
    "only a bounded prefix is stored, not the whole {}-byte input",
    huge.len()
  );
  assert_eq!(
    err.pattern(),
    &huge[..err.pattern().len()],
    "and what is stored is a genuine prefix of the input, not something else"
  );
  assert!(!err.message().is_empty());
  assert!(huge.parse::<Glob>().is_err(), "and through `FromStr`");
  assert!(Glob::try_from(huge.as_str()).is_err(), "and `TryFrom`");

  // The boundary is where the constant says it is, and nowhere else.
  assert!(
    Glob::new(&"?".repeat(MAX_GLOB_LEN)).is_ok(),
    "the ceiling itself compiles"
  );
  assert!(
    Glob::new(&"?".repeat(MAX_GLOB_LEN + 1)).is_err(),
    "and one byte past it does not"
  );

  // Non-vacuity: the size, not the syntax, is what is refused — the same shape
  // at a sane length compiles and matches.
  let ok = globs(&[&"?".repeat(4)]);
  assert!(ok.is_match("abcd"));
  assert!(!ok.is_match("abc"));
}

/// Alternation is the vocabulary's only recursive construct, and the matcher
/// parses and renders it recursively — so a balanced, syntactically PERFECT
/// pattern of a few thousand nested braces overflows the process stack inside
/// the builder, before any automaton exists for the size limit to catch. A
/// caller's configuration value must never be able to end the process, so the
/// depth is counted in a flat scan first.
///
/// Reachable from every face, which is why the refusal lives at the one door
/// they all come through.
#[test]
fn a_pattern_nested_past_the_limit_is_a_typed_refusal() {
  let nest = |depth: usize| std::format!("{}a{}", "{".repeat(depth), "}".repeat(depth));

  assert!(
    Glob::new(&nest(MAX_GLOB_NESTING)).is_ok(),
    "the ceiling itself compiles"
  );
  let err = Glob::new(&nest(MAX_GLOB_NESTING + 1)).expect_err("one level past it is refused");
  assert!(!err.message().is_empty());

  // The shape that motivates the ceiling: balanced, valid, and deep enough to
  // recurse the parser off the stack. Nothing is compiled — the scan answers
  // before the matcher is called at all.
  let deep = nest(50_000);
  assert!(Glob::new(&deep).is_err(), "and so is anything deeper");
  assert!(deep.parse::<Glob>().is_err(), "through `FromStr` too");

  // Depth is NESTING, not count: a hundred sibling alternations never nest.
  assert!(
    Glob::new(&"{a,b}".repeat(100)).is_ok(),
    "siblings are not depth"
  );
  // And an escaped brace is a literal, exactly as it is to the matcher.
  assert!(
    Glob::new(&"\\{".repeat(100)).is_ok(),
    "an escaped brace opens nothing"
  );
}

/// One serialized word means the same ground on every host. The matcher's
/// default for backslash escapes is the HOST's — escapes on Unix, a path
/// SEPARATOR on Windows — so `foo\*` would be the literal name `foo*` on one
/// platform and `foo/*` on the other, and one configuration would subtract
/// different trees depending on where it was read. Escapes are stated instead,
/// on every build.
///
/// This cell runs on both hosts and asserts the same answers on each.
#[test]
fn a_backslash_escapes_on_every_host() {
  let escaped = globs(&["foo\\*"]);
  assert!(
    escaped.is_match("foo*"),
    "the backslash escapes the wildcard, so the pattern names one literal name"
  );
  assert!(
    !escaped.is_match("foobar"),
    "it is not a wildcard the escape failed to reach"
  );
  assert!(
    !escaped.is_match("foo/bar"),
    "and above all it is not a separator: `foo\\*` is not `foo/*`"
  );

  // The separator spelling this vocabulary actually has still means what it says.
  let separated = globs(&["foo/*"]);
  assert!(separated.is_match("foo/bar"));
  assert!(!separated.is_match("foo*"));

  // A dangling escape has nothing to escape, and enabling escapes is what makes
  // that a refusal rather than a host-dependent guess.
  let err = Glob::new("foo\\").expect_err("a trailing backslash is refused");
  assert_eq!(err.pattern(), "foo\\");
  assert!(!err.message().is_empty());
}

/// A `Glob` that exists carries its own compiled matcher, so a [`Globs`] whose
/// UNION is refused has nothing left to compile — the fallback arm cannot fail
/// and cannot panic, whatever the caller configured.
#[test]
fn the_fallback_arm_compiles_nothing() {
  let each = Globs::each([glob("**/*.mp4"), glob("**/node_modules")]);
  assert!(each.is_match("a/b.mp4"));
  assert!(each.is_match("a/node_modules"));
  assert!(!each.is_match("a/b.txt"));
}

/// The two spellings of one name — composed (NFC, what an editor and a JSON
/// document write) and decomposed (NFD, what HFS+ stores and FSEvents reports) —
/// are DIFFERENT byte strings, so a seat that compared them raw would silently
/// match nothing on one of the three supported platforms. Both sides are folded
/// to NFC, so either spelling of the pattern matches either spelling of the path.
#[test]
fn a_pattern_matches_either_spelling_of_a_name() {
  // "Café.mp4", composed and decomposed.
  let composed = "Caf\u{e9}.mp4";
  let decomposed = "Cafe\u{301}.mp4";
  assert_ne!(composed, decomposed, "staging: the two spellings differ");

  let from_composed = globs(&[&std::format!("**/{composed}")]);
  assert!(from_composed.is_match(composed));
  assert!(from_composed.is_match(decomposed));
  assert!(from_composed.is_match(&std::format!("a/b/{decomposed}")));

  let from_decomposed = globs(&[&std::format!("**/{decomposed}")]);
  assert!(from_decomposed.is_match(decomposed));
  assert!(from_decomposed.is_match(composed));

  // And a name that is not the one either pattern names still misses.
  assert!(!from_composed.is_match("Cafe.mp4"));
  assert!(!from_decomposed.is_match("Cafe.mp4"));
}

/// The folding is for MATCHING only: a pattern keeps the caller's own bytes for
/// `as_str`, `Display`, equality and every format built on them, so a document
/// round-trips unchanged whichever spelling it was written in.
#[test]
fn the_source_text_is_never_normalized() {
  let decomposed = "**/Cafe\u{301}.mp4";
  let pattern = glob(decomposed);
  assert_eq!(pattern.as_str(), decomposed);
  assert_eq!(pattern.to_string(), decomposed);
  assert_ne!(
    pattern,
    glob("**/Caf\u{e9}.mp4"),
    "two spellings are two patterns, however identically they match"
  );
}

/// The pattern a set matched is nameable, which is what lets a refusal tell a
/// caller which word closed the door — and it agrees with the plain verdict on
/// every path, including the empty one.
#[test]
fn a_set_names_the_pattern_that_matched() {
  let set = globs(&["**/node_modules", "**/.git", "a/cache"]);
  assert_eq!(
    set.matched("x/node_modules").map(Glob::as_str),
    Some("**/node_modules")
  );
  assert_eq!(set.matched("a/cache").map(Glob::as_str), Some("a/cache"));
  assert_eq!(set.matched("a/b/cache"), None);
  for path in ["", "node_modules", "a/cache", "src", "a/b/.git", "cache"] {
    assert_eq!(set.matched(path).is_some(), set.is_match(path), "{path}");
  }
  assert_eq!(Globs::default().matched("anything"), None);
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
