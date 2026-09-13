# Changelog

All notable changes to this workspace are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crates adhere to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0]

### Added

- **`tributary-fs`**, **`tributary-proto`** — two per-ROOT **glob seats**, carried by a
  new `tributary_fs::RootOptions` and armed through `Watcher::watch_with(root, options)`.
  `Watcher::watch(root, interest)` stays, unchanged, as the shorthand for
  `watch_with(root, RootOptions::new().with_interest(interest))`, and the default
  household is byte-for-byte the behaviour it always had.

  - **`prune`** subtracts SUBTREES from the watch itself, matched against
    root-relative DIRECTORY paths: a directory whose path — or any ancestor's,
    below the root — matches is never enumerated, never armed, never descended,
    and nothing at or under it is delivered. It speaks for DIRECTORIES only — a
    plain file whose own name matches is not dropped by it, so `**/.*` skips
    dot-directories without silently banning every dotfile — and narrowing which
    files arrive is `include`'s job. It is the per-root, glob-shaped twin of
    `WatcherOptions::exclusions`, and unlike that option it never stands down to a
    backend: no OS API takes a glob, so the enforcement is the common layer's on
    every backend, FSEvents and fanotify included. No `Rescan` ever names a pruned
    path, and the watched root itself can never be pruned.
  - **`include`** narrows file DELIVERY only, changing no coverage, so it can be
    widened later without re-arming anything. It is matched against the object's
    NAME — the last path segment, alone — so `*.mp4` and `**/*.mp4` are the same
    seat and a pattern containing a `/` matches nothing. `None` — the default —
    delivers everything. Directories, `Rescan`s, objects whose class no backend
    proved, and renames whose SOURCE matched are always delivered: the seat fails
    OPEN, because a folder the consumer never hears about is a hole in its view.

  Neither seat reaches the watcher's own sync cookie, so a `sync` barrier resolves
  whatever the patterns say; a cookie directory `prune` would have covered is
  refused before anything is created, as the new `SyncRootError::DirPruned`. That
  verdict is taken on the CANONICAL directory the write itself selects — the
  target's parent when the target is a file, every symlink on the way resolved —
  so a link into a pruned subtree is refused rather than left waiting on an event
  the fence would suppress, and a file subscription whose parent is reportable is
  not refused for its own name.

  `prune` is enforced at each backend's OWN boundary, not only at the common
  layer's exit. The two kernel-recursive backends that keep an admission map
  (fanotify, the USN journal) receive the compiled seat and consult it in their
  seed walk, their reseed walk, every moved-in subtree walk, every live directory
  learn, and ahead of bounded transport admission — so a pruned subtree is never
  enumerated, never mapped, and its churn can never consume the directory cap
  whose exhaustion kills the source. FSEvents and `ReadDirectoryChangesW` keep no
  such map and need nothing beyond the common-layer fence.

  Patterns are `tributary_proto::glob::Glob` (re-exported as `tributary_fs::Glob`),
  matched case-insensitively with `literal_separator` — `*` never crosses a `/`,
  `**/` spans any depth including zero, so `**/node_modules` matches
  `node_modules` at any depth while `a/cache` names one place. Pattern and
  candidate are both folded to NFC, so a composed pattern matches a decomposed
  filesystem name (and back). They live behind `tributary-proto`'s new `glob`
  feature, which `tributary-fs` and `tributaries` enable unconditionally; both
  faces carry them (serde: lists of plain strings; clap: repeatable `--prune` /
  `--include` flags, where `--include` spells all three of the seat's states —
  absent, given with no value for the empty seat, and given with patterns).

  `Watcher::replace_root` keeps the root's words and RE-BASES them onto the new
  root — they are root-relative — so a depth-anchored `prune` pattern means
  something different after a replace; `replace_root`'s own docs name both the
  over- and the under-coverage consequence.

  `Glob::new` PROVES a pattern can be matched with, not merely parsed: it builds
  the pattern's own automaton and reports the size limit as a `GlobError`, so no
  face — serde, clap, or a programmatic build — can turn a caller's configuration
  value into a panic. `Globs::matched` names which pattern of a set answered,
  which is what makes the `DirPruned` refusal actionable.

- **`tributary-proto`** — `Change::is_dir()`: the object's class where the source
  proved it, `None` where nothing did. The same three-valued fact the OS records
  already carried, threaded through the emission path unchanged — no stat is
  performed for it, and a consumer filtering on it must treat `None` as unknown.
  `Change::new` takes it as a new final argument.

- **`tributary-proto`** — `DirEntry::with_boundary()` / `is_boundary()` /
  `descends()`: a listing can now say "a directory the core must NOT descend into"
  without lying about the object's class. A driver marks a directory across the
  scope's mount boundary this way instead of lowering its kind to a non-directory,
  so the boundary directory is still announced as a directory (`Change::is_dir()`
  is `Some(true)`) while the Monitor arms, descends and claims coverage over it
  exactly as before. `DirEntry::is_dir()` is the object's class; `descends()` is
  the coverage question.

- **`tributary-proto`** — `Monitor::cover_domination()`: mints the located
  `Rescan` a DOMINATED sync barrier is retired with, and reconciles nothing —
  the seat a coverage transition's retirement stands its instruction through,
  as distinct from an overflow, which additionally recovers the watch set.

- **`tributaries`**, **`tributary-fs`**, **`tributary-proto`** — optional **`serde`**
  and **`clap`** faces on the option households, both off by default and neither
  changing anything when off. `serde` gives every household one document keyed by its
  own field names, defaulted from the type's `Default` (a missing key is that
  default), with no `deny_unknown_fields` so a document written for a later version
  still loads; `Duration` knobs are humantime text (`"250ms"`, `"2s"`) and the
  non-zero capacities refuse a `0`. `clap` gives each household a `clap::Args` group
  whose flagless command line is that same `Default`. Faced: `WatcherOptions` and
  `Backend` (`tributary-fs`), `TributariesOptions`, `DebounceConfig`, `Debounce`,
  `Interest` and `WatchOptions` (`tributaries`), and the core `Interest`
  (`tributary-proto`).

  - `Backend` spells itself exactly as `Backend::as_str` does on both faces —
    `usn-journal`, not a second spelling.
  - `WatchOptions`'s `Filter` is on neither face: a caller's closure is not something
    a document can name, so it is skipped and comes back `Filter::all`. Neither face
    constrains the component parameter `C`.
  - `Debounce` has no `clap` face — `Debounce::Custom` carries a whole
    `DebounceConfig`, which one flag cannot name — but `TributariesOptions`'s
    watcher-global debounce does: its flattened flags stay off until one is given.
  - One flag is not its field's name: `WatcherOptions::event_capacity` is
    `--watcher-event-capacity`, so the three households can be flattened onto ONE
    `clap::Command` beside `TributariesOptions`'s `--event-capacity`. The `serde` key
    is unchanged.
  - `RootOptions`'s clap face reads its interest flags as "narrow to exactly these":
    a command line giving NONE of them is `RootOptions::new()` — every kind — like
    every other face of that household, and giving any narrows to those alone. The
    standalone `tributary_proto::Interest` group keeps its own face, where a flagless
    parse is the empty mask.

- **`tributaries`** — the two glob seats reach the umbrella, so a subscription carries
  them and every source is armed with them.

  - `WatchOptions::prune` / `WatchOptions::include`, with `with_prune`/`set_prune`,
    `with_include`/`set_include`/`without_include`/`clear_include` and getters. They
    are the one pair of knobs on that household that re-scopes the WATCH rather than
    narrowing this subscription's delivery: `prune` subtracts coverage, so a pruned
    subtree is never entered at all, while `interest`, the `Filter` and the `Debounce`
    posture stay per-subscription gates over a root armed at the source's widest
    policy. They match what the fs household's seats match — `prune` against
    root-relative DIRECTORY paths, `include` against the object's NAME alone. Both
    faces carry them (serde: lists of plain strings, an invalid pattern
    being a document error; clap: repeatable `--prune` / `--include`, an absent
    `--include` being the absent seat), and neither constrains `C`.
  - `RootGlobs` — the per-root words a source receives, `WatchOptions::root_globs`
    extracts them, and a root remembers the ones it was ARMED with, so a widen's
    restore re-arms a survivor under its own words rather than the newcomer's.
  - **One root, one set of words.** Roots are SHARED, so every subscription a root
    serves carries that root's `RootGlobs`, and the per-subscription `Filter` is what
    narrows delivery further. A watch whose seats differ from those of the root that
    would serve it — the root already covering it, or ANY root its wider key would
    subsume — is REFUSED with the new `WatchError::RootWordsConflict` (carrying the
    conflicting root's key depth and both word sets, with
    `WatchError::is_root_words_conflict` beside the other predicates), never silently
    re-scoped and never merged: no union or intersection of two callers' seats is one
    either of them asked for. Unengaged words are a value like any other and conflict
    with engaged ones; equality is `RootGlobs`'s own — the same patterns, as written, in
    the same order. The verdict is the planner's, taken off the root records BEFORE
    anything is armed, disarmed, retargeted or re-pointed — the gapless in-place widen
    included — so a refused watch moves no coverage and owes nobody a `Rescan`.
  - **`prune` is anchored to the root that carries it.** It is matched root-relative,
    so the same pattern text under a different root names different ground — while
    `include` matches an object's NAME and means the same thing anywhere. A
    subscription may therefore share a root only when the words are EQUAL *and*
    either its key IS that root's key or neither side carries a `prune` seat: a watch
    DEEPER than its covering root would ride words written for the shallower one, and
    a WIDEN re-bases every subsumed root's words onto the wider key — which is how
    `prune = ["sub"]` on a root at `/r/sub` came to name that entire root, and its
    still-published subscriber to fall silent after one `Rescan`. Both are refused
    with the same `WatchError::RootWordsConflict`, whose new `reason` field carries
    the new `WordsConflict` enum: `Differ` when the text conflicts, `Anchored` when
    equal text would be re-aimed. An `include`-only household is shareable at any
    depth, and the per-subscription `Filter` carries no anchor at all.
  - A cookie directory the root's own `prune` seat covers reaches a `sync` caller as
    `SyncError::CookieDirUncovered` — the same verdict as one outside the root or under a
    watcher exclusion, all three being "no event could ever arrive there" — rather than as
    a write failure it would be pointless to retry.
  - **The watcher's exclusions are judged where the cookie actually lands, too.**
    `sync_root` checked them against the caller's spelling alone, and a spelling is not a
    location: an intermediate symlink resolves one that clears every exclusion into a
    directory inside one, and the marker written there is a marker the source is under
    instruction never to report. The write now takes the same verdict the `prune` seat
    gets, on the directory its descriptor walk resolved, and answers
    `SyncRootError::DirExcluded` before creating anything — which also makes that variant
    spend its admission (`SyncRootDenied::admission` is `None` for it), since the caller
    cannot tell the pre-birth refusal from the post-birth one. A rename INTO excluded
    ground after the walk still lands the marker under the exclusion, where the barrier
    times out exactly as it would for any excluded delivery; `sync_root`'s docs say so.
  - **A cookie leaf is length-bounded at 255 bytes** (`NAME_MAX` on every supported
    filesystem), refused as `SyncRootError::BadCookieName` with the other name-shape
    violations. It is the only caller-supplied value of unbounded length the cookie
    machinery retains, and it retains it in several places at once — so the ledger's
    record caps bounded entries while a single invalid filename could still exhaust the
    allocator. The validated leaf is now shared across the ledger, the name index and the
    delivery seats' active-marker set rather than copied into each.
  - `Source::replace`'s contract states what the fs binding's `replace_root` does: a
    retarget swaps the root's key and KEEPS its words, which are root-relative and are
    therefore re-based onto the new key, so a depth-anchored `prune` pattern names a
    different directory afterwards (both the over- and the under-coverage case are named).
    Stating new words is what an `arm` is for.
  - `Event::is_dir()`: the affected object's class where the source proved it, `None`
    where nothing did. A move's two projections carry it (both endpoints are one
    object); a synthesized delivery reports `None`. `SourceEvent` carries it too, stated
    by the new `SourceEvent::with_is_dir` and read by `SourceEvent::is_dir`;
    `tributary_fs::Event::is_dir()` is the fs layer's own accessor behind it.
  - **`prune`'s leaf match wants a PROVEN directory.** An object whose class nothing
    reported is judged on its ANCESTORS alone, exactly as a proven file is: reading
    "unknown" as "directory" silenced real files — every create, write and delete of a
    regular `cache` under `prune = ["cache"]` on a backend whose ordinary records carry
    no class, with no `Rescan` behind them. The cost of the other direction is bounded
    and visible: an unclassified directory a word names costs one watch, and prunes at
    its children, where its name is a proper ancestor prefix. A located recovery signal
    is not dropped by its own leaf either — it is WIDENED to the nearest unpruned
    parent, so an exact-file `Rescan` (a USN `HARD_LINK_CHANGE`, a boundary-crossing
    rename) still covers what it was owed for without naming pruned ground; a signal
    under a pruned ANCESTOR is still dropped. fanotify renames now carry the class
    `FAN_ONDIR` proves, and `ReadDirectoryChangesW` pairs carry the class both halves
    agree on — two halves that contradict each other become a covering `Rescan` at
    their common parent rather than a guess.
  - **A replace on a scope with an engaged `prune` seat is make-before-break**, whatever
    its shape. The words re-base with the root, and the same-transport widen adopts the
    old subtree without walking it — so ground the re-based words stop covering would
    stay unarmed and unannounced forever. The fresh stream reads the whole new root and
    covers the difference with the `Rescan` it already mints.
  - **The sync cookie is created relative to the object that was judged.** The write
    opens the cookie's parent ONCE — on Unix through a root-confined, no-follow,
    descriptor-relative walk from the watched root; on Windows by reading the name back
    off the handle its mint path opens — then takes the containment and `prune` verdicts
    on that object and creates relative to it. A symlink swapped into an intermediate
    directory after the verdict can no longer redirect the create into pruned ground or
    out of the watched root.
  - **The sync cookie descends from the live ROOT OBJECT, and its marker is bound to the
    judged directory.** Each live scope now retains, from its spawn, the root itself —
    an `O_DIRECTORY|O_NOFOLLOW` descriptor on Unix, a zero-access directory handle on
    Windows — beside the canonical path and the generation, and every cookie write
    descends from it after re-checking its identity against the one the scope was armed
    on. A root renamed aside with a fresh tree stood at its name used to leave both
    canonical paths resolving inside the REPLACEMENT while the stream stayed attached to
    the original: containment passed, the write reported success, and the marker landed
    where no event of that scope could come from. The descriptor lives and dies with the
    scope's registry entry, so a replace or a retirement swaps it with the root it
    belongs to. On Windows the marker itself is now created with `NtCreateFile` anchored
    at the cookie directory's own handle — no component of its path is resolved, so a
    peer that renames the freshly minted directory aside and stands a junction at its old
    leaf has nothing to redirect — and the create's result is re-read off both handles
    and required to stand directly inside the directory the write judged before any
    success is reported.
  - **Every late repair goes through the prune fence.** The destination cover a
    geometry-less profile owes on a kept directory rename is born AFTER that record's
    verdict and names ground the verdict never judged, so it is now fenced like any other
    planned input — widened to the nearest unpruned parent, or dropped. An RDCW basic
    record proves no class, so `/r/src -> /r/cache` under `prune = ["cache"]` kept both
    halves and then aimed a `Rescan` at `cache`: an instruction to enumerate a subtree
    whose every later change stays silent.
  - **The cookie exemption is exactly two paths.** `prune` and `include` exempt the
    reserved cookie directory and its DIRECT marker child, and nothing deeper — the only
    two things this driver ever writes there. A whole-subtree exemption handed anything
    under a reserved name a free pass through both seats, so a peer's stray file (or a
    foreign platform's like-named user directory) was armed, mapped and delivered
    through ground the caller had closed.
  - **A cold listing's unclassified entry is announced as UNPROVEN.** The class stamped
    on such an entry's `Created` — and read by the `ondir` gate — is three-valued from
    `FileKind` (`proven_dir`): a directory is `Some(true)`, an unclassifiable entry is
    `None`, and every known non-directory is `Some(false)`. It used to collapse to
    `Some(false)`, which let a delivery seat drop a real directory's only announcement on
    a proof the listing never made — after which coverage installs and its children
    arrive with no parent creation and no `Rescan` behind them.

- **`tributary-proto`** — `glob::MAX_SEAT_PATTERNS` (256), `glob::GlobsError`, and a
  fallible `Globs::new`. The bound on a pattern SET now lives beside the matcher rather
  than on one configuration household above it: `Globs::new` is the only door a compiled
  set comes through, so a direct caller — or another crate's own seat — is bounded by the
  same number `RootOptions` refuses on, and the count is checked by bounded collection
  before anything is compiled or cloned. `RootOptions::MAX_SEAT_PATTERNS` is now that
  constant, and `RootOptions`' serde face refuses an over-full seat MID-DOCUMENT rather
  than after compiling every pattern in it. `Globs` has no `FromIterator` impl any more —
  `collect` cannot fail, and a set built by truncating past the bound is the unbounded
  seat the bound exists to refuse; `TryFrom<Vec<Glob>>` is the fallible spelling.
  `FileKind::proven_dir` states the three-valued directory class a kind proves.

- **`tributary-fs`** — `RootOptions` answers a stable `clap::ArgGroup` (`group_id`,
  explicitly populated with every direct and nested argument id), so
  `#[command(flatten)] root: Option<RootOptions>` builds and parses: it is `Some` after
  any of the household's flags — the nested interest flags included — and `None`
  otherwise. Without it clap panicked while BUILDING the command, and forwarding the
  proxy's own derived group would not have helped, that group being left empty by the
  derive for any struct containing a nested flatten.

- **`tributaries`** — every optional household on the `clap` face answers a stable,
  explicitly populated `ArgGroup`: `TributariesOptions`, `WatchOptions` and `RootGlobs`
  each name every argument they carry, the nested debounce, interest and seat flags
  included. `#[command(flatten)] options: Option<TributariesOptions>` used to build a
  command whose group was EMPTY — clap's derive leaves it so for any struct containing a
  nested flatten — and an empty group is never present, so `--event-capacity 4096` parsed
  and was then silently discarded as `None`. The same held of `Option<WatchOptions<C>>`
  under `--prune` or an interest flag.

- **`tributaries`** — the per-root glob seats are bounded before anything is armed.
  `RootGlobs::MAX_SEAT_PATTERNS` (the vocabulary's own `glob::MAX_SEAT_PATTERNS`) caps
  either seat of `RootGlobs` and `WatchOptions`; `validate` on both households and the
  new `OptionsError::TooManyPrunePatterns` / `OptionsError::TooManyIncludePatterns` state
  it, both serde faces refuse an over-full list MID-DOCUMENT rather than after building
  every pattern in it, and `Tributaries::watch` refuses one with the new
  `WatchError::InvalidOptions` before the request is even submitted. The seats are the
  words handed to `Source::arm` and asked once per candidate thereafter, so an unchecked
  length was per-event work a caller wrote and a custom source paid, with nothing above
  the seam to notice.

- **`tributary-proto`** — `glob::MAX_GLOB_LEN` (1024 bytes) and `glob::MAX_GLOB_NESTING`
  (8) bound what `Glob::new` will compile, as typed `GlobError`s, before the matcher is
  asked at all. Alternation is the vocabulary's only recursive construct and the matcher
  parses it recursively, so a balanced, syntactically perfect `{{{{…}}}}` of a few
  thousand levels overflowed the process stack from any face — serde, clap, or a
  programmatic build. `Glob::new` also sets `backslash_escape` explicitly on every host:
  the matcher's default is the platform's, so `foo\*` meant the literal name `foo*` on
  Unix and `foo/*` on Windows, and one serialized word subtracted different ground
  depending on where it was read. Escapes are on everywhere, and a dangling `\` is a
  refusal everywhere.

- **`tributary-fs`** — `RootOptions::MAX_SEAT_PATTERNS` (256) and
  `RootOptions::validate`, with `OptionsError::TooManyPrunePatterns` /
  `TooManyIncludePatterns` and the new `WatchRootError::InvalidOptions` that
  `watch_with` answers with before any filesystem work. A pattern set the matcher
  declines to union degrades to one automaton pass per pattern, and the prune fence asks
  a set once per directory prefix of every event — so the seat cap is what makes that
  worst case a number (256 passes per prefix) rather than whatever a document happened
  to list.

- **`tributaries`** — `TributariesOptions::MAX_EVENT_CAPACITY` (2^20) and
  `MAX_COMMAND_CAPACITY` (2^16), checked by the new `TributariesOptions::validate` and
  reported as the new `OptionsError` (`EventCapacityTooLarge` /
  `CommandCapacityTooLarge`, also carried by `BuildError::InvalidOptions`). Both
  channels are allocated eagerly with one slot per item, so a capacity a document or a
  flag could name but no allocator could serve was an allocation-size panic inside the
  channel; every face now refuses it where the value is written, and every constructor
  refuses it before the first channel exists.

- **`tributaries`** — `RootGlobs` carries both configuration faces: serde (two optional
  lists of plain pattern strings, an absent `include` being the absent seat) and a
  `clap::Args` group with the repeatable `--prune` / `--include` a subscription already
  spells its seats with. A consumer arming its own `Source` configures the words from a
  document or a command line instead of re-deriving the vocabulary.

- **`tributary-fs`**, **`tributaries`** — a barrier a coverage transition retired before
  it was installed is the new typed `SyncRootError::Dominated` refusal, and the umbrella
  carries it to the caller as `Ok(SyncOutcome::Dominated)`. It is a barrier MET by
  re-enumeration, not a failed write: the retirement stands the covering `Rescan` for the
  obligation's own ground before the terminal is answered, which is exactly what
  `SyncOutcome::Dominated` promises. It is deliberately not the retryable `Busy` its
  neighbours `WriteInFlight` and `CleanupBacklog` are — a caller whose barrier is already
  met must not be told to wait, or a tree churning faster than one round trip livelocks
  it. The admission's sequence is spent (re-minting is what takes a fresh cut over the
  ground the `Rescan` names).

### Changed

- **`tributaries`** — **BREAKING**: `Tributaries::with_source`, `parts` and
  `parts_local` return `Result<_, OptionsError>`. Construction is where the umbrella's
  capacities are checked, and the check has to be in front of the channels rather than
  behind them; `Tributaries::new` (the fs constructor) keeps its signature and answers
  `BuildError::InvalidOptions`. A household built from the defaults, or from any value
  either face will admit, is always `Ok`.

- **`tributaries`** — a `clap` UPDATE (`FromArgMatches::update_from_arg_matches`) on
  `TributariesOptions`, `DebounceConfig`, `Interest` or `WatchOptions` applies only the
  arguments the COMMAND LINE carried. A derived update cannot tell a flag's default from
  a value someone gave, so `--event-capacity` alone used to reset the command mailbox,
  switch the coalescer on with a default policy, and re-open an `Interest` a caller had
  narrowed. The optional flattened debounce group is instantiated only when one of its
  own flags was given, which is the rule a parse already followed.

- **`tributary-fs`** — a `clap` UPDATE on `WatcherOptions` applies only the knobs the
  COMMAND LINE carried: `--latency` alone leaves the backend selection, the native
  buffer size, both capacities, the liveness interval and the map cap exactly as they
  stood, where a derived update reset every one of them to its flag default.
  `--exclusions` REPLACES the list it updates — the flag repeats to spell a whole list,
  and there is no spelling for adding one path — and a list nobody names is left alone.
  The flags, their defaults and the parse result are unchanged.

- **`tributary-proto`** — a `clap` UPDATE on `Interest` writes only the bits the command
  line NAMED. A bare boolean flag carries clap's own `false` default, so a derived
  update unsubscribed every kind the command line did not mention — `--attrib` alone
  emptied the rest of the mask, and an update for an argument in some other group of the
  same command emptied it outright. The flagless PARSE still means the empty mask, which
  is what makes this group's flags the whole value they are.

- **`tributaries`** — a per-root household the fs layer refuses
  (`WatchRootError::InvalidOptions`) reaches a `watch` caller as an explicitly
  classified `FaultKind::Other`, with the typed refusal recoverable through
  `WatchError::as_fs`. It is a caller-configuration verdict: not `Capacity`, the one
  kind the umbrella retries, and not `Unsupported`, which is read as a verdict on the
  platform.

- **`tributary-fs`**, **`tributaries`** — the `clap` `--include` flag takes zero or one
  value (`num_args = 0..=1`), so a command line can spell every state the seat has.
  `include` is `Option<Vec<Glob>>` and its three states are three different policies:
  absent delivers every file, engaged-and-EMPTY delivers none (directories and `Rescan`s
  only), and engaged with patterns delivers what they name. A flag requiring a value per
  occurrence could reach only two of them — a bare `--include` was a parse error and every
  successful occurrence produced a non-empty list — so `tributary_fs::RootOptions`,
  `RootGlobs` and `WatchOptions` could not parse or update to the documented
  directories-and-`Rescan`s-only policy at all. Occurrences still append, so
  `--include a --include b` is unchanged, and an update still applies only what the
  command line carried.

- **`tributary-fs`** — **BREAKING**: `Watcher::sync_root(root, dir, admission)` no longer
  takes a cookie name, and `Watcher::mint_sync_ticket` returns
  `Option<(SyncAdmission, SyncTicket)>`. The marker LEAF is minted with the admission —
  the watcher's own brand, this process's id, the mint sequence and a word off a
  ChaCha20 stream the watcher seeded from the OS — and read back through the new
  `SyncTicket::leaf()`. `None` from the mint means the watcher never got an entropy seed
  and can admit no sync at all, which today is only `wasm32-unknown-unknown`.

  A caller-chosen leaf was unsound, not merely redundant: admitting a sync ARMS an
  exemption on the marker's leaf, so that for as long as the sync is live a change whose
  last segment is that leaf clears both per-root seats wherever it stands — which is what
  keeps the barrier resolvable when a peer renames the reserved directory out from under
  the marker. With a name the caller picked, an ORDINARY file of that name, changing
  anywhere in the scope, took the same exemption and could be recorded as the barrier's
  observation ahead of the marker's own create. The mint closes that: no other writer
  under the tree can name the file.

  `SyncRootError::BadCookieName` and `SyncRootError::NameInUse` are no longer reachable
  from `sync_root` and survive as the driver's own fail-closed invariants. The
  reserved-leaf grammar is exported as `tributary_fs::is_sync_cookie_name`, beside the
  existing `is_sync_cookie_dir_name`, so the layer that decides what reaches a consumer
  classifies with the minter's own rule rather than a copy of it.

- **`tributaries`** — the fs binding no longer renders a cookie name from `SyncToken`; it
  places the leaf `tributary_fs::Watcher` minted and correlates the barrier on that. A
  custom `Source` is unaffected in signature by this change — see the `begin_sync` entry
  below for the return type it IS breaking — and `Source::begin_sync`'s contract now
  states both ways to discharge the unpredictability obligation: render the token's
  `nonce` into the marker's identity, or take an identity a lower layer mints
  unpredictably itself. A binding built directly on `tributary_fs::Watcher` must take the
  second route — that watcher's leaf is no longer choosable.

- **`tributary-fs`** — on Unix a sync cookie's containment, exclusion and `prune` verdicts
  are taken on the path the OS answers for the descriptor the write ENDED HOLDING, not on
  the components the descent was handed. Each `openat` is descriptor-relative and so
  correct on its own, but a peer that renames an already-opened ancestor moves the rest of
  the descent with it while every remaining step still succeeds: a sync naming `<root>/a/x`
  whose `<root>/a` was renamed into excluded ground mid-walk used to be judged as
  `<root>/a/x`, pass, and create the marker where the source had been told never to report
  from — the write reporting success while the caller's barrier waited out its whole
  deadline. Such a descent is now refused before anything is created, with the same typed
  `DirExcluded` / `DirPruned` verdicts. Creation stays descriptor-relative, and the
  reported landing keeps its documented meaning: the spelling at write time, for reaping,
  never the marker's address.

- **`tributary-fs`** — on Unix a sync cookie's exclusion and `prune` verdicts are taken
  on the cookie's OWN directory — the reserved directory the marker is created in — and
  re-taken once the marker exists. Judging only the parent left two holes with the same
  outcome: an exclusion naming `<dir>/.tributaries-sync-cookies-<uid>` exactly covered
  every event the marker could mint while the parent passed every test, and a rename of
  the judged directory into excluded or pruned ground during the write carried the
  marker there with it, the create being descriptor-relative. Both used to return `Ok`
  for a marker the fence then suppressed, leaving the caller's barrier to wait out its
  whole deadline. Both are now the typed `DirExcluded` / `DirPruned` refusals: the first
  before anything is created, the second after the marker is removed again through the
  anchors that created it, so nothing of the write is on disk either way. A rename that
  lands after that last reading is unchanged — the seats' own documented semantics.

- **`tributary-fs`**, **`tributaries`** — both configuration faces enforce their
  collection ceilings WHILE THEY PARSE, rather than leaving them to `validate` after the
  whole input has been read. `WatcherOptions::exclusions` refuses the element past
  `MAX_EXCLUSIONS` mid-document and the occurrence past it on the command line; the four
  glob seats (`tributary_fs::RootOptions`, `RootGlobs`, `WatchOptions`) hold the flags'
  values as strings and refuse a seat longer than `MAX_SEAT_PATTERNS` BEFORE compiling
  any of them. Both ceilings are resource bounds — a path list allocated per entry, an
  automaton compiled and kept per pattern — so a face that read an untrusted length to
  the end before judging it had already paid what the bound exists to refuse; a
  `parse_from` or a streaming document could spend the process's memory on a household
  that could only ever be rejected. The refusals are the format's own (a document error,
  a `clap` `ValueValidation`), the accepted inputs are unchanged up to and including the
  ceiling, and `validate` keeps the same check for lists assembled in code.

- **`tributary-fs`** — a sync barrier certifies an ordering for the DIRECTORY OBJECT its
  cookie directory named when the sync was admitted, and a replacement standing at that
  name is the new typed `SyncRootError::DirReplaced` refusal. The write is detached from
  the admission by the coverage-settle fence and the blocking pool, and every step of its
  descent below the root is opened by name: a peer that renamed a covered directory aside
  and stood a fresh one at its name inside that window was descended into exactly as the
  original would have been. The marker then landed inside a directory whose coverage the
  scope had not armed, so its create entered no ordered queue, and a later cold
  enumeration of the replacement could report that create ahead of descendants that were
  on disk before it — a barrier that resolved while proving nothing. The directory's
  identity is now read at the admission door and re-read off the descriptor the write
  ends holding; a mismatch refuses before anything is created, so no marker is ever born
  inside an object whose coverage the admission did not judge. The sequence is spent by
  the refusal (the verdict needs the object only the write can reach), so a retry
  re-mints, which re-reads whatever now stands at the name.

- **`tributaries`** — the umbrella classifies that refusal as
  `SyncError::Busy`, beside the two transient refusals it already reported that way.
  Nothing was written and nothing about the caller's request is wrong — the directory it
  named still exists and is still covered — so it is neither a write failure nor an
  uncovered cookie directory, and a fresh sync is admitted for whatever now stands at
  the name.

- **`tributary-proto`** — `Glob`'s `serde` face reads through a string VISITOR, so
  `MAX_GLOB_LEN` is judged on the bytes the format is already holding rather than after
  an owned `String` has been built. Deserializing through `String` first handed an
  untrusted document one allocation of its own choosing per rejected pattern, paid in
  full before the ceiling that pattern was about to fail was consulted at all: a first
  word of a few hundred megabytes cost exactly that, and a streaming document could
  spend the process's memory on patterns that could only ever be refused. The refusal is
  the same typed one, bounded as it always was (the over-length arm keeps a short
  preview, never a copy of the word), and the accepted inputs are unchanged up to and
  including the ceiling. Both glob seats of `tributary_fs::RootOptions`, `RootGlobs` and
  `WatchOptions` inherit it, so an over-long word now stops a seat at that word rather
  than after the list. What a `Deserialize` cannot decline is the FORMAT's own reading —
  one that must allocate while unescaping still allocates the source once, and a
  document whose size must be bounded is bounded by a limited reader on the caller's
  side.

- **`tributary-fs`** — an exclusion path is LENGTH-bounded on every face, by the new
  `WatcherOptions::MAX_EXCLUSION_LEN` (4096 bytes, `PATH_MAX`). The seat's count ceiling
  bounded nothing on its own: eight is a small number, and a single entry can be as long
  as an untrusted document cares to make it, so a first exclusion of a few hundred
  megabytes was allocated in full before any bound was consulted. The `serde` face now
  reads each element through a string visitor and measures the bytes the format is
  already holding before it builds a `PathBuf`, and refuses the element PAST the seat by
  its count alone — probing for it without deserializing it into a path — so the one
  entry the seat is certain to refuse is never allocated either. `--exclusions` refuses
  an over-long value as the parse reads it, as a `clap` `ValueValidation`, and
  `validate` carries the same bound as the backstop for a list assembled in code, as the
  new `OptionsError::ExclusionTooLong`. Accepted inputs are unchanged up to and
  including both ceilings.

- **`tributary-fs`** — the identity proof now reaches the object a marker is actually
  born in: the RESERVED COOKIE DIRECTORY the watcher keeps inside the directory a sync
  names. A `mkdirat` that succeeds is its own proof — the directory is new, empty, named
  by nobody else, and its create is kernel-ordered after the cut that proved its parent —
  but one that reports `EEXIST` is now adopted only if it is EXACTLY the object the
  admission read at that name. Ownership and mode were the whole of that test before, and
  a peer running as the same user could satisfy them: prepare a directory, fill it with
  descendants, chmod it `0700`, and rename it onto the reserved name in the window the
  settle fence and the blocking pool open. The marker then landed in a directory no crawl
  of the scope had enumerated, so a later cold enumeration could report its create ahead
  of descendants that were on disk before it. A replacement, or a reserved directory that
  merely APPEARED after the cut, is now `SyncRootError::DirReplaced`; the uid and mode
  checks remain, as grounds to refuse and never as grounds to adopt.

- **`tributary-fs`**, **`tributaries`** — a reserved cookie directory standing across a
  MOUNT BOUNDARY is the new typed `SyncRootError::DirCrossesMount` refusal. A root's
  crawl does not descend across a mount and arms no watch beyond one, so a marker created
  there is unreportable however it is ordered and the barrier could only time out. It is
  refused before anything is created, and the umbrella classifies it as
  `SyncError::CookieDirUncovered` — the same "that directory could never report the
  cookie" the exclusion and `prune` refusals mean, and permanent in the same way (unlike
  `DirReplaced`, a retry meets the same mount).

- **`tributaries`** — **BREAKING for a custom `Source`**: `Source::arm` and
  `LocalSource::arm` take the per-root `&RootGlobs` as a third argument
  (`arm(&mut self, key: &[C], globs: &RootGlobs)`). An out-of-tree source must accept
  the parameter and either honour both seats or document in its own docs that it cannot
  — nothing above the seam re-checks them, so a source that ignores one silently
  watches or delivers what the caller asked it not to. `RootGlobs::new()` (both seats
  unengaged) asks for exactly the behaviour every source had before the seats existed.
  Every other seam item is unchanged, including canonical-key adoption.

- **`tributary-fs`**, **`tributaries`** — **a sync barrier certifies delivery only within
  one coverage epoch; any change to the root's coverage on the barrier's ground while it
  is in flight resolves it as dominated by a rescan.** A child watch armed or dropped
  beneath the marker's ground, a `set_cover` shrunk over it, a root replaced, a trust or
  overflow verdict on the whole scope: each is a coverage transition, each stands a
  located `Rescan`, and a barrier whose ground one of them touches is retired by it
  rather than certified past it. EXCEPT: arming the barrier's own reserved cookie
  directory is not a transition — it is the write's own ground coming into coverage,
  created by the write itself — so the first sync of a directory does not dominate
  its own marker. A directory rename inside the root is a transition on every backend:
  every barrier standing under the source is retired, with its covering `Rescan` stood
  at the destination's parent, where its marker now stands.

  A barrier is never retired silently — the covering
  `Rescan` is stood, queued ahead of every later delta on that ground, before the caller
  is answered; it reaches the stream at the next flush, not necessarily before the
  answer does, so a caller that re-reads at once may still race ahead of it and converges
  on it once it arrives.

  The caller learns it one of two ways, both at once rather than at its deadline: before
  the marker is installed, `Watcher::sync_root` answers `SyncRootError::Dominated` and
  `Tributaries::sync` answers `Ok(SyncOutcome::Dominated)`; afterwards, the located
  `Rescan` resolves the waiting barrier. `SyncOutcome::Dominated` therefore has one more
  producer than it did — coverage transitions, beside the losses and root deaths it
  always named — and its obligation is unchanged: re-read the ground the `Rescan` names.

  The rule bites where the kernel gives per-directory watch lifecycle (inotify). On a
  kernel-recursive backend (fanotify, FSEvents, `ReadDirectoryChangesW`, the USN journal)
  one whole-subtree stream holds the only watch there is, so only the root-wide
  transitions can fire and the barrier rests on the descriptors the watcher pins, as
  before. A busy tree with a stable watch set dominates nothing, and a transition deep in
  the tree dominates only the barriers standing on that ground.

  What this replaces is a cover change that WIDENED itself to keep a live barrier's
  ground, and the refusal that widening made necessary: `Watcher::set_cover` and
  `request_set_cover` now always apply the cover asked for, and a shrink dominates the
  barriers in flight it touches instead of deferring a caller's narrowing behind a sync
  it knows nothing about. A shrink currently touches every barrier in flight on the root
  rather than only those on the pruned ground — a dropped watch is reported after the
  node carrying its path is gone, so the transition cannot be placed — which costs an
  extra `Dominated`, never a wider instruction: each dominated caller's covering `Rescan`
  is minted from its own obligation's ground. A shrink that dominates a barrier still
  settles `CoverOutcome::Applied`: the domination is not a coverage loss of the cover
  that shrink applied, so its retirement's `Rescan` standing inside the reconcile's own
  settle window does not degrade that window or rewind its claim.

- **`tributaries`** — **BREAKING for a custom `Source`**: `Source::begin_sync` and
  `LocalSource::begin_sync` return `Result<Begun<C>, SyncError>` instead of
  `Result<Vec<C>, SyncError>`. The new `tributaries::Begun` enum is
  `Installed(Vec<C>)` — the marker's canonical key, what the old `Ok` carried — or
  `Dominated`, for a barrier a coverage transition retired before a marker could be
  installed. A key alone could not express the second: there is no marker to name and no
  later observation to mint the outcome from, so such a barrier could only be reported as
  a refusal the caller would then be told to retry. A source that never narrows coverage
  under a live barrier wraps its existing key in `Begun::Installed` and is otherwise
  unaffected; a source that answers `Begun::Dominated` OWES the covering `Rescan` before
  it does. `Source::end_sync`, `cancel_sync` and `is_sync_artifact` are unchanged.

- **`tributary-fs`** — `WatcherOptions::cookie_global_cap` now defaults to **64 on macOS
  and 128 everywhere else**, and the watcher's sync door admits at most `min(cap, 8)`
  concurrent admission samplings on macOS against `min(cap, 32)` elsewhere. The cap
  bounds sync obligations, and an obligation is also descriptors: macOS defaults to a
  256-descriptor soft limit against 1024 elsewhere, and its kernel-recursive lowering is
  the one that holds a target and a reserved-directory pin per barrier in flight, where a
  descending lowering releases both at the door. Both faces carry the platform value —
  the `serde` key's omitted default and the `--cookie-global-cap` flag's printed default
  are the host's — and `WatcherOptions::DEFAULT_COOKIE_GLOBAL_CAP` carries the
  arithmetic. macOS callers therefore get half the previous effective cap and a quarter
  of the previous door; raising either back is one call, with the host's descriptor
  budget in mind.

### Fixed

- **`tributary-fs`**, **`tributary-proto`** — a directory rename whose destination a root's
  `prune` seat covers now consumes the Monitor half its source parked and tears the subtree
  that half was holding down at once (the new `Monitor::consume_pending_move`), instead of
  retaining those watches — and the scope's move settle with them — until the pairing window
  elapsed.

### Known limitations

- **`tributary-fs`**, **`tributaries`** — on Windows, `Watcher::sync_root` and
  `Tributaries::sync`'s cookie path is still path-addressed at three points, so
  a concurrent rename of the watched root or of the cookie directory during a
  sync can leave the barrier unresolved until it times out rather than
  resolving or reporting a definite refusal. Tracked as
  [#134](https://github.com/al8n/tributaries/issues/134).

- **`tributary-fs`**, **`tributaries`** — on Linux and macOS the ordering certificate a
  sync returns rests on the coverage epoch: a change to the root's coverage on the
  barrier's ground while it is in flight retires the barrier, dominated by the located
  `Rescan` that change stands, rather than certifying past it. Where the kernel gives
  per-directory watch lifecycle (inotify) that rule carries the substitutions this entry
  once fenced by hand: arming a watch drops the incumbent before it arms the arrival, so
  every same-name substitution on the chain from the watched root down to the marker's
  landing is itself a watch-lifecycle transition and retires the barriers standing on
  it. On a kernel-recursive backend (FSEvents, fanotify) there are no per-directory
  watches to transition, so the certificate rests where it always did — on the
  descriptors the watcher pins for the sync target and the reserved cookie directory
  until the marker is created. The assumption below is the same one this entry always
  stated; it does not widen.

  Identity, mount frame and landing are re-verified at the write on every backend, a
  minted reserved directory is proved to hold only its marker, every cleanup terminal is
  decided by the pinned object's link count, and the reserved directory's owner-only
  mode is re-read off the descriptor on every open. Those verdicts are the belt UNDER
  the rule rather than a substitute for it: an inode number is reusable, so an identity
  comparison alone cannot separate the admitted object from a replacement that received
  its number back. On a descending backend a barrier parked on the coverage-settle fence
  holds no descriptor on the objects it was admitted against — the door samples them and
  releases — so what it carries into the write is a REMEMBERED tuple, and a replacement
  reusing the admitted inode inside that parked window is no longer refused
  `SyncRootError::DirReplaced`. A `Parked` obligation is exempt from move-retirement, and
  its dispatch re-judges only the applied cover — never the epoch — so an inode reuse
  inside that parked window on a descending backend is caught by neither the released
  pins nor the epoch: it is the same-uid residual this entry already names, full stop.

  What remains outside the contract is therefore a process running with the watcher's
  OWN uid acting BEHIND coverage that never transitions: renaming, hard-linking or
  replacing the marker, or planting entries beside it, inside a directory that stays
  armed throughout, between the write and the observation of the marker. An adversary
  holding the watcher's own credentials can always win one more race against a
  pathname-based filesystem API. On macOS an inheritable ACL on an ancestor that grants
  other users write rights is inherited by the reserved directory and extends the
  trusted set by the tree owner's own configuration — the watcher does not inspect ACLs.
  The watcher is not a security boundary against its own uid. Tracked as
  [#135](https://github.com/al8n/tributaries/issues/135), companion of
  [#134](https://github.com/al8n/tributaries/issues/134).

## [0.1.0]

### Added

- **`tributaries`** — a caller-visible **sync barrier** (#23): `Tributaries::sync(sub,
  timeout)` resolves once every change made under the subscription's key BEFORE the
  call is deliverable. It is kernel-mediated, not an owner-side drain: a cookie file
  is written under the subscription's coverage and its own event — riding the root's
  ordered queue behind every change the backend reported before the write — is what
  proves those changes have exited the pipeline. `SyncOutcome::{Delivered, Dominated}`
  distinguishes "read your deltas" from "a covering `Rescan` stood in; re-enumerate".
  Cookies are suppressed from every consumer stream by a reserved namespace
  (`.tributaries-sync-`), on every instance, always — including foreign instances'
  and crash leftovers. Three defaulted `Source`/`LocalSource` capability methods
  (`begin_sync`, `end_sync`, `is_sync_artifact`) carry it; a source without the
  capability refuses `SyncError::Unsupported` rather than pretending. The fs binding
  parks the cookie write on the coverage-settle fence, so a descending backend cannot
  place the marker while a subtree's watch is mid-re-arm.

- **`tributary-fs`** — `Watcher::sync_root` / `request_remove_cookie`, the
  settle-fenced cookie substrate beneath the umbrella's barrier (#23).

- **`tributaries`** — a **gapless widen** (#29): `Source::replace` (defaulted
  `Unsupported`) retargets an armed root in place, and the umbrella's widen now prefers
  it whenever exactly one root is subsumed. The fs binding implements it with
  `Watcher::replace_root`, which is make-before-break — so the coverage window that
  release-and-rearm opened (the old subtree unwatched between `disarm` and the wider
  `arm`, covered by the re-point `Rescan` but not un-lost) is gone. The handle is
  deliberately PRESERVED, the one sanctioned exception to the generation-unique handle
  contract; it is sound precisely because no fresh handle is minted. `replace` is atomic
  on failure, so any error — including a source that simply cannot do it — falls back to
  the old dance with the old root's coverage untouched.

- **`tributary-fs`** — a root replacement now **replays its swap window from the
  retiring stream's journal** (#27): the driver takes the old stream's resume point
  at command time and hands it to the replacement's spawn, so FSEvents replays the
  window instead of leaving it to the covering `Rescan` alone. Best-effort by
  construction (a wrapped id space mints no token, a purged journal replays nothing,
  a foreign device is never honored), so the `Rescan` still stands — delivery only
  gets denser.

- **`tributary-proto`** — the kernel-recursive addressing vocabulary the FSEvents
  driver (`tributary-fs`) lowers into:
  - `OsRecord` now addresses its object by a watch-relative multi-segment
    `target` `Location` (`with_target`); the depth-one `with_name` shape stays
    the enforced contract for descending backends, and a violating record — a
    deep target on a descending monitor, or a self-event kind carrying any
    target — escalates to a `Rescan` of the arrival watch instead of being
    mis-attributed;
  - `Scope::Subtree` carries a `SubtreeScope` (nearest watch + descent), so a
    targeted deep overflow (FSEvents `MustScanSubDirs`) rescans exactly the
    affected directory rather than the whole root;
  - `Location::join` appends one location to another;
  - a kernel-recursive seeded storm (deep targets, located overflows, root
    self-events) alongside the existing per-directory storm.

- **`tributary-fs`** — the first source crate: the `std`, async filesystem
  driver over the `Monitor`, with macOS FSEvents as the first backend.
  - `os::macos`: one kernel-recursive `FSEventStream` per watched root
    (`UseExtendedData` file ids, `NoDefer`, `WatchRoot`, private serial
    dispatch-queue delivery), every unsafe platform call confined to one
    cfg-gated module — decode-in-callback to owned batches, `Arc`-via-release-
    hook context ownership, `dispatch_sync(Stop; Invalidate)` teardown
    quiescence, `catch_unwind` panic containment, and an overflow latch so a
    full channel degrades to a rescan instead of a lost event.
  - a sans-I/O driver core: FSEvents flags are grounded against `lstat` truth
    (never trusted as verbs), renames classify by file id into the Monitor's
    cookie-pairing window, kernel loss clamps to located subtree rescans, and
    a lagging consumer costs one epoch-dominating parked `Rescan` — loss is
    structurally never silent.
  - the runtime-agnostic consumer surface: `Watcher<R: RuntimeLite>`
    (`TokioWatcher`/`SmolWatcher` aliases), `WatcherOptions`, `Event` with
    absolute + root-relative paths and the epoch/rescan contract, disjoint-root
    enforcement, orderly `close()`; watching means "changes from now on".
  - macOS integration suite (convergence-style, real FSEvents) atop the
    hermetic fake-filesystem loop tests and the pure sans-I/O core tests.

- **`tributary-proto`** — the pure `no_std` (+`alloc`) Sans-I/O state machine at
  the heart of the `tributaries` filesystem-notification stack. The `Monitor` is
  the primitive-agnostic engine, written once and shared by every backend:
  - a parent-relative watch tree (`WatchId`-keyed nodes + a `(parent, name)`
    child index + a children adjacency set), so paths reconstruct by walking to
    a root and an intra-tree directory move is one edge change;
  - a per-node `NodeState` machine (`Arming` / `Live` / `Enumerating`) carrying
    request correlation, discovery-vs-re-arm intent, dirty tracking for raced
    reads, and per-obligation bounded retries;
  - a per-scope reconciliation **`Epoch`** stamped on every `Change` — the
    no-silent-loss contract: a `Rescan` always dominates what the consumer has
    seen, is never filtered, and every root invalidation signals it;
  - opaque, driver-sourced object **`Identity`** on records and directory
    entries, so an overflow re-arm keeps watches whose object provably survived
    and rebuilds same-name replacements;
  - a coverage/delivery **`Interest`** split: the backend mask is augmented with
    the structural kinds the tree needs, and delivery is narrowed back to the
    registered interest (with the `ondir` target-class modifier enforced
    wherever the class is known, including through move resolution);
  - move normalization: `(scope, cookie)` pairing with a bounded window,
    detach-and-hold O(1) subtree reparenting, a total stale-path fence for held
    subtrees, and cross-generation purging on root invalidation;
  - overflow handling as a dual obligation — consumer `Rescan` plus watch-set
    re-arm — with identity-diffed reconciliation and obligation-preserving
    coalescing;
  - a deterministic core (`BTreeMap`/`BTreeSet` only), a structural invariant
    validator, and a seeded random-schedule fuzz over the full input alphabet.
