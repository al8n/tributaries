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
  refused before any write, as the new `SyncRootError::DirPruned`.

  Patterns are `tributary_proto::glob::Glob` (re-exported as `tributary_fs::Glob`),
  matched case-insensitively with `literal_separator` — `*` never crosses a `/`,
  `**/` spans any depth including zero, so `**/node_modules` matches
  `node_modules` at any depth while `a/cache` names one place. Pattern and
  candidate are both folded to NFC, so a composed pattern matches a decomposed
  filesystem name (and back). They live behind `tributary-proto`'s new `glob`
  feature, which `tributary-fs` and `tributaries` enable unconditionally; both
  faces carry them (serde: lists of plain strings; clap: repeatable `--prune` /
  `--include` flags, an absent `--include` being the absent seat).

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
  - A cookie directory the root's own `prune` seat covers reaches a `sync` caller as
    `SyncError::CookieDirUncovered` — the same verdict as one outside the root or under a
    watcher exclusion, all three being "no event could ever arrive there" — rather than as
    a write failure it would be pointless to retry.
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

### Changed

- **`tributaries`** — **BREAKING for a custom `Source`**: `Source::arm` and
  `LocalSource::arm` take the per-root `&RootGlobs` as a third argument
  (`arm(&mut self, key: &[C], globs: &RootGlobs)`). An out-of-tree source must accept
  the parameter and either honour both seats or document in its own docs that it cannot
  — nothing above the seam re-checks them, so a source that ignores one silently
  watches or delivers what the caller asked it not to. `RootGlobs::new()` (both seats
  unengaged) asks for exactly the behaviour every source had before the seats existed.
  Every other seam item is unchanged, including canonical-key adoption.

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
