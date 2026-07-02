# Changelog

All notable changes to this workspace are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crates adhere to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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

## [0.1.0]

### Added

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
