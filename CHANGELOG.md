# Changelog

All notable changes to this workspace are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crates adhere to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
