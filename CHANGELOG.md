# Changelog

All notable changes to this workspace are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crates adhere to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
