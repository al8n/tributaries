<div align="center">
<h1>tributary-proto</h1>
</div>
<div align="center">

Pure Sans-I/O state machine — the *brain* of the `tributaries`
filesystem-notification stack. `no_std`-capable, modeled on [`quinn-proto`].

[<img alt="github" src="https://img.shields.io/badge/github-al8n/tributaries-8da0cb?style=for-the-badge&logo=Github" height="22">][Github-url]
<img alt="LoC" src="https://img.shields.io/endpoint?url=https%3A%2F%2Fgist.githubusercontent.com%2Fal8n%2F327b2a8aef9003246e45c6e47fe63937%2Fraw%2Ftributary-proto" height="22">
[<img alt="Build" src="https://img.shields.io/github/actions/workflow/status/al8n/tributaries/ci.yml?logo=Github-Actions&style=for-the-badge" height="22">][CI-url]
[<img alt="codecov" src="https://img.shields.io/codecov/c/gh/al8n/tributaries?style=for-the-badge&logo=codecov" height="22">][codecov-url]

[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-tributary--proto-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" height="22">][doc-url]
[<img alt="crates.io" src="https://img.shields.io/crates/v/tributary-proto?style=for-the-badge&logo=rust" height="22">][crates-url]
[<img alt="crates.io" src="https://img.shields.io/crates/d/tributary-proto?color=critical&logo=rust&style=for-the-badge" height="22">][crates-url]
<img alt="license" src="https://img.shields.io/badge/License-Apache%202.0/MIT-blue.svg?style=for-the-badge" height="22">

</div>

## Introduction

This crate contains **no I/O, no syscalls, and no clock reads**. It is the
quinn-proto-style core that a driver feeds normalized `OsRecord`s and drains `Action`s
and `Change`s from. All the logic the design calls out as easy to get wrong — recursion,
overflow handling, move pairing, watch-limit degradation — lives here as a pure,
testable state machine, written once and shared across every backend.

Most applications want the [`tributaries`] umbrella or the [`tributary-fs`] source
rather than this core directly. Reach for it when you are writing a driver of your own.

## Shape

The `Monitor` is the primitive-agnostic *top half*: it owns the proto-minted handle
registries (`WatchId`, `ReqId`, `ChangeId`), the parent-relative watch tree (so paths
are reconstructed by walking to a root), delivery dedup, move normalization, overflow →
`ChangeKind::Rescan`, emission, and — given the object `Identity` the driver supplies —
whether a same-name reappearance is the same object.

Backend-specific behavior enters only as *data*, never as a trait the engine is generic
over:

- the static `Capabilities` a monitor is built with, whose most load-bearing flag,
  `kernel_recursive`, selects whether the core descends per-directory or leans on one
  kernel-recursive watch per root;
- the optional `Identity` carried on each record and entry.

One `Monitor` can host mixed backends: `register_root_with_profile` gives a single
scope its own capability profile, so a driver selecting per root registers each with
the profile its backend actually satisfies.

`ScopeId` — one disjoint watched root — is *not* proto-minted: the layer above supplies
it and guarantees roots are disjoint. Time is not read either; every time-dependent
input takes a `now: Instant`, a `Duration` since an opaque per-process origin the
driver chooses, so the same logic is portable across `std`, embedded, and test clocks.

## Driver contract

| Direction | Entry points |
|-----------|--------------|
| driver → core | `on_os_record`, `on_enumerate`, `on_watch_result`, `on_overflow`, `handle_timeout` |
| core → driver | `poll_action`, `poll_event`, `poll_timeout` |

The driver owns the `WatchId` ↔ raw-handle table; the core never sees a raw OS handle.

```rust
use core::num::NonZeroU64;

use tributary_proto::{Capabilities, Interest, Monitor, ScopeId};

// A kernel-recursive profile (FSEvents, fanotify-FILESYSTEM, ReadDirectoryChangesW):
// one native mark covers the whole root, so the core does not descend.
let mut monitor = Monitor::new(Capabilities::new().with_kernel_recursive());
assert!(!monitor.descends());

// The layer above supplies the scope id for each disjoint root; the returned
// `WatchId` is the handle the queued action carries.
let scope = ScopeId::new(NonZeroU64::new(1).unwrap());
let root = monitor.register_root(scope, Interest::all());
assert_eq!(monitor.scope_of(root), Some(scope));

// Drain the work the registration produced. A real driver executes each action
// against the OS and reports the outcome back through `on_watch_result`.
while let Some(_action) = monitor.poll_action() {}
```

## Feature tiers

| Features | Environment |
|----------|-------------|
| `std` *(default)* | `std` hosts |
| *(none)* | `no_std` with a global allocator |

The crate floor is `alloc`: every configuration needs collections and strings, so with
`std` off the crate aliases `alloc` unconditionally rather than gating it behind a
feature of its own.

## Installation

```toml
[dependencies]
tributary-proto = "0.1"                                                # std (default)

# no_std with a global allocator:
tributary-proto = { version = "0.1", default-features = false }
```

The minimum supported Rust version (MSRV) is **1.95** (edition 2024).

## The family

[`tributaries`] (the consumer surface — overlapping subscriptions, attribution,
filters, debounce) · [`tributary-fs`] (the `std` async filesystem source, and the
reference driver for this core) · [`tributary-proto`] (this crate).

## License

`tributary-proto` is dual-licensed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE], [LICENSE-MIT] for details.

Copyright (c) 2026 Al Liu.

[`quinn-proto`]: https://crates.io/crates/quinn-proto
[`tributaries`]: https://crates.io/crates/tributaries
[`tributary-fs`]: https://crates.io/crates/tributary-fs
[`tributary-proto`]: https://crates.io/crates/tributary-proto
[LICENSE-APACHE]: https://github.com/al8n/tributaries/blob/main/LICENSE-APACHE
[LICENSE-MIT]: https://github.com/al8n/tributaries/blob/main/LICENSE-MIT
[Github-url]: https://github.com/al8n/tributaries/
[CI-url]: https://github.com/al8n/tributaries/actions/workflows/ci.yml
[codecov-url]: https://app.codecov.io/gh/al8n/tributaries/
[doc-url]: https://docs.rs/tributary-proto
[crates-url]: https://crates.io/crates/tributary-proto
