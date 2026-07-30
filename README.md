<div align="center">
<h1>tributaries</h1>
</div>
<div align="center">

A from-scratch, cross-platform, **Sans-I/O** filesystem-notification stack for Rust — a
pure state-machine core with thin per-OS async drivers.

[<img alt="github" src="https://img.shields.io/badge/github-al8n/tributaries-8da0cb?style=for-the-badge&logo=Github" height="22">][Github-url]
<img alt="LoC" src="https://img.shields.io/endpoint?url=https%3A%2F%2Fgist.githubusercontent.com%2Fal8n%2F327b2a8aef9003246e45c6e47fe63937%2Fraw%2Ftributaries" height="22">
[<img alt="Build" src="https://img.shields.io/github/actions/workflow/status/al8n/tributaries/ci.yml?logo=Github-Actions&style=for-the-badge" height="22">][CI-url]
[<img alt="codecov" src="https://img.shields.io/codecov/c/gh/al8n/tributaries?style=for-the-badge&logo=codecov" height="22">][codecov-url]

[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-tributaries-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" height="22">][doc-url]
[<img alt="crates.io" src="https://img.shields.io/crates/v/tributaries?style=for-the-badge&logo=rust" height="22">][crates-url]
[<img alt="crates.io" src="https://img.shields.io/crates/d/tributaries?color=critical&logo=rust&style=for-the-badge" height="22">][crates-url]
<img alt="license" src="https://img.shields.io/badge/License-Apache%202.0/MIT-blue.svg?style=for-the-badge" height="22">

</div>

## Introduction

`tributaries` watches filesystem trees and delivers normalized, deduplicated,
loss-accounted change streams. Instead of wrapping an existing watcher, it is built
quinn-style: a pure state-machine core that owns all the logic that is easy to get
wrong — recursion, move pairing, queue overflow, watch-limit degradation — and thin
per-OS drivers that only perform I/O. It runs on macOS, Linux, and Windows over any
async runtime (`tokio` or `smol`).

The core never performs I/O, reads a clock, or sees a raw OS handle: drivers push
normalized records in and drain actions and changes out, so every hard case is
deterministic and testable as a pure state machine, written once and shared across
every backend.

## The family

The split follows the `quinn` / [`quinn-proto`] layering: a pure protocol crate, a
per-OS source crate (the tributaries feeding the river), and one umbrella crate
aggregating them.

| Crate | Role |
|-------|------|
| [`tributaries`] | the umbrella consumer surface — overlapping subscriptions, attribution, filters, debounce, snapshots, the `sync` barrier |
| [`tributary-fs`] | the `std` async filesystem source: one hardened driver core behind a runtime-agnostic `Watcher`, driving a native backend per platform |
| [`tributary-proto`] | the pure `no_std` Sans-I/O state machine (the *brain*): the primitive-agnostic `Monitor` |

`tributary-proto` owns the watch tree, per-scope reconciliation epochs,
driver-sourced object identity, the coverage/delivery interest split, move
normalization, overflow re-arm, and the coverage-settle fences that keep the sync
barrier honest across a re-arming tree. `tributary-fs` owns the syscalls: the
`WatchId` ↔ raw-handle table, stat-grounded records, file-id rename pairing, the
lossless overflow/lag protocols, and live root replacement. `tributaries` accepts
possibly-**overlapping** subscriptions, subsumes them onto the disjoint kernel roots
the source requires, **attributes** every event back to each covering subscription,
and adds live-swappable filters, an opt-in settle/debounce coalescer, and
per-subscription snapshots — routing and ergonomics, never new correctness logic.

## Design

Three properties anchor the contract:

- **No silent loss.** Every change carries its scope's reconciliation `Epoch`;
  whenever coverage becomes uncertain (queue overflow, an unreadable directory, a
  lost root) the consumer receives a `Rescan` that strictly dominates everything it
  has seen — never filtered, no matter the registered interest.
- **Coverage is delivery-independent.** The watch tree subscribes to whatever
  structural events it needs to stay complete, regardless of which change kinds the
  consumer asked to receive.
- **The sync barrier is exact, never hopeful.** `sync` writes a kernel cookie whose
  own event rides the ordered queue *behind* every change made before the call, so
  when it resolves those changes are provably deliverable — met either by delivery,
  or, if a loss intervened, by a dominating `Rescan` (the signal to re-enumerate). It
  is kernel-mediated, never a sleep, and the cookie is suppressed from the stream.

## Platform backends

`tributary-fs` selects a native primitive per disjoint root — `Backend::Auto` by
default, or forced, in which case a failing precondition is a typed spawn error
rather than a silent fallback. A kernel-recursive backend covers a whole root with one
mark and the core does not descend; the per-directory profile arms a watch before
reading each new directory.

| Backend | Platform | Profile |
|---------|----------|---------|
| FSEvents | macOS | kernel-recursive; flag words are hints, so records are grounded against `lstat` |
| inotify | Linux | per-directory (descending); precise verbs, unprivileged — the universal default |
| fanotify-FILESYSTEM | Linux | kernel-recursive; precise verbs, membership-only admission. Privileged (`CAP_SYS_ADMIN`) |
| `ReadDirectoryChangesW` | Windows | kernel-recursive, unprivileged; the per-volume fallback when the USN journal is unusable |
| USN change journal | Windows | kernel-recursive, journal-cursor sourced; volume-handle access effectively requires elevation |

Every unsafe platform call is confined to an internal, cfg-gated module behind a
platform-neutral seam. On a platform with no backend the crate still compiles and
watching reports `Unsupported`.

## Installation

```toml
[dependencies]
tributaries = { version = "0.1", features = ["tokio"] }
```

The minimum supported Rust version (MSRV) is **1.95** (edition 2024).

## Example

Watch possibly-overlapping paths, cross an exact barrier, and pull the merged,
per-subscription-attributed stream:

```rust,ignore
use std::{ffi::OsString, path::Path, time::Duration};

use tributaries::{TokioTributaries, TributariesOptions, WatchOptions, WatcherOptions};

// The local-fs source keys on a path's components.
fn key(path: &str) -> Vec<OsString> {
  Path::new(path)
    .components()
    .map(|c| c.as_os_str().to_os_string())
    .collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let mut tributaries =
    TokioTributaries::new(WatcherOptions::new(), TributariesOptions::new())?;

  // Overlapping watches are subsumed onto one kernel watch, yet every event is
  // still attributed to each covering subscription under its own id.
  let project = tributaries
    .watch(key("/path/to/project"), (), WatchOptions::new())
    .await?;

  // A barrier: once it resolves, every change made under `project` before the
  // call is deliverable — you will see it in the stream (or a dominating Rescan).
  tributaries.sync(project, Duration::from_secs(5)).await?;

  while let Some(event) = tributaries.next().await {
    println!(
      "{} [{}]: {}",
      event.kind(),
      event.subscription(),
      event.path().display()
    );
  }
  Ok(())
}
```

See the [`tributaries`] crate docs for the full API — filters, debounce, snapshots,
and forcing or probing a backend.

## Feature flags

- **`fs`** *(default)* — the local-filesystem binding: `FsSource`, the
  `RootHandle` / `WatcherOptions` re-exports, the pure-fs constructor and the runtime
  aliases. Turn it off to run the generic core over [`tributary-proto`] alone with your
  own `Source`.
- **`tokio`** / **`smol`** — the async runtime, through [`agnostic-lite`]. Orthogonal
  to `fs`: they gate the driver's `Tokio*` / `Smol*` aliases and forward the runtime
  into [`tributary-fs`] only when the fs binding is enabled too. The sans-I/O engines
  need no runtime at all.

[`tributary-proto`] is `no_std`-capable on its own: `std` *(default)*, or
`default-features = false` for `no_std` with an allocator.

## License

`tributaries` is dual-licensed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE], [LICENSE-MIT] for details.

Copyright (c) 2026 Al Liu.

[`quinn-proto`]: https://crates.io/crates/quinn-proto
[`agnostic-lite`]: https://crates.io/crates/agnostic-lite
[`tributaries`]: https://crates.io/crates/tributaries
[`tributary-fs`]: https://crates.io/crates/tributary-fs
[`tributary-proto`]: https://crates.io/crates/tributary-proto
[LICENSE-APACHE]: https://github.com/al8n/tributaries/blob/main/LICENSE-APACHE
[LICENSE-MIT]: https://github.com/al8n/tributaries/blob/main/LICENSE-MIT
[Github-url]: https://github.com/al8n/tributaries/
[CI-url]: https://github.com/al8n/tributaries/actions/workflows/ci.yml
[codecov-url]: https://app.codecov.io/gh/al8n/tributaries/
[doc-url]: https://docs.rs/tributaries
[crates-url]: https://crates.io/crates/tributaries
