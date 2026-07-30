<div align="center">
<h1>tributary-fs</h1>
</div>
<div align="center">

The filesystem source crate of the `tributaries` stack: an async, runtime-agnostic
watcher over the Sans-I/O [`tributary-proto`] `Monitor`, driving a native backend per
platform.

[<img alt="github" src="https://img.shields.io/badge/github-al8n/tributaries-8da0cb?style=for-the-badge&logo=Github" height="22">][Github-url]
<img alt="LoC" src="https://img.shields.io/endpoint?url=https%3A%2F%2Fgist.githubusercontent.com%2Fal8n%2F327b2a8aef9003246e45c6e47fe63937%2Fraw%2Ftributary-fs" height="22">
[<img alt="Build" src="https://img.shields.io/github/actions/workflow/status/al8n/tributaries/ci.yml?logo=Github-Actions&style=for-the-badge" height="22">][CI-url]
[<img alt="codecov" src="https://img.shields.io/codecov/c/gh/al8n/tributaries?style=for-the-badge&logo=codecov" height="22">][codecov-url]

[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-tributary--fs-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" height="22">][doc-url]
[<img alt="crates.io" src="https://img.shields.io/crates/v/tributary-fs?style=for-the-badge&logo=rust" height="22">][crates-url]
[<img alt="crates.io" src="https://img.shields.io/crates/d/tributary-fs?color=critical&logo=rust&style=for-the-badge" height="22">][crates-url]
<img alt="license" src="https://img.shields.io/badge/License-Apache%202.0/MIT-blue.svg?style=for-the-badge" height="22">

</div>

## Introduction

`tributary-fs` is the `std`, async driver layer over the Sans-I/O [`tributary-proto`]
`Monitor`: it performs the real OS filesystem watching and lowers raw kernel events
into the Monitor's normalized vocabulary. All the logic that is easy to get wrong lives
in testable, sans-I/O layers; the OS callback only decodes.

- **Truth-grounded events.** A backend's flag word is a hint, not a verdict — one
  FSEvents event can carry created + modified + removed + renamed OR'd together — so
  records are grounded against `lstat` before delivery, and renames pair by file id
  into a bounded window with a safe remove + create degrade.
- **Loss is never silent.** Kernel drops, a full buffer, a vanished root: every
  coverage gap surfaces as a `Rescan` event whose epoch dominates everything delivered
  before it.
- **Runtime-agnostic.** `Watcher<R: RuntimeLite>` over [`agnostic-lite`], with
  `TokioWatcher` / `SmolWatcher` aliases behind the `tokio` / `smol` features — or
  bring any other `RuntimeLite` implementation.
- **Unsafe is quarantined.** Every unsafe platform call is confined to an internal,
  cfg-gated module behind a platform-neutral seam.

`tributary-fs` watches only **disjoint** roots and rejects a new root that overlaps a
live one; subsuming overlapping trees is the [`tributaries`] umbrella's job.

## Backends

A backend is selected per disjoint root — `Backend::Auto` by default, or forced, in
which case a failing precondition is a typed spawn error rather than a silent
fallback. A kernel-recursive backend covers a whole root with one native mark and the
core does not descend; the per-directory profile arms a watch before reading each new
directory.

| `BackendKind` | Platform | Profile |
|---------------|----------|---------|
| `FsEvents` | macOS | kernel-recursive; flag words are hints |
| `Inotify` | Linux | per-directory (descending); precise verbs, unprivileged — the universal default |
| `Fanotify` | Linux | fanotify-FILESYSTEM: kernel-recursive, precise verbs, membership-only admission. Privileged (`CAP_SYS_ADMIN`) |
| `Rdcw` | Windows | `ReadDirectoryChangesW`: kernel-recursive, unprivileged; the per-volume fallback when the USN journal is unusable |
| `UsnJournal` | Windows | USN change journal: kernel-recursive, journal-cursor sourced; volume-handle access effectively requires elevation |

`Watcher::backend_of` reports what a live root actually settled on, and
`Watcher::backend_stats` surfaces the fanotify admission-map counters for a root that
keeps one. The crate compiles on every platform; where no backend exists, watching
returns `SourceError::Unsupported`.

## Installation

```toml
[dependencies]
tributary-fs = { version = "0.1", features = ["tokio"] }
```

The minimum supported Rust version (MSRV) is **1.95** (edition 2024).

## Quick start

```rust,no_run
# #[cfg(feature = "tokio")]
# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
use tributary_fs::{Interest, TokioWatcher, WatcherOptions};

let mut watcher = TokioWatcher::new(WatcherOptions::new())?;
let root = watcher.watch("/path/to/project", Interest::all()).await?;
println!("watching {:?}", watcher.root_path(root));
while let Some(event) = watcher.next().await {
  println!("{}: {}", event.kind(), event.path().display());
}
# Ok(())
# }
```

`WatcherOptions` carries the transport knobs: the coalescing latency, the rename
pairing window, the event and OS-batch capacities, path exclusions, the root-liveness
probe interval, the fanotify admission-map directory cap, and the `Backend` selection.

## The two contracts

- **Watching means "changes from now on."** No initial inventory is delivered.
  Consumers that need a snapshot start the watch first, then crawl — changes racing the
  crawl arrive as events, and grounding makes the overlap idempotent.
- **Loss is never silent.** Every coverage gap surfaces as a `Rescan` event whose
  epoch dominates everything delivered before it. That epoch is the re-enumeration
  contract: everything the consumer saw at a lower epoch is superseded, and a `Rescan`
  is delivered regardless of the registered interest.

## Feature flags

No feature is on by default; pick a runtime.

- **`tokio`** — the `TokioWatcher` alias, through [`agnostic-lite`].
- **`smol`** — the `SmolWatcher` alias, through [`agnostic-lite`].

Any other [`agnostic-lite`] `RuntimeLite` implementation can drive `Watcher<R>`
without a feature of its own.

## The family

[`tributaries`] (the consumer surface — overlapping subscriptions, attribution,
filters, debounce) · [`tributary-fs`] (this crate — the `std` async filesystem
source) · [`tributary-proto`] (the pure `no_std` Sans-I/O state machine).

Most applications want the [`tributaries`] umbrella. Reach for this crate directly when
you manage disjoint roots yourself, or when you are binding the fs watcher into your
own `Source`.

## License

`tributary-fs` is dual-licensed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE], [LICENSE-MIT] for details.

Copyright (c) 2026 Al Liu.

[`agnostic-lite`]: https://crates.io/crates/agnostic-lite
[`tributaries`]: https://crates.io/crates/tributaries
[`tributary-fs`]: https://crates.io/crates/tributary-fs
[`tributary-proto`]: https://crates.io/crates/tributary-proto
[LICENSE-APACHE]: https://github.com/al8n/tributaries/blob/main/LICENSE-APACHE
[LICENSE-MIT]: https://github.com/al8n/tributaries/blob/main/LICENSE-MIT
[Github-url]: https://github.com/al8n/tributaries/
[CI-url]: https://github.com/al8n/tributaries/actions/workflows/ci.yml
[codecov-url]: https://app.codecov.io/gh/al8n/tributaries/
[doc-url]: https://docs.rs/tributary-fs
[crates-url]: https://crates.io/crates/tributary-fs
