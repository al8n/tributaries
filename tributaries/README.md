<div align="center">
<h1>tributaries</h1>
</div>
<div align="center">

The public top-level crate of the `tributaries` filesystem-notification stack:
overlapping watch subscriptions, subsumed onto disjoint kernel roots and attributed
back to every covering subscriber.

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

[`tributary-fs`] deliberately watches only **disjoint** roots (it rejects a new root
that overlaps an existing one) because subsuming overlapping trees is the layer
above's job. `tributaries` is that layer. It:

1. accepts possibly-**overlapping** watch subscriptions from the caller and
   **subsumes** them into the disjoint roots `tributary-fs` requires — N overlapping
   subscriptions collapse to one kernel watch of their common ancestor;
2. **attributes** each raw event back to *every* caller subscription that covers its
   path, retagged with that subscription's id;
3. offers optional consumer conveniences — a filter and an opt-in settle/debounce
   coalescer — without touching the hardened core.

Everything hard (identity, move-pairing, loss-is-a-`Rescan`, epoch dominance) already
lives in the [`tributary-proto`] `Monitor` and ships through `tributary-fs`'s own
event type; `tributaries` adds routing and consumer ergonomics, not new correctness
logic.

The local-filesystem binding — `FsSource`, the `RootHandle` / `WatcherOptions`
re-exports, the pure-fs constructor and runtime aliases — rides the **`fs` feature, on
by default**. With it off, the crate is the generic core over `tributary-proto` alone:
bring your own `Source` (or `LocalSource`) and construct through
`Tributaries::with_source` / `Tributaries::parts` / `Tributaries::parts_local`.

## Installation

```toml
[dependencies]
tributaries = { version = "0.2", features = ["tokio"] }
```

The minimum supported Rust version (MSRV) is **1.95** (edition 2024).

## Quick start

Watch possibly-overlapping paths — each under its own per-watch `WatchOptions`
(interest, `Filter`, `Debounce` posture) — optionally settle bursts with a
`DebounceConfig`, and pull the merged, attributed stream. Each event is retagged with
the `Subscription` it belongs to, so one change under an overlap is delivered to every
covering subscription under its own id.

```rust,no_run
# #[cfg(all(feature = "tokio", feature = "fs"))]
# async fn demo() -> Result<(), Box<dyn std::error::Error>> {
use std::{ffi::OsString, path::Path};

use tributaries::{
  Debounce, DebounceConfig, Filter, TokioTributaries, TributariesOptions, WatchOptions,
  WatcherOptions,
};

// The local-fs source keys on a path's components (the caller supplies canonical paths).
fn key(path: &str) -> Vec<OsString> {
  Path::new(path)
    .components()
    .map(|c| c.as_os_str().to_os_string())
    .collect()
}

// The fs watcher's own transport options ride separately from the umbrella's knobs.
// Opt into the settle coalescer (omit `.debounce(..)` for raw pass-through).
let options = TributariesOptions::new().debounce(DebounceConfig::new());
let mut tributaries = TokioTributaries::new(WatcherOptions::new(), options)?;

// A subscription that only reports Rust sources — the filter is live-swappable.
let sources = Filter::new(|event| event.path().extension().is_some_and(|x| x == "rs"));
let handle = sources.clone(); // shares the swappable slot with the one `watch` holds
let project = tributaries
  .watch(
    key("/path/to/project"),
    (),
    WatchOptions::new().with_filter(sources),
  )
  .await?;

// An OVERLAPPING watch of a subtree — accepted, never `Overlaps`: it is subsumed
// onto the same kernel watch, and a change under it fans out to both subscriptions.
// Its per-watch Debounce::Off overrides the global debounce: raw pass-through for
// this subscription while `project` keeps settling.
let logs = tributaries
  .watch(
    key("/path/to/project/logs"),
    (),
    WatchOptions::new().with_debounce(Debounce::Off),
  )
  .await?;

// Re-scope what `project` delivers at any time — no re-watch:
handle.swap(|_| true);

// A SYNC BARRIER: after this resolves, every change made under `project`
// BEFORE the call is deliverable — read the stream and you will see it.
// Kernel-mediated (a cookie file whose own event rides the ordered queue
// behind those changes), never a hopeful sleep; the cookie is suppressed
// from the stream. `SyncOutcome` says whether the barrier was met by
// delivery or by a covering `Rescan` (re-enumerate then).
let outcome = tributaries
  .sync(project, std::time::Duration::from_secs(5))
  .await?;
if outcome.is_dominated() {
  // A loss stood a Rescan in for the cookie: re-read rather than replay.
}

while let Some(event) = tributaries.next().await {
  // `event.subscription()` is `project` or `logs`; a `Rescan` reaches every
  // subscriber of the affected root regardless of filter (coverage loss).
  println!(
    "{} [{}]: {}",
    event.kind(),
    event.subscription(),
    event.path().display()
  );
  let _ = (project, logs);
}
# Ok(())
# }
```

## Subsumption

The subsumption engine is the control plane: a sans-I/O state machine over an
[`iradix`] radix keyed by canonical root paths. It plans each `watch` into one of three
cases — the subtree is already covered, the new path *widens* over existing roots
(which are drained and re-pointed onto it), or it is disjoint — keeping the live root
set pairwise disjoint at all times. It is pure logic over paths and an abstract
root-id, so it is exhaustively property-tested with no real filesystem, clock, or
runtime.

## Settle / debounce (opt-in)

A caller that only cares about the *settled* state of a file — not every intermediate
write of an editor-save or a `cp` — can opt into the coalescer by setting a
`DebounceConfig` on `TributariesOptions`. It is a second sans-I/O state machine: it
buffers attributed events per `(subscription, path)` and collapses a burst to a single
emission on a settle timer, while treating a `Moved` atomically and flushing on a
`Rescan` so coverage loss is never held back or lost.

The global config is a per-subscription **default**: each watch can override its own
posture with a `Debounce` on its `WatchOptions` — `Debounce::Off` for raw pass-through
while siblings settle, `Debounce::Custom` for its own windows (which also *enables*
settling when the global debounce is off). Absent a `DebounceConfig` and absent any
`Custom` override, events pass through untouched at zero cost.

## Hosting on a `!Send` runtime

The umbrella runs on thread-per-core / completion-based apps (`compio`, a pinned
`LocalSet`) in either of two shapes:

- **A `Send` source, a `!Send` app** (the common case — the fs source is `Send`):
  spawn ONE auxiliary thread running any supported runtime, build there via
  `Tributaries::parts`, and poll the returned driver future on it. The whole handle
  plane is executor-agnostic and thread-mobile — `Tributaries` is `Clone + Send`,
  `WatchView` is a cheap `Clone + Send + Sync` read handle, `Subscription` is `Copy` —
  so `watch` / `unwatch` / `next` / `close` are awaitable from the `!Send` app
  directly; only the driver lives on the auxiliary thread. `Demux::parts` returns a
  `Send` routing future that can be hosted on either side.
- **A `!Send` source** (thread-local state, an `Rc`, a ring handle): implement
  `LocalSource` instead of `Source` and construct via `Tributaries::parts_local`; the
  returned driver future is `!Send` and must be polled on the thread that owns the
  source (`block_on`, `LocalSet::run_until`, or the executor's own local API).

Do **not** reach for [`agnostic-lite`]'s `spawn_local*` for either shape: its `smol`
local spawner panics (`smol` has no ambient thread-local executor to target) and its
`tokio` one panics outside a `LocalSet`. Poll the future directly, or use the host
executor's own local-spawn API.

## Feature flags

- **`fs`** *(default)* — the local-filesystem binding over [`tributary-fs`]. Off, the
  crate is the generic core over [`tributary-proto`] alone, and a custom-`Source`
  consumer skips the whole fs stack.
- **`tokio`** / **`smol`** — the async runtime, through [`agnostic-lite`]. Orthogonal
  to `fs`: they gate the driver's `TokioTributaries` / `SmolTributaries` aliases and
  forward the runtime into `tributary-fs` only when the fs binding is enabled too. The
  sans-I/O engines need no runtime.

## The family

[`tributaries`] (this crate — the consumer surface) · [`tributary-fs`] (the `std`
async filesystem source) · [`tributary-proto`] (the pure `no_std` Sans-I/O state
machine).

The identity and coordinate primitives — `ChangeId`, `Epoch`, `Location`, `Segment` —
are owned by `tributary-proto` and re-exported from here directly. The per-watch
`Interest` is **not** among them: the umbrella owns its own source-neutral mask
(aligned to its `EventKind`), and the proto/fs `Interest` stays a purely fs-internal
arm mask for consumers driving a raw fs watcher.

## License

`tributaries` is dual-licensed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE], [LICENSE-MIT] for details.

Copyright (c) 2026 Al Liu.

[`iradix`]: https://crates.io/crates/iradix
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
