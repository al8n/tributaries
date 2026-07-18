<div align="center">
<h1>tributaries</h1>
</div>
<div align="center">

A from-scratch, cross-platform, Sans-I/O filesystem-notification stack.

[<img alt="github" src="https://img.shields.io/badge/github-al8n/tributaries-8da0cb?style=for-the-badge&logo=Github" height="22">][Github-url]
[<img alt="Build" src="https://img.shields.io/github/actions/workflow/status/al8n/tributaries/ci.yml?logo=Github-Actions&style=for-the-badge" height="22">][CI-url]
[<img alt="codecov" src="https://img.shields.io/codecov/c/gh/al8n/tributaries?style=for-the-badge&logo=codecov" height="22">][codecov-url]
<img alt="license" src="https://img.shields.io/badge/License-Apache%202.0/MIT-blue.svg?style=for-the-badge" height="22">

</div>

## Overview

`tributaries` watches filesystem trees and delivers normalized, deduplicated,
loss-accounted change streams. Instead of wrapping an existing watcher, it is
built quinn-style: a pure state-machine core that owns all the logic that is
easy to get wrong — recursion, move pairing, queue overflow, watch-limit
degradation — and thin per-OS drivers that only perform I/O. It runs on macOS,
Linux, and Windows over any async runtime (tokio or smol).

## Crates

The split follows quinn/quinn-proto: a pure protocol crate, per-OS source
crates (the tributaries feeding the river), and one umbrella crate aggregating
them.

| crate | role |
|---|---|
| [`tributary-proto`](tributary-proto) | the pure `no_std` Sans-I/O state machine (the *brain*): the primitive-agnostic `Monitor` — watch tree, per-scope reconciliation epochs, driver-sourced object identity, coverage/delivery interest split, move normalization, overflow re-arm, and the coverage-settle fences that keep the sync barrier honest across a re-arming tree |
| [`tributary-fs`](tributary-fs) | the `std` async filesystem source: one hardened sans-I/O driver core (stat-grounded records, file-id rename pairing, lossless overflow/lag protocols, live root replacement) behind a runtime-agnostic `Watcher` (tokio/smol via `agnostic-lite`), driving a native backend per platform — **macOS** FSEvents, **Linux** inotify + fanotify, **Windows** `ReadDirectoryChangesW` + USN journal — auto-selected (`Backend::Auto`) or forced, with all unsafe FFI confined to internal modules |
| [`tributaries`](tributaries) | the umbrella consumer surface: it accepts possibly-**overlapping** subscriptions and subsumes them onto the disjoint kernel roots the source requires, **attributes** every event back to each covering subscription, and adds live-swappable filters, an opt-in settle/debounce coalescer, per-subscription snapshots, and a kernel-mediated `sync` barrier — routing and ergonomics, never new correctness logic |

## Design

The core never performs I/O, reads a clock, or sees a raw OS handle: drivers
push normalized records in and drain actions/changes out, so every hard case is
deterministic and testable as a pure state machine. Three properties anchor the
contract:

- **No silent loss.** Every `Change` carries its scope's reconciliation
  `Epoch`; whenever coverage becomes uncertain (queue overflow, an unreadable
  directory, a lost root) the consumer receives a `Rescan` that strictly
  dominates everything it has seen — never filtered, no matter the registered
  interest.
- **Coverage is delivery-independent.** The watch tree subscribes to whatever
  structural events it needs to stay complete, regardless of which change kinds
  the consumer asked to receive.
- **The sync barrier is exact, never hopeful.** `sync` writes a kernel cookie
  whose own event rides the ordered queue *behind* every change made before the
  call, so when it resolves those changes are provably deliverable — met either
  by delivery, or, if a loss intervened, by a dominating `Rescan`
  (`SyncOutcome::Dominated`, the signal to re-enumerate). It is kernel-mediated,
  never a sleep, and the cookie is suppressed from the stream.

## Quick start

Watch possibly-overlapping paths, cross an exact barrier, and pull the merged,
per-subscription-attributed stream:

```rust,no_run
use std::{ffi::OsString, path::Path, time::Duration};

use tributaries::{TokioTributaries, TributariesOptions, WatchOptions, WatcherOptions};

// The local-fs source keys on a path's canonical components.
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

The umbrella rides the `fs` feature (on by default); turn it off to run the
generic core over `tributary-proto` with your own `Source`. Choose the async
runtime with the `tokio` or `smol` feature. See the [`tributaries`](tributaries)
crate docs for the full API — filters, debounce, snapshots, and forcing or
probing a backend.

## License

`tributaries` is dual-licensed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE), [LICENSE-MIT](LICENSE-MIT) for details.

Copyright (c) 2026 Al Liu.

[Github-url]: https://github.com/al8n/tributaries/
[CI-url]: https://github.com/al8n/tributaries/actions/workflows/ci.yml
[codecov-url]: https://app.codecov.io/gh/al8n/tributaries/
