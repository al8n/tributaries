<div align="center">
<h1>tributary-fs</h1>
</div>
<div align="center">

The filesystem source crate of the [`tributaries`](https://github.com/al8n/tributaries) stack: an async,
runtime-agnostic watcher over the Sans-I/O `tributary-proto` Monitor. First
backend: macOS FSEvents.

[<img alt="github" src="https://img.shields.io/badge/github-al8n/tributaries-8da0cb?style=for-the-badge&logo=Github" height="22">][Github-url]
[<img alt="Build" src="https://img.shields.io/github/actions/workflow/status/al8n/tributaries/ci.yml?logo=Github-Actions&style=for-the-badge" height="22">][CI-url]
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-tributary--fs-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" height="22">][doc-url]

</div>

## Overview

`tributary-fs` does the real OS filesystem watching and lowers raw kernel
events into the Monitor's normalized vocabulary. All the logic that is easy to
get wrong lives in testable, sans-I/O layers; the OS callback only decodes.

- **macOS FSEvents backend** — one kernel-recursive stream per watched root,
  file-id object identity, every unsafe platform call confined to one internal
  cfg-gated module.
- **Truth-grounded events** — FSEvents flags are hints (one event can carry
  created+modified+removed+renamed OR'd together); records are grounded
  against `lstat` before delivery, and renames pair by file id into a bounded
  window with a safe remove+create degrade.
- **Loss is never silent** — kernel drops, a full buffer, a vanished root:
  every coverage gap surfaces as a `Rescan` event whose epoch dominates
  everything delivered before it.
- **Runtime-agnostic** — `Watcher<R: RuntimeLite>` with `tokio`/`smol`
  features (`TokioWatcher`, `SmolWatcher`); the crate compiles on every
  platform (non-macOS backends return `Unsupported` until inotify/fanotify
  land).

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

Watching means **"changes from now on"**: no initial inventory is delivered.
Consumers that need a snapshot start the watch first, then crawl — changes
racing the crawl arrive as events, and grounding makes the overlap idempotent.

#### License

`tributary-fs` is under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](../LICENSE-APACHE), [LICENSE-MIT](../LICENSE-MIT) for details.

Copyright (c) 2026 Al Liu.

[Github-url]: https://github.com/al8n/tributaries/
[CI-url]: https://github.com/al8n/tributaries/actions/workflows/ci.yml
[doc-url]: https://docs.rs/tributary-fs
