<div align="center">
<h1>tributaries</h1>
</div>
<div align="center">

A from-scratch, cross-platform, Sans-I/O filesystem-notification stack.

[<img alt="github" src="https://img.shields.io/badge/github-al8n/tributaries-8da0cb?style=for-the-badge&logo=Github" height="22">][Github-url]
[<img alt="Build" src="https://img.shields.io/github/actions/workflow/status/al8n/tributaries/ci.yml?logo=Github-Actions&style=for-the-badge" height="22">][CI-url]
[<img alt="codecov" src="https://img.shields.io/codecov/c/gh/al8n/tributaries?style=for-the-badge&logo=codecov" height="22">][codecov-url]
<img alt="license" src="https://img.shields.io/badge/License-Apache%202.0/MIT-blue.svg?style=for-the-badge" height="22">

English | [简体中文][zh-cn-url]

</div>

## Overview

`tributaries` watches filesystem trees and delivers normalized, deduplicated,
loss-accounted change streams. Instead of wrapping an existing watcher, it is
built quinn-style: a pure state-machine core that owns all the logic that is
easy to get wrong — recursion, move pairing, queue overflow, watch-limit
degradation — and thin per-OS drivers that only perform I/O.

## Crates

The split follows quinn/quinn-proto: a pure protocol crate, per-OS source
crates (the tributaries feeding the river), and one umbrella crate aggregating
them.

| crate | status | role |
|---|---|---|
| [`tributary-proto`](tributary-proto) | foundation complete | the pure `no_std` Sans-I/O state machine (the *brain*): the primitive-agnostic `Monitor` — watch tree, per-scope reconciliation epochs, driver-sourced object identity, coverage/delivery interest split, move normalization, overflow re-arm |
| [`tributary-fs`](tributary-fs) | macOS complete | the `std` async filesystem source: the FSEvents backend (one kernel-recursive stream per root, all unsafe FFI in one internal module), a sans-I/O driver core (stat-grounded records, file-id rename pairing, lossless overflow/lag protocols), and the runtime-agnostic `Watcher` API (tokio/smol via `agnostic-lite`); Linux inotify/fanotify next |
| `tributaries` | planned | the umbrella crate aggregating the source crates (`tributary-fs`, and later object-store sources) behind one consumer surface |

## Design

The core never performs I/O, reads a clock, or sees a raw OS handle: drivers
push normalized records in and drain actions/changes out, so every hard case is
deterministic and testable as a pure state machine. Two properties anchor the
contract:

- **No silent loss.** Every `Change` carries its scope's reconciliation
  `Epoch`; whenever coverage becomes uncertain (queue overflow, an unreadable
  directory, a lost root) the consumer receives a `Rescan` that strictly
  dominates everything it has seen — never filtered, no matter the registered
  interest.
- **Coverage is delivery-independent.** The watch tree subscribes to whatever
  structural events it needs to stay complete, regardless of which change kinds
  the consumer asked to receive.

## License

`tributaries` is dual-licensed under the terms of both the MIT license and the
Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE), [LICENSE-MIT](LICENSE-MIT) for details.

Copyright (c) 2026 Al Liu.

[Github-url]: https://github.com/al8n/tributaries/
[CI-url]: https://github.com/al8n/tributaries/actions/workflows/ci.yml
[codecov-url]: https://app.codecov.io/gh/al8n/tributaries/
[zh-cn-url]: https://github.com/al8n/tributaries/tree/main/README-zh_CN.md
