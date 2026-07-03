<div align="center">
<h1>tributaries</h1>
</div>
<div align="center">

从零实现的跨平台 Sans-I/O 文件系统通知栈。

[<img alt="github" src="https://img.shields.io/badge/github-al8n/tributaries-8da0cb?style=for-the-badge&logo=Github" height="22">][Github-url]
[<img alt="Build" src="https://img.shields.io/github/actions/workflow/status/al8n/tributaries/ci.yml?logo=Github-Actions&style=for-the-badge" height="22">][CI-url]
[<img alt="codecov" src="https://img.shields.io/codecov/c/gh/al8n/tributaries?style=for-the-badge&logo=codecov" height="22">][codecov-url]
<img alt="license" src="https://img.shields.io/badge/License-Apache%202.0/MIT-blue.svg?style=for-the-badge" height="22">

[English][en-url] | 简体中文

</div>

## 概览

`tributaries` 监视文件系统目录树，输出归一化、去重且不静默丢失的变更流。它不是
对现有 watcher 的包装，而是 quinn 式的架构：一个纯状态机内核承担所有易错逻辑
（递归、重命名配对、队列溢出、watch 上限降级），各操作系统只保留极薄的 I/O
驱动层。

## Crates

crate 划分沿用 quinn/quinn-proto 模式：一个纯协议 crate，加上按 OS 划分的
source crate（汇入干流的支流），以及一个聚合它们的伞形 crate。

| crate | 状态 | 职责 |
|---|---|---|
| [`tributary-proto`](tributary-proto) | 基础完成 | 纯 `no_std` Sans-I/O 状态机（“大脑”）：与后端无关的 `Monitor` —— watch 树、按 scope 的 reconciliation epoch、驱动提供的对象 identity、覆盖/投递 interest 分离、move 归一化、溢出 re-arm |
| [`tributary-fs`](tributary-fs) | macOS 完成 | `std` 异步文件系统 source：FSEvents 后端（每个根一条内核递归流，全部 unsafe FFI 收敛在一个内部模块）、sans-I/O 驱动核心（stat 校真记录、file-id 重命名配对、无损溢出/滞后协议），以及运行时无关的 `Watcher` API（经 `agnostic-lite` 支持 tokio/smol）；Linux inotify/fanotify 为后续目标 |
| `tributaries` | 规划中 | 聚合各 source crate（`tributary-fs`，以及后续的对象存储 source）的伞形 crate，对外提供统一的消费者接口 |

## 设计

内核不做任何 I/O、不读时钟、也看不到任何原生 OS 句柄：驱动向内核推入归一化的
记录，再取出动作与变更，因此所有困难场景都是确定性的、可作为纯状态机测试的。
契约的两个支点：

- **不静默丢失。** 每个 `Change` 携带其 scope 的 reconciliation `Epoch`；一旦
  覆盖变得不确定（队列溢出、目录不可读、根丢失），消费者一定会收到一个严格
  支配其已见内容的 `Rescan` —— 无论注册的 interest 是什么，它永不被过滤。
- **覆盖独立于投递。** watch 树始终订阅维持自身完整所需的结构性事件，与消费者
  要求接收哪些变更种类无关。

## License

`tributaries` 以 MIT 与 Apache License (Version 2.0) 双许可发布。

详见 [LICENSE-APACHE](LICENSE-APACHE)、[LICENSE-MIT](LICENSE-MIT)。

Copyright (c) 2026 Al Liu.

[Github-url]: https://github.com/al8n/tributaries/
[CI-url]: https://github.com/al8n/tributaries/actions/workflows/ci.yml
[codecov-url]: https://app.codecov.io/gh/al8n/tributaries/
[en-url]: https://github.com/al8n/tributaries/tree/main/README.md
