#!/bin/bash
set -e
# `run_shard` reads the count out of a tee'd log, so a cargo that dies must
# still fail the pipeline rather than hand the gate an empty log to judge.
set -o pipefail

if [ -z "$1" ]; then
  echo "Error: TARGET is not provided"
  exit 1
fi

TARGET="$1"
# Optional 2nd arg: which shard of the suite this process runs (see the case
# below). Omitted => the whole workspace in one pass.
TEST_GROUP="${2:-}"

# Install cross-compilation toolchain on Linux
if [ "$(uname)" = "Linux" ]; then
  case "$TARGET" in
    aarch64-unknown-linux-gnu)
      sudo apt-get update && sudo apt-get install -y gcc-aarch64-linux-gnu
      ;;
    i686-unknown-linux-gnu)
      sudo apt-get update && sudo apt-get install -y gcc-multilib
      ;;
    powerpc64-unknown-linux-gnu)
      sudo apt-get update && sudo apt-get install -y gcc-powerpc64-linux-gnu
      ;;
    s390x-unknown-linux-gnu)
      sudo apt-get update && sudo apt-get install -y gcc-s390x-linux-gnu
      ;;
    riscv64gc-unknown-linux-gnu)
      sudo apt-get update && sudo apt-get install -y gcc-riscv64-linux-gnu
      ;;
  esac
fi

rustup toolchain install nightly --component miri
rustup override set nightly
cargo miri setup

# The glob engine (globset, pulled in through regex-automata) depends on memchr,
# whose fallback word loads compute an aligned pointer by address arithmetic
# rather than by construction. The SYMBOLIC alignment check flags that
# arithmetic as UB by design — Miri documents this as a known false-positive
# class of the flag, not a bug in memchr or in this crate's own code. Miri's
# default alignment check stays on and still enforces real alignment here.
export MIRIFLAGS="-Zmiri-strict-provenance -Zmiri-disable-isolation -Zmiri-tree-borrows"

# Miri reports ONE cpu unless told otherwise, and `available_parallelism` is what a
# multi-threaded runtime sizes its worker pool from — so every `flavor = "multi_thread"`
# cell silently runs on a single worker here. A cell that stages an always-ready command
# source then starves the whole EXECUTOR rather than the one select arm it means to
# starve: the driver task holds the only worker and never yields it, the task that would
# wind the flood down is never polled again, and the run makes no further progress at
# all. Two is the smallest count that keeps "multi-threaded" honest.
MIRIFLAGS="$MIRIFLAGS -Zmiri-num-cpus=2"

# ...and libtest sizes its own default thread count from the SAME number, so raising
# it would otherwise put two cells on the interpreter at once. That is not throughput
# — there is one interpreter either way, so the two only halve each other's share —
# and it costs: the heaviest cells are the ones that then run concurrently, and a
# 32-bit run pays for both cells' live allocations out of one 4 GB space. One test
# per process keeps each cell's wall time its own and its address space its own.
export RUST_TEST_THREADS=1

# 32-bit targets share one 4 GB address space across a lib test binary, and miri's
# default partial address reuse (-Zmiri-address-reuse-rate=0.5) leaves a long suite
# short of it. Full reuse buys most of that back and is part of what makes these shards
# fit — but it raises the ceiling rather than removing it. An allocation rate nothing
# bounds still reaches the end of the space, and the report then names the cell that was
# allocating rather than whichever one happened to run last. 64-bit cells keep the
# stricter default.
case "$TARGET" in
  i686-*)
    export MIRIFLAGS="$MIRIFLAGS -Zmiri-address-reuse-rate=1.0 -Zmiri-address-reuse-cross-thread-rate=1.0"
    ;;
esac

SHARD_LOG="$(mktemp)"
trap 'rm -f "$SHARD_LOG"' EXIT

# Every shard runs THROUGH this, and a shard that executed nothing is red.
#
# A libtest filter that matches nothing exits 0 and prints a healthy-looking
# `test result: ok.` line, so a vacuous shard is otherwise indistinguishable from
# a shard that proved something. That is not hypothetical here: the three
# `driver::` shards filtered on `driver::tests::` while passing no features at
# all, and `driver::tests` is `#[cfg(all(test, feature = "tokio"))]` — so they
# ran 0 tests and reported success on every target, in both borrow models, for
# their whole existence. The feature set below fixes those three; this gate is
# what makes the NEXT filter typo fail loudly instead of joining them.
#
# It mirrors the "Assert neither leg was vacuous" step the Linux legs carry in
# .github/workflows/ci.yml, kept in the script rather than the workflow so a
# local shard run is held to the same bar as a hosted one.
#
# The count is the sum over every test binary the shard ran, not a per-binary
# floor: `tributary-fs/tests/watcher.rs` is `#![cfg(..., not(miri))]` and so is
# legitimately empty HERE, and a per-binary floor would fail on it forever.
run_shard() {
  "$@" 2>&1 | tee "$SHARD_LOG"

  local executed
  executed=$(grep -ho 'test result: ok\. [0-9]\+ passed' "$SHARD_LOG" \
    | awk '{ sum += $4 } END { print sum + 0 }')
  if [ "$executed" -eq 0 ]; then
    echo "::error::miri shard '${TEST_GROUP:-whole-workspace}' on $TARGET executed 0 tests; a filter that matches nothing exits 0, so this shard proved nothing" >&2
    exit 1
  fi
  echo "miri shard '${TEST_GROUP:-whole-workspace}' on $TARGET executed $executed tests"
}

# The suite runs one shard per process, and the partition covers every workspace
# test exactly once: the six `fs-*` groups partition tributary-fs by test-name
# prefix, the two `proto-monitor-*` groups partition the monitor suite,
# `proto-rest` is everything else in tributary-proto, and the two `umbrella-*`
# groups partition the tributaries crate's own suite.
#
# All six `fs-*` shards pass `--features tokio,sync`, and they must agree on it: the
# test modules under `driver::` and `watcher::` are gated
# `#[cfg(all(test, feature = "tokio"))]`, so without the feature the three
# `driver::` filters match nothing and `watcher::`'s slice of `fs-rest` goes
# with them. `sync` is the same condition for the barrier cells: the whole
# `fs-cookie` shard is `driver::tests::sync_cookie::`, which the `sync` feature
# gates, so a shard run without it matches nothing at all and `run_shard`'s
# vacuity guard below turns that into a red job. With it the six are a true partition — 301 + 404 + 60 + 139 + 97 +
# 77 = 1078, the whole tokio-enabled lib suite (counts from a native run; miri
# drops the `not(miri)` cells from each side alike).
#
# `proto-rest`, `umbrella-head` and `umbrella-tail` deliberately keep the default
# feature set. None is vacuous, but the umbrella's own `driver::tests`/
# `demux::tests` carry the same tokio gate as tributary-fs's `driver::` suite and
# so are not interpreted here; enabling them is a coverage decision, not part of
# un-vacuuming the shards above.
#
# The 32-bit target FORCED this — full address reuse alone does not fit the whole
# workspace in one i686 process — but every target runs the same partition. A
# shard is its own process with a fresh address space, so the split that rescues
# i686 also keeps each job short on the emulated targets, where interpreting the
# whole workspace in one pass makes a single late failure cost the entire run's
# feedback. Keeping one partition rather than a per-target special case is also
# what stops a target from quietly growing past a limit its neighbours already hit.
#
# Passing no group runs the whole workspace in a single pass. CI never does; it is
# kept for a local run that wants one process.
#
# The monitor suite is one flat module, so its halves split on the first letter of
# the test name. Only the FIRST half enumerates letters; the second is its
# complement, expressed as skips. That asymmetry is deliberate — a test named
# outside the enumerated range still lands in the second shard rather than falling
# through a gap, so the partition stays exhaustive as the suite grows.
#
# The tributaries crate's own suite splits by top-level module instead of by
# letter: `coalesce`, `subsume` and `route` are its three heaviest modules by
# native count and together make up the larger half, so `umbrella-head`
# enumerates exactly those three and `umbrella-tail` is their complement,
# expressed as skips of the same three names — the same asymmetry as the monitor
# split: a module added tomorrow, or a test added to a module already on one
# side, lands in `umbrella-tail` rather than falling through a gap.
#
# `tributary-fs`'s own suite (minus `driver::`) splits by top-level module the
# same way: `core::` (301 cells) and `os::` (404) are its two heaviest
# non-driver modules by native count, each big enough to be its own shard, so
# `fs-core` and `fs-os` each enumerate exactly one of them and the narrower
# `fs-rest` is their complement, expressed as skips of `driver::`, `core::` and
# `os::` together — a module added tomorrow lands in `fs-rest` rather than
# falling through a gap. This is what took the old `fs-rest` off the critical
# path: on CI run 34430926057 (a523620) the single `fs-rest` shard (`--skip
# driver::`) ran 45-72 min stacked and 69-90+ min tree borrows, and
# `miri-tb-x86_64 [fs-rest]` hit the 90-minute timeout while still inside
# `watcher::tests` at 86 min — the shard had grown with this branch's cells
# (options faces, glob seats, watcher lifecycle and door cells) past what one
# process fits. Pulling `core::` and `os::` into their own shards leaves the
# renamed `fs-rest` at just `watcher::` + `options::` + `event::` (60 cells),
# so the module that stalled now runs early in a short shard instead of late in
# a long one.
case "$TEST_GROUP" in
  "")
    run_shard cargo miri test --all-targets --target "$TARGET"
    ;;
  proto-rest)
    run_shard cargo miri test -p tributary-proto --lib --target "$TARGET" -- \
      --skip monitor::tests::
    ;;
  proto-monitor-head)
    run_shard cargo miri test -p tributary-proto --lib --target "$TARGET" -- \
      monitor::tests::a monitor::tests::b monitor::tests::c monitor::tests::d monitor::tests::e monitor::tests::f monitor::tests::g monitor::tests::h monitor::tests::i
    ;;
  proto-monitor-tail)
    run_shard cargo miri test -p tributary-proto --lib --target "$TARGET" -- monitor::tests:: \
      --skip monitor::tests::a \
      --skip monitor::tests::b \
      --skip monitor::tests::c \
      --skip monitor::tests::d \
      --skip monitor::tests::e \
      --skip monitor::tests::f \
      --skip monitor::tests::g \
      --skip monitor::tests::h \
      --skip monitor::tests::i
    ;;
  umbrella-head)
    run_shard cargo miri test -p tributaries --all-targets --target "$TARGET" -- \
      coalesce:: subsume:: route::
    ;;
  umbrella-tail)
    run_shard cargo miri test -p tributaries --all-targets --target "$TARGET" -- \
      --skip coalesce:: --skip subsume:: --skip route::
    ;;
  fs-core)
    run_shard cargo miri test -p tributary-fs --lib --features tokio,sync --target "$TARGET" -- \
      core::
    ;;
  fs-os)
    run_shard cargo miri test -p tributary-fs --lib --features tokio,sync --target "$TARGET" -- \
      os::
    ;;
  fs-rest)
    run_shard cargo miri test -p tributary-fs --all-targets --features tokio,sync --target "$TARGET" -- \
      --skip driver:: --skip core:: --skip os::
    ;;
  fs-cookie)
    run_shard cargo miri test -p tributary-fs --lib --features tokio,sync --target "$TARGET" -- \
      driver::tests::sync_cookie::
    ;;
  fs-descending)
    run_shard cargo miri test -p tributary-fs --lib --features tokio,sync --target "$TARGET" -- \
      driver::tests::descending::
    ;;
  fs-driver)
    run_shard cargo miri test -p tributary-fs --lib --features tokio,sync --target "$TARGET" -- driver:: \
      --skip driver::tests::sync_cookie:: --skip driver::tests::descending::
    ;;
  *)
    echo "unknown miri test group: $TEST_GROUP" >&2
    exit 1
    ;;
esac
