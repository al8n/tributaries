#!/bin/bash
set -e

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

export MIRIFLAGS="-Zmiri-strict-provenance -Zmiri-disable-isolation -Zmiri-symbolic-alignment-check"

# 32-bit targets share one 4 GB address space across a lib test binary, and miri's
# default partial address reuse (-Zmiri-address-reuse-rate=0.5) exhausts it near the
# end of a long suite — the failure then surfaces as "no more free addresses" in
# whichever test happens to run last. Full reuse keeps the run inside the space;
# 64-bit cells keep the stricter default.
case "$TARGET" in
  i686-*)
    export MIRIFLAGS="$MIRIFLAGS -Zmiri-address-reuse-rate=1.0 -Zmiri-address-reuse-cross-thread-rate=1.0"
    ;;
esac

# The suite runs one shard per process, and the partition covers every workspace
# test exactly once: the four `fs-*` groups partition tributary-fs by test-name
# prefix, the two `proto-monitor-*` groups partition the monitor suite, and `rest`
# is everything else outside tributary-fs.
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
case "$TEST_GROUP" in
  "")
    cargo miri test --all-targets --target "$TARGET"
    ;;
  rest)
    cargo miri test --all-targets --workspace --exclude tributary-fs --target "$TARGET" -- \
      --skip monitor::tests::
    ;;
  proto-monitor-head)
    cargo miri test -p tributary-proto --lib --target "$TARGET" -- \
      monitor::tests::a monitor::tests::b monitor::tests::c monitor::tests::d monitor::tests::e monitor::tests::f monitor::tests::g monitor::tests::h monitor::tests::i
    ;;
  proto-monitor-tail)
    cargo miri test -p tributary-proto --lib --target "$TARGET" -- monitor::tests:: \
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
  fs-rest)
    cargo miri test -p tributary-fs --all-targets --target "$TARGET" -- --skip driver::
    ;;
  fs-cookie)
    cargo miri test -p tributary-fs --lib --target "$TARGET" -- driver::tests::sync_cookie::
    ;;
  fs-descending)
    cargo miri test -p tributary-fs --lib --target "$TARGET" -- driver::tests::descending::
    ;;
  fs-driver)
    cargo miri test -p tributary-fs --lib --target "$TARGET" -- driver:: \
      --skip driver::tests::sync_cookie:: --skip driver::tests::descending::
    ;;
  *)
    echo "unknown miri test group: $TEST_GROUP" >&2
    exit 1
    ;;
esac
