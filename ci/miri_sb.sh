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

# Full address reuse alone does not fit the whole workspace in one i686 process, so
# the constrained target splits into disjoint, exhaustive shards — each its own
# process with a fresh address space. The partition covers every workspace test
# exactly once: `rest` is every crate except tributary-fs; the four `fs-*` groups
# partition tributary-fs by test-name prefix. Unsharded targets pass no group and
# keep their single-pass coverage.
case "$TEST_GROUP" in
  "")
    cargo miri test --all-targets --target "$TARGET"
    ;;
  rest)
    cargo miri test --all-targets --workspace --exclude tributary-fs --target "$TARGET"
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
