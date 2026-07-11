#!/bin/bash
set -ex

export ASAN_OPTIONS="detect_odr_violation=0 detect_leaks=0"

TARGET="x86_64-unknown-linux-gnu"

# Run address sanitizer
RUSTFLAGS="-Z sanitizer=address" \
cargo test --tests --target "$TARGET" --all-features

# Run leak sanitizer
RUSTFLAGS="-Z sanitizer=leak" \
cargo test --tests --target "$TARGET" --all-features

# Run memory sanitizer (requires -Zbuild-std for instrumented std).
# MSAN instruments neither libc nor the kernel, so a buffer a raw syscall fills
# (statx, inotify/getdents reads) reads as uninitialized under MSAN even when it
# is fully written. tributary-fs is built on exactly those raw syscalls, so it is
# excluded from MSAN specifically; ASAN/LSAN/TSAN understand syscalls and retain
# full coverage of it. For the same reason MSAN runs lib targets only — the
# integration binaries exist to drive that same kernel watch — and skips the
# umbrella lib's own fs-source integration module. The sans-I/O core, view,
# subsume, demux, and coalesce suites all stay under MSAN.
RUSTFLAGS="-Z sanitizer=memory" \
cargo -Zbuild-std test --lib --target "$TARGET" --all-features --workspace --exclude tributary-fs -- --skip source::fs::tests::integration

# Run thread sanitizer (requires -Zbuild-std for instrumented std)
RUSTFLAGS="-Z sanitizer=thread" \
cargo -Zbuild-std test --tests --target "$TARGET" --all-features
