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
# full coverage of it. Nothing depends on tributary-fs, so excluding it still
# leaves tributary-proto (and any future crates) as meaningful MSAN targets.
RUSTFLAGS="-Z sanitizer=memory" \
cargo -Zbuild-std test --tests --target "$TARGET" --all-features --workspace --exclude tributary-fs

# Run thread sanitizer (requires -Zbuild-std for instrumented std)
RUSTFLAGS="-Z sanitizer=thread" \
cargo -Zbuild-std test --tests --target "$TARGET" --all-features
