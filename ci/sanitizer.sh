#!/bin/bash
set -ex

export ASAN_OPTIONS="detect_odr_violation=0 detect_leaks=0"

TARGET="x86_64-unknown-linux-gnu"

# Selector for which sanitizer(s) this invocation runs. The four passes are slow
# (MSAN/TSAN each rebuild an instrumented `std` via -Zbuild-std), so CI runs them as
# separate parallel jobs; `all` keeps the original single-invocation behaviour for
# local use.
#   $1  which : asan-lsan | msan | tsan | all   (default: all)
WHICH="${1:-all}"

run_asan_lsan() {
  # Run address sanitizer
  RUSTFLAGS="-Z sanitizer=address" \
  cargo test --tests --target "$TARGET" --all-features

  # Run leak sanitizer
  RUSTFLAGS="-Z sanitizer=leak" \
  cargo test --tests --target "$TARGET" --all-features
}

run_msan() {
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
}

run_tsan() {
  # Run thread sanitizer (requires -Zbuild-std for instrumented std).
  #
  # `close_quiesces_under_sustained_traffic` is a real-kernel liveness smoke test:
  # a producer thread saturates the ingress while close drains it. Under TSan's
  # adversarial thread scheduling the producer can outpace the drain and the cell
  # livelocks (a 6 h job timeout rather than a finish). It completes under ASan /
  # LSan and on the native integration job, and its deterministic correctness twin
  # `close_is_bounded_and_honest_while_the_ingress_hammers` runs green under TSan in
  # the lib suite — so skip only this one cell here, keeping every other cell's
  # TSan coverage of the real backend reader / driver handoff.
  RUSTFLAGS="-Z sanitizer=thread" \
  cargo -Zbuild-std test --tests --target "$TARGET" --all-features -- \
    --skip close_quiesces_under_sustained_traffic
}

case "$WHICH" in
  asan-lsan) run_asan_lsan ;;
  msan) run_msan ;;
  tsan) run_tsan ;;
  all) run_asan_lsan; run_msan; run_tsan ;;
  *) echo "unknown sanitizer selector: $WHICH" >&2; exit 1 ;;
esac
