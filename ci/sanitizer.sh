#!/bin/bash
set -ex

export ASAN_OPTIONS="detect_odr_violation=0 detect_leaks=0"

# The instrumented target. CI never sets it, so the pinned x86_64 GitHub runner is
# unchanged; overridable so the same script reproduces a red lane on a developer's
# own Linux (an aarch64 container, say), which is otherwise unreachable — every
# sanitizer verdict here would have to be read off CI.
TARGET="${TARGET:-x86_64-unknown-linux-gnu}"

# Selector for which sanitizer(s) this invocation runs. The four passes are slow
# (MSAN/TSAN each rebuild an instrumented `std` via -Zbuild-std), so CI runs them as
# separate parallel jobs; `all` keeps the original single-invocation behaviour for
# local use.
#   $1  which : asan-lsan | msan | tsan | all   (default: all)
WHICH="${1:-all}"

# The libtest arguments every leg that runs the INTEGRATION binaries shares.
#
# `--test-threads=1` is a REQUIREMENT of the two Linux integration binaries rather
# than a tuning knob, and `--tests` runs both of them. `ci/linux-verify.sh` states
# the contract and passes the same flag in all four of its invocations:
# `linux_inotify`'s privileged cells shrink the user namespace's inotify sysctls,
# which starves every concurrent event cell; `linux_fanotify` mounts and unmounts
# ONE shared ext4 loopback, whose `LoopbackGuard` drop pulls the filesystem out
# from under any cell still using it. Without the flag this script ran those
# binaries in parallel and failed intermittently in a DIFFERENT cell each run —
# `superblock_firehose_is_filtered` writing into a scratch directory a concurrent
# unmount had already removed, then `overflow_swallowed_unmount_rebinds_or_dies_loudly`
# starved by a sysctl shrink — neither of which is a sanitizer verdict, and both of
# which read as one.
#
# The runs that stayed GREEN were worse. `ext4_loopback()` creates the mount for
# the first caller and hands the same one to every caller after it, so a cell
# whose `LoopbackGuard` dropped early left `ext4_loopback()` answering `None` for
# the rest of the binary — and those cells then took their `no ext4 loopback`
# self-skip, which libtest counts as PASSED. Measured on this branch, one parallel
# ASan leg reported 22 `no ext4 loopback` skips inside a `--privileged` container
# where the loopback demonstrably worked, against 0 serially: the fanotify
# integration surface was being reported green while a third of it never ran.
#
# DO NOT drop this flag as redundant with the other harness: nothing in this file
# bounds those two binaries' concurrency, the failures it prevents are red lanes
# carrying no sanitizer report at all, and the passes it prevents are worse.
#
# It serializes the lib targets too (`--tests` covers them), which is a real cost
# and a deliberate one: the alternative is a per-binary invocation, and a
# split-by-target script is how a future target quietly escapes instrumentation.
# `run_msan` is `--lib` only — it never runs either integration binary — so it
# keeps its own argument list and stays parallel.
#
# `close_quiesces_under_sustained_traffic` drives an UNBOUNDED real-kernel producer
# thread (raw write/remove syscalls) that only stops once close() returns, racing an
# instrumented reader. Every sanitizer slows the reader/runtime but not the syscall
# producer, so the producer outpaces the drain and the cell can livelock to a job
# timeout — intermittently, under ASan/LSan and TSan alike (it has cancelled `main`'s
# own sanitizer run this way). It runs unimpeded on the native integration job, and
# its deterministic correctness twin `close_is_bounded_and_honest_while_the_ingress_hammers`
# covers the property in the lib suite under every sanitizer. Skip only this one cell
# wherever an instrumented build runs the integration binaries.
SANITIZER_SKIP=(-- --test-threads=1 --skip close_quiesces_under_sustained_traffic)

# A destructor that UNWINDS abandons every deallocation standing behind it: the frames between the
# panicking `Drop` and whatever contains it never reach their `Arc` frees, so the nodes on that path
# are unreachable for the rest of the process. That is a property of the language, not a defect, and
# `owner_teardown_enters_the_seam_although_releasing_the_displaced_plane_unwinds` drives it
# deliberately — a caller value whose destructor unwinds while the owner's teardown releases the read
# plane that last owned it — to pin that the teardown still enters the source seam and still reaps
# its cookies. LSan reports the handful of abandoned radix nodes as leaks, so the LEAK pass alone
# skips it. Every other instrument still runs it (ASan/TSan here, MSan via `--lib`, and the native
# suites), and the payload-disposal cells stay under LSan because their retained payloads are
# zero-sized by construction — see `ForgottenPayload`.
LEAK_SKIP=("${SANITIZER_SKIP[@]}"
  --skip owner_teardown_enters_the_seam_although_releasing_the_displaced_plane_unwinds)

run_asan_lsan() {
  # Run address sanitizer
  RUSTFLAGS="-Z sanitizer=address" \
  cargo test --tests --target "$TARGET" --all-features "${SANITIZER_SKIP[@]}"

  # Run leak sanitizer
  RUSTFLAGS="-Z sanitizer=leak" \
  cargo test --tests --target "$TARGET" --all-features "${LEAK_SKIP[@]}"
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
  #
  # The umbrella keeps one real-watch cell OUTSIDE that module deliberately — the fs event
  # seam's capability boundary must be pinned by the main and narrow gates, not only by the
  # integration one — so it is named here individually. A real `Watcher::watch` reports
  # `use-of-uninitialized-value` inside the backend's spawn barrier (the `statx`/`statfs`
  # results the kernel writes) and ABORTS the lib binary, so the suite reports no result at
  # all. Any future cell driving a real kernel watch belongs on this list: `cfg(sanitize)`
  # cannot gate one out, being feature-gated (E0658) on the stable this workspace targets.
  RUSTFLAGS="-Z sanitizer=memory" \
  cargo -Zbuild-std test --lib --target "$TARGET" --all-features --workspace --exclude tributary-fs \
    -- --skip source::fs::tests::integration \
       --skip source::fs::tests::a_real_fs_move_carries_its_source_coordinate_into_the_move_out_projection
}

run_tsan() {
  # Run thread sanitizer (requires -Zbuild-std for instrumented std). The
  # sustained-traffic liveness cell is skipped for the reason documented on
  # SANITIZER_SKIP above.
  RUSTFLAGS="-Z sanitizer=thread" \
  cargo -Zbuild-std test --tests --target "$TARGET" --all-features "${SANITIZER_SKIP[@]}"
}

case "$WHICH" in
  asan-lsan) run_asan_lsan ;;
  msan) run_msan ;;
  tsan) run_tsan ;;
  all) run_asan_lsan; run_msan; run_tsan ;;
  *) echo "unknown sanitizer selector: $WHICH" >&2; exit 1 ;;
esac
