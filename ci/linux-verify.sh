#!/usr/bin/env bash
# The tributaries Linux verify loop: one command from the host runs a suite
# inside the pinned container (ci/docker/Dockerfile) on container-native
# paths. TMPDIR rides a tmpfs so bind-mount unreliability can never leak into
# inotify results, and the cargo registry/target volumes keep the loop warm.
#
# Usage: ci/linux-verify.sh <selector> [repo-path]
#   REPO=<path> may be set instead of the second argument; defaults to the
#   repository this script lives in.
#
# Selectors:
#   unit         - cargo test -p tributary-fs (linux cfg), default caps
#   unit-priv    - the same lib suite under --privileged. A DIFFERENT run, not a
#                  duplicate: under CAP_SYS_ADMIN the `Backend::Auto` probe
#                  resolves fanotify, so the capability set decides which
#                  primitive a cell that does not pin one actually arms
#   umbrella     - the umbrella crate on the linux cfg, default caps: its lib —
#                  where `source::fs::tests::integration` drives a real kernel
#                  watch — plus both integration targets (tests/umbrella.rs,
#                  tests/indexer_shaped.rs). `--tests` picks up the lib test
#                  target and the integration targets in one invocation
#   inotify      - the linux_inotify and linux_fanotify integration suites under
#                  DEFAULT caps (privileged cells self-probe and skip loudly).
#                  linux_fanotify's loopback cells self-skip here, but its
#                  selection-matrix cell exercises the `Backend::Auto` FALLBACK
#                  arm (probe fails without CAP_SYS_ADMIN -> inotify) and the
#                  forced-`Fanotify`-without-privilege typed-error cell — the
#                  default-caps half of suite 12 the privileged `fanotify` suite
#                  cannot reach
#   inotify-priv - linux_inotify under --privileged: unlocks the sysctl
#                  overflow/watch-limit cells and the bind-mount aliasing cell
#   fanotify     - linux_fanotify under --privileged (ext4 loopback the tests
#                  build inside the container; cells self-skip loudly)
#   doc          - the tributary-fs doctests
#   proto        - the sans-I/O core's own suite
#   all          - every suite above, in that order
#   shell        - interactive shell, --privileged (debugging)
#
# NO SELECTOR SHORT-CIRCUITS. `all` used to be one `&&` chain whose FIRST link
# was the lib suite, so six capability-sensitive lib cells kept it from ever
# reaching the integration targets, the doctests, the proto suite or the
# umbrella — `all` verified LESS than `unit` while reading as the thorough
# option. Every selector now runs each of its suites to completion, records a
# verdict, and exits nonzero if any of them failed.
#
# The per-suite verdict is the point, not a convenience: a suite's exit code
# alone cannot distinguish these three, and the summary separates all of them.
#   - a suite that ran and passed
#   - a suite that ran NOTHING (a filter, or an unmet `required-features`, that
#     matched no cell — libtest exits 0 with `test result: ok. 0 passed`)
#   - a suite whose cells RAN and SKIPPED: `privileged_or_skip` returns early and
#     libtest counts the cell as passed, which is the same green as a real pass
#
# The exit status is the AGGREGATE — 0 only if every selected suite ran cells and
# passed: fix-round agents drive this foreground with a timeout, exactly like
# every other verify gate, and a one-suite selector still exits on that suite
# alone.
set -u

IMAGE="${IMAGE:-tributaries-linux-verify:dev}"
SUITE="${1:?usage: linux-verify.sh <unit|unit-priv|umbrella|inotify|inotify-priv|fanotify|doc|proto|all|shell> [repo]}"
DEFAULT_REPO="$(cd "$(dirname "$0")/.." && pwd)"
REPO="${2:-${REPO:-$DEFAULT_REPO}}"

if [ ! -f "$REPO/Cargo.toml" ]; then
  echo "linux-verify: '$REPO' does not look like the workspace root" >&2
  exit 2
fi

if ! docker image inspect "$IMAGE" > /dev/null 2>&1; then
  echo "linux-verify: building $IMAGE" >&2
  docker build -q -t "$IMAGE" "$REPO/ci/docker" || exit 2
fi

COMMON=(
  --rm
  -v "$REPO":/work
  -v tributaries-cargo-registry:/usr/local/cargo/registry
  -v tributaries-linux-target:/ct
  -e CARGO_TARGET_DIR=/ct
  -e TMPDIR=/itest
  --tmpfs /itest:exec,mode=1777
  -w /work
)

# Every suite declared ONCE, as `name|caps|command`, and every selector below is
# a subset of these names. `all` hand-copied its commands before, which is how it
# came to run the two integration binaries ONLY under privilege — dropping the
# default-caps legs whose whole purpose is to catch a regression that privilege
# would mask.
#
# Single-threaded by contract wherever linux_inotify runs: its privileged cells
# shrink the user namespace's inotify sysctls, which would starve concurrent
# event tests. linux_fanotify likewise mounts and unmounts a shared ext4
# loopback that concurrent cells would race.
SUITES=(
  "unit|default|cargo test -p tributary-fs --all-features --lib"
  "unit-priv|priv|cargo test -p tributary-fs --all-features --lib"
  "umbrella|default|cargo test -p tributaries --all-features --tests"
  "inotify|default|cargo test -p tributary-fs --all-features --test linux_inotify -- --test-threads=1"
  "fanotify-unpriv|default|cargo test -p tributary-fs --all-features --test linux_fanotify -- --test-threads=1"
  "inotify-priv|priv|cargo test -p tributary-fs --all-features --test linux_inotify -- --test-threads=1"
  "fanotify|priv|cargo test -p tributary-fs --all-features --test linux_fanotify -- --test-threads=1"
  "doc|default|cargo test -p tributary-fs --all-features --doc"
  "proto|default|cargo test -p tributary-proto"
)

case "$SUITE" in
  unit)            SELECTED="unit" ;;
  unit-priv)       SELECTED="unit-priv" ;;
  umbrella)        SELECTED="umbrella" ;;
  # One selector, two binaries — and they no longer share an `&&`: a red
  # linux_inotify used to keep linux_fanotify's default-caps half from running.
  inotify)         SELECTED="inotify fanotify-unpriv" ;;
  inotify-priv)    SELECTED="inotify-priv" ;;
  fanotify)        SELECTED="fanotify" ;;
  doc)             SELECTED="doc" ;;
  proto)           SELECTED="proto" ;;
  all)             SELECTED="unit unit-priv umbrella inotify fanotify-unpriv inotify-priv fanotify doc proto" ;;
  shell)
    docker run --privileged -it "${COMMON[@]}" "$IMAGE" bash
    exit $?
    ;;
  *)
    echo "linux-verify: unknown suite '$SUITE'" >&2
    exit 2
    ;;
esac

LOGDIR="$(mktemp -d)"
trap 'rm -rf "$LOGDIR"' EXIT

VERDICTS=()
SKIPLINES="$LOGDIR/skips"
: > "$SKIPLINES"
FAILURES=0
RAN=0

# Runs one suite to completion and records its verdict. Never aborts the caller:
# the whole point is that a red suite cannot stop the ones behind it.
run_suite() {
  # Declared up front: `local` is itself a command, and running one between the
  # pipeline below and its `${PIPESTATUS[0]}` read would clobber the status.
  local name caps cmd log status cells skips
  name=$1
  caps=$2
  cmd=$3
  log="$LOGDIR/$name.log"

  printf '\n===== linux-verify: %s (%s caps) =====\n' "$name" "$caps" >&2
  if [ "$caps" = priv ]; then
    docker run --privileged "${COMMON[@]}" "$IMAGE" bash -ec "$cmd" 2>&1 | tee "$log"
  else
    docker run "${COMMON[@]}" "$IMAGE" bash -ec "$cmd" 2>&1 | tee "$log"
  fi
  status=${PIPESTATUS[0]}
  RAN=$((RAN + 1))

  # Summed over every test binary the suite ran. A suite whose filter matched
  # nothing, or whose `required-features` were unmet, prints `test result: ok.
  # 0 passed` and exits 0 — indistinguishable from a real pass in the exit code.
  cells=$(grep -ho 'test result: ok\. [0-9]\+ passed' "$log" | awk '{ s += $4 } END { print s + 0 }')
  # A `privileged_or_skip` cell prints its notice and RETURNS, and libtest counts
  # it passed — the same `ok` a real pass reports. The notice is written to the
  # inherited stderr precisely so it survives a green run
  # (tributary-fs/tests/common/mod.rs::skip_notice), and this is its only reader
  # here. Not fatal: the default-caps legs are SUPPOSED to skip the six
  # privileged-only cells, and three cells skip a single staging round while
  # still asserting over their own round count. Loud, though — a silent skip is
  # the coverage this harness would otherwise report as verified.
  skips=$(grep -c 'TRIBUTARY-SKIP' "$log" || true)
  if [ "$skips" -gt 0 ]; then
    printf '%s:\n' "$name" >> "$SKIPLINES"
    grep 'TRIBUTARY-SKIP' "$log" | sed 's/^/  /' >> "$SKIPLINES"
  fi

  if [ "$status" -ne 0 ]; then
    VERDICTS+=("FAIL     $name ($caps) exit=$status cells=$cells skips=$skips")
    FAILURES=$((FAILURES + 1))
  elif [ "$cells" -eq 0 ]; then
    VERDICTS+=("VACUOUS  $name ($caps) ran no cell at all skips=$skips")
    FAILURES=$((FAILURES + 1))
  elif [ "$skips" -gt 0 ]; then
    VERDICTS+=("ok+SKIP  $name ($caps) cells=$cells skips=$skips")
  else
    VERDICTS+=("ok       $name ($caps) cells=$cells")
  fi
}

for entry in "${SUITES[@]}"; do
  name=${entry%%|*}
  rest=${entry#*|}
  caps=${rest%%|*}
  cmd=${rest#*|}
  case " $SELECTED " in
    *" $name "*) run_suite "$name" "$caps" "$cmd" ;;
  esac
done

printf '\n===== linux-verify summary (%s) =====\n' "$SUITE"
if [ "$RAN" -gt 0 ]; then
  for verdict in "${VERDICTS[@]}"; do
    printf '  %s\n' "$verdict"
  done
fi
if [ -s "$SKIPLINES" ]; then
  printf '\n  skips (each one is a cell libtest counted as PASSED):\n'
  sed 's/^/  /' "$SKIPLINES"
fi
if [ "$FAILURES" -gt 0 ]; then
  printf '\n%d of %d suite(s) failed or were vacuous\n' "$FAILURES" "$RAN"
  exit 1
fi
printf '\nall %d suite(s) passed\n' "$RAN"
