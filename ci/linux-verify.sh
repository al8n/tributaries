#!/usr/bin/env bash
# The tributaries Linux verify loop: one command from the host runs a suite
# inside the pinned container (ci/docker/Dockerfile) on container-native
# paths. TMPDIR rides a tmpfs so bind-mount unreliability can never leak into
# inotify results, and the cargo registry/target volumes keep the loop warm.
#
# Usage: ci/linux-verify.sh <unit|inotify|inotify-priv|fanotify|all|shell> [repo-path]
#   REPO=<path> may be set instead of the second argument; defaults to the
#   repository this script lives in.
#
# Suites:
#   unit         - cargo test -p tributary-fs (linux cfg), default caps
#   inotify      - the linux_inotify integration suite, default caps
#                  (privileged cells self-probe and skip loudly)
#   inotify-priv - the same binary under --privileged: unlocks the sysctl
#                  overflow/watch-limit cells and the bind-mount aliasing cell
#   fanotify     - the fanotify integration suite, --privileged (lands at L4;
#                  until then this runs the full default battery privileged)
#   all          - the full battery, --privileged
#   shell        - interactive shell, --privileged (debugging)
#
# The container's exit code is the script's: fix-round agents drive this
# foreground with a timeout, exactly like every other verify gate.
set -u

IMAGE="${IMAGE:-tributaries-linux-verify:dev}"
SUITE="${1:?usage: linux-verify.sh <unit|inotify|inotify-priv|fanotify|all|shell> [repo]}"
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

run_default() { docker run "${COMMON[@]}" "$IMAGE" bash -ec "$1"; }
run_priv()    { docker run --privileged "${COMMON[@]}" "$IMAGE" bash -ec "$1"; }

case "$SUITE" in
  unit)
    run_default 'cargo test -p tributary-fs --all-features --lib'
    ;;
  # Single-threaded by contract: the privileged cells shrink the user
  # namespace's inotify sysctls, which would starve concurrent event tests.
  inotify)
    run_default 'cargo test -p tributary-fs --all-features --test linux_inotify -- --test-threads=1'
    ;;
  inotify-priv)
    run_priv 'cargo test -p tributary-fs --all-features --test linux_inotify -- --test-threads=1'
    ;;
  fanotify)
    run_priv 'cargo test -p tributary-fs --all-features --test linux_fanotify 2>/dev/null \
      || cargo test -p tributary-fs --all-features'
    ;;
  all)
    run_priv 'cargo test -p tributary-fs --all-features --lib \
      && cargo test -p tributary-fs --all-features --test linux_inotify -- --test-threads=1 \
      && cargo test -p tributary-fs --all-features --doc \
      && cargo test -p tributary-proto'
    ;;
  shell)
    docker run --privileged -it "${COMMON[@]}" "$IMAGE" bash
    ;;
  *)
    echo "linux-verify: unknown suite '$SUITE'" >&2
    exit 2
    ;;
esac
