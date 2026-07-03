# tributaries Linux verify image (design §6.1).
# Base: rust:1.95-bookworm (workspace MSRV), pinned by digest:
#   rust@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1
# The full (non-slim) image ships build-essential, so the C capability probes
# compile with no extra packages. Stable toolchain only — miri and sanitizers
# stay host/CI concerns.
FROM rust@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    e2fsprogs \
    util-linux \
    procps \
    btrfs-progs \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /work
