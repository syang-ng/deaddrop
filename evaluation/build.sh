#!/usr/bin/env bash
# Builds everything the evaluation scripts run:
#   - the omr-env:focal Docker image (omr-env/Dockerfile), if it is not present;
#   - tag_scan (Rust, on the host), after running its tests;
#   - omr_bench for N = 32,768 and 131,072 (in the image);
#   - the upstream DoS-PerfOMR overlay and rusage_exec (in the image).
# Requires Docker and Rust 1.96 or later. The image build and cargo fetch sources from the network.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
docker image inspect omr-env:focal > /dev/null 2>&1 || docker build -t omr-env:focal "$HERE/omr-env"
(cd "$HERE/omr_vs_tag_scan/tag_scan" && cargo test --release && cargo build --release)
for N in 32768 131072; do
  docker run --rm --user "$(id -u):$(id -g)" -v "$REPO:$REPO" -w "$HERE/omr_vs_tag_scan/omr_bench" omr-env:focal bash -c \
    "cmake -S . -B build-$N -DCMAKE_PREFIX_PATH=/opt/omr -DNUM_TRANSACTIONS=$N > /dev/null && cmake --build build-$N -j8"
done
"$HERE/omr_retrieval_vs_detection/upstream/build.sh"
