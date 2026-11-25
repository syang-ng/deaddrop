#!/usr/bin/env bash
# Builds the upstream DoS-PerfOMR demo (omr-server/main.cpp, mode "dos" = OMR3_dos()) without
# touching omr-server/. It assembles a source overlay in build/src:
#   - main.cpp: an exact copy of omr-server/main.cpp
#   - include/: symlinks to every omr-server/include header, except OMRdos.h, which is a copy with
#     timing.patch applied (one added line that prints the receiver decoding time upstream
#     already measures)
# and compiles it in the omr-env:focal image with the same libraries and flags as omr-server.
# Also builds rusage_exec, which runs a command and reports its CPU time and peak RSS.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
SRC=$HERE/build/src
rm -rf "$SRC" && mkdir -p "$SRC/include"
cp "$REPO/omr-server/main.cpp" "$SRC/main.cpp"
for f in "$REPO"/omr-server/include/*; do
  [[ $(basename "$f") == OMRdos.h ]] && continue
  ln -s "$f" "$SRC/include/$(basename "$f")"
done
cp "$REPO/omr-server/include/OMRdos.h" "$SRC/include/OMRdos.h"
patch --quiet "$SRC/include/OMRdos.h" "$HERE/timing.patch"
cmp -s "$REPO/omr-server/main.cpp" "$SRC/main.cpp"
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$REPO:$REPO" -w "$HERE" omr-env:focal bash -c "
  cmake -S . -B build/cmake -DCMAKE_PREFIX_PATH=/opt/omr > /dev/null &&
  cmake --build build/cmake -j8 2>&1 | grep -E 'error|warning: |Built target' ;
  gcc -O2 -Wall -Werror -o build/rusage_exec rusage_exec.c"
ls -la "$HERE/build/cmake/omr_upstream" "$HERE/build/rusage_exec"
