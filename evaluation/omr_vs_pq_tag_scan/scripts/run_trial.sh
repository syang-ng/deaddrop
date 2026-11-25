#!/usr/bin/env bash
# One Tag Scan repetition for SCHEME (mlkem512, mlkem768 or x25519-awslc): receiver key
# generation, board construction (N entries, one addressed to the receiver at INDEX, the rest to
# 1,024 other receivers), and the receiver's scan on 1 thread and on all logical CPUs.
# Uses the tag_scan crate from ../omr_vs_tag_scan.
#
# Usage: run_trial.sh SCHEME N TRIAL INDEX     (RESULTS=dir overrides the output directory)
set -euo pipefail
SCHEME=$1 N=$2 TRIAL=$3 INDEX=$4
HERE=$(cd "$(dirname "$0")/.." && pwd)
REPO=$(cd "$HERE/../.." && pwd)
RESULTS=${RESULTS:-$HERE/results}
BIN=$REPO/evaluation/omr_vs_tag_scan/tag_scan/target/release/tagscan
WORK=$HERE/work/$SCHEME-$N-$TRIAL
LOG=$RESULTS/logs/$SCHEME-$N-$TRIAL
[[ -x $BIN ]] || { echo "missing $BIN; run evaluation/build.sh first"; exit 1; }
mkdir -p "$WORK" "$RESULTS/logs"

step() {
  local name=$1; shift
  echo "$(date '+%F %T') $SCHEME N=$N trial=$TRIAL $name"
  "$BIN" "$@" --scheme "$SCHEME" > "$LOG-$name.log" 2>&1 || { echo "FAILED: $name"; cat "$LOG-$name.log"; exit 1; }
  sed "s/^{/{\"scheme\":\"$SCHEME\",\"N\":$N,\"trial\":$TRIAL,\"truth\":[$INDEX],/" "$LOG-$name.log" >> "$RESULTS/raw.jsonl"
}

step receiver_keygen keygen --out "$WORK"
step build_board build-board --n "$N" --pk "$WORK/pk.bin" --pertinent "$INDEX" --out "$WORK/board.bin"
step scan_1thread scan --sk "$WORK/sk.bin" --board "$WORK/board.bin" --threads 1
step scan_allthreads scan --sk "$WORK/sk.bin" --board "$WORK/board.bin" --threads "$(nproc)"
rm -rf "$WORK"
