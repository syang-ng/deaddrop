#!/usr/bin/env bash
# One Tag Scan repetition: receiver key generation, board construction (N entries, one addressed
# to the receiver at INDEX, the rest to other receivers), and the receiver's scan on 1 thread.
# A supplementary scan on all logical CPUs is recorded with threads=<nproc>.
#
# Usage: run_tagscan_trial.sh N TRIAL INDEX    (RESULTS=dir overrides the output directory)
set -euo pipefail
N=$1 TRIAL=$2 INDEX=$3
HERE=$(cd "$(dirname "$0")/.." && pwd)
RESULTS=${RESULTS:-$HERE/results}
BIN=$HERE/tag_scan/target/release/tagscan
WORK=$HERE/work/tagscan/$N-$TRIAL
LOG=$RESULTS/logs/tagscan-$N-$TRIAL
[[ -x $BIN ]] || { echo "missing $BIN; run evaluation/build.sh first"; exit 1; }
mkdir -p "$WORK" "$RESULTS/logs"

step() {
  local name=$1; shift
  echo "$(date '+%F %T') tagscan N=$N trial=$TRIAL $name"
  "$BIN" "$@" > "$LOG-$name.log" 2>&1 || { echo "FAILED: $name"; cat "$LOG-$name.log"; exit 1; }
  sed "s/^{/{\"scheme\":\"tagscan\",\"N\":$N,\"trial\":$TRIAL,\"truth\":[$INDEX],/" "$LOG-$name.log" >> "$RESULTS/raw.jsonl"
}

step receiver_keygen keygen --out "$WORK"
step build_board build-board --n "$N" --pk "$WORK/pk.bin" --pertinent "$INDEX" --out "$WORK/board.bin"
step scan_1thread scan --sk "$WORK/sk.bin" --board "$WORK/board.bin" --threads 1
step scan_allthreads scan --sk "$WORK/sk.bin" --board "$WORK/board.bin" --threads "$(nproc)"
rm -f "$WORK/board.bin"
