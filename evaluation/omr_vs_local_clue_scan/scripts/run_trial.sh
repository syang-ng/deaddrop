#!/usr/bin/env bash
# One local-clue-scan repetition: receiver key generation, board construction (N dummy clues plus
# one sender clue at INDEX, exactly as in E2), export of all clues in the clue wire format (what
# the receiver downloads), and the receiver's local scan on 1 thread and on all logical CPUs.
# It uses the E2 harness binary; there is no detector in this scheme.
#
# Usage: run_trial.sh N TRIAL INDEX        (RESULTS=dir overrides the output directory)
set -euo pipefail
N=$1 TRIAL=$2 INDEX=$3
HERE=$(cd "$(dirname "$0")/.." && pwd)
REPO=$(cd "$HERE/../.." && pwd)
RESULTS=${RESULTS:-$HERE/results}
BIN=$REPO/evaluation/omr_vs_tag_scan/omr_bench/build-$N/omr_bench
WORK=$HERE/work
RUN=$WORK/run              # the prototype reads and writes clues at ../data/clues
CLUES=$WORK/data/clues
KEYS=$WORK/keys/$N-$TRIAL
LOG=$RESULTS/logs/localscan-$N-$TRIAL
[[ -x $BIN ]] || { echo "missing $BIN; run evaluation/build.sh first"; exit 1; }
mkdir -p "$RUN" "$KEYS" "$RESULTS/logs"
rm -rf "$CLUES" && mkdir -p "$CLUES"

step() {
  local name=$1; shift
  echo "$(date '+%F %T') localscan N=$N trial=$TRIAL $name"
  docker run --rm --network none --user "$(id -u):$(id -g)" -v "$REPO:$REPO" -w "$RUN" \
    omr-env:focal "$BIN" "$@" > "$LOG-$name.log" 2>&1 \
    || { echo "FAILED: $name (see $LOG-$name.log)"; tail -5 "$LOG-$name.log"; exit 1; }
  grep '^RESULT ' "$LOG-$name.log" \
    | sed "s/^RESULT {/{\"scheme\":\"localscan\",\"N\":$N,\"trial\":$TRIAL,\"truth\":[$INDEX],/" >> "$RESULTS/raw.jsonl"
}

step receiver_keygen receiver-keygen "$KEYS"
step build_board build-board "$N" "$INDEX" "$KEYS/pk_clue.bin"
step board_export export-board "$N" "$KEYS/board_wire.bin"
step scan_1thread local-scan "$KEYS" "$KEYS/board_wire.bin" 1
step scan_allthreads local-scan "$KEYS" "$KEYS/board_wire.bin" "$(nproc)"
# The exported board (up to 940 MiB) and the BFV keys are not needed afterwards.
rm -f "$KEYS"/{board_wire,pk_detect,relin_keys,galois_keys,pk_clue,sk_decode,sk_clue}.bin
