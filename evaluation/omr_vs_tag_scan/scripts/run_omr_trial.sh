#!/usr/bin/env bash
# One OMR repetition: receiver key generation, board construction (N dummy clues plus one sender
# clue at INDEX), one detector poll, receiver decoding. Each role is its own process in the
# omr-env:focal image, so CPU time and peak RSS are per role.
#
# Usage: run_omr_trial.sh N TRIAL INDEX        (RESULTS=dir overrides the output directory)
set -euo pipefail
N=$1 TRIAL=$2 INDEX=$3
HERE=$(cd "$(dirname "$0")/.." && pwd)
REPO=$(cd "$HERE/../.." && pwd)
RESULTS=${RESULTS:-$HERE/results}
BIN=$HERE/omr_bench/build-$N/omr_bench
WORK=$HERE/work/omr
RUN=$WORK/run              # the prototype reads and writes clues at ../data/clues
CLUES=$WORK/data/clues
KEYS=$WORK/keys/$N-$TRIAL
LOG=$RESULTS/logs/omr-$N-$TRIAL
[[ -x $BIN ]] || { echo "missing $BIN; run evaluation/build.sh first"; exit 1; }
mkdir -p "$RUN" "$KEYS" "$RESULTS/logs"
rm -rf "$CLUES" && mkdir -p "$CLUES"

step() {
  local name=$1; shift
  echo "$(date '+%F %T') omr N=$N trial=$TRIAL $name"
  docker run --rm --network none --user "$(id -u):$(id -g)" -v "$REPO:$REPO" -w "$RUN" \
    omr-env:focal "$BIN" "$@" > "$LOG-$name.log" 2>&1 \
    || { echo "FAILED: $name (see $LOG-$name.log)"; tail -5 "$LOG-$name.log"; exit 1; }
  grep '^RESULT ' "$LOG-$name.log" \
    | sed "s/^RESULT {/{\"scheme\":\"omr\",\"N\":$N,\"trial\":$TRIAL,\"truth\":[$INDEX],/" >> "$RESULTS/raw.jsonl"
}

step receiver_keygen receiver-keygen "$KEYS"
step build_board build-board "$N" "$INDEX" "$KEYS/pk_clue.bin"
step detect detect "$KEYS" "$KEYS/digest.bin"
step decode decode "$KEYS" "$KEYS/digest.bin"
# The key files are about 170 MB per repetition; their sizes are already in raw.jsonl.
rm -f "$KEYS"/{pk_detect,relin_keys,galois_keys,pk_clue,sk_decode}.bin
