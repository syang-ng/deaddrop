#!/usr/bin/env bash
# One run of the upstream DoS-PerfOMR retrieval pipeline (OMR3_dos, main.cpp mode "dos") at
# N = 32,768 on 1 core with the native payload (612 slots per message) and bound KBAR on the number
# of pertinent messages. Upstream makes exactly KBAR messages pertinent and checks that the receiver
# recovers all their payloads ("Result is correct!"). The run is wrapped in rusage_exec for CPU
# time and peak RSS.
#
# Usage: run_trial.sh KBAR TRIAL            (RESULTS=dir overrides the output directory)
set -euo pipefail
KBAR=$1 TRIAL=$2
N=32768
HERE=$(cd "$(dirname "$0")/.." && pwd)
REPO=$(cd "$HERE/../.." && pwd)
RESULTS=${RESULTS:-$HERE/results}
BIN=$HERE/upstream/build/cmake/omr_upstream
WRAP=$HERE/upstream/build/rusage_exec
WORK=$HERE/work
RUN=$WORK/run                       # upstream reads and writes ../data/{clues,payloads}
LOG=$RESULTS/logs/upstream-kbar$KBAR-$TRIAL.log
[[ -x $BIN && -x $WRAP ]] || { echo "missing binaries; run upstream/build.sh first"; exit 1; }
mkdir -p "$RUN" "$RESULTS/logs"
rm -rf "$WORK/data" && mkdir -p "$WORK/data/clues" "$WORK/data/payloads"
echo "$(date '+%F %T') upstream OMR3_dos N=$N kbar=$KBAR trial=$TRIAL"
docker run --rm --network none --user "$(id -u):$(id -g)" -v "$REPO:$REPO" -w "$RUN" omr-env:focal \
  "$WRAP" "$BIN" dos 1 1 "$N" "$KBAR" > "$LOG" 2>&1 || { echo "FAILED (see $LOG)"; tail -5 "$LOG"; exit 1; }
grep -q 'Result is correct!' "$LOG" || { echo "INCORRECT RESULT (see $LOG)"; exit 1; }
grep -E 'Prepare switching key time|ClueToPackedPV|PVUnpack|ExpandedPVToDigest|Detector running time:|Digest size:|Receiver decoding|Result is|RUSAGE' "$LOG"
