#!/usr/bin/env bash
# Runs every repetition with the same ground truth as E2 (../omr_vs_tag_scan/results/ground_truth.csv),
# then builds the comparison against E2's OMR measurements. About 5 minutes. Stops at the first failure.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
REPO=$(cd "$HERE/../.." && pwd)
E2=$REPO/evaluation/omr_vs_tag_scan
RES=$HERE/results
mkdir -p "$RES/logs"
[[ -e $RES/raw.jsonl ]] && { echo "results/raw.jsonl exists; move it away to start a fresh run"; exit 1; }
cp "$E2/results/ground_truth.csv" "$RES/ground_truth.csv"
"$E2/scripts/environment.sh" > "$RES/environment.txt" 2>&1
tail -n +2 "$RES/ground_truth.csv" | while IFS=, read -r N TRIAL INDEX; do INDEX=${INDEX%$'\r'}
  "$HERE/scripts/run_trial.sh" "$N" "$TRIAL" "$INDEX"
done
python3 "$HERE/scripts/collect.py" "$RES"
echo "$(date '+%F %T') all repetitions done"
