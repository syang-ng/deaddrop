#!/usr/bin/env bash
# Runs every repetition in results/ground_truth.csv: all Tag Scan runs first (about 2 minutes),
# then OMR at N = 32,768 and 131,072 (about 50 minutes). Stops at the first failure.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
RES=$HERE/results
mkdir -p "$RES/logs"
[[ -e $RES/raw.jsonl ]] && { echo "results/raw.jsonl exists; move it away to start a fresh run"; exit 1; }
python3 "$HERE/scripts/ground_truth.py" "$RES/ground_truth.csv"
"$HERE/scripts/environment.sh" > "$RES/environment.txt" 2>&1
tail -n +2 "$RES/ground_truth.csv" | while IFS=, read -r N TRIAL INDEX; do INDEX=${INDEX%$'\r'}
  "$HERE/scripts/run_tagscan_trial.sh" "$N" "$TRIAL" "$INDEX"
done
tail -n +2 "$RES/ground_truth.csv" | while IFS=, read -r N TRIAL INDEX; do INDEX=${INDEX%$'\r'}
  "$HERE/scripts/run_omr_trial.sh" "$N" "$TRIAL" "$INDEX"
done
python3 "$HERE/scripts/collect.py" "$RES"
echo "$(date '+%F %T') all repetitions done"
