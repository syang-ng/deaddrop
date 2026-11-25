#!/usr/bin/env bash
# Runs ML-KEM-512, ML-KEM-768 and X25519 (AWS-LC) tag scans for every repetition in E2's ground
# truth, then builds the combined comparison with E2 (OMR, X25519 dalek) and the local clue scan.
# About 3 minutes. Stops at the first failure.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
REPO=$(cd "$HERE/../.." && pwd)
E2=$REPO/evaluation/omr_vs_tag_scan
RES=$HERE/results
mkdir -p "$RES/logs"
[[ -e $RES/raw.jsonl ]] && { echo "results/raw.jsonl exists; move it away to start a fresh run"; exit 1; }
cp "$E2/results/ground_truth.csv" "$RES/ground_truth.csv"
"$E2/scripts/environment.sh" > "$RES/environment.txt" 2>&1
awk '/^name = "aws-lc-(rs|sys)"/ {n=$3; getline; print "  " n " " $3}' "$E2/tag_scan/Cargo.lock" | tr -d '"' \
  | sed '1i aws-lc crates:' >> "$RES/environment.txt"
for SCHEME in mlkem512 mlkem768 x25519-awslc; do
  tail -n +2 "$RES/ground_truth.csv" | while IFS=, read -r N TRIAL INDEX; do INDEX=${INDEX%$'\r'}
    "$HERE/scripts/run_trial.sh" "$SCHEME" "$N" "$TRIAL" "$INDEX"
  done
done
python3 "$HERE/scripts/collect.py" "$RES"
echo "$(date '+%F %T') all repetitions done"
