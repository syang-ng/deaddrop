#!/usr/bin/env python3
"""Writes the shared ground truth: one pertinent index per (N, trial), used by both schemes.

The seed fixes only which index is pertinent; all keys and encryption randomness come from the
OS RNG in each implementation. At N = 131,072 the index is drawn from [32768, N) so that every
repetition exercises a block after the first.
"""
import csv
import random
import sys

SEED = 20261125
rng = random.Random(SEED)
out = sys.argv[1]
with open(out, "w", newline="") as f:
    w = csv.writer(f, lineterminator="\n")
    w.writerow(["N", "trial", "index"])
    for n in (32768, 131072):
        lo = 0 if n == 32768 else 32768
        for trial in (1, 2, 3):
            w.writerow([n, trial, rng.randrange(lo, n)])
