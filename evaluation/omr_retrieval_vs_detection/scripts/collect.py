#!/usr/bin/env python3
"""Experiment 1: upstream OMR retrieval (OMR3_dos) vs. DeadDrop detection-only.

Measured: the upstream runs in results/logs/upstream-kbar<K>-<T>.log (N = 32,768, 1 core, native
612-slot payloads) and DeadDrop's detection from ../omr_vs_tag_scan/results/summary.csv.

Projected (labelled "projection" everywhere): larger payloads. Upstream lays payloads out as 53
buckets x 612 slots in one 32,768-slot ciphertext per 50 pertinent messages. A payload of S slots
would need c(P) = ceil(53 * S / 32768) bucket ciphertexts. Doubling k-bar from 50 to 100 doubles
the bucket ciphertexts (1 -> 2) and leaves the rest of the pipeline unchanged, so the measured
difference between the two is the cost of one more bucket ciphertext. Payload size P maps to
S = P / 2 slots (each slot holds a value mod 65537, i.e. 2 bytes).
"""
import csv
import math
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
RES = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "results"
E2 = HERE.parent / "omr_vs_tag_scan" / "results"
N, SLOTS, BUCKETS, NATIVE_SLOTS = 32768, 32768, 53, 612
MIB = 1024 * 1024

def grab(text, pat, cast=float):
    m = re.search(pat, text)
    return cast(m.group(1)) if m else None

runs = []
for log in sorted((RES / "logs").glob("upstream-kbar*-*.log")):
    kbar, trial = map(int, re.match(r"upstream-kbar(\d+)-(\d+)\.log", log.name).groups())
    t = log.read_text()
    if "RUSAGE" not in t:  # run still in progress or killed before rusage_exec reported
        print(f"skipping incomplete {log.name}", file=sys.stderr)
        continue
    ru = re.search(r"RUSAGE wall_s=([\d.]+) user_s=([\d.]+) sys_s=([\d.]+) maxrss_kb=(\d+) exit=(\d+)", t)
    r = {
        "kbar": kbar, "trial": trial,
        "prepare_s": grab(t, r"Prepare switching key time: (\d+)") / 1e6,
        "clue_to_pv_s": grab(t, r"ClueToPackedPV time: (\d+) us") / 1e6,
        "pv_unpack_s": grab(t, r"PVUnpack time: (\d+) us") / 1e6,
        "pv_to_digest_s": grab(t, r"ExpandedPVToDigest time: (\d+) us") / 1e6,
        "detector_running_s": grab(t, r"Detector running time: (\d+) us") / 1e6,
        "digest_bytes": grab(t, r"Digest size: (\d+) bytes", int),
        "decode_s": grab(t, r"Receiver decoding time: (\d+) us") / 1e6,
        "correct": "Result is correct!" in t,
        "process_wall_s": float(ru.group(1)), "process_cpu_s": float(ru.group(2)) + float(ru.group(3)),
        "peak_rss_mib": int(ru.group(4)) / 1024, "exit": int(ru.group(5)),
    }
    # Detector total: the switching-key precomputation (timed separately upstream) plus everything
    # upstream counts as "Detector running time". Upstream runs it on one thread here.
    r["detector_s"] = r["prepare_s"] + r["detector_running_s"]
    r["detection_part_s"] = r["prepare_s"] + r["clue_to_pv_s"]
    r["retrieval_part_s"] = r["detector_s"] - r["detection_part_s"]
    runs.append(r)

cols = list(runs[0].keys())
with open(RES / "raw.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    w.writerows(runs)

by = defaultdict(list)
for r in runs:
    by[r["kbar"]].append(r)
med = lambda xs: statistics.median(xs)
S = {k: {c: med([r[c] for r in v]) for c in cols if c not in ("kbar", "trial", "correct")} | {
        "n": len(v), "correct": sum(r["correct"] for r in v), "kbar": k} for k, v in by.items()}
with open(RES / "summary.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(next(iter(S.values())).keys()))
    w.writeheader()
    w.writerows(S[k] for k in sorted(S))

e2 = {}
with open(E2 / "summary.csv") as f:
    for x in csv.DictReader(f):
        if x["scheme"] == "omr" and int(x["N"]) == N:
            e2[x["phase"]] = x
dd_cpu = float(e2["detector_poll"]["cpu_s_median"])
dd_wall = float(e2["detector_poll"]["wall_s_median"])
dd_digest = float(e2["receiver_poll"]["bytes_down"])
dd_decode = float(e2["receiver_poll"]["cpu_s_median"])
dd_rss = float(e2["detector_poll"]["peak_rss_mib_median"])

def rng(k, c, fmt):
    xs = [r[c] for r in by[k]]
    return fmt(med(xs)) if len(xs) == 1 else f"{fmt(med(xs))} ({fmt(min(xs))}–{fmt(max(xs))})"
s_ = lambda v: f"{v:.1f} s" if v >= 1 else f"{v * 1e3:.0f} ms"
mb = lambda b: f"{b / MIB:.2f} MiB"

lines = ["## Measured at N = 32,768, 1 core, native payload (612 slots per message)", "",
         "| Metric | DeadDrop detection (E2) | " + " | ".join(f"Upstream OMR retrieval, k̄={k}" for k in sorted(by)) + " |",
         "|---|---|" + "---|" * len(by)]
def row(label, dd, fn):
    lines.append(f"| {label} | {dd} | " + " | ".join(fn(k) for k in sorted(by)) + " |")
row("Runs, correct", "3, 3", lambda k: f"{S[k]['n']}, {S[k]['correct']}")
row("Bucket ciphertexts for payloads", "none", lambda k: str(math.ceil(BUCKETS * (k // 50) * NATIVE_SLOTS / SLOTS)))
row("Detection: switching-key precompute + clues → packed PV (wall)", f"{s_(dd_wall)} wall, {s_(dd_cpu)} CPU (3-thread precompute)",
    lambda k: f"{rng(k, 'prepare_s', s_)} + {rng(k, 'clue_to_pv_s', s_)}")
row("Retrieval: PV unpack (expansion)", "none", lambda k: rng(k, "pv_unpack_s", s_))
row("Retrieval: expanded PV → digest (payloads, index counters)", "none", lambda k: rng(k, "pv_to_digest_s", s_))
row("Detector total CPU (upstream is single-threaded, so CPU ≈ wall)", s_(dd_cpu), lambda k: rng(k, "detector_s", s_))
row("— of which retrieval", "0", lambda k: rng(k, "retrieval_part_s", s_))
row("Process CPU, whole run (setup + detector + receiver)", "—", lambda k: rng(k, "process_cpu_s", s_))
row("Digest download", mb(dd_digest), lambda k: rng(k, "digest_bytes", mb))
row("Receiver decoding", f"{dd_decode * 1e3:.0f} ms", lambda k: rng(k, "decode_s", s_))
row("Peak RSS (whole process)", f"{dd_rss / 1024:.1f} GiB (detector)", lambda k: f"{S[k]['peak_rss_mib'] / 1024:.1f} GiB")
lines.append("")

def fit(key):
    """Least-squares line value = a + b * c over the measured k-bar points (c = k-bar / 50)."""
    pts = [(k // 50, S[k][key]) for k in sorted(S)]
    n = len(pts)
    mx, my = sum(c for c, _ in pts) / n, sum(v for _, v in pts) / n
    b = sum((c - mx) * (v - my) for c, v in pts) / sum((c - mx) ** 2 for c, _ in pts)
    a = my - b * mx
    worst = max(abs(v - (a + b * c)) / v for c, v in pts)
    return a, b, worst, pts

if 50 in S and len(S) >= 2:
    base = S[50]
    a_det, d_cpu, res_det, pts_det = fit("detector_s")
    a_dig, d_dig, res_dig, _ = fit("digest_bytes")
    _, d_stage, res_stage, pts_stage = fit("pv_to_digest_s")
    lines += ["## Projection to larger payloads (k̄ = 50, N = 32,768; projection, not measured)", "",
              "Linear fit over the measured points c = " + ", ".join(str(c) for c, _ in pts_det) +
              f" bucket ciphertexts: each extra bucket ciphertext adds {d_cpu:.1f} s of detector time "
              f"(the payload stage alone: {d_stage:.1f} s) and {d_dig / MIB:.3f} MiB of digest. Largest relative "
              f"deviation from the line: detector {res_det:.1%}, payload stage {res_stage:.1%}, digest {res_dig:.1%}. "
              "Upstream supports only payloads up to 612 slots; larger sizes need code changes (chunked buckets, "
              "streamed payloads, receiver decoding).", "",
              "| Payload | Bucket ciphertexts c(P) | Upstream detector (wall ≈ CPU) | Upstream digest | Payload memory per 32,768-message batch | "
              "DeadDrop detector | DeadDrop download, padded to k̄ = 50 | DeadDrop download, k = 1 |",
              "|---|---|---|---|---|---|---|---|"]
    for label, p in (("native (612 slots, 1.2 KB)", 2 * NATIVE_SLOTS), ("1 KB", 1024), ("10 KB", 10240),
                     ("100 KB", 102400), ("1 MB", 1048576)):
        slots = math.ceil(p / 2)
        c = max(1, math.ceil(BUCKETS * slots / SLOTS))
        det = a_det + c * d_cpu
        dig = a_dig + c * d_dig
        mem = N * max(slots, NATIVE_SLOTS) * 8
        lines.append(f"| {label} | {c} | {det:,.0f} s | {dig / MIB:,.1f} MiB | {mem / 2**30:,.2f} GiB | "
                     f"{dd_cpu:.0f} CPU-s (any size) | {(dd_digest + 50 * p) / MIB:,.2f} MiB + oblivious-read cost | "
                     f"{(dd_digest + p) / MIB:,.2f} MiB + oblivious-read cost |")
    lines.append("")
(RES / "table.md").write_text("\n".join(lines) + "\n")
print("\n".join(lines))
