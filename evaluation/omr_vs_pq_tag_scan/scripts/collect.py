#!/usr/bin/env python3
"""Builds raw.csv, summary.csv and table.md for the post-quantum tag scans, plus a combined
table (combined_table.md) of every detection scheme measured so far:

  OMR detection and X25519 tags (x25519-dalek)  from ../omr_vs_tag_scan/results
  local OMR clue scan                            from ../omr_vs_local_clue_scan/results
  ML-KEM-512, ML-KEM-768 and X25519 (AWS-LC) tags from results/ (this directory)

All runs share E2's ground truth, machine and repetition count. Rows marked "model" are computed
from measured byte counts.
"""
import csv
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
RES = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "results"
E2 = HERE.parent / "omr_vs_tag_scan" / "results"
LS = HERE.parent / "omr_vs_local_clue_scan" / "results"
MIB = 1024 * 1024
LABEL = {"mlkem512": "ML-KEM-512 tags", "mlkem768": "ML-KEM-768 tags", "x25519-awslc": "X25519 tags (AWS-LC)"}

recs = [json.loads(l) for l in (RES / "raw.jsonl").read_text().splitlines() if l.strip()]

# ---- raw.csv for this directory ----
rows = []
for r in recs:
    base = {"scheme": r["scheme"], "N": r["N"], "k": len(r["truth"]), "trial": r["trial"]}
    if r["phase"] == "receiver_keygen":
        rows.append({**base, "threads": 1, "phase": "receiver_setup_keygen", "wall_s": r["wall_s"], "cpu_s": r["cpu_s"],
                     "peak_rss_mib": round(r["maxrss_kb"] / 1024, 1), "bytes_up": 0, "bytes_down": 0, "correct": "",
                     "extra": f"pk {r['pk_bytes']} B to senders; sk {r['sk_bytes']} B kept"})
    elif r["phase"] == "sender_build_board":
        rows.append({**base, "threads": 1, "phase": "sender_report", "wall_s": r["sender_us_per_entry"] * 1e-6,
                     "cpu_s": r["cpu_s"] / r["n"], "peak_rss_mib": "", "bytes_up": r["entry_bytes"], "bytes_down": "",
                     "correct": "", "extra": f"mean over {r['n']} entries; board {r['board_bytes']} B"})
    elif r["phase"] == "receiver_scan":
        fp = len(set(r["matches"]) - set(r["truth"]))
        rows.append({**base, "threads": r["threads"], "phase": "receiver_poll", "wall_s": r["wall_s"], "cpu_s": r["cpu_s"],
                     "peak_rss_mib": round(r["maxrss_kb"] / 1024, 1), "bytes_up": "", "bytes_down": r["download_bytes"],
                     "correct": r["matches"] == r["truth"],
                     "extra": f"recovered {r['matches']}; false positives {fp}; {r['us_per_entry_cpu']:.1f} us/entry CPU"})
cols = ["scheme", "N", "k", "trial", "threads", "phase", "wall_s", "cpu_s", "peak_rss_mib", "bytes_up",
        "bytes_down", "correct", "extra"]
with open(RES / "raw.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    w.writerows(rows)

def med(xs):
    xs = [x for x in xs if x != ""]
    return statistics.median(xs) if xs else ""

groups = defaultdict(list)
for r in rows:
    groups[(r["scheme"], r["N"], r["phase"], str(r["threads"]))].append(r)
summary = []
for (s, n, p, t), g in sorted(groups.items()):
    walls, cpus = [x["wall_s"] for x in g], [x["cpu_s"] for x in g]
    summary.append({
        "scheme": s, "N": n, "phase": p, "threads": t, "trials": len(g),
        "correct": f"{sum(1 for x in g if x['correct'] is True)}/{len(g)}" if g[0]["correct"] != "" else "",
        "wall_s_median": med(walls), "wall_s_min": min(walls), "wall_s_max": max(walls),
        "cpu_s_median": med(cpus), "cpu_s_min": min(cpus), "cpu_s_max": max(cpus),
        "peak_rss_mib_median": med([x["peak_rss_mib"] for x in g]),
        "bytes_up": med([x["bytes_up"] for x in g]), "bytes_down": med([x["bytes_down"] for x in g]),
    })
with open(RES / "summary.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(summary[0].keys()))
    w.writeheader()
    w.writerows(summary)

# ---- combined table across all three experiments ----
def load_summary(path, rename=None):
    out = {}
    with open(path) as f:
        for x in csv.DictReader(f):
            s = rename.get(x["scheme"], x["scheme"]) if rename else x["scheme"]
            out[(s, int(x["N"]), x["phase"], x["threads"])] = x
    return out

S = {}
S.update(load_summary(E2 / "summary.csv", {"tagscan": "x25519"}))
S.update(load_summary(LS / "summary.csv"))
S.update({(x["scheme"], x["N"], x["phase"], x["threads"]): {k: str(v) for k, v in x.items()} for x in summary})

def get(s, n, p, t=None):
    if t is not None:
        return S[(s, n, p, str(t))]
    return next(v for k, v in S.items() if k[:3] == (s, n, p))

f_ = float
def sec(v):
    v = f_(v)
    if v < 1e-3:
        return f"{v * 1e6:.0f} µs"
    if v < 1:
        return f"{v * 1e3:.1f} ms"
    return f"{v:.2f} s" if v < 10 else f"{v:.1f} s"
def mib(b):
    b = f_(b) / MIB
    return f"{b:.2f} MiB" if b < 10 else f"{b:.1f} MiB"

SCHEMES = [("omr", "OMR detection", "lattice (srPKE + BFV)"),
           ("x25519", "X25519 tags (dalek)", "classical"),
           ("x25519-awslc", "X25519 tags (AWS-LC)", "classical"),
           ("mlkem512", "ML-KEM-512 tags", "lattice (MLWE)"),
           ("mlkem768", "ML-KEM-768 tags", "lattice (MLWE)"),
           ("localscan", "Local OMR clue scan", "lattice (srPKE)")]
NPROC = max(int(k[3]) for k in S if k[0] == "mlkem512" and k[2] == "receiver_poll")
Ns = sorted({k[1] for k in S if k[0] == "mlkem512"})

def detector_cpu(s, n):
    return f_(get("omr", n, "detector_poll")["cpu_s_median"]) if s == "omr" else 0.0

def entry_bytes(s, n):
    return f_(get(s, n, "sender_report")["bytes_up"])

lines = []
for n in Ns:
    omr_down = f_(get("omr", n, "receiver_poll", 1)["bytes_down"])
    lines.append(f"### N = {n:,} (median of 3 repetitions; correctness is exact recovery of the one pertinent index)")
    lines.append("")
    lines.append("| Scheme | Assumption | Correct | Entry size | Download per poll | vs OMR | Receiver CPU, 1 thread "
                 f"| Receiver wall, {NPROC} threads | Detector CPU | Total CPU | OMR extra CPU-s per MiB saved |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for s, name, assumption in SCHEMES:
        rp = get(s, n, "receiver_poll", 1)
        down = f_(rp["bytes_down"])
        rcpu = f_(rp["cpu_s_median"])
        try:
            many = sec(get(s, n, "receiver_poll", NPROC)["wall_s_median"])
        except (KeyError, StopIteration):
            many = "—"
        det = detector_cpu(s, n)
        if s == "omr":
            ratio, per_mib = "1×", "—"
        else:
            saved = (down - omr_down) / MIB
            ratio = f"{down / omr_down:.1f}×" if down / omr_down < 10 else f"{down / omr_down:.0f}×"
            # Same definition as E2: OMR's extra total CPU per poll, per MiB of receiver download saved.
            omr_total = f_(get("omr", n, "receiver_poll", 1)["cpu_s_median"]) + detector_cpu("omr", n)
            per_mib = f"{(omr_total - (rcpu + det)) / saved:.1f}" if saved > 0 else "OMR downloads more"
        eb = entry_bytes(s, n)
        lines.append(f"| {name} | {assumption} | {rp['correct']} | {eb:,.0f} B | {mib(down)} | {ratio} | {sec(rcpu)} "
                     f"| {many} | {sec(det) if det else 'none'} | {sec(rcpu + det)} | {per_mib} |")
    lines.append("")
lines.append("- **One-time setup.** OMR uploads 160.3 MiB of keys to the detector and needs about 27 GiB of "
             "detector memory per poll. Every tag scheme and the local clue scan upload nothing to the detector.")
lines.append(f"- **Download time (model).** At 10 Mbps: OMR {omr_down * 8 / 10e6:.2f} s per poll. For each "
             "tag scheme or local scan, the download per poll × 8 / 10⁷ s.")
(RES / "combined_table.md").write_text("\n".join(lines) + "\n")
print("\n".join(lines))
