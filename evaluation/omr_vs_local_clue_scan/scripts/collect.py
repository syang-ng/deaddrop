#!/usr/bin/env python3
"""Builds raw.csv, summary.csv and table.md for the local clue scan, next to E2's OMR rows.

Local-scan numbers come from results/raw.jsonl. OMR numbers come from
../omr_vs_tag_scan/results/summary.csv (same commit, harness, board generator and ground truth).
Rows marked "model" are computed from measured byte counts or from the clue parameters.
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
MIB = 1024 * 1024
N1, ELL, Q_BITS = 936, 3, 17                     # srPKEParam(): n1, ell, q = 65537
PACKED_CLUE_BYTES = -(-(N1 + ELL) * Q_BITS // 8)  # 1,996 B if coefficients were packed at 17 bits

recs = [json.loads(l) for l in (RES / "raw.jsonl").read_text().splitlines() if l.strip()]
truth = {(r["N"], r["trial"]): r["truth"] for r in recs}

# ---- raw.csv ----
rows = []
for r in recs:
    p = r["phase"]
    base = {"scheme": "localscan", "N": r["N"], "k": len(r["truth"]), "trial": r["trial"]}
    if p == "receiver_keygen":
        rows.append({**base, "phase": "receiver_setup_keygen", "threads": 1, "wall_s": r["clue_keys_wall_s"],
                     "cpu_s": r["clue_keys_cpu_s"], "peak_rss_mib": "", "bytes_up": 0, "bytes_down": 0,
                     "correct": "", "extra": f"srPKE key pair only; pk_clue {r['pk_clue_bytes']} B to senders; "
                                             f"sk_clue {r['sk_clue_bytes']} B kept"})
    elif p == "build_board":
        rows.append({**base, "phase": "board_simulation", "threads": 1, "wall_s": r["board_wall_s"],
                     "cpu_s": r["board_cpu_s"], "peak_rss_mib": round(r["maxrss_kb"] / 1024, 1), "bytes_up": "",
                     "bytes_down": "", "correct": "", "extra": f"{r['n']} dummy clues (not a role cost)"})
        rows.append({**base, "phase": "sender_report", "threads": 1, "wall_s": r["sender_clue_wall_s"],
                     "cpu_s": r["sender_clue_cpu_s"], "peak_rss_mib": "", "bytes_up": r["clue_wire_bytes"],
                     "bytes_down": "", "correct": "", "extra": f"clue on disk {r['clue_file_bytes']} B"})
    elif p == "board_export":
        rows.append({**base, "phase": "board_export", "threads": 1, "wall_s": r["wall_s"], "cpu_s": "",
                     "peak_rss_mib": "", "bytes_up": "", "bytes_down": r["board_bytes"], "correct": "",
                     "extra": "all clues in wire format (not a role cost)"})
    elif p == "receiver_local_scan":
        fp = len(set(r["matches"]) - set(r["truth"]))
        rows.append({**base, "phase": "receiver_poll", "threads": r["threads"], "wall_s": r["wall_s"],
                     "cpu_s": r["cpu_s"], "peak_rss_mib": round(r["maxrss_kb"] / 1024, 1), "bytes_up": "",
                     "bytes_down": r["download_bytes"], "correct": r["matches"] == r["truth"],
                     "extra": f"recovered {r['matches']}; false positives {fp} of {r['n'] - len(r['truth'])}; "
                              f"{r['us_per_clue_cpu']:.2f} us/clue CPU; load {r['load_s']:.2f} s"})

cols = ["scheme", "N", "k", "trial", "threads", "phase", "wall_s", "cpu_s", "peak_rss_mib",
        "bytes_up", "bytes_down", "correct", "extra"]
with open(RES / "raw.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    w.writerows(rows)

# ---- summary.csv ----
def med(xs):
    xs = [x for x in xs if x != ""]
    return statistics.median(xs) if xs else ""

groups = defaultdict(list)
for r in rows:
    groups[(r["N"], r["phase"], str(r["threads"]))].append(r)
summary = []
for (n, p, t), g in sorted(groups.items()):
    walls = [x["wall_s"] for x in g]
    cpus = [x["cpu_s"] for x in g if x["cpu_s"] != ""]
    summary.append({
        "scheme": "localscan", "N": n, "phase": p, "threads": t, "trials": len(g),
        "correct": f"{sum(1 for x in g if x['correct'] is True)}/{len(g)}" if g[0]["correct"] != "" else "",
        "wall_s_median": med(walls), "wall_s_min": min(walls), "wall_s_max": max(walls),
        "cpu_s_median": med(cpus), "cpu_s_min": min(cpus) if cpus else "", "cpu_s_max": max(cpus) if cpus else "",
        "peak_rss_mib_median": med([x["peak_rss_mib"] for x in g]),
        "bytes_up": med([x["bytes_up"] for x in g]), "bytes_down": med([x["bytes_down"] for x in g]),
    })
with open(RES / "summary.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(summary[0].keys()))
    w.writeheader()
    w.writerows(summary)

# ---- table.md: local scan next to E2's OMR rows ----
L = {(x["N"], x["phase"], x["threads"]): x for x in summary}
O = {}
with open(E2 / "summary.csv") as f:
    for x in csv.DictReader(f):
        if x["scheme"] == "omr":
            O[(int(x["N"]), x["phase"])] = x
NPROC = max(int(t) for (_, p, t) in L if p == "receiver_poll")
Ns = sorted({n for (n, _, _) in L})
f_ = float

def sec(v):
    v = f_(v)
    if v < 1e-3:
        return f"{v * 1e6:.0f} µs"
    if v < 1:
        return f"{v * 1e3:.1f} ms"
    return f"{v:.2f} s" if v < 10 else f"{v:.1f} s"

def rng(x, key):
    return f"{sec(x[key + '_median'])} ({sec(x[key + '_min'])}–{sec(x[key + '_max'])})"

def mib(b):
    b = f_(b) / MIB
    return f"{b:.3f} MiB" if b < 10 else f"{b:.1f} MiB"

hdr = ["Metric"] + [f"{s} N={n:,}" for n in Ns for s in ("Local clue scan", "OMR detection (E2)")]
lines = ["| " + " | ".join(hdr) + " |", "|" + "---|" * len(hdr)]
def row(label, fl, fo):
    cells = []
    for n in Ns:
        for fn in (fl, fo):
            try:
                cells.append(fn(n))
            except (KeyError, ValueError, TypeError):
                cells.append("n/a")
    lines.append("| " + label + " | " + " | ".join(cells) + " |")

lp = lambda n, t=1: L[(n, "receiver_poll", str(t))]
row("Correct repetitions (k = 1)", lambda n: lp(n)["correct"], lambda n: O[(n, "receiver_poll")]["correct"])
row("False positives (non-pertinent clues accepted)", lambda n: str(sum(
    len(set(r["matches"]) - set(r["truth"])) for r in recs if r["phase"] == "receiver_local_scan" and r["N"] == n)),
    lambda n: "0 (exact sets)")
row("Receiver CPU per poll, 1 thread", lambda n: rng(lp(n), "cpu_s"), lambda n: rng(O[(n, "receiver_poll")], "cpu_s"))
row(f"Receiver wall per poll, {NPROC} threads (supplementary)", lambda n: rng(lp(n, NPROC), "wall_s"), lambda n: "—")
row("Detector CPU per poll", lambda n: "none", lambda n: rng(O[(n, "detector_poll")], "cpu_s"))
row("Detector wall per poll", lambda n: "none", lambda n: rng(O[(n, "detector_poll")], "wall_s"))
row("Total CPU per poll (receiver + detector)", lambda n: sec(lp(n)["cpu_s_median"]),
    lambda n: sec(f_(O[(n, "receiver_poll")]["cpu_s_median"]) + f_(O[(n, "detector_poll")]["cpu_s_median"])))
row("Download per poll", lambda n: mib(lp(n)["bytes_down"]), lambda n: mib(O[(n, "receiver_poll")]["bytes_down"]))
row(f"Download if clues were packed at 17 bits (model, {PACKED_CLUE_BYTES} B/clue)",
    lambda n: mib(PACKED_CLUE_BYTES * n), lambda n: "—")
row("Download time at 10 / 100 Mbps (model)",
    lambda n: "{:.0f} s / {:.1f} s".format(f_(lp(n)["bytes_down"]) * 8 / 10e6, f_(lp(n)["bytes_down"]) * 8 / 100e6),
    lambda n: "{:.2f} s / {:.3f} s".format(f_(O[(n, "receiver_poll")]["bytes_down"]) * 8 / 10e6,
                                          f_(O[(n, "receiver_poll")]["bytes_down"]) * 8 / 100e6))
row("One-time upload to detector", lambda n: "0 B", lambda n: mib(O[(n, "receiver_setup_keygen")]["bytes_up"]))
row("One-time receiver key generation CPU", lambda n: rng(L[(n, "receiver_setup_keygen", "1")], "cpu_s"),
    lambda n: rng(O[(n, "receiver_setup_keygen")], "cpu_s"))
row("Peak RSS, receiver poll process", lambda n: f"{f_(lp(n)['peak_rss_mib_median']):.0f} MiB",
    lambda n: f"{f_(O[(n, 'receiver_poll')]['peak_rss_mib_median']):.0f} MiB")
row("Peak RSS, detector poll process", lambda n: "—",
    lambda n: f"{f_(O[(n, 'detector_poll')]['peak_rss_mib_median']) / 1024:.1f} GiB")
row("Board storage per entry (same clue)", lambda n: f"{f_(L[(n, 'sender_report', '1')]['bytes_up']):.0f} B",
    lambda n: f"{f_(O[(n, 'sender_report')]['bytes_up']):.0f} B")

lines.append("")
lines.append("Trade-off (medians): detector CPU OMR spends per MiB of receiver download it saves")
for n in Ns:
    omr_down = f_(O[(n, "receiver_poll")]["bytes_down"])
    det = f_(O[(n, "detector_poll")]["cpu_s_median"])
    for label, local_down in (("wire format", f_(lp(n)["bytes_down"])), ("packed model", PACKED_CLUE_BYTES * n)):
        saved = (local_down - omr_down) / MIB
        lines.append(f"- N={n:,}, {label}: OMR downloads {local_down / omr_down:.0f}x less, saving {saved:.1f} MiB "
                     f"per poll for {det:.0f} detector CPU-s = {det / saved:.2f} CPU-s per MiB saved")
(RES / "table.md").write_text("\n".join(lines) + "\n")
print("\n".join(lines))
