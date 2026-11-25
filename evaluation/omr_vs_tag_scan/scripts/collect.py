#!/usr/bin/env python3
"""Turns results/raw.jsonl into raw.csv, summary.csv and table.md.

Every number in the outputs comes from a measured RESULT line or a detector log, except rows
marked "model", which are computed from measured byte counts at a stated link speed.
"""
import csv
import json
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
RES = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "results"
MIB = 1024 * 1024

recs = [json.loads(l) for l in (RES / "raw.jsonl").read_text().splitlines() if l.strip()]
NPROC = max((r["threads"] for r in recs if r["scheme"] == "tagscan" and r["phase"] == "receiver_scan"), default=1)


def detector_phases(n, trial):
    """Phase wall times (integer seconds) printed by gen_encrypted_digest()."""
    text = (RES / "logs" / f"omr-{n}-{trial}-detect.log").read_text()
    grab = lambda pat: int(re.search(pat + r"\s*:\s*(\d+) s", text).group(1))
    return {
        "precompute_s": grab(r"rotating switching key precomputation"),
        "online_s": grab(r"generating encrypted indices"),
        "compression_s": grab(r"compression"),
    }


# ---- raw.csv: one row per scheme x N x trial x phase ----
rows = []
def add(r, phase, wall, cpu, rss_kb, up, down, correct="", threads="", extra=""):
    rows.append({
        "scheme": r["scheme"], "N": r["N"], "k": len(r["truth"]), "trial": r["trial"],
        "threads": threads, "phase": phase, "wall_s": wall, "cpu_s": cpu,
        "peak_rss_mib": round(rss_kb / 1024, 1) if rss_kb != "" else "",
        "bytes_up": up, "bytes_down": down, "correct": correct, "extra": extra,
    })

for r in recs:
    s, p = r["scheme"], r["phase"]
    if s == "omr" and p == "receiver_keygen":
        up = r["pk_detect_bytes"] + r["relin_keys_bytes"] + r["galois_keys_bytes"]
        add(r, "receiver_setup_keygen", r["wall_s"], r["cpu_s"], r["maxrss_kb"], up, 0, threads="as shipped",
            extra=f"to detector: pk_detect {r['pk_detect_bytes']} + relin {r['relin_keys_bytes']} + galois "
                  f"{r['galois_keys_bytes']} B; to senders: pk_clue {r['pk_clue_bytes']} B; "
                  f"detection key gen {r['detection_key_wall_s']:.2f} s")
    elif s == "omr" and p == "build_board":
        add(r, "board_simulation", r["board_wall_s"], r["board_cpu_s"], r["maxrss_kb"], "", "",
            extra=f"{r['n']} dummy clues (not a role cost)")
        add(r, "sender_report", r["sender_clue_wall_s"], r["sender_clue_cpu_s"], "", r["clue_wire_bytes"], "",
            threads=1, extra=f"clue on disk {r['clue_file_bytes']} B")
    elif s == "omr" and p == "detect":
        add(r, "detector_setup", r["setup_wall_s"], r["setup_cpu_s"], r["maxrss_after_setup_kb"], "", "",
            extra="load keys from the receiver")
        ph = detector_phases(r["N"], r["trial"])
        add(r, "detector_poll", r["wall_s"], r["cpu_s"], r["maxrss_kb"], "", r["digest_bytes"],
            threads="3 precompute / 1 online",
            extra=f"precompute {ph['precompute_s']} s, online {ph['online_s']} s, compression {ph['compression_s']} s")
    elif s == "omr" and p == "decode":
        add(r, "receiver_setup_load", r["setup_wall_s"], r["setup_cpu_s"], "", "", "")
        add(r, "receiver_poll", r["wall_s"], r["cpu_s"], r["maxrss_kb"], "", r["digest_bytes"],
            correct=r["matches"] == r["truth"], threads=1, extra=f"recovered {r['matches']}")
    elif s == "tagscan" and p == "receiver_keygen":
        add(r, "receiver_setup_keygen", r["wall_s"], r["cpu_s"], r["maxrss_kb"], 0, 0, threads=1,
            extra=f"to senders: pk {r['pk_bytes']} B; nothing to the board")
    elif s == "tagscan" and p == "sender_build_board":
        add(r, "sender_report", r["sender_us_per_entry"] * 1e-6, r["cpu_s"] / r["n"], "", r["entry_bytes"], "",
            threads=1, extra=f"mean over {r['n']} entries; board {r['board_bytes']} B")
    elif s == "tagscan" and p == "receiver_scan":
        add(r, "receiver_poll", r["wall_s"], r["cpu_s"], r["maxrss_kb"], "", r["download_bytes"],
            correct=r["matches"] == r["truth"], threads=r["threads"],
            extra=f"recovered {r['matches']}; {r['us_per_entry_cpu']:.1f} us/entry CPU")

cols = ["scheme", "N", "k", "trial", "threads", "phase", "wall_s", "cpu_s", "peak_rss_mib",
        "bytes_up", "bytes_down", "correct", "extra"]
with open(RES / "raw.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    w.writerows(rows)

# ---- summary.csv: median and range over trials ----
groups = defaultdict(list)
for r in rows:
    groups[(r["scheme"], r["N"], r["phase"], str(r["threads"]))].append(r)

def med(xs):
    xs = [x for x in xs if x != ""]
    return statistics.median(xs) if xs else ""

summary = []
for (s, n, p, t), g in sorted(groups.items()):
    walls = [x["wall_s"] for x in g]
    cpus = [x["cpu_s"] for x in g]
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

# ---- table.md ----
S = {(x["scheme"], x["N"], x["phase"], x["threads"]): x for x in summary}
def get(s, n, p, t=None):
    if t is None:
        cands = [v for k, v in S.items() if k[:3] == (s, n, p)]
        return cands[0] if cands else None
    return S.get((s, n, p, str(t)))

def rng(x, key, fmt):
    if x is None:
        return "n/a"
    m, lo, hi = x[f"{key}_median"], x[f"{key}_min"], x[f"{key}_max"]
    return f"{fmt(m)} ({fmt(lo)}–{fmt(hi)})"

def sec(v):
    if v < 1e-3:
        return f"{v * 1e6:.0f} µs"
    if v < 1:
        return f"{v * 1e3:.1f} ms"
    return f"{v:.2f} s" if v < 10 else f"{v:.1f} s"
mib = lambda b: f"{b / MIB:.3f} MiB" if b < 10 * MIB else f"{b / MIB:.1f} MiB"
def kib_or_b(b):
    return f"{b} B" if b < 1024 else f"{b / 1024:.2f} KiB"

Ns = sorted({r["N"] for r in recs})
hdr = ["Metric"] + [f"{name} N={n:,}" for n in Ns for name in ("OMR", "Tag Scan")]
lines = ["| " + " | ".join(hdr) + " |", "|" + "---|" * len(hdr)]
def row(label, fn):
    cells = []
    for n in Ns:
        for s in ("omr", "tagscan"):
            try:
                cells.append(fn(s, n))
            except Exception as e:  # keep the table honest about gaps
                cells.append("n/a")
    lines.append("| " + label + " | " + " | ".join(cells) + " |")

row("Correct repetitions (k = 1)", lambda s, n: get(s, n, "receiver_poll", 1)["correct"])
row("Receiver CPU per poll, 1 thread", lambda s, n: rng(get(s, n, "receiver_poll", 1), "cpu_s", sec))
row(f"Receiver wall per poll, {NPROC} threads (supplementary)",
    lambda s, n: rng(get(s, n, "receiver_poll", NPROC), "wall_s", sec) if s == "tagscan" else "—")
row("Detector CPU per poll", lambda s, n: rng(get(s, n, "detector_poll"), "cpu_s", sec) if s == "omr" else "none (static file)")
row("Detector wall per poll", lambda s, n: rng(get(s, n, "detector_poll"), "wall_s", sec) if s == "omr" else "none")
def total_cpu(s, n):
    r = get(s, n, "receiver_poll", 1)["cpu_s_median"]
    d = get(s, n, "detector_poll")["cpu_s_median"] if s == "omr" else 0.0
    return r + d
row("Total CPU per poll (median receiver + detector)", lambda s, n: sec(total_cpu(s, n)))
row("Download per poll", lambda s, n: mib(get(s, n, "receiver_poll", 1)["bytes_down"]))
row("Download at 10 / 100 Mbps (model)", lambda s, n: "{:.2f} s / {:.3f} s".format(
    get(s, n, "receiver_poll", 1)["bytes_down"] * 8 / 10e6, get(s, n, "receiver_poll", 1)["bytes_down"] * 8 / 100e6))
row("One-time upload to detector", lambda s, n: mib(get(s, n, "receiver_setup_keygen")["bytes_up"]) if s == "omr" else "0 B")
row("One-time receiver key generation CPU", lambda s, n: rng(get(s, n, "receiver_setup_keygen"), "cpu_s", sec))
row("Peak RSS, receiver poll process", lambda s, n: f"{get(s, n, 'receiver_poll', 1)['peak_rss_mib_median']:.0f} MiB")
row("Peak RSS, detector poll process", lambda s, n: f"{get(s, n, 'detector_poll')['peak_rss_mib_median'] / 1024:.1f} GiB" if s == "omr" else "—")
row("Board storage per entry (serialized)", lambda s, n: kib_or_b(get(s, n, "sender_report")["bytes_up"]))
row("Board storage total", lambda s, n: mib(get(s, n, "sender_report")["bytes_up"] * n))
row("Sender metadata per report", lambda s, n: rng(get(s, n, "sender_report"), "wall_s", sec))

lines.append("")
lines.append("Trade-off (from medians): extra CPU OMR spends per MiB of receiver download it saves")
for n in Ns:
    saved = (get("tagscan", n, "receiver_poll", 1)["bytes_down"] - get("omr", n, "receiver_poll", 1)["bytes_down"]) / MIB
    extra = total_cpu("omr", n) - total_cpu("tagscan", n)
    det = get("omr", n, "detector_poll")["cpu_s_median"]
    lines.append(f"- N={n:,}: saves {saved:.3f} MiB per poll; detector CPU {det:.0f} s; net extra CPU "
                 f"{extra:.0f} s; {extra / saved:.0f} CPU-s per MiB saved" if saved > 0 else
                 f"- N={n:,}: OMR downloads more than Tag Scan")
(RES / "table.md").write_text("\n".join(lines) + "\n")
print("\n".join(lines))
