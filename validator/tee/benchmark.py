"""Request and verify fresh evidence and emit one JSON line per measured trial."""

import argparse
import secrets
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen

from protocol import BUNDLE_LIMIT, canonical, experiment, parse_json, require_recipient
from verify import load_policy, verify_bundle

METRICS = ("validation_ns", "peak_child_rss_bytes", "cgroup_start_bytes",
           "cgroup_lifetime_peak_bytes", "quote_generation_ns")


def request_bundle(endpoint, nonce):
    request = Request(endpoint.rstrip("/") + "/validate", canonical({"nonce": nonce}),
                      {"Content-Type": "application/json"})
    with urlopen(request, timeout=70) as response:
        data = response.read(BUNDLE_LIMIT + 1)
    if len(data) > BUNDLE_LIMIT:
        raise ValueError("evidence bundle too large")
    return parse_json(data)


def read_metrics(bundle):
    metrics = bundle["metrics"]
    if set(metrics) != set(METRICS):
        raise ValueError("unexpected guest metric fields")
    for name in METRICS:
        value = metrics[name]
        if name.startswith("cgroup_") and value is None:
            continue
        if type(value) is not int or value < 0:
            raise ValueError(f"invalid metric value for {name}")
    return metrics


def main():
    defaults = experiment()[0]["benchmark"]
    parser = argparse.ArgumentParser()
    parser.add_argument("endpoint")
    parser.add_argument("--recipient", required=True)
    parser.add_argument("--mode", choices=("tdx", "mock"), default="tdx")
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--collateral", type=Path)
    parser.add_argument("--warmups", type=int, default=defaults["warmups"])
    parser.add_argument("--runs", type=int, default=defaults["runs"])
    parser.add_argument("--bundle-dir", type=Path)
    args = parser.parse_args()
    if args.runs <= 0 or args.warmups < 0:
        parser.error("runs must be positive and warmups non-negative")
    if args.mode == "tdx" and args.policy is None:
        parser.error("--policy is required in TDX mode")
    if args.mode == "mock" and (args.policy or args.collateral):
        parser.error("TDX policy and collateral apply only to TDX mode")
    require_recipient(args.recipient)
    policy = load_policy(args.policy) if args.policy else None
    if args.bundle_dir:
        args.bundle_dir.mkdir(parents=True, exist_ok=True)

    for index in range(-args.warmups, args.runs):
        nonce = secrets.token_hex(32)
        started = time.perf_counter_ns()
        bundle = request_bundle(args.endpoint, nonce)
        response_ns = time.perf_counter_ns() - started
        verified = verify_bundle(bundle, nonce, args.recipient, args.mode, policy, args.collateral)
        metrics = read_metrics(bundle)
        if index < 0:
            continue
        if args.bundle_dir:
            with (args.bundle_dir / f"{nonce}.json").open("xb") as stream:
                stream.write(canonical(bundle) + b"\n")
        row = {"trial": index + 1, "nonce": nonce, "mode": args.mode, "response_ns": response_ns,
               "experiment_sha256": bundle["manifest"]["experiment_sha256"],
               **metrics, **verified}
        print(canonical(row).decode(), flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, ImportError) as error:
        sys.exit(f"benchmark failed: {error}")
