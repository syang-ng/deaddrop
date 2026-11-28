"""Verify an evidence bundle on the relying party's machine."""

import argparse
import asyncio
import hmac
import sys
import time
from pathlib import Path

from protocol import (BUNDLE_LIMIT, canonical, experiment, manifest, parse_json, report_data,
                      require_hex, require_recipient, unpack_ciphertext)

PCCS = "https://pccs.phala.network"
MEASUREMENTS = ("mr_td", "rt_mr0", "rt_mr1", "rt_mr2", "rt_mr3")


def load_policy(path):
    policy = parse_json(path.read_bytes())
    if not isinstance(policy, dict) or set(policy) != set(MEASUREMENTS):
        raise ValueError("policy must contain MRTD and RTMR0 through RTMR3")
    for name in MEASUREMENTS:
        require_hex(policy[name], 48, name)
    return policy


def verify_tdx(quote, expected_data, policy, collateral_path):
    import dcap_qvl

    if policy is None:
        raise ValueError("TDX verification requires a trusted measurement policy")

    started = time.perf_counter_ns()
    parsed = dcap_qvl.parse_quote(quote)
    if not parsed.is_tdx():
        raise ValueError("expected an Intel TDX quote")
    if collateral_path is None:
        async def fetch():
            return await asyncio.wait_for(dcap_qvl.get_collateral(PCCS, quote), timeout=30)
        collateral = asyncio.run(fetch())
    else:
        collateral = dcap_qvl.QuoteCollateralV3.from_json(collateral_path.read_text())
    collateral_ns = time.perf_counter_ns() - started

    result = dcap_qvl.verify(quote, collateral, int(time.time()))
    if result.status != "UpToDate":
        raise ValueError(f"DCAP TCB status is {result.status}")

    report = parsed.report
    if int.from_bytes(report.td_attributes, "little") & 1:
        raise ValueError("debug-enabled TDX quotes are rejected")
    if not hmac.compare_digest(report.report_data, expected_data):
        raise ValueError("signed REPORTDATA does not bind this result")
    for name in MEASUREMENTS:
        if not hmac.compare_digest(getattr(report, name).hex(), policy[name]):
            raise ValueError(f"unexpected guest measurement: {name}")
    return collateral_ns


def verify_bundle(bundle, nonce, recipient, mode, policy=None, collateral=None):
    started = time.perf_counter_ns()
    require_hex(nonce, 32, "expected nonce")
    require_recipient(recipient)
    if not isinstance(bundle, dict) or set(bundle) != {"manifest", "ciphertext_b64", "quote_hex", "metrics"}:
        raise ValueError("invalid evidence bundle")
    statement = bundle["manifest"]
    if not isinstance(statement, dict) or statement.get("mode") != mode:
        raise ValueError(f"expected {mode} evidence")
    if statement.get("verdict") not in ("pass", "fail"):
        raise ValueError("invalid verdict")
    config, config_hash = experiment()
    ciphertext = unpack_ciphertext(bundle["ciphertext_b64"])
    expected = manifest(mode, nonce, recipient, config, config_hash, statement["verdict"], ciphertext)
    if canonical(statement) != canonical(expected):
        raise ValueError("binding inputs differ from the independently expected values")
    encoded = bundle["quote_hex"]
    if not isinstance(encoded, str) or not 0 < len(encoded) <= 128 * 1024 or len(encoded) % 2:
        raise ValueError("invalid quote length")
    quote = require_hex(encoded, len(encoded) // 2, "quote")
    data = report_data(statement)
    collateral_ns = None
    if mode == "tdx":
        collateral_ns = verify_tdx(quote, data, policy, collateral)
    elif mode == "mock":
        from mock_quote import mock_quote
        if not hmac.compare_digest(quote, mock_quote(data)):
            raise ValueError("local mock binding mismatch")
    else:
        raise ValueError("unknown verification mode")

    return {
        "verification": "hardware_verified" if mode == "tdx" else "unsigned_mock_checked",
        "verdict": statement["verdict"],
        "quote_bytes": len(quote),
        "quote_verification_ns": time.perf_counter_ns() - started,
        "collateral_ns": collateral_ns,
    }


def load_bundle(path):
    with path.open("rb") as stream:
        data = stream.read(BUNDLE_LIMIT + 1)
    if len(data) > BUNDLE_LIMIT:
        raise ValueError("evidence bundle too large")
    return parse_json(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--recipient", required=True)
    parser.add_argument("--mode", choices=("tdx", "mock"), default="tdx")
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--collateral", type=Path)
    parser.add_argument("--ciphertext-out", type=Path)
    args = parser.parse_args()
    if args.mode == "tdx" and args.policy is None:
        parser.error("--policy is required in TDX mode")
    if args.mode == "mock" and (args.policy or args.collateral):
        parser.error("TDX policy and collateral apply only to TDX mode")
    policy = load_policy(args.policy) if args.policy else None
    bundle = load_bundle(args.bundle)
    result = verify_bundle(bundle, args.nonce, args.recipient, args.mode, policy, args.collateral)
    if args.ciphertext_out:
        with args.ciphertext_out.open("xb") as stream:
            stream.write(unpack_ciphertext(bundle["ciphertext_b64"]))
    print(canonical(result).decode())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, ImportError) as error:
        sys.exit(f"verification failed: {error}")
