"""Run the fixed historical-state check in a fresh loopback Anvil instance."""

import json
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener

from protocol import ROOT, canonical, experiment, parse_json, sha256

RPC_PORT = 18545
OPENER = build_opener(ProxyHandler({}))


def rpc(method, *params):
    request = Request(f"http://127.0.0.1:{RPC_PORT}",
                      canonical({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
                      {"Content-Type": "application/json"})
    with OPENER.open(request, timeout=2) as response:
        body = parse_json(response.read(128 * 1024))
    if body.get("id") != 1 or "error" in body or "result" not in body:
        raise ValueError(f"Anvil RPC failed: {method}")
    return body["result"]


def wait_for_anvil(process):
    deadline = time.monotonic() + 5
    while process.poll() is None and time.monotonic() < deadline:
        try:
            return int(rpc("eth_chainId"), 16)
        except URLError:
            time.sleep(0.02)
    raise ValueError("Anvil failed to start within 5 seconds")


def chain_state(chain_id, config):
    for timestamp in config["mine_timestamps"]:
        rpc("evm_mine", timestamp)

    expected = config["blockchain"]
    height = hex(expected["block_number"])
    head = int(rpc("eth_blockNumber"), 16)
    block = rpc("eth_getBlockByNumber", height, False)
    if head != len(config["mine_timestamps"]) or head <= expected["block_number"] or block is None:
        raise ValueError("fixture block is missing or is not historical")
    actual = {
        "chain_id": chain_id,
        "block_number": int(block["number"], 16),
        "block_hash": block["hash"],
        "state_root": block["stateRoot"],
        "target": expected["target"],
        "storage_slot": expected["storage_slot"],
    }
    if actual != expected:
        raise ValueError("observed Anvil checkpoint differs from the pinned checkpoint")
    return rpc("eth_getStorageAt", actual["target"], actual["storage_slot"], height)


def run_forge(project, config):
    validator = os.getenv("DEADDROP_VALIDATOR", "validator")
    solc = os.getenv("DEADDROP_SOLC", "/usr/local/bin/solc")
    process = subprocess.run([validator, "--fixture", str(RPC_PORT), str(project), solc],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if process.returncode not in (0, 1) or not process.stdout:
        raise ValueError("Forge failed to execute the pinned test")
    suites = parse_json(process.stdout)
    if set(suites) != {config["test_suite"]}:
        raise ValueError("unexpected Forge test suite")
    results = suites[config["test_suite"]]["test_results"]
    if set(results) != {config["test_name"]}:
        raise ValueError("unexpected Forge test result")
    result = results[config["test_name"]]
    if (process.returncode, result["status"]) not in {(0, "Success"), (1, "Failure")}:
        raise ValueError("Forge exit code and test status disagree")
    return result


def run():
    config, _ = experiment()
    with tempfile.TemporaryDirectory(prefix="deaddrop-") as directory:
        project = Path(directory) / "fixture"
        shutil.copytree(ROOT / "fixture", project)
        for name, checksum in config["file_sha256"].items():
            if sha256((project / name).read_bytes()) != checksum:
                raise ValueError(f"fixture digest mismatch: {name}")
        with subprocess.Popen(["anvil", "--host", "127.0.0.1", "--port", str(RPC_PORT),
                               "--init", str(project / "genesis.json"), "--accounts", "0",
                               "--hardfork", config["hardfork"], "--no-mining", "--quiet"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL) as anvil:
            try:
                chain_id = wait_for_anvil(anvil)
                storage = chain_state(chain_id, config)
                result = run_forge(project, config)
            finally:
                if anvil.poll() is None:
                    anvil.terminate()
                    try:
                        anvil.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        anvil.kill()
                        anvil.wait()
    # Linux reports KiB, Darwin reports bytes. This is the maximum child RSS,
    # including waited descendants, rather than the concurrent sum.
    peak_rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    return {"storage_value": storage, "forge_result": result,
            "peak_child_rss_bytes": peak_rss if sys.platform == "darwin" else peak_rss * 1024}


if __name__ == "__main__":
    try:
        print(json.dumps(run(), allow_nan=False))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        sys.exit(f"fixture error: {error}")
