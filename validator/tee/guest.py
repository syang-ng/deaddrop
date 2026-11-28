"""Issue one evidence bundle for each completed validation run."""

import argparse
import http.client
import os
import signal
import socket
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from protocol import (BUNDLE_LIMIT, ROOT, canonical, experiment, manifest, pack_ciphertext,
                      parse_json, report_data, require_hex, require_recipient)

DSTACK_SOCKET = "/var/run/dstack.sock"


class DstackConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(DSTACK_SOCKET)


def tdx_quote(data):
    conn = DstackConnection("localhost", timeout=10)
    try:
        conn.request("POST", "/GetQuote", canonical({"report_data": data.hex()}),
                     {"Content-Type": "application/json"})
        response = conn.getresponse()
        body = response.read(BUNDLE_LIMIT + 1)
        if response.status != 200 or len(body) > BUNDLE_LIMIT:
            raise ValueError(f"dstack returned an invalid response (HTTP {response.status})")
    finally:
        conn.close()

    result = parse_json(body)
    encoded = result["quote"]
    if not isinstance(encoded, str) or not 0 < len(encoded) <= 128 * 1024 or len(encoded) % 2:
        raise ValueError("invalid dstack quote length")
    quote = require_hex(encoded, len(encoded) // 2, "quote")
    if quote[:2] not in (b"\x04\x00", b"\x05\x00") or quote[4:8] != b"\x81\x00\x00\x00":
        raise ValueError("dstack did not return an Intel TDX quote")
    # This is a transport check. The external verifier checks the signed report data.
    if result.get("report_data", data.hex()) != data.hex():
        raise ValueError("dstack report data echo differs from the request")
    return quote


def cgroup_memory(field):
    try:
        return int((Path("/sys/fs/cgroup") / field).read_text())
    except (OSError, ValueError):
        return None


def run_workload():
    with subprocess.Popen([sys.executable, str(ROOT / "workload.py")],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          start_new_session=True) as process:
        try:
            stdout, stderr = process.communicate(timeout=45)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise
    if process.returncode:
        raise ValueError(stderr.decode("utf-8", errors="replace").strip())
    return parse_json(stdout)


def validation_bundle(nonce, recipient, mode):
    require_hex(nonce, 32, "nonce")
    require_recipient(recipient)
    config, config_hash = experiment()
    memory_at_start = cgroup_memory("memory.current")
    started = time.perf_counter_ns()
    outcome = run_workload()
    validation_ns = time.perf_counter_ns() - started
    memory_high_water = cgroup_memory("memory.peak")
    verdict = "pass" if outcome["forge_result"]["status"] == "Success" else "fail"
    statement = manifest(mode, nonce, recipient, config, config_hash, verdict, b"")
    del statement["ciphertext_sha256"]
    plaintext = canonical({"validation": statement, "observations": outcome})
    ciphertext = subprocess.run(["age", "--encrypt", "--recipient", recipient], input=plaintext,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=5, check=True).stdout
    statement = manifest(mode, nonce, recipient, config, config_hash, verdict, ciphertext)
    data = report_data(statement)
    started = time.perf_counter_ns()
    if mode == "tdx":
        quote = tdx_quote(data)
    elif mode == "mock":
        from mock_quote import mock_quote
        quote = mock_quote(data)
    else:
        raise ValueError("unknown attestation mode")
    quote_generation_ns = time.perf_counter_ns() - started
    return {
        "manifest": statement,
        "ciphertext_b64": pack_ciphertext(ciphertext),
        "quote_hex": quote.hex(),
        "metrics": {
            "validation_ns": validation_ns,
            "peak_child_rss_bytes": outcome["peak_child_rss_bytes"],
            "cgroup_start_bytes": memory_at_start,
            "cgroup_lifetime_peak_bytes": memory_high_water,
            "quote_generation_ns": quote_generation_ns,
        },
    }


class RequestHandler(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(10)
        super().setup()

    def reply(self, status, payload):
        body = canonical(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/validate":
            self.reply(404, {"error": "unknown endpoint"})
            return
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if (len(lengths) != 1 or len(lengths[0]) > 3 or not lengths[0].isascii()
                    or not lengths[0].isdecimal() or not 1 <= int(lengths[0]) <= 128
                    or self.headers.get("Transfer-Encoding")):
                raise ValueError("invalid request length")
            payload = parse_json(self.rfile.read(int(lengths[0])))
            if not isinstance(payload, dict) or set(payload) != {"nonce"}:
                raise ValueError("expected a nonce")
            require_hex(payload["nonce"], 32, "nonce")
        except (OSError, ValueError):
            self.reply(400, {"error": "invalid validation request"})
            return

        try:
            result = validation_bundle(payload["nonce"], self.server.recipient, self.server.mode)
        except (OSError, ValueError, KeyError, subprocess.SubprocessError, http.client.HTTPException) as error:
            self.log_error("validation failed: %s", error)
            self.reply(503, {"error": "validation unavailable"})
            return
        self.reply(200, result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("serve", "run"))
    parser.add_argument("--mode", required=True, choices=("mock", "tdx"))
    parser.add_argument("--recipient", default=os.getenv("DEADDROP_RECIPIENT"))
    parser.add_argument("--nonce")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    recipient = require_recipient(args.recipient)
    if args.mode == "mock":
        # The mock module is shipped exclusively in the local image.
        import mock_quote  # noqa: F401
    if args.action == "run":
        print(canonical(validation_bundle(args.nonce, recipient, args.mode)).decode())
    else:
        if args.nonce is not None:
            parser.error("--nonce applies only to run")
        with HTTPServer((args.host, args.port), RequestHandler) as server:
            server.recipient = recipient
            server.mode = args.mode
            server.serve_forever()


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, http.client.HTTPException) as error:
        sys.exit(f"validation error: {error}")
