"""Wire format shared by the guest and the independent verifier."""

import base64
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SCHEMA = "deaddrop-validation-v1"
DOMAIN = b"deaddrop-validation-v1\x00"
BUNDLE_LIMIT = 256 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def parse_json(data):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(data, object_pairs_hook=unique_object)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def experiment():
    data = (ROOT / "experiment.json").read_bytes()
    return parse_json(data), sha256(data)


def require_hex(value, byte_count, label):
    if not isinstance(value, str) or not re.fullmatch(f"[0-9a-f]{{{byte_count * 2}}}", value):
        raise ValueError(f"{label} must be {byte_count} bytes of lowercase hex")
    return bytes.fromhex(value)


def require_recipient(recipient):
    if not isinstance(recipient, str) or not re.fullmatch(
        r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}", recipient
    ):
        raise ValueError("expected a native age X25519 recipient")
    return recipient


def manifest(mode, nonce, recipient, config, config_hash, verdict, ciphertext):
    return {
        "schema": SCHEMA,
        "mode": mode,
        "nonce": nonce,
        "recipient_sha256": sha256(recipient.encode("ascii")),
        "experiment_sha256": config_hash,
        "fixture": config["fixture"],
        "blockchain": config["blockchain"],
        "verdict": verdict,
        "ciphertext_sha256": sha256(ciphertext),
    }


def report_data(statement):
    return hashlib.sha512(DOMAIN + canonical(statement)).digest()


def pack_ciphertext(ciphertext):
    return base64.b64encode(ciphertext).decode("ascii")


def unpack_ciphertext(value):
    if not isinstance(value, str):
        raise ValueError("ciphertext must be base64")
    data = base64.b64decode(value, validate=True)
    if not data.startswith(b"age-encryption.org/v1\n") or pack_ciphertext(data) != value:
        raise ValueError("ciphertext must be a canonical base64-encoded age v1 file")
    return data
