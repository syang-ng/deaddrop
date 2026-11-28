"""Render the immutable Compose file for upload to Phala."""

import argparse
import re

from protocol import ROOT, require_recipient

IMAGE = re.compile(r"[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--recipient", required=True)
    args = parser.parse_args()
    if not IMAGE.fullmatch(args.image):
        parser.error("--image must be an immutable registry image reference with a lowercase digest")
    recipient = require_recipient(args.recipient)
    template = (ROOT / "compose.phala.yaml").read_text()
    for name, value in (("DEADDROP_IMAGE", args.image), ("DEADDROP_RECIPIENT", recipient)):
        template, count = re.subn(r"\$\{" + name + r":\?[^}]+\}", value, template)
        if count != 1:
            raise ValueError(f"expected exactly one Compose variable named {name}")
    print(template, end="")


if __name__ == "__main__":
    main()
