"""Fetch and verify the three Linux/AMD64 inputs for the named build context."""

import argparse
import hashlib
import shutil
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.request import urlopen

from protocol import ROOT

SOURCES = {
    "foundry.tar.gz": "https://github.com/foundry-rs/foundry/releases/download/v1.5.1/"
                     "foundry_v1.5.1_linux_amd64.tar.gz",
    "age.tar.gz": "https://github.com/FiloSottile/age/releases/download/v1.3.1/"
                  "age-v1.3.1-linux-amd64.tar.gz",
    "solc": "https://raw.githubusercontent.com/ethereum/solc-bin/gh-pages/linux-amd64/"
            "solc-linux-amd64-v0.8.28+commit.7893614a",
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def download(directory, name, checksum):
    path = directory / name
    if path.exists() and digest(path) == checksum:
        print(f"verified {path}", file=sys.stderr)
        return
    with tempfile.TemporaryDirectory(dir=directory) as temp:
        staged = Path(temp) / name
        with urlopen(SOURCES[name], timeout=90) as response, staged.open("wb") as stream:
            shutil.copyfileobj(response, stream)
        if digest(staged) != checksum:
            raise ValueError(f"checksum mismatch for {name}")
        staged.replace(path)
    print(f"verified {path}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=True)
    locks = {name: checksum for checksum, name in
             map(str.split, (ROOT / "build-assets.sha256").read_text().splitlines())}
    if set(locks) != set(SOURCES):
        raise ValueError("asset lock and source list differ")
    with ThreadPoolExecutor(max_workers=len(locks)) as pool:
        jobs = [pool.submit(download, args.directory, name, checksum)
                for name, checksum in locks.items()]
        for job in jobs:
            job.result()


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        sys.exit(f"asset download failed: {error}")
