# DeadDrop

## Open Science Artifact

DeadDrop is a research prototype for confidential smart-contract vulnerability
reporting. It separates three responsibilities: a submitter demonstrates that a
candidate exploit violates a stated invariant, a bulletin-board service stores
an encrypted report and its discovery metadata, and an authorized receiver
detects and decrypts reports intended for it.

This repository is the anonymized artifact prepared for open-science review. It
contains the Rust prototype, two validation paths, a local web interface, test
fixtures, an HTTP client for an oblivious-message-retrieval (OMR) service, and a
source snapshot of that service in `omr-server/`. Generated keys, attestations, submitted reports, build products, and
author-identifying metadata are intentionally excluded from the artifact tree.

### Artifact scope

| Capability | Entry point | External requirements |
| --- | --- | --- |
| Build and unit tests | Rust workspace in `deadbug/` | Rust and Cargo |
| Foundry invariant validation | `submitter foundry` | Foundry, `jq`, and a historical-state Ethereum mainnet RPC |
| Transaction-replay validation | `submitter validation` | Anvil and an Ethereum archive RPC |
| Encrypted report packaging | `submitter` after a detected violation | Python, `dstack-sdk`, and a Tappd/TDX socket |
| Local receiver/detector demonstration | `receiver` and `deadbug_detector` | No external OMR service |
| OMR HTTP protocol and timing client | `rust_omr` binary | The OMR server from `omr-server/`, built separately and running on a trusted host |
| Local bulletin-board UI | Flask application in `frontend/` | Python, Flask, and Flask-SQLAlchemy |

The application-facing OMR modules currently form a compatibility prototype
used by the local tests and demonstrations. The separate HTTP client preserves
the imported five-operation OMR protocol (`init`, clue generation, clue
submission, digest generation, and digest decoding), but it is not wired into
the submitter, detector, or receiver workflow. Consequently, the offline test
suite validates application wiring and serialization, not the security or
performance of the external OMR construction.

## Repository layout

```text
deadbug/
  submitter/   Foundry and transaction-replay validation; report encryption
  detector/    Compatibility detector over bulletin-board entries
  receiver/    Interactive receiver and local end-to-end demonstration
  rust_omr/    Compatibility OMR API plus the external HTTP protocol client
  utils/       Encryption, key management, hashing, and JSON data types
  server/      Minimal server placeholder
frontend/      Local Flask bulletin-board interface
validator/     Standalone Foundry validator fixture
omr-server/    C++ OMR server source snapshot (see omr-server/VENDORED.md)
```

## Reproducing the artifact

### Prerequisites

The local checks require Rust and Cargo. The experiment workflows additionally
use the following tools as indicated:

- Foundry (`forge` and `anvil`)
- `jq`
- Python 3
- an Ethereum mainnet/archive RPC endpoint
- a Tappd-compatible socket and the Python `dstack-sdk`, only for attestation

The artifact was verified with Rust/Cargo 1.94.1, Foundry 1.5.1, and Python
3.9.6. Dependency manifests are authoritative; the repository does not pin a
Rust toolchain or commit a workspace `Cargo.lock`. A fresh setup also needs
network access to fetch Rust dependencies and the Forge standard library.

### 1. Local build and tests

After Cargo has downloaded the Rust dependencies, these commands do not require
an Ethereum RPC, TDX socket, or OMR server:

```bash
cd deadbug
cargo check --workspace --all-targets
cargo test --workspace
cargo run -p submitter -- --help
cargo run -p submitter -- validation --help
```

The submitter help output should list both `foundry` and `validation`. In the
current revision, 13 workspace tests pass. Compiler warnings from prototype-only
code do not indicate test failures.

### 2. Foundry invariant workflow

To evaluate only the bundled Foundry fixture, without report packaging or TDX
attestation, run:

```bash
cd validator
MAINNET_RPC_URL="https://your-mainnet-rpc.example" cargo run --release
```

For the full submitter path, run from `deadbug/submitter` so that a generated
submission is written at the repository root:

```bash
cd deadbug/submitter

export MAINNET_RPC_URL="https://your-mainnet-rpc.example"
# Alternatively:
# export INFURA_PROJECT_ID="your-project-id"

export BUG_FILE="bug/bug_report.sol"
export BLOCK_NUM_FILE="test/block_num.txt"
export TEST_FILE="test/test_example.sol"
export CONTRACT_ADDR_FILE="test/contract_addr.txt"

cargo run -- foundry
```

Calling `cargo run` without a subcommand also selects Foundry mode. The bundled
script creates a temporary Forge project, forks mainnet at the requested block,
and evaluates the invariant test. If the candidate violates the invariant, the
submitter continues to encrypted packaging and attestation.

Attestation requires `dstack-sdk` and a reachable Tappd socket. Without those
dependencies, the Foundry validation subprocess can run, but a detected
violation will make the full command fail at the final attestation step rather
than produce a submission with an attestation quote.

### 3. Transaction-replay workflow

Validation mode forks the supplied RPC at a historical block, impersonates the
sender, executes the transaction in Anvil, and compares selected ERC-20 balances
before and after execution:

```bash
cd deadbug/submitter

cargo run -- validation \
  --rpc-url "https://your-archive-rpc.example" \
  --block-number 23555153 \
  --block-time 1760193791 \
  --from 0x9696f59E4d72E237BE84fFD425DCaD154Bf96976 \
  --to 0x64F2095CC11e4726078F4A64d4279c7e7fB7e6Ec \
  --value 0 \
  --data 0xfa461e330000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
```

The validator starts Anvil on port `28545`. A decrease in one of the monitored
token balances is treated as an invariant violation and invokes the same
packaging and attestation path as Foundry mode. A transaction that reverts or an
unreachable RPC causes a non-zero exit.

### 4. Local compatibility demonstration

The receiver demonstration exercises key generation, submission, detection,
payload recovery, and report decryption entirely within the compatibility
backend:

```bash
cd deadbug/receiver
cargo run --bin receiver
```

For the interactive receiver menu instead, run:

```bash
cargo run --bin main
```

These commands are useful for checking the data flow; they are not measurements
of the external OMR construction.

### 5. External OMR protocol client

The server source is in `omr-server/`; it is not built by the Rust workspace or
the Dockerfile. `omr-server/README.md` lists its dependencies and build steps,
and the HTTP server is the `http_server` target. With that server already
running, the imported timing driver can exercise its five endpoints:

```bash
cd deadbug
OMR_HOST=127.0.0.1 OMR_PORT=8080 \
  cargo run --release -p rust_omr --bin rust_omr
```

The driver initializes the server, submits clues at four fixed indices,
generates an encrypted digest, decodes it, and prints operation times and object
sizes. It is an integration/timing harness rather than a statistical benchmark.
The protocol sends key material over HTTP, so the service should remain on a
trusted loopback interface.

### 6. Local web interface

First build the detector, then start the Flask application:

```bash
cd deadbug
cargo build --release -p deadbug_detector

cd ../frontend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export DETECTOR_PATH="$(pwd)/../deadbug/target/release/deadbug_detector"
flask --app app.py run
```

The interface is a local research prototype. Its default Flask secret and SQLite
configuration are not suitable for an Internet-facing deployment.

## Generated data and key handling

On first use, the compatibility backend creates local AGE and mock-OMR key files
with mode `0600` on Unix. These files are ignored by Git. When the submitter and
receiver run from different working directories, point both processes to shared
files:

```bash
export DEADDROP_LEGACY_AGE_KEYS_FILE="/absolute/path/to/age-keys.txt"
export DEADDROP_LEGACY_OMR_KEYS_FILE="/absolute/path/to/omr-keys.txt"
```

The following are intentionally excluded from the release tree:

- generated private keys;
- `submitted_data.json` and run-specific attestation material;
- Rust `target/` directories and Docker build outputs;
- the local Flask database.

Do not publish a zip of a previously built working directory. Create release
archives from a clean checkout so ignored binaries and machine-specific build
paths are not included.
