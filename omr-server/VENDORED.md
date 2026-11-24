# Vendored OMR server

This directory is a source snapshot of the OMR server that the `rust_omr` HTTP client in
`deadbug/rust_omr/` talks to. It is maintained here; there is no submodule and no git history.

## Origin

- Base: the public DoS-PerfOMR implementation,
  `https://github.com/ObliviousMessageRetrieval/ObliviousMessageRetrieval`, branch `ec25`,
  commit `0a35f72278bd1897edc262bf18b76604681e32da` (2025-05-11). MIT licence, see `LICENSE`.
- On top of that base, the DeadDrop integration adds an HTTP API for detection mode.

## Changes relative to the base commit

| File | Change |
| --- | --- |
| `include/API.h` | Added: `init_deaddrop`, `gen_clue`, `submit_clue`, `gen_encrypted_digest`, `decode_digest` |
| `include/serialize.h` | Added: wire encoding of keys, clues, indices and ciphertexts |
| `http_server.cpp` | Added: the five HTTP endpoints |
| `banana.cpp`, `server.cpp` | Added: local drivers for the API |
| `include/httplib.h` | Added: third-party cpp-httplib (MIT) |
| `CMakeLists.txt` | Builds `http_server` and `banana_demo` instead of `OMRdemos` |
| `include/OMRUtil.h`, `include/OMRdos.h`, `include/PVWToBFVSeal.h` | Small edits (25 lines in total) |

## Changes made in this repository after the snapshot

| File | Change |
| --- | --- |
| `include/API.h` | No seeded random generator, so keys and encryptions no longer share randomness. Relinearization and Galois keys are made once in `init_deaddrop` by the key generator that holds `sk_decode`, and `gen_encrypted_digest` uses them. `submit_clue` rejects indices outside the scanned range and clues of the wrong shape. The database size is one constant, `ddctx::num_transactions`. |
| `include/LoadAndSaveUtils.h` | `saveClues_dos` and `loadClues_dos` throw on a failed write and on a missing, truncated or malformed clue file. |
| `include/serialize.h` | `DeserializeIndex` throws on a malformed index; it used to return 0. |
| `http_server.cpp` | `/submit_clue` stores the clue once and answers 400 to an invalid index or clue. |
| `include/global.h` | `range_check_r_dos` is 94 (accepts \|x\| <= 93); it was 80. |
| `banana.cpp` | Submits to an index inside the scanned range and checks the result. |

`README.md` and `figures/` are unchanged from the base commit. The
upstream `README.md` lists the dependencies (PALISADE, the SEAL 4.1 fork, OpenSSL 1.1.1, NTL, GMP)
and the build steps; with this tree the build targets are `http_server` and `banana_demo`.
