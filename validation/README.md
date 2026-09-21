# Reproducible cryptographic checks

These are implementation conformance and interoperability checks, not a FIPS
validation, independent audit, proof of the composition, or proof against all
classical/quantum attacks. The production package never loads OpenSSL or Python.
All private keys in this directory are public test material.

## NIST ACVP

`acvp/manifest.json` pins NIST ACVP-Server commit
`975de31eb83d87039ec88934fdc47d8c312b892d`, upstream URLs, SHA-256 hashes, group IDs
and case counts. The checked-in JSON preserves all tests in the selected groups.
The 195 cases cover:

| Algorithm | Tests |
| --- | ---: |
| ML-KEM-1024 key generation, public and expanded private bytes | 25 |
| ML-KEM-1024 deterministic encapsulation | 25 |
| ML-KEM-1024 decapsulation, including implicit rejection | 10 |
| ML-KEM-1024 public/private validation | 20 |
| ML-DSA-87 key generation, public and expanded private bytes | 25 |
| ML-DSA-87 deterministic/randomized, internal/external pure signing | 60 |
| ML-DSA-87 valid/invalid internal/external pure verification | 30 |

Prehash ML-DSA and externally computed mu are not features of this package and
are excluded. Passing these selected tests is not an ACVTS certification. The
expanded-key and deterministic interfaces are available only through `#[cfg(test)]` local modules;
the public package uses seed imports and fresh system randomness.

```sh
python3 validation/fetch_acvp.py --check
cargo test --frozen -p post-quantum-core validation_tests
```

To reproduce the selection from the network, run `python3 validation/fetch_acvp.py`.
It verifies the pinned upstream hashes before replacing local fixtures. NIST's
complete attribution/license notice is retained in `acvp/NOTICE.md`.

## Independent implementation and wire vector

`openssl_backend.py` uses public OpenSSL EVP APIs through Python ctypes.
`openssl_interop.py` independently implements the documented PQRS wire format,
HKDF-SHA-512 transcript and signature transcript. This oracle does not call the
Rust primitives. OpenSSL >=3.5 is required; set `OPENSSL_LIBCRYPTO` to a specific
shared library if necessary. No pip packages are needed.

```sh
cargo build --frozen -p post-quantum-core --example interop
npm run build
python3 validation/openssl_interop.py --node
```

The runner checks 18 directed exchanges between OpenSSL, Rust and Node: each
producer's envelope must decrypt and signature must verify in each consumer, for
empty, binary and 64 KiB messages, with context lengths 0, 8 and 255. It checks
OpenSSL/Rust public derivation from the same seeds, modified ciphertext rejection,
and invalid message/context rejection by the independent signature verifier.
Node uses imported public keys; its keypair consistency is exercised by decryption
and signing with the matching imported private keys.

`vectors/protocol-v1.json` is a fixed OpenSSL-created envelope/signature vector
using deliberately public seeds. Rust and Node also consume this immutable vector.
The Rust integration test `protocol.rs` consumes it without requiring OpenSSL.
Its SHA-256 is `aedf730ca32fa16555e45bde347c1a61a728e02cc9e8cbc234c38f39f7552f92`.
Do not regenerate it during tests. `--write-vector` intentionally replaces it and
must only be used when changing the protocol or adding a reviewed fixture.

OpenSSL API references:
[ML-KEM keys](https://docs.openssl.org/3.6/man7/EVP_PKEY-ML-KEM/),
[ML-DSA signatures](https://docs.openssl.org/3.6/man7/EVP_SIGNATURE-ML-DSA/).
Official test source:
[NIST ACVP-Server](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files).

## Coverage-guided fuzzing

`fuzz/` is a separate locked workspace using libFuzzer and AddressSanitizer.
`primitives` directly compiles the local hash/symmetric source into the isolated fuzz target and tests partition invariants, XOF squeezing and AEAD authenticity. `byte_inputs` attacks all four key parsers, envelope decryption and signature
verification. Seeds include valid full envelopes/signatures so the fuzzer reaches
cryptographic processing beyond the header. `operations` fuzzes message/AAD/context
round trips and requires altered tags/signatures to fail. Limits bound each
process; max-length boundary behavior is tested separately by Rust/Node tests.

```sh
rustup toolchain install nightly-2026-09-21 --profile minimal
cargo +nightly-2026-09-21 install cargo-fuzz --version 0.13.2 --locked
node validation/fuzz.mjs
```

These bounded campaigns do not exhaust the input space or establish absence of
side channels. Preserve any crash input as a regression test and investigate it
before release. Local extended campaign results are recorded in the validation
report; generated raw logs belong in ignored `artifacts/validation/`. The wrapper
runs 100,000 parser cases, 200 complete operations and 100,000 primitive cases.
Its report records the source snapshot, both lockfile digests, tool versions,
commands, random seeds and log digests, and rejects changed sources or lockfiles.

## New local primitive implementation

The production crates have no third-party dependencies. The ACVP consumer calls
local algorithms through `#[cfg(test)]` helpers; the previous direct RustCrypto
consumer has been removed. `prepare_vectors.py --check` compares all 195 cases and
the immutable protocol vector against their dependency-free `.kat` conversions.

`kat/primitives-manifest.json` pins 1,771 additional official NIST AFT cases for
SHA-512, SHA3-256/512, SHAKE128/256, HMAC-SHA-512 and HKDF-SHA-512. Selected cases
are byte-oriented, without MCT/LDT claims. `fetch_primitives.py --check` checks
the local digest offline; running without `--check` reproduces the pinned source
selection and independently checks the interpretation with Python hashlib/hmac.
The NIST attribution in `acvp/NOTICE.md` also applies to these derived data.

`kat/symmetric-independent.kat` adds 256 Poly1305 cases from an independent Python
big-integer mathematical reference and 128 OpenSSL AEAD cases. Run
`python3 validation/symmetric_reference.py --check` to regenerate and compare the
same public test data. RFC 8439 section 2.3.2, 2.5.2 and 2.8.2 vectors are tested
separately in the local Rust unit tests.

Production isolation: `node validation/production_graph.mjs` (Linux user/network
namespaces required). Development dependencies: `node validation/audit_tooling.mjs`.
Manual FFI error injection: `node validation/ffi_failures.mjs`, using a separate
artifact and never replacing the distributed native binary. Statistical timing:
`node validation/timing/run.mjs`; see `docs/VALIDATION.md` for scenarios and limits.

`node validation/ffi_asan.mjs` instruments the Rust binding/core/platform on Linux
x64 GNU with pinned nightly Rust and the installed GCC ASan runtime. Node 22 or
24 is required; `--node /path/to/node` selects another executable. A deliberately
invalid isolated addon must report its known heap overflow before test results
are trusted. API/GC/Worker termination and injected failures run without leak
suppressions. Node/V8 and precompiled Rust std remain uninstrumented. The report
`.reports/ffi-asan.json` identifies both native test binaries and the actual ASan
runtime; these artifacts never replace the package's production native binary.
