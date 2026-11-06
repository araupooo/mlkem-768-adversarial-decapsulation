# Claim-to-evidence index — ML-KEM-768 adversarial decapsulation

Each claim cites the file and the exact location of its evidence.
`results.json` holds one record per case (2100 total); `run_harness.log`
is the unedited harness stdout; `matrix.md` tabulates the counts.

| Claim | Statement | Evidence |
|---|---|---|
| M-1 | All four implementations return the valid shared secret for a valid ciphertext (25/25 each). | `outputs/results.json`, class `VALID`, outcome `MATCH` (100 cases); `matrix.md` §A–D |
| M-2 | A single-bit flip in the ciphertext (ct[0], ct[543], ct[1087]) triggers implicit rejection in every implementation (75/75 each). | `outputs/results.json`, class `MALFORMED-1BIT`, outcome `IMPLICIT_REJECT` (300 cases) |
| M-3 | Zeroing a 32-byte block of the ciphertext triggers implicit rejection (25/25 each). | `outputs/results.json`, class `MALFORMED-MULTIBIT` (100 cases) |
| M-4 | Synthetic ciphertexts (all-zero, all-0xFF, random) trigger implicit rejection (75/75 each). | `outputs/results.json`, class `SYNTHETIC-CT` (300 cases) |
| M-5 | Decapsulating with the wrong key triggers implicit rejection (25/25 each). | `outputs/results.json`, class `WRONG-KEY` (100 cases) |
| M-6 | Corrupting the d-region / K-PKE region of the decapsulation key triggers implicit rejection (25/25 each). | `outputs/results.json`, class `CORRUPT-DK-D` (100 cases) |
| M-7 | Corrupting the z-region of the decapsulation key leaves valid-ciphertext decapsulation unchanged (25/25 MATCH each), confirming z is only consumed on the rejection path (FIPS 203 §6.3, Algorithm 18 step 7). | `outputs/results.json`, class `CORRUPT-DK-Z` (100 cases) |
| M-8 | pyca/cryptography and Go enforce the FIPS 203 §7.3 ciphertext length check: every wrong-length ciphertext (1087/544/32/1/0/1089/2176 bytes) raises an error (175/175 each). | `outputs/results.json`, class `WRONG-LENGTH-CT` for `pyca-cryptography` (`ValueError: Invalid ML-KEM-768 ciphertext`) and `go-stdlib-crypto-mlkem` (`RuntimeError: mlkem: invalid ciphertext length`; the 0-byte case is rejected by the Go driver's argument check, see `matrix.md`) |
| M-9 | pyca/cryptography and Go reject a wrong-length decapsulation key at load (25/25 each). | `outputs/results.json`, class `WRONG-LENGTH-DK`: pyca `ValueError: An ML-KEM-768 seed is 64 bytes long`; Go `RuntimeError: mlkem: invalid seed length` |
| M-10 | liboqs 0.12.0 and the Kyber reference do not enforce the FIPS 203 §7.3 decapsulation-key hash check: a key with a corrupted stored H(ekPKE) still decapsulates to a wrong 32-byte secret instead of failing (25/25 each). | `outputs/results.json`, class `CORRUPT-DK-H` for `liboqs` and `kyber-ref` (50 cases, `IMPLICIT_REJECT`); `findings.md` F-1 |
| M-11 | liboqs and the Kyber reference expose fixed-size C APIs that cannot be invoked with wrong-length inputs; the §7.3 length checks are enforced by the caller-side wrapper (400 cases `NOT_INVOKED`, zero C calls with wrong lengths). | `outputs/results.json`, classes `WRONG-LENGTH-CT` / `WRONG-LENGTH-DK` for `liboqs` and `kyber-ref`; `src/run_harness.py` length-guard code; `findings.md` F-2 |
| M-12 | The three FIPS 203 implementations agree on shared secrets: pyca ↔ Go via a shared 64-byte seed, liboqs ↔ pyca via a shared keypair. | `outputs/results.json`, `cross_implementation` (leg 1 `agree: true`, leg 2 `agree: true`); `outputs/run_harness.log`, `== cross-implementation check ==` |
| M-13 | No crash, no unexpected match, no non-32-byte output in any of the 2100 cases. | `outputs/results.json` outcome distribution (MATCH 300, IMPLICIT_REJECT 950, ERROR 400, NOT_INVOKED 400, NOT_APPLICABLE 50; zero other outcomes); `outputs/run_harness.log` tail (`TOTAL CASES: 2100`, exit 0) |

## Primary sources

- FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*,
  NIST, August 2024 — `outputs/raw/fips-203.pdf`
  (SHA-256 `fe1f12f32a7e44ec9fdebbf400cda843a40b506dee676725234dc6f7923b6cac`),
  plain text `outputs/raw/fips-203.txt`.
- liboqs 0.12.0 — `open-quantum-safe/liboqs`, commit
  `f4b96220e4bd208895172acc4fedb5a191d9f5b1` (source in `src/liboqs`).
- pq-crystals/kyber — commit `3edd5af5991927164edd4aacebfcbee00b8064e7`
  (source in `src/kyber-ref`).
- pyca/cryptography 50.0.2 — `cryptography.hazmat.primitives.asymmetric.mlkem`.
- Go 1.24.6 stdlib — `crypto/mlkem`.

## Reproduction

```
python3 -m venv /tmp/mlkem-prep-venv
/tmp/mlkem-prep-venv/bin/pip install "cryptography==50.0.2"
# build liboqs 0.12.0 (cmake) and the Go driver (go1.24.6) and the Kyber
# driver (gcc) as in src/, then:
/tmp/mlkem-prep-venv/bin/python src/run_harness.py > outputs/run_harness.log
```

Expected: exit 0, `TOTAL CASES: 2100`,
`CROSS-IMPL ALL THREE AGREE (by transitivity): True`.
