# ML-KEM-768 Adversarial Decapsulation Assessment

Negative decapsulation behavior of ML-KEM-768 (FIPS 203) across four
implementations, measured with a runnable harness. 2100 cases, 25 fresh
keypairs per implementation.

## Headline results

- Implicit rejection (FIPS 203 §6.3, Algorithm 18) is uniformly correct:
  950/950 adversarial-input cases returned a 32-byte rejection secret
  different from the valid secret, with no error and no crash.
- pyca/cryptography 50.0.2 and Go 1.24.6 stdlib enforce the §7.3 input
  checks inside the API (wrong-length ciphertext/key → error).
- liboqs 0.12.0 and the pq-crystals Kyber reference do not enforce the
  §7.3 decapsulation-key hash check themselves: a key with a corrupted
  stored `H(ekPKE)` still decapsulates to a wrong 32-byte secret. §7.3
  permits the check to be performed by other means, so this is a
  validation gap, not a standard violation — callers must check the key
  themselves.
- The three FIPS 203 implementations agree on shared secrets
  (pyca ↔ Go via a shared 64-byte seed; liboqs ↔ pyca via a shared
  keypair).

## Implementations

| ID | Implementation | Version |
|---|---|---|
| A | pyca/cryptography (`cryptography.hazmat.primitives.asymmetric.mlkem`) | 50.0.2 |
| B | liboqs (`ML-KEM-768`, built from source) | 0.12.0, commit `f4b9622` |
| C | Go stdlib `crypto/mlkem` | go1.24.6 |
| D | pq-crystals/kyber Kyber768 reference (round-3, pre-FIPS 203 — lineage reference only) | commit `3edd5af` |

## Files

- `rubric.md` — input classes mapped to expected FIPS 203 behavior.
- `matrix.md` — measured negative-test matrix (counts per implementation).
- `findings.md` — severity-ranked findings (F-1…F-4).
- `index.md` — claim-to-evidence index (M-1…M-13).
- `src/run_harness.py` — the harness (stdlib + `cryptography` + `ctypes`).
- `src/go-mlkem/main.go` — Go stdlib driver.
- `src/kyber-ref-driver.c` — Kyber reference driver.
- `outputs/results.json` — one record per case (2100).
- `outputs/results.txt` — summary counts.
- `outputs/run_harness.log` — unedited harness stdout.
- `outputs/SHA256SUMS` — digests of all outputs.
- `outputs/raw/fips-203.pdf` (+ `.txt`) — FIPS 203 primary source.
- `outputs/raw/SOURCES.txt` — source commit identifiers.

## Reproduce

```
python3 -m venv /tmp/mlkem-prep-venv
/tmp/mlkem-prep-venv/bin/pip install "cryptography==50.0.2"

# liboqs 0.12.0 (from src/liboqs):
cmake -S src/liboqs -B src/liboqs/build -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build src/liboqs/build -j"$(nproc)"

# Go driver (needs go1.24.6):
(cd src/go-mlkem && go build -o gomlkem .)

# Kyber reference driver (needs gcc):
cc -O2 -DKYBER_K=3 -Isrc/kyber-ref/ref src/kyber-ref/ref/{kem,indcpa,polyvec,poly,ntt,cbd,reduce,verify,fips202,symmetric-shake,randombytes}.c \
   src/kyber-ref-driver.c -o src/kyber768-driver

/tmp/mlkem-prep-venv/bin/python src/run_harness.py > outputs/run_harness.log
```

Expected: exit 0, `TOTAL CASES: 2100`,
`CROSS-IMPL ALL THREE AGREE (by transitivity): True`.

## Notes

- Wrong-length ciphertexts and keys are never passed to the fixed-size C
  APIs (liboqs, Kyber reference). The harness wrapper enforces the §7.3
  length check before the call and records `NOT_INVOKED`.
- pyca/cryptography and Go store the decapsulation key as the 64-byte seed
  (d‖z); no public API exports the 2400-byte expanded key, so the
  `CORRUPT-DK-H` probe does not apply to them.
- The Kyber reference implements round-3 Kyber768, not FIPS 203 ML-KEM:
  its shared secrets are not comparable with A/B/C. Only its behavioral
  class outcomes are compared.
