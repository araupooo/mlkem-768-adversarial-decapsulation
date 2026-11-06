# Rubric — ML-KEM-768 adversarial decapsulation input classes

Source of expected behavior: FIPS 203, *Module-Lattice-Based Key-Encapsulation
Mechanism Standard* (NIST.FIPS.203, August 2024; minor corrections 22 Aug 2024),
file `outputs/raw/fips-203.pdf` (SHA-256
`fe1f12f32a7e44ec9fdebbf400cda843a40b506dee676725234dc6f7923b6cac`).

Parameter set under test: ML-KEM-768 (Table 2: n=256, q=3329, k=3, η1=2, η2=2,
du=10, dv=4). Table 3 sizes: encapsulation key 1184 bytes, decapsulation key
2400 bytes, ciphertext 1088 bytes, shared secret 32 bytes.

## Expected behavior, by FIPS 203 section

### §6.3 Algorithm 18 — ML-KEM.Decaps_internal(dk, c)
Decapsulation decrypts `c` to `m'`, re-encrypts `m'` with the derived
randomness `r'`, and compares the re-encrypted ciphertext `c'` with the
provided `c`. If `c ≠ c'`, the algorithm performs **implicit rejection**:
`K' ← J(z‖c)` — a 32-byte shared secret derived from the rejection value `z`
stored in the decapsulation key and the provided ciphertext. In either case
decapsulation outputs a 32-byte shared secret; no error is raised and the
rejection flag is a secret intermediate value that shall be destroyed before
the algorithm terminates (it must not be returned in any form).

Consequence for the matrix: for every adversarial ciphertext that is not a
valid encapsulation under the tested key, the expected outcome is a 32-byte
shared secret **different from** the valid shared secret, with **no error**.

### §7.3 — ML-KEM.Decaps input checking
Before `ML-KEM.Decaps` runs, the following checks apply:
1. **Ciphertext type check** — `c` must be a byte array of length
   `32·(du·k + dv)` = 1088 bytes for ML-KEM-768. Otherwise input checking
   has failed.
2. **Decapsulation key type check** — `dk` must be a byte array of length
   `768·k + 96` = 2400 bytes. Otherwise input checking has failed.
3. **Hash check** — `test ← H(dk[384k : 768k+32])` must equal
   `dk[768k+32 : 768k+64]`. Otherwise input checking has failed.

"ML-KEM.Decaps shall not be run with a decapsulation key or a ciphertext
unless both have been checked. However, checking of the decapsulation key
need not be performed by the decapsulating party, nor with every execution
of ML-KEM.Decaps. ... Ciphertext checking shall be performed with every
execution of ML-KEM.Decaps."

Consequence for the matrix: a wrong-length ciphertext must produce an
**error** (input checking failed), never a 32-byte secret. A decapsulation
key that fails the length or hash check must produce an **error** if the
implementation performs the check itself; if the implementation leaves the
check to the caller (§7.3 permits this for the key), a corrupted key must
still never yield the *valid* shared secret.

### §7.1 / Algorithm 18 key layout (ML-KEM-768, dk = 2400 bytes)
- `dk[0 : 1152]` — K-PKE decryption key (384k)
- `dk[1152 : 2336]` — K-PKE encryption key (384k+32)
- `dk[2336 : 2368]` — `h = H(ekPKE)` (32 bytes; used in step 6, `G(m'‖h)`)
- `dk[2368 : 2400]` — `z`, the implicit-rejection value (32 bytes; used only
  in step 7, `J(z‖c)`)

Corrupting `z` must therefore **not** change the result for a valid
ciphertext (z is not consumed on the success path), while corrupting `h`
changes the derived shared secret even for a valid ciphertext (h feeds
`G(m'‖h)`), and corrupting the K-PKE decryption key changes the decrypted
`m'`, which fails the re-encryption check and triggers implicit rejection.

## Input classes and expected outcomes

| Class | Input | Expected outcome (FIPS 203) |
|---|---|---|
| VALID | valid encapsulation under the tested key | MATCH — decapsulated secret equals the encapsulation secret |
| MALFORMED-1BIT | ciphertext with one bit flipped (ct[0], ct[543], ct[1087]) | IMPLICIT_REJECT — 32-byte secret ≠ valid secret, no error (§6.3) |
| MALFORMED-MULTIBIT | 32-byte block of the ciphertext zeroed | IMPLICIT_REJECT (§6.3) |
| SYNTHETIC-CT | all-zero / all-0xFF / random 1088-byte ciphertext | IMPLICIT_REJECT (§6.3) |
| WRONG-KEY | valid ciphertext decapsulated with a different keypair | IMPLICIT_REJECT (§6.3) |
| CORRUPT-DK-D | first byte of the decapsulation key flipped (d-region / K-PKE key) | IMPLICIT_REJECT (§6.3) |
| CORRUPT-DK-Z | last byte of the decapsulation key flipped (z-region) | MATCH for a valid ciphertext (z unused on success path, Alg 18) |
| CORRUPT-DK-H | byte 2350 flipped (inside stored H(ekPKE), expanded-key form only) | ERROR if the §7.3 hash check is enforced, else IMPLICIT_REJECT |
| REPLAY-DETERMINISM | same valid ciphertext decapsulated 3 times | MATCH every time (decapsulation uses no randomness, §6.3) |
| WRONG-LENGTH-CT | ciphertext of 1087 / 544 / 32 / 1 / 0 / 1089 / 2176 bytes | ERROR — §7.3 ciphertext type check |
| WRONG-LENGTH-DK | decapsulation key of 2399 bytes (expanded) or 63-byte seed | ERROR — §7.3 key type check |

## Implementations under test

| ID | Implementation | Version / source | Key encoding |
|---|---|---|---|
| A | pyca/cryptography | 50.0.2 (`cryptography.hazmat.primitives.asymmetric.mlkem`) | ek 1184 B; dk as 64-byte seed (d‖z); no public API exports the 2400-byte expanded dk |
| B | liboqs | 0.12.0, built from source (`open-quantum-safe/liboqs`, commit `f4b96220e4bd208895172acc4fedb5a191d9f5b1`) | ek 1184 B; sk 2400 B expanded |
| C | Go stdlib crypto/mlkem | go1.24.6, stdlib `crypto/mlkem` | ek 1184 B; dk as 64-byte seed (d‖z) |
| D | pq-crystals/kyber Kyber768 reference | commit `3edd5af5991927164edd4aacebfcbee00b8064e7` | pk 1184 B; sk 2400 B |

D is a **lineage reference only**: it implements round-3 Kyber768
(pre-FIPS 203). Its KEM hashing differs from FIPS 203, so its shared
secrets are not comparable with A/B/C and it is excluded from the
cross-implementation agreement check. Only its *behavioral* class outcomes
are compared (implicit rejection, determinism, length handling).

## Method notes

- 25 fresh keypairs per implementation; every class applied to every pair.
- Cross-implementation agreement is checked in two legs: (leg 1) the same
  64-byte seed loaded into A (`from_seed_bytes`) and C
  (`NewDecapsulationKey768`), encapsulation by C with A's ek, decapsulation
  by both; (leg 2) a keypair generated by B, encapsulation by A with B's ek
  (`from_public_bytes`), decapsulation by B. A and C cannot export the
  expanded dk and B cannot export the seed, so the two legs are
  complementary.
- Wrong-length ciphertexts and keys are **never** passed to the fixed-size C
  APIs (B, D). The harness wrapper enforces the §7.3 length check before
  the call and records `NOT_INVOKED`. Only A and C — whose public APIs
  validate lengths — are actually invoked with wrong-length input, and their
  exceptions are recorded verbatim.
- Harness: `src/run_harness.py` (stdlib-only apart from `cryptography` and
  the `ctypes` liboqs binding; Go and Kyber drivers are small subprocess
  programs in `src/go-mlkem/main.go` and `src/kyber-ref-driver.c`).
