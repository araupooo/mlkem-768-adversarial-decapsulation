# Findings — ML-KEM-768 adversarial decapsulation

Ordered by severity. Every finding cites the measured cases in
`outputs/results.json` and the unedited log `outputs/run_harness.log`.

## F-1 — Low: liboqs 0.12.0 and the Kyber reference do not enforce the FIPS 203 §7.3 decapsulation-key hash check

**Observation.** Corrupting one byte inside the stored `H(ekPKE)` region of
the expanded decapsulation key (byte 2350 of 2400) and then decapsulating a
valid ciphertext yields a wrong 32-byte shared secret in 25/25 cases for
liboqs and 25/25 for the Kyber reference — no error is raised
(`CORRUPT-DK-H` → `IMPLICIT_REJECT` in `matrix.md`).

**Why it matters.** FIPS 203 §7.3 requires the hash check
`H(dk[1152:2336]) == dk[2336:2368]` before `ML-KEM.Decaps` runs. The
corrupted key fails that check, so a conforming caller must reject it.
liboqs's `OQS_KEM_decaps` runs the internal decapsulation directly without
the check: the corrupted `h` feeds `G(m'‖h)` (Algorithm 18, step 6), so the
caller silently establishes a *wrong* shared secret with the peer instead of
failing. The failure is silent — the output is a well-formed 32-byte secret
indistinguishable from a correct one without an independent check.

**Scope and mitigation.** §7.3 explicitly permits the key check to be
performed by means other than the decapsulating party ("checking of the
decapsulation key need not be performed by the decapsulating party, nor with
every execution of ML-KEM.Decaps"), so this is a validation gap, not a
standard violation — severity Low. Callers must perform the §7.3 hash check
themselves before handing a decapsulation key to liboqs, or verify the key
at load time. The Kyber reference predates FIPS 203 (round-3 Kyber had no
equivalent external hash check), so the §7.3 framing applies to liboqs;
the reference shows the same behavior in its own lineage.
pyca/cryptography and Go store the decapsulation key as the 64-byte seed
(d‖z), so the expanded-key hash region does not exist for them and the
probe is not applicable — their keys are self-consistent by construction.

**Evidence:** `outputs/results.json`, cases with class `CORRUPT-DK-H` for
`liboqs` and `kyber-ref` (50 cases, all `IMPLICIT_REJECT`);
`outputs/run_harness.log` lines `[liboqs] CORRUPT-DK-H …` and
`[kyber-ref] CORRUPT-DK-H …`.

## F-2 — Informational: fixed-size C APIs cannot enforce the §7.3 length checks; the caller must

**Observation.** liboqs (`OQS_KEM_decaps`) and the Kyber reference
(`crypto_kem_dec`) take fixed-size buffers and assume a 1088-byte
ciphertext and a 2400-byte decapsulation key. They cannot be invoked with a
wrong-length input at all. The harness wrapper enforces the §7.3 length
checks before every call: 400 cases recorded `NOT_INVOKED`, and zero C
calls were made with a wrong-length buffer.

**Why it matters.** A caller that skips the length check and passes a short
buffer to these APIs invokes undefined behavior (the API contract assumes
fixed sizes). The §7.3 ciphertext check — which "shall be performed with
every execution of ML-KEM.Decaps" — therefore lives entirely in the caller
for these two implementations. By contrast, pyca/cryptography and Go
enforce the checks inside the API: wrong-length ciphertexts raise
`ValueError: Invalid ML-KEM-768 ciphertext` (pyca, 175/175) and
`mlkem: invalid ciphertext length` (Go, 174/175 library errors plus one
driver-level rejection for the empty-ciphertext case); wrong-length keys are
rejected at load (`ValueError: An ML-KEM-768 seed is 64 bytes long`,
`mlkem: invalid seed length`).

**Evidence:** `outputs/results.json`, classes `WRONG-LENGTH-CT` and
`WRONG-LENGTH-DK`; `src/run_harness.py` length-guard code.

## F-3 — Positive: implicit rejection is uniformly correct across all four implementations

**Observation.** 950/950 adversarial-input cases (single-bit flips at three
positions, a zeroed 32-byte block, all-zero / all-0xFF / random
ciphertexts, wrong-key decapsulation, corrupted d-region of the key)
returned a 32-byte rejection secret different from the valid secret, with
no error and no crash — exactly FIPS 203 §6.3 Algorithm 18. The z-region
probe confirms the mechanism's structure: corrupting the last byte of the
key (the rejection value `z`) leaves valid-ciphertext decapsulation
unchanged (25/25 `MATCH` per implementation), because `z` is only consumed
on the rejection path (`J(z‖c)`, step 7).

**Evidence:** `outputs/results.json`, classes `MALFORMED-1BIT`,
`MALFORMED-MULTIBIT`, `SYNTHETIC-CT`, `WRONG-KEY`, `CORRUPT-DK-D`,
`CORRUPT-DK-Z`; `matrix.md`.

## F-4 — Positive: the three FIPS 203 implementations agree on shared secrets

**Observation.** Cross-implementation agreement holds in both legs: the
same 64-byte seed in pyca and Go yields identical shared secrets
(leg 1, `c55d3f85…`), and a liboqs-generated keypair encapsulated by pyca
and decapsulated by liboqs yields identical shared secrets (leg 2,
`bfa2c967…`). No distinguishable failure, non-rejection secret, or crash
was found in any of the 2100 cases.

**Evidence:** `outputs/results.json`, `cross_implementation`;
`outputs/run_harness.log`, `== cross-implementation check ==` section.
