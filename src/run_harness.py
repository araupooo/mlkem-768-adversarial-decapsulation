#!/usr/bin/env python3
"""ML-KEM-768 adversarial decapsulation harness.

Compares negative decapsulation behavior across four implementations:
  A. pyca/cryptography 50.0.2 (MLKEM768)          -- Python, OpenSSL-backed
  B. liboqs 0.12.0 (ML-KEM-768, built from source) -- C library via ctypes
  C. Go 1.24.6 stdlib crypto/mlkem (ML-KEM-768)    -- subprocess driver
  D. pq-crystals/kyber Kyber768 reference (round-3, pre-FIPS 203)
     -- subprocess driver; LINEAGE REFERENCE ONLY, not an ML-KEM
     implementation; behavioral comparison only (its KEM hashing differs
     from FIPS 203, so cross-implementation secret agreement is NOT
     expected for D).

Expected behavior (FIPS 203, NIST.FIPS.203, Aug 2024):
  * 6.3 Algorithm 18 (ML-KEM.Decaps_internal): on ciphertext mismatch the
    algorithm performs IMPLICIT REJECTION -- K' <- J(z||c), a 32-byte
    shared secret, no error, no flag returned.
  * 7.3 (ML-KEM.Decaps): ciphertext MUST be exactly 32*(du*k+dv) bytes
    (ML-KEM-768: 1088); dk MUST be exactly 768*k+96 bytes (2400); the dk
    hash check H(dk[384k:768k+32]) == dk[768k+32:768k+64] must pass.
    Ciphertext checking SHALL be performed with every execution.
  * Table 3: ML-KEM-768 ek 1184 B, dk 2400 B, ct 1088 B, ss 32 B.

Safety: wrong-length ciphertexts/keys are NEVER passed to a fixed-size C
API (liboqs, kyber-ref). Those cases are recorded as NOT_INVOKED with the
wrapper's length-guard reason. Only implementations whose public API
validates lengths (pyca, Go) are actually invoked with wrong-length input,
and their exception is recorded verbatim.

Every run is logged to stdout (redirected to outputs/run_harness.log) and
summarized in outputs/results.json / outputs/results.txt.
"""
import ctypes
import hashlib
import json
import os
import random
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)  # task-6cd9a321/
OUT = os.path.join(ROOT, "outputs")
VENV_PY = "/tmp/mlkem-prep-venv/bin/python"

EK_LEN, DK_LEN, CT_LEN, SS_LEN = 1184, 2400, 1088, 32
N_PAIRS = 25
# Fixed 64-byte seed (d||z) for the cross-implementation keypair, hex-encoded.
FIXED_SEED_HEX = (
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
)

rng = random.Random(20261107)
results = {"generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "standard": "FIPS 203 (NIST.FIPS.203, Aug 2024), ML-KEM-768",
           "implementations": {}, "cases": [], "cross_implementation": {}}


def log(*a):
    print(*a, flush=True)


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def rec(impl, cls, detail, outcome, ss=None, note=""):
    results["cases"].append({
        "implementation": impl, "class": cls, "detail": detail,
        "outcome": outcome,
        "ss_len": None if ss is None else len(ss),
        "ss_sha256": None if ss is None else sha256(ss),
        "note": note})
    log(f"[{impl}] {cls} {detail} -> {outcome}" + (f" | {note}" if note else ""))


# ---------------------------------------------------------------- pyca (A)
log("== implementation A: pyca/cryptography ==")
from cryptography import __version__ as CRYPTO_VER
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey, MLKEM768PublicKey)

results["implementations"]["pyca-cryptography"] = {
    "version": CRYPTO_VER, "module": "cryptography.hazmat.primitives.asymmetric.mlkem",
    "key_encoding": "ek 1184 B (public_bytes_raw); dk stored as the 64-byte "
                    "seed (d||z) -- private_bytes_raw() returns the seed, NOT "
                    "the 2400-byte expanded dk; no public API exports the "
                    "expanded dk",
    "standard": "FIPS 203 ML-KEM-768"}
log("pyca cryptography version:", CRYPTO_VER)


def pyca_keypair():
    sk = MLKEM768PrivateKey.generate()
    return sk, sk.public_key()


def pyca_encap(pk):
    return pk.encapsulate()  # returns (ss, ct)


def pyca_decap(sk, ct):
    return sk.decapsulate(ct)


# ---------------------------------------------------------------- liboqs (B)
log("== implementation B: liboqs ==")
LIBOQS_SO = os.path.join(ROOT, "src", "liboqs", "build", "lib", "liboqs.so")
lib = ctypes.CDLL(LIBOQS_SO)
lib.OQS_version.restype = ctypes.c_char_p
lib.OQS_KEM_new.argtypes = [ctypes.c_char_p]
lib.OQS_KEM_new.restype = ctypes.c_void_p
lib.OQS_KEM_free.argtypes = [ctypes.c_void_p]
lib.OQS_KEM_keypair.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
lib.OQS_KEM_encaps.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.OQS_KEM_decaps.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
for f in (lib.OQS_KEM_keypair, lib.OQS_KEM_encaps, lib.OQS_KEM_decaps):
    f.restype = ctypes.c_int
OQS_SUCCESS = 0
kem = lib.OQS_KEM_new(b"ML-KEM-768")
assert kem, "OQS_KEM_new(ML-KEM-768) failed"
liboqs_ver = lib.OQS_version().decode()
results["implementations"]["liboqs"] = {
    "version": liboqs_ver, "source": "open-quantum-safe/liboqs 0.12.0, built from source",
    "key_encoding": "ek 1184 B, sk 2400 B expanded (OQS_KEM API)",
    "standard": "FIPS 203 ML-KEM-768"}
log("liboqs version:", liboqs_ver)


def oqs_keypair():
    pk = ctypes.create_string_buffer(EK_LEN)
    sk = ctypes.create_string_buffer(DK_LEN)
    assert lib.OQS_KEM_keypair(kem, pk, sk) == OQS_SUCCESS
    return sk.raw, pk.raw  # (sk, pk)


def oqs_encap(pk_bytes):
    pk = ctypes.create_string_buffer(pk_bytes, EK_LEN + 1)  # +1: NUL terminator
    ct = ctypes.create_string_buffer(CT_LEN)
    ss = ctypes.create_string_buffer(SS_LEN)
    assert lib.OQS_KEM_encaps(kem, ct, ss, pk) == OQS_SUCCESS
    return ct.raw, ss.raw


def oqs_decap(sk_bytes, ct_bytes):
    # Length guard: the OQS C API assumes fixed-size buffers; never invoke
    # it with a wrong-length ciphertext (undefined caller behavior).
    if len(ct_bytes) != CT_LEN or len(sk_bytes) != DK_LEN:
        return None  # caller records NOT_INVOKED
    sk = ctypes.create_string_buffer(sk_bytes, DK_LEN + 1)  # +1: NUL terminator
    ct = ctypes.create_string_buffer(ct_bytes, CT_LEN + 1)
    ss = ctypes.create_string_buffer(SS_LEN)
    rc = lib.OQS_KEM_decaps(kem, ss, ct, sk)
    if rc != OQS_SUCCESS:
        raise RuntimeError(f"OQS_KEM_decaps returned {rc}")
    return ss.raw


# ---------------------------------------------------------------- Go driver (C)
log("== implementation C: Go stdlib crypto/mlkem ==")
GO_BIN = os.path.join(ROOT, "src", "go-mlkem", "gomlkem")
go = subprocess.Popen([GO_BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                      text=True, bufsize=1)
go_ready = go.stdout.readline().strip()
log("go driver:", go_ready)
results["implementations"]["go-stdlib-crypto-mlkem"] = {
    "version": "go1.24.6 stdlib crypto/mlkem",
    "key_encoding": "ek 1184 B; dk 64-byte seed (d||z) -- Go exposes the seed "
                    "form, not the 2400-byte expanded dk",
    "standard": "FIPS 203 ML-KEM-768"}


def go_cmd(line):
    go.stdin.write(line + "\n")
    go.stdin.flush()
    return go.stdout.readline().strip()


def go_keypair():
    out = go_cmd("keygen")
    parts = out.split()
    assert parts[0] == "PK", out
    return bytes.fromhex(parts[3]), bytes.fromhex(parts[1])  # (dk seed, ek)


def go_encap(ek):
    out = go_cmd("encap " + ek.hex())
    parts = out.split()
    assert parts[0] == "CT", out
    return bytes.fromhex(parts[3]), bytes.fromhex(parts[1])  # (ss, ct)


def go_decap(dk_seed, ct):
    out = go_cmd("decap " + dk_seed.hex() + " " + ct.hex())
    parts = out.split()
    if parts[0] == "SS":
        return bytes.fromhex(parts[1])
    raise RuntimeError(" ".join(parts))


# ---------------------------------------------------------------- kyber-ref (D)
log("== implementation D: pq-crystals/kyber Kyber768 reference ==")
KYBER_BIN = os.path.join(ROOT, "src", "kyber768-driver")
ky = subprocess.Popen([KYBER_BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                      text=True, bufsize=1)
ky_ready = ky.stdout.readline().strip()
log("kyber driver:", ky_ready)
results["implementations"]["kyber-ref"] = {
    "version": "pq-crystals/kyber (round-3 reference C code)",
    "key_encoding": "pk 1184 B, sk 2400 B",
    "standard": "Kyber768 round-3 (pre-FIPS 203) -- LINEAGE REFERENCE ONLY; "
                "its KEM hashing differs from FIPS 203, so cross-implementation "
                "secret agreement with A/B/C is NOT expected; behavioral "
                "comparison only"}


def ky_cmd(line):
    ky.stdin.write(line + "\n")
    ky.stdin.flush()
    return ky.stdout.readline().strip()


def ky_keypair():
    out = ky_cmd("keygen")
    parts = out.split()
    assert parts[0] == "PK", out
    return bytes.fromhex(parts[3]), bytes.fromhex(parts[1])  # (sk, pk)


def ky_encap(pk):
    out = ky_cmd("enc " + pk.hex())
    parts = out.split()
    assert parts[0] == "CT", out
    return bytes.fromhex(parts[3]), bytes.fromhex(parts[1])  # (ss, ct)


def ky_decap(sk, ct):
    if len(ct) != CT_LEN or len(sk) != DK_LEN:
        return None  # length guard, same as liboqs
    out = ky_cmd("dec " + sk.hex() + " " + ct.hex())
    parts = out.split()
    if parts[0] == "SS":
        return bytes.fromhex(parts[1])
    raise RuntimeError(" ".join(parts))


def flip(b: bytes, positions) -> bytes:
    c = bytearray(b)
    for p in positions:
        c[p % len(c)] ^= 0x01
    return bytes(c)


def zero_block(b: bytes, start, n) -> bytes:
    c = bytearray(b)
    for i in range(start, min(start + n, len(c))):
        c[i] = 0
    return bytes(c)


# ================================================================ cross-impl
log("== cross-implementation check ==")
seed = bytes.fromhex(FIXED_SEED_HEX)
py_sk = MLKEM768PrivateKey.from_seed_bytes(seed)
py_pk = py_sk.public_key()
py_ek_raw = py_pk.public_bytes_raw()
# Leg 1 -- pyca <-> Go via the shared 64-byte seed (d||z). Go loads the same
# seed with NewDecapsulationKey768; pyca loads it with from_seed_bytes.
# Encapsulation is done by Go with pyca's ek; both sides decapsulate.
go_ss, go_ct = go_encap(py_ek_raw)
py_ss = pyca_decap(py_sk, go_ct)
go_ss2 = go_decap(seed, go_ct)
leg1 = {"seed_hex": FIXED_SEED_HEX,
        "pyca_ek_sha256": sha256(py_ek_raw),
        "go_encap_ct_sha256": sha256(go_ct),
        "go_encap_ss_sha256": sha256(go_ss),
        "pyca_decap_ss_sha256": sha256(py_ss),
        "go_decap_ss_sha256": sha256(go_ss2),
        "agree": (go_ss == py_ss == go_ss2),
        "note": "Same 64-byte seed in pyca (from_seed_bytes) and Go "
                "(NewDecapsulationKey768). Encapsulation by Go with pyca's ek."}
log("leg1 pyca<->Go: go_ss==pyca_ss:", go_ss == py_ss,
    "| go_ss==go_decap_ss:", go_ss == go_ss2)
# Leg 2 -- liboqs <-> pyca via a liboqs-generated keypair. pyca cannot export
# the 2400-byte expanded dk (it stores the 64-byte seed), and liboqs cannot
# export the seed (d is not stored in the expanded dk), so the two legs are
# complementary: leg 1 ties pyca to Go, leg 2 ties liboqs to pyca.
oqs_sk, oqs_pk = oqs_keypair()
py_pk2 = MLKEM768PublicKey.from_public_bytes(oqs_pk)
py_ss2, py_ct2 = pyca_encap(py_pk2)
oqs_ss2 = oqs_decap(oqs_sk, py_ct2)
leg2 = {"liboqs_ek_sha256": sha256(oqs_pk),
        "pyca_encap_ct_sha256": sha256(py_ct2),
        "pyca_encap_ss_sha256": sha256(py_ss2),
        "liboqs_decap_ss_sha256": sha256(oqs_ss2) if oqs_ss2 else None,
        "agree": (py_ss2 == oqs_ss2),
        "note": "Keypair generated by liboqs; encapsulation by pyca with "
                "liboqs's ek (from_public_bytes); decapsulation by liboqs "
                "with its expanded sk. Go cannot join this leg: it needs "
                "the 64-byte seed, which liboqs does not expose."}
log("leg2 liboqs<->pyca: pyca_ss==liboqs_ss:", py_ss2 == oqs_ss2)
cross = {"leg1_pyca_go": leg1, "leg2_liboqs_pyca": leg2,
         "all_three_agree_by_transitivity": bool(leg1["agree"] and leg2["agree"]),
         "note": "kyber-ref is excluded: its KEM hashing differs from FIPS "
                 "203, so secret agreement with A/B/C is not expected."}
results["cross_implementation"] = cross
log("CROSS-IMPL all three agree (by transitivity):",
    cross["all_three_agree_by_transitivity"])

# ================================================================ matrix
log("== adversarial matrix ==")


def run_matrix(name, keypair_fn, encap_fn, decap_fn, dk_kind, corrupt_fn, bad_dk_fn):
    """dk_kind: 'expanded' (2400 B dk) or 'seed' (64 B dk)."""
    for i in range(N_PAIRS):
        sk, pk = keypair_fn()
        ss, ct = encap_fn(pk)
        tag = f"pair#{i+1}"
        # 1. control
        try:
            d = decap_fn(sk, ct)
            rec(name, "VALID", tag, "MATCH" if d == ss else "MISMATCH",
                d, "control: valid ct must decapsulate to the encaps ss")
        except Exception as e:
            rec(name, "VALID", tag, f"ERROR:{type(e).__name__}", None, str(e))
        # 2. single-bit flips
        for pos, lbl in ((0, "ct[0]"), (543, "ct[543]"), (CT_LEN - 1, "ct[1087]")):
            bad = flip(ct, [pos])
            try:
                d = decap_fn(sk, bad)
                rec(name, "MALFORMED-1BIT", f"{tag} flip {lbl}",
                    "IMPLICIT_REJECT" if (d is not None and d != ss and len(d) == SS_LEN)
                    else ("MATCH-UNEXPECTED" if d == ss else "OTHER"),
                    d, "FIPS 203 6.3: mismatch -> K'=J(z||c), 32-byte ss, no error")
            except Exception as e:
                rec(name, "MALFORMED-1BIT", f"{tag} flip {lbl}",
                    f"ERROR:{type(e).__name__}", None, str(e))
        # 3. multi-bit: zero a 32-byte block
        bad = zero_block(ct, 100, 32)
        try:
            d = decap_fn(sk, bad)
            rec(name, "MALFORMED-MULTIBIT", f"{tag} zero ct[100:132]",
                "IMPLICIT_REJECT" if (d is not None and d != ss and len(d) == SS_LEN)
                else ("MATCH-UNEXPECTED" if d == ss else "OTHER"),
                d, "FIPS 203 6.3: mismatch -> implicit rejection ss")
        except Exception as e:
            rec(name, "MALFORMED-MULTIBIT", f"{tag} zero ct[100:132]",
                f"ERROR:{type(e).__name__}", None, str(e))
        # 4. all-zero / all-ones / random ct
        for bad, lbl in ((bytes(CT_LEN), "all-zero"),
                         (bytes([0xFF]) * CT_LEN, "all-0xFF"),
                         (bytes(rng.randrange(256) for _ in range(CT_LEN)), "random")):
            try:
                d = decap_fn(sk, bad)
                rec(name, "SYNTHETIC-CT", f"{tag} {lbl}",
                    "IMPLICIT_REJECT" if (d is not None and d != ss and len(d) == SS_LEN)
                    else ("MATCH-UNEXPECTED" if d == ss else "OTHER"),
                    d, "synthetic ct must not yield the valid ss")
            except Exception as e:
                rec(name, "SYNTHETIC-CT", f"{tag} {lbl}",
                    f"ERROR:{type(e).__name__}", None, str(e))
        # 5. wrong key
        sk2, _ = keypair_fn()
        try:
            d = decap_fn(sk2, ct)
            rec(name, "WRONG-KEY", tag,
                "IMPLICIT_REJECT" if (d is not None and d != ss and len(d) == SS_LEN)
                else ("MATCH-UNEXPECTED" if d == ss else "OTHER"),
                d, "FIPS 203 6.3: wrong key -> re-encryption mismatch -> rejection ss")
        except Exception as e:
            rec(name, "WRONG-KEY", tag, f"ERROR:{type(e).__name__}", None, str(e))
        # 6. corrupted dk (one bit, by region).
        #    "d": first byte -- d-region (seed form) / dkPKE region (expanded).
        #         Expect IMPLICIT_REJECT (different key -> re-encryption mismatch).
        #    "z": last byte -- implicit-rejection value z. z is only used on the
        #         rejection path (Alg 18 step 7), so a valid ct must still MATCH.
        #    "h": byte 2350 -- inside H(ekPKE) in the expanded dk (Alg 18 step 6
        #         feeds h into G(m'||h)). Expect ERROR if the implementation
        #         enforces the FIPS 203 7.3 dk hash check, else IMPLICIT_REJECT.
        for kind, expect in (("d", "IMPLICIT_REJECT"), ("z", "MATCH"),
                             ("h", "ERROR-or-IMPLICIT_REJECT")):
            bad_sk = corrupt_fn(sk, kind)
            if bad_sk is None:
                rec(name, "CORRUPT-DK-" + kind.upper(), tag, "NOT_APPLICABLE",
                    None, "this key encoding has no stored h region (seed form)")
                continue
            try:
                d = decap_fn(bad_sk, ct)
                got = ("IMPLICIT_REJECT" if (d is not None and d != ss and len(d) == SS_LEN)
                       else ("MATCH" if d == ss else "OTHER"))
                rec(name, "CORRUPT-DK-" + kind.upper(), tag, got, d,
                    f"expected {expect}")
            except Exception as e:
                rec(name, "CORRUPT-DK-" + kind.upper(), tag,
                    f"ERROR:{type(e).__name__}", None,
                    f"expected {expect}; {e}")
        # 7. replay / determinism: decap same ct 3x
        try:
            ds = [decap_fn(sk, ct) for _ in range(3)]
            rec(name, "REPLAY-DETERMINISM", tag,
                "MATCH" if all(d == ss for d in ds) else "NONDETERMINISTIC",
                ds[0] if ds and ds[0] is not None else None,
                "decaps is deterministic (FIPS 203 6.3: no randomness); "
                "replay of a valid ct must return the same ss every time")
        except Exception as e:
            rec(name, "REPLAY-DETERMINISM", tag, f"ERROR:{type(e).__name__}", None, str(e))
        # 8. wrong-length ct (truncated / oversized)
        for bad_len, lbl in ((CT_LEN - 1, "1087B"), (544, "544B"), (32, "32B"),
                             (1, "1B"), (0, "0B"), (CT_LEN + 1, "1089B"),
                             (CT_LEN * 2, "2176B")):
            bad = ct[:bad_len] if bad_len <= CT_LEN else ct + bytes(bad_len - CT_LEN)
            if dk_kind in ("expanded", "seed") and name in ("liboqs", "kyber-ref"):
                # Fixed-size C API: never invoke with wrong length.
                rec(name, "WRONG-LENGTH-CT", f"{tag} {lbl}", "NOT_INVOKED",
                    None, "harness length guard: fixed-size C API assumes "
                          f"{CT_LEN} B ct; FIPS 203 7.3 input check enforced by "
                          "the wrapper before the call (no C call made)")
                continue
            try:
                d = decap_fn(sk, bad)
                rec(name, "WRONG-LENGTH-CT", f"{tag} {lbl}",
                    "IMPLICIT_REJECT" if (d is not None and d != ss and len(d) == SS_LEN)
                    else ("MATCH-UNEXPECTED" if d == ss else "OTHER"),
                    d, "FIPS 203 7.3: ct length check SHALL fail -> error "
                       "expected; a 32-byte ss here means the check was skipped")
            except Exception as e:
                rec(name, "WRONG-LENGTH-CT", f"{tag} {lbl}",
                    f"ERROR:{type(e).__name__}", None, str(e))
        # 9. wrong-length dk. Construction of the bad key may itself fail
        #    (pyca rejects a 63-byte seed at load); that is recorded as the
        #    outcome. Fixed-size C APIs are never invoked (NOT_INVOKED).
        try:
            lbl, bad_dk = bad_dk_fn(sk)
        except Exception as e:
            rec(name, "WRONG-LENGTH-DK", tag, f"ERROR:{type(e).__name__}",
                None, f"rejected at key load: {e}")
            continue
        if bad_dk is None:
            rec(name, "WRONG-LENGTH-DK", f"{tag} {lbl}", "NOT_INVOKED",
                None, "harness length guard: fixed-size C API assumes "
                      f"{DK_LEN} B dk; FIPS 203 7.3 input check enforced by "
                      "the wrapper before the call (no C call made)")
            continue
        try:
            d = decap_fn(bad_dk, ct)
            rec(name, "WRONG-LENGTH-DK", f"{tag} {lbl}",
                "OTHER" if d is None else
                ("IMPLICIT_REJECT" if d != ss else "MATCH-UNEXPECTED"),
                d, "FIPS 203 7.3: dk length check SHOULD fail -> error expected")
        except Exception as e:
            rec(name, "WRONG-LENGTH-DK", f"{tag} {lbl}",
                f"ERROR:{type(e).__name__}", None, str(e))


def pyca_corrupt(sk, kind):
    seed = sk.private_bytes_raw()
    if kind == "d":
        return MLKEM768PrivateKey.from_seed_bytes(flip(seed, [0]))
    if kind == "z":
        return MLKEM768PrivateKey.from_seed_bytes(flip(seed, [63]))
    return None  # "h": seed form has no stored H(ekPKE) region


def pyca_bad_dk(sk):
    # 63-byte seed: rejected at load by from_seed_bytes (ValueError).
    return "63B seed", MLKEM768PrivateKey.from_seed_bytes(sk.private_bytes_raw()[:-1])


def bytes_corrupt(sk_bytes, kind):
    if kind == "d":
        return flip(sk_bytes, [0])
    if kind == "z":
        return flip(sk_bytes, [len(sk_bytes) - 1])
    if kind == "h":
        return flip(sk_bytes, [2350])  # inside H(ekPKE) region of expanded dk
    return None


def bytes_bad_dk(sk_bytes):
    return "2399B", None  # never invoked: fixed-size C API guard


def go_bad_dk(seed):
    return "63B seed", seed[:-1]  # Go driver rejects at NewDecapsulationKey768


run_matrix("pyca-cryptography", pyca_keypair, pyca_encap, pyca_decap, "expanded",
           pyca_corrupt, pyca_bad_dk)
run_matrix("liboqs", oqs_keypair,
           lambda pk: (lambda c, s: (s, c))(*oqs_encap(pk)), oqs_decap, "expanded",
           bytes_corrupt, bytes_bad_dk)
run_matrix("go-stdlib-crypto-mlkem", go_keypair, go_encap, go_decap, "seed",
           lambda sk, kind: flip(sk, [0]) if kind == "d" else
           (flip(sk, [63]) if kind == "z" else None), go_bad_dk)
run_matrix("kyber-ref", ky_keypair, ky_encap, ky_decap, "expanded",
           bytes_corrupt, bytes_bad_dk)

# cleanup
lib.OQS_KEM_free(ctypes.c_void_p(kem))
go.stdin.close(); go.wait()
ky.stdin.close(); ky.wait()

# ---------------------------------------------------------------- summary
by_impl_cls = {}
for c in results["cases"]:
    key = (c["implementation"], c["class"], c["outcome"].split(":")[0])
    by_impl_cls[key] = by_impl_cls.get(key, 0) + 1
results["summary_counts"] = {f"{k[0]}|{k[1]}|{k[2]}": v for k, v in sorted(by_impl_cls.items())}
results["total_cases"] = len(results["cases"])

with open(os.path.join(OUT, "results.json"), "w") as f:
    json.dump(results, f, indent=2)
with open(os.path.join(OUT, "results.txt"), "w") as f:
    f.write("ML-KEM-768 adversarial decapsulation -- summary\n")
    f.write(f"generated_utc: {results['generated_utc']}\n")
    f.write(f"total_cases: {results['total_cases']}\n")
    f.write(f"cross_implementation all_three_agree_by_transitivity: {cross['all_three_agree_by_transitivity']}\n\n")
    for k, v in sorted(results["summary_counts"].items()):
        f.write(f"{v:5d}  {k}\n")
log("TOTAL CASES:", results["total_cases"])
log("CROSS-IMPL ALL THREE AGREE (by transitivity):", cross["all_three_agree_by_transitivity"])
log("DONE")
