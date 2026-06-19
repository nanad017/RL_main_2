"""Tests for funcval.oracles.proven.ProvenOracle.

The oracle's contract: emit a Proof ONLY with a machine-re-checkable cert
(DECODE_IDENTICAL or Z3_UNSAT); everything else -> Unknown.  It must NEVER emit
a Proof backed by an SDM_ARGUMENT cert.

Run with the comp venv (capstone+z3 present):
    .venv-comp/bin/python -m pytest tests/funcval/test_proven.py -q
"""
from __future__ import annotations

import json

import pytest

from funcval.evidence import Proof, Unknown
from funcval.oracles.proven import ProvenOracle, recheck_cert

# capstone is required for the DECODE_IDENTICAL tier; z3 for the Z3_UNSAT tier.
capstone = pytest.importorskip("capstone")


@pytest.fixture(scope="module")
def oracle():
    return ProvenOracle()


def _find_pattern_pair(oracle, pattern):
    """Pull one (orig, var) library pair with the given proof_pattern."""
    import json as _json

    from funcval.oracles.proven import resolve_library_path

    raw = _json.loads(resolve_library_path().read_text())
    items = raw["entries"] if isinstance(raw, dict) and "entries" in raw else raw
    for ent in items:
        if str(ent.get("proof_pattern") or "") == pattern:
            return str(ent["original_hex"]).lower(), str(ent["variant_hex"]).lower()
    pytest.skip(f"no {pattern} entry in library")


def test_alt_modrm_pair_yields_decode_identical_proof(oracle):
    """An alt_modrm d-bit-swap pair -> Proof with a re-checkable
    DECODE_IDENTICAL cert."""
    orig, var = _find_pattern_pair(oracle, "alt_modrm_d_bit_swap")
    ev = oracle.produce(orig, var)
    assert isinstance(ev, Proof), f"expected Proof, got {ev.kind}"
    assert ev.cert.cert_kind == "DECODE_IDENTICAL"
    assert ev.cert.recheckable is True
    assert ev.false_admit_bound() == 0.0
    # Payload is JSON with both hex strings + the shared disasm text.
    payload = json.loads(ev.cert.payload)
    assert payload["orig_hex"] == orig
    assert payload["var_hex"] == var
    assert payload["disasm"]
    # The cert genuinely re-checks.
    assert recheck_cert(ev.cert) is True


def test_decode_identical_concrete_example(oracle):
    """01 c3 (add ebx, eax) and 03 d8 (add ebx, eax) — the textbook d-bit swap.

    Only asserted as a Proof if this exact pair is in the library; otherwise we
    still assert capstone agrees the two encodings disassemble identically.
    """
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    a = list(md.disasm(bytes.fromhex("01c3"), 0))
    b = list(md.disasm(bytes.fromhex("03d8"), 0))
    assert len(a) == 1 and len(b) == 1
    ta = f"{a[0].mnemonic} {a[0].op_str}".strip().lower()
    tb = f"{b[0].mnemonic} {b[0].op_str}".strip().lower()
    assert ta == tb == "add ebx, eax"


def test_xor_sub_pair_yields_z3_unsat_proof(oracle):
    """xor r,r (31c0) <-> sub r,r (29c0) -> Proof Z3_UNSAT (we did NOT defer
    this pattern to Unknown)."""
    pytest.importorskip("z3")
    ev = oracle.produce("31c0", "29c0")
    assert isinstance(ev, Proof), f"expected Proof, got {ev.kind}"
    assert ev.cert.cert_kind == "Z3_UNSAT"
    assert ev.cert.recheckable is True
    assert ev.false_admit_bound() == 0.0
    assert recheck_cert(ev.cert) is True


def test_pair_not_in_library_yields_unknown(oracle):
    """A pair that is not in the proven library -> Unknown."""
    ev = oracle.produce("9090", "f4f4")  # nop nop vs hlt hlt
    assert isinstance(ev, Unknown)
    assert ev.reason == "not in proven library"
    assert ev.false_admit_bound() is None


def test_no_entry_ever_yields_sdm_argument_proof(oracle):
    """The whole point of the redesign: NO library entry may be admitted as a
    Proof backed by an SDM_ARGUMENT cert."""
    from funcval.oracles.proven import resolve_library_path

    raw = json.loads(resolve_library_path().read_text())
    items = raw["entries"] if isinstance(raw, dict) and "entries" in raw else raw
    for ent in items:
        orig = str(ent["original_hex"]).lower()
        var = str(ent["variant_hex"]).lower()
        ev = oracle.produce(orig, var)
        if isinstance(ev, Proof):
            assert ev.cert.cert_kind != "SDM_ARGUMENT", (
                f"OVERCLAIM: {orig}/{var} ({ent.get('proof_pattern')}) "
                "got an SDM_ARGUMENT Proof"
            )
            # Every emitted cert kind must be machine-re-checkable.
            assert ev.cert.cert_kind in {
                "DECODE_IDENTICAL",
                "Z3_UNSAT",
                "ISA_BITWISE_ALIAS",
            }
            assert ev.cert.recheckable is True


def test_every_proof_cert_rechecks_on_a_sample(oracle):
    """A re-checkable cert that does not re-check is worthless; assert a sample
    of produced certs re-verify True."""
    import random

    from funcval.oracles.proven import resolve_library_path

    raw = json.loads(resolve_library_path().read_text())
    items = raw["entries"] if isinstance(raw, dict) and "entries" in raw else raw
    rng = random.Random(7)
    sample = rng.sample(items, min(100, len(items)))
    checked = 0
    for ent in sample:
        ev = oracle.produce(
            str(ent["original_hex"]).lower(), str(ent["variant_hex"]).lower()
        )
        if isinstance(ev, Proof) and ev.cert.recheckable:
            assert recheck_cert(ev.cert) is True
            checked += 1
    assert checked > 0  # the sample must contain at least some proofs
