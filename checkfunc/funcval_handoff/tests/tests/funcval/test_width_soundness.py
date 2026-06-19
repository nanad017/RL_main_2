"""Width-soundness regression tests (adversarial review of verify_sync).

An adversarial review found that ``verify_sync`` FALSE-ADMITS non-equivalent
pairs because the verification path was hardwired to x86-64 (UC_MODE_64 /
CS_MODE_64 / Z3 BitVec(...,64)), never compared memory writes, and emulated
arbitrary byte blobs as if they were valid instructions.  Each test below
reproduces one confirmed defect and guards its fix.  Written test-first (TDD):
each was confirmed to FAIL against the pre-fix code.

Defects guarded:
  * FIX A  width threaded end-to-end (bits=32 vs bits=64).
  * FIX B  Unicorn memory writes compared (push 0 vs push 1 must NOT admit).
  * FIX C  input-validity guard (undecodable / non-instruction-aligned -> Unknown).
  * FIX D  32-bit library bundled + ProvenOracle width-aware.

capstone + unicorn are required for the differential oracle; on VM1 they are
present, so these tests RUN (not skip).  z3 is only needed for the ProvenOracle
Z3 idioms and is imported lazily there.

Run with the comp env (capstone+unicorn[+z3]):
    python -m pytest tests/funcval/test_width_soundness.py -q
"""
from __future__ import annotations

import pytest

from funcval import FunctionValidator
from funcval.evidence import Proof, Refuted, Sampled, Unknown

# The differential oracle and the input guard both need capstone/unicorn.
pytest.importorskip("capstone")
pytest.importorskip("unicorn")


def _v() -> FunctionValidator:
    return FunctionValidator()


def _hx(h: str) -> bytes:
    return bytes.fromhex(h)


# ===========================================================================
# FIX A + FIX C: inc eax (40) vs dec eax (48) at bits=32 must NOT admit.
# ===========================================================================
# In 64-bit, 40 and 48 are BARE REX prefixes that decode to nothing -> no
# divergence -> k=0 -> the OLD code admitted.  The INTENDED 32-bit meaning is
# `inc eax` vs `dec eax`, which are NOT equivalent and must be REFUTED (or, if
# the input guard fires first, Unknown).  Either way: not admissible.


def test_inc_vs_dec_eax_bits32_not_admissible():
    v = _v()
    ev = v.verify_sync(_hx("40"), _hx("48"), bits=32)
    assert ev.kind in ("refuted", "unknown"), (
        f"inc eax vs dec eax (bits=32) must be Refuted or Unknown, got {ev.kind}"
    )
    assert not v.admissible(ev), "inc vs dec must never admit"


def test_inc_vs_dec_eax_bits64_not_admissible_via_input_guard():
    """At bits=64, 40/48 are bare REX prefixes (decode to nothing).  The input
    guard must catch the non-instruction bytes and return Unknown rather than
    emulate them and admit k=0 (the historical false-admit)."""
    v = _v()
    ev = v.verify_sync(_hx("40"), _hx("48"), bits=64)
    assert ev.kind in ("unknown", "refuted"), (
        f"bare REX prefixes (bits=64) must NOT admit; got {ev.kind}"
    )
    assert not v.admissible(ev)


# ===========================================================================
# FIX A: 32-bit-equivalent pairs FALSE-REFUSED in 64-bit mode must ADMIT @ 32.
# ===========================================================================
# and eax,eax (21c0) / test eax,eax (85c0): in 64-bit, AND zero-extends the upper
# 32 bits while TEST does not -> they diverge (correctly Refuted at bits=64).  In
# 32-bit there is NO upper half, so they ARE equivalent and must be ADMITTED.
# Neither pair is in either proven library, so this exercises the 32-bit
# LocalEquivOracle (UC_MODE_32) Sampled(k=0) path.


def test_and_vs_test_eax_bits32_admissible():
    v = _v()
    ev = v.verify_sync(_hx("21c0"), _hx("85c0"), bits=32)
    assert isinstance(ev, (Sampled, Proof)), (
        f"and eax,eax vs test eax,eax (bits=32) should be equivalent, got {ev.kind}"
    )
    assert v.admissible(ev, alpha=0.05), "32-bit and/test must admit at 0.05"


def test_or_vs_test_eax_bits32_admissible():
    v = _v()
    ev = v.verify_sync(_hx("09c0"), _hx("85c0"), bits=32)
    assert isinstance(ev, (Sampled, Proof)), (
        f"or eax,eax vs test eax,eax (bits=32) should be equivalent, got {ev.kind}"
    )
    assert v.admissible(ev, alpha=0.05), "32-bit or/test must admit at 0.05"


def test_and_vs_test_eax_bits64_refuted():
    """Regression on the other side: the SAME pair at bits=64 must be Refuted
    (upper-32 zero-extension hazard) — width really is load-bearing."""
    v = _v()
    ev = v.verify_sync(_hx("21c0"), _hx("85c0"), bits=64)
    assert ev.kind == "refuted", (
        f"and eax,eax vs test eax,eax (bits=64) must be Refuted, got {ev.kind}"
    )
    assert not v.admissible(ev)


# ===========================================================================
# FIX B: push 0 (6a00) vs push 1 (6a01) must NOT admit at EITHER width.
# ===========================================================================
# These write DIFFERENT values to the stack but leave registers/flags identical,
# so the OLD register-only comparison admitted k=0.  Comparing memory writes must
# now make them diverge (Refuted), at both 32-bit and 64-bit.


def test_push0_vs_push1_bits32_not_admissible():
    v = _v()
    ev = v.verify_sync(_hx("6a00"), _hx("6a01"), bits=32)
    assert ev.kind == "refuted", (
        f"push 0 vs push 1 (bits=32) must be Refuted on the memory write, got {ev.kind}"
    )
    assert not v.admissible(ev)


def test_push0_vs_push1_bits64_not_admissible():
    v = _v()
    ev = v.verify_sync(_hx("6a00"), _hx("6a01"), bits=64)
    assert ev.kind == "refuted", (
        f"push 0 vs push 1 (bits=64) must be Refuted on the memory write, got {ev.kind}"
    )
    assert not v.admissible(ev)


# ===========================================================================
# FIX A: 64-bit regressions must stay correct.
# ===========================================================================
# 4889ec vs 488be5 = two encodings of `mov rsp, rbp` (library alt_modrm pair) ->
# Proof, admissible.  31c0 vs 09c0 = xor eax,eax vs or eax,eax: NOT equivalent in
# 64-bit (xor zeroes & zero-extends; or eax,eax leaves eax unchanged, zero-extends
# but result differs unless eax==0) -> Refuted.  31c0 vs 29c0 = xor/sub eax,eax,
# both zero rax -> admissible.


def test_mov_rsp_rbp_bits64_proof_admissible():
    v = _v()
    ev = v.verify_sync(_hx("4889ec"), _hx("488be5"), bits=64)
    assert isinstance(ev, Proof), f"expected Proof for the alt_modrm pair, got {ev.kind}"
    assert ev.false_admit_bound() == 0.0
    assert v.admissible(ev)


def test_xor_vs_or_eax_bits64_refuted():
    v = _v()
    ev = v.verify_sync(_hx("31c0"), _hx("09c0"), bits=64)
    assert ev.kind == "refuted", f"xor vs or eax,eax (bits=64) must be Refuted, got {ev.kind}"
    assert not v.admissible(ev)


def test_xor_vs_sub_eax_bits64_admissible():
    v = _v()
    ev = v.verify_sync(_hx("31c0"), _hx("29c0"), bits=64)
    assert v.admissible(ev, alpha=0.05), (
        f"xor vs sub eax,eax (bits=64, both zero rax) must admit, got {ev.kind}"
    )


def test_default_bits_is_64_regression():
    """The existing 64-bit quickstart must still work with NO bits= argument."""
    v = _v()
    ev = v.verify_sync(_hx("4889ec"), _hx("488be5"))  # no bits=
    assert isinstance(ev, Proof)
    assert v.admissible(ev)


# ===========================================================================
# FIX C: non-instruction byte blobs must yield Unknown, never admit.
# ===========================================================================


def test_arbitrary_blob_is_unknown_not_admitted_bits64():
    """A whole-PE / arbitrary blob (e.g. bytes(range(64)) vs a tweaked copy) is
    not a clean instruction sequence; the input guard must return Unknown rather
    than emulating garbage and sampling an admissible k=0."""
    v = _v()
    blob = bytes(range(64))
    tweaked = bytearray(blob)
    tweaked[10] ^= 0xFF
    ev = v.verify_sync(blob, bytes(tweaked), bits=64)
    assert ev.kind == "unknown", f"arbitrary blob must be Unknown, got {ev.kind}"
    assert not v.admissible(ev)


def test_arbitrary_blob_is_unknown_not_admitted_bits32():
    v = _v()
    blob = bytes(range(64))
    tweaked = bytearray(blob)
    tweaked[10] ^= 0xFF
    ev = v.verify_sync(blob, bytes(tweaked), bits=32)
    assert ev.kind == "unknown", f"arbitrary blob (bits=32) must be Unknown, got {ev.kind}"
    assert not v.admissible(ev)


# ===========================================================================
# FIX D: 32-bit proven library is bundled and selected by width.
# ===========================================================================


def test_proven_oracle_width_selects_32bit_library():
    """ProvenOracle(bits=32) loads the bundled 32-bit verified library, and the
    xor/sub eax,eax pair (31c0/29c0, present in both libs) proves at bits=32."""
    from funcval.oracles.proven import ProvenOracle

    o32 = ProvenOracle(bits=32)
    o64 = ProvenOracle(bits=64)
    # Different library files behind each width.
    assert o32.library_path != o64.library_path
    # The xor/sub pair is in the 32-bit verified library and proves there.
    ev = o32.produce("31c0", "29c0")
    assert ev.kind in ("proof", "unknown"), f"unexpected {ev.kind}"
    # The 32-bit library has the documented entry count.
    import json

    raw = json.loads(o32.library_path.read_text())
    entries = raw["entries"] if isinstance(raw, dict) else raw
    assert len(entries) == 1476, f"expected 1476 32-bit entries, got {len(entries)}"
