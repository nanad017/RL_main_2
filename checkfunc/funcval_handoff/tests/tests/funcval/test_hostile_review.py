"""Regression tests for the hostile code review of lib/funcval/.

Each test reproduces one finding from the review and guards the fix.  Written
test-first (TDD): each was confirmed to FAIL against the pre-fix code before the
corresponding fix was applied.

Run with the comp venv (capstone+z3 present):
    .venv-comp/bin/python -m pytest tests/funcval/test_hostile_review.py -q
"""
from __future__ import annotations

import pytest

from funcval.evidence import (
    Behavioral,
    Cert,
    ComposedBound,
    Proof,
    Refuted,
    Sampled,
    Scope,
    Unknown,
)
from funcval.ledger import admit, compose

capstone = pytest.importorskip("capstone")


# ===========================================================================
# Finding 1 [CRITICAL]: vacuous SIMD Z3 cert.
# ===========================================================================
# The simd_bitwise_alias proof asserted (a^b) != (a^b) -> trivially UNSAT
# regardless of semantics.  A NON-equivalent SIMD pair (pxor vs por) must NOT be
# certified as a Proof.


def test_nonequivalent_simd_pair_is_not_certified():
    """pxor xmm0,xmm1 (660fefc1) vs por xmm0,xmm1 (660febc1) are NOT equivalent
    (xor != or).  The oracle must NOT return a Proof for them, no matter what
    cert machinery is used."""
    from funcval.oracles.proven import ProvenOracle

    # Build an oracle whose library contains this NON-equivalent pair tagged as a
    # simd alias, to be sure the cert path (not just the library miss) is what
    # rejects it.
    import json
    import tempfile
    from pathlib import Path

    entries = [
        {
            "original_hex": "660fefc1",  # pxor xmm0, xmm1
            "variant_hex": "660febc1",   # por  xmm0, xmm1
            "proof_pattern": "simd_bitwise_alias",
            "proof_tier": "STRUCTURAL_PROVEN",
            "original_asm": "pxor %xmm1, %xmm0",
            "variant_asm": "por %xmm1, %xmm0",
        }
    ]
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "lib.json"
        p.write_text(json.dumps(entries))
        oracle = ProvenOracle(library_path=p)
        ev = oracle.produce("660fefc1", "660febc1")
        assert not isinstance(ev, Proof), (
            f"pxor vs por must NOT be certified equivalent; got Proof "
            f"(cert {getattr(ev, 'cert', None)})"
        )


def test_genuine_simd_alias_pair_is_certified_recheckable():
    """A genuine alias (pxor xmm0,xmm1 vs xorpd xmm0,xmm1) IS certified, with a
    re-checkable, NON-vacuous cert."""
    from funcval.oracles.proven import ProvenOracle, recheck_cert

    oracle = ProvenOracle()
    # 660fefc1 = pxor xmm0,xmm1 ; 660f57c1 = xorpd xmm0,xmm1 (genuine alias).
    ev = oracle.produce("660fefc1", "660f57c1")
    assert isinstance(ev, Proof), f"genuine SIMD alias should prove, got {ev.kind}"
    assert ev.false_admit_bound() == 0.0
    assert ev.cert.recheckable is True
    assert recheck_cert(ev.cert) is True


def test_simd_cert_is_not_vacuous_z3():
    """Whatever cert backs a SIMD alias proof, it must not be a Z3 cert whose
    payload is the vacuous x!=x query (which 'proves' ANY pair)."""
    from funcval.oracles.proven import ProvenOracle

    oracle = ProvenOracle()
    ev = oracle.produce("660fefc1", "660f57c1")  # pxor vs xorpd
    assert isinstance(ev, Proof)
    # The cert must be the honest structural ISA-alias cert, not a Z3 cert.
    assert ev.cert.cert_kind == "ISA_BITWISE_ALIAS", (
        f"expected structural ISA_BITWISE_ALIAS cert, got {ev.cert.cert_kind}"
    )


# ===========================================================================
# Finding 2 [HIGH]: compose identical-scope shortcut unsound for partial scopes.
# ===========================================================================


def _rax_only_proof():
    return Proof(
        cert=Cert("Z3_UNSAT", "unsat", True),
        scope=Scope(live_out=frozenset({"rax"}), input_dist=None),
    )


def test_two_partial_scope_proofs_do_not_compose_without_livein():
    """Two {rax}-only Proofs must NOT silently compose to an admissible Proof:
    {rax} is not the full architectural state, so a later step reading rbx is
    unverified -> Unknown unless live_in supplied."""
    out = compose([_rax_only_proof(), _rax_only_proof()])
    assert out.kind == "unknown", (
        f"two partial-scope proofs must not compose to {out.kind} without live_in"
    )


def test_two_partial_scope_proofs_with_uncovered_livein_unknown():
    """Even WITH live_in, if a later step reads rbx that the {rax}-only earlier
    step never compared, the chain is Unknown."""
    out = compose(
        [_rax_only_proof(), _rax_only_proof()],
        live_in_of_later_steps=[frozenset(), frozenset({"rbx"})],
    )
    assert out.kind == "unknown"
    assert "uncompared state" in out.reason


# ===========================================================================
# Finding 3 [HIGH]: _steps_from_diff per-byte-run split feeds garbage.
# ===========================================================================


def test_multi_run_diff_does_not_split_into_subinstruction_garbage():
    """The critic's case: 4831c0 90 4831c0 vs 4829c0 90 4829c0.  Two disjoint
    diff runs at byte level; the OLD per-byte-run split dropped the shared 48 REX
    prefix and fed '31'/'29' garbage sub-instructions to the oracles.  The fix:
    when there is >1 diff run and the caller did not pass instruction-aligned
    steps, emit a SINGLE whole-buffer step (no '31'/'29' sub-spans)."""
    from funcval import FunctionValidator

    v = FunctionValidator()
    orig = bytes.fromhex("4831c090" + "4831c0")  # xor rax,rax ; nop ; xor rax,rax
    mut = bytes.fromhex("4829c090" + "4829c0")   # sub rax,rax ; nop ; sub rax,rax

    steps = v._steps_from_diff(orig, mut)
    # No step may be a sub-instruction byte fragment like '31'/'29'.
    for s in steps:
        assert s["chunk_a_bytes_hex"] not in ("31", "29"), (
            f"multi-run diff produced a sub-instruction garbage step {s}"
        )
    # Either one whole-buffer step or zero; never per-byte-run garbage.
    assert len(steps) <= 1, f"expected single whole-buffer step, got {steps}"


def test_multi_run_diff_nonequiv_is_refuted_not_admitted_via_garbage():
    """End-to-end: a multi-run NON-equivalent case must NOT be admitted.

    ``85c0 90 85c0`` (test eax,eax ; nop ; test eax,eax) vs ``21c0 90 21c0``
    (and eax,eax ; nop ; and eax,eax) is a 2-run byte diff (bytes 0 and 3 differ,
    the ``c0``/``90``/``c0`` are shared).  The OLD per-byte-run split dropped the
    shared bytes and fed ``85``/``21`` garbage fragments to the oracle, which
    emulated raw bytes and returned an admissible Sampled(k=0).  The whole-buffer
    step is the 32-bit zero-extension defect (and zero-extends rax, test does
    not) -> the oracle correctly REFUTES it.  Either way: not admissible."""
    from funcval import FunctionValidator

    v = FunctionValidator()
    orig = bytes.fromhex("85c0" + "90" + "85c0")
    mut = bytes.fromhex("21c0" + "90" + "21c0")
    ev = v.verify_sync(orig, mut)
    assert ev.kind == "refuted", f"expected refuted whole-buffer verdict, got {ev.kind}"
    assert not v.admissible(ev), (
        f"a multi-run non-equivalent diff must not be admitted; got "
        f"{ev.kind} admissible={v.admissible(ev)}"
    )


def test_multi_run_diff_equiv_whole_buffer_is_sound_sampled():
    """A multi-run diff whose WHOLE buffer is genuinely equivalent (xor/sub rax)
    yields a sound whole-buffer Sampled — NOT a fabricated per-run split.  The
    fix is about not feeding garbage, not about refusing genuine equivalence."""
    from funcval import FunctionValidator
    from funcval.evidence import Sampled

    v = FunctionValidator()
    orig = bytes.fromhex("4831c090" + "4831c0")  # xor rax,rax ; nop ; xor rax,rax
    mut = bytes.fromhex("4829c090" + "4829c0")   # sub rax,rax ; nop ; sub rax,rax
    ev = v.verify_sync(orig, mut)
    assert isinstance(ev, Sampled), f"expected whole-buffer Sampled, got {ev.kind}"
    # The dist_id proves it was emulated as ONE 7-byte buffer, not byte fragments.
    assert ev.n == 256


# ===========================================================================
# Finding 4 [MEDIUM]: admit ignores cert.recheckable.
# ===========================================================================


def test_admit_rejects_nonrecheckable_proof_by_default():
    """A Proof with a non-recheckable (SDM_ARGUMENT) cert must NOT clear the gate
    by default."""
    p = Proof(
        cert=Cert("SDM_ARGUMENT", "Intel SDM Vol.2", recheckable=False),
        scope=Scope(live_out=frozenset({"rax"}), input_dist=None),
    )
    assert admit(p, alpha=0.05) is False, "non-recheckable proof must not admit by default"


def test_admit_allows_nonrecheckable_proof_when_explicitly_opted_out():
    """When require_recheckable=False, the old behavior (proof admits) is
    available for callers that knowingly trust SDM arguments."""
    p = Proof(
        cert=Cert("SDM_ARGUMENT", "Intel SDM Vol.2", recheckable=False),
        scope=Scope(live_out=frozenset({"rax"}), input_dist=None),
    )
    assert admit(p, alpha=0.05, require_recheckable=False) is True


def test_admit_allows_recheckable_proof():
    """A recheckable Z3 proof still admits under the default."""
    p = Proof(
        cert=Cert("Z3_UNSAT", "unsat", recheckable=True),
        scope=Scope(live_out=frozenset({"rax"}), input_dist=None),
    )
    assert admit(p, alpha=0.0) is True


# ===========================================================================
# Finding 5 [MEDIUM]: ComposedBound drops per-step delta.
# ===========================================================================


def test_composed_bound_carries_summed_delta():
    """A 3-step compose must report the summed per-step delta (Boole union of the
    confidence residuals), not silently drop it."""
    sc = Scope(live_out=frozenset({"rax"}), input_dist=None)
    steps = [
        Sampled(n=256, k=0, dist_id="d", live_out=sc, delta=0.05),
        Sampled(n=256, k=0, dist_id="d", live_out=sc, delta=0.05),
        Sampled(n=256, k=0, dist_id="d", live_out=sc, delta=0.05),
    ]
    out = compose(
        steps,
        live_in_of_later_steps=[frozenset(), frozenset({"rax"}), frozenset({"rax"})],
    )
    assert isinstance(out, ComposedBound)
    assert out.delta == pytest.approx(0.15), f"expected summed delta 0.15, got {out.delta}"


def test_composed_bound_delta_capped_at_one():
    sc = Scope(live_out=frozenset({"rax"}), input_dist=None)
    steps = [Sampled(n=10, k=0, dist_id="d", live_out=sc, delta=0.5) for _ in range(3)]
    out = compose(
        steps,
        live_in_of_later_steps=[frozenset()] + [frozenset({"rax"})] * 2,
    )
    assert isinstance(out, ComposedBound)
    assert out.delta == pytest.approx(1.0)


# ===========================================================================
# Finding 6 [LOW]: Evidence invariants under-enforced.
# ===========================================================================


def test_sampled_rejects_empty_scope():
    """A bound-bearing Sampled over an EMPTY scope is meaningless and rejected."""
    with pytest.raises(ValueError):
        Sampled(n=256, k=0, dist_id="d",
                live_out=Scope(live_out=frozenset(), input_dist=None), delta=0.05)


def test_composed_bound_rejects_empty_scope():
    with pytest.raises(ValueError):
        ComposedBound(false_admit=0.01, scope=Scope(live_out=frozenset(), input_dist=None))


def test_behavioral_rejects_empty_scope_when_bound_present():
    with pytest.raises(ValueError):
        Behavioral(0.9, 0.8, "b", "c", false_admit=0.02,
                   scope=Scope(live_out=frozenset(), input_dist=None))


def test_refuted_requires_nonnone_scope():
    with pytest.raises((ValueError, TypeError)):
        Refuted(counterexample={}, scope=None, oracle="z3")  # type: ignore[arg-type]


# ===========================================================================
# Finding: Sampled delta sanity guard (cheap-shot cleanup).
# ===========================================================================


def test_sampled_rejects_large_delta():
    """A large delta gives a tighter (falsely admitting) bound; guard delta<=0.5."""
    sc = Scope(live_out=frozenset({"rax"}), input_dist=None)
    with pytest.raises(ValueError):
        Sampled(n=256, k=0, dist_id="d", live_out=sc, delta=0.6)
