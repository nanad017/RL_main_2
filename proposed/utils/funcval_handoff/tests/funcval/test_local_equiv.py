"""Tests for lib/funcval/oracles/local_equiv.py — the LocalEquivOracle.

The oracle emulates a byte-pair from a shared input state under Unicorn and
compares the FULL architectural state (16 GPR@64-bit + 16 XMM@128 +
eflags&0x8D5).  These tests pin the two canonical cases:

  * xorl %eax,%eax (31c0) vs subl %eax,%eax (29c0) -> both zero eax and set the
    same flags, so the oracle must return Sampled(k=0) which admits at 0.05.
  * testl %eax,%eax (85c0) vs andl %eax,%eax (21c0) -> the 32-bit zero-extension
    defect: andl zero-extends rax to 64 bits, testl does not, so they diverge on
    the full-64-bit comparison whenever the upper 32 bits of rax are nonzero.
    The oracle must REFUTE it — and the boundary battery guarantees it is caught
    deterministically (the 0xFFFFFFFF / INT_MIN vectors put a nonzero upper half
    in place), not left to uniform luck.

They also assert the boundary battery actually contains the hazardous constants
(0xFFFFFFFF and INT_MIN) the critic demanded.
"""
from __future__ import annotations

from funcval import Refuted, Sampled, admit
from funcval.oracles import LocalEquivOracle
from funcval.oracles.local_equiv import (
    _BOUNDARY_FILLS,
    EFLAGS_ARITH_MASK,
    GPR_NAMES_64,
)

# Canonical byte pairs (from artifacts/stoke_maps/equiv_library_proven_v3*).
XOR_EAX = "31c0"   # xorl %eax, %eax  (zeroes eax, clears CF/OF, sets ZF/PF)
SUB_EAX = "29c0"   # subl %eax, %eax  (zeroes eax, same flag result)
TESTL_EAX = "85c0"  # testl %eax, %eax (does NOT write rax; upper 32 bits kept)
ANDL_EAX = "21c0"   # andl %eax, %eax  (writes eax -> zero-extends rax to 64 bits)

ALPHA = 0.05
DELTA = 0.05


# --- xor <-> sub : genuinely equivalent -> Sampled, admits ------------------

def test_xor_sub_is_sampled_and_admits():
    oracle = LocalEquivOracle()
    ev = oracle.produce(XOR_EAX, SUB_EAX, n=256, delta=DELTA)
    assert isinstance(ev, Sampled), f"expected Sampled, got {type(ev).__name__}"
    assert ev.k == 0
    assert ev.n == 256
    # the single comparable quantity is the CP upper bound; admits at alpha=0.05
    assert ev.false_admit_bound() is not None
    assert admit(ev, ALPHA) is True


def test_xor_sub_bound_matches_clopper_pearson_k0():
    from funcval import clopper_pearson_upper

    oracle = LocalEquivOracle()
    ev = oracle.produce(XOR_EAX, SUB_EAX, n=256, delta=DELTA)
    assert isinstance(ev, Sampled)
    assert ev.false_admit_bound() == clopper_pearson_upper(0, 256, DELTA)


def test_xor_sub_scope_is_full_state():
    oracle = LocalEquivOracle()
    ev = oracle.produce(XOR_EAX, SUB_EAX, n=128, delta=DELTA)
    assert isinstance(ev, Sampled)
    lo = ev.scope.live_out
    # all 16 GPRs + eflags present in the compared scope
    for r in GPR_NAMES_64:
        assert r in lo
    assert "eflags" in lo
    # at least some XMM registers compared (16 if the build exposes them)
    assert any(name.startswith("xmm") for name in lo)
    # dist_id is recorded and reproducible-by-seed
    assert ev.scope.input_dist.startswith("unicorn-fullstate-boundary+uniform-n128-seed0x")
    assert ev.dist_id == ev.scope.input_dist


# --- testl <-> andl : the 32-bit defect -> Refuted --------------------------

def test_testl_andl_is_refuted():
    oracle = LocalEquivOracle()
    ev = oracle.produce(TESTL_EAX, ANDL_EAX, n=256, delta=DELTA)
    assert isinstance(ev, Refuted), f"expected Refuted, got {type(ev).__name__}"
    assert ev.is_refutation is True
    # a refutation carries no comparable number and never admits
    assert ev.false_admit_bound() is None
    assert admit(ev, ALPHA) is False
    assert ev.oracle == "local_equiv"


def test_testl_andl_counterexample_blames_rax():
    oracle = LocalEquivOracle()
    ev = oracle.produce(TESTL_EAX, ANDL_EAX, n=256, delta=DELTA)
    assert isinstance(ev, Refuted)
    ce = ev.counterexample
    # the witness must carry the diverging registers and the input state
    assert "diverging_regs" in ce and ce["diverging_regs"]
    assert "rax" in ce["diverging_regs"], ce["diverging_regs"]
    assert "input_state" in ce


def test_testl_andl_refuted_deterministically_across_seeds():
    # The boundary battery (run first, every call) guarantees the defect is
    # caught regardless of the per-call urandom seed — not left to uniform luck.
    oracle = LocalEquivOracle()
    for _ in range(5):
        ev = oracle.produce(TESTL_EAX, ANDL_EAX, n=256, delta=DELTA)
        assert isinstance(ev, Refuted)


# --- boundary battery contains the hazardous constants ----------------------

def test_boundary_battery_includes_32bit_minus1_and_int_min():
    # 0xFFFFFFFF (32-bit -1, the zero-extension exposer) MUST be in the battery.
    assert 0x00000000FFFFFFFF in _BOUNDARY_FILLS
    # INT_MIN (64-bit sign bit) MUST be in the battery.
    assert 0x8000000000000000 in _BOUNDARY_FILLS
    # and the 32-bit sign bit, the other half of the extension hazard class.
    assert 0x0000000080000000 in _BOUNDARY_FILLS


def test_boundary_battery_states_are_built():
    import random

    oracle = LocalEquivOracle()
    rng = random.Random(0)
    battery = oracle._boundary_battery(rng)
    # family 1: all-regs=b for each fill, x2 eflags extremes.
    assert len(battery) >= 2 * len(_BOUNDARY_FILLS)
    # an all-ones vector exists with every GPR (except pinned rsp/rbp) == -1
    found_all_ones = False
    for st in battery:
        nonpinned = [st[r] for r in GPR_NAMES_64 if r not in ("rsp", "rbp")]
        if all(v == 0xFFFFFFFFFFFFFFFF for v in nonpinned):
            found_all_ones = True
            break
    assert found_all_ones
    # eflags always carries the reserved bit and stays within the arith mask + 0x2
    for st in battery:
        assert (st["eflags"] & ~(EFLAGS_ARITH_MASK | 0x2)) == 0
