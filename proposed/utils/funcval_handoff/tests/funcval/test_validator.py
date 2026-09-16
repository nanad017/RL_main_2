"""Tests for funcval.validator.FunctionValidator + funcval.async_runner.

These tests NEVER touch the live CAPE box: the async/behavioral path is
exercised with a MOCK behavioral oracle (a plain object exposing submit/collect)
so no detonation happens.

What is pinned (the facade contract):
  * a library ``alt_modrm`` pair -> verify_sync -> Proof; admissible True.
  * a NON-library but truly-equivalent pair -> verify_sync -> Sampled;
    admissible True at 0.05, False at 1e-4 (the bound is between those budgets).
  * the 32-bit defect pair (testl 85c0 / andl 21c0) as a chunk step ->
    verify_sync -> Refuted; admissible False.
  * a 2-step chain whose scopes interact through uncompared state (live_in of a
    later step that an earlier step never compared) -> composed Unknown;
    admissible False.
  * async: verify_async/collect_async with a mock behavioral oracle returns the
    mocked Behavioral; ProgressRewardRunner delivers it to a registered callback.

Run with the comp venv:
    .venv-comp/bin/python -m pytest tests/funcval/test_validator.py -q
"""
from __future__ import annotations

import threading

import pytest

import funcval
from funcval import FunctionValidator, ProgressRewardRunner
from funcval.evidence import Behavioral, Proof, Refuted, Sampled, Scope, Unknown


# ---------------------------------------------------------------------------
# Fixtures: known pairs
# ---------------------------------------------------------------------------

# A library alt_modrm_d_bit_swap pair: two encodings of `mov rsp, rbp`.
# 4889ec = mov rsp,rbp ; 488be5 = the alternate ModRM d-bit encoding of the same.
LIB_PROOF_ORIG = "4889ec"
LIB_PROOF_VAR = "488be5"

# A NON-library but truly-equivalent pair: two encodings of `mov eax, eax`.
# 8bc0 (mov eax, eax via /r-form) vs 89c0 (mov eax, eax via /r d-bit swap).
# Not present in the cleaned proven library, so ProvenOracle returns Unknown and
# verify_sync escalates to LocalEquivOracle, which proves it Sampled (k=0).
NONLIB_EQUIV_ORIG = "8bc0"
NONLIB_EQUIV_VAR = "89c0"

# The 32-bit defect class: testl %eax,%eax (85c0) vs andl %eax,%eax (21c0).
# andl zero-extends the upper 32 bits; testl leaves them untouched. NOT
# equivalent on full-64-bit state -> LocalEquivOracle Refutes.
DEFECT_ORIG = "85c0"
DEFECT_VAR = "21c0"


def _hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)


def _single_step(orig_hex: str, var_hex: str, *, offset: int = 0) -> dict:
    return {
        "chunk_offset": offset,
        "chunk_a_bytes_hex": orig_hex,
        "chunk_b_bytes_hex": var_hex,
    }


# ---------------------------------------------------------------------------
# Sync gate
# ---------------------------------------------------------------------------


def test_library_pair_proves_and_admits():
    """A proven-library alt_modrm pair -> Proof; admissible True."""
    v = FunctionValidator()
    ev = v.verify_sync(
        _hex_to_bytes(LIB_PROOF_ORIG),
        _hex_to_bytes(LIB_PROOF_VAR),
    )
    assert isinstance(ev, Proof), f"expected Proof, got {ev.kind}"
    assert ev.false_admit_bound() == 0.0
    assert v.admissible(ev) is True
    # A proof admits at any non-negative budget, including the strict offline one.
    assert v.admissible(ev, alpha=v.alpha_offline) is True


def test_nonlibrary_equivalent_pair_samples_and_admits_at_online_not_tiny():
    """A non-library truly-equivalent pair -> Sampled (proven escalated to
    local_equiv); admissible True at 0.05, False at 1e-4."""
    v = FunctionValidator()
    # Sanity: the proven oracle does NOT know this pair (so escalation is real).
    assert v.proven.produce(NONLIB_EQUIV_ORIG, NONLIB_EQUIV_VAR).kind == "unknown"

    ev = v.verify_sync(
        _hex_to_bytes(NONLIB_EQUIV_ORIG),
        _hex_to_bytes(NONLIB_EQUIV_VAR),
    )
    assert isinstance(ev, Sampled), f"expected Sampled, got {ev.kind}"
    bound = ev.false_admit_bound()
    assert bound is not None and 1e-4 < bound < 0.05, (
        f"bound {bound} should sit between the tiny and online budgets"
    )
    assert v.admissible(ev, alpha=0.05) is True
    assert v.admissible(ev, alpha=1e-4) is False


def test_escalation_order_proven_then_local_equiv(monkeypatch):
    """verify_sync runs ProvenOracle FIRST and only escalates to LocalEquiv on
    Unknown (and NEVER touches behavioral)."""
    v = FunctionValidator()
    calls = []

    real_proven = v.proven.produce
    real_le = v.local_equiv.produce

    def spy_proven(o, var):
        calls.append("proven")
        return real_proven(o, var)

    def spy_le(o, var, **kw):
        calls.append("local_equiv")
        return real_le(o, var, **kw)

    monkeypatch.setattr(v.proven, "produce", spy_proven)
    monkeypatch.setattr(v.local_equiv, "produce", spy_le)

    # Library pair: proven only, no escalation.
    calls.clear()
    v.verify_sync(_hex_to_bytes(LIB_PROOF_ORIG), _hex_to_bytes(LIB_PROOF_VAR))
    assert calls == ["proven"], f"library pair should not escalate: {calls}"

    # Non-library pair: proven THEN local_equiv (order matters).
    calls.clear()
    v.verify_sync(_hex_to_bytes(NONLIB_EQUIV_ORIG), _hex_to_bytes(NONLIB_EQUIV_VAR))
    assert calls == ["proven", "local_equiv"], f"expected proven->local_equiv, got {calls}"


def test_32bit_defect_pair_refuted_and_not_admissible():
    """The testl<->andl 32-bit defect pair (as a chunk step) -> Refuted; not
    admissible at any budget."""
    v = FunctionValidator()
    ev = v.verify_sync(
        _hex_to_bytes(DEFECT_ORIG),
        _hex_to_bytes(DEFECT_VAR),
        steps=[_single_step(DEFECT_ORIG, DEFECT_VAR)],
    )
    assert isinstance(ev, Refuted), f"expected Refuted, got {ev.kind}"
    assert ev.is_refutation is True
    assert v.admissible(ev) is False
    assert v.admissible(ev, alpha=1.0) is False  # refutation never admits


def test_two_step_chain_scope_violation_composes_unknown():
    """A 2-step chain whose later step reads state an earlier step never
    compared (live_in precondition violated) -> Unknown; not admissible."""
    v = FunctionValidator()
    # Two non-library equivalent steps (each escalates to a full-state Sampled).
    # The later step declares it reads a MEMORY location the register-scoped
    # local_equiv comparison never covered -> the scope precondition is violated.
    steps = [
        {
            "chunk_offset": 0,
            "chunk_a_bytes_hex": NONLIB_EQUIV_ORIG,
            "chunk_b_bytes_hex": NONLIB_EQUIV_VAR,
            "live_in": [],
        },
        {
            "chunk_offset": 2,
            "chunk_a_bytes_hex": NONLIB_EQUIV_ORIG,
            "chunk_b_bytes_hex": NONLIB_EQUIV_VAR,
            # reads a stack memory cell that the full-register-state oracle did
            # not compare -> step 0 may have clobbered it unseen.
            "live_in": ["mem:[rsp-8]"],
        },
    ]
    ev = v.verify_sync(b"", b"", steps=steps)
    assert isinstance(ev, Unknown), f"expected Unknown, got {ev.kind}"
    assert "uncompared state" in ev.reason
    assert v.admissible(ev) is False


def test_no_op_mutation_is_unknown():
    """A mutation with no differing bytes is a no-op -> Unknown (honest)."""
    v = FunctionValidator()
    ev = v.verify_sync(_hex_to_bytes(LIB_PROOF_ORIG), _hex_to_bytes(LIB_PROOF_ORIG))
    assert isinstance(ev, Unknown)
    assert v.admissible(ev) is False


# ---------------------------------------------------------------------------
# Async / behavioral path (MOCK transport — no live CAPE)
# ---------------------------------------------------------------------------


class _MockBehavioralOracle:
    """A behavioral-oracle-shaped mock: submit -> handle, collect -> Behavioral.

    NEVER touches CAPE.  Returns a fixed Behavioral verdict so the async wiring
    can be tested deterministically.
    """

    def __init__(self, evidence: Behavioral) -> None:
        self._evidence = evidence
        self.submit_calls = 0
        self.collect_calls = 0

    def submit(self, orig_bytes, mut_bytes, **kw):
        self.submit_calls += 1
        return {"orig_task": 1001, "mut_task": 1002, "guests": ("g1", "g2"),
                "_orig": orig_bytes, "_mut": mut_bytes}

    def collect(self, handle, **kw):
        self.collect_calls += 1
        return self._evidence


def _make_behavioral_evidence(false_admit=None) -> Behavioral:
    return Behavioral(
        composite=0.917,
        noise_floor=0.0,
        threshold_basis="mock",
        coverage="mock-detonation",
        false_admit=false_admit,
        scope=Scope(live_out=frozenset({"behavior:api"}),
                    input_dist="mock", notes="mock"),
    )


def test_verify_async_without_behavioral_oracle_raises():
    """The facade works without a behavioral oracle, but verify_async is honest
    about needing one."""
    v = FunctionValidator()  # no behavioral
    assert v.behavioral is None
    with pytest.raises(RuntimeError, match="behavioral oracle"):
        v.verify_async(b"\x90", b"\x90")


def test_verify_async_collect_returns_mocked_behavioral():
    """verify_async/collect_async route through the (mock) behavioral oracle."""
    mock = _MockBehavioralOracle(_make_behavioral_evidence(false_admit=None))
    v = FunctionValidator(behavioral=mock)
    handle = v.verify_async(b"\x90\x90", b"\x90\x90")
    assert mock.submit_calls == 1 and mock.collect_calls == 0
    ev = v.collect_async(handle)
    assert isinstance(ev, Behavioral)
    assert ev.composite == 0.917
    assert mock.collect_calls == 1
    # Uncalibrated behavioral (false_admit None) does not admit.
    assert v.admissible(ev) is False


def test_progress_reward_runner_delivers_verdict_to_callback():
    """ProgressRewardRunner.enqueue -> worker -> on_verdict callback receives
    (job_id, meta, Evidence).  No live CAPE."""
    mock = _MockBehavioralOracle(_make_behavioral_evidence(false_admit=None))
    runner = ProgressRewardRunner(mock)

    received = []
    done = threading.Event()

    @runner.on_verdict
    def _cb(job_id, meta, evidence):
        received.append((job_id, meta, evidence))
        done.set()

    job_id = runner.enqueue(b"\x90", b"\x90", meta={"episode": 7, "step": 3})
    assert isinstance(job_id, int) and job_id >= 1

    assert done.wait(timeout=10.0), "callback was not invoked within 10s"
    runner.stop(timeout=5.0)

    assert len(received) == 1
    got_id, got_meta, got_ev = received[0]
    assert got_id == job_id
    assert got_meta == {"episode": 7, "step": 3}
    assert isinstance(got_ev, Behavioral)
    assert got_ev.composite == 0.917
    assert mock.submit_calls == 1 and mock.collect_calls == 1


def test_progress_reward_runner_isolates_failing_oracle():
    """A behavioral oracle that raises maps to Unknown delivered to the callback;
    the worker survives."""
    class _Boom:
        def submit(self, *a, **k):
            raise RuntimeError("box offline")

        def collect(self, *a, **k):  # pragma: no cover - submit raises first
            raise AssertionError("collect should not be reached")

    runner = ProgressRewardRunner(_Boom())
    received = []
    done = threading.Event()

    runner.on_verdict(lambda jid, meta, ev: (received.append(ev), done.set()))
    runner.enqueue(b"\x90", b"\x90", meta={})
    assert done.wait(timeout=10.0)
    runner.stop(timeout=5.0)

    assert len(received) == 1
    assert isinstance(received[0], Unknown)
    assert "behavioral job failed" in received[0].reason
