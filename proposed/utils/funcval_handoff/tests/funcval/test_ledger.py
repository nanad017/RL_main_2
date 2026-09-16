"""Tests for lib/funcval/ledger.py — composition + the single admit() gate.

admit() is the ONLY place a number is compared, and every number compared is
the SAME quantity (a false-admit upper bound).  Composition refuses to
overclaim: refutation dominates, Unknown poisons, and an unverified scope
precondition yields Unknown rather than a min()-capped PASS.
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
from funcval.ledger import FULL_STATE_LIVE_OUT, admit, compose


# A partial scope (the historical {rax,rbx,eflags} stand-in) used wherever the
# test does not depend on the full-state compose shortcut.
FULL = frozenset({"rax", "rbx", "eflags"})


def _full_scope(notes=""):
    return Scope(live_out=FULL, input_dist=None, notes=notes)


def _proof_full(notes=""):
    return Proof(cert=Cert("Z3_UNSAT", "unsat", True), scope=_full_scope(notes))


def _proof_whole_state(notes=""):
    """A Proof over the ACTUAL full architectural-state vocabulary.

    The no-live_in compose shortcut is sound ONLY over the full state, so this is
    what the shortcut test must use (a partial scope must NOT take the shortcut).
    """
    return Proof(
        cert=Cert("Z3_UNSAT", "unsat", True),
        scope=Scope(live_out=FULL_STATE_LIVE_OUT, input_dist=None, notes=notes),
    )


def _sampled(n=256, k=0, scope=None):
    return Sampled(n=n, k=k, dist_id="d", live_out=scope or _full_scope(), delta=0.05)


# === admit() ===============================================================

def test_admit_sampled_within_budget():
    s = _sampled(256, 0)  # bound ~0.0116
    assert admit(s, alpha=0.05) is True


def test_admit_sampled_outside_budget():
    s = _sampled(256, 0)  # bound ~0.0116 > 0.005
    assert admit(s, alpha=0.005) is False


def test_admit_proof_at_tiny_alpha():
    assert admit(_proof_full(), alpha=1e-9) is True


def test_admit_refuted_always_false():
    r = Refuted(counterexample={}, scope=_full_scope(), oracle="z3")
    assert admit(r, alpha=1.0) is False


def test_admit_unknown_always_false():
    assert admit(Unknown(reason="x"), alpha=1.0) is False


def test_admit_behavioral_without_bound_is_false():
    b = Behavioral(0.99, 0.9, "x", "c", None, _full_scope())
    assert admit(b, alpha=1.0) is False


def test_admit_behavioral_with_bound():
    b = Behavioral(0.99, 0.9, "x", "c", false_admit=0.02, scope=_full_scope())
    assert admit(b, alpha=0.05) is True
    assert admit(b, alpha=0.01) is False


# === compose() =============================================================

def test_refutation_dominates():
    r = Refuted(counterexample={"rax": (1, 2)}, scope=_full_scope(), oracle="z3")
    out = compose([_sampled(256, 0), r])
    assert out is r  # the exact refutation is returned, sound NO


def test_unknown_poisons():
    out = compose([_proof_full(), Unknown(reason="oracle missing")])
    assert out.kind == "unknown"


def test_proof_then_sampled_without_liveinfo_is_unknown():
    # Mixed kinds, no live-in info => scope precondition UNVERIFIED => Unknown.
    out = compose([_proof_full(), _sampled(256, 0)])
    assert out.kind == "unknown"
    assert "precondition unverified" in out.reason


def test_two_full_state_proofs_identical_scope_compose_to_proof():
    # Two proofs over the FULL architectural state share an identical full scope,
    # so the no-live_in shortcut is sound and they compose to a Proof.
    out = compose([_proof_whole_state(), _proof_whole_state()])
    assert out.kind == "proof"
    assert out.false_admit_bound() == 0.0


def test_two_partial_scope_proofs_do_not_take_full_state_shortcut():
    # Two proofs sharing a PARTIAL identical scope must NOT take the shortcut:
    # a later step could read state neither proof compared (finding 2).
    out = compose([_proof_full(), _proof_full()])
    assert out.kind == "unknown"
    assert "precondition unverified" in out.reason


def test_uncovered_later_live_in_is_unknown():
    # Step 0 only compared {rax}; step 1's live-in needs {rbx} which step 0
    # did NOT compare => steps interact through uncompared state => Unknown.
    s0 = _sampled(256, 0, scope=Scope(live_out=frozenset({"rax"}), input_dist=None))
    s1 = _sampled(256, 0, scope=Scope(live_out=frozenset({"rax", "rbx"}), input_dist=None))
    out = compose([s0, s1], live_in_of_later_steps=[frozenset({"rax"}), frozenset({"rbx"})])
    assert out.kind == "unknown"
    assert "uncompared state" in out.reason


def test_two_sampled_with_covering_scopes_compose_to_composed_bound():
    # Step 0 compares {rax,rbx}; step 1's live-in {rax} is covered.
    s0 = _sampled(256, 0, scope=Scope(live_out=frozenset({"rax", "rbx"}), input_dist=None))
    s1 = _sampled(256, 0, scope=Scope(live_out=frozenset({"rax", "rbx"}), input_dist=None))
    out = compose(
        [s0, s1],
        live_in_of_later_steps=[frozenset({"rax"}), frozenset({"rax"})],
    )
    assert isinstance(out, ComposedBound)
    # union bound = sum of the two CP bounds
    expected = s0.false_admit_bound() + s1.false_admit_bound()
    assert out.false_admit_bound() == pytest.approx(expected)
    # scope is the intersection of step live_outs
    assert out.scope.live_out == frozenset({"rax", "rbx"})


def test_empty_chain_is_unknown():
    out = compose([])
    assert out.kind == "unknown"


def test_composed_bound_then_admit():
    s0 = _sampled(256, 0, scope=Scope(live_out=frozenset({"rax"}), input_dist=None))
    s1 = _sampled(256, 0, scope=Scope(live_out=frozenset({"rax"}), input_dist=None))
    out = compose(
        [s0, s1],
        live_in_of_later_steps=[frozenset({"rax"}), frozenset({"rax"})],
    )
    # union ~0.0233; admissible at 0.05, not at 0.01
    assert admit(out, alpha=0.05) is True
    assert admit(out, alpha=0.01) is False
