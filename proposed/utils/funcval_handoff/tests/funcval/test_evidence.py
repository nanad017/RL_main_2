"""Tests for lib/funcval/evidence.py — the typed evidence model.

The whole design replaces an overloaded ``confidence: float`` with named,
typed records, each exposing exactly ONE comparable quantity: a false-admit
upper bound (or None when there is no comparable number).
"""
from __future__ import annotations

import dataclasses

import pytest

from funcval.evidence import (
    Behavioral,
    Cert,
    ComposedBound,
    Evidence,
    Proof,
    Refuted,
    Sampled,
    Scope,
    Unknown,
)


def _full_scope(notes=""):
    return Scope(live_out=frozenset({"rax", "eflags"}), input_dist=None, notes=notes)


# --- Scope -----------------------------------------------------------------

def test_scope_is_frozen():
    s = _full_scope()
    with pytest.raises(dataclasses.FrozenInstanceError):
        s.live_out = frozenset()  # type: ignore[misc]


# --- Refuted: a sound NO ---------------------------------------------------

def test_refuted_dominates_and_has_no_bound():
    r = Refuted(counterexample={"input": "x", "rax": (1, 2)}, scope=_full_scope(), oracle="z3")
    assert r.kind == "refuted"
    assert r.is_refutation is True
    assert r.false_admit_bound() is None


# --- Proof: zero error WITHIN scope ----------------------------------------

def test_proof_bound_is_zero():
    cert = Cert(cert_kind="Z3_UNSAT", payload="(check-sat) unsat", recheckable=True)
    p = Proof(cert=cert, scope=_full_scope())
    assert p.kind == "proof"
    assert p.false_admit_bound() == 0.0
    assert p.is_refutation is False


def test_proof_sdm_argument_is_not_machine_checked():
    # SDM_ARGUMENT certs are valid Proof certs but must be flagged not-recheckable
    # so the caller can refuse to trust them like a Z3 proof.
    cert = Cert(cert_kind="SDM_ARGUMENT", payload="Intel SDM Vol.2 d-bit", recheckable=False)
    p = Proof(cert=cert, scope=_full_scope())
    assert p.false_admit_bound() == 0.0
    assert p.cert.recheckable is False
    assert p.cert.cert_kind == "SDM_ARGUMENT"


def test_cert_rejects_unknown_kind():
    with pytest.raises(ValueError):
        Cert(cert_kind="HANDWAVE", payload="", recheckable=False)


# --- Sampled: Clopper-Pearson bound under a distribution -------------------

def test_sampled_bound_matches_clopper_pearson():
    from funcval.bounds import clopper_pearson_upper

    s = Sampled(n=256, k=0, dist_id="benign_text_v1", live_out=_full_scope(), delta=0.05)
    assert s.kind == "sampled"
    assert s.false_admit_bound() == pytest.approx(clopper_pearson_upper(0, 256, 0.05))
    # scope returns the live_out Scope
    assert s.scope is s.live_out


def test_sampled_invariants():
    with pytest.raises(ValueError):
        Sampled(n=10, k=-1, dist_id="d", live_out=_full_scope(), delta=0.05)
    with pytest.raises(ValueError):
        Sampled(n=10, k=11, dist_id="d", live_out=_full_scope(), delta=0.05)
    with pytest.raises(ValueError):
        Sampled(n=-1, k=0, dist_id="d", live_out=_full_scope(), delta=0.05)
    with pytest.raises(ValueError):
        Sampled(n=10, k=0, dist_id="d", live_out=_full_scope(), delta=0.0)
    with pytest.raises(ValueError):
        Sampled(n=10, k=0, dist_id="d", live_out=_full_scope(), delta=1.0)


# --- Behavioral: an OBSERVATION, never a proof -----------------------------

def test_behavioral_with_calibrated_false_admit():
    b = Behavioral(
        composite=0.98,
        noise_floor=0.90,
        threshold_basis="calib_set_v1",
        coverage="detonation",
        false_admit=0.04,
        scope=_full_scope(),
    )
    assert b.kind == "behavioral"
    assert b.false_admit_bound() == 0.04


def test_behavioral_without_calibration_has_no_bound():
    # No calibration => no honest bound => behaves like Unknown for admission.
    b = Behavioral(
        composite=0.98,
        noise_floor=0.90,
        threshold_basis="none",
        coverage="detonation",
        false_admit=None,
        scope=_full_scope(),
    )
    assert b.false_admit_bound() is None


def test_behavioral_false_admit_must_be_unit_interval():
    with pytest.raises(ValueError):
        Behavioral(
            composite=0.98,
            noise_floor=0.90,
            threshold_basis="x",
            coverage="detonation",
            false_admit=1.5,
            scope=_full_scope(),
        )


# --- Unknown: absence of evidence, NOT the number 0.5 ----------------------

def test_unknown_carries_no_number():
    u = Unknown(reason="oracle timed out")
    assert u.kind == "unknown"
    assert u.false_admit_bound() is None
    assert u.scope is None
    assert u.is_refutation is False


# --- ComposedBound (added for ledger composition) --------------------------

def test_composed_bound_returns_union():
    sc = _full_scope()
    cb = ComposedBound(false_admit=0.06, scope=sc, parts=())
    assert cb.kind == "sampled"  # composite behaves like a sampled bound for admission
    assert cb.false_admit_bound() == 0.06
    assert cb.scope is sc


def test_composed_bound_invariant():
    with pytest.raises(ValueError):
        ComposedBound(false_admit=1.5, scope=_full_scope(), parts=())


# --- Common API present on every kind --------------------------------------

@pytest.mark.parametrize(
    "ev",
    [
        Refuted(counterexample={}, scope=_full_scope(), oracle="z3"),
        Proof(cert=Cert("Z3_UNSAT", "p", True), scope=_full_scope()),
        Sampled(n=10, k=0, dist_id="d", live_out=_full_scope(), delta=0.05),
        Behavioral(0.9, 0.8, "b", "c", None, _full_scope()),
        Unknown(reason="r"),
    ],
)
def test_every_kind_implements_common_api(ev):
    assert isinstance(ev, Evidence)
    assert isinstance(ev.kind, str)
    # false_admit_bound is either None or a float in [0,1]
    b = ev.false_admit_bound()
    assert b is None or (0.0 <= b <= 1.0)
    assert isinstance(ev.is_refutation, bool)
