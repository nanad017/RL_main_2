"""Tests for funcval.oracles.behavioral.BehavioralOracle — OFFLINE only.

These tests NEVER touch the live CAPE box.  They load the already-downloaded
reports for tasks 7992 / 7993 (the SAME benign PE detonated twice — the
noise-floor experiment) from ``assets/logs/cape_reports/`` and monkeypatch the
transport so submit/poll/fetch resolve to those saved JSON files.

What we pin (the design contract):
  * NON-EMPTY-channel scoring: 7992-vs-7993 api_similarity == 0.8814 and the
    nonempty_composite EXCLUDES the 4 vacuous-1.0 EMPTY channels (file/network/
    dropped/mutex), so it is NOT the inflated naive composite 0.9585.
  * Empty-trace gate: a synthetic 3-api-call report -> Unknown.
  * UNCALIBRATED behavioral has false_admit None -> funcval.admit(..) is False
    (honest: behavioral alone can't gate without negative calibration).
  * CALIBRATED path: a tiny fake calibration (positive + negative dists) yields
    the noise-floor threshold and reads false_admit from the negatives; a
    high-similarity pair with false_admit <= alpha admits.

Run with the comp venv:
    .venv-comp/bin/python -m pytest tests/funcval/test_behavioral.py -q
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import funcval
from funcval.evidence import Behavioral, Unknown
from funcval.oracles.behavioral import BehavioralOracle

# Repo root via conftest's sys.path setup; locate the saved reports.
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parents[1]
_REPORTS = _ROOT / "assets" / "logs" / "cape_reports"


def _load_report(task_id: int) -> dict:
    path = _REPORTS / f"{task_id}.report.json"
    if not path.exists():
        pytest.skip(f"saved report {path} not present (offline fixture missing)")
    return json.loads(path.read_text())


class _FakeScorer:
    """A real SandboxVerifier scorer without the `requests` import requirement.

    Built via __new__ so SandboxVerifier.__init__ (which requires `requests`)
    never runs — this is exactly how CapeCliClient builds its own scorer.
    """

    def __new__(cls):
        from funcval.cape.sandbox_verify import SandboxVerifier

        scorer = SandboxVerifier.__new__(SandboxVerifier)
        scorer.threshold = 0.70
        return scorer


class _MockCapeClient:
    """A drop-in for CapeCliClient that resolves the saved 7992/7993 reports.

    NO live box call: submit() hands out the pre-loaded task ids in order,
    await_terminal() declares them DONE, fetch_report() reads the on-disk JSON.
    ``_scorer`` is a real SandboxVerifier so scoring is identical to production.
    """

    def __init__(self, report_map):
        self._report_map = dict(report_map)  # task_id -> report dict
        self._scorer = _FakeScorer()
        self._guest_rr = 0
        self.guests = ["win11", "win11_2", "win11_3"]
        # Task ids handed out in insertion order, one per submit() call.
        self._task_queue = list(self._report_map.keys())
        self._submitted = 0

    def _next_guest(self):
        g = self.guests[self._guest_rr % len(self.guests)]
        self._guest_rr += 1
        return g

    def submit(self, pe_bytes, *, machine=None, timeout=None, package=None):
        # Deterministically hand out the next pre-loaded task id.
        tid = self._task_queue[self._submitted % len(self._task_queue)]
        self._submitted += 1
        return tid

    def await_terminal(self, task_ids, *, deadline=None):
        from funcval.cape.cape_cli_client import PollState

        return {int(t): PollState.DONE for t in task_ids}

    def fetch_report(self, task_id, *, projection=None):
        return self._report_map[int(task_id)]


def _make_oracle(report_map, calibration_path=None, k_sigma=3.0,
                 min_api_calls=20):
    client = _MockCapeClient(report_map)
    return BehavioralOracle(
        client=client,
        calibration_path=calibration_path,
        min_api_calls=min_api_calls,
        k_sigma=k_sigma,
    )


def _synthetic_report(n_api: int, *, with_file_ops: bool = False) -> dict:
    """A minimal CAPE-report-shaped dict with `n_api` api calls (and optionally
    file ops). Matches SandboxVerifier.extract_behavior's expected shape."""
    calls = [{"api": f"NtFoo{i}", "category": "system"} for i in range(n_api)]
    summary = {}
    if with_file_ops:
        summary["files"] = ["C:\\Users\\admin\\x.txt"]
    return {"behavior": {"processes": [{"calls": calls}], "summary": summary}}


# ----------------------------------------------------------------------
# score_reports: non-empty-channel scoring on 7992 vs 7993
# ----------------------------------------------------------------------

def test_score_reports_nonempty_excludes_vacuous_channels():
    """7992-vs-7993 (same PE): api_similarity == 0.8814 and the nonempty
    composite EXCLUDES the 4 empty-in-both channels, so it is NOT 0.9585."""
    r92, r93 = _load_report(7992), _load_report(7993)
    oracle = _make_oracle({7992: r92, 7993: r93})

    score = oracle.score_reports(r92, r93)

    # api_calls is the primary signal and the measured noise floor.
    assert score["api_similarity"] == pytest.approx(0.8814, abs=1e-4)
    assert score["api_counts"]["original"] == 162
    assert score["api_counts"]["mutated"] == 171
    assert score["api_counts"]["common"] == 156

    # Only api_calls + registry_ops carried events; the other 4 are EMPTY in
    # both reports and must be EXCLUDED.
    assert set(score["nonempty_channels"]) == {"api_calls", "registry_ops"}
    for vacuous in ("file_ops", "network_ops", "dropped_files", "mutexes"):
        assert vacuous not in score["nonempty_channels"]

    # The non-empty composite is dominated by api_calls (0.8814) + registry
    # (1.0), re-normalized over weights {0.35, 0.15} -> 0.917. It is NOT the
    # inflated naive composite.
    assert score["raw_compare"]["composite_similarity"] == pytest.approx(0.9585, abs=1e-4)
    assert score["nonempty_composite"] == pytest.approx(0.917, abs=1e-3)
    assert score["nonempty_composite"] < 0.9585


def test_produce_offline_same_pe_yields_behavioral():
    """End-to-end (mocked transport): same-PE pair -> Behavioral whose composite
    is the non-empty composite (not 0.9585)."""
    r92, r93 = _load_report(7992), _load_report(7993)
    oracle = _make_oracle({7992: r92, 7993: r93})

    ev = oracle.produce(b"orig-bytes", b"mut-bytes", timeout=120)
    assert isinstance(ev, Behavioral)
    assert ev.composite == pytest.approx(0.917, abs=1e-3)
    assert ev.composite < 0.9585
    assert ev.scope.input_dist == "cape:win11:t120"
    assert ev.scope.live_out == frozenset({
        "behavior:api", "behavior:file", "behavior:registry",
        "behavior:network", "behavior:dropped", "behavior:mutex",
    })


# ----------------------------------------------------------------------
# Empty-trace gate
# ----------------------------------------------------------------------

def test_empty_trace_gate_returns_unknown():
    """A report with only 3 api calls and no file/reg/net ops -> Unknown
    (a broken-vs-broken pair must never score an admissible similarity)."""
    broken = _synthetic_report(3)
    healthy = _load_report(7992)
    oracle = _make_oracle({1: broken, 2: healthy})

    ev = oracle._evidence_from_reports(broken, healthy, timeout=120)
    assert isinstance(ev, Unknown)
    assert "empty trace" in ev.reason
    assert "orig=3" in ev.reason
    assert ev.false_admit_bound() is None


def test_empty_trace_gate_both_broken_is_unknown_not_one():
    """Empty-vs-empty would score a vacuous 1.0 composite; the gate forces
    Unknown instead."""
    a, b = _synthetic_report(0), _synthetic_report(2)
    oracle = _make_oracle({1: a, 2: b})
    ev = oracle._evidence_from_reports(a, b, timeout=60)
    assert isinstance(ev, Unknown)


# ----------------------------------------------------------------------
# Uncalibrated path: false_admit None -> admit False
# ----------------------------------------------------------------------

def test_uncalibrated_behavioral_does_not_admit():
    """A Behavioral built with NO calibration has false_admit None, and
    funcval.admit(..) is False even at a generous alpha (honest: behavioral
    alone can't gate uncalibrated)."""
    r92, r93 = _load_report(7992), _load_report(7993)
    oracle = _make_oracle({7992: r92, 7993: r93}, calibration_path=None)
    assert oracle.calibrated is False

    ev = oracle.produce(b"a", b"b", timeout=120)
    assert isinstance(ev, Behavioral)
    assert ev.false_admit is None
    assert ev.false_admit_bound() is None
    assert ev.threshold_basis == "UNCALIBRATED"
    # The single gate: no comparable number -> never admits.
    assert funcval.admit(ev, alpha=0.5) is False
    assert funcval.admit(ev, alpha=0.99) is False


# ----------------------------------------------------------------------
# Calibrated path: threshold from positives, false_admit from negatives
# ----------------------------------------------------------------------

def test_calibrated_threshold_and_false_admit_from_negatives(tmp_path):
    """A tiny calibration with positive (mean/stdev) + a negative distribution:
    threshold == pos_mean - k_sigma*pos_stdev, and false_admit is the empirical
    tail fraction of negatives >= threshold."""
    calib = {
        "positive": {"mean": 0.90, "stdev": 0.02, "min": 0.86, "n": 10},
        # 5 known-DIFFERENT pairs; only one (0.90) sits >= threshold (0.84).
        "negative": {"samples": [0.10, 0.30, 0.55, 0.70, 0.90], "n": 5},
    }
    cpath = tmp_path / "behavioral_calibration.json"
    cpath.write_text(json.dumps(calib))

    r92, r93 = _load_report(7992), _load_report(7993)
    oracle = _make_oracle({7992: r92, 7993: r93}, calibration_path=cpath,
                          k_sigma=3.0)

    assert oracle.calibrated is True
    # threshold = 0.90 - 3.0*0.02 = 0.84
    assert oracle._threshold == pytest.approx(0.84, abs=1e-9)
    # false_admit = #{negatives >= 0.84} / 5 = 1/5 = 0.20
    assert oracle._false_admit == pytest.approx(0.20, abs=1e-9)

    ev = oracle.produce(b"a", b"b", timeout=120)
    assert isinstance(ev, Behavioral)
    assert ev.false_admit == pytest.approx(0.20, abs=1e-9)
    assert ev.noise_floor == pytest.approx(0.84, abs=1e-9)
    assert "calibration" in ev.threshold_basis
    # A high-similarity pair with false_admit (0.20) <= alpha (0.5) ADMITS.
    assert funcval.admit(ev, alpha=0.5) is True
    # ... but a stricter budget than the bound does NOT admit.
    assert funcval.admit(ev, alpha=0.1) is False


# ----------------------------------------------------------------------
# REAL calibration file: artifacts/validator/behavioral_calibration.json
# (produced by scripts/behavioral_calibrate.py from EXISTING CAPE reports —
# positive = orig-vs-mutated, negative = cross-sample distinct-malware pairs).
# This pins that the shipped calibration file LOADS and GATES correctly.
# ----------------------------------------------------------------------

_CALIB_FILE = _ROOT / "artifacts" / "validator" / "behavioral_calibration.json"


def _require_calib() -> dict:
    if not _CALIB_FILE.exists():
        pytest.skip(f"{_CALIB_FILE} not present (run scripts/behavioral_calibrate.py)")
    return json.loads(_CALIB_FILE.read_text())


def test_real_calibration_loads_and_derives_measured_false_admit():
    """The shipped behavioral_calibration.json loads, gives a threshold from the
    positive noise floor, and a NON-None MEASURED false_admit from the negative
    cross-pairs (empirical tail fraction over negative['samples'])."""
    calib = _require_calib()
    r92, r93 = _load_report(7992), _load_report(7993)
    oracle = _make_oracle({7992: r92, 7993: r93},
                          calibration_path=_CALIB_FILE, k_sigma=3.0)

    assert oracle.calibrated is True

    # threshold = pos_mean - 3*pos_stdev, from the positive set-Jaccard dist.
    pos = calib["positive"]
    expected_thr = pos["mean"] - 3.0 * pos["stdev"]
    assert oracle._threshold == pytest.approx(expected_thr, abs=1e-9)

    # false_admit = #{negatives >= threshold} / n_neg  (empirical tail fraction).
    neg = calib["negative"]
    k = sum(1 for s in neg["samples"] if s >= oracle._threshold)
    expected_fa = k / len(neg["samples"])
    assert oracle._false_admit is not None
    assert oracle._false_admit == pytest.approx(expected_fa, abs=1e-9)
    # On this data: 2 same-family pairs sit above the threshold -> 2/55.
    assert oracle._false_admit == pytest.approx(2.0 / 55.0, abs=1e-9)


def test_real_calibration_gates_behavioral_evidence():
    """With the real calibration loaded, funcval.admit() of the produced
    Behavioral admits at alpha >= measured false_admit and REFUSES below it."""
    _require_calib()
    r92, r93 = _load_report(7992), _load_report(7993)
    oracle = _make_oracle({7992: r92, 7993: r93},
                          calibration_path=_CALIB_FILE, k_sigma=3.0)

    ev = oracle.produce(b"orig", b"mut", timeout=120)
    assert isinstance(ev, Behavioral)
    fa = ev.false_admit
    assert fa is not None
    assert fa == pytest.approx(2.0 / 55.0, abs=1e-9)
    assert ev.false_admit_bound() == pytest.approx(fa, abs=1e-9)
    assert ev.threshold_basis != "UNCALIBRATED"

    # Gate: admit iff false_admit <= alpha.
    assert funcval.admit(ev, alpha=fa) is True            # exactly at the bound
    assert funcval.admit(ev, alpha=fa + 1e-6) is True     # above the bound
    assert funcval.admit(ev, alpha=fa - 1e-6) is False    # below the bound
    assert funcval.admit(ev, alpha=0.10) is True          # generous budget
    assert funcval.admit(ev, alpha=0.01) is False         # stricter than the CP-bounded rate


def test_calibration_without_negatives_yields_none_false_admit(tmp_path):
    """Positive-only calibration => threshold set but false_admit None: we
    cannot bound false admits without negative examples. Honest -> admit False."""
    calib = {"positive": {"mean": 0.90, "stdev": 0.02, "min": 0.86, "n": 10}}
    cpath = tmp_path / "calib_pos_only.json"
    cpath.write_text(json.dumps(calib))

    r92, r93 = _load_report(7992), _load_report(7993)
    oracle = _make_oracle({7992: r92, 7993: r93}, calibration_path=cpath)

    assert oracle.calibrated is True       # we DO have a threshold
    assert oracle._false_admit is None     # but NO false-admit bound

    ev = oracle.produce(b"a", b"b", timeout=120)
    assert isinstance(ev, Behavioral)
    assert ev.false_admit is None
    assert funcval.admit(ev, alpha=0.99) is False
