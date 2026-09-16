#!/usr/bin/env python3
"""funcval behavioral-detonation SMOKE test — run ON VM1, talking to the CAPE box.

PURPOSE
=======
End-to-end proof that the funcval behavioral path can drive the CAPE box from
VM1: submit -> poll -> fetch -> score, through the real ``CapeCliClient`` with
``transport="local"`` (we ARE on VM1, so sbx.py + the conda python are local;
the vmctl two-hop would be nonsensical here).

This is a TRANSPORT + SCORING smoke, NOT a malware experiment. We submit the
SAME benign PE as both ``orig`` and ``mut`` (orig == mut). That exercises the
full pipeline and SHOULD yield a Behavioral verdict with HIGH composite
similarity (an identical sample detonated twice scores near 1.0 on the
api-calls channel). It stays HONEST: if either trace is empty (sample never
detonated) or the transport fails, ``collect`` returns Unknown and we exit
non-zero with ``[SMOKE_FAIL]`` — never a spurious pass.

EXPECTED OUTCOME
================
  * Healthy box, sample detonates:  kind == "behavioral",
    composite high (api Jaccard ~1.0). ``false_admit_bound()`` is ``None``
    because the oracle is UNCALIBRATED (no labelled known-different pairs yet) —
    this is the correct, honest state and is treated as a PASS for the SMOKE
    (the smoke proves transport+scoring, not gate admission).
  * Empty trace / transport error:  kind == "unknown" -> ``[SMOKE_FAIL]``.

RUN (on VM1, with the conda python)
===================================
    /home/rl/miniconda3/envs/sorel-malware-detector/bin/python \
        /home/rl/funcval_pkg/examples/behavioral_smoke.py \
        [PE_PATH]

PE_PATH defaults to the benign sample found during prep:
    /home/rl/stoke_workspace/stoke_actions_handoff/sa_sample.exe
"""
from __future__ import annotations

import sys
import time
import traceback

# Default benign sample on VM1 (PE32+ x86-64 console, 14848 bytes) located during
# smoke prep. Override via argv[1].
DEFAULT_PE = "/home/rl/stoke_workspace/stoke_actions_handoff/sa_sample.exe"


def _log(msg: str) -> None:
    """Flushed, marker-prefixed progress line (so the mirrored log shows order)."""
    print(f"[SMOKE] {msg}", flush=True)


def main() -> int:
    pe_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PE
    _log(f"funcval behavioral detonation smoke starting (t0={time.strftime('%H:%M:%S')})")
    _log(f"sample PE path: {pe_path}")

    # --- imports (inside main so an import failure is a clean [SMOKE_FAIL]) ----
    try:
        from funcval import FunctionValidator
        from funcval.oracles.behavioral import BehavioralOracle
        from funcval.cape.cape_cli_client import CapeCliClient
    except Exception as exc:  # noqa: BLE001
        _log(f"import failed: {type(exc).__name__}: {exc}")
        traceback.print_exc()
        print("[SMOKE_FAIL] could not import funcval", flush=True)
        return 2

    # --- read the sample bytes ------------------------------------------------
    try:
        with open(pe_path, "rb") as fh:
            pe_bytes = fh.read()
    except OSError as exc:
        _log(f"could not read sample PE {pe_path!r}: {exc}")
        print("[SMOKE_FAIL] sample PE unreadable", flush=True)
        return 2
    if not pe_bytes:
        _log(f"sample PE {pe_path!r} is empty")
        print("[SMOKE_FAIL] sample PE empty", flush=True)
        return 2
    _log(f"read {len(pe_bytes)} bytes from sample; "
         f"head={pe_bytes[:2]!r} (expect b'MZ')")

    # --- build the validator with an EXPLICIT local-transport CAPE client -----
    # transport="local": we are ON VM1, so <vm_python> sbx.py <b64> runs directly
    # via subprocess (no scripts/vmctl wrapper, which does not exist on VM1).
    try:
        client = CapeCliClient(transport="local")
        behavioral = BehavioralOracle(client=client)
        validator = FunctionValidator(behavioral=behavioral)
    except Exception as exc:  # noqa: BLE001
        _log(f"validator construction failed: {type(exc).__name__}: {exc}")
        traceback.print_exc()
        print("[SMOKE_FAIL] validator construction failed", flush=True)
        return 2
    _log(f"validator built: transport={client.transport!r} "
         f"guests={client.guests} analysis_deadline={client.analysis_deadline}s "
         f"submit_grace={client.submit_grace}s")

    # --- submit (orig == mut) -------------------------------------------------
    # Identical bytes for both arms: a transport+scoring smoke, not a real
    # equivalence experiment. Should detonate twice and score ~1.0 on api_calls.
    _log("submitting detonation pair (orig == mut, same benign bytes)...")
    try:
        handle = validator.verify_async(pe_bytes, pe_bytes)
    except Exception as exc:  # noqa: BLE001
        _log(f"verify_async (submit) failed: {type(exc).__name__}: {exc}")
        traceback.print_exc()
        print("[SMOKE_FAIL] submit failed", flush=True)
        return 1
    _log(f"submitted. handle={handle}  "
         f"(orig_task={handle.get('orig_task')} mut_task={handle.get('mut_task')} "
         f"guests={handle.get('guests')})")
    _log("polling to terminal + fetching reports (this is the slow part; "
         f"deadline ~{client.analysis_deadline}s)...")

    # --- collect (poll -> fetch -> score -> gate) -----------------------------
    t_submit = time.monotonic()
    try:
        ev = validator.collect_async(handle)
    except Exception as exc:  # noqa: BLE001
        _log(f"collect_async raised: {type(exc).__name__}: {exc}")
        traceback.print_exc()
        print("[SMOKE_FAIL] collect raised", flush=True)
        return 1
    dt = time.monotonic() - t_submit
    _log(f"collect_async returned after {dt:.1f}s")

    # --- report the typed Evidence -------------------------------------------
    _log(f"evidence.kind            = {ev.kind}")
    _log(f"false_admit_bound()      = {ev.false_admit_bound()}")

    if ev.kind == "behavioral":
        # Behavioral fields (see funcval.evidence.Behavioral).
        _log(f"composite                = {ev.composite}")
        _log(f"noise_floor              = {ev.noise_floor}")
        _log(f"threshold_basis          = {ev.threshold_basis}")
        _log(f"coverage                 = {ev.coverage}")
        scope = ev.scope
        if scope is not None:
            _log(f"scope.live_out           = {sorted(scope.live_out)}")
            _log(f"scope.input_dist         = {scope.input_dist}")
        # false_admit_bound() is None while UNCALIBRATED — that is the honest,
        # expected state and is a PASS for this transport smoke. The smoke proves
        # the pipeline produced a real Behavioral verdict with a composite score.
        bound = ev.false_admit_bound()
        if bound is None:
            _log("false_admit_bound is None -> oracle UNCALIBRATED (expected; "
                 "behavioral evidence reports similarity but does not clear the "
                 "gate alone). This is a PASS for the transport smoke.")
        _log("PASS criterion: a real Behavioral verdict with a composite score "
             "was produced end-to-end (submit->poll->fetch->score).")
        print("[SMOKE_OK] behavioral pipeline end-to-end OK "
              f"(kind=behavioral composite={ev.composite} bound={bound})",
              flush=True)
        return 0

    if ev.kind == "unknown":
        # Honest non-pass: empty trace, non-DONE task, fetch failure, or transport
        # error. The reason string carries the cause.
        reason = getattr(ev, "reason", "<no reason>")
        _log(f"UNKNOWN reason           = {reason}")
        _log("This is the HONEST non-pass path (empty trace / transport error / "
             "task did not complete). NOT a spurious admit, but the smoke did not "
             "prove a live scored detonation.")
        print(f"[SMOKE_FAIL] evidence was Unknown: {reason}", flush=True)
        return 1

    # Any other kind is unexpected for the behavioral path.
    _log(f"unexpected evidence kind {ev.kind!r}")
    print(f"[SMOKE_FAIL] unexpected evidence kind {ev.kind!r}", flush=True)
    return 1


if __name__ == "__main__":
    try:
        rc = main()
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - last-resort guard, never crash silent
        print(f"[SMOKE] uncaught {type(exc).__name__}: {exc}", flush=True)
        traceback.print_exc()
        print("[SMOKE_FAIL] uncaught exception", flush=True)
        rc = 3
    sys.exit(rc)
