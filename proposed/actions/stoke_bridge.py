"""Python 3.7 bridge for the STOKE worker subprocess.

This module never imports ``stoke_actions`` directly. All worker execution is
isolated behind a subprocess so the core RL runtime stays Python 3.7-compatible.
"""

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_N = 8
DEFAULT_REWRITES = "proven_v3_cleaned"
DEFAULT_TIMEOUT = 60.0
_DEFAULT_WORKER = str(Path(__file__).resolve().parent / "stoke_worker.py")


def _fail(original, reason):
    logger.warning("stoke action fallback: %s", reason)
    return original, {
        "action": "stoke_rewrite",
        "changed": False,
        "reason": reason,
        "funcval": {"ran": False, "passed": False, "reason": reason},
    }


def _load_int_env(name, default=None):
    value = os.environ.get(name)
    if value in (None, ""):
        return default
    return int(value)


def _load_float_env(name, default):
    value = os.environ.get(name)
    if value in (None, ""):
        return default
    return float(value)


def _parse_status(stdout_text):
    lines = (stdout_text or "").strip().splitlines()
    if not lines:
        return None
    return json.loads(lines[-1])


def apply_stoke_action_with_report(
    pe_bytes, seed=None, n=None, rewrites=None, timeout=None
):
    """Apply STOKE mutations through the Python >=3.9 worker.

    Returns the original bytes on any failure so the RL loop never crashes.
    """
    if not isinstance(pe_bytes, (bytes, bytearray)):
        return pe_bytes, {
            "action": "stoke_rewrite",
            "changed": False,
            "reason": "input is not bytes",
            "funcval": {"ran": False, "passed": False, "reason": "input is not bytes"},
        }

    original = bytes(pe_bytes)

    try:
        stoke_python = os.environ.get("STOKE_PYTHON", "python3.9")
        worker_path = os.environ.get("STOKE_WORKER", _DEFAULT_WORKER)

        if n is None:
            n = _load_int_env("STOKE_N", DEFAULT_N)
        if rewrites is None:
            rewrites = os.environ.get("STOKE_REWRITES", DEFAULT_REWRITES)
        if timeout is None:
            timeout = _load_float_env("STOKE_TIMEOUT", DEFAULT_TIMEOUT)
        if seed is None:
            seed = _load_int_env("STOKE_SEED", None)
    except (TypeError, ValueError) as exc:
        return _fail(original, "bad STOKE_* env: %r" % exc)

    if not os.path.isfile(worker_path):
        return _fail(original, "worker not found: %s" % worker_path)

    try:
        with tempfile.TemporaryDirectory(prefix="stoke_action_") as temp_dir:
            temp_dir = Path(temp_dir)
            input_path = temp_dir / "input.exe"
            output_path = temp_dir / "output.exe"
            input_path.write_bytes(original)

            command = [
                stoke_python,
                worker_path,
                "--input",
                str(input_path),
                "--output",
                str(output_path),
                "--n",
                str(int(n)),
                "--rewrites",
                str(rewrites),
            ]
            if seed is not None:
                command.extend(["--seed", str(int(seed))])

            proc = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=float(timeout),
                universal_newlines=True,
            )

            status = None
            try:
                status = _parse_status(proc.stdout)
            except Exception:
                status = None

            if proc.returncode != 0:
                if status and not status.get("ok"):
                    return _fail(original, "worker error: %s" % status.get("error"))
                err_text = (proc.stderr or "").strip()[:200]
                return _fail(original, "rc=%s err=%s" % (proc.returncode, err_text))

            if not status:
                return _fail(original, "missing or invalid JSON status")
            if not status.get("ok"):
                return _fail(original, "worker ok=false: %s" % status.get("error"))
            if not output_path.exists():
                return _fail(original, "no output file")

            mutated = output_path.read_bytes()
            if not mutated:
                return _fail(original, "empty output")
            if len(mutated) != len(original):
                return _fail(
                    original,
                    "size mismatch %d!=%d" % (len(mutated), len(original)),
                )
            report = dict(status)
            report.setdefault("action", "stoke_rewrite")
            report["changed"] = mutated != original
            report.setdefault(
                "funcval",
                {
                    "ran": False,
                    "passed": False,
                    "reason": "worker did not return funcval metadata",
                },
            )
            funcval_report = report["funcval"]
            logger.info(
                "action=stoke_rewrite changed=%s bits=%s funcval_ran=%s "
                "funcval_pass=%s cape_enabled=%s reason=%s",
                report["changed"],
                report.get("bits", funcval_report.get("bits")),
                funcval_report.get("ran"),
                funcval_report.get("passed"),
                funcval_report.get("cape_enabled"),
                funcval_report.get("reason", ""),
            )
            return mutated, report
    except subprocess.TimeoutExpired:
        return _fail(original, "timeout")
    except Exception as exc:
        return _fail(original, "exception: %r" % exc)


def apply_stoke_action(pe_bytes, seed=None, n=None, rewrites=None, timeout=None):
    """Backward-compatible bytes-only STOKE API."""
    mutated, _report = apply_stoke_action_with_report(
        pe_bytes,
        seed=seed,
        n=n,
        rewrites=rewrites,
        timeout=timeout,
    )
    return mutated
