"""Lightweight structural integrity checks for mutated PE binaries."""

import os

import lief

CODE_REWRITE_ACTIONS = frozenset(("stoke_rewrite",))
DISABLE_STOKE_FUNC_CHECK_ENV = "MALWARE_RL_DISABLE_STOKE_FUNC_CHECK"


def _env_flag_enabled(name):
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def check_pe_integrity(binary):
    """Return whether *binary* can be parsed as a PE file by LIEF."""
    if not isinstance(binary, (bytes, bytearray)) or not binary:
        return False

    try:
        return lief.PE.parse(list(binary)) is not None
    except Exception:
        return False


def check_functional_integrity(binary, action_name, action_context=None):
    """Check PE structure and require admitted evidence for changed code."""
    if not check_pe_integrity(binary):
        return False
    if action_name not in CODE_REWRITE_ACTIONS:
        return True
    if _env_flag_enabled(DISABLE_STOKE_FUNC_CHECK_ENV):
        return True

    context = action_context if isinstance(action_context, dict) else {}
    if context.get("changed") is False:
        return True
    verdict = context.get("funcval")
    return isinstance(verdict, dict) and verdict.get("passed") is True
