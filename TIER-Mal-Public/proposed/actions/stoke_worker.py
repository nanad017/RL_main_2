#!/usr/bin/env python3
"""Python >=3.9 STOKE worker with local funcval synchronisation checks."""

import argparse
import json
import os
import random
import struct
import sys
from pathlib import Path


def emit(payload, code=0):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()
    raise SystemExit(code)


def pe_bits(pe_bytes):
    """Read i386/x86-64 width from the PE COFF Machine field."""
    if len(pe_bytes) < 0x40 or pe_bytes[:2] != b"MZ":
        raise ValueError("not a PE (missing MZ header)")
    pe_offset = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    if pe_bytes[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise ValueError("not a PE (missing PE signature)")
    machine = struct.unpack_from("<H", pe_bytes, pe_offset + 4)[0]
    if machine == 0x14C:
        return 32
    if machine == 0x8664:
        return 64
    raise ValueError("unsupported COFF Machine 0x%04x" % machine)


def _evidence_report(evidence, admitted):
    bound = evidence.false_admit_bound()
    report = {
        "kind": str(evidence.kind),
        "false_admit_bound": bound,
        "passed": bool(admitted),
    }
    for name in ("composite", "api_similarity", "reason"):
        value = getattr(evidence, name, None)
        if value is not None and isinstance(value, (str, int, float, bool)):
            report[name] = value
    return report


def _normalise_pair(pair):
    if isinstance(pair, dict):
        original = pair.get("orig_bytes", pair.get("original"))
        mutated = pair.get("mut_bytes", pair.get("mutated"))
    elif isinstance(pair, (tuple, list)) and len(pair) >= 2:
        original, mutated = pair[0], pair[1]
    else:
        raise ValueError("invalid rewrite pair")
    if not isinstance(original, (bytes, bytearray)) or not isinstance(
        mutated, (bytes, bytearray)
    ):
        raise ValueError("rewrite pair must contain bytes")
    return bytes(original), bytes(mutated)


def _mutate_with_pairs(stoke_actions, pe_bytes, args):
    kwargs = {"n": args.n, "rewrites": args.rewrites, "seed": args.seed}
    mutate_with_report = getattr(stoke_actions, "mutate_with_report", None)
    if mutate_with_report is None:
        return _apply_reportable_rewrites(stoke_actions, pe_bytes, args)
    result = mutate_with_report(pe_bytes, **kwargs)

    pairs = []
    if isinstance(result, dict):
        mutated = result.get("bytes", result.get("mutated"))
        pairs = result.get("rewrite_pairs", result.get("rewrites", []))
    elif isinstance(result, (tuple, list)) and len(result) == 2:
        mutated, report = result
        pairs = report.get("rewrite_pairs", []) if isinstance(report, dict) else report
    else:
        mutated = result
    return mutated, [_normalise_pair(pair) for pair in (pairs or [])]


def _apply_reportable_rewrites(stoke_actions, pe_bytes, args):
    """Apply STOKE's own aligned rewrite pairs while retaining their metadata."""
    get_rewrites = getattr(stoke_actions, "get_rewrites", None)
    catalog = get_rewrites(args.rewrites) if callable(get_rewrites) else stoke_actions.DEFAULT_REWRITES
    catalog = [
        _normalise_pair(pair)
        for pair in catalog
        if isinstance(pair, (tuple, list, dict))
    ]
    rng = random.Random(args.seed)
    mutated = bytes(pe_bytes)
    applied = []

    for _ in range(max(0, args.n)):
        candidates = []
        for original, variant in catalog:
            if len(original) != len(variant) or original == variant:
                continue
            sites = stoke_actions.find_rewrite_sites(mutated, original)
            candidates.extend((offset, original, variant) for offset in sites)
        if not candidates:
            break
        offset, original, variant = rng.choice(candidates)
        end = offset + len(original)
        if mutated[offset:end] != original:
            continue
        mutated = mutated[:offset] + variant + mutated[end:]
        applied.append((original, variant))

    return mutated, applied


def verify_pairs(rewrite_pairs, bits, alpha):
    """Verify every instruction pair with local functional equivalence evidence."""
    import funcval

    validator = funcval.FunctionValidator()
    reports = []
    for original, mutated in rewrite_pairs:
        sync_ev = validator.verify_sync(original, mutated, bits=bits)
        sync_pass = funcval.admit(sync_ev, alpha=alpha)
        item = {
            "orig_hex": original[:32].hex(),
            "mut_hex": mutated[:32].hex(),
            "sync": _evidence_report(sync_ev, sync_pass),
        }

        sync_refuted = str(sync_ev.kind).lower() == "refuted"
        item["passed"] = False if sync_refuted else bool(sync_pass)
        reports.append(item)

    return {
        "ran": bool(reports),
        "passed": bool(reports) and all(item["passed"] for item in reports),
        "alpha": alpha,
        "bits": bits,
        "validator": "sync",
        "pairs": reports,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--n", type=int, default=8)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--rewrites", default="proven_v3_cleaned")
    args = parser.parse_args()

    try:
        import stoke_actions

        pe_bytes = Path(args.input).read_bytes()
        if not pe_bytes:
            emit({"ok": False, "error": "empty input"}, code=2)
        bits = pe_bits(pe_bytes)
        mutated, rewrite_pairs = _mutate_with_pairs(stoke_actions, pe_bytes, args)
        if not isinstance(mutated, (bytes, bytearray)):
            emit({"ok": False, "error": "stoke returned non-bytes"}, code=3)
        mutated = bytes(mutated)
        if len(mutated) != len(pe_bytes):
            emit({"ok": False, "error": "size changed"}, code=4)

        changed = mutated != pe_bytes
        alpha = float(os.environ.get("FUNCVAL_ALPHA", "0.05"))
        if rewrite_pairs:
            funcval_report = verify_pairs(rewrite_pairs, bits, alpha)
        else:
            reason = "no changed bytes" if not changed else "missing rewrite metadata"
            funcval_report = {
                "ran": False,
                "passed": not changed,
                "alpha": alpha,
                "bits": bits,
                "validator": "sync",
                "reason": reason,
                "pairs": [],
            }

        Path(args.output).write_bytes(mutated)
        emit(
            {
                "ok": True,
                "action": "stoke_rewrite",
                "input_size": len(pe_bytes),
                "output_size": len(mutated),
                "changed": changed,
                "bits": bits,
                "funcval": funcval_report,
            }
        )
    except Exception as exc:
        emit({"ok": False, "error": repr(exc)}, code=1)


if __name__ == "__main__":
    main()
