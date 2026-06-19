#!/usr/bin/env python3
"""funcval quick-start — a self-contained, runnable example.

Builds a ``FunctionValidator``, verifies a real proven equivalence pair pulled
from the BUNDLED library, prints the resulting typed Evidence and the gate
decision, and shows the (guarded) optional async CAPE behavioral path.

Run it from the package (after install, or with PYTHONPATH=src):

    python examples/quickstart.py

Requires ``unicorn`` (a core dependency) for the escalation path, and benefits
from the ``[proofs]`` extra (capstone/z3) so the proven oracle can emit a
re-checkable Proof. Without capstone, proven entries degrade to Unknown and the
gate falls through to the Unicorn-sampled bound — still a valid run.
"""
from __future__ import annotations

import json

import funcval
from funcval.oracles.proven import resolve_library_path


def _first_decode_identical_pair():
    """Return (orig_bytes, mut_bytes, asm) for the first DECODE_IDENTICAL-style
    proven pair (``alt_modrm_d_bit_swap``) in the bundled library, falling back
    to the first entry of any kind. These pairs are two encodings of the SAME
    instruction, so the proven oracle returns a real Proof with only capstone.
    """
    lib = json.loads(resolve_library_path().read_text())
    entries = lib["entries"] if isinstance(lib, dict) and "entries" in lib else lib

    chosen = None
    for ent in entries:
        if ent.get("proof_pattern") == "alt_modrm_d_bit_swap":
            chosen = ent
            break
    if chosen is None:
        chosen = entries[0]

    orig = bytes.fromhex(chosen["original_hex"])
    mut = bytes.fromhex(chosen["variant_hex"])
    asm = f'{chosen.get("original_asm", "?")}  <->  {chosen.get("variant_asm", "?")}'
    return orig, mut, asm


def main() -> None:
    v = funcval.FunctionValidator()

    orig, mut, asm = _first_decode_identical_pair()
    print("=" * 70)
    print("funcval quick-start")
    print("=" * 70)
    print(f"orig bytes : {orig.hex()}")
    print(f"mut  bytes : {mut.hex()}")
    print(f"asm        : {asm}")
    print("-" * 70)

    # 1) The synchronous gate: typed Evidence, not a bare bool / float.
    ev = v.verify_sync(orig, mut)
    print(f"verify_sync -> Evidence kind     : {ev.kind}")
    print(f"             false_admit_bound() : {ev.false_admit_bound()}")
    scope = ev.scope
    if scope is not None:
        print(f"             scope.live_out      : {sorted(scope.live_out)}")
        if scope.notes:
            print(f"             scope.notes         : {scope.notes}")

    # 2) THE single gate. A re-checkable Proof admits at any alpha >= 0; an
    #    Unknown (e.g. capstone absent) never admits.
    alpha = 0.05
    print("-" * 70)
    print(f"admit(ev, alpha={alpha})            : {funcval.admit(ev, alpha)}")
    print(f"validator.admissible(ev)         : {v.admissible(ev)}")

    # 3) Optional async CAPE behavioral path — only when a behavioral oracle was
    #    configured (it needs a live CAPE box). The default validator has none,
    #    so this branch is skipped honestly rather than crashing.
    print("-" * 70)
    if v.behavioral is not None:
        print("behavioral oracle present: submitting async CAPE detonation...")
        handle = v.verify_async(orig, mut)
        beh_ev = v.collect_async(handle)
        print(f"  collect_async -> {beh_ev.kind}  bound={beh_ev.false_admit_bound()}")
        print(f"  admit(behavioral, {alpha}) = {funcval.admit(beh_ev, alpha)}")
    else:
        print("behavioral oracle: NOT configured (validator.behavioral is None).")
        print("  The CAPE path is optional and needs a reachable sandbox. To enable:")
        print("    from funcval.oracles.behavioral import BehavioralOracle")
        print("    from funcval.cape.cape_cli_client import CapeCliClient")
        print("    v = FunctionValidator(behavioral=BehavioralOracle(client=CapeCliClient(...)))")
    print("=" * 70)


if __name__ == "__main__":
    main()
