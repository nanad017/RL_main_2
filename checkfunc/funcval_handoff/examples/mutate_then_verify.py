#!/usr/bin/env python3
"""mutate_then_verify — the collaborator's actual workflow: stoke_actions -> funcval.

THE BRIDGE THIS EXAMPLE DEMONSTRATES
====================================
The friend mutates a Windows PE's executable (``.text``) section in place with
the ``stoke_actions`` package (size-preserving, instruction-aligned rewrites),
then must CHECK that each rewrite preserved functionality. ``funcval`` is the
checker. The correct composition is:

    the SAME ``(orig, var)`` instruction-fragment pair that stoke_actions
    SPLICES into the binary is exactly what funcval VERIFIES, at the PE's
    TRUE architecture width.

WHAT IS (AND IS NOT) A VALID funcval INPUT
==========================================
``funcval.verify_sync(orig, mut, *, bits=...)`` verifies INSTRUCTION-ALIGNED
byte fragments — a single instruction or a fully-decoding instruction sequence
— at a stated width. Concretely:

  * VALID:   the changed fragment, e.g. ``b"\\x85\\xc0"`` (``test eax,eax``) vs
             ``b"\\x09\\xc0"`` (``or eax,eax``).  This is what stoke_actions'
             ``(orig, var)`` rewrite pairs ARE.
  * INVALID: the whole PE buffer (or any arbitrary blob).  funcval's
             input-validity guard returns ``Unknown`` for bytes that do not
             cleanly decode at the chosen width — it will NOT silently PASS a
             whole PE. So extract the CHANGED FRAGMENT bytes and pass those, not
             the megabytes of PE around them.

WIDTH MATTERS (the footgun this package closes)
===============================================
``bits`` MUST match the target architecture: ``32`` for i386, ``64`` for
x86-64. Omitting it defaults to ``64``. A 32-bit fragment verified at the
default 64-bit width is either correctly Refuted (e.g. the upper-32
zero-extension hazard) or returns ``Unknown`` from the decode guard — never a
silent wrong PASS. We read the width FROM THE PE HEADER (COFF Machine field) so
the fragment is always verified at the binary's real width.

CIRCULARITY NOTE (read before over-trusting a Proof here)
=========================================================
The pairs in ``stoke_actions.DEFAULT_REWRITES`` / its bundled libraries are
drawn from the SAME proven equivalence tables funcval ships, so verifying one
is PARTIALLY CIRCULAR: funcval's ProvenOracle finds it in the library and emits
a ``Proof`` (bound 0.0). That confirms the bridge wiring and the width handling,
but it is not an independent re-derivation. The genuinely-NOVEL case is an
algorithmic ``stoke_actions.mutate()`` fragment that is NOT a library entry:
there funcval escalates to the Unicorn full-state differential oracle and
returns a ``Sampled(k=0)`` bound (or a ``Refuted`` if the mutation actually
broke semantics) — that is the real check.

RUN (on VM1, where stoke_actions + unicorn + capstone are installed)
====================================================================
    python examples/mutate_then_verify.py [PE_PATH]

PE_PATH defaults to the bundled handoff sample if present, else argv[1] is
required. This example is NOT run during packaging (it needs VM + deps); it is
``py_compile``-checked only.
"""
from __future__ import annotations

import struct
import sys

# Default benign handoff sample on VM1 (override via argv[1]).
DEFAULT_PE = "/home/rl/stoke_workspace/stoke_actions_handoff/sa_sample.exe"

# COFF Machine field values (PE header) -> funcval `bits`.
IMAGE_FILE_MACHINE_I386 = 0x14C   # i386  -> bits=32
IMAGE_FILE_MACHINE_AMD64 = 0x8664  # x86-64 -> bits=64


def pe_bits(pe_bytes: bytes) -> int:
    """Return 32 or 64 by reading the PE COFF Machine field (pure struct, no LIEF).

    Layout: the DOS header at offset 0x3C holds a 4-byte little-endian pointer to
    the PE signature ("PE\\0\\0"); the COFF file header begins immediately after
    that 4-byte signature, and its FIRST field is the 2-byte little-endian
    Machine value. 0x14C = i386 (bits=32); 0x8664 = AMD64 (bits=64).
    """
    if len(pe_bytes) < 0x40 or pe_bytes[:2] != b"MZ":
        raise ValueError("not a PE (no MZ header)")
    pe_off = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    if pe_bytes[pe_off:pe_off + 4] != b"PE\x00\x00":
        raise ValueError("not a PE (no PE\\0\\0 signature)")
    machine = struct.unpack_from("<H", pe_bytes, pe_off + 4)[0]
    if machine == IMAGE_FILE_MACHINE_I386:
        return 32
    if machine == IMAGE_FILE_MACHINE_AMD64:
        return 64
    raise ValueError(f"unsupported COFF Machine 0x{machine:04x} "
                     "(only i386 0x14c / AMD64 0x8664 are mapped)")


def main() -> int:
    pe_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PE
    print("=" * 72)
    print("stoke_actions -> funcval bridge: mutate .text, then verify each rewrite")
    print("=" * 72)
    print(f"sample PE: {pe_path}")

    # --- guarded imports: a missing dep prints guidance, never a raw crash ----
    try:
        import stoke_actions
    except ImportError:
        print("[SKIP] stoke_actions is not installed in this environment.")
        print("       Install it on VM1 (it ships the .text mutation API):")
        print("           pip install stoke_actions   # plus [disasm] for capstone")
        print("       This example needs it to produce the (orig, var) rewrite pairs.")
        return 0

    try:
        import funcval
    except ImportError:
        print("[SKIP] funcval is not installed; pip install the funcval wheel first.")
        return 0

    # --- read the PE and determine its TRUE width from the header -------------
    try:
        with open(pe_path, "rb") as fh:
            pe_bytes = fh.read()
    except OSError as exc:
        print(f"[SKIP] could not read sample PE {pe_path!r}: {exc}")
        print("       Pass a PE path as argv[1].")
        return 0

    bits = pe_bits(pe_bytes)
    print(f"PE width from COFF Machine field: bits={bits} "
          f"({'i386' if bits == 32 else 'x86-64'})")
    print("-" * 72)

    v = funcval.FunctionValidator()
    alpha = 0.05

    # --- pick rewrite pairs from stoke_actions.DEFAULT_REWRITES ---------------
    # DEFAULT_REWRITES is a list of (orig_bytes, var_bytes, description). These are
    # the SAME (orig, var) fragments stoke_actions would splice into .text. We
    # verify the FRAGMENTS (instruction-aligned, valid funcval input) — NOT the
    # whole PE buffer (which the input-validity guard would return Unknown for).
    #
    # We prefer pairs that actually OCCUR in this PE's .text (so the demo mirrors
    # a real mutation site), but fall back to the first few table pairs so the
    # example always prints something even if no site matches this sample.
    rewrites = list(stoke_actions.DEFAULT_REWRITES)

    def occurs_in_pe(orig: bytes) -> bool:
        try:
            # aligned=True is the SOUND, instruction-boundary-aware site finder
            # (needs capstone). Fall back to a presence check if capstone absent.
            return len(stoke_actions.find_rewrite_sites(pe_bytes, orig)) > 0
        except ImportError:
            return orig in pe_bytes

    matching = [(o, var, desc) for (o, var, desc) in rewrites if occurs_in_pe(o)]
    chosen = (matching or rewrites)[:5]
    if matching:
        print(f"{len(matching)} rewrite pair(s) have aligned sites in this PE; "
              f"verifying up to {len(chosen)} of them.")
    else:
        print("No rewrite pair has an aligned site in this PE; verifying the "
              f"first {len(chosen)} library pairs as a wiring demo instead.")
    print("-" * 72)

    # --- the COMPOSITION: same (orig, var) stoke_actions applies -> funcval ----
    for orig, var, desc in chosen:
        # `bits=<PE width>` is the load-bearing argument: verify the fragment at
        # the binary's TRUE architecture. Omitting it would default to 64 and the
        # input guard would protect a 32-bit user with Unknown rather than a wrong
        # PASS — but here we pass the matching width so genuine pairs admit.
        ev = v.verify_sync(orig, var, bits=bits)
        bound = ev.false_admit_bound()
        admitted = funcval.admit(ev, alpha)
        print(f"  orig={orig.hex():<12} var={var.hex():<12} bits={bits}  {desc}")
        print(f"    -> kind={ev.kind:<9} false_admit_bound={bound}  "
              f"admit(alpha={alpha})={admitted}")
        # Interpretation: a library pair -> Proof (bound 0.0) is PARTIALLY
        # CIRCULAR (funcval found it in the same proven table). A NOVEL
        # algorithmic mutate() fragment would instead yield Sampled(k=0) from the
        # Unicorn differential (the genuinely-independent check) or Refuted.

    print("-" * 72)
    print("Note: whole-PE bytes are NOT valid funcval input — pass the changed")
    print("fragment bytes (the same (orig, var) stoke_actions splices), at the")
    print("PE's true width. For a genuinely-novel check, verify a stoke_actions")
    print(".mutate() fragment that is not a library entry (funcval -> Sampled).")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
