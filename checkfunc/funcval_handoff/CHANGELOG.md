# Changelog

All notable changes to `funcval` are documented here.

## 0.2.0

- **Width-aware verification (`bits=32|64`).** `FunctionValidator.verify_sync`
  now takes a keyword-only `bits` parameter selecting the target architecture
  (`32` = i386 / UC_MODE_32 / CS_MODE_32 / 32-bit library, `64` = x86-64). It
  is threaded into BOTH oracles (library selection, capstone/Unicorn mode, Z3
  bit width, compared register set). Default is `64` for backward compatibility.
- **Bundled 32-bit i386 library** (`data/equiv_library_32bit_verified.json`,
  1476 verified pairs), selected when `bits=32`; the 64-bit library
  (`data/equiv_library_proven_v3_cleaned.json`, 6480 pairs) is selected when
  `bits=64`.
- **Memory-write comparison** added to the local differential oracle.
- **Input-validity guard:** bytes that do not cleanly decode in the stated width
  return `Unknown` instead of a spurious admissible `Sampled(k=0)` — so a 32-bit
  caller who forgets `bits=32` is protected from a silent false-admit rather than
  given a wrong PASS.
- **Env-overridable CAPE config:** `cape_cli_client` reads `FUNCVAL_CAPE_PASSWORD`,
  `FUNCVAL_CAPE_VM_PYTHON`, `FUNCVAL_CAPE_SBX_PATH`, `FUNCVAL_CAPE_ROOT`, and
  `FUNCVAL_CAPE_POETRY_BIN` from the environment, falling back to the lab
  defaults (behavior is identical when unset). The wheel still embeds lab
  defaults; the log-redaction of the password is unchanged.
- **Integration example** `examples/mutate_then_verify.py` demonstrating the
  `stoke_actions` → `funcval` bridge (mutate PE `.text`, then verify the same
  `(orig, var)` fragment at the PE's true width).

> **WARNING — do not use `0.1.0` for 32-bit inputs.** `0.1.0` is 64-bit-only and
> FALSELY ADMITS non-equivalent 32-bit (i386) pairs (e.g. `test eax,eax` vs
> `and eax,eax`, which diverge on the upper 32 bits): it emulated them in 64-bit
> mode and returned a spurious admissible verdict. Use `0.2.0` with `bits=32`
> for any i386 input.

## 0.1.0

- Initial release: typed evidence-ledger functionality-equivalence validator
  (`Proof` / `Sampled` / `Behavioral` / `Refuted` / `Unknown`), single
  `admit(ev, alpha)` gate, proven + local-equiv + behavioral oracles, CAPE
  transport. **64-bit only — unsound on 32-bit inputs (see the 0.2.0 warning).**
