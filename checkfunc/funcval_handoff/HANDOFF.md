# funcval — handoff (start here)

A typed evidence-ledger functionality-equivalence validator for x86-64
mutations. This page is the copy-paste start for a collaborator operating on
**VM1**. For the overview read `README.md`; for the full API, evidence model,
and scope limits read `USAGE.md`.

---

## 1. Install (30 seconds, on VM1)

```bash
conda activate sorel-malware-detector
pip install /path/to/funcval-0.2.0-py3-none-any.whl[proofs]
```

The `[proofs]` extra pulls in `capstone` + `z3-solver` so the proven oracle can
emit re-checkable certificates. The wheel lives in this package under
`dist/funcval-0.2.0-py3-none-any.whl` (source dist: `dist/funcval-0.2.0.tar.gz`).

Validated on VM1: `~106 passed, 8 skipped, 0 failed`; sync smoke green; live CAPE
behavioral detonation proved end-to-end (composite ≈ 0.993).

---

## 2. Sync usage (no sandbox needed)

```python
import funcval

v = funcval.FunctionValidator()

orig = bytes.fromhex("4889ec")   # mov rsp, rbp
mut  = bytes.fromhex("488be5")   # mov rsp, rbp (alternate encoding)

# verify_sync(orig, mut, *, bits=64). `bits` MUST match the target arch:
# 32 for i386, 64 for x86-64. Omitting it defaults to 64; a 32-bit fragment
# verified at the default 64-bit width is caught by the decode guard (-> Unknown)
# or correctly Refuted — a 32-bit user who forgets is PROTECTED from a silent
# false-admit, not given a wrong PASS.
ev = v.verify_sync(orig, mut, bits=64)     # -> typed Evidence
print(ev.kind, ev.false_admit_bound())     # e.g. "proof" 0.0
print(funcval.admit(ev, alpha=0.05))       # THE single gate -> True for a re-checkable proof
```

**Valid inputs:** pass INSTRUCTION-ALIGNED bytes (one instruction or a
fully-decoding sequence) at a stated width — NOT a whole PE / arbitrary blob
(the guard returns `Unknown`, never a silent PASS). The bundled `data/` ships
BOTH libraries selected by `bits`: `equiv_library_proven_v3_cleaned.json`
(64-bit, 6480) and `equiv_library_32bit_verified.json` (32-bit i386, 1476).

Or just run the bundled examples:

```bash
python examples/quickstart.py          # the sync gate
python examples/mutate_then_verify.py  # the stoke_actions -> funcval bridge
```

---

## 3. Behavioral usage (live CAPE detonation, on VM1)

```python
from funcval import FunctionValidator
from funcval.oracles.behavioral import BehavioralOracle
from funcval.cape.cape_cli_client import CapeCliClient

client = CapeCliClient(transport="local")          # already on VM1: calls sbx.py directly
v = FunctionValidator(behavioral=BehavioralOracle(client=client))

# orig_bytes, mut_bytes = your instruction-fragment pair (e.g. bytes.fromhex(...))
if v.behavioral is not None:
    handle = v.verify_async(orig_bytes, mut_bytes)  # non-blocking submit
    ev = v.collect_async(handle)                     # later: typed Evidence
    print(ev.kind, ev.false_admit_bound())
```

`transport="auto"` (the default) also picks `"local"` automatically when run on
VM1 (no `scripts/vmctl` present), so you can omit the arg. Or run the bundled
example end-to-end:

```bash
python examples/behavioral_smoke.py
```

---

## 4. Honesty one-liner

The behavioral oracle ships **uncalibrated**: it reports a similarity signal
(and `composite`) but its `false_admit` bound is `None`, so it does **not**
admit a pair on behavioral evidence alone. This is intentional — see USAGE
"Calibration (optional — ships uncalibrated by design)" for how to calibrate on
your own corpus.

---

## 5. Run the tests

```bash
python -m pytest tests/funcval
```

Expect **~106 passed, 8 skipped** (offline behavioral fixtures) on the VM conda
env. The orchestrator confirms the exact numbers. Honest caveat: in a non-conda
env a broken `z3-solver` native lib (`libz3.so` fails to load at call time) may
cause that one z3 test to **skip** (it is now hardened to skip cleanly rather
than fail) — an environment issue, not a defect. See USAGE §9 "Test suite notes".

---

## 6. Where to read more

- **`README.md`** — overview, install, 60-second quick start.
- **`USAGE.md`** — full API, evidence model (`Refuted`/`Proof`/`Sampled`/
  `Behavioral`/`Unknown`), the `compose`/`admit` contract, scope/honesty limits,
  CAPE wiring, and calibration.
