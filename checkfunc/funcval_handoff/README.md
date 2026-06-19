# funcval

Decide whether two x86-64 byte sequences are **functionally equivalent**, and get
back typed **evidence** — `Proof` / `Sampled` / `Behavioral` / `Refuted` /
`Unknown` — instead of a vague confidence score. One gate: `admit(ev, alpha)`
passes iff `ev.false_admit_bound() <= alpha`.

## Install (on VM1)

```bash
conda activate sorel-malware-detector
pip install funcval-0.2.0-py3-none-any.whl[proofs]   # core dep: unicorn; [proofs]: capstone + z3
```

## Valid inputs (read this first)

`funcval` verifies **instruction-aligned bytes** — a single instruction or a
fully-decoding instruction sequence — at matching offsets and at a stated width.
Do **not** pass whole PEs or arbitrary blobs: the input-validity guard returns
`Unknown` (it will **not** silently PASS). Extract the *changed fragment* and
verify that. For the `stoke_actions` → `funcval` bridge (mutate a PE's `.text`,
then verify each rewrite) see [`examples/mutate_then_verify.py`](examples/mutate_then_verify.py).

## Use

```python
import funcval
v = funcval.FunctionValidator()
# verify_sync(orig, mut, *, bits=64). `bits` MUST match the target arch:
# 32 for i386, 64 for x86-64. It defaults to 64; a 32-bit fragment verified at
# the default 64-bit width is caught by the decode guard (-> Unknown) or
# correctly Refuted, so a 32-bit user who forgets is PROTECTED from a silent
# false-admit, not given a wrong PASS.
ev = v.verify_sync(bytes.fromhex("4889ec"), bytes.fromhex("488be5"), bits=64)  # mov rsp,rbp ≡ alt encoding
print(ev.kind, ev.false_admit_bound(), funcval.admit(ev, alpha=0.05))  # -> proof 0.0 True

# i386 example: test eax,eax ≡ and eax,eax is equivalent ONLY at 32-bit width.
ev32 = v.verify_sync(bytes.fromhex("85c0"), bytes.fromhex("21c0"), bits=32)
print(ev32.kind, funcval.admit(ev32, alpha=0.05))                      # -> sampled True (at bits=32)
```

The bundled `data/` ships BOTH libraries, selected by `bits`:
`equiv_library_proven_v3_cleaned.json` (64-bit, 6480 entries) and
`equiv_library_32bit_verified.json` (32-bit i386, 1476 entries).

Behavioral check (live CAPE detonation, run **on VM1**):

```python
from funcval.oracles.behavioral import BehavioralOracle
from funcval.cape.cape_cli_client import CapeCliClient
v = funcval.FunctionValidator(behavioral=BehavioralOracle(client=CapeCliClient(transport="local")))
# orig_bytes, mut_bytes = your instruction-fragment pair (e.g. bytes.fromhex(...))
ev = v.collect_async(v.verify_async(orig_bytes, mut_bytes))            # -> Behavioral (similarity)
```

Behavioral ships **uncalibrated**: it reports similarity but never admits a pair on its own.

## More

- **`HANDOFF.md`** — one-page start · **`USAGE.md`** — full API + scope/honesty limits · `examples/` — runnable.
- `python -m pytest tests/funcval` → **~106 passed, 8 skipped** (offline behavioral
  fixtures) on the VM conda env. In a non-conda env a broken `z3-solver` native
  lib (`libz3.so` fails to load) may cause that one z3 test to **skip** (now
  hardened) — that is an environment issue, not a defect.

MIT.
