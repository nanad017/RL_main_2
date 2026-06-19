# funcval — Usage & API reference

`funcval` validates that a mutated x86-64 byte sequence is functionally
equivalent to the original, and returns a **typed Evidence** verdict instead of
an overloaded confidence float. This document is the full API reference; start
with `README.md` for the one-paragraph overview and quick start.

---

## 1. The evidence model in one sentence

A functionality verdict is *evidence about the proposition* `mutated == original`
(observationally equivalent over a stated architectural scope). Each evidence
kind is its own frozen type, and they share exactly one comparable quantity —
`Evidence.false_admit_bound() -> Optional[float]` — an upper bound on the
probability that admitting the mutation as equivalent is a mistake, paired
inseparably with the `Scope` it was measured over. `None` means "this kind
carries no comparable number" and is NEVER coerced to `0.5` or any stand-in.

---

## 2. Evidence types and their false-admit semantics

| Kind | `false_admit_bound()` | Meaning | Admits at `alpha`? |
|------|----------------------|---------|--------------------|
| `Refuted` | `None` | **Sound NO** — a witnessed counterexample on in-scope state proves non-equivalence. Dominates everything in composition. | Never (admitting a known-bad mutation is the one thing the gate must refuse). |
| `Proof` | `0.0` | Equivalence proven WITHIN `scope`, as sound as the certificate. Backed by a re-checkable `Cert`. | Yes — `0.0 <= alpha` — **but only when `cert.recheckable` is True** under the default `require_recheckable=True`. |
| `Sampled` | `clopper_pearson_upper(k, n, delta)` | `k` counterexamples in `n` i.i.d. draws → an exact one-sided Clopper-Pearson upper bound on the failure probability UNDER the sampling distribution `dist_id` (not over all inputs). | Yes iff bound `<= alpha`. |
| `Behavioral` | `false_admit` (calibrated) or `None` | A NOISY CAPE-detonation similarity observation. The bound is the calibrated rate at which a score this good corresponds to a genuinely non-equivalent pair. **Uncalibrated (no labelled negatives) ⇒ `None`.** | Yes iff calibrated AND bound `<= alpha`; an uncalibrated Behavioral (`None`) never admits — treated like Unknown. |
| `Unknown` | `None` | Absence of evidence (not in library, no cert, timeout, empty trace, unverified scope precondition). | Never. |
| `ComposedBound` | union (Boole) bound | The combination of several steps' per-step bounds (see §5). Reports `kind == "sampled"` so the gate treats it as one numeric bound. | Yes iff bound `<= alpha`. |

Supporting types:

- **`Scope(live_out, input_dist=None, notes="")`** — the architectural state a
  verdict is actually about. `live_out` is a `frozenset` of location names
  (e.g. `{"rax", "rbx", "eflags", "xmm0"}`); the validator only relies on set
  containment, never on parsing the strings. A bound-bearing evidence with an
  empty `live_out` is rejected at construction (it would compare nothing).
- **`Cert(cert_kind, payload, recheckable)`** — the certificate backing a
  `Proof`. `cert_kind ∈ {Z3_UNSAT, ALIVE2, DECODE_IDENTICAL, ISA_BITWISE_ALIAS,
  SDM_ARGUMENT}`. The first four are machine-re-checkable; `SDM_ARGUMENT` is a
  human Intel-SDM argument and MUST set `recheckable=False`.

Math (pure, stdlib-only):

- **`clopper_pearson_upper(k, n, delta) -> float`** — exact one-sided upper
  confidence bound on a failure probability.
- **`union_bound(bounds) -> float`** — Boole/union sum of per-step bounds,
  capped at 1.0.

---

## 3. `FunctionValidator` — the facade

```python
FunctionValidator(
    *, proven=None, local_equiv=None, behavioral=None,
    alpha_online=0.05, alpha_offline=0.01,
)
```

Construction is lazy and import-safe: the `proven` and `local_equiv` oracles are
built on first use, so simply constructing a validator is free. The `behavioral`
oracle is **optional** (`None` by default) and is the only one not
auto-constructed (it needs a live box).

| Method | Returns | Notes |
|--------|---------|-------|
| `verify_sync(orig_bytes, mut_bytes, *, bits=64, steps=None, alpha=None)` | `Evidence` | The cheap online gate. Per step: try `ProvenOracle` first (O(1) lookup + re-checkable cert); on `Unknown`, escalate to `LocalEquivOracle` (Unicorn differential). A `Refuted` at any step short-circuits. Multi-step chains go through `compose`. `bits` selects the target arch — **see "Width (`bits`)" below**. `alpha` is reserved/unused — the verdict is budget-free; admission is a separate call. The behavioral oracle is NEVER invoked here (too slow). |
| `admissible(evidence, *, alpha=None)` | `bool` | Thin wrapper over `admit`; defaults to `alpha_online` (0.05). |
| `verify_async(orig_bytes, mut_bytes)` | handle `dict` | Submit a CAPE detonation WITHOUT blocking. Raises `RuntimeError` if `behavioral is None`. |
| `collect_async(handle)` | `Evidence` | Resolve a `verify_async` handle. Raises `RuntimeError` if `behavioral is None`. |

Property `validator.behavioral` is the configured `BehavioralOracle` or `None`
(it is NOT auto-built — the facade is honest about its absence). Guard the async
path with `if validator.behavioral is not None:`.

### Valid inputs (the input contract — read before you call it)

`funcval` verifies **instruction-aligned bytes**: a single instruction or a
fully-decoding instruction sequence, at matching offsets, at a stated width.

- **VALID:** the changed *fragment*, e.g. `bytes.fromhex("85c0")`
  (`test eax,eax`) vs `bytes.fromhex("21c0")` (`and eax,eax`). This is what a
  `stoke_actions` `(orig, var)` rewrite pair is.
- **INVALID:** a whole PE file, or any arbitrary blob. The LocalEquivOracle runs
  an **input-validity guard** first; bytes that do not cleanly decode at the
  chosen width return **`Unknown`** — funcval will **not** silently PASS a whole
  PE or junk. Extract the changed fragment and verify that.

For the `stoke_actions` → `funcval` bridge (mutate a PE's `.text`, then verify
each rewrite at the PE's true width) see `examples/mutate_then_verify.py`.

### Width (`bits`) — the footgun, and how it is closed

`verify_sync(orig, mut, *, bits=64)` — `bits` selects the target architecture
and is threaded into BOTH oracles (library selection, capstone/Unicorn mode, Z3
bit width, compared register set):

- `bits=32` → i386 / `UC_MODE_32` / `CS_MODE_32` / the bundled 32-bit library.
- `bits=64` → x86-64 (the default, so existing 64-bit callers are unchanged).

**`bits` MUST match the target architecture (32 for i386, 64 for x86-64).**
Omitting it defaults to `64`. A 32-bit caller who forgets `bits=32` does **not**
silently get an unsound 64-bit verdict: the input-validity guard decodes the
bytes in 64-bit mode first, and 32-bit-only encodings (e.g. `40` = `inc eax`,
which is a bare REX prefix in 64-bit) fail to decode cleanly and return
`Unknown`. Genuinely-32-bit-equivalent pairs (e.g. `and eax,eax` vs
`test eax,eax`, which differ only on the upper 32 bits) ADMIT only at `bits=32`;
at the default 64-bit width they are correctly **Refuted** (the upper-32
zero-extension hazard). So a 32-bit user who forgets is *protected from a silent
false-admit*, never handed a wrong PASS.

```python
v = funcval.FunctionValidator()
# 64-bit (default): mov rsp,rbp ≡ alt encoding -> Proof.
v.verify_sync(bytes.fromhex("4889ec"), bytes.fromhex("488be5"), bits=64)
# 32-bit i386: test eax,eax ≡ and eax,eax — equivalent ONLY at 32-bit width.
v.verify_sync(bytes.fromhex("85c0"), bytes.fromhex("21c0"), bits=32)
```

The bundled `data/` ships BOTH libraries, selected by `bits`:
`equiv_library_proven_v3_cleaned.json` (64-bit, 6480 entries) and
`equiv_library_32bit_verified.json` (32-bit i386, 1476 entries).

### Deriving steps

If `steps` is `None`, `verify_sync` diffs `(orig_bytes, mut_bytes)`. Because the
proven library is keyed on **whole-instruction** encodings and the Unicorn
oracle decodes the chunk as x86, a multi-run byte diff is collapsed into a
**single whole-buffer step** (a per-run split would drop shared prefix/suffix
bytes such as a REX `48` and feed malformed sub-instructions to the oracles). To
get a genuine instruction-aligned multi-step chain, pass explicit
`steps=[{chunk_offset, chunk_a_bytes_hex, chunk_b_bytes_hex, live_in?}, ...]`.

---

## 4. The oracles (what produces the Evidence)

- **`ProvenOracle`** (`funcval.oracles.proven`) — O(1) library lookup that emits
  a `Proof` ONLY with a machine-re-checkable certificate:
  - **DECODE_IDENTICAL** (capstone): both byte strings disassemble to the
    identical single instruction (e.g. an alt-ModRM d-bit swap). Covers the bulk
    of the cleaned library.
  - **ISA_BITWISE_ALIAS** (capstone, structural): whitelisted SIMD bitwise
    aliases (pxor/xorpd, pand/andpd, por/orpd, pandn/andnpd) on identical
    operands — equivalent by ISA definition, NOT via a (vacuous) Z3 model.
  - **Z3_UNSAT** (z3): the arithmetic idioms (`xor r,r` == `sub r,r`,
    `test/and/or r,r`, commutative `test a,b` == `test b,a`).
  Anything it cannot certify → `Unknown`. It NEVER emits an `SDM_ARGUMENT`
  proof. `recheck_cert(cert) -> bool` mechanically re-verifies any cert it
  produced. The library path is resolved by `resolve_library_path()`:
  `$FUNCVAL_LIBRARY_PATH` → bundled `funcval/data/...` → repo-relative fallback.
- **`LocalEquivOracle`** (`funcval.oracles.local_equiv`, needs `unicorn`) — a
  context-free full-architectural-state differential oracle. It emulates both
  snippets from the SAME input state and compares all 16 GPRs at full 64-bit
  width + all 16 XMM + the arithmetic EFLAGS (`0x8D5`). First observed
  divergence → `Refuted`; zero divergences over `n` draws → `Sampled(k=0)` with
  a Clopper-Pearson bound. Its input distribution front-loads a boundary battery
  before fresh-entropy i.i.d. uniform draws and re-seeds per call from
  `os.urandom`.
- **`BehavioralOracle`** (`funcval.oracles.behavioral`) — turns a pair of CAPE
  detonations into a `Behavioral` verdict (§7). It NEVER admits alone while
  uncalibrated. `submit(orig, mut) -> handle` / `collect(handle) -> Evidence`
  split the slow detonation off the critical path; `produce()` is
  `submit` then `collect`.

`ProgressRewardRunner` (`funcval.async_runner`) wraps the async behavioral path
into an event stream so a slow detonation never blocks an RL step.

---

## 5. The `compose` / `admit` contract

```python
compose(step_evidences, *, live_in_of_later_steps=None) -> Evidence
admit(evidence, alpha, *, require_recheckable=True) -> bool
```

**`compose`** combines a chain conservatively, in this order:

1. Empty chain → `Unknown`.
2. ANY step `Refuted` → return that `Refuted` (refutation dominates).
3. ANY step `Unknown` → `Unknown` (an unverified step poisons the chain).
4. **Scope precondition (the "R8-clobber" hole).** A chain is equivalent only if
   each step's `live_out` covers every state a LATER step reads (its live-in).
   - With `live_in_of_later_steps` supplied, each step is checked against the
     union of later steps' live-ins; a violation → `Unknown("steps interact
     through uncompared state ...")`.
   - Without it, the precondition is UNVERIFIED → `Unknown` UNLESS every step is
     a `Proof` sharing one identical scope equal to the FULL architectural state
     (then the chain is provably safe).
5. Surviving confirming evidence: all `Proof` → a composed `Proof` (bound `0.0`,
   scoped to the intersection of step scopes, cert kind `SDM_ARGUMENT` because a
   *derived* chain is not itself machine-checked → `recheckable=False`).
   Otherwise → a `ComposedBound` with a `union_bound` false-admit over the
   intersection of step `live_out`s. If the steps share NO compared location,
   compose refuses to overclaim → `Unknown`.

**`admit`** is THE single gate — the only place a number is compared:

- A `Proof` admits iff `alpha >= 0` AND (default) `cert.recheckable` is True.
  Pass `require_recheckable=False` to knowingly trust SDM/non-recheckable
  proofs. (The gate trusts the oracle's `recheckable` flag; call
  `funcval.oracles.proven.recheck_cert(cert)` first if you want a fresh
  re-check.)
- A `Refuted` and an `Unknown` always return `False`.
- Anything else admits iff `false_admit_bound() is not None` and `<= alpha`.

Use a SMALLER `alpha` offline (admitting into a trusted corpus, where mistakes
compound) than online (a transient per-action decision).

---

## 6. Scope and honesty limits (read before trusting a PASS)

- **Per-instruction / local equivalence is NOT whole-binary preservation.** A
  PASS from `verify_sync` means "locally architecturally equivalent over the
  compared register/flag/XMM scope", NOT "the binary still does the same thing".
  It does not hold for self-modifying, self-checking, packed, or
  relocation-sensitive code. (Empirically a single per-instruction-equivalent
  rewrite collapsed a sample's API trace from 11706 → 199 calls.)
- **The local oracle compares registers + flags + XMM, NOT memory writes.** A
  rewrite that diverges only in a value stored to memory samples `k=0` and
  admits, yet has changed observable behavior. Treat the register/flag/XMM scope
  as exactly that.
- **An uncalibrated `BehavioralOracle` has `false_admit = None` and never admits
  alone.** This project currently has only labelled POSITIVE (known-equivalent)
  pairs and no negatives, so the honest false-admit bound is `None`. The oracle
  reports a usable similarity signal but cannot clear the gate until negatives
  calibrate it. It does NOT fabricate a number from the positive distribution.
- **`compose` refuses to overclaim** — it returns `Unknown` rather than a
  `min()`-capped PASS when a scope precondition is unverified, and refutation
  dominates.
- The behavioral composite uses **non-empty-channel** weighting: a channel where
  both detonations have zero events contributes nothing (the underlying scorer
  would vacuously score it 1.0). An empty trace (either sample never meaningfully
  detonated) forces `Unknown`, never an admissible similarity.

---

## 7. CAPE wiring (the behavioral path)

The behavioral path needs a **reachable CAPE sandbox**. It is configured through
the `BehavioralOracle` constructor and the vendored `CapeCliClient` transport
(`funcval.cape.cape_cli_client`), which submits via CLI and polls the
filesystem (the box's HTTP control plane is disabled). Wire it explicitly:

```python
from funcval import FunctionValidator
from funcval.oracles.behavioral import BehavioralOracle
from funcval.cape.cape_cli_client import CapeCliClient

client = CapeCliClient(guests=("win11", "win11_2"), report_dir="cape_reports")
beh = BehavioralOracle(client=client, calibration_path="behavioral_calibration.json")
v = FunctionValidator(behavioral=beh)

# orig_bytes, mut_bytes = your instruction-fragment pair (e.g. bytes.fromhex(...))
if v.behavioral is not None:
    handle = v.verify_async(orig_bytes, mut_bytes)   # non-blocking
    ev = v.collect_async(handle)                     # later: Evidence
```

If you pass `client=None`, the transport is built lazily on first use with
defaults — so `import funcval` and the synchronous gate carry NO CAPE
dependency.

### Where does funcval run? The `transport` arg

`CapeCliClient` reaches the CAPE box (`10.105.198.0`) through a paramiko bridge
`sbx.py` that lives on the PRIMARY VM (VM1) at `/home/rl/sbx.py`. The underlying
box command is always `<vm_python> sbx.py <b64>`; the only thing that changes is
**how that command is dispatched**, controlled by the `transport` constructor
arg:

| `transport` | Where you are | What it does |
|-------------|---------------|--------------|
| `"auto"` (default) | either | Picks `"vmctl"` if a runnable `scripts/vmctl` is present (workstation), else `"local"` (vmctl absent ⇒ on VM1). Inert, filesystem-only detection. |
| `"vmctl"` | a **workstation** | Two-hop: wraps the box command as `scripts/vmctl ssh '<vm_python> sbx.py <b64>'`, hopping into VM1 first via the netns + VPN + socat + SSH mux. |
| `"local"` | **on VM1** | Runs `<vm_python> sbx.py <b64>` DIRECTLY via subprocess — NO `vmctl ssh` wrapper, because `sbx.py` and the VM python are local there and the hop would be nonsensical. |

Only the command *shape* differs between modes; timeouts, retry, the empty-trace
gate, polling cadence, and all soundness logic are identical.

**Copy-paste config for a collaborator running funcval ON VM1** (inside the
`sorel-malware-detector` conda env, where there is no `scripts/vmctl`):

```python
from funcval.cape.cape_cli_client import CapeCliClient
from funcval.oracles.behavioral import BehavioralOracle
from funcval import FunctionValidator

client = CapeCliClient(transport="local")  # already on VM1; calls sbx.py directly
validator = FunctionValidator(behavioral=BehavioralOracle(client=client))
```

In practice you can simply omit the arg — `transport="auto"` (the default) does
the right thing automatically: `"vmctl"` when a runnable `scripts/vmctl` is found
(your workstation), `"local"` when it is absent (on VM1). Pass an explicit
`"local"` / `"vmctl"` only when you want to override the auto-detection.

### Calibration (optional — ships uncalibrated by design)

`BehavioralOracle` defaults to `calibration_path=None`, the sound, conservative
state: it produces a similarity signal (and reports `composite`) but its
`false_admit` bound is `None`, so `funcval.admit` will **not** clear a pair on
behavioral evidence alone. This is intentional — there is no statistically valid
negative (known-different) calibration for this corpus.

Do **not** treat behavioral similarity as a gate until you calibrate on *your
own* corpus. A sound calibration needs:

- a positive set of known-equivalent detonation pairs with enough samples for a
  real noise-floor band;
- a negative set of known-different pairs that are **i.i.d.** (≥~30 negatives
  with **no binary reused** — a C(n,2) pairwise expansion of a few binaries is
  pairwise-dependent and does **not** multiply sample size);
- ideally hard negatives (same malware, behavior-altering mutation).

Write it as
`{"positive": {"mean", "stdev", "min", "n"}, "negative": {"samples": [...], "n"}}`
and pass its path as `calibration_path=`. The oracle derives
`threshold = pos_mean - k_sigma·pos_stdev` and
`false_admit = P(api_sim ≥ threshold | not equivalent)` from your negatives.
Verify the classes separate (positive min > negative max) before trusting any
admit.

### `BehavioralOracle` knobs

- `client` — a `CapeCliClient`-shaped transport, or `None` to build lazily.
- `calibration_path` — path to a behavioral-calibration JSON (positive +
  optional negative api-similarity distributions). `None`/missing ⇒ UNCALIBRATED
  (`threshold`/`false_admit` = `None`; never admits alone).
- `min_api_calls` (default `20`) — empty-trace gate threshold.
- `k_sigma` (default `3.0`) — noise-floor band width:
  `threshold = pos_mean - k_sigma * pos_stdev`.

### `CapeCliClient` configurable knobs (constructor args, with their defaults)

These are the **actual** constructor parameters and the module constants they
default to (from `funcval/cape/cape_cli_client.py`):

| Constructor arg | Default (constant) | What it controls |
|-----------------|--------------------|------------------|
| `vm_python` | `VM_PY = /home/rl/miniconda3/envs/sorel-malware-detector/bin/python` | Python (with paramiko) on the PRIMARY VM that drives `sbx.py`. |
| `sbx_path` | `SBX_PATH = /home/rl/sbx.py` | The paramiko driver on the PRIMARY VM. |
| `vmctl` | `VMCTL = scripts/vmctl` | Local control-plane wrapper (netns + VPN + socat + SSH mux). |
| `transport` | `"auto"` | How the box command is dispatched: `"vmctl"` (wrap as `vmctl ssh ...`, on a workstation), `"local"` (run directly, on VM1), or `"auto"` (vmctl if runnable, else local). See "Where does funcval run?" above. |
| `repo_root` | repo root (two parents up) | Resolves `vmctl` + `report_dir`. |
| `guests` | `DEFAULT_GUESTS = ("win11", "win11_2", "win11_3")` | Fixed roster for round-robin fan-out (`DEFAULT_MACHINE` = first guest). |
| `analysis_timeout` | `ANALYSIS_TIMEOUT = 60` | Guest detonation budget (passed to `submit.py --timeout`). |
| `poll_interval` | `POLL_INTERVAL = 5` | Seconds between filesystem polls. |
| `analysis_deadline` | `ANALYSIS_DEADLINE = 180` | Per-task wall deadline; on expiry → `MISSING`. |
| `submit_grace` | `SUBMIT_GRACE = 90` | Seconds to wait for a task id to first appear. |
| `threshold` | `DEFAULT_THRESHOLD = SandboxVerifier.DEFAULT_THRESHOLD = 0.70` | Composite-similarity PASS threshold (used by `verify_pair`). |
| `report_dir` | `DEFAULT_REPORT_DIR = assets/logs/cape_reports` | Workstation dir where raw reports are persisted (the box is ephemeral). |
| `min_free_bytes` | `MIN_FREE_BYTES = 5 GiB` | Constrained-mode trigger for box disk pruning. |
| `min_api_calls` | `MIN_API_CALLS = 20` | Empty-trace gate threshold. |
| `local_timeout` | `LOCAL_TIMEOUT = 60` | Local `vmctl ssh` wrapper bound (rc=124 on expiry → transport error → retried once). |
| `require_isolation_for_malicious` | `True` | Refuse malicious samples unless a network-isolation sentinel confirms containment. |
| `build_log` | `None` | Optional path; box output is tee'd here with the rl password redacted. |

Other module constants the transport uses internally (not constructor args):
`EXEC_TIMEOUT = 45` (per-box-command exec budget; `sbx.py` hard-caps at 45 s),
`SUBMIT_EXEC_TIMEOUT = 20`, `RETRY_BACKOFF = 3`, `TRANSPORT_RETRIES = 1`,
`MAX_IN_FLIGHT = 3`, `FETCH_CHUNK_BYTES = 2 MiB`, `MAX_REPORT_BYTES = 64 MiB`.
Submission auto-detects the package (no `--package`); `submit(...)` accepts an
optional `package=` only if auto-detect ever misfires. Soundness contract: every
terminal non-PASS condition (CAPE/transport down, FAILED/MISSING analysis, fetch
corruption, empty trace) yields `INCONCLUSIVE` / `Unknown`, NEVER a silent PASS.

### Lab defaults are env-overridable (host-config hygiene)

The CAPE transport's host-config constants are **env-overridable**, with the lab
values as fallback defaults baked into the wheel for zero-config in-lab use.
Behavior is identical when the env vars are unset. To run against a different
box without editing the wheel, set:

| Env var | Overrides (lab default) |
|---------|-------------------------|
| `FUNCVAL_CAPE_PASSWORD` | the `sudo -S` password (`123`) — never written to a log (existing `_redact` scrubbing is unchanged) |
| `FUNCVAL_CAPE_VM_PYTHON` | `VM_PY` (`/home/rl/miniconda3/envs/sorel-malware-detector/bin/python`) |
| `FUNCVAL_CAPE_SBX_PATH` | `SBX_PATH` (`/home/rl/sbx.py`) |
| `FUNCVAL_CAPE_ROOT` | `CAPE_ROOT` (`/opt/CAPEv2`; `CUCKOO_LOG` follows it) |
| `FUNCVAL_CAPE_POETRY_BIN` | `POETRY_BIN` (`/etc/poetry/bin/poetry`) |

The wheel embeds the lab defaults so an in-lab collaborator needs no config; a
different host sets the env vars instead of shipping a credential in source.

---

## 8. Public surface (importable from `funcval`)

```
FunctionValidator, ProgressRewardRunner,
compose, admit,
Evidence, Refuted, Proof, Sampled, Behavioral, Unknown, ComposedBound,
Scope, Cert,
clopper_pearson_upper, union_bound
```

Oracles live under `funcval.oracles` (`ProvenOracle`, `LocalEquivOracle`,
`BehavioralOracle`, `recheck_cert`); the CAPE transport under `funcval.cape`.

---

## 9. Test suite notes

Running `python -m pytest tests/funcval` against the installed package yields
**~106 passed, 8 skipped** on the VM conda env (the orchestrator confirms the
exact numbers). The 8 skips are expected, not failures:

- **8** are offline behavioral unit-tests that self-skip unless you stage the
  saved CAPE report/calibration fixtures next to the package.

Honest caveat about z3: the proven oracle's z3 test needs the optional `z3`
proofs extra (`pip install "funcval[proofs]"`). In a non-conda env the
`z3-solver` wheel may import while its bundled `libz3.so` fails to load at call
time; that test is now **hardened to skip cleanly** (rather than fail) in that
case — it is an environment issue, not a defect. (Earlier docs reported
`91 passed, 9 skipped`; the count changed with the width-soundness tests and the
hardened z3 skip.)

Neither indicates a problem; the live behavioral smoke covers the behavioral
path regardless.
