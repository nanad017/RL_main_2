# stoke_actions handoff install

This directory contains the local wheel used by the `stoke_rewrite` worker:

```bash
stoke_actions-0.1.0-py3-none-any.whl
```

The wheel SHA-256 is:

```text
66da1f8893a63232548e1e57eb0ca6b67bcd93108cb6b8553ac45f753fa254bf
```

Install it in the Python environment used by `STOKE_PYTHON`:

```bash
conda activate sorel-malware-detector
pip install checkfunc/stoke_actions_handoff/stoke_actions-0.1.0-py3-none-any.whl
```

For instruction-boundary-aware library rewrites, ensure `capstone` is installed
in the same environment:

```bash
pip install capstone
```

Verify the install:

```bash
python - <<'PY'
import importlib.util
import stoke_actions

print("stoke_actions", getattr(stoke_actions, "__version__", "unknown"))
print("path", stoke_actions.__file__)
print("capstone", importlib.util.find_spec("capstone") is not None)
print("libraries", stoke_actions.list_libraries())
PY
```

The RL code does not import `stoke_actions` directly. It calls
`malware_rl/envs/controls/stoke_worker.py` through a subprocess. Set these
variables before running STOKE-enabled training or evaluation:

```bash
export STOKE_PYTHON=/home/rl/miniconda3/envs/sorel-malware-detector/bin/python
export STOKE_WORKER=/home/rl/RL/RL_main_2/malware_rl/envs/controls/stoke_worker.py
```

The wheel contents were checked against the currently installed package at:

```text
/home/rl/miniconda3/envs/sorel-malware-detector/lib/python3.9/site-packages/stoke_actions
```

Ignoring generated `__pycache__` files, the wheel package files match the
installed package files byte-for-byte.
