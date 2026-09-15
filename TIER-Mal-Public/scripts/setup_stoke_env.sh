#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-$ROOT_DIR/.venv-stoke}"
FUNCVAL_WHEEL="$ROOT_DIR/proposed/utils/funcval_handoff/funcval-0.2.0-py3-none-any.whl"
STOKE_WHEEL="$ROOT_DIR/proposed/utils/stoke_actions_handoff/stoke_actions-0.1.0-py3-none-any.whl"

for wheel in "$FUNCVAL_WHEEL" "$STOKE_WHEEL"; do
  [[ -f "$wheel" ]] || { echo "Missing bundled wheel: $wheel" >&2; exit 1; }
done

"$PYTHON_BIN" - <<'PY'
import sys
if sys.version_info < (3, 9):
    raise SystemExit("The STOKE environment requires Python 3.9 or newer.")
PY

"$PYTHON_BIN" -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --upgrade pip wheel
"$VENV_DIR/bin/python" -m pip install \
  "funcval[proofs] @ file://$FUNCVAL_WHEEL" \
  "stoke-actions[disasm,pe] @ file://$STOKE_WHEEL"
"$VENV_DIR/bin/python" -m pip check
"$VENV_DIR/bin/python" - <<'PY'
import funcval
import stoke_actions
print("funcval and stoke_actions imports: ok")
PY

echo "STOKE environment ready: $VENV_DIR"
