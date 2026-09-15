#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3.7}"
VENV_DIR="${VENV_DIR:-$ROOT_DIR/.venv-rl}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python interpreter not found: $PYTHON_BIN (the RL stack requires Python 3.7.17)." >&2
  exit 1
fi

"$PYTHON_BIN" - <<'PY'
import sys
if sys.version_info[:2] != (3, 7):
    raise SystemExit("The RL environment requires Python 3.7.x; got %s" % sys.version.split()[0])
PY

"$PYTHON_BIN" -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --upgrade 'pip<24.1' 'setuptools<58' wheel
"$VENV_DIR/bin/python" -m pip install -r "$ROOT_DIR/configs/requirements.txt"
"$VENV_DIR/bin/python" -m pip check

echo "RL environment ready: $VENV_DIR"
