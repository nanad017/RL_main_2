#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DETECTOR="${1:-}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

usage() {
  echo "Usage: $0 {custom-xgboost|sorel|deepmal|cnn|ember}" >&2
  exit 2
}

case "$DETECTOR" in
  custom-xgboost)
    REQUIREMENTS="$ROOT_DIR/detectors/custom_rl/xgboost/requirements.txt"
    DEFAULT_VENV="$ROOT_DIR/.venv-detector-custom-xgboost"
    ;;
  sorel)
    REQUIREMENTS="$ROOT_DIR/detectors/evaluation/sorel_multi/requirements.txt"
    DEFAULT_VENV="$ROOT_DIR/.venv-detector-sorel"
    ;;
  deepmal)
    REQUIREMENTS="$ROOT_DIR/detectors/evaluation/deep-malware-detection/requirements.txt"
    DEFAULT_VENV="$ROOT_DIR/.venv-detector-deepmal"
    ;;
  cnn)
    REQUIREMENTS="$ROOT_DIR/detectors/evaluation/malware-classification-CNN/requirements.txt"
    DEFAULT_VENV="$ROOT_DIR/.venv-detector-cnn"
    ;;
  ember)
    REQUIREMENTS=""
    DEFAULT_VENV="$ROOT_DIR/.venv-detector-ember"
    ;;
  *) usage ;;
esac

VENV_DIR="${VENV_DIR:-$DEFAULT_VENV}"
"$PYTHON_BIN" -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --upgrade pip wheel

if [[ "$DETECTOR" == "ember" ]]; then
  "$VENV_DIR/bin/python" -m pip install -e "$ROOT_DIR/detectors/evaluation/EMBER2024"
else
  "$VENV_DIR/bin/python" -m pip install -r "$REQUIREMENTS"
fi
"$VENV_DIR/bin/python" -m pip check

echo "Detector environment ready: $VENV_DIR"
