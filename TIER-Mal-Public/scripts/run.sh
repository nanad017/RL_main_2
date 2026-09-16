#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RL_PYTHON="${RL_PYTHON:-$ROOT_DIR/.venv-rl/bin/python}"

CUSTOM_DETECTOR_URL="${CUSTOM_DETECTOR_URL:-http://127.0.0.1:8000}"
CUSTOM_DETECTOR_SHARED_ROOT="${CUSTOM_DETECTOR_SHARED_ROOT:-$ROOT_DIR/runtime/share}"
CUSTOM_DETECTOR_THRESHOLD="${CUSTOM_DETECTOR_THRESHOLD:-0.5}"

STOKE_PYTHON="${STOKE_PYTHON:-python}"
STOKE_WORKER="${STOKE_WORKER:-$ROOT_DIR/proposed/actions/stoke_worker.py}"
STOKE_N="${STOKE_N:-8}"
STOKE_REWRITES="${STOKE_REWRITES:-proven_v3_cleaned}"
STOKE_TIMEOUT="${STOKE_TIMEOUT:-1800}"
STOKE_SEED="${STOKE_SEED:-}"
FUNCVAL_ALPHA="${FUNCVAL_ALPHA:-0.05}"

SEED="${SEED:-39720}"
NUM_QUERIES="${NUM_QUERIES:-4096}"
NUM_EPISODES="${NUM_EPISODES:-300}"
MALWARE_RL_TRAIN_DIR="${MALWARE_RL_TRAIN_DIR:-$ROOT_DIR/runtime/datasets/main_dataset/RL/virus}"
MALWARE_RL_TEST_DIR="${MALWARE_RL_TEST_DIR:-$ROOT_DIR/runtime/datasets/main_dataset/test}"

MODE="${1:-help}"

export CUSTOM_DETECTOR_URL
export CUSTOM_DETECTOR_SHARED_ROOT
export CUSTOM_DETECTOR_THRESHOLD
export STOKE_PYTHON
export STOKE_WORKER
export STOKE_N
export STOKE_REWRITES
export STOKE_TIMEOUT
export FUNCVAL_ALPHA
export MALWARE_RL_TRAIN_DIR
export MALWARE_RL_TEST_DIR
export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"
if [[ -n "${STOKE_SEED}" ]]; then
  export STOKE_SEED
fi

require_file() {
  local path="$1"
  if [[ ! -e "$path" ]]; then
    echo "Missing required path: $path" >&2
    exit 1
  fi
}

require_exec() {
  local executable="$1"
  if [[ "$executable" == */* ]]; then
    [[ -x "$executable" ]] || {
      echo "Missing executable: $executable" >&2
      exit 1
    }
  elif ! command -v "$executable" >/dev/null 2>&1; then
    echo "Missing executable on PATH: $executable" >&2
    exit 1
  fi
}

show_config() {
  cat <<EOF
ROOT_DIR=$ROOT_DIR
RL_PYTHON=$RL_PYTHON
CUSTOM_DETECTOR_URL=$CUSTOM_DETECTOR_URL
CUSTOM_DETECTOR_SHARED_ROOT=$CUSTOM_DETECTOR_SHARED_ROOT
CUSTOM_DETECTOR_THRESHOLD=$CUSTOM_DETECTOR_THRESHOLD
STOKE_PYTHON=$STOKE_PYTHON
STOKE_WORKER=$STOKE_WORKER
STOKE_N=$STOKE_N
STOKE_REWRITES=$STOKE_REWRITES
STOKE_TIMEOUT=$STOKE_TIMEOUT
STOKE_SEED=${STOKE_SEED:-<unset>}
FUNCVAL_ALPHA=$FUNCVAL_ALPHA
SEED=$SEED
NUM_QUERIES=$NUM_QUERIES
NUM_EPISODES=$NUM_EPISODES
MALWARE_RL_TRAIN_DIR=$MALWARE_RL_TRAIN_DIR
MALWARE_RL_TEST_DIR=$MALWARE_RL_TEST_DIR
EOF
}

check_prereqs() {
  require_exec "$RL_PYTHON"
  require_exec "$STOKE_PYTHON"
  require_file "$STOKE_WORKER"
  require_file "$ROOT_DIR/proposed/agent/ppo.py"
  require_file "$ROOT_DIR/proposed/agent/random_agent.py"

  "$RL_PYTHON" - <<'PY'
import os
from proposed.actions import modifier

actions = list(modifier.ACTION_TABLE.keys())
assert actions.index("stoke_rewrite") == 16, actions.index("stoke_rewrite")
assert len(actions) == 17, len(actions)

print("Action space (%d actions):" % len(actions))
for idx, name in enumerate(actions):
    print("%02d %s" % (idx, name))
print("stoke_rewrite index:", actions.index("stoke_rewrite"))
print("CUSTOM_DETECTOR_URL:", os.environ.get("CUSTOM_DETECTOR_URL"))
print("STOKE_WORKER:", os.environ.get("STOKE_WORKER"))
PY

  "$STOKE_PYTHON" - <<'PY'
import importlib.util
import sys

print("STOKE runtime:", sys.version.split()[0])
print("stoke_actions:", bool(importlib.util.find_spec("stoke_actions")))
print("capstone:", bool(importlib.util.find_spec("capstone")))
print("funcval:", bool(importlib.util.find_spec("funcval")))
if not importlib.util.find_spec("stoke_actions"):
    raise SystemExit("stoke_actions is missing in STOKE_PYTHON env")
if not importlib.util.find_spec("funcval"):
    raise SystemExit("funcval is missing in STOKE_PYTHON env")
print("funcval local sync validation: ok")
PY
}

run_random() {
  check_prereqs
  "$RL_PYTHON" -m proposed.agent.random_agent \
    --target custom \
    --seed "$SEED" \
    --num-episodes "$NUM_EPISODES" \
    --num-queries "$NUM_QUERIES"
}

run_ppo_only() {
  check_prereqs
  "$RL_PYTHON" -m proposed.agent.ppo \
    --target custom \
    --seed "$SEED" \
    --num-episodes "$NUM_EPISODES" \
    --num-queries "$NUM_QUERIES"
}

usage() {
  cat <<'EOF'
Usage:
  scripts/run.sh check
  scripts/run.sh random
  scripts/run.sh ppo
  scripts/run.sh env

What this script does:
  - Exports CUSTOM_* variables for the custom detector API
  - Exports STOKE_* variables for stoke_rewrite backend
  - Verifies that the live action space still includes all actions, with
    stoke_rewrite fixed at index 16
  - Runs one of the repo entrypoints against target=custom

Important:
  - The action space comes from modifier.ACTION_TABLE at runtime. There is no
    extra switch to "enable all actions"; running custom mode automatically
    uses the full current action table, including stoke_rewrite.
  - If the STOKE env lacks capstone, stoke_actions still runs but may skip the
    instruction-aligned library rewrite pass.

Common overrides:
  export CUSTOM_DETECTOR_URL=http://127.0.0.1:8000
  export CUSTOM_DETECTOR_SHARED_ROOT=/path/to/shared/root
  export CUSTOM_DETECTOR_THRESHOLD=0.5
  export RL_PYTHON=/path/to/.venv-rl/bin/python
  export STOKE_PYTHON=/path/to/python>=3.9
  export STOKE_WORKER=/path/to/stoke_worker.py
  export STOKE_N=8
  export STOKE_REWRITES=proven_v3_cleaned
  export STOKE_TIMEOUT=1800
  export STOKE_SEED=39720
  export FUNCVAL_ALPHA=0.05
  export SEED=39720
  export NUM_QUERIES=4096
  export NUM_EPISODES=300
  export MALWARE_RL_TRAIN_DIR=$ROOT_DIR/runtime/datasets/main_dataset/RL/virus
  export MALWARE_RL_TEST_DIR=$ROOT_DIR/runtime/datasets/main_dataset/test
EOF
}

case "$MODE" in
  check)
    show_config
    check_prereqs
    ;;
  random)
    show_config
    run_random
    ;;
  ppo)
    show_config
    run_ppo_only
    ;;
  env)
    show_config
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    echo "Unknown mode: $MODE" >&2
    usage
    exit 2
    ;;
esac
