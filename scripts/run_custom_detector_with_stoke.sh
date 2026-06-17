#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RL_PYTHON="${RL_PYTHON:-$ROOT_DIR/.venv37_clean/bin/python}"

CUSTOM_DETECTOR_URL="${CUSTOM_DETECTOR_URL:-http://127.0.0.1:8000}"
CUSTOM_DETECTOR_SHARED_ROOT="${CUSTOM_DETECTOR_SHARED_ROOT:-$ROOT_DIR/data/share}"
CUSTOM_DETECTOR_THRESHOLD="${CUSTOM_DETECTOR_THRESHOLD:-0.5}"

STOKE_PYTHON="${STOKE_PYTHON:-/home/rl/miniconda3/envs/sorel-malware-detector/bin/python}"
STOKE_WORKER="${STOKE_WORKER:-$ROOT_DIR/malware_rl/envs/controls/stoke_worker.py}"
STOKE_N="${STOKE_N:-8}"
STOKE_REWRITES="${STOKE_REWRITES:-proven_v3_cleaned}"
STOKE_TIMEOUT="${STOKE_TIMEOUT:-60}"
STOKE_SEED="${STOKE_SEED:-}"

SEED="${SEED:-39720}"
NUM_QUERIES="${NUM_QUERIES:-4096}"
NUM_EPISODES="${NUM_EPISODES:-300}"
NUM_BOOSTING_ROUNDS="${NUM_BOOSTING_ROUNDS:-500}"
INIT_TIMESTEPS="${INIT_TIMESTEPS:-256}"
NUM_TIMESTEPS="${NUM_TIMESTEPS:-2048}"
EVAL_TIMESTEPS="${EVAL_TIMESTEPS:-2048}"
NUM_ROUNDS="${NUM_ROUNDS:-3}"
TRAIN_ONLY="${TRAIN_ONLY:-0}"
MALWARE_RL_TRAIN_DIR="${MALWARE_RL_TRAIN_DIR:-$HOME/RL/dataset/main_dataset/RL/virus}"
MALWARE_RL_TEST_DIR="${MALWARE_RL_TEST_DIR:-$HOME/RL/dataset/main_dataset/test}"
SORELFFNN_EVAL_TIMESTEPS="${SORELFFNN_EVAL_TIMESTEPS:-59610}"
SORELFFNN_NUM_TIMESTEPS="${SORELFFNN_NUM_TIMESTEPS:-59610}"
SORELFFNN_NUM_ROUNDS="${SORELFFNN_NUM_ROUNDS:-1}"

MODE="${1:-help}"

export CUSTOM_DETECTOR_URL
export CUSTOM_DETECTOR_SHARED_ROOT
export CUSTOM_DETECTOR_THRESHOLD
export STOKE_PYTHON
export STOKE_WORKER
export STOKE_N
export STOKE_REWRITES
export STOKE_TIMEOUT
export MALWARE_RL_TRAIN_DIR
export MALWARE_RL_TEST_DIR
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
  local path="$1"
  if [[ ! -x "$path" ]]; then
    echo "Missing executable: $path" >&2
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
SEED=$SEED
NUM_QUERIES=$NUM_QUERIES
NUM_EPISODES=$NUM_EPISODES
NUM_BOOSTING_ROUNDS=$NUM_BOOSTING_ROUNDS
INIT_TIMESTEPS=$INIT_TIMESTEPS
NUM_TIMESTEPS=$NUM_TIMESTEPS
EVAL_TIMESTEPS=$EVAL_TIMESTEPS
NUM_ROUNDS=$NUM_ROUNDS
TRAIN_ONLY=$TRAIN_ONLY
MALWARE_RL_TRAIN_DIR=$MALWARE_RL_TRAIN_DIR
MALWARE_RL_TEST_DIR=$MALWARE_RL_TEST_DIR
SORELFFNN_EVAL_TIMESTEPS=$SORELFFNN_EVAL_TIMESTEPS
SORELFFNN_NUM_TIMESTEPS=$SORELFFNN_NUM_TIMESTEPS
SORELFFNN_NUM_ROUNDS=$SORELFFNN_NUM_ROUNDS
EOF
}

check_prereqs() {
  require_exec "$RL_PYTHON"
  require_exec "$STOKE_PYTHON"
  require_file "$STOKE_WORKER"
  require_file "$ROOT_DIR/ppo_model_extract.py"
  require_file "$ROOT_DIR/ppo.py"
  require_file "$ROOT_DIR/random_agent.py"

  "$RL_PYTHON" - <<'PY'
import os
from malware_rl.envs.controls import modifier

actions = list(modifier.ACTION_TABLE.keys())
assert actions.index("stoke_rewrite") == 16, actions.index("stoke_rewrite")
assert "bytecode_swap" in actions

print("Action space (%d actions):" % len(actions))
for idx, name in enumerate(actions):
    print("%02d %s" % (idx, name))
print("stoke_rewrite index:", actions.index("stoke_rewrite"))
print("bytecode_swap index:", actions.index("bytecode_swap"))
print("CUSTOM_DETECTOR_URL:", os.environ.get("CUSTOM_DETECTOR_URL"))
print("STOKE_WORKER:", os.environ.get("STOKE_WORKER"))
PY

  "$STOKE_PYTHON" - <<'PY'
import importlib.util
import sys

print("STOKE runtime:", sys.version.split()[0])
print("stoke_actions:", bool(importlib.util.find_spec("stoke_actions")))
print("capstone:", bool(importlib.util.find_spec("capstone")))
if not importlib.util.find_spec("stoke_actions"):
    raise SystemExit("stoke_actions is missing in STOKE_PYTHON env")
PY
}

run_pytest() {
  check_prereqs
  "$RL_PYTHON" -m pytest "$ROOT_DIR/malware_rl/envs/controls/test_stoke_bridge.py" -q
}

run_random() {
  check_prereqs
  "$RL_PYTHON" "$ROOT_DIR/random_agent.py" \
    --target custom \
    --seed "$SEED" \
    --num-episodes "$NUM_EPISODES" \
    --num-queries "$NUM_QUERIES"
}

run_ppo_only() {
  check_prereqs
  "$RL_PYTHON" "$ROOT_DIR/ppo.py" \
    --target custom \
    --seed "$SEED" \
    --num-episodes "$NUM_EPISODES" \
    --num-queries "$NUM_QUERIES"
}

run_meme() {
  check_prereqs
  local extra_args=()
  if [[ "$TRAIN_ONLY" == "1" ]]; then
    extra_args+=(--train_only)
  fi
  "$RL_PYTHON" "$ROOT_DIR/ppo_model_extract.py" \
    --target custom \
    --seed "$SEED" \
    --num_boosting_rounds "$NUM_BOOSTING_ROUNDS" \
    --init_timesteps "$INIT_TIMESTEPS" \
    --num_timesteps "$NUM_TIMESTEPS" \
    --eval_timesteps "$EVAL_TIMESTEPS" \
    --num_rounds "$NUM_ROUNDS" \
    "${extra_args[@]}"
}

run_meme_sorelffnn() {
  check_prereqs
  "$RL_PYTHON" "$ROOT_DIR/ppo_model_extract.py" \
    --target sorelFFNN \
    --eval_timesteps "$SORELFFNN_EVAL_TIMESTEPS" \
    --num_timesteps "$SORELFFNN_NUM_TIMESTEPS" \
    --num_rounds "$SORELFFNN_NUM_ROUNDS"
}

usage() {
  cat <<'EOF'
Usage:
  scripts/run_custom_detector_with_stoke.sh check
  scripts/run_custom_detector_with_stoke.sh test
  scripts/run_custom_detector_with_stoke.sh random
  scripts/run_custom_detector_with_stoke.sh ppo
  scripts/run_custom_detector_with_stoke.sh meme
  scripts/run_custom_detector_with_stoke.sh meme-sorelffnn
  scripts/run_custom_detector_with_stoke.sh env

What this script does:
  - Exports CUSTOM_* variables for the custom detector API
  - Exports STOKE_* variables for stoke_rewrite backend
  - Verifies that the live action space still includes all actions, with
    stoke_rewrite fixed at index 16
  - Runs one of the repo entrypoints against target=custom

Important:
  - The action space comes from modifier.ACTION_TABLE at runtime. There is no
    extra switch to "enable all actions"; running custom mode automatically
    uses the full current action table, including stoke_rewrite and bytecode_swap.
  - If the STOKE env lacks capstone, stoke_actions still runs but may skip the
    instruction-aligned library rewrite pass.

Common overrides:
  export CUSTOM_DETECTOR_URL=http://127.0.0.1:8000
  export CUSTOM_DETECTOR_SHARED_ROOT=/path/to/shared/root
  export CUSTOM_DETECTOR_THRESHOLD=0.5
  export RL_PYTHON=/path/to/.venv37_clean/bin/python
  export STOKE_PYTHON=/path/to/python>=3.9
  export STOKE_WORKER=/path/to/stoke_worker.py
  export STOKE_N=8
  export STOKE_REWRITES=proven_v3_cleaned
  export STOKE_TIMEOUT=60
  export STOKE_SEED=39720
  export SEED=39720
  export NUM_QUERIES=4096
  export NUM_EPISODES=300
  export NUM_BOOSTING_ROUNDS=500
  export INIT_TIMESTEPS=256
  export NUM_TIMESTEPS=2048
  export EVAL_TIMESTEPS=2048
  export NUM_ROUNDS=3
  export TRAIN_ONLY=1
  export MALWARE_RL_TRAIN_DIR=$HOME/RL/dataset/main_dataset/RL/virus
  export MALWARE_RL_TEST_DIR=$HOME/RL/dataset/main_dataset/test
  export SORELFFNN_EVAL_TIMESTEPS=59610
  export SORELFFNN_NUM_TIMESTEPS=59610
  export SORELFFNN_NUM_ROUNDS=1
EOF
}

case "$MODE" in
  check)
    show_config
    check_prereqs
    ;;
  test)
    show_config
    run_pytest
    ;;
  random)
    show_config
    run_random
    ;;
  ppo)
    show_config
    run_ppo_only
    ;;
  meme)
    show_config
    run_meme
    ;;
  meme-sorelffnn)
    show_config
    run_meme_sorelffnn
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
