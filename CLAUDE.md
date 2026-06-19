# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

RL-based PE malware mutation framework that trains a PPO agent to evade ML-based static malware detectors. Fork/adaptation of [malware_rl](https://github.com/bfilar/malware_rl). Uses an iterative surrogate-training loop: query real detector → train LightGBM surrogate → train PPO against surrogate → repeat.

**Python 3.7.17** is required for the RL runtime (stable-baselines3 compatibility). The STOKE code-rewrite action runs as a subprocess via Python >=3.9.

## Key Commands

```bash
# Validate prerequisites (Python, STOKE, action space)
bash scripts/run_custom_detector_with_stoke.sh check

# Run main training pipeline: PPO + surrogate + iterative rounds
TRAIN_ONLY=1 bash scripts/run_custom_detector_with_stoke.sh meme

# Run tests
python run_tests.py                                           # IAT hook / inject_call tests
python -m pytest tests_reward -q                             # TierAwareReward tests
bash scripts/run_custom_detector_with_stoke.sh test          # STOKE bridge tests
python stable_baselines_env_check.py                         # Gym env validation

# Evaluate trained checkpoint
python evaluate.py --target custom --seed <seed> --agent <checkpoint_path>

# Hyperparameter search
python optuna_ppo.py
python optuna_surrogate.py
```

## Architecture

### Training Pipeline (`ppo_model_extract.py`)

Iterative loop over NUM_ROUNDS rounds:
1. Run PPO agent against real detector (`custom-train-v0` env) → collect observations + scores
2. Train LightGBM surrogate on static EMBER data + RL-collected data (weighted, `alpha=6.668`)
3. Switch agent to surrogate env (`lgb-train-v0`) for further training
4. Repeat

Controlled entirely by environment variables (`CUSTOM_DETECTOR_URL`, `CUSTOM_DETECTOR_SHARED_ROOT`, `TRAIN_ONLY`, `NUM_TIMESTEPS`, `SEED`, etc.)

### Active Gym Environments (`malware_rl/envs/`)

| Env ID | Class | Target |
|--------|-------|--------|
| `custom-train-v0` / `custom-test-v0` | `CustomDetectorEnv` (custom_gym.py) | External REST API |
| `AV1-train-v0` / `AV1-test-v0` | `AVEnv` (AV_gym.py) | External AV API |
| `lgb-train-v0` / `lgb-test-v0` | `LGBEnv` (lgb_gym.py) | LightGBM surrogate |

All envs share: 2381-dim observation space (Ember feature vector), discrete 18-action space, TierAwareReward, and save data to `data/memory/<target>/`.

### Action Space (`malware_rl/envs/controls/modifier.py`)

**Tier 1 — Structural (13):** overlay padding/append, section manipulation, import addition, header modification, debug removal, checksum breaking
**Tier 2 — API surface (3):** import group addition, IAT hooking, benign API call injection
**Tier 3 — Code rewrite (2):** STOKE superoptimizer rewrites (subprocess to Python >=3.9), bytecode swap

STOKE cross-version bridge: `modifier.py` → `stoke_bridge.py` → subprocess `stoke_worker.py` (Python >=3.9 env).

### Reward (`malware_rl/envs/reward.py`)

`TierAwareReward` — 4 components:
- **R_score:** detection score reduction + evasion bonus (scaled by query efficiency `lambda_q`)
- **R_size:** penalty for file size inflation (`lambda_s`)
- **R_tier:** episode-end bonus for tier diversity (`lambda_d`)
- **R_func:** penalty if binary is broken (`lambda_f=15.0`, checker is currently a placeholder returning True)

Planned refactor (see `.scratch/funcval-reward-refactor-plan.md`): wire `funcval` binary verification into R_func for STOKE rewrites.

### Surrogate Model (`surrogate.py`)

LightGBM trained on EMBER static dataset + RL-collected queries. RL data weighted vs static by `alpha`. Tuned to match target detector at a specific FPR. Input: 2381-dim Ember feature vectors → predict detection score.

### Key Files

- `ppo_model_extract.py` — main iterative training loop
- `malware_rl/envs/custom_gym.py` — custom detector gym environment (active training env)
- `malware_rl/envs/controls/modifier.py` — `ModifyBinary`, `ACTION_TABLE`, all 18 actions
- `malware_rl/envs/reward.py` — `TierAwareReward`
- `malware_rl/__init__.py` — env registration, train/test split logic
- `malware_rl/envs/controls/stoke_bridge.py` + `stoke_worker.py` — STOKE rewrite subprocess bridge
- `malware_rl/envs/controls/inline_hook.py` + `inject_call.py` — API-hooking actions

### Test Infrastructure

- `run_tests.py`: unittest-based tests for `inline_hook.py` and `inject_call.py` (tests on real PE files in `malware_rl/envs/controls/ls/trusted/`)
- `tests_reward/test_reward.py`: pytest tests for `TierAwareReward`
- `malware_rl/envs/controls/test_stoke_bridge.py`: pytest tests for STOKE bridge (run via `scripts/run_custom_detector_with_stoke.sh test`)
- Test PE files: `malware_rl/envs/controls/ls/trusted/` (10 benign Windows binaries)
