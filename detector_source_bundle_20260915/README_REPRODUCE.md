# Detector Source Bundle

This folder is a source-code-only copy of the detector implementations used for the paper experiments.

It intentionally excludes large or machine-specific files:

- virtual environments
- datasets
- generated results/logs
- model artifacts/checkpoints
- Git object databases
- Python caches

## Contents

- `detectors/malware-classification-CNN`: CNN detector source
- `detectors/EMBER2024`: EMBER2024 detector source
- `detectors/sorel_multi`: SOREL-style detector source
- `detectors/deep-malware-detection`: DeepMal detector source
- `detectors/Malware-Detection-System-XGBoost`: XGBoost detector source
- `runner_scripts/run_detector_batch.py`: batch runner for CNN/EMBER/SOREL/DeepMal
- `runner_scripts/run_xgb_batch.py`: batch runner for XGBoost

## Original Repositories And Commits

CNN:

- GitHub: `https://github.com/cridin1/malware-classification-CNN`
- Local commit: `8de787fbbbc3dc59178722eeb43b31f731f53675`

EMBER2024:

- GitHub: `https://github.com/futurecomputing4ai/EMBER2024`
- Local commit: `0ef753e81d98bf209f71b03cd331dfc190b5b54d`

DeepMal:

- GitHub: `https://github.com/jaketae/deep-malware-detection`
- Local commit: `8c45fc0e967f60de4caa40b8dc144528c0eefb01`

XGBoost:

- GitHub: `https://github.com/hyginusobi/Malware-Detection-System`
- Local commit: `cdaec30b727870063cf506c4b0f0f869170e6dfd`

SOREL-style detector:

- Related upstream project: `https://github.com/sophos/SOREL-20M`
- Local implementation path: `/home/rl/detector/sorel_multi`
- Note: local folder does not contain Git metadata, so no local commit SHA is available.

## Model Artifacts Used In Experiments

The actual model files remain in their original local paths and are not copied into this bundle.

CNN:

- `/home/rl/detector/malware-classification-CNN/artifacts/combined_local/modellozzo_ckpt.keras`
- `/home/rl/detector/malware-classification-CNN/artifacts/combined_local/class_indices.json`

EMBER2024:

- `/home/rl/detector/EMBER2024/models/custom_multiclass.model`
- `/home/rl/detector/EMBER2024/dataset_json/family_labels.json`

SOREL:

- `/home/rl/detector/sorel_multi/baselines/ffnn_seed1.pt`
- `/home/rl/detector/sorel_multi/baselines/ffnn_seed2.pt`
- `/home/rl/detector/sorel_multi/baselines/ffnn_seed3.pt`
- `/home/rl/detector/sorel_multi/baselines/ffnn_seed4.pt`
- `/home/rl/detector/sorel_multi/baselines/ffnn_seed5.pt`
- `/home/rl/detector/sorel_multi/baselines/lgbm_seed1.joblib`
- `/home/rl/detector/sorel_multi/baselines/threshold.json`

DeepMal:

- `/home/rl/detector/deep-mal/deep-malware-detection/assets/checkpoints/run1.pt`

XGBoost:

- `/home/rl/sup_detector/Malware-Detection-System/artifacts/binary_xgboost.joblib`
- `/home/rl/sup_detector/Malware-Detection-System/artifacts/metrics_xgboost.json`

## Decision Rules

- CNN/EMBER/DeepMal/SOREL: if the detector returns `BENIGN` or predicted family `benign`, the malware sample is counted as evaded.
- XGBoost: uses `p(malware) >= 0.91` as malware. Otherwise, the sample is benign and counted as evaded.
- SOREL threshold used in runner: `0.8327`.

## Batch Evaluation Usage

Use the original local model paths unless the runner constants are changed.

Example:

```bash
python /home/rl/RL/RL_main_2/detector_source_bundle_20260915/runner_scripts/run_detector_batch.py \
  --detector ember \
  --dataset-root /path/to/dataset \
  --label dataset_label \
  --output-dir /path/to/output
```

XGBoost:

```bash
/home/rl/sup_detector/Malware-Detection-System/venv/bin/python \
  /home/rl/RL/RL_main_2/detector_source_bundle_20260915/runner_scripts/run_xgb_batch.py \
  --dataset-root /path/to/dataset \
  --label dataset_label \
  --output-dir /path/to/output
```
