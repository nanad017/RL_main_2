# Changes Made

## SOREL-FFNN as default detector

- Changed the default RL target from `ember` to `sorelFFNN` in:
  - `ppo.py`
  - `random_agent.py`
  - `evaluate.py`
  - `ppo_model_extract.py`
- Added target aliases so these values are accepted and normalized to `sorelFFNN`:
  - `sorelFFNN`
  - `SOREL-FFNN`
  - `sorel-ffnn`
  - `sorel_ffnn`
  - `sorelffnn`

## Dataset folder structure

- Changed dataset loading to support recursive family folders under:

```text
malware_rl/envs/utils/samples/
```

- Expected folder structure:

```text
malware_rl/envs/utils/samples/Locker/...
malware_rl/envs/utils/samples/Mediyes/...
malware_rl/envs/utils/samples/Winwebsec/...
malware_rl/envs/utils/samples/Zbot/...
malware_rl/envs/utils/samples/Zeroaccess/...
```

- Added empty `.gitkeep` placeholders for those family folders.
- Updated `malware_rl/envs/utils/interface.py` so sample ids keep the relative family path, for example:

```text
Locker/<filename>
Zbot/<filename>
```

## Train/test split saving

- Updated `malware_rl/__init__.py` so the train/test split is saved after it is created.
- Split output folder:

```text
data/splits/samples/
```

- Files created when the code runs:

```text
data/splits/samples/split.json
data/splits/samples/train.txt
data/splits/samples/test.txt
data/splits/samples/train/<family>/samples.txt
data/splits/samples/test/<family>/samples.txt
```

- The split uses a fixed seed by default:

```text
MALWARE_RL_SPLIT_SEED=42
```

- The split output directory can be changed with:

```text
MALWARE_RL_SPLIT_DIR=<path>
```

- The code saves only manifest files, not copies of the binary samples.

## Evasion output structure

- Updated all gym environments so evasion outputs preserve the original family folder.
- Example:

```text
Input sample:
malware_rl/envs/utils/samples/Locker/abc.exe

Output evasion:
data/evaded/sorelFFNN/Locker/<sha256_of_modified_file>
```

- Updated environments:
  - `malware_rl/envs/malconv_gym.py`
  - `malware_rl/envs/ember_gym.py`
  - `malware_rl/envs/sorel_gym.py`
  - `malware_rl/envs/sorelFFNN_gym.py`
  - `malware_rl/envs/AV_gym.py`
  - `malware_rl/envs/lgb_gym.py`
  - `malware_rl/envs/custom_gym.py`

## Save evasion only during test

- Kept `sorelFFNN-train-v0` with:

```python
"save_modified_data": False
```

- Changed `sorelFFNN-test-v0` to:

```python
"save_modified_data": True
```

- Changed `custom-train-v0` to:

```python
"save_modified_data": False
```

so train does not write modified evasion files.

## PPO max turns

- Changed the shared environment max turns from `15` to `10` in `malware_rl/__init__.py`:

```python
MAXTURNS = 10
```

- PPO uses this value through the registered train/test gym environments.

## Verification

- Ran syntax check with `ast.parse`.
- Result:

```text
syntax ok
```

- Full RL execution was not run because the workspace currently does not include real samples or `sorelFFNN.pt`.
