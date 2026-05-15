# Cách bật lại Surrogate Models

Surrogate models (ember, sorel, sorelFFNN, malconv) hiện đang bị tắt để chạy thẳng trên real detector.

---

## 1. Bật env registration (`malware_rl/__init__.py`)

Thay block comment surrogate bằng code thật:

```python
register(
    id="malconv-train-v0",
    entry_point="malware_rl.envs.malconv_gym:MalConvEnv",
    kwargs={"random_sample": True, "maxturns": MAXTURNS, "sha256list": sha256_train, "save_modified_data": False},
)
register(
    id="malconv-test-v0",
    entry_point="malware_rl.envs.malconv_gym:MalConvEnv",
    kwargs={"random_sample": False, "maxturns": MAXTURNS, "sha256list": sha256_holdout, "save_modified_data": True},
)
register(
    id="ember-train-v0",
    entry_point="malware_rl.envs.ember_gym:EmberEnv",
    kwargs={"random_sample": True, "maxturns": MAXTURNS, "sha256list": sha256_train, "save_modified_data": False},
)
register(
    id="ember-test-v0",
    entry_point="malware_rl.envs.ember_gym:EmberEnv",
    kwargs={"random_sample": False, "maxturns": MAXTURNS, "sha256list": sha256_holdout, "save_modified_data": True},
)
register(
    id="sorel-train-v0",
    entry_point="malware_rl.envs.sorel_gym:SorelEnv",
    kwargs={"random_sample": True, "maxturns": MAXTURNS, "sha256list": sha256_train, "save_modified_data": False},
)
register(
    id="sorel-test-v0",
    entry_point="malware_rl.envs.sorel_gym:SorelEnv",
    kwargs={"random_sample": False, "maxturns": MAXTURNS, "sha256list": sha256_holdout, "save_modified_data": False},
)
register(
    id="sorelFFNN-train-v0",
    entry_point="malware_rl.envs.sorelFFNN_gym:SorelFFNNEnv",
    kwargs={"random_sample": True, "maxturns": MAXTURNS, "sha256list": sha256_train, "save_modified_data": False},
)
register(
    id="sorelFFNN-test-v0",
    entry_point="malware_rl.envs.sorelFFNN_gym:SorelFFNNEnv",
    kwargs={"random_sample": False, "maxturns": MAXTURNS, "sha256list": sha256_holdout, "save_modified_data": True},
)
```

---

## 2. Bật lại choices trong argparse

Trong `ppo.py`, `evaluate.py`, `random_agent.py` — đổi dòng `--target` thành:

```python
# ppo.py / random_agent.py
TARGET_ALIASES = {
    "sorel-ffnn": "sorelFFNN",
    "sorel_ffnn": "sorelFFNN",
    "sorelffnn": "sorelFFNN",
}

def normalize_target(target):
    return TARGET_ALIASES.get(target.lower(), target)

parser.add_argument('--target', type=normalize_target,
    choices=['ember', 'sorel', 'sorelFFNN', 'AV1', 'custom'],
    default='sorelFFNN', help='target detector to use')
```

```python
# evaluate.py
parser.add_argument("--target", type=normalize_target,
    choices=["ember", "sorel", "sorelFFNN", "AV1", "custom"],
    default="sorelFFNN")
```

---

## 3. Chạy với surrogate

```bash
python ppo.py --target sorelFFNN
python ppo.py --target ember
python evaluate.py --target sorelFFNN --agent saved_models/xxx.zip
```
