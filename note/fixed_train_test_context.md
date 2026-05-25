# Fixed Train/Test Dataset Mode

## Goal

Cho phep chay RL voi tap train va tap test da tach san, khong de code tu chia lai 70/30.

## Source changes

- `malware_rl/__init__.py`
  - Them bien moi:

```text
MALWARE_RL_TRAIN_DIR=<path_to_train_dataset>
MALWARE_RL_TEST_DIR=<path_to_test_dataset>
```

  - Neu ca hai bien nay duoc set, code se:
    - load sample tu thu muc train rieng
    - load sample tu thu muc test rieng
    - khong goi `train_test_split`
    - dang ky `*-train-v0` bang train list
    - dang ky `*-test-v0` bang test list
    - luu manifest vao `data/splits/samples/`

- `malware_rl/envs/utils/interface.py`
  - Them registry de moi sample id co the doc tu root rieng.
  - `fetch_sample(sample_id)` van duoc env goi nhu cu, nhung co the doc tu train/test root da dang ky.
  - `get_available_sha256(sample_root)` co the scan recursive tu bat ky root nao.
  - `save_dataset_split(...)` co the luu them `source_roots` vao `split.json`.
  - `load_dataset_split(...)` se tu dang ky lai source roots neu `split.json` co `source_roots`.

## Dataset structure

Dat train va test thanh hai thu muc rieng, moi thu muc van giu family folder:

```text
data/my_dataset/train/Locker/a.exe
data/my_dataset/train/Zbot/b.exe
data/my_dataset/test/Locker/c.exe
data/my_dataset/test/Zbot/d.exe
```

Sample id trong code se la relative path trong tung root:

```text
Locker/a.exe
Zbot/b.exe
```

Train va test khong duoc co cung mot relative sample id. Vi du neu ca hai ben deu co `Locker/a.exe`, code se bao loi de tranh doc nham root.

## Run train

PowerShell:

```powershell
$env:MALWARE_RL_TRAIN_DIR="data/my_dataset/train"
$env:MALWARE_RL_TEST_DIR="data/my_dataset/test"
python ppo.py --target custom --seed 26871 --num-queries 4096 --num-episodes 300
```

Trong mode nay:

- `custom-train-v0` dung toan bo file trong `MALWARE_RL_TRAIN_DIR`
- `custom-test-v0` dung toan bo file trong `MALWARE_RL_TEST_DIR`
- khong co chia random
- evasion chi luu khi test vi `custom-test-v0` co `save_modified_data=True`

## Run evaluate only

```powershell
$env:MALWARE_RL_TRAIN_DIR="data/my_dataset/train"
$env:MALWARE_RL_TEST_DIR="data/my_dataset/test"
python evaluate.py --target custom --agent saved_models/ppo-only-custom-train-v0-26871.zip --seed 26871
```

## Manifest output

Khi chay voi train/test dir, code se ghi manifest vao:

```text
data/splits/samples/split.json
data/splits/samples/train.txt
data/splits/samples/test.txt
data/splits/samples/train/<family>/samples.txt
data/splits/samples/test/<family>/samples.txt
```

`split.json` co them `source_roots`, nen co the dung lai bang:

```powershell
$env:MALWARE_RL_SPLIT_FILE="data/splits/samples/split.json"
python evaluate.py --target custom --agent saved_models/ppo-only-custom-train-v0-26871.zip --seed 26871
```

Khong set dong thoi `MALWARE_RL_SPLIT_FILE` voi `MALWARE_RL_TRAIN_DIR` / `MALWARE_RL_TEST_DIR`.

## Fallback behavior

Neu khong set `MALWARE_RL_TRAIN_DIR`, `MALWARE_RL_TEST_DIR`, hoac `MALWARE_RL_SPLIT_FILE`, code quay ve hanh vi cu:

- scan `malware_rl/envs/utils/samples/`
- tu chia train/test theo ty le 70/30
- seed mac dinh `MALWARE_RL_SPLIT_SEED=42`
