# Fixed Train/Test Dataset Mode

## User requirement

Nguoi dung muon chu dong chia dataset tu ben ngoai:

- Bo san data train vao mot thu muc rieng.
- Bo san data test vao mot thu muc rieng.
- Khi train model, code phai dung dung tap train do.
- Khi test/evaluate, code phai dung dung tap test do.
- Code khong duoc tu chia lai 70/30 neu da cung cap train/test folder.
- Khong can copy binary vao manifest; manifest chi ghi danh sach sample va root de doc lai.
- Lan sau chi can set duong dan train/test la model chay duoc.

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

## Dataset paths on Linux VM

Dataset hien tai tren Linux:

```text
/home/rl/RL/dataset/main_dataset/RL/benign
/home/rl/RL/dataset/main_dataset/RL/virus
/home/rl/RL/dataset/main_dataset/test/benign
/home/rl/RL/dataset/main_dataset/test/virus
```

Voi structure nay:

- train root = `/home/rl/RL/dataset/main_dataset/RL`
- test root = `/home/rl/RL/dataset/main_dataset/test`
- family folder la `benign` va `virus`

## Run train

Bash/Linux:

```bash
cd /path/to/meme_main

unset MALWARE_RL_SPLIT_FILE

export MALWARE_RL_TRAIN_DIR="/home/rl/RL/dataset/main_dataset/RL"
export MALWARE_RL_TEST_DIR="/home/rl/RL/dataset/main_dataset/test"

python ppo.py --target custom --seed 26871 --num-episodes 5961 --num-queries 59610
```

Trong mode nay:

- `custom-train-v0` dung toan bo file trong `MALWARE_RL_TRAIN_DIR`
- `custom-test-v0` dung toan bo file trong `MALWARE_RL_TEST_DIR`
- khong co chia random
- evasion chi luu khi test vi `custom-test-v0` co `save_modified_data=True`
- `maxturns` hien dang hard-code la `10` trong `malware_rl/__init__.py`, khong co CLI flag `--maxturns`

## Run evaluate only

```bash
cd /path/to/meme_main

unset MALWARE_RL_SPLIT_FILE

export MALWARE_RL_TRAIN_DIR="/home/rl/RL/dataset/main_dataset/RL"
export MALWARE_RL_TEST_DIR="/home/rl/RL/dataset/main_dataset/test"

python evaluate.py --target custom --agent saved_models/ppo-only-custom-train-v0-26871.zip --seed 26871
```

Luu y: `evaluate.py` hien chua co CLI flag `--num-episodes`, no goi `evaluate_model(..., 300, ...)` truc tiep trong code.

## Run random baseline

Neu muon chay random agent tren tap test voi cung gioi han:

```bash
cd /path/to/meme_main

unset MALWARE_RL_SPLIT_FILE

export MALWARE_RL_TRAIN_DIR="/home/rl/RL/dataset/main_dataset/RL"
export MALWARE_RL_TEST_DIR="/home/rl/RL/dataset/main_dataset/test"

python random_agent.py --target custom --seed 26871 --num-episodes 5961 --num-queries 59610
```

## Parameter locations

```text
/path/to/meme_main/ppo.py
  --num-episodes
  --num-queries

/path/to/meme_main/random_agent.py
  --num-episodes
  --num-queries

/path/to/meme_main/malware_rl/__init__.py
  MAXTURNS = 10

/path/to/meme_main/malware_rl/envs/utils/interface.py
  get_available_sha256(sample_root)
  fetch_sample(sample_id)
  save_dataset_split(...)
  load_dataset_split(...)
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

```bash
cd /path/to/meme_main

unset MALWARE_RL_TRAIN_DIR
unset MALWARE_RL_TEST_DIR

export MALWARE_RL_SPLIT_FILE="/path/to/meme_main/data/splits/samples/split.json"

python evaluate.py --target custom --agent saved_models/ppo-only-custom-train-v0-26871.zip --seed 26871
```

Khong set dong thoi `MALWARE_RL_SPLIT_FILE` voi `MALWARE_RL_TRAIN_DIR` / `MALWARE_RL_TEST_DIR`.

## Fallback behavior

Neu khong set `MALWARE_RL_TRAIN_DIR`, `MALWARE_RL_TEST_DIR`, hoac `MALWARE_RL_SPLIT_FILE`, code quay ve hanh vi cu:

- scan `malware_rl/envs/utils/samples/`
- tu chia train/test theo ty le 70/30
- seed mac dinh `MALWARE_RL_SPLIT_SEED=42`
