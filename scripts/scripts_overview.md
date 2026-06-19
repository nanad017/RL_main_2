# Tong quan cac script

Thu muc nay hien co 3 file Bash script. Cac script nay phu hop de chay tren Linux, WSL, hoac Git Bash hon la PowerShell thuan.

## copy_test_split.sh

Script dung de copy cac sample that nam trong test split sang mot folder rieng.

Mac dinh:

- Doc danh sach test tu `data/splits/samples/test.txt`
- Lay sample goc tu `malware_rl/envs/utils/samples`
- Ghi output vao `data/test_samples`

Cach chay mac dinh:

```bash
bash scripts/copy_test_split.sh
```

Cach chi dinh duong dan rieng:

```bash
bash scripts/copy_test_split.sh <split_file> <source_samples_dir> <output_dir>
```

Vi du:

```bash
bash scripts/copy_test_split.sh data/splits/samples/test.txt malware_rl/envs/utils/samples data/test_samples
```

## run_custom_detector_with_stoke.sh

Script dieu phoi chay pipeline RL voi custom detector va STOKE rewrite.

No set cac bien moi truong lien quan den:

- Custom detector API
- Shared root cho detector
- STOKE Python runtime
- STOKE worker
- Dataset train/test
- So episode, query, timestep, boosting round

Cac mode co san:

```bash
bash scripts/run_custom_detector_with_stoke.sh check
bash scripts/run_custom_detector_with_stoke.sh test
bash scripts/run_custom_detector_with_stoke.sh random
bash scripts/run_custom_detector_with_stoke.sh ppo
bash scripts/run_custom_detector_with_stoke.sh meme
bash scripts/run_custom_detector_with_stoke.sh meme-sorelffnn
bash scripts/run_custom_detector_with_stoke.sh env
```

Y nghia nhanh:

- `check`: kiem tra cau hinh, Python runtime, STOKE worker, action space
- `test`: chay pytest cho STOKE bridge
- `random`: chay `random_agent.py` voi target custom
- `ppo`: chay `ppo.py` voi target custom
- `meme`: chay `ppo_model_extract.py` voi target custom
- `meme-sorelffnn`: chay `ppo_model_extract.py` voi target sorelFFNN
- `env`: in cau hinh hien tai

Day la script de chay thi nghiem/model, khong phai script dung de cai dat moi truong.

## recreate_env_no_dataset.sh

Script dung de dung lai moi truong Python sach cho project, khong kem dataset.

Mac dinh:

- Dung Python `3.7.17`
- Tao virtualenv `.venv37_clean`
- Build/cai `libffi`
- Build/cai `bzip2`
- Cai dependency tu `requirements.txt`
- Tai Ember model
- Tao mot so thu muc can thiet trong `malware_rl/envs`

Script nay yeu cau cac lenh he thong:

- `curl`
- `tar`
- `make`
- `gcc`
- `pyenv`

Can luu y truoc khi chay:

- Script co tai file tu internet
- Script co compile thu vien
- Script ghi vao `$HOME/.local`
- Script tao virtualenv trong project

Nen chay script nay trong Linux/WSL khi da co day du toolchain can thiet.

