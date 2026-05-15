# Reproduce On A New Machine (No Malware/Dataset Download)

Muc tieu: chi `git clone` repo, tao moi truong Python 3.7 va tai cac file cong khai can thiet cho model. Khong tai malware samples/dataset. Cac artefact tuy chon nhu `upx`, `good_strings`, `trusted` sample de trong cau truc thu muc de bo sung sau.

## 1. Yeu cau tren may moi

- Linux x86_64 (khuyen nghi)
- Co `pyenv`, `gcc`, `make`, `curl`, `tar`
- Co internet de tai source/wheels/models

## 2. Clone va chay script

```bash
git clone <REPO_URL>
cd meme_modify
bash scripts/recreate_env_no_dataset.sh
source .venv37_clean/bin/activate
```

## 3. Cai gi script se lam

- Build `libffi` va `bzip2` vao `$HOME/.local/opt/...` (khong can sudo)
- Rebuild Python `3.7.17` bang `pyenv` de co `_ctypes` va `_bz2`
- Tao venv `.venv37_clean`
- Cai `pip install -r requirements.txt`
- Tai:
  - `malware_rl/envs/utils/ember_model.txt`
  - `malware_rl/envs/utils/lgb_ember_model.txt` (copy tu ember model)
 - Tao cau truc thu muc rong:
   - `malware_rl/envs/controls/trusted/`
   - `malware_rl/envs/controls/good_strings/`
   - `malware_rl/envs/utils/samples/`

## 4. Khong tai dataset

Script KHONG chay `download_deps.py --accept`, vi lenh do se tai malware samples.

Script cung KHONG tai `upx`, trusted PE hay `good_strings`. Neu can, ban tu bo sung sau.

## 5. Push cai gi

Khong push `.venv*/`, model files lon, UPX binary, trusted/good_strings, samples.

Da cap nhat `.gitignore` de tu dong bo qua nhung thu nay.

Ban chi can push:

- code
- `requirements.txt`
- `scripts/recreate_env_no_dataset.sh`
- `REPRODUCE_ON_NEW_MACHINE.md`
- `SETUP_FIXES.md`, `WORK_DONE.md` (neu muon luu ghi chep)
