# Reproduce On A New Machine (No Malware/Dataset Download)

Muc tieu: chi `git clone` repo, tao moi truong Python 3.7 va tai cac file cong khai can thiet (Ember model, UPX, benign trusted/good_strings). Khong tai malware samples/dataset.

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
  - `malware_rl/envs/controls/upx`
  - `malware_rl/envs/controls/trusted/xournalpp-1.0.18-windows.exe`
  - `malware_rl/envs/controls/good_strings/xournal-strings.txt`

## 4. Khong tai dataset

Script KHONG chay `download_deps.py --accept`, vi lenh do se tai malware samples.

## 5. Push cai gi

Khong push `.venv*/`, model files lon, UPX binary, trusted/good_strings, samples.

Da cap nhat `.gitignore` de tu dong bo qua nhung thu nay.

Ban chi can push:

- code
- `requirements.txt`
- `scripts/recreate_env_no_dataset.sh`
- `REPRODUCE_ON_NEW_MACHINE.md`
- `SETUP_FIXES.md`, `WORK_DONE.md` (neu muon luu ghi chep)
