# Work Done

## 1. Python va virtualenv

Da tao moi truong:

```bash
python3.7 -m venv .venv37_clean
```

Da dung moi truong nay de cai dependencies cua du an.

## 2. Da sua `requirements.txt`

Da chinh cac version de giai conflict voi Python 3.7:

- `appnope==0.1.0` -> chi cai tren macOS
- `ipython==8.10.0` -> `ipython==7.34.0`
- `gym==0.17.2` -> `gym==0.21.0`
- `numpy==1.22.0` -> `numpy==1.18.5`
- `protobuf>=3.18.3` -> `protobuf>=3.18.3,<4`
- `stable-baselines3` -> `stable-baselines3==1.6.2`
- `tensorflow>=2.3.1` -> `tensorflow==2.3.1`
- `urllib3>=1.26.5` -> `urllib3==1.25.11`
- `importlib-metadata==1.7.0` -> `importlib-metadata==4.13.0`
- them `torch` ban CPU-only

## 3. Da sua Python 3.7 cua may

Ban `pyenv` Python 3.7.17 ban dau bi thieu module he thong, gay loi khi cai package:

- `_ctypes`
- `_bz2`

Da build thu cong:

- `libffi` tai `/home/rl/.local/opt/libffi-3.4.6`
- `bzip2` tai `/home/rl/.local/opt/bzip2-1.0.8`

Sau do rebuild lai `pyenv` Python `3.7.17`.

Ket qua:

- `import ctypes` OK
- `import bz2` OK

Van con thieu mot so module he thong khac:

- `_lzma`
- `_sqlite3`
- `_curses`
- `readline`
- `_tkinter`

## 4. Da cai xong Python packages

Trong `.venv37_clean`, da cai xong cac goi chinh:

- `tensorflow==2.3.1`
- `tensorflow-estimator==2.3.0`
- `gym==0.21.0`
- `stable-baselines3==1.6.2`
- `torch==1.13.1+cpu`
- `lightgbm==2.3.1`
- `lief==0.12.3`

## 5. Da cai them cac file/phu thuoc runtime khong phai dataset

### Da co san hoac da bo sung

- `malware_rl/envs/utils/malconv.h5` da co san trong repo
- da tai `malware_rl/envs/utils/ember_model.txt`
- da copy them `malware_rl/envs/utils/lgb_ember_model.txt`
- da tai benign executable vao:
  - `malware_rl/envs/controls/trusted/xournalpp-1.0.18-windows.exe`
- da sinh strings vao:
  - `malware_rl/envs/controls/good_strings/xournal-strings.txt`
- da tai binary:
  - `malware_rl/envs/controls/upx`

## 6. Da sua code de `upx` chay dung

Da sua file:

- `malware_rl/envs/controls/modifier.py`

Noi dung sua:

- them ham tim `upx` ngay trong thu muc `controls`
- neu co file `malware_rl/envs/controls/upx` thi uu tien dung file nay
- neu khong co moi fallback sang `PATH`

Muc dich:

- code cua repo goi `upx` bang subprocess
- README bao chi can dat binary vao thu muc `controls`
- sua nay giup hai phan do khop nhau

## 7. Da kiem tra duoc gi

Da test thanh cong:

- import TensorFlow
- import Gym
- import Stable-Baselines3
- import LightGBM
- import LIEF
- file `trusted/` va `good_strings/` da co noi dung that
- `upx` da ton tai trong repo
- `ember_model.txt` da ton tai

## 8. Phan con thieu

Cac file nay van chua co:

- `malware_rl/envs/utils/sorel.model`
- `malware_rl/envs/utils/sorelFFNN.pt`

Vi repo import mot so module `sorel` ngay khi load package, nen neu 2 file nay chua co thi mot so lenh import se loi.

## 9. Viec dang lam do anh dung giua chung

Toi da bat dau tai baseline SOREL public models de bo sung:

- `sorel.model`
- `sorelFFNN.pt`

Nhung anh da dung turn do giua chung, nen khong xac nhan duoc viec tai xong hay chua.

Can kiem tra lai cac file sau:

```bash
ls -lh malware_rl/envs/utils/sorel.model
ls -lh malware_rl/envs/utils/sorelFFNN.pt
```

Neu chua co, can tai tiep.

## 10. Khong lam

Theo dung yeu cau, chua tai dataset/malware samples.

Cac thu muc du lieu malware van khong duoc nap them:

- `malware_rl/envs/utils/samples/`

Script `download_deps.py --accept` chua duoc chay.
