# Setup And Dependency Fixes

Ngay trong thu muc du an `meme_modify`, toi da tao moi truong ao Python 3.7 moi:

```bash
python3.7 -m venv .venv37_clean
source .venv37_clean/bin/activate
```

## Cac thay doi trong `requirements.txt`

Da sua cac dong sau de giai conflict va phu hop voi Python 3.7:

- `appnope==0.1.0` -> `appnope==0.1.0; platform_system == "Darwin"`
- `ipython==8.10.0` -> `ipython==7.34.0`
- `gym==0.17.2` -> `gym==0.21.0`
- `numpy==1.22.0` -> `numpy==1.18.5`
- `protobuf>=3.18.3` -> `protobuf>=3.18.3,<4`
- `stable-baselines3` -> `stable-baselines3==1.6.2`
- `tensorflow>=2.3.1` -> `tensorflow==2.3.1`
- `urllib3>=1.26.5` -> `urllib3==1.25.11`
- `importlib-metadata==1.7.0` -> `importlib-metadata==4.13.0`
- them:

```txt
torch @ https://download.pytorch.org/whl/cpu/torch-1.13.1%2Bcpu-cp37-cp37m-linux_x86_64.whl
```

## Van de phat hien trong Python 3.7 cua may

Ban Python `3.7.17` trong `pyenv` ban dau bi thieu module he thong:

- `_ctypes`
- `_bz2`

Dieu nay lam:

- `pip` khong build duoc wheel cho mot so goi
- `stable_baselines3` import loi vi `pandas` can `bz2`

## Cach da xu ly

Da build thu cong cac thu vien he thong vao thu muc nguoi dung:

- `libffi` tai: `/home/rl/.local/opt/libffi-3.4.6`
- `bzip2` tai: `/home/rl/.local/opt/bzip2-1.0.8`

Sau do rebuild lai `pyenv` Python `3.7.17` voi cac bien moi truong tro toi cac thu vien tren.

## Cac thao tac pip quan trong

Da dung:

```bash
./.venv37_clean/bin/pip install --upgrade pip 'setuptools<66' wheel==0.37.1
```

Ly do:

- `setuptools` moi hon gay van de voi mot so goi cu
- `wheel 0.42.0` gay loi khi build `gym==0.21.0`
- `wheel==0.37.1` build `gym` thanh cong

## Ket qua cuoi

Moi truong `.venv37_clean` da cai thanh cong cac goi chinh:

- `tensorflow==2.3.1`
- `tensorflow-estimator==2.3.0`
- `gym==0.21.0`
- `stable-baselines3==1.6.2`
- `torch==1.13.1+cpu`
- `lightgbm==2.3.1`
- `lief==0.12.3`

Da kiem tra import thanh cong:

```python
import tensorflow as tf
import gym
import stable_baselines3
import lightgbm
import lief
```

## Canh bao con lai

Python 3.7 hien tai van thieu mot so module he thong khac:

- `_lzma`
- `_sqlite3`
- `_curses`
- `readline`
- `_tkinter`

Anh huong hien tai:

- stack chinh cua du an da import duoc
- `pandas` se canh bao ve `lzma`
- TensorFlow se canh bao thieu CUDA neu may khong co GPU, co the bo qua

## Cach dung

```bash
cd /home/rl/meme_modify
source .venv37_clean/bin/activate
```
