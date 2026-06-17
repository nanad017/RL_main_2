# Worklog: STOKE Integration, Custom Runner, And Surrogate Fixes

**Generated:** 2026-06-01 12:47:32 UTC
**Repo:** `/home/rl/RL/RL_main_2`

## 1. Mục tiêu đã xử lý

Trong phiên làm việc này, tôi đã xử lý các hạng mục chính sau:

1. Tích hợp backend mới cho action `stoke_rewrite` bằng mô hình `bridge 3.7 -> worker 3.9+`.
2. Giữ nguyên compatibility của action space hiện tại:
   - `stoke_rewrite` vẫn ở index `16`
   - `bytecode_swap` ở index `17`
3. Cập nhật tài liệu action và tài liệu custom mode theo trạng thái mã thật.
4. Tạo script chạy tổng hợp cho:
   - `custom` detector
   - `sorelFFNN` mode với dataset path đã chỉ định
5. Gỡ 2 blocker cho `custom + LightGBM surrogate`:
   - thiếu package `ember`
   - `surrogate.py` hardcode đường dẫn EMBER cũ thay vì dùng dữ liệu local
6. Copy bộ dữ liệu local `ember_dat` từ repo khác sang repo hiện tại.

---

## 2. Thay đổi mã nguồn đã thực hiện

### 2.1. STOKE backend

#### File thêm mới

- `malware_rl/envs/controls/stoke_worker.py`
  - Worker chạy bằng Python `>=3.9`
  - `import stoke_actions` chỉ diễn ra ở đây
  - nhận `--input`, `--output`, `--n`, `--seed`, `--rewrites`
  - in JSON status ra stdout
  - enforce output cùng size với input

- `malware_rl/envs/controls/stoke_bridge.py`
  - Bridge Python 3.7-compatible
  - đọc các env:
    - `STOKE_PYTHON`
    - `STOKE_WORKER`
    - `STOKE_N`
    - `STOKE_REWRITES`
    - `STOKE_TIMEOUT`
    - `STOKE_SEED`
  - gọi worker qua `subprocess`
  - fallback về bytes gốc nếu worker lỗi, timeout, JSON lỗi, output thiếu, hoặc size mismatch

#### File sửa

- `malware_rl/envs/controls/modifier.py`
  - thêm import:
    - `from .stoke_bridge import apply_stoke_action as _apply_stoke_action`
  - thay thân `ModifyBinary.stoke_rewrite()` thành wrapper gọi bridge
  - bỏ backend STOKE cũ dựa trên `get_stoke_command()`
  - không đổi `ACTION_TABLE` hiện tại
  - không đổi vị trí runtime của `stoke_rewrite` trong action space

### 2.2. Test cho STOKE integration

#### File thêm mới

- `malware_rl/envs/controls/test_stoke_bridge.py`
  - test giữ index của `stoke_rewrite`
  - test fallback khi worker thiếu
  - test dispatch qua `modifier.modify_sample(...)`
  - test worker thật với sample PE và output cùng size

### 2.3. Tài liệu

#### File sửa

- `docs/mo_ta_chi_tiet_actions.md`
  - cập nhật từ 17 action lên 18 action
  - phản ánh đúng Tier 3 hiện tại gồm:
    - `stoke_rewrite`
    - `bytecode_swap`
  - thay mô tả STOKE cũ bằng flow `bridge + worker + stoke_actions`
  - ghi rõ `stoke_rewrite` hiện ở index `16`

- `docs/custom_mode/README.md`
  - thêm biến môi trường `STOKE_*`
  - thêm cách dùng script tổng hợp
  - cập nhật `STOKE_PYTHON` về env thật:
    `/home/rl/miniconda3/envs/sorel-malware-detector/bin/python`

### 2.4. Script chạy

#### File thêm mới

- `scripts/run_custom_detector_with_stoke.sh`
  - script wrapper cho các mode:
    - `check`
    - `test`
    - `random`
    - `ppo`
    - `meme`
    - `meme-sorelffnn`
    - `env`
  - tự export:
    - `CUSTOM_*`
    - `STOKE_*`
    - `MALWARE_RL_TRAIN_DIR`
    - `MALWARE_RL_TEST_DIR`
  - mode `meme-sorelffnn` tự chạy:
    - `--target sorelFFNN`
    - `--eval_timesteps 59610`
    - `--num_timesteps 59610`
    - `--num_rounds 1`
  - default dataset path:
    - `$HOME/RL/dataset/main_dataset/RL/virus`
    - `$HOME/RL/dataset/main_dataset/test`

### 2.5. Surrogate / EMBER path

#### File sửa

- `surrogate.py`
  - đổi `import ember` thành lazy-safe import:
    - nếu chưa có package thì giữ `ember = None`
  - thêm resolver cho dữ liệu EMBER:
    - ưu tiên env `MALWARE_RL_EMBER_DATA_DIR`
    - rồi `./ember_dat`
    - rồi fallback `/data/mari/ember2018`
  - thêm loader cho local memmap files:
    - `X_val.dat`
    - `X_test.dat`
    - `y_val.dat`
    - `y_test.dat`
  - nhánh `target in ['ember', 'custom']` giờ dùng local `./ember_dat` nếu có
  - sửa bug case-sensitive:
    - `elif target == 'SorelFFNN'` -> `elif target == 'sorelFFNN'`

---

## 3. Dữ liệu và dependency đã xử lý

### 3.1. Copy dữ liệu EMBER local

Đã copy các file sau từ repo cũ `/home/rl/RL/meme_modify/ember_dat` sang:

- `/home/rl/RL/RL_main_2/ember_dat/X_test.dat`
- `/home/rl/RL/RL_main_2/ember_dat/X_val.dat`
- `/home/rl/RL/RL_main_2/ember_dat/y_test.dat`
- `/home/rl/RL/RL_main_2/ember_dat/y_val.dat`
- `/home/rl/RL/RL_main_2/ember_dat/test_manifest.csv`
- `/home/rl/RL/RL_main_2/ember_dat/val_manifest.csv`

### 3.2. Cài package

Trong `.venv37_clean` đã cài:

- `ember`
  - từ GitHub repo `elastic/ember`
- `tqdm`
  - là dependency thiếu làm `import ember` fail sau khi cài package chính

---

## 4. Kiểm tra đã chạy

### 4.1. STOKE path

Đã xác nhận:

- `scripts/run_custom_detector_with_stoke.sh check`
  - `stoke_rewrite` index `16`
  - `bytecode_swap` index `17`
  - `STOKE_PYTHON` đúng:
    `/home/rl/miniconda3/envs/sorel-malware-detector/bin/python`
  - `stoke_actions: True`
  - `capstone: True`

### 4.2. Kiểm tra code / test

Đã chạy:

- compile check cho các file STOKE mới/sửa
- `pytest malware_rl/envs/controls/test_stoke_bridge.py -q`
- worker standalone trên sample PE
- bridge 3.7 -> worker 3.9+ trên sample PE

### 4.3. Kiểm tra EMBER / surrogate

Đã xác nhận:

- `.venv37_clean` import được `ember`
- `surrogate.py` import được
- `surrogate._resolve_ember_data_dir()` trả về:
  - `/home/rl/RL/RL_main_2/ember_dat`
- `surrogate.get_ember_data('ember_dat')` chạy được
  - `X_train.shape == (3988, 2381)`
  - `X_test.shape == (3988, 2381)`
  - `y_train.shape == (3988,)`
  - `y_test.shape == (3988,)`

---

## 5. Blocker đã gỡ

### 5.1. Blocker 1: `ModuleNotFoundError: No module named 'ember'`

Nguyên nhân:

- `ppo_model_extract.py` import `surrogate.py`
- `surrogate.py` import `ember`
- `.venv37_clean` chưa có package `ember`

Trạng thái hiện tại:

- đã gỡ xong

### 5.2. Blocker 2: `surrogate.py` không dùng dữ liệu local `ember_dat`

Nguyên nhân:

- code hardcode `/data/mari/ember2018`
- bộ `.dat` local trong repo không được dùng

Trạng thái hiện tại:

- đã gỡ xong

---

## 6. Blocker mới phát hiện sau khi gỡ 2 lỗi trên

### 6.1. `sorelFFNN-train-v0` chưa được register

Khi smoke-test import tiếp theo cho `ppo_model_extract.py`, lỗi mới xuất hiện:

- `gym.error.UnregisteredEnv: No registered env with id: sorelFFNN-train-v0`

Nguyên nhân:

- trong `malware_rl/__init__.py`, các env surrogate/SOREL đang bị comment hoặc không được register tương ứng
- nên `ppo_model_extract.py --target sorelFFNN` chưa chạy được hết chỉ bằng việc gỡ lỗi EMBER

Ảnh hưởng:

- không chặn case `custom` nếu dùng `custom-train-v0`
- chặn case `sorelFFNN` cho đến khi đăng ký env tương ứng

---

## 7. Trạng thái hiện tại theo mục tiêu

### 7.1. `custom + LightGBM surrogate`

Trạng thái:

- gần hoàn chỉnh
- hai blocker chính về `ember` và `ember_dat` đã được gỡ
- cần detector API custom chạy đúng shared root để chạy full `ppo_model_extract.py`

### 7.2. `sorelFFNN + ppo_model_extract.py`

Trạng thái:

- chưa hoàn chỉnh
- hiện còn blocker:
  - env `sorelFFNN-train-v0` chưa được register

---

## 8. Những file trong worktree không phải trọng tâm của phiên này

`git status --short` tại thời điểm tạo báo cáo còn cho thấy một số thay đổi/untracked khác đã có trong repo, ví dụ:

- `malware_rl/envs/controls/_equiv_map_loader.py`
- `malware_rl/envs/controls/test_bytecode_swap.py`
- `training.log`
- `ppo_custom_tensorboard/PPO_2/`
- `ppo_custom_tensorboard/PPO_3/`
- các file trong `set_up/`

Các mục này không phải là phần mới do riêng hạng mục STOKE/custom/surrogate của phiên hiện tại sinh ra hoàn toàn, nên cần phân biệt khi review hoặc commit.

---

## 9. Tóm tắt ngắn

Trong phiên này, tôi đã:

1. Tích hợp xong backend STOKE mới bằng worker Python 3.9+.
2. Cập nhật tài liệu action và custom mode.
3. Tạo script chạy tổng hợp cho `custom` và `sorelFFNN`.
4. Copy bộ `ember_dat` local vào repo hiện tại.
5. Cài `ember` và `tqdm` vào `.venv37_clean`.
6. Sửa `surrogate.py` để dùng được local `ember_dat`.
7. Xác nhận `custom + LightGBM surrogate` đã vượt qua 2 blocker ban đầu.
8. Phát hiện thêm blocker độc lập cho `sorelFFNN`: env chưa được register.
