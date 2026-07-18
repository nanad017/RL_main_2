Dưới đây là bản ghi lại **chi tiết, rõ hơn** cho codebase `~/RL/RL_main_2` theo những gì anh đang chạy.

## Tổng quan codebase

Codebase này dùng để train RL agent nhằm tạo mẫu/ảnh đầu vào có khả năng **né detector custom**.

Luồng chính hiện tại:

```text
RL_main_2
├── scripts/run_custom_detector_with_stoke.sh
├── ppo_model_extract.py
├── evaluate.py
├── saved_models/
├── logs/
└── data/share/
```

## 1. Detector API

Detector chạy riêng ở repo `detector`.

Lệnh chạy debug:

```bash
mkdir -p logs
nohup env CUSTOM_DETECTOR_SHARED_ROOT=/home/rl/RL/RL_main_2/data/share \
  venv/bin/python -m uvicorn API:app --host 0.0.0.0 --port 8000 --reload --log-level debug \
  > logs/custom_api.out 2>&1 &
echo $!
```

Xem log:

```bash
tail -f logs/custom_api.out
```

Ý nghĩa:

```text
CUSTOM_DETECTOR_SHARED_ROOT
```

là thư mục share chung giữa RL code và detector API.

Detector API đọc/ghi dữ liệu qua:

```text
/home/rl/RL/RL_main_2/data/share
```

RL gọi API qua:

```text
http://127.0.0.1:8000
```

Nếu chạy ổn định lâu dài thì nên bỏ `--reload`:

```bash
mkdir -p logs
nohup env CUSTOM_DETECTOR_SHARED_ROOT=/home/rl/RL/RL_main_2/data/share \
  venv/bin/python -m uvicorn API:app --host 0.0.0.0 --port 8000 --log-level info \
  > logs/custom_api.out 2>&1 &
echo $!
```

## 2. Script train chính

File:

```text
scripts/run_custom_detector_with_stoke.sh
```

Script này setup biến môi trường rồi gọi pipeline train.

Lệnh train hiện tại theo hướng `TRAIN_ONLY=1`:

```bash
cd /home/rl/RL/RL_main_2
mkdir -p logs

nohup env \
  CUSTOM_DETECTOR_URL=http://127.0.0.1:8000 \
  CUSTOM_DETECTOR_SHARED_ROOT=/home/rl/RL/RL_main_2/data/share \
  MALWARE_RL_DISABLE_STOKE_FUNC_CHECK=1 \
  TRAIN_ONLY=1 \
  EVAL_TIMESTEPS=59610 \
  NUM_TIMESTEPS=59610 \
  NUM_ROUNDS=1 \
  bash scripts/run_custom_detector_with_stoke.sh meme \
  > logs/rl_custom_meme.out 2>&1 &
echo $!
```

Xem log:

```bash
tail -f logs/rl_custom_meme.out
```

Pipeline sẽ:

```text
1. train trên custom-train-v0
2. lưu checkpoint pre-surrogate-round-1
3. dừng trước train_surrogate()
4. không chạy test cuối
```

Checkpoint dự kiến:

```text
saved_models/ppo-model_rl-custom-train-v0-39720-pre-surrogate-round-1.zip
```

## 3. File train PPO

File chính:

```text
ppo_model_extract.py
```

Vai trò:

```text
- tạo môi trường custom-train-v0
- train PPO agent
- lưu model checkpoint
- bình thường có thể gọi train_surrogate()
- nhưng với TRAIN_ONLY=1 thì dừng trước surrogate
```

Anh đã sửa ở:

```text
ppo_model_extract.py:126
```

Ý nghĩa sửa:

```text
Nếu TRAIN_ONLY=1:
  - train PPO xong
  - save checkpoint
  - return/dừng pipeline
  - không chạy surrogate
  - không chạy test cuối
```

## 4. File evaluate test cuối

File:

```text
evaluate.py
```

Dùng để test model đã train trên môi trường custom test.

Lệnh test cuối bằng nohup:

```bash
cd /home/rl/RL/RL_main_2
mkdir -p logs

nohup env CUSTOM_DETECTOR_SHARED_ROOT=/home/rl/RL/RL_main_2/data/share \
  /home/rl/RL/RL_main_2/.venv37_clean/bin/python evaluate.py \
  --target custom \
  --seed 39720 \
  --agent saved_models/ppo-model_rl-custom-train-v0-39720-pre-surrogate-round-1.zip \
  > logs/rl_custom_eval.out 2>&1 &
echo $!
```

Xem log:

```bash
tail -f logs/rl_custom_eval.out
```

Ý nghĩa:

```text
--target custom
```

chạy môi trường custom detector.

```text
--seed 39720
```

phải khớp seed của model train.

```text
--agent ...
```

là đường dẫn checkpoint cần test.

Hiện tại `evaluate.py` mặc định chạy khoảng:

```text
300 episode
```

trên:

```text
custom-test-v0
```

## 5. Kiểm tra process

Kiểm tra detector API:

```bash
ps -ef | grep uvicorn
```

Kiểm tra train PPO:

```bash
ps -ef | grep ppo_model_extract.py
```

Kiểm tra evaluate:

```bash
ps -ef | grep evaluate.py
```

Kiểm tra PID cụ thể:

```bash
ps -fp <PID>
```

Dừng process:

```bash
kill <PID>
```

Nếu không dừng:

```bash
kill -9 <PID>
```

## 6. Thứ tự chạy chuẩn

### Bước 1: chạy detector API

Trong repo detector:

```bash
mkdir -p logs
nohup env CUSTOM_DETECTOR_SHARED_ROOT=/home/rl/RL/RL_main_2/data/share \
  venv/bin/python -m uvicorn API:app --host 0.0.0.0 --port 8000 --log-level info \
  > logs/custom_api.out 2>&1 &
echo $!
```

### Bước 2: kiểm tra API còn sống

```bash
tail -f logs/custom_api.out
```

Hoặc:

```bash
ps -ef | grep uvicorn
```

### Bước 3: chạy train only

Trong `/home/rl/RL/RL_main_2`:

```bash
mkdir -p logs
nohup env \
  CUSTOM_DETECTOR_URL=http://127.0.0.1:8000 \
  CUSTOM_DETECTOR_SHARED_ROOT=/home/rl/RL/RL_main_2/data/share \
  TRAIN_ONLY=1 \
  EVAL_TIMESTEPS=59610 \
  NUM_TIMESTEPS=59610 \
  NUM_ROUNDS=1 \
  bash scripts/run_custom_detector_with_stoke.sh meme \
  > logs/rl_custom_meme.out 2>&1 &
echo $!
```

### Bước 4: xem log train

```bash
tail -f logs/rl_custom_meme.out
```

### Bước 5: sau khi có checkpoint, chạy evaluate

```bash
nohup env CUSTOM_DETECTOR_SHARED_ROOT=/home/rl/RL/RL_main_2/data/share \
  /home/rl/RL/RL_main_2/.venv37_clean/bin/python evaluate.py \
  --target custom \
  --seed 39720 \
  --agent saved_models/ppo-model_rl-custom-train-v0-39720-pre-surrogate-round-1.zip \
  > logs/rl_custom_eval.out 2>&1 &
echo $!
```

## Lệnh ngắn nhất cần nhớ

### Train only

```bash
cd /home/rl/RL/RL_main_2 && mkdir -p logs && nohup env CUSTOM_DETECTOR_URL=http://127.0.0.1:8000 CUSTOM_DETECTOR_SHARED_ROOT=/home/rl/RL/RL_main_2/data/share TRAIN_ONLY=1 EVAL_TIMESTEPS=59610 NUM_TIMESTEPS=59610 NUM_ROUNDS=1 bash scripts/run_custom_detector_with_stoke.sh meme > logs/rl_custom_meme.out 2>&1 & echo $!
```

### Test cuối

```bash
cd /home/rl/RL/RL_main_2 && mkdir -p logs && nohup env CUSTOM_DETECTOR_SHARED_ROOT=/home/rl/RL/RL_main_2/data/share /home/rl/RL/RL_main_2/.venv37_clean/bin/python evaluate.py --target custom --seed 39720 --agent saved_models/ppo-model_rl-custom-train-v0-39720-pre-surrogate-round-1.zip > logs/rl_custom_eval.out 2>&1 & echo $!
```
