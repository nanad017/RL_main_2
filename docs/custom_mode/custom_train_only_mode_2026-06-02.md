# Worklog: thêm mode train-only cho custom MEME run

Ngày giờ ghi nhận: `2026-06-02 02:45:57 UTC`

## Mục tiêu

Cho phép chạy:

```bash
TRAIN_ONLY=1 bash scripts/run_custom_detector_with_stoke.sh meme
```

để:

- train trên `custom-train-v0`
- lưu agent checkpoint
- dừng trước `train_surrogate()`
- không chạy final test

## Thay đổi đã làm

### 1. `ppo_model_extract.py`

Đã thêm cờ CLI:

```python
--train_only
```

Hành vi:

- sau khi train trên target env và lưu checkpoint `pre-surrogate-round-N`
- nếu `--train_only` được bật thì `break`
- bỏ qua toàn bộ phần:
  - `train_surrogate(...)`
  - train trên surrogate
  - final eval trên `target-test-v0`

### 2. `scripts/run_custom_detector_with_stoke.sh`

Đã thêm env var:

```bash
TRAIN_ONLY="${TRAIN_ONLY:-0}"
```

Trong mode `meme`:

- nếu `TRAIN_ONLY=1`
- script sẽ truyền thêm:

```bash
--train_only
```

vào `ppo_model_extract.py`

Ngoài ra `show_config` và phần `Common overrides` đã được cập nhật để hiển thị `TRAIN_ONLY`.

## Cách dùng

Ví dụ train target-only với bộ tham số lớn:

```bash
TRAIN_ONLY=1 \
EVAL_TIMESTEPS=59610 \
NUM_TIMESTEPS=59610 \
NUM_ROUNDS=1 \
bash scripts/run_custom_detector_with_stoke.sh meme \
> logs/rl_custom_meme.out 2>&1 &
echo $!
```

Với mode này, run sẽ:

1. train target env
2. lưu checkpoint:

```text
saved_models/ppo-model_rl-custom-train-v0-<SEED>-pre-surrogate-round-1.zip
```

3. dừng

Nó sẽ **không**:

- train surrogate
- train tiếp trên `lgb-train-v0`
- chạy `custom-test-v0`

## Ghi chú

Mode này phù hợp khi muốn:

- train trước
- giữ lại agent
- tự test sau bằng `evaluate.py`
