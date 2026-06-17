# Worklog: surrogate checkpoint và dọn cache hỏng

Ngày ghi nhận: `2026-06-02`

## Bối cảnh

Run `bash scripts/run_custom_detector_with_stoke.sh meme` bị dừng ở bước train surrogate với lỗi:

```text
lightgbm.basic.LightGBMError: Length of label is not same with #data
```

## Nguyên nhân

Cache dữ liệu surrogate cũ trong `malware_rl/envs/utils/` bị lệch số mẫu giữa:

- `observations.npy`
- `scores.npy`

Khi `train_surrogate()` nối dữ liệu cũ với batch RL mới, số dòng của `X` và `y` không còn khớp nhau, nên LightGBM crash.

## Thay đổi đã làm

### 1. Lưu agent trước khi gọi `train_surrogate()`

Đã thêm checkpoint ngay trước bước train surrogate trong `ppo_model_extract.py`:

```python
agent.save(f"saved_models/ppo-model_rl-{TARGET}-train-v0-{SEED}-pre-surrogate-round-{i+1}")
```

Vị trí: `ppo_model_extract.py`, ngay trước:

```python
threshold = train_surrogate(TARGET, data_path, save_model_path, SEED)
```

Mục đích:

- nếu surrogate crash, vẫn còn checkpoint agent của round hiện tại
- giảm mất mát khi pipeline hỏng ở bước hậu xử lý dữ liệu / train surrogate

### 2. Xóa cache surrogate cũ bị hỏng

Đã xóa:

- `malware_rl/envs/utils/observations.npy`
- `malware_rl/envs/utils/scores.npy`

Mục đích:

- tránh lặp lại lỗi `Length of label is not same with #data`
- ép pipeline tạo lại cache sạch từ dữ liệu mới

## Trạng thái sau thay đổi

- `ppo_model_extract.py` đã qua kiểm tra cú pháp (`py_compile`)
- cache cũ gây lệch dữ liệu đã được dọn

## Ghi chú vận hành

Thay đổi này **không** giúp resume trực tiếp run đã crash trước đó.

Nó chỉ đảm bảo:

- các run sau không bị dính lại cache lệch cũ
- nếu surrogate lại crash, sẽ có checkpoint agent trước bước `train_surrogate()`
