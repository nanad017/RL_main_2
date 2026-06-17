# Ghi lại vấn đề: metric `evaded` lệch với logic save file

Ngày ghi nhận: `2026-06-01`

Trạng thái: `Đã sửa`

## Hiện tượng

Khi chạy:

```bash
CUSTOM_DETECTOR_SHARED_ROOT=/home/rl/RL/RL_main_2/data/share \
  bash scripts/run_custom_detector_with_stoke.sh meme \
  > logs/rl_custom_meme.out 2>&1 &
```

log cuối có thể báo:

- `0.0% samples evaded model.`
- `History: {}`

nhưng thư mục `data/evaded/custom` vẫn có file evade được lưu.

## Nguyên nhân

Có sự lệch giữa:

1. Tiêu chí **đếm metric evade** trong `ppo_model_extract.py`
2. Tiêu chí **xác định evade thật** trong env `custom_gym.py`

### 1. Metric cũ trong `ppo_model_extract.py`

Trong `evaluate_agent()`, episode chỉ được tính là evade nếu:

```python
if done and reward >= 10.0:
```

File: `ppo_model_extract.py`

### 2. Logic evade thật trong env

Trong `CustomDetectorEnv.step()`, sample được coi là evade nếu:

```python
self.score < self.threshold
```

và việc save file cũng dựa trên đúng điều kiện đó:

```python
if self.score < self.threshold and self.save_data:
```

File: `malware_rl/envs/custom_gym.py`

## Vì sao `reward >= 10.0` là sai tiêu chí

Reward hiện tại là reward shaped:

- evade thành công cho `R_bonus = 10.0`
- nhưng còn bị scale theo `lambda_q`
- còn bị trừ `r_size`
- chỉ cộng `r_tier` ở cuối episode

Nghĩa là sample có thể **đã evade thật** (`score < threshold`) nhưng reward cuối vẫn `< 10.0`.

Kết quả:

- metric trong log có thể báo `0.0%`
- `History` có thể rỗng
- nhưng file evade vẫn được lưu đúng theo logic env

## Ảnh hưởng

- Log đánh giá hiện tại có thể **under-report** số evade thật.
- Người đọc log dễ kết luận sai rằng agent không evade được sample nào.
- Số file trong `data/evaded/custom` có thể không khớp với `History` in ra từ `ppo_model_extract.py`.

## Điều kiện đúng để đếm evade

Metric evade nên bám theo cờ mà env đã trả về:

```python
ep_history["evaded"]
```

hoặc tương đương với điều kiện:

```python
score < threshold
```

Thay vì:

```python
reward >= 10.0
```

## Cách đã sửa

Success condition trong các entrypoint runtime đã được đổi từ:

```python
if done and reward >= 10.0:
```

sang:

```python
if done and ep_history["evaded"]:
```

Các file đã sửa:

- `ppo_model_extract.py`
- `ppo.py`
- `random_agent.py`
- `evaluate.py`

Sau thay đổi này:

- metric `evaded` bám theo logic thật của env
- `History` sẽ nhất quán hơn với số file được lưu trong `data/evaded/custom`
- reward tiếp tục chỉ đóng vai trò reward shaping, không còn bị dùng sai như proxy cho evade

## Ghi chú thêm

- Vấn đề này là vấn đề **metric/evaluation reporting**, không phải lỗi ở logic save file.
- Với mode `meme`, file evade chỉ được lưu ở `custom-test-v0` vì `custom-train-v0` đang chạy với `save_modified_data=False`.
