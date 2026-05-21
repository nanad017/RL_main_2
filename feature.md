# Reward Function 4-component Implementation Notes

## Lý do phát sinh

Triển khai theo source of truth `docs/reward_implementation_plan.md` cho các phase bắt buộc:

- Phase 1: thêm `R_func` placeholder vào reward function.
- Phase 2: truyền binary hiện tại từ 7 gym env vào reward.
- Phase 3: hỗ trợ inject `reward_fn` qua constructor env để tune hyperparameter/checker.
- Phase 5: thêm unit test cho reward.

Phase 4 và Phase 6 được yêu cầu không triển khai.

## File đã tạo/chỉnh sửa

### File chỉnh sửa

- `malware_rl/envs/reward.py`
  - Cập nhật docstring từ Three components sang Four components.
  - Thêm `DEFAULT_LAMBDA_F = 15.0`.
  - Thêm `_default_check_func(binary: bytes) -> bool`.
  - Thêm constructor params `lambda_f` và `check_func`.
  - Thêm tham số `binary` vào `TierAwareReward.__call__`.
  - Thêm penalty `R_func` với fail-safe warning nếu checker raise exception.
  - Đảm bảo return contract là `(float, bool)`.

- `malware_rl/envs/malconv_gym.py`
  - Thêm constructor param `reward_fn=None`.
  - Dùng injected reward instance nếu được truyền.
  - Truyền `binary=self.bytez` vào `self.reward_fn(...)`.

- `malware_rl/envs/ember_gym.py`
  - Thêm constructor param `reward_fn=None`.
  - Dùng injected reward instance nếu được truyền.
  - Truyền `binary=self.bytez` vào `self.reward_fn(...)`.

- `malware_rl/envs/sorel_gym.py`
  - Thêm constructor param `reward_fn=None`.
  - Dùng injected reward instance nếu được truyền.
  - Truyền `binary=self.bytez` vào `self.reward_fn(...)`.

- `malware_rl/envs/sorelFFNN_gym.py`
  - Thêm constructor param `reward_fn=None`.
  - Dùng injected reward instance nếu được truyền.
  - Truyền `binary=self.bytez` vào `self.reward_fn(...)`.

- `malware_rl/envs/custom_gym.py`
  - Thêm constructor param `reward_fn=None`.
  - Dùng injected reward instance nếu được truyền.
  - Truyền `binary=self.bytez` vào `self.reward_fn(...)`.

- `malware_rl/envs/AV_gym.py`
  - Thêm constructor param `reward_fn=None`.
  - Dùng injected reward instance nếu được truyền.
  - Truyền `binary=self.bytez` vào `self.reward_fn(...)`.

- `malware_rl/envs/lgb_gym.py`
  - Thêm constructor param `reward_fn=None`.
  - Dùng injected reward instance nếu được truyền.
  - Truyền `binary=self.bytez` vào `self.reward_fn(...)`.

### File mới

- `tests/test_reward.py`
  - Unit tests cho default checker, backward compatibility, functional penalty, fail-safe checker exception và tunable `lambda_f`.

- `feature.md`
  - Ghi nhận thay đổi theo yêu cầu triển khai.

## Mục tiêu thay đổi

- Bổ sung reward component thứ 4: `R_func`, phạt binary bị checker đánh dấu hỏng.
- Giữ default behavior tương thích ngược: `TierAwareReward()` mặc định dùng `_default_check_func` luôn trả `True`, nên `R_func = 0.0`.
- Cho phép inject checker thực tế trong tương lai qua `check_func` mà không import checker cụ thể vào `reward.py`.
- Cho phép inject reward instance đã cấu hình vào các env qua `reward_fn=None`.

## Ảnh hưởng tới hệ thống

- Internal reward API thay đổi: `TierAwareReward.__call__` có thêm tham số bắt buộc `binary` trước `tiers_used`.
- 7 gym env đã được cập nhật đồng bộ để truyền `binary=self.bytez`.
- Training scripts hiện tại vẫn dùng `gym.make(...)` và default env constructor nên tiếp tục sử dụng default reward.
- Không thay đổi action space, observation space, cách tracking `self.bytez`, `self.original_size`, `self.score`.
- Không thêm dependency mới.
- Không triển khai checker PE thực tế, đúng yêu cầu defer Phase 4.
- Không thêm logging/breakdown từng component, đúng yêu cầu defer Phase 6.

## Tương thích ngược

- Có tương thích ngược với training flow hiện tại:
  - `TierAwareReward()` không tham số vẫn cho reward giống bản 3-component vì default checker trả `True`.
  - Env constructors có thêm `reward_fn=None` ở cuối signature nên các caller hiện tại không bị ảnh hưởng.
  - `gym.make(...)` vẫn dùng default reward nếu không truyền `reward_fn`.

- Có breaking change ở internal API của `TierAwareReward.__call__`:
  - Caller trực tiếp cũ cần truyền thêm `binary`.
  - Theo plan, đây là breaking change nội bộ và 7 env call sites đã được cập nhật.

## Migration/database change

Không có migration hoặc database schema change.

## Quyết định kỹ thuật ngoài plan

Không có quyết định kỹ thuật ngoài phạm vi plan. Các thay đổi đều bám theo Phase 1, Phase 2, Phase 3 và Phase 5 của `docs/reward_implementation_plan.md`.

## Phase không triển khai

- Phase 4: không tạo `malware_rl/envs/controls/integrity.py`, không implement `check_pe_header`/`check_import_table`.
- Phase 6: không thêm `last_breakdown`, không thay đổi return signature để log component breakdown.