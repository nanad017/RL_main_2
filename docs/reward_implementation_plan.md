# Kế hoạch triển khai Reward Function (4-component)

> **Mục đích tài liệu**: Đây là spec để một AI/coder khác đọc và triển khai chính xác phần reward được mô tả trong `docs/reward_presentation_script.md`. Plan giả định người đọc chưa biết codebase — mọi đường dẫn, signature, ràng buộc đều được liệt kê tường minh.

---

## 0. Bối cảnh & trạng thái hiện tại

### 0.1 File reward chính
- **`malware_rl/envs/reward.py`** (90 dòng, đã tồn tại).
- Hiện implement **3 thành phần**: `R_score`, `R_size`, `R_tier`.
- **Thiếu**: `R_func` (functional integrity penalty).
- Docstring đầu file còn ghi `"Three components"` — chưa đồng bộ với spec mới (4 components).

### 0.2 File phụ thuộc
- **`malware_rl/envs/controls/modifier.py`**: định nghĩa `ACTION_TABLE` (17 actions), `ACTION_TIER` (dict map action_name → tier 1/2/3), `NUM_TIERS = 3`.
- **7 gym envs** đang gọi reward (tất cả gọi cùng signature):
  - `malware_rl/envs/malconv_gym.py:71-94`
  - `malware_rl/envs/ember_gym.py:71-94`
  - `malware_rl/envs/sorel_gym.py:71-94`
  - `malware_rl/envs/sorelFFNN_gym.py:71-94`
  - `malware_rl/envs/custom_gym.py:71-102`
  - `malware_rl/envs/AV_gym.py:71-96`
  - `malware_rl/envs/lgb_gym.py:71-89`
- **Entrypoints training**: `ppo.py`, `optuna_ppo.py`, `random_agent.py` — chỉ tạo env qua `gym.make(...)`, **không truyền reward hyperparameter**.

### 0.3 Hợp đồng `__call__` hiện tại
```python
TierAwareReward.__call__(
    score,           # float, malicious score của detector sau step
    original_score,  # float, score ban đầu (chưa mutate)
    threshold,       # float, ngưỡng evade (vd 0.8336 cho EMBER)
    turn,            # int, step hiện tại (bắt đầu từ 1)
    maxturns,        # int, T_max
    original_size,   # int, byte count của B_0
    current_size,    # int, byte count của B_t
    tiers_used,      # set[int], tier đã dùng trong episode
) -> tuple[float, bool]   # (reward, episode_over)
```

---

## 1. Phạm vi công việc

| Phase | Nội dung | Bắt buộc | Có thể defer |
|---|---|---|---|
| 1 | Thêm `R_func` với placeholder (default = 0) | ✅ | |
| 2 | Update 7 gym envs để truyền `binary` vào reward | ✅ | |
| 3 | Expose hyperparameters qua env registration | ✅ | |
| 4 | Implement `check_func` thực (3 tier checker) | | ✅ — viết hook sẵn, chưa cần chạy |
| 5 | Unit tests + smoke test | ✅ | |
| 6 | Ablation hook (logging từng component) | | ✅ |

---

## 2. Rules bắt buộc tuân thủ

### R1. Backward compatibility — default behavior không đổi
- Khi gọi `TierAwareReward()` không tham số, **kết quả reward phải giống hệt phiên bản hiện tại** (cho tất cả input cũ).
- Cụ thể: `R_func = 0` mặc định → tổng reward không thay đổi.
- Lý do: training scripts hiện tại (`ppo.py`) không config gì, phải tiếp tục chạy bình thường.

### R2. Tách dữ liệu khỏi logic
- `check_func` là **callable injected** qua constructor, **không** hard-code trong class.
- Class `TierAwareReward` **không** import `pefile`, `lief`, hay bất kỳ checker cụ thể nào.
- Lý do: dễ test, dễ swap checker, không bloat reward class.

### R3. Fail-safe trên checker
- Nếu `check_func` raise exception → coi như binary OK (`indicator_broken = 0`), log warning, **không** crash episode.
- Lý do: checker là kiểm tra phụ trợ, không được phá flow training.

### R4. Mọi hyperparameter phải tunable
- `R_bonus`, `lambda_q`, `lambda_s`, `lambda_d`, `lambda_f` đều qua constructor.
- Có hằng `DEFAULT_*` ở module-level (giữ pattern hiện tại).

### R5. Numerical contract
- Reward luôn là `float` (không int, không tensor).
- Episode_over luôn là `bool`.
- Không trả `None`, không trả `NaN`. Nếu input invalid → trả 0.0 + log.

### R6. Episode-end timing cho R_tier và R_func
- `R_tier` chỉ tính khi `episode_over=True` (giữ nguyên hiện tại).
- `R_func` tính **mỗi step** (vì cần phát hiện ngay khi binary vỡ, không chờ end).
  - Trade-off được chấp nhận: agent phá binary giữa episode bị phạt ngay, đúng ý muốn.

### R7. Không tự ý refactor ngoài scope
- **Không** đổi cách gym envs tracking `self.bytez`, `self.original_size`, `self.score`.
- **Không** đổi action space, observation space.
- Chỉ chỉnh **chỗ gọi `reward_fn(...)`** và file `reward.py`.

### R8. Đặt tên & docs
- Mọi symbol khớp với `docs/reward_presentation_script.md`: `R_bonus`, `lambda_q`, `lambda_s`, `lambda_d`, `lambda_f`.
- Update docstring `reward.py` từ `"Three components"` → `"Four components"`.

---

## 3. Phase 1 — Update `reward.py`

### 3.1 Thêm constants

Tại block `# ── defaults ──` (sau dòng 16), thêm:

```python
DEFAULT_LAMBDA_F = 15.0    # functional-integrity penalty weight

def _default_check_func(binary: bytes) -> bool:
    """Default placeholder — assumes binary is always valid.

    Replace via constructor `check_func=...` when a real checker is ready.
    """
    return True
```

**Lý do λ_f = 15.0**: lớn hơn `R_bonus = 10.0` → ngay cả khi agent evade hoàn hảo (R_score = 10), nếu binary hỏng thì tổng vẫn âm (−5). Agent không thể "đánh đổi" evade lấy việc phá binary.

### 3.2 Update constructor

```python
def __init__(
    self,
    R_bonus=DEFAULT_BONUS,
    lambda_q=DEFAULT_LAMBDA_Q,
    lambda_s=DEFAULT_LAMBDA_S,
    lambda_d=DEFAULT_LAMBDA_D,
    lambda_f=DEFAULT_LAMBDA_F,
    check_func=None,
):
    self.R_bonus = R_bonus
    self.lambda_q = lambda_q
    self.lambda_s = lambda_s
    self.lambda_d = lambda_d
    self.lambda_f = lambda_f
    self.check_func = check_func if check_func is not None else _default_check_func
```

**Lý do dùng `None` rồi gán default**: tránh mutable default argument anti-pattern; cho phép truyền explicit `None` để trigger default.

### 3.3 Update signature `__call__`

Thêm tham số **`binary: bytes`** (đặt **trước `tiers_used`** để các param liên quan đến state binary đứng cùng nhau):

```python
def __call__(
    self,
    score,
    original_score,
    threshold,
    turn,
    maxturns,
    original_size,
    current_size,
    binary,           # ← MỚI: bytes của B_t hiện tại
    tiers_used,
):
```

**Lưu ý**: vì 7 gym envs đều phải update theo, phải coi đây là **breaking change của internal API**. Không có user code bên ngoài gọi `reward_fn` nên an toàn.

### 3.4 Thêm block tính R_func

Đặt **trước** block "Tier diversity" (vì R_func tính mỗi step, R_tier chỉ tính cuối):

```python
# ── 4. Functional-integrity penalty (every step) ──────────────────────
try:
    is_broken = not bool(self.check_func(binary))
except Exception as exc:
    # R3: fail-safe — checker không được crash training
    import warnings
    warnings.warn(f"check_func raised {exc!r}; treating binary as OK")
    is_broken = False
r_func = -self.lambda_f if is_broken else 0.0
```

### 3.5 Update return statement

```python
return r_score + r_size + r_tier + r_func, episode_over
```

### 3.6 Update module docstring

```python
"""
Tier-aware shaped reward for hybrid PE mutation RL.

Four components:
  R_score  — score-reduction shaping + efficiency-scaled evasion bonus
  R_size   — penalizes file-size bloat from overlay/section actions
  R_tier   — encourages multi-surface perturbation (structural + API + code)
  R_func   — penalizes mutations that break binary's core functionality
"""
```

### 3.7 Acceptance criteria Phase 1

- [ ] `reward.py` import được không lỗi.
- [ ] `TierAwareReward()` không tham số tạo ra instance dùng `_default_check_func`.
- [ ] Gọi `__call__` với binary bất kỳ, default checker → `R_func = 0`.
- [ ] Truyền `check_func=lambda _: False` → `R_func = -15.0`.
- [ ] Truyền `check_func=lambda _: 1/0` → log warning, `R_func = 0`, không raise.

---

## 4. Phase 2 — Update 7 gym envs

### 4.1 Pattern cần áp dụng

Trong mỗi file gym, tìm call site `self.reward_fn(...)` và thêm `binary=self.bytez,` vào kwargs.

**Before:**
```python
reward, episode_over = self.reward_fn(
    score=self.score,
    original_score=self.original_score,
    threshold=malicious_threshold,
    turn=self.turns,
    maxturns=self.maxturns,
    original_size=self.original_size,
    current_size=len(self.bytez),
    tiers_used=self.tiers_used,
)
```

**After:**
```python
reward, episode_over = self.reward_fn(
    score=self.score,
    original_score=self.original_score,
    threshold=malicious_threshold,
    turn=self.turns,
    maxturns=self.maxturns,
    original_size=self.original_size,
    current_size=len(self.bytez),
    binary=self.bytez,          # ← MỚI
    tiers_used=self.tiers_used,
)
```

### 4.2 Danh sách file cần sửa (chính xác)

| File | Dòng gọi `self.reward_fn(...)` |
|---|---|
| `malware_rl/envs/malconv_gym.py` | ~71-81 |
| `malware_rl/envs/ember_gym.py` | 85-94 |
| `malware_rl/envs/sorel_gym.py` | ~85-94 |
| `malware_rl/envs/sorelFFNN_gym.py` | ~85-94 |
| `malware_rl/envs/custom_gym.py` | ~93-102 |
| `malware_rl/envs/AV_gym.py` | ~87-96 |
| `malware_rl/envs/lgb_gym.py` | ~80-89 |

**Cảnh báo**: Số dòng có thể lệch nhẹ — phải Read file trước khi Edit, KHÔNG dùng Edit bằng số dòng tin tưởng từ doc này.

### 4.3 Threshold variable mỗi env

Mỗi env dùng tên threshold khác nhau (`malicious_threshold`, `MALICIOUS_THRESHOLD`, ...). **Không đổi tên** — giữ nguyên cách env hiện tại tham chiếu threshold.

### 4.4 Acceptance criteria Phase 2

- [ ] Tất cả 7 file đều pass `binary=self.bytez` vào reward call.
- [ ] Chạy `python -c "import gym; import malware_rl; gym.make('AV1-train-v0')"` không lỗi.
- [ ] Chạy 1 episode random agent trên mỗi env (xem Phase 5), không crash.

---

## 5. Phase 3 — Expose hyperparameters

### 5.1 Mục tiêu
Cho phép user tune `lambda_q`, `lambda_s`, `lambda_d`, `lambda_f` mà không phải sửa code env.

### 5.2 Hai cách (chọn cách A)

**Cách A (recommended): qua constructor env**

Trong mỗi gym env, thay:
```python
self.reward_fn = TierAwareReward()
```

bằng:
```python
self.reward_fn = TierAwareReward(
    R_bonus=reward_bonus,
    lambda_q=lambda_q,
    lambda_s=lambda_s,
    lambda_d=lambda_d,
    lambda_f=lambda_f,
    check_func=check_func,
)
```

và thêm các params vào `__init__` của env với default = None, rồi map None → dùng default của TierAwareReward.

Hoặc đơn giản hơn: thêm 1 param duy nhất `reward_fn=None`, cho phép user inject hẳn 1 instance đã config sẵn:

```python
def __init__(self, ..., reward_fn=None):
    ...
    self.reward_fn = reward_fn if reward_fn is not None else TierAwareReward()
```

**Recommended**: đi với pattern `reward_fn=None` — gọn nhất, không bloat signature, user nào cần tune tự tạo instance.

**Cách B (defer): qua gym registration kwargs**

Trong `malware_rl/__init__.py`, thêm `reward_fn` vào `kwargs` của `register(...)`. Phức tạp hơn, defer.

### 5.3 Acceptance criteria Phase 3

- [ ] `gym.make('AV1-train-v0')` vẫn dùng default reward.
- [ ] `env = AVEnv(reward_fn=TierAwareReward(lambda_f=20))` override được.
- [ ] Tất cả 7 envs hỗ trợ pattern này.

---

## 6. Phase 4 — Implement `check_func` (defer được, viết hook sẵn)

### 6.1 Vị trí mới
Tạo file mới: **`malware_rl/envs/controls/integrity.py`**.

### 6.2 Tier checker

#### Tier A — PE header validation (nhanh, ~ms)
```python
def check_pe_header(binary: bytes) -> bool:
    """Return True if binary parses as a valid PE."""
    import pefile
    try:
        pe = pefile.PE(data=binary, fast_load=True)
        pe.close()
        return True
    except Exception:
        return False
```

Trade-off: phát hiện được stoke phá header, IAT patch sai. KHÔNG phát hiện được lỗi runtime.

#### Tier B — Import table integrity (medium, ~10ms)
```python
def check_import_table(binary: bytes) -> bool:
    """Stronger: parse imports, check no orphan DLL/API references."""
    import pefile
    try:
        pe = pefile.PE(data=binary, fast_load=False)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]
        )
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return False
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll is None or len(entry.imports) == 0:
                return False
            for imp in entry.imports:
                if imp.name is None and imp.ordinal is None:
                    return False
        return True
    except Exception:
        return False
```

#### Tier C — Sandbox execution (slow, ~seconds, defer)
Chạy binary trong Wine/cuckoo, check exit code. Quá tốn cho training loop (1 episode = 5-10 steps, mỗi check vài giây → unacceptable). Để future work.

### 6.3 Default chosen
**Tier A** cho production training (cân bằng cost/benefit). Tier B làm option, expose qua `check_func` param.

### 6.4 Acceptance criteria Phase 4

- [ ] `from malware_rl.envs.controls.integrity import check_pe_header` import được.
- [ ] `check_pe_header(valid_pe_bytes)` → `True`.
- [ ] `check_pe_header(b"garbage")` → `False`.
- [ ] `check_pe_header(b"")` → `False`, không raise.
- [ ] Pass `TierAwareReward(check_func=check_pe_header)` chạy 1 episode không lỗi.

---

## 7. Phase 5 — Testing

### 7.1 Unit test `reward.py`

Tạo `tests/test_reward.py` (hoặc nếu repo chưa có `tests/`, tạo mới):

```python
import pytest
from malware_rl.envs.reward import TierAwareReward, _default_check_func

def make_call(reward_fn, **overrides):
    """Helper: call __call__ với input mặc định + overrides."""
    defaults = dict(
        score=0.7, original_score=0.9, threshold=0.5,
        turn=2, maxturns=10,
        original_size=1000, current_size=1000,
        binary=b"\x00" * 100,
        tiers_used={1},
    )
    defaults.update(overrides)
    return reward_fn(**defaults)

class TestDefault:
    def test_default_check_func_returns_true(self):
        assert _default_check_func(b"anything") is True

    def test_no_evasion_no_inflation_default(self):
        r, done = make_call(TierAwareReward())
        # R_score = 0.9 - 0.7 = 0.2, R_size = 0, R_tier = 0 (not done), R_func = 0
        assert r == pytest.approx(0.2)
        assert done is False

    def test_evasion_default(self):
        r, done = make_call(TierAwareReward(), score=0.3)
        # R_score = 10 * (1 - 0.3 * 1/10) = 9.7, R_tier = 1.0 * 1/3 = 0.333
        assert r == pytest.approx(9.7 + 1/3)
        assert done is True

class TestRFunc:
    def test_broken_binary_penalty(self):
        rfn = TierAwareReward(check_func=lambda _: False)
        r, done = make_call(rfn)
        # R_score = 0.2, R_func = -15
        assert r == pytest.approx(0.2 - 15.0)

    def test_broken_with_evasion_still_negative(self):
        rfn = TierAwareReward(check_func=lambda _: False)
        r, done = make_call(rfn, score=0.3)
        # R_score ≈ 9.7, R_tier ≈ 0.333, R_func = -15 → tổng < 0
        assert r < 0

    def test_checker_exception_fail_safe(self):
        def bad_checker(b):
            raise RuntimeError("simulated")
        rfn = TierAwareReward(check_func=bad_checker)
        r, done = make_call(rfn)
        # Phải không crash, R_func = 0
        assert r == pytest.approx(0.2)

    def test_lambda_f_tunable(self):
        rfn = TierAwareReward(lambda_f=50.0, check_func=lambda _: False)
        r, done = make_call(rfn)
        assert r == pytest.approx(0.2 - 50.0)

class TestBackwardCompat:
    """R1: gọi không tham số phải cho kết quả giống bản 3-component."""
    def test_no_func_does_not_affect_reward(self):
        rfn = TierAwareReward()  # default check_func = True
        r_new, _ = make_call(rfn)
        # Tính tay R_score + R_size + R_tier (không có R_func)
        expected = 0.2 + 0 + 0  # score-diff, no inflation, mid-episode
        assert r_new == pytest.approx(expected)
```

### 7.2 Smoke test gym envs

Sau Phase 2:

```python
# Lưu vào tests/test_gym_smoke.py
import gym
import malware_rl
import numpy as np

def test_ember_env_runs_episode():
    env = gym.make('AV1-train-v0')
    obs = env.reset()
    for _ in range(3):
        action = env.action_space.sample()
        obs, reward, done, info = env.step(action)
        assert isinstance(reward, (int, float))
        assert not np.isnan(reward)
        if done:
            break
```

### 7.3 Acceptance criteria Phase 5

- [ ] `pytest tests/test_reward.py` pass 100%.
- [ ] Smoke test mỗi env chạy được 1 episode không crash.
- [ ] Random agent (`random_agent.py`) chạy ổn định 10 episodes.

---

## 8. Phase 6 — Logging từng component (optional, defer)

### 8.1 Mục tiêu
Cho phép ablation study: biết mỗi component đóng góp bao nhiêu vào reward tổng.

### 8.2 Cách
`__call__` trả thêm dict `breakdown`:

```python
breakdown = {
    "r_score": r_score,
    "r_size": r_size,
    "r_tier": r_tier,
    "r_func": r_func,
}
return r_score + r_size + r_tier + r_func, episode_over, breakdown
```

**Vấn đề**: thay đổi return signature → breaking change cho 7 envs. Có 2 cách:

- **8.2.a**: thêm flag `return_breakdown=False` vào `__call__`, default False (backward compat).
- **8.2.b**: lưu breakdown vào `self.last_breakdown` attribute, env truy cập sau khi gọi.

**Recommended**: 8.2.b — gọn, không đổi signature.

### 8.3 Acceptance criteria Phase 6

- [ ] Sau mỗi `__call__`, `reward_fn.last_breakdown` có 4 key.
- [ ] Sum của 4 giá trị = reward trả về.
- [ ] Env có thể log vào `self.history[sha256]["reward_breakdown"] = self.reward_fn.last_breakdown`.

---

## 9. Thứ tự thực hiện đề xuất

```
Phase 1 (reward.py)
    ↓
Phase 5.1 (unit test reward.py — chạy ngay)
    ↓
Phase 2 (7 gym envs)
    ↓
Phase 5.2 (smoke test gym)
    ↓
Phase 3 (expose hyperparameters)
    ↓
[STOP HERE — đủ cho training; Phase 4 + 6 defer]
    ↓
Phase 4 (check_pe_header) — khi cần bật R_func thực
    ↓
Phase 6 (logging) — khi chạy ablation study
```

---

## 10. Anti-patterns cần tránh

1. ❌ **Đừng** import `pefile` trong `reward.py`. Reward không được biết về PE format.
2. ❌ **Đừng** tạo dependency vòng: `reward.py` đã import từ `controls.modifier`, **không** import ngược lại.
3. ❌ **Đừng** cache check_func result theo binary hash. Binary thay đổi mỗi step → cache miss luôn → vô ích, tốn RAM.
4. ❌ Nếu thay đổi default values (`R_bonus`, `lambda_q`, `lambda_s`, ...), phải cập nhật code, docs và test cùng lúc để tránh metric/reward drift.
5. ❌ **Đừng** thêm prints/logging vào `__call__` mặc định. Hot path, log riêng qua hook nếu cần.
6. ❌ **Đừng** dùng `assert` cho input validation trong production code — assertion có thể bị tắt bằng `python -O`. Dùng `if ...: raise` hoặc warning.

---

## 11. Checklist tổng

### Bắt buộc (Phase 1-3, 5)
- [ ] `reward.py`: thêm `DEFAULT_LAMBDA_F`, `_default_check_func`, params `lambda_f` & `check_func`, block tính `r_func`, update docstring.
- [ ] 7 gym envs: thêm `binary=self.bytez` vào `reward_fn(...)`.
- [ ] 7 gym envs: support `reward_fn=None` param trong `__init__` (Phase 3).
- [ ] `tests/test_reward.py`: viết & pass.
- [ ] Smoke test 1 env (recommend: ember hoặc AV vì stable nhất).

### Defer (Phase 4, 6)
- [ ] `malware_rl/envs/controls/integrity.py`: `check_pe_header`, `check_import_table`.
- [ ] `__call__` lưu `self.last_breakdown` cho ablation.

---

## 12. Câu hỏi mở (cần user trả lời trước khi Phase 4)

1. **Checker level mặc định khi bật**: Tier A (PE header) hay Tier B (import table)?
   - Đề xuất: bắt đầu Tier A, nếu thấy false negative quá nhiều → upgrade Tier B.
2. **Khi binary hỏng giữa episode, có nên kết thúc episode luôn không?**
   - Hiện tại spec: vẫn cho agent thử các step còn lại (chỉ phạt, không terminate).
   - Alternative: terminate ngay → tránh phí compute trên binary đã hỏng.
   - Đề xuất: defer, theo dõi data thực tế rồi quyết định.
3. **R_func có nên scale theo step (giống R_score) không?**
   - Spec hiện tại: penalty cố định -15 bất kể step nào.
   - Alternative: tăng dần (vỡ ở step cuối phạt nhẹ hơn vỡ ở step 1)?
   - Đề xuất: giữ cố định — vỡ là vỡ, không có "vỡ nhẹ".

---

**File này được viết để đứng độc lập.** AI/coder khác chỉ cần đọc file này + `docs/reward_presentation_script.md` là đủ thông tin triển khai, không cần hỏi lại context.
