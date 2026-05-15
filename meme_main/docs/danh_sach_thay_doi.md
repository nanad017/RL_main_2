# Danh Sách Thay Đổi

## Tổng Kết

```
Trước: 15 actions
Sau:   18 actions (thêm 3 actions API-related)
```

---

## File Mới Tạo

### `malware_rl/envs/controls/api_groups.py`
- `API_GROUPS` — 12 nhóm API benign (sysinfo, file, time, registry, network, ui, crypto_benign, memory, string, com, gdi, version)
- `IAT_HOOK_TARGETS` — 4 nhóm API suspicious (injection, network, kernel, crypto)
- `STUB_DLL_NAME` = "stub.dll"
- `STUB_REPLACEMENT_POOL` — 30 tên hàm benign dùng khi IAT patch

---

## File Đã Sửa

### `malware_rl/envs/controls/modifier.py`

**Import thêm:**
```python
from .api_groups import API_GROUPS, IAT_HOOK_TARGETS, STUB_DLL_NAME, STUB_REPLACEMENT_POOL
```

**Constant thêm:**
```python
IAT_PATCHER_CLI  # đọc từ env var, fallback path mặc định
```

**3 methods thêm vào class ModifyBinary:**

| # | Method | Cơ chế | Cần tool? | Đổi code bytes? |
|---|--------|--------|-----------|-----------------|
| 16 | `add_api_group()` | LIEF thêm 2-5 API benign từ 1 nhóm random | Không | Không |
| 17 | `iat_hook_suspicious()` | LIEF xóa DLL chứa API suspicious khỏi import table | Không | Không |
| 18 | `iat_patch_api()` | IAT_Patcher CLI hook API suspicious → stub.dll | Cần CLI + stub.dll | Có |

**ACTION_TABLE cập nhật:** 15 → 18 entries

---

## Gym Files

Không cần sửa — tất cả đều dùng `len(ACTION_TABLE)` động, tự nhận 18 actions.
