# Danh Sách Thay Đổi

## Tổng Kết

```
Trước: 13 actions (gốc)
Sau:   15 actions (thêm 2 actions API-related)
```

---

## File Mới Tạo

### `malware_rl/envs/controls/api_groups.py`
- `API_GROUPS` — 12 nhóm API benign (sysinfo, file, time, registry, network, ui, crypto_benign, memory, string, com, gdi, version)
- `IAT_HOOK_TARGETS` — 10 nhóm API suspicious (injection, network, kernel, crypto, evasion, persistence, timing, fingerprint, window_enum, nt_registry)
- `STUB_DLL_NAME` = "stub.dll"
- `STUB_REPLACEMENT_POOL` — 72 tên hàm benign dùng khi IAT hook

---

## File Đã Sửa

### `malware_rl/envs/controls/modifier.py`

**Import thêm:**
```python
import shlex
import shutil
from .api_groups import API_GROUPS, IAT_HOOK_TARGETS, STUB_DLL_NAME, STUB_REPLACEMENT_POOL
```

**Hàm helper thêm:**
```python
get_iat_patcher_command()  # tìm IAT_Patcher_CLI: env var → local build → legacy path
get_stub_dll_source()      # resolve đường dẫn stub.dll
```

**2 methods thêm vào class ModifyBinary:**

| # | Method | Cơ chế | Cần tool? | Đổi code bytes? |
|---|--------|--------|-----------|-----------------|
| 14 | `add_api_group()` | LIEF thêm 2-5 API benign từ 1 nhóm random | Không | Không |
| 15 | `iat_patch_api()` | IAT_Patcher CLI hook từng API suspicious → stub.dll (sequential `--hook`) | Cần CLI + stub.dll | Có |

**Ghi chú `iat_patch_api` — flow hook:**
- Parse PE tìm API target hiện có trong import table
- Với mỗi API: gọi `IAT_Patcher_CLI --hook input output api replacement`
- Output mỗi stage → input stage tiếp theo (chained)
- Nếu một hook lỗi, stage đó bị skip, các hook tiếp theo vẫn chạy trên input trước đó
- No-op tự động nếu CLI hoặc stub.dll không tìm thấy

**ACTION_TABLE cập nhật:** 13 → 15 entries

---

## Action bị xóa

| Action | Lý do xóa |
|--------|-----------|
| `iat_hook_suspicious` | Dùng LIEF xóa cả DLL khỏi import table — binary bị broken, không phù hợp với mục tiêu hook. Thay bằng `iat_patch_api` với flow hook đúng nghĩa. |

---

## Gym Files

Không cần sửa — tất cả đều dùng `len(ACTION_TABLE)` động, tự nhận 15 actions.
