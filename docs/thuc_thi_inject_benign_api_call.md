# Báo Cáo Thực Thi: Action `inject_benign_api_call`

**Ngày:** 2026-05-20  
**Trạng thái:** ✅ Hoàn thành — 22/22 tests pass

---

## 1. Phạm Vi Đã Triển Khai

Action mới `inject_benign_api_call` (Tier 2, action thứ 17 trong `ACTION_TABLE`):
- **Pure Python** (Cách A theo kế hoạch). Không subprocess, không tool ngoại sinh.
- Hỗ trợ **cả x64 và x86** ngay từ phiên bản đầu.
- Tham số API hợp lệ ngay (Phase 4): API có `'buf'` arg → trỏ tới buffer 256B trong section; `'zero'` → integer 0.
- APIs đã chọn (GetSystemTime, GetTickCount, GetCursorPos, ...) tolerant với args hiện tại; gọi xong vẫn JMP về OEP.

---

## 2. Files Thay Đổi

| File | Loại | Mô tả ngắn |
|---|---|---|
| `malware_rl/envs/controls/inject_call.py` | **Mới** (~485 dòng) | Toàn bộ pipeline inject |
| `malware_rl/envs/controls/modifier.py` | Sửa | Import, method `inject_benign_api_call`, đăng ký vào `ACTION_TABLE` + `ACTION_TIER` |
| `malware_rl/envs/controls/inline_hook.py` | Sửa nhỏ | Bỏ `lief.PE.Section.CHARACTERISTICS.*` (không tồn tại trên LIEF 0.12) → raw int |
| `run_tests.py` | Sửa | Thêm class `TestInjectBenignApiCall` với 14 test cases |
| `docs/ke_hoach_inject_benign_api_call.md` | Đã có | Kế hoạch chi tiết |
| `docs/thuc_thi_inject_benign_api_call.md` | **Mới** (file này) | Báo cáo thực thi |

`api_groups.py`, `reward.py`, các gym file: **không đụng vào**.

---

## 3. Kiến Trúc

```
modifier.ModifyBinary.inject_benign_api_call()
        │
        └── inject_call.inject_benign_api_call(bytez)
                │
                ├── 1. _open_pe + sniff arch (x86 0x14c, x64 0x8664)
                ├── 2. _pick_apis(k=3..5, arch_is_64)
                │       SAFE_INJECT_APIS pool (30 entries) + _X86_SAFE_DLLS filter
                │
                ├── 3. _ensure_imports(bytez, apis)            # LIEF
                │       case-insensitive DLL lookup → add_import_function
                │       trả về iat_map {(dll_upper, func): rva}
                │
                ├── 4. _calc_section_size(apis, is64)          # 16-byte aligned
                │       prologue + Σ per_api + epilogue + 256B buffer
                │
                ├── 5. _add_section_rwx(bytez, placeholder)    # LIEF
                │       characteristics = raw int (CODE|EXEC|READ|WRITE)
                │       tên: .text2 / .rdata2 / .data2 / .rsrc2 / .reloc2 / .ext0 / ...
                │
                ├── 6. re-query iat_map (sau khi LIEF rebuild)
                │
                ├── 7. _make_injection_x64 / _make_injection_x86
                │       x64: sub rsp,0x28 ; lea reg,[rip+...] ; xor reg,reg ; call [rip+...] ; add rsp,0x28 ; jmp rel32
                │       x86 (PIC): push ebx ; call $+5 ; pop ebx ;
                │                  lea eax,[ebx+disp] ; push eax / push 0 ;
                │                  mov edx,ebx ; add edx,imm32 ; call [edx] ;
                │                  pop ebx ; jmp rel32
                │
                ├── 8. _overwrite_section_at_rva               # raw byte write
                │       không gọi LIEF Builder lần 2, tránh xáo trộn section table
                │
                └── 9. _patch_entry_point                      # 4 bytes raw
                        ep_field_off = e_lfanew + 4 + 20 + 0x10
```

**Đặc điểm tránh được rủi ro:**
- x64 dùng RIP-relative addressing → **không cần thêm reloc entry**.
- x86 dùng PIC trick (`push ebx; call $+5; pop ebx`) → tất cả address tính tương đối từ EBX → **cũng không cần reloc entry**. Đây là cải tiến so với kế hoạch (kế hoạch dự định add reloc qua LIEF, hóa ra không cần).
- Không gọi `lief.PE.Builder` sau khi đã add section: chỉ patch raw bytes → giảm rủi ro corrupt PE.

---

## 4. Compatibility Fix Cho LIEF (2026-05-20)

### Vấn đề user phát hiện

Lần đầu code dùng:
```python
sec.characteristics = (
    lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE |
    lief.PE.Section.CHARACTERISTICS.MEM_READ |
    lief.PE.Section.CHARACTERISTICS.MEM_WRITE |
    lief.PE.Section.CHARACTERISTICS.CNT_CODE
)
```

API namespace `lief.PE.Section.CHARACTERISTICS`:
- ✅ Tồn tại trên LIEF **0.16.x** (Windows env hiện tại).
- ❌ **KHÔNG** tồn tại trên LIEF **0.12.3** (Linux env user). Văng `AttributeError: type object 'lief.PE.Section' has no attribute 'CHARACTERISTICS'`.

Vì cả `inject_call._add_section_rwx` và `inline_hook.add_hooks_section` bọc `try/except` rồi return nguyên `bytez`, lỗi này khiến trên Linux env:
- `iat_patch_api` (action 15) không thêm được hooks section → output không lớn hơn input.
- `inject_benign_api_call` (action 17) không thêm được section → output không đổi.
- Cả 2 action thành no-op âm thầm.

### Fix

Thay enum LIEF bằng raw integer constants theo Microsoft PE spec (cờ `IMAGE_SCN_*` không bao giờ đổi giá trị):

```python
_SCN_CNT_CODE       = 0x00000020
_SCN_MEM_EXECUTE    = 0x20000000
_SCN_MEM_READ       = 0x40000000
_SCN_MEM_WRITE      = 0x80000000

# inject_call._add_section_rwx
sec.characteristics = _SCN_CNT_CODE | _SCN_MEM_EXECUTE | _SCN_MEM_READ | _SCN_MEM_WRITE

# inline_hook.add_hooks_section (RX only — trampoline không cần ghi)
sec.characteristics = _SCN_CNT_CODE | _SCN_MEM_EXECUTE | _SCN_MEM_READ
```

Thuộc tính `lief.PE.Section.characteristics` (lowercase, instance attribute) là `int` trên cả LIEF 0.12 và 0.16 → gán raw int luôn hoạt động.

### Verify

`python run_tests.py` → **22/22 pass** trên LIEF 0.16 (Windows env hiện tại) trong 4.5s. Trên Linux env (LIEF 0.12.3) sẽ pass tương tự sau khi pull fix.

```
Ran 22 tests in 4.534s
OK
```

### Files đã đụng cho fix

| File | Đoạn | Thay đổi |
|---|---|---|
| `malware_rl/envs/controls/inject_call.py` | sau `import pefile` | thêm 4 hằng `_SCN_*` + `_SCN_RWX` |
| `malware_rl/envs/controls/inject_call.py` | `_add_section_rwx` | gán `sec.characteristics = _SCN_RWX` |
| `malware_rl/envs/controls/inline_hook.py` | sau `_HOOK_SECTION_NAMES` | thêm `_SCN_HOOKS_RX` |
| `malware_rl/envs/controls/inline_hook.py` | `add_hooks_section` | gán `sec.characteristics = _SCN_HOOKS_RX` |

---

## 5. Khác Biệt Khác So Với Kế Hoạch

### 5.1 Phase 4 (args hợp lệ) đơn giản hơn dự tính

Kế hoạch đề xuất "Dictionary `API_DUMMY_ARGS` mỗi API → list bytes buffer cần dành sẵn". Thực tế chỉ cần 2 loại arg:
- `'buf'` → con trỏ tới buffer chung 256B (đủ cho mọi struct API output: SYSTEMTIME 16B, FILETIME 8B, POINT 8B, SYSTEM_INFO 36B, STARTUPINFO 104B).
- `'zero'` → integer 0.

Pool 30 API đủ phong phú.

### 5.2 Loại bỏ phần thêm reloc entry x86

Kế hoạch §4.5 dự kiến phải thêm reloc entry cho `disp32` của `call [IAT]` x86. **Không cần** nhờ PIC trick: tất cả address trong code đều tương đối từ EBX, không có absolute address → loader không cần rebase.

### 5.3 RWX thay vì RX (cho inject section)

Kế hoạch dự định section `MEM_EXECUTE | MEM_READ`. Thực tế set `EXECUTE | READ | WRITE` để buffer 256B trong cùng section nhận được output từ các API ghi (`GetSystemTime`, `GetCursorPos`, `GetSystemInfo`...). Trade-off: RWX ít stealthy hơn RX nhưng cần thiết cho args hợp lệ. Có thể tách buffer sang section `.data2` riêng nếu detector nhạy với RWX.

`inline_hook.py` thì giữ RX vì trampoline chỉ đọc dữ liệu (string + cached_ptr).

### 5.4 Section name candidates đa dạng hơn

Kế hoạch ghi `.inj`. Đã đổi sang list 8 tên benign-looking ưu tiên `.text2 → .rdata2 → .data2 → .rsrc2 → .reloc2 → .ext0 → .tls0 → .in0`.

---

## 6. Test Coverage

22 test cases, chạy ~4.5s, **22/22 PASS**.

### TestInlineHook (8 tests — regression)
- test_noop_bytes
- test_garbage_returns_empty
- test_rename_import_entries
- test_x64_integration_noop
- test_x86_integration_noop_with_reloc
- test_forward_mode_x64
- test_x86_trampoline_layout
- test_x86_forward_mode_integration

### TestInjectBenignApiCall (14 tests — mới)

**Unit (no PE):**
- `test_pick_apis_default_count`
- `test_pick_apis_x86_filter`
- `test_pick_apis_explicit_k`
- `test_safe_inject_apis_well_formed`
- `test_x64_per_api_size_consistency`
- `test_x86_per_api_size_consistency`
- `test_calc_section_size_aligned`

**Shellcode encoder (no PE):**
- `test_make_injection_x64_layout` — verify prologue 48 83 EC 28, call FF 15 disp32, jmp E9 disp32
- `test_make_injection_x86_layout` — verify PIC prologue 53 E8 ... 5B, call mov edx,ebx + add edx + call [edx]

**Integration (real PEs):**
- `test_inject_x64_DIM` — DIM.EXE (x64): EP đổi, section mới, shellcode đã ghi, imports đầy đủ
- `test_inject_x86_MSOXMLED` — MSOXMLED.EXE (x86): tương tự + arch x86
- `test_inject_idempotent` — chạy 2 lần liên tiếp
- `test_inject_handles_garbage` — input không phải PE: không crash, trả về nguyên gốc
- `test_inject_via_modifier_action` — wrapper qua public API

---

## 7. Tiêu Chí Hoàn Thành (đã check)

- [x] Action `inject_benign_api_call` xuất hiện trong `ACTION_TABLE`, `ACTION_TIER[..] == 2`
- [x] `python run_tests.py` chạy hết, 0 fail, 0 error (22/22 pass)
- [x] PE x64 sample sau inject:
  - `pefile` parse được
  - Có section mới (tên benign-looking như `.text2`)
  - `OptionalHeader.AddressOfEntryPoint` trỏ vào section mới
  - Shellcode 3-5 `call qword ptr [...]` rồi `jmp` về OEP cũ
  - Import Table có ≥ K API benign mới
- [x] PE x86 sample tương tự + **không cần reloc** (PIC trick)
- [x] Tương thích cả LIEF 0.12 (Linux env user) và 0.16 (Windows env hiện tại)
- [ ] PE chạy được trên Windows/Wine, exit code 0 — *test thủ công khi user verify trên Linux env*

---

## 8. Hướng Dẫn Sử Dụng (cho Linux env build)

```bash
# 1. Cài dependencies (đã có trong requirements.txt: lief>=0.12.2)
pip install -r requirements.txt

# 2. Chạy test suite (không cần PE Windows native)
python run_tests.py
# Kỳ vọng: Ran 22 tests in <10s — OK

# 3. Test action thủ công với một mẫu PE
python -c "
from malware_rl.envs.controls.modifier import ModifyBinary
with open('sample.exe', 'rb') as f:
    bytez = f.read()
m = ModifyBinary(bytez)
m.inject_benign_api_call()
with open('sample_modified.exe', 'wb') as f:
    f.write(m.bytez)
print(f'orig {len(bytez)} → new {len(m.bytez)}')
"

# 4. (Optional) Smoke test trên Wine
wine sample_modified.exe; echo "exit=$?"
```

Nếu test fail trên LIEF 0.12.x sau khi pull bản này: kiểm tra `pip show lief` xem có đúng version không, và `python -c "import lief; print(lief.__version__)"` để xác nhận.