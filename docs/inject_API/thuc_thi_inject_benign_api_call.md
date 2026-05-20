# Báo Cáo Thực Thi: Action `inject_benign_api_call`

**Ngày:** 2026-05-20  
**Trạng thái:** ✅ Hoàn thành Phase 1-4 (đã pass 22/22 unit tests)

---

## 1. Phạm Vi Đã Triển Khai

Action mới `inject_benign_api_call` (Tier 2, action thứ 17 trong `ACTION_TABLE`):
- **Pure Python** (Cách A theo kế hoạch). Không subprocess, không tool ngoại sinh.
- Hỗ trợ **cả x64 và x86** ngay từ phiên bản đầu (đã test).
- Tham số API hợp lệ ngay (Phase 4): API có `'buf'` arg → trỏ tới buffer 256B trong section; API có `'zero'` arg → integer 0.
- Sandbox-friendly: APIs đã chọn (GetSystemTime, GetTickCount, GetCursorPos, ...) tolerant với args hiện tại; gọi xong vẫn JMP về OEP.

---

## 2. Files Thay Đổi

| File | Loại | Mô tả ngắn |
|---|---|---|
| `malware_rl/envs/controls/inject_call.py` | **Mới** (~480 dòng) | Toàn bộ pipeline inject |
| `malware_rl/envs/controls/modifier.py` | Sửa | Import, method `inject_benign_api_call`, đăng ký vào `ACTION_TABLE` + `ACTION_TIER` |
| `run_tests.py` | Sửa | Thêm class `TestInjectBenignApiCall` với 14 test cases |
| `docs/ke_hoach_inject_benign_api_call.md` | Đã có | Kế hoạch chi tiết (12 mục) |
| `docs/thuc_thi_inject_benign_api_call.md` | **Mới** (file này) | Báo cáo thực thi |

`api_groups.py`, `inline_hook.py`, `reward.py` và mọi gym file: **không động vào**.

---

## 3. Kiến Trúc Triển Khai

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
                │       MEM_EXECUTE | MEM_READ | MEM_WRITE | CNT_CODE
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
- x86 dùng PIC trick (push ebx; call $+5; pop ebx) → **EBX runtime = ImageBase + sec_rva + 6**, từ đó tính tương đối tới IAT slot và buffer → cũng **không cần reloc entry**. Đây là cải tiến so với kế hoạch (kế hoạch đề xuất add reloc qua LIEF, hóa ra không cần).
- Không gọi `lief.PE.Builder` sau khi đã add section: chỉ patch raw bytes → giảm rủi ro corrupt PE.

---

## 4. Khác Biệt So Với Kế Hoạch

### 4.1 Bỏ Phase tách rời, làm gộp 4 phase ngay từ đầu

**Lý do:** Người dùng yêu cầu "làm đủ cả 4 phase". Chia 4 phase trong kế hoạch chỉ là milestone phòng khi cần dừng giữa chừng.

### 4.2 Phase 4 (args hợp lệ) đơn giản hơn dự tính

Kế hoạch đề xuất "Dictionary `API_DUMMY_ARGS` mỗi API → list bytes buffer cần dành sẵn". Thực tế chỉ cần 2 loại arg:
- `'buf'` → con trỏ tới buffer chung 256B (đủ cho mọi struct API output: SYSTEMTIME 16B, FILETIME 8B, POINT 8B, SYSTEM_INFO 36B, STARTUPINFO 104B).
- `'zero'` → integer 0.

Mọi API trong `SAFE_INJECT_APIS` đều có signature đơn giản kiểu `void GetX(LPX out)` hoặc `T GetY()` hoặc `T GetZ(int idx)` — không cần vector argument types phức tạp. Pool 30 API đủ phong phú.

### 4.3 Loại bỏ phần thêm reloc entry x86

Kế hoạch §4.5 dự kiến phải thêm reloc entry mới cho `disp32` của `call [IAT]` trong x86. **Không cần** vì shellcode dùng PIC trick: tất cả address tính tương đối từ EBX, không có absolute address nào trong code → loader không cần rebase gì cả.

### 4.4 RWX thay vì RX

Kế hoạch dự định section `MEM_EXECUTE | MEM_READ`. Đã set thành `MEM_EXECUTE | MEM_READ | MEM_WRITE` để buffer 256B trong cùng section có thể nhận output từ `GetSystemTime`, `GetCursorPos`, ... Đây là trade-off (RWX ít stealthy hơn RX) nhưng cần thiết cho các API ghi vào buffer. Nếu cần stealthier có thể tách buffer sang section `.data2` riêng — để tới khi đo được tác động detector mới quyết định.

### 4.5 Section name candidates đa dạng hơn

Kế hoạch ghi `.inj`. Đã đổi sang list 8 tên benign-looking ưu tiên `.text2 → .rdata2 → .data2 → .rsrc2 → .reloc2 → .ext0 → .tls0 → .in0`, tận dụng list đã chứng minh stealthy của `inline_hook.py`.

---

## 5. Test Coverage

22 test cases, chạy 6.5 giây, **22/22 PASS**:

### TestInlineHook (8 tests — không thay đổi, regression check)
- test_noop_bytes
- test_garbage_returns_empty
- test_rename_import_entries
- test_x64_integration_noop
- test_x86_integration_noop_with_reloc
- test_forward_mode_x64
- test_x86_trampoline_layout
- test_x86_forward_mode_integration

### TestInjectBenignApiCall (14 tests — mới)

**Unit tests (no PE):**
- `test_pick_apis_default_count` — random 3-5 apis, args ≤ 4
- `test_pick_apis_x86_filter` — chỉ DLL trong `_X86_SAFE_DLLS`
- `test_pick_apis_explicit_k` — pick chính xác k api
- `test_safe_inject_apis_well_formed` — 30 entries hợp lệ
- `test_x64_per_api_size_consistency` — 4-buf=34B, 4-zero=16B, no-args=6B
- `test_x86_per_api_size_consistency` — 1-buf=17B, 1-zero=12B, no-args=10B
- `test_calc_section_size_aligned` — 16-byte aligned, ≥256B buffer

**Shellcode encoder tests (no PE):**
- `test_make_injection_x64_layout` — verify prologue 48 83 EC 28, call FF 15 disp32, jmp E9 disp32, displacement đúng công thức
- `test_make_injection_x86_layout` — verify PIC prologue 53 E8 ... 5B, call mov edx,ebx + add edx,imm32 + call [edx], jmp đúng

**Integration tests (real PEs):**
- `test_inject_x64_DIM` — DIM.EXE (x64): EP đổi, section mới, shellcode đã ghi, imports đầy đủ
- `test_inject_x86_MSOXMLED` — MSOXMLED.EXE (x86): tương tự + arch x86
- `test_inject_idempotent` — chạy 2 lần liên tiếp: lần 2 vẫn add section + đổi EP
- `test_inject_handles_garbage` — input không phải PE: không crash, trả về nguyên gốc
- `test_inject_via_modifier_action` — wrapper qua public API

---

## 6. Tiêu Chí Hoàn Thành (đã check)

- [x] Action `inject_benign_api_call` xuất hiện trong `ACTION_TABLE`, `ACTION_TIER[..] == 2`
- [x] `python run_tests.py` chạy hết, 0 fail, 0 error (22/22 pass)
- [x] PE x64 sample sau inject:
  - `pefile` parse được
  - Có section mới (tên benign-looking như `.text2`)
  - `OptionalHeader.AddressOfEntryPoint` trỏ vào section mới
  - Shellcode 3-5 `call qword ptr [...]` rồi `jmp` về OEP cũ
  - Import Table có ≥ K API benign mới
- [x] PE x86 sample tương tự + **không cần reloc** (PIC trick)
- [ ] PE chạy được trên Windows/Wine, exit code 0 — *test thủ công, làm khi user build trên Linux env*

---

## 7. Hạn Chế / Cải Tiến Tương Lai

1. **RWX section** — có thể tách `.code` (RX) và `.data` (RW) thành 2 section nếu detector cảnh báo.
2. **Pool 30 API có thể mở rộng** — thêm GDI32 (CreateCompatibleDC, ...), VERSION (GetFileVersionInfoSizeW), CRYPT32 (CryptStringToBinary) nếu cần đa dạng hơn.
3. **Số lượng API động** — hiện random 3-5; có thể tăng tới 10 nếu reward function khuyến khích nhiều API hơn.
4. **Argument types nâng cao** — hiện chỉ `'buf'` và `'zero'`. Nếu muốn gọi API như `OpenProcess(PROCESS_QUERY_INFO, FALSE, GetCurrentProcessId())` thì cần thêm type `'const_int'` và logic phức tạp hơn — chưa thấy lợi ích rõ rệt.
5. **Khi build trên Linux**: cần cài `lief` + `pefile` (đã có trong `requirements.txt`?). Test chạy headless không cần Windows API.

---

## 8. Hướng Dẫn Sử Dụng (cho Linux env build)

Trên repo đã clone:

```bash
# 1. Verify dependencies có lief + pefile
pip install lief pefile

# 2. Chạy test suite (không cần PE Windows native)
python run_tests.py

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

# 4. (Optional) Test trên Wine
wine sample_modified.exe; echo "exit=$?"
```

Nếu test phase 3+4 phát sinh issue trên môi trường Linux, kiểm tra `lief` version (đã thử với 0.13+).