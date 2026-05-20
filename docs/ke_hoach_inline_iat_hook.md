# Inline IAT Hook — Chèn Code Hook Trực Tiếp Vào PE

**Ngày tạo:** 2026-05-16  
**Cập nhật lần cuối:** 2026-05-20 (xóa noop mode)  
**Trạng thái tổng thể:** ✅ Hoàn thành toàn bộ (Phase 1–4)

---

## 1. Vấn Đề Đã Giải Quyết

Action `iat_patch_api` (action 15) trước đây dùng flow:

```
modifier.py → gọi IAT_Patcher_CLI.exe (external tool, C++)
            → CLI patch PE: đổi IAT entry từ KERNEL32!VirtualAllocEx → stub.dll!AllocateMemoryBlock
            → stub.dll phải đi kèm PE khi runtime
```

**Hạn chế đã khắc phục:**
- Phụ thuộc `IAT_Patcher_CLI.exe` — **đã loại bỏ hoàn toàn**
- Phụ thuộc `stub.dll` bên ngoài — **PE giờ self-contained**
- Subprocess cho mỗi API hook — **thay bằng pure Python in-memory**
- Nếu CLI không có → action no-op — **không còn xảy ra**

---

## 2. Thiết Kế Đã Triển Khai: Inline IAT Hook

```
Flow runtime (forwarding mode — mode duy nhất):
  Code gốc: CALL [IAT_VirtualAllocEx]
  ──── SAU KHI PATCH ────
  Code mới:  CALL trampoline_in_.hooks_section
  Trampoline: lazy-resolve qua LoadLibraryA + GetProcAddress → JMP real_api
  → quay về luồng chính, PE vẫn chạy bình thường
```

```
Flow static detector (cả hai mode):
  Import table: tên API suspicious bị rename sang tên benign
  Code bytes:   CALL thay đổi (E8 thay vì FF 15)
  String:       Tên API không còn trong import name table
  Section mới:  .reloc2 / .rsrc2 / .data2 chứa trampoline code
```

### So Sánh: Cũ vs Mới

| Khía cạnh | Cũ (IAT_Patcher) | Mới (Inline) |
|---|---|---|
| External tool | IAT_Patcher_CLI.exe | **Không** |
| External DLL | stub.dll đi kèm PE | **Không — PE self-contained** |
| Ngôn ngữ | C++ CLI + Python wrapper | **Pure Python** |
| Cross-platform | Cần Wine trên Linux | **Chạy mọi nơi** |
| Tốc độ | subprocess × N hooks | **In-memory** |
| x86 support | Có (qua CLI) | **Có (native Python)** |
| Forwarding mode | Có (qua stub.dll) | **Có (lazy-resolve trampoline)** |

---

## 3. Kiến Trúc Đã Triển Khai

```
modifier.py
└── iat_patch_api()                          [modifier.py:396]
    ├── random chọn category từ IAT_HOOK_TARGETS
    ├── mode cố định: 'forward'
    └── gọi inline_iat_hook(bytez, targets, SAFE_RENAME, mode='forward')
            │
            ├── 1. ensure_loader_apis()      [inline_hook.py:278]  (chỉ forward mode)
            │       Đảm bảo LoadLibraryA + GetProcAddress có trong import table
            │
            ├── 2. find_iat_hooks()          [inline_hook.py:32]
            │       Parse PE → tìm IAT slots của suspicious APIs
            │
            ├── 3. find_call_sites()         [inline_hook.py:103]
            │       Scan executable sections tìm FF 15/FF 25 (x64 RIP-relative & x86 absolute VA)
            │
            ├── 4. rename_import_entries()   [inline_hook.py:150]
            │       Overwrite IMAGE_IMPORT_BY_NAME.Name bằng tên benign (in-place)
            │
            ├── 5. add_hooks_section()       [inline_hook.py:173]
            │       Thêm section .reloc2/.rsrc2/... (EXECUTE|READ|CODE) chứa trampolines
            │
            ├── 6. patch_call_sites()        [inline_hook.py:204]
            │       FF 15 xx xx xx xx → 90 E8 yy yy yy yy (indirect→direct call)
            │
            └── 7. neutralize_relocations_x86()  [inline_hook.py:244]
                    (x86 only) Đặt relocation type = 0 cho các call sites đã patch
```

**Library stack:**
- **pefile** — parse PE, scan sections, patch bytes, read IAT/ILT
- **LIEF** — add section, add import function (đã có trong project)
- **struct** — encode/decode little-endian integers

---

## 4. Chi Tiết Kỹ Thuật

### 4.1 find_iat_hooks() — Tìm IAT Slots

Dùng `pefile` parse PE, tìm IAT slot RVA và file offset của `IMAGE_IMPORT_BY_NAME.Name` cho từng suspicious API.

Trả về: `[{api, dll, iat_rva, name_file_offset, original_name_len}]`

**Xử lý đặc biệt:** Đọc ILT (Original First Thunk) thay vì IAT trực tiếp để lấy `hint_name_rva`, hỗ trợ cả x86 (4-byte ptr) và x64 (8-byte ptr).

### 4.2 find_call_sites() — Scan Code

Scan tất cả executable sections tìm `FF 15` (CALL indirect) và `FF 25` (JMP thunk):

```
x64: ref_rva = instr_rva + 6 + disp32          (RIP-relative)
x86: ref_rva = (abs32_va - imagebase) & 0xFFFFFFFF  (absolute VA → RVA)
```

### 4.3 Trampolines

#### Forwarding x64 (~120+ bytes, position-independent)

Lazy-resolve qua LoadLibraryA + GetProcAddress (RIP-relative addressing):
- Lần đầu gọi: resolve rồi cache vào `cached_ptr` trong section
- Lần sau: đọc cache, JMP thẳng tới real API
- Bảo toàn RCX, RDX, R8, R9, R10, R11 trước khi resolve

Xem `_make_forward_trampoline_x64()` — `inline_hook.py:360`

#### Forwarding x86 (~67+ bytes, position-independent)

PIC technique: `push ebx; call $+5; pop ebx` để lấy địa chỉ runtime:

```
offset  instruction                ghi chú
  0     push ebx                   save caller's EBX (callee-saved register)
  1-5   call $+5                   push tramp_va+6, jump to offset 6
  6     pop ebx                    EBX = tramp_va+6 (PIC base)
  7-12  mov eax, [ebx + 61]        read cached_ptr at offset 67
  13-14 test eax, eax
  15-16 jnz .forward (+47 → 64)   skip resolution if cached
  17-63 (resolution: push ecx/edx, LoadLibraryA, GetProcAddress, cache, pop edx/ecx)
  64    pop ebx           ← .forward    restore orig EBX (cả fast & slow path)
  65-66 jmp eax                    jump to real API
  67-70 cached_ptr (4 bytes, zeroed)
  71+   dll_name\0 + api_name\0
```

**Quan trọng:** `.forward` label ở offset 64 (`pop ebx`) đảm bảo EBX gốc luôn được restore trước khi JMP vào real API, bất kể đi qua fast path (jnz) hay slow path (fall-through).

IAT slot VA tính như sau (với EBX = tramp_va+6 = ImageBase+tramp_rva+6):
```
EDX = EBX + (iat_rva - tramp_rva - 6) = ImageBase + iat_rva  ✓
```

Xem `_make_forward_trampoline_x86()` — `inline_hook.py:420`

### 4.4 add_hooks_section() — Thêm Section

Dùng LIEF. Tên section được chọn từ list benign-looking theo thứ tự:
`.reloc2`, `.rsrc2`, `.data2`, `.rdata2`, `.text2`, `.ext`, `.ex0`

Characteristics: `MEM_EXECUTE | MEM_READ | CNT_CODE`

### 4.5 patch_call_sites() — Patch Code Bytes

```
Trước: FF 15 xx xx xx xx   (6 bytes — CALL [RIP+disp32], indirect qua IAT)
Sau:   90 E8 yy yy yy yy   (6 bytes — NOP + CALL rel32, direct tới trampoline)

displacement = tramp_rva - instr_rva - 6
```

### 4.6 rename_import_entries() — Ẩn Tên API

Overwrite `IMAGE_IMPORT_BY_NAME.Name` in-place bằng tên benign. Constraint: `len(new) ≤ len(original)`. Padding null bytes để fill phần còn lại.

`SAFE_RENAME` mapping: `api_groups.py:417` — ~45 APIs covered.

**APIs không có rename phù hợp** (len constraint không thỏa, bỏ qua — vẫn hook nhưng không rename):
- `InternetOpenA`, `WinHttpOpen`, `WinHttpConnect` — không có WININET/WINHTTP API ngắn hơn
- `CryptEncrypt`, `CryptDecrypt`, `CryptGenKey` — không có ADVAPI32 Crypt API ngắn hơn

### 4.7 neutralize_relocations_x86() — Vô Hiệu Hóa Relocation (x86 only)

Sau khi patch `FF 15` → `90 E8`, relocation entry `IMAGE_REL_BASED_HIGHLOW` tại `instr_rva+2` phải được vô hiệu hóa (type = 0) để loader không corrupt displacement khi rebase.

Dùng `entry.struct.get_file_offset()` của pefile (chính xác hơn tính tay `block_offset + i*2`).

---

## 5. Trạng Thái Triển Khai

### Phase 1 — Core No-op Mode (x64): ✅ DONE

| Task | File | Status |
|---|---|---|
| `find_iat_hooks()` | `inline_hook.py:32` | ✅ |
| `find_call_sites()` x64 | `inline_hook.py:103` | ✅ |
| `_NOOP_TRAMPOLINE` (3 bytes) | `inline_hook.py:19` | ✅ |
| `add_hooks_section()` | `inline_hook.py:173` | ✅ |
| `patch_call_sites()` | `inline_hook.py:204` | ✅ |
| `rename_import_entries()` | `inline_hook.py:150` | ✅ |
| `inline_iat_hook()` toplevel | `inline_hook.py:487` | ✅ |
| `iat_patch_api()` viết lại | `modifier.py:396` | ✅ — không còn subprocess |

### Phase 2 — Import Cleanup + Polish: ✅ DONE

| Task | File | Status |
|---|---|---|
| `SAFE_RENAME` mapping ~45 APIs | `api_groups.py:417` | ✅ |
| Section name fallback list | `inline_hook.py:22` | ✅ |
| Edge cases (API không tìm thấy, no call sites, ...) | `inline_hook.py:487` | ✅ |

### Phase 3 — x86 Support: ✅ DONE

| Task | File | Status |
|---|---|---|
| `find_call_sites()` x86 (absolute VA) | `inline_hook.py:136` | ✅ |
| `neutralize_relocations_x86()` | `inline_hook.py:244` | ✅ |
| Gọi neutralize trong `inline_iat_hook()` | `inline_hook.py:574` | ✅ |

**Cải tiến so với kế hoạch ban đầu:** Dùng `entry.struct.get_file_offset()` thay vì tính tay offset, tránh sai số khi block có padding.

### Phase 4 — Forwarding Mode: ✅ DONE

| Task | File | Status |
|---|---|---|
| `ensure_loader_apis()` | `inline_hook.py:278` | ✅ |
| `_make_forward_trampoline_x64()` | `inline_hook.py:360` | ✅ |
| `_make_forward_trampoline_x86()` | `inline_hook.py:420` | ✅ (sau khi fix — xem mục 6) |
| `mode` param trong `inline_iat_hook()` | `inline_hook.py:487` | ✅ |
| `modifier.py` cố định `forward` mode | `modifier.py:401` | ✅ — noop đã xóa |

**Cải tiến so với kế hoạch ban đầu:**
- Không dùng keystone-engine — hardcode opcodes trực tiếp bằng Python
- LIEF case-insensitive DLL name lookup (`imp.name.upper() == "KERNEL32.DLL"`) để tránh lỗi casing
- x86 trampoline dùng PIC technique thuần (`push ebx; call $+5; pop ebx`)

### Tests: ✅ DONE

File: `run_tests.py` (8 test cases, chạy trong ~1.4 giây)

| Test | Mô tả |
|---|---|
| `test_noop_bytes` | `_NOOP_TRAMPOLINE == b'\x31\xC0\xC3'` (giữ để test constant) |
| `test_garbage_returns_empty` | garbage input → empty list |
| `test_rename_import_entries` | rename đúng + pad zeros + reject len > original |
| `test_x64_integration_noop` | PE x64 → hook noop → verify hooks section tồn tại |
| `test_x86_integration_noop_with_reloc` | PE x86 → hook noop → verify output lớn hơn |
| `test_forward_mode_x64` | PE x64 → hook forward → verify LoadLibraryA+GetProcAddress present |
| `test_x86_trampoline_layout` | Verify byte layout trampoline x86 (fix off-by-1 + ABI) |
| `test_x86_forward_mode_integration` | PE x86 → hook forward → verify LoadLibraryA+GetProcAddress present |

> **Lưu ý:** `modifier.py` giờ chỉ dùng `forward` mode. Các test noop trong `run_tests.py` test trực tiếp `inline_iat_hook(..., mode='noop')` (vẫn hợp lệ cho `inline_hook.py`), nhưng `iat_patch_api()` sẽ không chạy noop nữa.

---

## 6. Bug Fixes Sau Khi Triển Khai

### Fix: x86 Forwarding Trampoline — Off-by-1 & ABI Violation (2026-05-20)

**File:** `inline_hook.py:420` — `_make_forward_trampoline_x86()`

**Hai lỗi trong implementation ban đầu:**

**Lỗi 1 — Off-by-1 (crash ngay khi chạy):**

```
Cũ: code[0:5] = b'\xE8\x00\x00\x00\x00'  # call $+5 ở offset 0
    → push tramp_va+5 → EBX = tramp_va+5
    → [EBX + (CACHED_PTR_OFFSET-6)] = [tramp_va+66]  ← sai (nên là tramp_va+67)
    → đọc byte \xE0 (phần của JMP EAX), EAX = 0x000000E0 → non-zero
    → jnz taken → jmp eax → jump tới 0x000000E0 → CRASH

Mới: code[0:1] = b'\x53'                   # push ebx ở offset 0
     code[1:6] = b'\xE8\x00\x00\x00\x00'  # call $+5 ở offset 1
     → push tramp_va+6 → EBX = tramp_va+6
     → tất cả offset -6 đúng ✓
```

**Lỗi 2 — ABI violation (EBX bị corrupt):**

```
Cũ:  push ebx ở trong resolution block (chỉ save EBX của trampoline, không phải EBX gốc)
     Sau JMP EAX: EBX = tramp_va+5 (không phải EBX gốc của caller)
     → undefined behavior ở bất kỳ code nào dùng EBX sau đó

Mới: push ebx ở ngay đầu (offset 0) — save EBX gốc của caller
     .forward label (offset 64): pop ebx — restore EBX gốc
     Hoạt động cho cả fast path (cache hit, jnz → 64) và slow path (fall-through → 64)
```

**Tác động của fix:**

| Scenario | Trước fix | Sau fix |
|---|---|---|
| x86 noop mode | ✅ OK | ✅ OK |
| x64 noop mode | ✅ OK | ✅ OK |
| x64 forward mode | ✅ OK | ✅ OK |
| x86 forward mode | ❌ Crash ngay lập tức | ✅ PE chạy bình thường |

---

## 7. Files Đã Thay Đổi

| File | Thay đổi | Trạng thái |
|---|---|---|
| `malware_rl/envs/controls/inline_hook.py` | Module mới — toàn bộ pipeline | ✅ Hoàn chỉnh |
| `malware_rl/envs/controls/modifier.py` | Viết lại `iat_patch_api()` — bỏ subprocess | ✅ Hoàn chỉnh |
| `malware_rl/envs/controls/api_groups.py` | Thêm `SAFE_RENAME` mapping | ✅ Hoàn chỉnh |
| `run_tests.py` | 8 unit + integration tests | ✅ Tất cả pass |

### Files Không Cần Sửa

| File | Lý do |
|---|---|
| Tất cả gym files | `ACTION_TABLE` không đổi → gym tự adapt |
| `stub.c` / `stub.dll` | Giữ làm reference, không còn dùng bởi action |

---

## 8. Dependencies

### Đã Có Trong Project (không cần thêm)
- `pefile` — PE parsing, byte patching
- `lief` — section addition, import injection
- `struct` — standard library

### Đã Loại Bỏ
- `IAT_Patcher_CLI.exe` — không còn dùng
- `stub.dll` runtime — PE self-contained
- `Wine` — không còn subprocess
- `keystone-engine` — không cần (hardcode opcodes)

---

## 9. Lợi Ích Cho Research Paper

1. **Self-contained perturbation:** PE sau khi biến đổi đứng một mình — không phụ thuộc external DLL. Đây là yêu cầu thực tế cho adversarial examples.

2. **Code byte diversity:** Section `.reloc2` / `.rsrc2` thêm code patterns mới vào PE, ảnh hưởng byte n-gram features mà MalConv/SOREL dùng — beyond chỉ import table manipulation.

3. **Single-mode operation (forward only):**
   - `mode='forward'`: functionality preservation — PE vẫn chạy được sau khi biến đổi. Adversarial examples thực tế hơn: qua được cả static detector lẫn không crash khi dynamic analysis.

4. **Formal preservation argument (forwarding mode):** Mọi CALL đều được forward tới API thật sau khi lazy-resolve. Với x64: `Trace(A(B), x) = Trace(B, x)`. Với x86: PIC trampoline bảo toàn đầy đủ stdcall/cdecl calling convention.
