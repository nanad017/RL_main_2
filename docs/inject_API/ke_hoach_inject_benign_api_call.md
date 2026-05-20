# Kế Hoạch: Action `inject_benign_api_call` — Chèn Benign API Call Vào Execution Flow

**Ngày tạo:** 2026-05-20  
**Trạng thái:** Đề xuất, chờ phê duyệt

---

## 1. Mục Tiêu

Thêm action số 17 (Tier 2) tên `inject_benign_api_call` vào `ACTION_TABLE`. Action này:

1. Chọn ngẫu nhiên K=3..5 API benign từ `API_GROUPS` (đã có sẵn 12 nhóm trong `api_groups.py`).
2. Đảm bảo các API đó nằm trong Import Table.
3. Tạo một section mới chứa **mã máy thực sự gọi các API đó** (CALL với tham số dummy hợp lệ).
4. Đổi Entry Point của PE để section mới chạy trước, sau đó JMP về Original Entry Point (OEP).

Kết quả: khi PE chạy, sandbox sẽ ghi nhận **thêm** một loạt lời gọi API benign (`GetSystemTime`, `GetTickCount`, `HeapAlloc`...) trộn lẫn với hành vi malware gốc. Hành vi malware gốc **không bị ảnh hưởng**.

---

## 2. Phân Biệt Với Các Action Đã Có

| Action | Tác động Static | Tác động Dynamic | Self-contained? |
|---|---|---|---|
| `add_imports` (#9) | + 1 entry trong Import Table | Không (không gọi) | ✅ |
| `add_api_group` (#14) | + 2-5 entry / 1 nhóm | Không (không gọi) | ✅ |
| `iat_patch_api` (#15) | Rename suspicious → benign trong Import Table | Đổi trampoline cho call site **hiện có** | ✅ |
| **`inject_benign_api_call` (#17 — mới)** | + 3-5 entry + 1 section mới + EP mới | **Phát sinh API call mới** chạy trước OEP | ✅ |

Điểm khác biệt quan trọng nhất: ba action cũ chỉ chỉnh **bề mặt static** hoặc **thay tên** call site cũ. Action mới phát sinh **call site hoàn toàn mới**, làm thay đổi **dynamic API trace** mà các detector kiểu Cuckoo/CAPE quan sát được.

---

## 3. Đánh Giá Hai Cách Tiếp Cận

### 3.1 Cách A — Pure Python (đề xuất chính)

Dựa trên kiến trúc `inline_hook.py` đã có sẵn. Toàn bộ pipeline trong-bộ-nhớ.

**Ưu:**
- Cùng phong cách với `inline_hook.py` — dễ bảo trì, test cùng style.
- Không phụ thuộc binary ngoại sinh, không subprocess.
- Cross-platform (Windows + Linux + macOS, không cần Wine).
- Chỉnh được fine-grained (số API, vị trí inject, thứ tự call).
- Kế thừa logic `ensure_loader_apis`, `add_section` của `inline_hook.py`.

**Nhược:**
- Phải tự sinh bytecode ASM (đã có precedent với `_make_forward_trampoline_x64/x86`).

### 3.2 Cách B — Build IAT_Patcher_CLI và gọi qua subprocess

Như comment trong task. CLI nằm ở `D:\model\GAMErl\IAT\IAT_patcher\patcher\cli\iat_patcher_cli.cpp`, **chưa được build** (không tìm thấy `iat_patcher_cli.exe` trong workspace; chỉ có source).

**Ưu:**
- Tận dụng được logic StubMaker đã chứng minh chạy được trên hàng ngàn PE.

**Nhược:**
- IAT_patcher CLI chỉ làm được 2 việc: `--list-imports` và `--hook` (replace IAT thunk). **Không có chức năng "inject call site mới"** mà task yêu cầu — nó chỉ swap entry hiện có sang `stub.dll.X`. Đây chính xác là việc `iat_patch_api` (action 15) đã làm từ trước (qua `inline_hook.py`).
- Nếu vẫn dùng CLI thì action mới sẽ **trùng lặp** với action 15.
- Cần build Qt5 + bearparser trên máy (Linux: `iatp_autobuild.sh`, Windows: cần MSVC + Qt SDK). Nặng.

**Kết luận:** Cách B không tạo ra hành vi mới so với action 15. Đề xuất chọn **Cách A**. Phần sau triển khai theo Cách A; nếu sau này cần build CLI để debug/visualize thì làm song song, không thay đổi action.

---

## 4. Thiết Kế Chi Tiết (Cách A)

### 4.1 Tổng quan flow runtime

```
PE đã biến đổi:
   EP = đầu section .inj   ──┐
                              │
   .inj section:              ▼
       sub rsp, 0x28          # x64: align stack + shadow space
       call [IAT_GetTickCount]
       call [IAT_HeapAlloc]   ; tham số dummy
       ...
       add rsp, 0x28
       jmp OEP_real           # JMP về entry point gốc
   ────────────────────────
   .text (malware code)       # chạy bình thường như chưa đổi gì
```

### 4.2 Pipeline pure-Python

```
inject_benign_api_call(bytez):
  1. parse PE → arch (x86/x64), oep_rva, imagebase
  2. chọn K=3..5 API ngẫu nhiên từ API_GROUPS (ưu tiên đa dạng nhóm)
  3. ensure_imports(bytez, picked_apis)        ← LIEF
       → trả về bytez_new + dict {api: iat_rva}
  4. build_trampoline_code(arch, iat_rvas, oep_rva, tramp_rva)
       → bytes shellcode position-aware (cần biết tramp_rva)
  5. add new executable section ".inj" với shellcode
       → tramp_rva = section.virtual_address
       (do bước 4 cần tramp_rva, lặp lại bước 4 với rva thật rồi
        ghi đè raw bytes của section vừa tạo — pattern y hệt
        forward mode trong inline_hook.py:556-579)
  6. update PE EntryPoint → tramp_rva
  7. trả về bytez đã chỉnh
```

### 4.3 Module mới `controls/inject_call.py`

API public:

```python
def inject_benign_api_call(bytez: bytes,
                           num_apis: int = None,
                           api_pool: dict = None) -> bytes:
    """Inject K benign API calls vào trước OEP.
    
    bytez:    PE gốc
    num_apis: số API muốn chèn (default random 3-5)
    api_pool: dict {category: {dll: [funcs]}} — mặc định API_GROUPS
    Returns: bytez đã biến đổi, hoặc bytez gốc nếu thất bại
    """
```

Internal helpers (file-private, prefix `_`):

| Hàm | Trách nhiệm | Tham chiếu |
|---|---|---|
| `_pick_apis(pool, k)` | Chọn k API random, đa dạng nhóm | mới |
| `_ensure_imports(bytez, apis)` | Add import qua LIEF + tìm IAT RVA | giống `ensure_loader_apis` (`inline_hook.py:278`) |
| `_make_injection_x64(...)` | Sinh shellcode x64 | mới (xem 4.4.1) |
| `_make_injection_x86(...)` | Sinh shellcode x86 | mới (xem 4.4.2) |
| `_add_section(bytez, code)` | Add section EXEC|READ | reuse `add_hooks_section` (`inline_hook.py:173`) |
| `_set_entry_point(bytez, rva)` | Patch `OptionalHeader.AddressOfEntryPoint` | mới (LIEF rebuild) |

### 4.4 Sinh shellcode

Mọi tham số đều dùng giá trị **không gây tác dụng phụ**: 0/NULL hoặc trỏ tới buffer dummy nằm trong cùng section. Mục tiêu là call thành công, không quan tâm return value.

#### 4.4.1 x64 (Microsoft x64 calling convention: RCX, RDX, R8, R9 + 32-byte shadow)

Layout section (relative offset trong code):
```
prologue:
   sub rsp, 0x28              ; 4 bytes — align 16 + shadow 32
   xor rcx, rcx               ; 3 bytes — arg1 = 0
   xor rdx, rdx               ; 3 bytes — arg2 = 0  
   xor r8, r8                 ; 3 bytes — arg3 = 0
   xor r9, r9                 ; 3 bytes — arg4 = 0
                              ; total prologue = 16 bytes
api_calls (mỗi cái 6 bytes):
   FF 15 <RIP-relative disp32>  ; call [IAT_api_i]
   ...
epilogue:
   add rsp, 0x28              ; 4 bytes
   E9 <disp32>                ; 5 bytes — jmp OEP (RIP-relative)
                              ; total epilogue = 9 bytes
```

Tổng size = 16 + 6*K + 9 (≈ 55 bytes với K=5).

`disp32` cho mỗi `call [IAT]` được tính giống `_make_forward_trampoline_x64`:
```
disp = iat_rva_i - (tramp_rva + offset_call_in_section + 6)
```

`disp32` cho `jmp OEP`:
```
disp = oep_rva - (tramp_rva + offset_jmp_in_section + 5)
```

#### 4.4.2 x86 (stdcall: args qua stack, callee cleans)

Layout (x86 không có shadow, mỗi API có đặc tả số args khác nhau, nhưng dùng stdcall thì callee tự pop, an toàn để push dư):

```
prologue (mỗi API):
   push 0            ; push 8 zero arguments to cover any signature
   push 0            ; (worst case 8 args, same as x64 stub.c uses 12)
   ... (8 lần)        ; 8 bytes (8 × \x6A\x00)
   call [IAT_api]    ; FF 15 <abs32 = imagebase + iat_rva>  — 6 bytes
                     ; stdcall callee cleans → stack tự cân
   (lặp K lần)
epilogue:
   E9 <disp32>       ; jmp OEP — 5 bytes
```

Lưu ý quan trọng cho x86:
- API có thể là `cdecl` (như MSVCRT) → caller phải clean stack. Để đơn giản, **giới hạn API_pool x86 chỉ chọn từ KERNEL32/USER32/ADVAPI32** (toàn stdcall trên Win32). Loại trừ MSVCRT trong x86 mode.
- `call [IAT]` x86 dùng absolute VA → cần thêm relocation entry tại `disp32` để loader rebase đúng. **Hoặc** đặt section ở virtual address cố định (không khả thi — LIEF chọn). **Đúng nhất:** phát sinh thêm reloc entry tại offset `disp32` trong section mới (xem 4.5).

#### 4.4.3 Lựa chọn tham số cho từng API (tùy chọn nâng cao)

Phiên bản đầu (MVP): tất cả tham số = 0. Hầu hết API benign sẽ trả về lỗi nhưng **không crash** (ví dụ `GetSystemTime(NULL)` trả về 0, không exception).

Phiên bản nâng cao (sau): mỗi API có signature đúng — dành dữ liệu dummy hợp lệ trong section (ví dụ `SYSTEMTIME` buffer 16 bytes cho `GetSystemTime`). Phức tạp hơn, để Phase 2.

### 4.5 Xử lý relocation x86

Tương tự `neutralize_relocations_x86` (`inline_hook.py:244`) nhưng **ngược chiều**: ta phải **thêm** reloc entry mới chứ không vô hiệu hóa entry cũ.

Hai cách:

**Cách 1 (đơn giản, đề xuất):** dùng LIEF API:
```python
binary.relocations  # list of base reloc blocks
new_block = lief.PE.Relocation()  # ...
new_block.add_entry(...)
```

**Cách 2 (manual):** sửa raw bytes bảng `IMAGE_DATA_DIRECTORY[5]`. Phức tạp.

→ Chọn cách 1.

### 4.6 Patch Entry Point

Dùng LIEF:
```python
binary.optional_header.addressof_entrypoint = tramp_rva
builder = lief.PE.Builder(binary)
builder.build()
```

Hoặc patch trực tiếp 4 bytes tại file offset của `AddressOfEntryPoint` field (sau khi đã add section + reloc, tránh LIEF rebuild section table):
- File offset = `e_lfanew + 0x18 + 0x10` (PE signature + COFF header + optional header offset 0x10 cho cả x86/x64).

Để tránh LIEF rebuild gây xáo trộn các section đã add, dùng **patch trực tiếp** là an toàn hơn.

---

## 5. Cấu Trúc API Pool

### 5.1 Sử dụng lại `API_GROUPS` đã có

`api_groups.py` đã định nghĩa 12 nhóm benign đầy đủ DLL+function name. Tận dụng trực tiếp:

```python
from .api_groups import API_GROUPS
# API_GROUPS = {
#   "sysinfo":  {"KERNEL32.DLL": ["GetSystemInfo", "GetComputerNameW", ...]},
#   "file":     {"KERNEL32.DLL": [...]},
#   "time":     {"KERNEL32.DLL": [...]},
#   ...
# }
```

### 5.2 Filter theo arch

Một số DLL chỉ tồn tại trên x86/x64 cụ thể? Thực tế Win32 → cả hai. Nhưng **MSVCRT cdecl** dễ phá stack ở x86. Filter:

```python
X86_SAFE_DLLS = {"KERNEL32.DLL", "USER32.DLL", "ADVAPI32.DLL",
                 "GDI32.DLL", "OLE32.DLL", "OLEAUT32.DLL",
                 "VERSION.DLL", "WS2_32.DLL"}  # all stdcall
```

x64 thì mọi API cùng calling convention → không cần filter.

### 5.3 Chiến lược chọn API

```python
def _pick_apis(pool, k=None, arch_is_64=True):
    if k is None:
        k = random.randint(3, 5)
    # 1. Random chọn k category KHÁC NHAU
    cats = random.sample(list(pool.keys()), min(k, len(pool)))
    out = []
    for cat in cats:
        # 2. Trong mỗi category, pick 1 random (DLL, func)
        dll = random.choice(list(pool[cat].keys()))
        if not arch_is_64 and dll not in X86_SAFE_DLLS:
            continue  # skip MSVCRT etc on x86
        func = random.choice(pool[cat][dll])
        out.append((dll, func))
    return out
```

---

## 6. Tích Hợp Vào `modifier.py`

Sau khi `inject_call.py` xong, sửa `modifier.py`:

```python
# at top:
from .inject_call import inject_benign_api_call as _inject_impl

# in ModifyBinary class:
def inject_benign_api_call(self):
    """Tier 2: Inject 3-5 benign API calls trước OEP.
    Không thay đổi logic malware, chỉ thêm dynamic API surface."""
    result = _inject_impl(self.bytez)
    if result and len(result) > len(self.bytez):
        self.bytez = result
    return self.bytez

# in ACTION_TABLE (after iat_patch_api):
"inject_benign_api_call": "inject_benign_api_call",

# in ACTION_TIER:
"inject_benign_api_call": 2,
```

`reward.py` không cần đổi — `NUM_TIERS = 3` đã đủ.
`custom_gym.py` và các gym khác tự cập nhật `ACTION_LOOKUP` qua `modifier.ACTION_TABLE.keys()`.

---

## 7. Kế Hoạch Test

File mới: thêm test cases vào `run_tests.py` (hoặc tạo `run_tests_inject.py` nếu muốn cô lập).

| Test case | Mô tả | Assertion |
|---|---|---|
| `test_pick_apis_basic` | Gọi `_pick_apis(API_GROUPS, k=3)` | trả về 3 tuple (dll, func) |
| `test_pick_apis_x86_filter` | Gọi với `arch_is_64=False` | không có `MSVCRT.DLL` |
| `test_inject_x64_DIM` | Load `DIM.EXE` (x64) → inject → parse lại | EP đã đổi, có section mới, có K imports mới |
| `test_inject_x86_MSOXMLED` | Load `MSOXMLED.EXE` (x86) → inject → parse lại | Như trên + có reloc entries mới tại đúng offset |
| `test_inject_idempotent` | Inject 2 lần liên tiếp | Lần 2 vẫn không crash, EP trỏ về lần 2 |
| `test_inject_e2e_run` *(optional, nếu có sandbox)* | Inject vào EXE benign → chạy thử trên Wine | exit code = 0 |

Chạy:
```
python run_tests.py
```

Tiêu chí pass: 6/6 test, không exception, output PE size lớn hơn input.

---

## 8. Roadmap Triển Khai (Ưu Tiên Thứ Tự)

### Phase 1 — MVP (x64 only, args = 0, API_GROUPS)
- [ ] `controls/inject_call.py` skeleton: `_pick_apis`, `_ensure_imports`, `inject_benign_api_call`
- [ ] `_make_injection_x64` với args = 0
- [ ] Patch entry point trực tiếp (4 bytes raw)
- [ ] Reuse `add_hooks_section` từ `inline_hook.py`
- [ ] Test `test_inject_x64_DIM`
- [ ] Đăng ký action trong `modifier.py` + `ACTION_TIER`

### Phase 2 — x86 support
- [ ] `_make_injection_x86` (stdcall, push 0×8)
- [ ] Filter `X86_SAFE_DLLS`
- [ ] Add reloc entries mới qua LIEF
- [ ] Test `test_inject_x86_MSOXMLED`

### Phase 3 — Polish & robustness
- [ ] Idempotency test (`test_inject_idempotent`) — chạy action 2 lần
- [ ] Edge case: PE không có space cho thêm imports → fallback no-op
- [ ] Edge case: arch lạ (ARM, ARM64) → fallback no-op
- [ ] Edge case: TLS callback (giữ nguyên)
- [ ] Logging/debug nhỏ qua env var `INJECT_DEBUG=1`

### Phase 4 — Tham số dummy hợp lệ (optional)
- [ ] Dictionary `API_DUMMY_ARGS` mỗi API → list bytes buffer cần dành sẵn
- [ ] Cấp phát buffer trong section `.inj` ngay sau code
- [ ] Sinh `lea rcx, [rip+offset]` thay vì `xor rcx, rcx`
- [ ] Test gọi thực sự không crash trên sandbox

---

## 9. Các File Sẽ Thay Đổi

| File | Loại thay đổi |
|---|---|
| `malware_rl/envs/controls/inject_call.py` | **Tạo mới** (~300 dòng) |
| `malware_rl/envs/controls/modifier.py` | Thêm import + method + entry trong `ACTION_TABLE`, `ACTION_TIER` |
| `run_tests.py` (hoặc file test riêng) | Thêm 4-6 test case |
| `docs/ke_hoach_inject_benign_api_call.md` | File này (đã có) |

Không động tới: `inline_hook.py`, `api_groups.py` (chỉ đọc), `reward.py`, các gym files, `stub.c`/`stub.dll`.

---

## 10. Rủi Ro & Giảm Thiểu

| Rủi ro | Khả năng | Tác động | Giảm thiểu |
|---|---|---|---|
| Crash khi gọi API với args=0 | Thấp (API benign tolerant) | Sandbox báo crash → detector nghi ngờ | Test trước trên 5-10 PE benign mẫu, fallback Phase 4 nếu cần |
| LIEF rebuild làm hỏng section khác | Trung bình | PE corrupted | Add section TRƯỚC, patch EP trực tiếp byte (không gọi `Builder`) |
| x86 reloc thiếu → loader rebase sai | Trung bình | PE crash trên Win không có ASLR ngoại lệ | Thêm reloc entry đầy đủ; nếu LIEF không hỗ trợ thì fallback x64-only |
| Tăng size PE quá lớn | Thấp | Reward `r_size` âm | Section ~256 bytes (1 page nhỏ) — không đáng kể |
| Detector nhận diện section name `.inj` | Trung bình | Bị phát hiện | Dùng tên benign-looking như `inline_hook.py` đã làm: `.text2`, `.rdata2`, `.ext` |
| Action trùng lặp với `iat_patch_api` | Đã loại trừ | Không có giá trị mới | Đã phân tích §2 — bản chất khác hẳn (inject mới vs rename cũ) |

---

## 11. Tiêu Chí Hoàn Thành

- [ ] Action `inject_benign_api_call` xuất hiện trong `ACTION_TABLE`, `ACTION_TIER[..] == 2`
- [ ] `python run_tests.py` chạy hết, 0 fail, 0 error
- [ ] PE x64 sample sau inject:
  - `pefile` parse được
  - Có section mới (tên benign-looking)
  - `OptionalHeader.AddressOfEntryPoint` trỏ vào section mới
  - Disassemble section mới thấy 3-5 `call qword ptr [...]` rồi `jmp` về OEP cũ
  - Import Table có 3-5 API benign mới
- [ ] PE x86 sample tương tự + reloc entries mới hợp lệ
- [ ] PE chạy được trên Windows/Wine, exit code 0 (test thủ công, optional)

---

## 12. Quyết Định Cần Người Dùng Phê Duyệt Trước Khi Code

1. **Cách A (pure-Python) hay Cách B (build CLI)?** — Đề xuất A (xem §3).
2. **MVP chỉ x64 trước, hay cả x86 ngay?** — Đề xuất MVP x64 (Phase 1) rồi mở rộng.
3. **Args = 0 (Phase 1) đủ chưa, hay làm Phase 4 luôn?** — Đề xuất Phase 1 trước, đo reward trên detector, nếu không đủ thì làm Phase 4.
4. **Tên action có ổn không** (`inject_benign_api_call`)? — Có thể đổi tên ngắn hơn nếu muốn.
5. **Có muốn build IAT_Patcher_CLI để dùng song song cho debug/visualize?** — Optional, không trên critical path.