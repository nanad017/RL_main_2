# Mô Tả Chi Tiết Logic Của Từng Action

**File:** `malware_rl/envs/controls/modifier.py` (class `ModifyBinary`)
**Tổng:** 18 action (13 Tier 1 + 3 Tier 2 + 2 Tier 3)

Tài liệu này mô tả chính xác cho từng action: nó thay đổi gì, thay đổi như thế nào, lấy data ở đâu, chọn data như thế nào, và các điểm cần lưu ý.

---

## Bảng Tổng Quan

| Tier | Action | Thay đổi | Nguồn data |
|------|--------|----------|-----------|
| 1 | `pad_overlay` | Append 100KB cùng 1 byte vào overlay | Random byte 0-255 |
| 1 | `append_benign_data_overlay` | Append nội dung 1 section của file benign | `trusted/` |
| 1 | `append_benign_binary_overlay` | Append toàn bộ 1 file benign | `trusted/` |
| 1 | `add_bytes_to_section_cave` | Điền random bytes vào null cave bên trong section | (sinh tại runtime) |
| 1 | `add_section_strings` | Tạo section mới chứa strings benign | `good_strings/`, `section_names.txt` |
| 1 | `add_section_benign_data` | Tạo section mới chứa data từ file benign | `trusted/`, `section_names.txt` |
| 1 | `add_strings_to_overlay` | Append chuỗi strings benign vào overlay | `good_strings/` |
| 1 | `add_imports` | Thêm 1 hàm vào import table | `small_dll_imports.json` |
| 1 | `rename_section` | Đổi tên 1 section thành tên phổ biến | `section_names.txt` |
| 1 | `remove_debug` | Xóa Debug Data Directory | (không cần data) |
| 1 | `modify_optional_header` | Chỉnh 1 field metadata của Optional Header | (hard-coded list) |
| 1 | `modify_timestamp` | Đổi timestamp PE header | (hard-coded list) |
| 1 | `break_optional_header_checksum` | Đặt checksum = 0 | (không cần data) |
| 2 | `add_api_group` | Thêm 2-5 API benign cùng nhóm vào import table | `api_groups.py:API_GROUPS` |
| 2 | `iat_patch_api` | Inline IAT hook + rename + forwarding trampoline | `api_groups.py:IAT_HOOK_TARGETS, SAFE_RENAME` |
| 2 | `inject_benign_api_call` | Inject 3-5 API call vào trước Original Entry Point | `inject_call.py:SAFE_INJECT_APIS` |
| 3 | `stoke_rewrite` | Rewrite `.text` bằng `stoke_actions` qua worker Python >= 3.9 | `stoke_bridge.py`, `stoke_worker.py`, env `STOKE_*` |
| 3 | `bytecode_swap` | Thay 1 byte chunk trong `.text` bằng biến thể cùng size đã verify | `data/bytecode_swap_map.json` qua `_equiv_map_loader.py` |

---

# TIER 1 — STRUCTURAL MUTATIONS (13 actions)

## 1. `pad_overlay`

**Mục đích:** Tăng file size, thay đổi byte histogram phần cuối.

**Logic:**
1. Random 1 byte pattern `b ∈ [0, 255]`.
2. Tạo `bytearray([b] * 100_000)` (100KB toàn cùng 1 byte).
3. `self.bytez += overlay` (append vào cuối).

**Data:** Không cần file ngoài. Random byte sinh tại runtime bằng `random.choice(range(256))`.

**Selection:** Hoàn toàn ngẫu nhiên trong `[0, 255]`.

**Lưu ý:**
- Không động vào PE header → PE vẫn hợp lệ.
- Tăng file size cố định 100KB mỗi lần gọi.
- Nếu detector chuẩn hóa size hoặc bỏ qua overlay thì action này gần như vô hại với detector, nhưng nó vẫn thay đổi byte entropy → ảnh hưởng MalConv.

---

## 2. `append_benign_data_overlay`

**Mục đích:** Append nội dung 1 section "trông benign" vào overlay → nhiễu byte features bằng phân bố giống file sạch.

**Logic:**
1. `_randomly_select_trusted_file()` → lấy ngẫu nhiên 1 file trong `malware_rl/envs/controls/trusted/`.
2. `_get_benign_section_content(file)`:
   - Parse file bằng LIEF.
   - Ưu tiên `binary.get_section(".text")`.
   - Nếu không có thì random 1 section bất kỳ.
   - Nếu LIEF parse fail thì đọc raw bytes của cả file.
3. Append `bytearray(content)` vào `self.bytez`.

**Data:**
- Folder: `malware_rl/envs/controls/trusted/`
- Hiện chỉ có `.gitkeep`, người dùng phải tự thêm file benign (Office utility, system tools, v.v.). Folder con `ls/trusted/` chứa 10 file Office sample (`ACCICONS.EXE`, `DIM.EXE`, ...) nhưng không phải mục tiêu của action này.

**Selection:**
- File: `random.choice([f for f in os.listdir(trusted/) if isfile(...)])`.
- Section: ưu tiên `.text`, fallback random.

**Lưu ý:**
- Nếu folder rỗng → return nguyên bytez (no-op).
- Mỗi lần gọi có thể append section khác nhau (do random.choice).

---

## 3. `append_benign_binary_overlay`

**Mục đích:** Tương tự (2) nhưng append **toàn bộ binary** thay vì 1 section → tăng size mạnh hơn.

**Logic:**
1. `_randomly_select_trusted_file()`.
2. `open(file, "rb").read()` → bytes thô của cả file.
3. Append vào `self.bytez`.

**Data:** Cùng `trusted/` như (2).

**Selection:** Random file trong `trusted/`.

**Lưu ý:**
- File được nối ở overlay → loader Windows không execute.
- Detector có thể nhận biết "PE-in-PE" (nếu nó scan PE signatures), nhưng đa số byte/header detectors bị nhiễu.

---

## 4. `add_bytes_to_section_cave`

**Mục đích:** Sửa đổi nội dung section mà không tăng size, không thay đổi structure.

**Logic:**
1. Parse PE bằng LIEF.
2. Với mỗi section:
   - Lấy `pointerto_raw_data` (file offset) và `content`.
   - Nếu `sizeof_raw_data > virtual_size` thì pad zeros cho đủ (vì cave thường nằm trong phần padding).
   - Gọi `_search_cave(name, body, file_offset, vaddr, cave_size=128)`:
     - Quét tuần tự từng byte.
     - Đếm dãy null bytes liên tiếp ≥ 128.
     - Trả về `[cave_start, cave_end, cave_size]` cho mỗi vùng tìm được.
3. Random chọn 1 cave.
4. Random `upper ∈ [0, 255]`.
5. Sinh `cave_size` byte ngẫu nhiên trong `[0, upper]`.
6. Replace tại `[cave_start:cave_end]` trong `self.bytez` (slicing trực tiếp, không qua LIEF builder).

**Data:** Không cần file ngoài. Cave được tìm runtime trong PE đang xử lý.

**Selection:**
- Cave: `random.choice(caves)`.
- Byte distribution: `[0, random.randrange(256)]` → mỗi cave có dải byte khác nhau.

**Lưu ý:**
- Không thay đổi `sizeof_raw_data` hay `virtual_size` → PE chạy nguyên vẹn.
- `cave_size` ban đầu là 128 nhưng bị **shadow** trong vòng lặp: dòng `cave_size = null_count` ghi đè biến local. Điều này khiến cave kế tiếp dùng `null_count` mới làm threshold (bug nhỏ, chưa sửa).
- Nếu PE không có cave ≥ 128 byte → no-op.

---

## 5. `add_section_strings`

**Mục đích:** Thêm 1 section mới chứa strings của file benign → tăng "good string" features.

**Logic:**
1. `_randomly_select_good_strings()` → đọc 1 file txt từ `good_strings/`.
2. Parse PE bằng LIEF.
3. `available_section_names = COMMON_SECTION_NAMES − {tên section đã có}`.
4. `random.choice(available_section_names)` → chọn tên section mới.
5. `lief.PE.Section(name); section.content = [ord(c) for c in good_strings]`.
6. `binary.add_section(section, lief.PE.SECTION_TYPES.DATA)`.
7. `_binary_to_bytez(binary)` → rebuild PE bằng LIEF Builder.

**Data:**
- Folder: `malware_rl/envs/controls/good_strings/` — chứa các file `.strings.txt` từ binary lành (hiện folder có `.gitkeep`, `ls/good_strings/` con có nhiều file thực tế như `vmware-vdiskmanager.exe.strings.txt`, `ncgen.exe.strings.txt`, v.v.).
- File: `malware_rl/envs/controls/section_names.txt` — danh sách tên section phổ biến.

**Selection:**
- File strings: `random.choice(...)` các file trong `good_strings/`.
- Section name: `random.choice(...)` từ `COMMON_SECTION_NAMES`.

**Lưu ý:**
- Gọi `_binary_to_bytez(binary)` (mặc định `imports=False`) → KHÔNG rebuild import table.
- Section có characteristic mặc định của `SECTION_TYPES.DATA` (read-only).

---

## 6. `add_section_benign_data`

**Mục đích:** Thêm section mới chứa raw data từ section của file benign (thường là `.text`).

**Logic:**
1. `_randomly_select_trusted_file()`.
2. `_get_benign_section_content(file)` (xem action 2).
3. Parse PE.
4. Tương tự (5): chọn `available_section_names`, tạo `lief.PE.Section`, gán `content`, `add_section(..., SECTION_TYPES.DATA)`.
5. `_binary_to_bytez(binary)` rebuild PE.

**Data:**
- `trusted/` (lấy nội dung section).
- `section_names.txt` (chọn tên).

**Selection:** Random file benign + ưu tiên `.text` + random tên section.

**Lưu ý:** Khác (5) ở chỗ data là **opcodes/data binary** thay vì strings ASCII — entropy cao hơn.

---

## 7. `add_strings_to_overlay`

**Mục đích:** Tương tự (5) nhưng append vào overlay thay vì tạo section mới → nhẹ nhàng hơn (không thay structure).

**Logic:**
1. `_randomly_select_good_strings()`.
2. `self.bytez += bytes(good_strings, encoding="ascii")`.

**Data:** `good_strings/` (xem action 5).

**Selection:** Random file txt.

**Lưu ý:** Không qua LIEF rebuild → giữ nguyên byte gốc của PE.

---

## 8. `add_imports`

**Mục đích:** Thêm **1 hàm** vào **1 DLL** trong import table.

**Logic:**
1. Parse PE bằng LIEF.
2. `libname = random.choice(list(COMMON_IMPORTS.keys()))`.
3. `funcname = random.choice(list(COMMON_IMPORTS[libname]))`.
4. Tìm DLL trong `binary.imports` (case-insensitive).
5. Nếu chưa có DLL → `binary.add_library(libname)`.
6. Nếu funcname chưa có trong DLL → `lib.add_entry(funcname)`.
7. `_binary_to_bytez(binary, imports=True)` — **bắt buộc rebuild import table**.

**Data:** `malware_rl/envs/controls/small_dll_imports.json` — JSON map `{DLL: [func1, func2, ...]}` từ các DLL nhỏ phổ biến.

**Selection:**
- DLL: random key.
- Function: random từ list functions của DLL đó.

**Lưu ý:**
- Mỗi lần gọi chỉ thêm **1 function** (khác `add_api_group` thêm 2-5).
- `imports=True` ở `_binary_to_bytez` → LIEF Builder gọi `build_imports(True)` → relayout import table.

---

## 9. `rename_section`

**Mục đích:** Đổi tên 1 section ngẫu nhiên thành tên phổ biến → fool detector dùng section name làm feature.

**Logic:**
1. Parse PE bằng LIEF.
2. `targeted_section = random.choice(binary.sections)`.
3. `targeted_section.name = random.choice(COMMON_SECTION_NAMES)[:5]` — cắt 5 ký tự đầu.
4. `_binary_to_bytez(binary)`.

**Data:** `section_names.txt`.

**Selection:** Random section + random tên.

**Lưu ý:**
- Cắt 5 ký tự là chiến lược an toàn (PE section name max 8 byte). Nhưng nếu chuỗi gốc có dấu `.` ở đầu (e.g., `.rdata` → `.rdat`) thì kết quả vẫn hợp lệ.
- Có thể trùng tên với section khác (không kiểm tra) → có thể tạo 2 section cùng tên (vẫn hợp lệ trong PE spec nhưng detectors có thể flag).

---

## 10. `remove_debug`

**Mục đích:** Xóa Debug Data Directory → ẩn dấu vết build (PDB path, debug info).

**Logic:**
1. Parse PE bằng LIEF.
2. Nếu `binary.has_debug`:
   - Duyệt `binary.data_directories`.
   - Tìm directory có `type == DATA_DIRECTORY.DEBUG`.
   - `e.rva = 0; e.size = 0`.
   - `_binary_to_bytez(binary)`.

**Data:** Không cần.

**Selection:** Không có (đơn lẻ).

**Lưu ý:**
- Chỉ clear directory entry, không xóa data thực sự (debug data vẫn còn ở RVA cũ).
- Nếu PE không có debug → no-op.

---

## 11. `modify_optional_header`

**Mục đích:** Sửa 1 field metadata Optional Header → fool linker/version-based features.

**Logic:**
1. Parse PE.
2. Random chọn 1 trong 6 key:
   - `major_linker_version`: `[2, 6, 7, 9, 11, 14]`
   - `minor_linker_version`: `[0, 16, 20, 22, 25]`
   - `major_operating_system_version`: `[4, 5, 6, 10]`
   - `minor_operating_system_version`: `[0, 1, 3]`
   - `major_image_version`: `[0, 1, 5, 6, 10]`
   - `minor_image_version`: `[0, 1, 3]`
3. Random chọn 1 giá trị từ list tương ứng.
4. `binary.optional_header.__setattr__(key, modified_val)`.
5. `_binary_to_bytez(binary)`.

**Data:** Hard-coded dict `oh` trong code.

**Selection:** 2 lần random — chọn key, rồi chọn value.

**Lưu ý:** Giá trị trong list mô phỏng các phiên bản Visual Studio và Windows phổ biến.

---

## 12. `modify_timestamp`

**Mục đích:** Đổi `TimeDateStamp` trong File Header → fool detector dùng build time.

**Logic:**
1. Parse PE.
2. `binary.header.time_date_stamps = random.choice([0, 868967292, 993636360, 587902357, 872078556])`.
3. `_binary_to_bytez(binary)`.

**Data:** Hard-coded list 5 giá trị (gồm `0` và 4 timestamp tương ứng các build cũ).

**Selection:** Random.

**Lưu ý:** Timestamp `0` đặc biệt (là giá trị "reproducible build" của LLD/MSVC mới).

---

## 13. `break_optional_header_checksum`

**Mục đích:** Set CheckSum = 0 → mô phỏng PE chưa được sign hoặc patch.

**Logic:**
1. Parse PE.
2. `binary.optional_header.checksum = 0`.
3. `_binary_to_bytez(binary)`.

**Data:** Không cần.

**Lưu ý:** Windows loader không kiểm tra checksum cho đa số .exe (chỉ kiểm cho service và driver). Nên set = 0 không làm hỏng PE.

---

# TIER 2 — API SURFACE ACTIONS (3 actions)

## 14. `add_api_group`

**Mục đích:** Tăng API surface với **nhiều hàm cùng nhóm** (theo chủ đề: file I/O, registry, time, ...) → tạo dấu vết của ứng dụng "lành" theo cụm.

**Logic:**
1. `group_name = random.choice(list(API_GROUPS.keys()))` — 1 trong 12 nhóm.
2. Parse PE bằng LIEF.
3. Với mỗi `(dll_name, funcs)` trong group:
   - Tìm/thêm `lib` (case-insensitive).
   - Tìm `candidates = funcs − {existing functions}`.
   - Nếu không có ứng viên → skip nhóm con này.
   - `n = random.randint(2, min(5, len(candidates)))` → quyết định thêm 2-5 hàm.
   - `random.sample(candidates, n)` → chọn không trùng.
   - `lib.add_entry(func)` cho từng hàm.
4. Nếu có thay đổi → `_binary_to_bytez(binary, imports=True)`.

**Data:** `api_groups.py:API_GROUPS` — dict 12 nhóm:

| Nhóm | DLL | Số API |
|------|-----|--------|
| `sysinfo` | KERNEL32 | 11 |
| `file` | KERNEL32 | 22 |
| `time` | KERNEL32 | 9 |
| `registry` | ADVAPI32 | 14 |
| `network` | WS2_32 | 24 |
| `ui` | USER32 | 21 |
| `crypto_benign` | ADVAPI32 + CRYPT32 | 9 + 6 |
| `memory` | KERNEL32 | 14 |
| `string` | KERNEL32 + MSVCRT | 14 + 21 |
| `com` | OLE32 + OLEAUT32 | 9 + 8 |
| `gdi` | GDI32 | 14 |
| `version` | VERSION | 6 |

**Selection:**
- Group: 1 trong 12 (uniform random).
- Số hàm: `randint(2, min(5, |candidates|))`.
- Hàm cụ thể: `random.sample(candidates, n)`.

**Lưu ý:**
- Khác `add_imports` ở chỗ thêm cả "cluster" cùng chủ đề → tạo "API signature" giống ứng dụng benign thực sự (vd: ứng dụng GUI sẽ có nhiều USER32 API cùng lúc).
- Các function chỉ được khai báo trong import, **không được gọi** → an toàn 100% với binary gốc.

---

## 15. `iat_patch_api`

**Mục đích:** Inline IAT hook — chèn trampoline để **chuyển hướng** call từ API "đáng nghi" sang API benign hoặc tới API thật qua lazy resolution.

**Logic chi tiết** (xem thêm `inline_hook.py`):

1. `category = random.choice(list(IAT_HOOK_TARGETS.keys()))` — 1 trong **10 category** (mask_injection, mask_network, mask_suspicious_kernel, normalize_crypto, mask_evasion, mask_persistence, mask_timing, mask_fingerprint, mask_window_enum, mask_nt_registry).
2. `targets = IAT_HOOK_TARGETS[category]` — list `[(DLL, API), ...]`.
3. `mode = "forward"` (cố định trong code hiện tại).
4. Gọi `inline_iat_hook(self.bytez, targets, SAFE_RENAME, mode=mode)`:

   **a) Nếu `mode='forward'`:**
   - `ensure_loader_apis(bytez)` → đảm bảo `LoadLibraryA` + `GetProcAddress` có trong `KERNEL32.DLL` (LIEF rebuild import nếu thiếu, kèm logic case-insensitive matching `KERNEL32.dll` vs `KERNEL32.DLL`).

   **b) Tìm IAT hooks:**
   - Parse PE bằng pefile.
   - Duyệt `DIRECTORY_ENTRY_IMPORT`, lọc các API có trong `targets`.
   - Lấy `iat_rva = imp.address - imagebase` cho mỗi hit.
   - Tính `name_file_offset` để rename in-place.

   **c) Tìm call sites:**
   - Quét mọi section executable.
   - Tìm pattern `FF 15` / `FF 25` (call/jmp indirect qua IAT).
   - x64: `ref_rva = instr_rva + 6 + signed_disp`.
   - x86: `ref_rva = (unsigned_disp - imagebase) & 0xFFFFFFFF`.
   - Match với `iat_rva` trong hooks → lưu vào `sites`.

   **d) Build trampoline shellcode:**
   - Mode `noop`: chỉ `xor eax, eax; ret` (3 byte) → API trả về NULL.
   - Mode `forward`: shellcode lazy-resolve (~78 byte x64, ~67 byte x86):
     - Check `cached_ptr` (8 byte trong section).
     - Nếu NULL → push args, gọi `LoadLibraryA(dll_name)`, `GetProcAddress(handle, api_name)`, lưu kết quả vào `cached_ptr`.
     - `jmp` tới function thật.
     - x64: dùng RIP-relative addressing (`48 8B 05 ...`, `48 8D 0D ...`, `FF 15 ...`).
     - x86: dùng PIC trick `call $+5; pop ebx` để lấy EIP, tính địa chỉ runtime của IAT slot.

   **e) Rename import names:**
   - Với mỗi hook, nếu `SAFE_RENAME[api]` tồn tại VÀ `len(replacement) ≤ len(original)`:
     - Ghi đè in-place tại `name_file_offset` trong `IMAGE_IMPORT_BY_NAME.Name`.
     - Pad null bytes cho phần dư.
   - Ví dụ: `VirtualAllocEx` → `GlobalAlloc`, `NtCreateUserProcess` → `NtClose`.

   **f) Add hooks section:**
   - Tên section ưu tiên: `.reloc2`, `.rsrc2`, `.data2`, `.rdata2`, `.text2`, `.ext`.
   - Characteristic: `MEM_EXECUTE | MEM_READ | CNT_CODE`.
   - LIEF rebuild PE.

   **g) Patch call sites:**
   - Mỗi `FF 15 disp32` → `90 E8 disp32` (NOP + relative call to trampoline).
   - x86 only: gọi `neutralize_relocations_x86()` để set type của relocation entry tại `instr_rva+2` về `IMAGE_REL_BASED_ABSOLUTE` (0) — tránh loader làm hỏng E8 displacement khi rebase.

5. Nếu `len(result) > len(self.bytez)` → cập nhật `self.bytez`.

**Data:**
- `api_groups.py:IAT_HOOK_TARGETS` — 10 category × ~5-12 (DLL, API) = ~76 mục tiêu.
- `api_groups.py:SAFE_RENAME` — ~70 mapping tên gốc → tên benign (có filter `len(rep) ≤ len(orig)`).

**Selection:** 1 category random + tự động xử lý mọi API trong category đó nếu có trong PE.

**Lưu ý:**
- Action chỉ "thành công" (cập nhật bytez) khi PE có **ít nhất 1** API mục tiêu trong import table.
- `mode='forward'` đảm bảo PE vẫn chạy được vì call thật vẫn được thực thi qua trampoline.
- Có thể fallback `mode='noop'` nếu `ensure_loader_apis` thất bại.

---

## 16. `inject_benign_api_call`

**Mục đích:** Thêm **3-5 API call benign** chạy **trước** Original Entry Point → tạo dynamic API signature cho sandbox (Cuckoo/CAPE).

**Logic chi tiết** (xem `inject_call.py`):

1. Parse PE bằng pefile.
2. Lấy:
   - `is64 = (Magic == 0x20b)`.
   - `machine` (chỉ chấp nhận x86 0x14c hoặc x64 0x8664).
   - `oep_rva = AddressOfEntryPoint`.
3. Nếu `oep_rva == 0` → bỏ qua (PE không có entry).
4. `_pick_apis(k, arch_is_64=is64)`:
   - `k = random.randint(3, 5)` mặc định.
   - Pool gốc: `SAFE_INJECT_APIS` (~30 API benign).
   - Với x86: filter chỉ giữ DLL trong `_X86_SAFE_DLLS` (KERNEL32, USER32, ADVAPI32, GDI32, OLE32, OLEAUT32, VERSION, WS2_32, SHELL32, COMCTL32, COMDLG32, CRYPT32) — đảm bảo stdcall (callee cleans stack).
   - `random.sample(pool, k)` → tránh trùng.
5. `_ensure_imports(bytez, apis)`:
   - Truy vấn IAT RVA cho từng API.
   - Nếu thiếu → `lief.PE.add_library(dll)` + `binary.add_import_function(dll, func)` (case-insensitive matching).
   - Rebuild PE bằng LIEF.
   - Re-query IAT để lấy RVA mới.
6. Re-read OEP từ PE đã rebuild (LIEF có thể shift OEP nếu rebuild import).
7. `_calc_section_size(apis, is64)`:
   - x64: `4 (sub rsp,0x28) + sum(_x64_per_api_size) + 4+5 (epilogue+jmp)`.
   - x86: `7 (push ebx; call $+5; pop ebx) + sum(_x86_per_api_size) + 1+5`.
   - + 256 byte dummy buffer cho APIs cần con trỏ đầu ra (`GetSystemTime`, `GetCursorPos`, `QueryPerformanceCounter`, ...).
   - Round up 16 byte.
8. `_add_section_rwx(bytez, b'\x00' * size)`:
   - Tên ưu tiên: `.text2`, `.rdata2`, `.data2`, `.rsrc2`, `.reloc2`, `.ext0`, `.tls0`, `.in0`.
   - Characteristic: `MEM_EXECUTE | MEM_READ | MEM_WRITE | CNT_CODE` (RWX).
   - LIEF build PE.
9. Re-query IAT lần cuối (vì LIEF có thể shift lại sau khi add section).
10. `_make_injection_x64()` hoặc `_make_injection_x86()`:
    - **x64:** Đẩy args vào RCX/RDX/R8/R9 (≤ 4 args):
      - `'buf'` → `lea reg, [rip+disp]` trỏ tới dummy buffer.
      - `'zero'` → `xor reg32, reg32`.
      - Sau đó `call qword ptr [rip+disp]` tới IAT slot.
    - **x86:** Push args lên stack:
      - `'buf'` → `lea eax, [ebx+disp]; push eax`.
      - `'zero'` → `push 0`.
      - Sau đó `mov edx, ebx; add edx, disp; call [edx]`.
    - Cuối cùng: `jmp rel32` về OEP.
11. `_overwrite_section_at_rva()`: ghi đè in-place 0-byte placeholder thành shellcode thực.
12. `_patch_entry_point(new_ep_rva = sec_rva)`: ghi đè 4 byte `AddressOfEntryPoint` trong Optional Header.

**Data:** `inject_call.py:SAFE_INJECT_APIS` — danh sách `(DLL, FUNC, [arg_types])`:

| Nhóm | DLL | API ví dụ | arg signature |
|------|-----|-----------|---------------|
| Time/system | KERNEL32 | GetSystemTime, GetTickCount, QueryPerformanceCounter, GetSystemInfo | `['buf']` hoặc `[]` |
| User info | USER32 | GetCursorPos, GetActiveWindow, GetSysColor | `['buf']` hoặc `['zero']` hoặc `[]` |

`arg_types`:
- `'buf'`: trỏ tới buffer 256 byte zeroed (an toàn cho mọi struct out param).
- `'zero'`: integer 0.

**Selection:**
- `k`: `randint(3, 5)`.
- API: `random.sample(pool, k)` (sau khi filter theo arch).

**Lưu ý:**
- Section RWX → có thể bị flag bởi static detector chuyên kiểm characteristic, nhưng đa số coi đây là dấu hiệu của packer chứ không phải malware.
- PIC technique x86 (`call $+5; pop ebx`) tránh việc phải sinh thêm relocation entry.
- Shellcode position-independent → không phụ thuộc imagebase, hoạt động cả khi PE bị ASLR rebase.
- API gọi xong, các register volatile (`RAX`, `RCX`, `RDX`, ...) bị clobber nhưng vì chúng ta `jmp` sang OEP (mà OEP chuẩn không phụ thuộc vào volatile registers), nên malware gốc vẫn chạy bình thường.

---

# TIER 3 — CODE REWRITE (2 actions)

## 17. `stoke_rewrite`

**Mục đích:** Rewrite `.text` section bằng `stoke_actions` qua worker Python >= 3.9 → tạo binary ngữ nghĩa giống hệt nhưng có thể khác bytes, trong khi **giữ nguyên kích thước file**.

**Logic:**
1. `ModifyBinary.stoke_rewrite()` chỉ là thin wrapper gọi `_apply_stoke_action(self.bytez)` từ `stoke_bridge.py`.
2. `stoke_bridge.apply_stoke_action(...)`:
   - Đọc cấu hình từ env:
     - `STOKE_PYTHON` — interpreter Python >= 3.9 chạy worker
     - `STOKE_WORKER` — path tới `stoke_worker.py`
     - `STOKE_N` — số mutation tối đa
     - `STOKE_REWRITES` — thư viện rewrite, mặc định `proven_v3_cleaned`
     - `STOKE_TIMEOUT` — timeout subprocess
     - `STOKE_SEED` — seed cố định nếu muốn reproducible
   - Ghi `self.bytez` vào file tạm `input.exe`.
   - Chạy subprocess:
     ```bash
     $STOKE_PYTHON $STOKE_WORKER --input ... --output ... --n ... --rewrites ... [--seed ...]
     ```
3. `stoke_worker.py` (chạy bằng Python >= 3.9):
   - `import stoke_actions as sa`
   - `mutated = sa.mutate(pe_bytes, n=args.n, rewrites=args.rewrites, seed=args.seed)`
   - Kiểm tra `mutated` là `bytes|bytearray`
   - Kiểm tra `len(mutated) == len(input)`
   - Ghi `output.exe`
   - In đúng 1 dòng JSON cuối cùng ra stdout:
     - thành công: `{"ok": true, ...}`
     - lỗi: `{"ok": false, "error": "..."}`
4. Bridge parse JSON dòng cuối, kiểm tra output file tồn tại, không rỗng, cùng size input.
5. Nếu mọi kiểm tra đều pass → trả bytes mới. Nếu có lỗi ở bất kỳ bước nào → trả lại bytes gốc.

**Data / dependency:**
- Worker script: `malware_rl/envs/controls/stoke_worker.py`
- Bridge script: `malware_rl/envs/controls/stoke_bridge.py`
- Python env riêng có package `stoke_actions`
- Optional nhưng rất nên có: `capstone` trong env STOKE để pass rewrite theo thư viện `proven_v3_cleaned` không bị skip

**Selection:** `stoke_actions` tự chọn mutation trên `.text` theo `n`, `seed`, `rewrites` truyền vào.

**Lưu ý:**
- Core RL runtime **không import `stoke_actions` trực tiếp**; mọi thứ được cô lập qua subprocess để giữ tương thích Python 3.7.
- Action này vẫn là no-op an toàn nếu:
  - `STOKE_PYTHON` sai
  - `STOKE_WORKER` sai
  - worker timeout
  - worker trả JSON lỗi
  - output đổi size
- Trên máy hiện tại, `stoke_rewrite` nằm ở **index 16** trong `ACTION_TABLE`.
- Nếu env STOKE thiếu `capstone`, `stoke_actions.mutate()` vẫn chạy nhưng có thể bỏ qua pass rewrite theo equivalence library.

---

## 18. `bytecode_swap`

**Mục đích:** Thay 1 byte chunk trong section executable bằng biến thể **cùng kích thước** đã được verify trước, không rebuild PE và không làm xê dịch offset.

**Logic:**
1. `ModifyBinary._get_equiv_map()` lazy-load map từ `BYTECODE_SWAP_MAP_PATH = <repo>/data/bytecode_swap_map.json` qua `_equiv_map_loader.load_equiv_map(...)`.
2. Loader chỉ giữ các cặp:
   - `verified == true`
   - `same_size == true`
   - `len(original_hex) == len(variant_hex)`
3. Parse PE bằng LIEF.
4. Tìm section executable:
   - ưu tiên `.text`
   - fallback section đầu tiên có characteristic `MEM_EXECUTE`
5. Quét raw bytes của executable section để tìm mọi occurrence của từng `original_bytes` trong equivalence map.
6. Random chọn 1 hit `(abs_offset, original)` và random chọn 1 `variant` tương ứng.
7. Nếu `len(variant) == len(original)` thì splice trực tiếp:
   ```python
   self.bytez = self.bytez[:abs_offset] + variant + self.bytez[abs_offset + len(original):]
   ```
8. Không có LIEF rebuild; output luôn cùng total file size với input.

**Data:**
- `data/bytecode_swap_map.json`
- `malware_rl/envs/controls/_equiv_map_loader.py`

**Selection:**
- Match site: random trong tất cả occurrence tìm được ở executable section
- Variant: random trong list biến thể của opcode gốc

**Lưu ý:**
- Nếu map rỗng, file JSON thiếu, PE parse fail, không có executable section, hoặc không có match → action no-op.
- Vì chỉ dùng cặp cùng size, action này không thay đổi layout PE.
- Đây là action Tier 3 thứ hai sau `stoke_rewrite`, nên `stoke_rewrite` không còn là action cuối cùng của `ACTION_TABLE`.

---

# Phụ Lục: Các Helper & Utilities

## `_binary_to_bytez(binary, imports=False)`

Wrapper rebuild PE bằng LIEF Builder:
```python
builder = lief.PE.Builder(binary)
builder.build_imports(imports)   # True khi có thay đổi import table
builder.build()
self.bytez = bytes(builder.get_build())
```

## `_randomly_select_trusted_file()`

Chọn 1 file ngẫu nhiên trong `trusted/` (loại trừ `.gitkeep`). Trả về `None` nếu folder rỗng.

## `_randomly_select_good_strings()`

Chọn 1 file ngẫu nhiên trong `good_strings/`, đọc nội dung dạng ASCII.

## `_get_benign_section_content(file)`

- Ưu tiên `.text` section của file benign.
- Fallback: random section bất kỳ.
- Cuối cùng: raw bytes cả file.

## `_search_cave(...)`

Quét tìm dãy null bytes liên tiếp ≥ `cave_size` (mặc định 128) trong nội dung section.

---

# Tổng Kết Nguồn Data

| Nguồn | Loại | Dùng bởi |
|-------|------|----------|
| `trusted/` | Folder chứa PE benign | `append_benign_data_overlay`, `append_benign_binary_overlay`, `add_section_benign_data` |
| `good_strings/` | Folder chứa file txt strings | `add_strings_to_overlay`, `add_section_strings` |
| `section_names.txt` | List tên section phổ biến | `rename_section`, `add_section_strings`, `add_section_benign_data` |
| `small_dll_imports.json` | DLL → list functions phổ biến | `add_imports` |
| `api_groups.py:API_GROUPS` | 12 nhóm API benign | `add_api_group` |
| `api_groups.py:IAT_HOOK_TARGETS` | 10 nhóm API "đáng nghi" | `iat_patch_api` |
| `api_groups.py:SAFE_RENAME` | Map rename API → benign | `iat_patch_api` |
| `inject_call.py:SAFE_INJECT_APIS` | ~30 API benign + arg signatures | `inject_benign_api_call` |
| Hard-coded lists | Optional Header values, timestamps | `modify_optional_header`, `modify_timestamp` |
| Runtime gen | Random bytes | `pad_overlay`, `add_bytes_to_section_cave` |
| `stoke_bridge.py` + `stoke_worker.py` + env `STOKE_*` | Bridge/worker cho `stoke_actions` | `stoke_rewrite` |
| `data/bytecode_swap_map.json` | Map opcode tương đương cùng size đã verify | `bytecode_swap` |

---

# Các Điểm Cần Lưu Ý Chung

1. **Tất cả action đều idempotent về PE validity:** nếu input PE hợp lệ, output cũng hợp lệ (hoặc giữ nguyên bytez cũ nếu thất bại). Không có action nào "phá" PE để rồi return PE hỏng.

2. **No-op khi data thiếu:** Nếu folder data (`trusted/`, `good_strings/`) rỗng, action lặng lẽ trả về bytez gốc.

3. **Random selection được điều khiển bởi Python `random` module** — chưa có seed cố định; trong RL training thường truyền seed qua env layer.

4. **Tier khác nhau ở mức độ ảnh hưởng:**
   - **Tier 1:** Thay đổi structural/metadata, không động vào execution flow.
   - **Tier 2:** Thay đổi API surface (static + dynamic), có thể chèn shellcode vào execution flow nhưng vẫn preserve original logic.
   - **Tier 3:** Rewrite execution logic ở mức instruction hoặc thay bytecode trong executable section theo cặp tương đương cùng size.

5. **Action không đảm bảo "evasive":** Mỗi action chỉ là **1 phép biến đổi** trong action space của RL agent. Agent học cách kết hợp nhiều action để vượt qua detector cụ thể.

6. **Side effects:**
   - Một số action tăng file size (`pad_overlay` luôn +100KB, `append_benign_binary_overlay` tùy file).
   - `iat_patch_api` và `inject_benign_api_call` thêm section mới → tăng `NumberOfSections` trong File Header.
   - `add_imports` và `add_api_group` thay đổi cấu trúc Import Directory → có thể shift các section khác.

7. **Bug nhẹ chưa sửa:**
   - `_search_cave` shadow biến `cave_size` (không nghiêm trọng, chỉ làm threshold nhỏ dần).
   - `rename_section` có thể tạo trùng tên (rất hiếm gặp do `COMMON_SECTION_NAMES` lớn).

8. **`mode='forward'` của `iat_patch_api` hiện đang hard-code:** Code cũ có biến chọn random `mode` giữa `noop` và `forward`, nhưng phiên bản hiện tại cố định `mode = "forward"`. Nếu muốn quay lại random, sửa dòng `mode = "forward"` thành `mode = random.choice(["noop", "forward"])`.
