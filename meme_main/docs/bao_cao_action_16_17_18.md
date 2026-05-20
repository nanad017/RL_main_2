# Báo Cáo Kỹ Thuật: Action 14 & 15 — Import Table Perturbation

**Dự án:** MEME-RL — Problem-space RL adversarial evasion  
**Phạm vi:** 2 actions API-related thêm vào action space (action 14–15)  
**Cập nhật lần cuối:** 2026-05-16

---

## 1. Bối Cảnh và Động Lực Nghiên Cứu

MEME-RL sử dụng Reinforcement Learning để biến đổi PE malware nhằm đánh lừa **static malware detector**. Static detector (EMBER, SOREL, MalConv, custom LGB) phân tích file PE mà **không thực thi** — chúng trích xuất đặc trưng từ cấu trúc file bao gồm:

- Import table: danh sách DLL và function name malware import
- Section names, entropy, size
- Header fields, timestamp, checksum
- Byte n-gram, string features

13 actions gốc tập trung vào overlay, section, header. **Import table** là một trong những signal mạnh nhất với static detector nhưng chưa được khai thác đúng mức — đây là lý do thêm 2 actions mới.

---

## 2. Action 14: `add_api_group`

### Cơ chế

Thêm 2–5 API **benign** vào import table của PE bằng LIEF. Không thay đổi code bytes, không cần tool ngoài.

```
Trước:  Import table: kernel32.dll → [VirtualAlloc, CreateThread, ...]
Sau:    Import table: kernel32.dll → [VirtualAlloc, CreateThread, ...]
                      gdi32.dll    → [BitBlt, CreateCompatibleDC, ...]  ← thêm vào
```

### Mục đích

Kỹ thuật **import dilution** — pha loãng tín hiệu malicious bằng cách thêm các API phổ biến trong benign software. Static detector dùng TF-IDF hoặc feature hashing trên DLL/API name sẽ bị ảnh hưởng vì tỷ lệ API benign/malicious thay đổi.

### Thiết kế API_GROUPS (12 nhóm)

| Nhóm | DLL chính | Mục đích giả lập |
|---|---|---|
| `sysinfo` | KERNEL32 | App đọc thông tin hệ thống |
| `file` | KERNEL32 | App đọc/ghi file |
| `time` | KERNEL32 | App xử lý thời gian |
| `registry` | ADVAPI32 | App đọc/ghi registry |
| `network` | WS2_32 | App networking |
| `ui` | USER32 | GUI application |
| `crypto_benign` | ADVAPI32, CRYPT32 | App dùng mã hóa hợp lệ (TLS, hash) |
| `memory` | KERNEL32 | App quản lý bộ nhớ |
| `string` | KERNEL32, MSVCRT | App xử lý chuỗi |
| `com` | OLE32, OLEAUT32 | App dùng COM/OLE |
| `gdi` | GDI32 | App đồ họa/in ấn |
| `version` | VERSION | App kiểm tra phiên bản |

### Đặc điểm kỹ thuật

- **Không đổi code bytes**: API được thêm nhưng không bao giờ được gọi — PE vẫn chạy bình thường
- **Idempotent-safe**: kiểm tra duplicate trước khi thêm
- **Random**: mỗi episode chọn nhóm và số lượng API ngẫu nhiên (2–5)

---

## 3. Action 15: `iat_patch_api` (IAT Hook)

### Cơ chế

Dùng `IAT_Patcher_CLI.exe` để hook từng API suspicious theo flow:

```
gọi API chính → hook qua stub.dll → quay lại luồng chính
```

Cụ thể với từng API target:
1. Xác định API suspicious tồn tại trong import table (parse PE bằng LIEF)
2. Hook từng API riêng lẻ qua `--hook`: đổi IAT entry từ `kernel32.dll!VirtualAllocEx` → `stub.dll!AllocateMemoryBlock`
3. Output của hook N trở thành input của hook N+1 (chained stages)

```
stage_0.exe  →[--hook VirtualAllocEx]→  stage_1.exe
stage_1.exe  →[--hook WriteProcess  ]→  stage_2.exe
stage_2.exe  →[--hook CreateRemote  ]→  stage_3.exe   (final)
```

```
Trước (import table):  kernel32.dll → VirtualAllocEx
Trước (code bytes):    FF 15 [IAT_VirtualAllocEx]

Sau (import table):    stub.dll     → AllocateMemoryBlock
Sau (code bytes):      FF 15 [IAT_AllocateMemoryBlock]   ← code bytes thay đổi
```

Khi PE thực thi:
- Lệnh `CALL [IAT_VirtualAllocEx]` → thực ra gọi `stub.dll.AllocateMemoryBlock`
- Hàm stub chạy (no-op) → trả về → luồng chính tiếp tục

### Tại sao dùng `--hook` tuần tự thay vì `--batch`?

`--batch` xử lý tất cả API trong một lần gọi CLI (nhanh hơn nhưng all-or-nothing). `--hook` tuần tự:
- Mỗi API được hook độc lập — nếu một hook lỗi, các API còn lại vẫn được xử lý
- Flow rõ ràng: xử lý API chính → hook → tiếp tục API tiếp theo

Nếu một `--hook` call thất bại, `current_pe` không được cập nhật, các hook tiếp theo vẫn chạy trên input trước đó.

### stub.dll

Một Windows DLL export 72 hàm no-op có tên benign-sounding. Tên hàm được thiết kế để:
- Không trùng với bất kỳ Windows API thật nào
- Nghe như utility function của phần mềm hợp lệ
- Không gợi ý behavior malicious

Ví dụ: `AllocateMemoryBlock`, `NetworkInitialize`, `CryptoHashBuffer`, `ValidateInputBuffer`...

**Build command (Linux training server):**
```bash
x86_64-w64-mingw32-gcc -shared -o stub.dll stub.c -Wl,--out-implib,libstub.a
```

---

## 4. Thiết Kế IAT_HOOK_TARGETS — Phương Pháp Luận

### Nguồn tham khảo: CAPEv2 / capemon

Để xác định API nào là **ground truth malware indicator**, chúng tôi nghiên cứu **capemon** — monitor DLL của sandbox CAPEv2 (https://github.com/kevoreilly/capemon). Capemon hook **530+ Windows API** chia thành 20 file chuyên biệt để detect malware behavior tại runtime.

**Lý luận**: API mà dynamic sandbox chọn để monitor = API có khả năng cao xuất hiện trong malware import table = API mà static detector học để flag.

Đây là cách tiếp cận có căn cứ thực nghiệm thay vì chọn API theo cảm tính.

### Nguyên tắc lọc API

Từ 530+ API của capemon, chúng tôi lọc theo 3 tiêu chí:

**1. Strong static indicator không?**

API phải là signal mạnh trong import table. Ví dụ `NtAllocateVirtualMemory` rất suspicious; `GetTickCount` ít suspicious hơn nhưng vẫn xuất hiện trong malware fingerprinting research.

**2. Có thực sự xuất hiện trong malware import table không?**

Nhiều malware dùng dynamic API resolution (`GetProcAddress`) nên không import statically. Tuy nhiên, nhiều malware vẫn import statically — khi đó action có tác dụng; khi không import thì action là no-op (an toàn).

**3. Ảnh hưởng đến core payload không?** *(quan trọng với action 15)*

| Loại | Quyết định | Lý do |
|---|---|---|
| API là side-effect (anti-VM, timing, fingerprint) | ✅ Ưu tiên | Hook không phá vỡ payload chính |
| API là cơ chế tấn công chính (injection, C2) | ✅ Chấp nhận | Static evasion là mục tiêu, không cần functional |

### 10 Categories trong IAT_HOOK_TARGETS

#### Nhóm 1: Core Malicious APIs (4 categories, nguồn capemon)

**`mask_injection`** — Process injection primitives  
*Source: hook_process.c, hook_thread.c*

| API | DLL | Kỹ thuật injection |
|---|---|---|
| VirtualAllocEx | KERNEL32 | Classic remote allocation |
| VirtualAlloc | KERNEL32 | Local allocation |
| WriteProcessMemory | KERNEL32 | Write shellcode |
| ReadProcessMemory | KERNEL32 | Read target memory |
| CreateRemoteThread | KERNEL32 | Execute injected code |
| CreateRemoteThreadEx | KERNEL32 | Extended version |
| NtCreateThreadEx | NTDLL | NT-level thread creation |
| RtlCreateUserThread | NTDLL | Undocumented thread creation |
| NtProtectVirtualMemory | NTDLL | Change memory permissions |
| VirtualProtectEx | KERNEL32 | RWX permission manipulation |
| NtQueueApcThread | NTDLL | APC injection technique |

**`mask_network`** — C2 communication  
*Source: hook_network.c*

| API | DLL | Dùng cho |
|---|---|---|
| InternetOpenW/A | WININET | Khởi tạo WinInet session |
| InternetConnectW | WININET | Kết nối HTTP/FTP |
| HttpOpenRequestW | WININET | Tạo HTTP request |
| HttpSendRequestW | WININET | Gửi HTTP request |
| InternetReadFile | WININET | Đọc response |
| InternetCloseHandle | WININET | Cleanup |
| URLDownloadToFileW | URLMON | Download file |
| WinHttpOpen | WINHTTP | WinHTTP session |
| WinHttpConnect | WINHTTP | WinHTTP kết nối |
| WinHttpOpenRequest | WINHTTP | WinHTTP request |
| WinHttpSendRequest | WINHTTP | WinHTTP gửi |

**`mask_suspicious_kernel`** — NT-level kernel operations  
*Source: hook_process.c*

| API | DLL | Mức độ suspicious |
|---|---|---|
| NtOpenProcess | NTDLL | Mở process để inject |
| NtAllocateVirtualMemory | NTDLL | NT-level memory allocation |
| NtWriteVirtualMemory | NTDLL | NT-level memory write |
| NtCreateSection | NTDLL | Section-based injection |
| NtMapViewOfSection | NTDLL | Map section vào target process |
| NtUnmapViewOfSection | NTDLL | Process hollowing step |
| NtCreateProcess | NTDLL | NT-level process creation |
| NtResumeThread | NTDLL | Resume suspended thread |
| NtDuplicateObject | NTDLL | Handle duplication |
| NtCreateUserProcess | NTDLL | NT-level user process creation |

**`normalize_crypto`** — Cryptographic APIs (ransomware signature)  
*Source: hook_crypto.c*

| API | DLL | Dùng trong ransomware cho |
|---|---|---|
| CryptEncrypt | ADVAPI32 | Mã hóa file nạn nhân |
| CryptDecrypt | ADVAPI32 | Giải mã key |
| CryptImportKey | ADVAPI32 | Import key từ attacker |
| CryptExportKey | ADVAPI32 | Export key đã tạo |
| CryptSetKeyParam | ADVAPI32 | Cấu hình key (IV, mode) |
| CryptGenKey | ADVAPI32 | Tạo encryption key |
| CryptProtectData | ADVAPI32 | DPAPI encryption |
| CryptUnprotectData | ADVAPI32 | Credential theft via DPAPI |

---

#### Nhóm 2: Evasion & Side-Effect APIs (6 categories, mới thêm)

**`mask_evasion`** — Anti-debug / Anti-VM  
*Source: hook_misc.c*

| API | DLL | Kỹ thuật evasion |
|---|---|---|
| IsDebuggerPresent | KERNEL32 | PEB.BeingDebugged check |
| NtQueryInformationProcess | NTDLL | ProcessDebugPort check |
| NtQuerySystemInformation | NTDLL | System/process enumeration, VM detection |
| NtSetInformationProcess | NTDLL | Disable debug heap, DEP manipulation |

*Ảnh hưởng khi hook*: Malware bỏ qua anti-debug check → **vẫn thực thi payload chính**.

**`mask_persistence`** — Service-based persistence  
*Source: hook_services.c*

| API | DLL | Mục đích |
|---|---|---|
| CreateServiceW/A | ADVAPI32 | Tạo service để tự khởi động cùng Windows |
| StartServiceW/A | ADVAPI32 | Khởi động service |
| OpenServiceW/A | ADVAPI32 | Mở service để modify |

*Ảnh hưởng khi hook*: Malware không cài được persistence → **payload trong lần chạy đó vẫn hoạt động**.

**`mask_timing`** — Anti-sandbox timing  
*Source: hook_sleep.c*

| API | DLL | Kỹ thuật |
|---|---|---|
| NtDelayExecution | NTDLL | NT-level sleep (bypass sandbox timeout) |
| GetTickCount | KERNEL32 | Timing check (sandbox too fast) |
| GetTickCount64 | KERNEL32 | High-res timing check |
| NtQueryPerformanceCounter | NTDLL | High-precision timing |
| GetSystemTimeAsFileTime | KERNEL32 | Absolute time check |

*Ảnh hưởng khi hook*: Malware không sleep được → **payload vẫn thực thi, chỉ mất timing evasion**.

**`mask_fingerprint`** — System fingerprinting / Anti-VM probing  
*Source: hook_misc.c*

| API | DLL | Thông tin thu thập |
|---|---|---|
| GetSystemInfo | KERNEL32 | CPU count, memory (VM thường ít CPU/RAM) |
| GetSystemMetrics | USER32 | Screen resolution (sandbox thường nhỏ) |
| GetCursorPos | USER32 | Mouse movement (sandbox không có mouse) |
| GetComputerNameW | KERNEL32 | Hostname recon |
| GetUserNameW | ADVAPI32 | Username recon |
| GlobalMemoryStatusEx | KERNEL32 | Physical RAM check |

*Ảnh hưởng khi hook*: Malware không detect được môi trường → **payload vẫn thực thi, chỉ mất VM detection**.

**`mask_window_enum`** — Sandbox tool detection  
*Source: hook_window.c*

| API | DLL | Công cụ bị detect |
|---|---|---|
| FindWindowA/W | USER32 | Tìm cửa sổ Wireshark, Process Monitor, x64dbg |
| FindWindowExA/W | USER32 | Extended window search |
| EnumWindows | USER32 | Liệt kê tất cả cửa sổ đang mở |

*Ảnh hưởng khi hook*: Malware không phát hiện được analysis tool → **payload vẫn thực thi**.

**`mask_nt_registry`** — NT-level registry persistence  
*Source: hook_reg_native.c*

| API | DLL | Lý do suspicious |
|---|---|---|
| NtCreateKey | NTDLL | Tạo registry key ở native level |
| NtOpenKey | NTDLL | Mở key ở native level |
| NtSetValueKey | NTDLL | Ghi value ở native level |
| NtDeleteKey | NTDLL | Xóa key |
| NtDeleteValueKey | NTDLL | Xóa value |

Lý do thêm **native-level** registry (Nt*): malware dùng Nt* để bypass security hooks và monitoring tools vốn chỉ hook Win32 layer. Đây là signal mạnh hơn nhiều so với `RegSetValueExW`.

*Ảnh hưởng khi hook*: Malware không ghi được registry → **payload vẫn thực thi, chỉ mất registry persistence**.

---

## 5. Tổng Hợp Action Space

### Action Space Đầy Đủ (15 actions)

| # | Action | Kỹ thuật | Tool cần | Đổi code bytes |
|---|---|---|---|---|
| 1 | `pad_overlay` | Thêm 100KB bytes ngẫu nhiên | Không | Không |
| 2 | `append_benign_data_overlay` | Nối section từ benign file | Không | Không |
| 3 | `append_benign_binary_overlay` | Nối toàn bộ benign binary | Không | Không |
| 4 | `add_strings_to_overlay` | Nối benign strings | Không | Không |
| 5 | `add_bytes_to_section_cave` | Điền bytes vào null cave | Không | Không |
| 6 | `add_section_strings` | Tạo section chứa benign strings | Không | Không |
| 7 | `add_section_benign_data` | Tạo section chứa benign data | Không | Không |
| 8 | `rename_section` | Đổi tên section thành tên phổ biến | Không | Không |
| 9 | `add_imports` | Thêm 1 API từ small_dll_imports.json | Không | Không |
| 10 | `modify_optional_header` | Đổi linker/OS version | Không | Không |
| 11 | `modify_timestamp` | Đổi timestamp PE header | Không | Không |
| 12 | `break_optional_header_checksum` | Đặt checksum = 0 | Không | Không |
| 13 | `remove_debug` | Xóa debug directory | Không | Không |
| **14** | **`add_api_group`** | **Thêm 2–5 API benign vào import table** | **Không** | **Không** |
| **15** | **`iat_patch_api`** | **Hook API suspicious → stub.dll (sequential)** | **IAT_Patcher + stub.dll** | **Có** |

### So sánh 2 API actions

```
add_api_group  → THÊM API benign  → pha loãng malware signal (additive)
iat_patch_api  → HOOK API suspicious → thay thế malware signal bằng stub (surgical)
```

---

## 6. Thiết Kế STUB_REPLACEMENT_POOL

72 tên benign-sounding chia thành các nhóm ngữ nghĩa để stub.dll trông như một utility library:

| Nhóm ngữ nghĩa | Ví dụ tên |
|---|---|
| Memory management | `AllocateMemoryBlock`, `ReleaseMemoryBlock`, `CompactMemoryPool` |
| Context/lifecycle | `InitAppContext`, `FinalizeContext`, `OpenContext` |
| Data I/O | `ReadDataBuffer`, `WriteDataBuffer`, `FlushDataBuffer` |
| Network | `NetworkInitialize`, `NetworkSendData`, `ResolveHostEndpoint` |
| Crypto/hash | `CryptoInitProvider`, `CryptoHashBuffer`, `EncodeDataBlock` |
| Thread | `ThreadInitialize`, `SuspendWorkerThread`, `TerminateWorkerThread` |
| Registry/config | `RegistryReadValue`, `LoadConfigSection`, `SyncConfigData` |
| System query | `QuerySystemInfo`, `QueryHardwareProfile`, `QueryDeviceStatus` |
| Transaction | `BeginWorkTransaction`, `EndWorkTransaction`, `RollbackWorkUnit` |

**Thiết kế đặc biệt**: Tất cả tên đã được verify không trùng với bất kỳ Windows API export nào để tránh compiler conflict (phát hiện qua thực nghiệm: `InitializeContext` trùng với `winbase.h` → đổi thành `InitAppContext`).

---

## 7. Tác Động Với Static Detector

### Feature space bị ảnh hưởng

| Feature type | Action 14 (`add_api_group`) | Action 15 (`iat_patch_api`) |
|---|---|---|
| DLL name presence | ✅ Thêm DLL mới | ✅ Thêm stub.dll |
| API name presence | ✅ Thêm API benign | ✅ Thay tên API suspicious |
| Import count | ✅ Tăng | = (swap 1-1 per hook) |
| Byte n-gram | ❌ | ✅ (IAT bytes thay đổi) |
| String features | ❌ | ✅ (API name string đổi) |

### Tại sao cần 2 API actions?

- **Action 14** là additive — pha loãng signal, không xóa suspicious API
- **Action 15** là surgical — thay thế chính xác từng API, binary vẫn valid (code bytes đổi)

Agent RL học cách phối hợp 2 actions này (cùng 13 actions gốc) để tối đa hóa evasion rate.

---

## 8. Dependency và Deployment

| Component | Trạng thái | Ghi chú |
|---|---|---|
| `modifier.py` | ✅ Complete | 15 actions |
| `api_groups.py` | ✅ Complete | 10 categories, 72 pool entries |
| `stub.c` | ✅ Complete | 72 exports, no Windows API name conflicts |
| `stub.dll` (64-bit) | ✅ Built | `malware_rl/envs/controls/stub.dll` |
| `stub.dll` (32-bit) | ⬜ Cần build | `i686-w64-mingw32-gcc -shared -o stub32.dll stub.c` |
| `IAT_Patcher_CLI.exe` | ⬜ Cần build | Từ `D:\model\GAMErl\IAT\IAT_patcher\` |

**Fallback**: Nếu `IAT_PATCHER_CLI` không tìm thấy → action 15 tự động no-op. Training vẫn chạy đủ 15 actions (action 15 đơn giản là không có tác dụng).

---

## 9. Hạn Chế và Hướng Mở Rộng

### Hạn chế hiện tại

1. **Dynamic API resolution**: Malware dùng `GetProcAddress` để load API dynamically sẽ không có entry trong import table → action 15 là no-op với những mẫu này. Ước tính ~40–60% malware modern dùng kỹ thuật này.

2. **Action 15 stub là no-op**: Với các API thuộc `mask_injection`, `mask_network`, `normalize_crypto` — malware sau khi patch sẽ không thực thi được payload. Điều này acceptable cho mục tiêu static evasion nhưng cần lưu ý nếu dự án mở rộng sang dynamic evasion.

3. **Architecture**: `stub.dll` hiện chỉ có bản 64-bit. Malware x86 (32-bit) cần `stub32.dll`.

4. **Hiệu năng**: `iat_patch_api` dùng sequential `--hook` thay vì `--batch` — chậm hơn khi có nhiều API target. Trade-off: nếu một hook lỗi, các hook còn lại vẫn chạy.

### Hướng mở rộng

1. **Forwarding stub**: Viết lại `stub.c` để forward call về API thật (dùng `GetProcAddress` runtime). Khi đó action 15 vừa bypass static detector vừa giữ functional payload.

2. **Batch mode tùy chọn**: Cho phép chọn `--batch` cho tốc độ hoặc `--hook` tuần tự cho resilience tùy thuộc vào môi trường training.

3. **Delay load import**: Thêm action chuyển static import thành delay-load import — API vẫn được gọi nhưng không xuất hiện trong standard import table section.

4. **Export table manipulation**: Thêm fake export entries vào PE để làm nó trông giống legitimate DLL/utility.
