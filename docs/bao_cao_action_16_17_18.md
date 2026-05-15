# Báo Cáo Kỹ Thuật: Action 16, 17, 18 — Import Table Perturbation

**Dự án:** MEME-RL — Problem-space RL adversarial evasion  
**Phạm vi:** 3 actions mới thêm vào action space (action 16–18)  
**Ngày hoàn thành:** 2026-05-16

---

## 1. Bối Cảnh và Động Lực Nghiên Cứu

MEME-RL sử dụng Reinforcement Learning để biến đổi PE malware nhằm đánh lừa **static malware detector**. Static detector (EMBER, SOREL, MalConv, custom LGB) phân tích file PE mà **không thực thi** — chúng trích xuất đặc trưng từ cấu trúc file bao gồm:

- Import table: danh sách DLL và function name malware import
- Section names, entropy, size
- Header fields, timestamp, checksum
- Byte n-gram, string features

15 actions gốc tập trung vào overlay, section, header, và packing. **Import table** là một trong những signal mạnh nhất với static detector nhưng chưa được khai thác đúng mức — đây là lý do thêm 3 actions mới.

---

## 2. Action 16: `add_api_group`

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

## 3. Action 17: `iat_hook_suspicious`

### Cơ chế

Xóa toàn bộ DLL chứa API suspicious khỏi import table bằng LIEF. Không cần tool ngoài.

```
Trước:  Import table: ntdll.dll     → [NtAllocateVirtualMemory, NtCreateSection, ...]
                      kernel32.dll  → [VirtualAllocEx, WriteProcessMemory, ...]
Sau:    Import table: (ntdll.dll bị xóa)
                      (kernel32.dll bị xóa nếu cùng category)
```

### Mục đích

**Hard removal** — xóa hoàn toàn các DLL chứa API nguy hiểm. Static detector không còn thấy import pattern đặc trưng của malware.

**Đánh đổi**: Binary bị broken (không thể chạy) nhưng đây là hành vi có chủ ý — mục tiêu là static evasion, không phải functional evasion.

### Tại sao không xóa từng API?

LIEF không hỗ trợ xóa từng entry trong import table một cách ổn định — chỉ `remove_library()` là reliable. Action 18 giải quyết vấn đề này bằng IAT patching.

---

## 4. Action 18: `iat_patch_api`

### Cơ chế

Dùng `IAT_Patcher_CLI.exe` để:
1. Tìm API suspicious trong code bytes (CALL/JMP qua IAT)
2. Thay đổi import table entry: `kernel32.dll!VirtualAllocEx` → `stub.dll!AllocateMemoryBlock`
3. Patch code bytes tại tất cả call site tương ứng

```
Trước (import table):  kernel32.dll → VirtualAllocEx
Trước (code bytes):    FF 15 [IAT_VirtualAllocEx]

Sau (import table):    stub.dll     → AllocateMemoryBlock
Sau (code bytes):      FF 15 [IAT_AllocateMemoryBlock]   ← code bytes thay đổi
```

### Sự khác biệt căn bản so với Action 17

| | Action 17 | Action 18 |
|---|---|---|
| Công cụ | LIEF only | IAT_Patcher CLI + stub.dll |
| Đổi code bytes | **Không** | **Có** |
| Binary sau đó | Broken | Structurally valid |
| Granularity | Cả DLL | Từng API |
| Dependency | Không có | Cần IAT_Patcher_CLI.exe |
| Fallback | N/A | Auto no-op nếu CLI vắng mặt |

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

## 5. Thiết Kế IAT_HOOK_TARGETS — Phương Pháp Luận

### Nguồn tham khảo: CAPEv2 / capemon

Để xác định API nào là **ground truth malware indicator**, chúng tôi nghiên cứu **capemon** — monitor DLL của sandbox CAPEv2 (https://github.com/kevoreilly/capemon). Capemon hook **530+ Windows API** chia thành 20 file chuyên biệt để detect malware behavior tại runtime.

**Lý luận**: API mà dynamic sandbox chọn để monitor = API có khả năng cao xuất hiện trong malware import table = API mà static detector học để flag.

Đây là cách tiếp cận có căn cứ thực nghiệm thay vì chọn API theo cảm tính.

### Nguyên tắc lọc API

Từ 530+ API của capemon, chúng tôi lọc theo 3 tiêu chí:

**1. Ảnh hưởng đến core payload không?**

| Loại | Quyết định | Lý do |
|---|---|---|
| API là cơ chế tấn công chính | ✅ Thêm vào targets | Xóa khỏi import table làm giảm malware score mạnh |
| API là side-effect (anti-VM, timing, fingerprint) | ✅ Thêm vào targets | Xóa không phá vỡ payload chính, malware vẫn functional |
| API là cơ chế duy nhất của malware type đó | ✅ Thêm vào targets | Static detector score vẫn giảm |

> **Lưu ý quan trọng**: "Ảnh hưởng đến core payload" chỉ quan trọng với action 18 (stub no-op). Với action 17 (binary broken), tất cả đều acceptable vì mục tiêu là static evasion.

**2. Strong static indicator không?**

API phải là signal mạnh trong import table. Ví dụ `NtAllocateVirtualMemory` rất suspicious; `GetTickCount` ít suspicious hơn nhưng vẫn xuất hiện trong malware fingerprinting research.

**3. Có thực sự xuất hiện trong malware import table không?**

Nhiều malware dùng dynamic API resolution (`GetProcAddress`) nên không import statically. Tuy nhiên, nhiều malware vẫn import statically — khi đó action có tác dụng; khi không import thì action là no-op (an toàn).

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

Lý do thêm **native-level** registry (Nt*) thay vì Win32 (Reg*): malware dùng Nt* để bypass security hooks và monitoring tools vốn chỉ hook Win32 layer. Đây là signal mạnh hơn nhiều so với `RegSetValueExW`.

*Ảnh hưởng khi hook*: Malware không ghi được registry → **payload vẫn thực thi, chỉ mất registry persistence**.

---

## 6. Tổng Hợp Action Space

### Action Space Đầy Đủ (18 actions)

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
| 14 | `upx_pack` | Nén UPX | upx | Có |
| 15 | `upx_unpack` | Giải nén UPX | upx | Có |
| **16** | **`add_api_group`** | **Thêm 2–5 API benign vào import table** | **Không** | **Không** |
| **17** | **`iat_hook_suspicious`** | **Xóa DLL suspicious khỏi import table** | **Không** | **Không** |
| **18** | **`iat_patch_api`** | **Thay API suspicious → stub.dll** | **IAT_Patcher + stub.dll** | **Có** |

### So sánh 3 API actions

```
add_api_group       → THÊM API benign       → pha loãng malware signal
iat_hook_suspicious → XÓA DLL suspicious    → loại bỏ malware signal (binary broken)
iat_patch_api       → THAY API suspicious   → thay thế malware signal (stub no-op)
```

---

## 7. Thiết Kế STUB_REPLACEMENT_POOL

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

## 8. Tác Động Với Static Detector

### Feature space bị ảnh hưởng

| Feature type | Action 16 | Action 17 | Action 18 |
|---|---|---|---|
| DLL name presence | ✅ Thêm DLL mới | ✅ Xóa DLL suspicious | ✅ Thêm stub.dll |
| API name presence | ✅ Thêm API benign | ✅ Xóa API suspicious | ✅ Thay tên API |
| Import count | ✅ Tăng | ✅ Giảm | = (swap 1-1) |
| Byte n-gram | ❌ | ❌ | ✅ (IAT bytes thay đổi) |
| String features | ❌ | ❌ | ✅ (API name string đổi) |

### Tại sao cần cả 3 actions?

- **Action 16** là additive — pha loãng signal, không xóa
- **Action 17** là destructive — xóa cứng, không quan tâm functional
- **Action 18** là surgical — thay thế chính xác từng API, binary vẫn valid

Agent RL học cách phối hợp 3 actions này (cùng 15 actions gốc) để tối đa hóa evasion rate.

---

## 9. Dependency và Deployment

| Component | Trạng thái | Ghi chú |
|---|---|---|
| `modifier.py` | ✅ Complete | 18 actions |
| `api_groups.py` | ✅ Complete | 10 categories, 72 pool entries |
| `stub.c` | ✅ Complete | 72 exports, no Windows API name conflicts |
| `stub.dll` (64-bit) | ✅ Built | `malware_rl/envs/controls/stub.dll` |
| `stub.dll` (32-bit) | ⬜ Cần build | `i686-w64-mingw32-gcc -shared -o stub32.dll stub.c` |
| `IAT_Patcher_CLI.exe` | ⬜ Cần build | Từ `D:\model\GAMErl\IAT\IAT_patcher\` |

**Fallback**: Nếu `IAT_PATCHER_CLI` không tìm thấy → action 18 tự động no-op. Training vẫn chạy đủ 18 actions (action 18 đơn giản là không có tác dụng).

---

## 10. Hạn Chế và Hướng Mở Rộng

### Hạn chế hiện tại

1. **Dynamic API resolution**: Malware dùng `GetProcAddress` để load API dynamically sẽ không có entry trong import table → action 17/18 là no-op với những mẫu này. Ước tính ~40–60% malware modern dùng kỹ thuật này.

2. **Action 18 stub là no-op**: Với các API thuộc `mask_injection`, `mask_network`, `normalize_crypto` — malware sau khi patch sẽ không thực thi được payload. Điều này acceptable cho mục tiêu static evasion nhưng cần lưu ý nếu dự án mở rộng sang dynamic evasion.

3. **Architecture**: `stub.dll` hiện chỉ có bản 64-bit. Malware x86 (32-bit) cần `stub32.dll`.

### Hướng mở rộng

1. **Forwarding stub**: Viết lại `stub.c` để forward call về API thật (dùng `GetProcAddress` runtime). Khi đó action 18 vừa bypass static detector vừa giữ functional payload.

2. **Delay load import**: Thêm action chuyển static import thành delay-load import — API vẫn được gọi nhưng không xuất hiện trong standard import table section.

3. **Export table manipulation**: Thêm fake export entries vào PE để làm nó trông giống legitimate DLL/utility.
