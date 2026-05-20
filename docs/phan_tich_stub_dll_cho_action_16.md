# Phân Tích: Có Thể Dùng `stub.dll` Cho Action 16 (`inject_benign_api_call`) Không?

**Câu hỏi:** stub.dll có function nào no-op và an toàn để dùng cho action `inject_benign_api_call` (Tier 2) không?

**Trả lời ngắn:** Tài liệu `huong_dan_action_18_iat_patch.md` mô tả stub.dll là "no-op", nhưng đọc source `stub.c` thì **không có function nào thực sự no-op**. Tất cả 72 export đều là **forwarding stub** — gọi `LoadLibraryA + GetProcAddress` để resolve API thật rồi forward args và return value. Một **subset** trong đó có thể tái sử dụng cho action 16, nhưng kèm trade-off đáng kể.

---

## 1. stub.dll Thực Sự Làm Gì

Đọc `malware_rl/envs/controls/stub.c`, mỗi export được tạo bằng macro `FORWARD(stub_name, dll_str, api_str)`:

```c
__declspec(dllexport) ULONG_PTR stub_name(
    ULONG_PTR a1,  ULONG_PTR a2,  ..., ULONG_PTR a12)
{
    static GenericFunc _real = NULL;
    if (!_real) {
        HMODULE _h = LoadLibraryA(dll_str);
        if (_h) _real = (GenericFunc)GetProcAddress(_h, api_str);
    }
    if (!_real) return 0;
    return _real(a1, a2, ..., a12);
}
```

→ Function gọi vào sẽ **chạy API thật**. Không phải no-op.

Lý do thiết kế này: `iat_patch_api` (action 15) cần PE giữ functionality. Khi rename `VirtualAllocEx` → `AllocateMemoryBlock`, runtime vẫn phải allocate được memory thật. Nếu là no-op, malware crash.

> Tài liệu `huong_dan_action_18_iat_patch.md` dùng từ "no-op" theo nghĩa "trông như no-op từ góc nhìn static analysis" (tên export ABC không gợi ý hành vi nào), không phải nghĩa "không làm gì khi runtime call".

---

## 2. Filter Theo Tiêu Chí "An Toàn Cho Action 16"

Action 16 cần API thoả 4 điều kiện:

1. **Không crash với args zero/buf:** Pass `[]` (no args), `['buf']` (con trỏ tới 256 byte zero), hoặc `['zero']` (integer 0).
2. **Không có side-effect độc hại:** Không spawn process, không sửa registry, không ghi disk, không thay đổi memory bên ngoài.
3. **Không cần state hợp lệ trước đó:** Không cần handle hợp lệ, không cần struct được khởi tạo.
4. **Trả về sạch sẽ:** Không leak handle/memory, không để loader/sandbox vào trạng thái lạ.

Bảng đánh giá từng forward target trong stub.c:

| Stub export | API thật | Args cần thiết | Đánh giá | Kết luận |
|-------------|----------|----------------|----------|----------|
| **mask_injection (KERNEL32 + NTDLL)** | | | | |
| `AllocateMemoryBlock` | `VirtualAllocEx(handle, ...)` | Cần handle hợp lệ | Crash/fail nếu pass 0 | ❌ Không an toàn |
| `ReleaseMemoryBlock` | `VirtualAlloc(NULL, size, ...)` | Cần size hợp lệ | Có thể alloc memory thật → leak | ❌ Side-effect |
| `CreateSharedRegion` | `WriteProcessMemory(handle, ...)` | Cần handle | Fail an toàn (return 0) nhưng vô nghĩa | ⚠️ Vô hại nhưng dùng được |
| `ReadDataBuffer` | `ReadProcessMemory(handle, ...)` | Cần handle | Fail an toàn | ⚠️ Vô hại |
| `ThreadInitialize` | `CreateRemoteThread(handle, ...)` | Cần handle | Fail an toàn | ⚠️ Vô hại |
| `ThreadExecute` | `CreateRemoteThreadEx(handle, ...)` | Cần handle | Fail an toàn | ⚠️ Vô hại |
| `HandleAllocate` | `NtCreateThreadEx(...)` | NT API, kén args | Có thể crash | ❌ Risky |
| `HandleRelease` | `RtlCreateUserThread(...)` | Kén args | Risky | ❌ Risky |
| `HandleQuery` | `NtProtectVirtualMemory(...)` | Kén args | Risky | ❌ Risky |
| `CompactMemoryPool` | `VirtualProtectEx(handle, ...)` | Cần handle | Fail an toàn | ⚠️ Vô hại |
| `ValidateInputBuffer` | `NtQueueApcThread(...)` | Cần handle | Fail an toàn | ⚠️ Vô hại |
| **mask_network** | | | | |
| `NetworkInitialize` | `InternetOpenW(NULL, 0, NULL, NULL, 0)` | OK với NULL | Có thể tạo internet handle → **leak handle** | ❌ Side-effect |
| `NetworkFinalize` | `InternetOpenA(NULL, ...)` | OK | Tạo handle → leak | ❌ Side-effect |
| `NetworkSendData` | `InternetConnectW(handle, ...)` | Cần handle | Fail | ⚠️ Vô hại |
| `ParseProtocolData` | `HttpOpenRequestW(handle, ...)` | Cần handle | Fail | ⚠️ Vô hại |
| ... | ... | ... | ... | (tương tự) |
| `OpenDeviceStream` | `WinHttpOpen(NULL, ...)` | OK | Tạo session → leak | ❌ Side-effect |
| **mask_suspicious_kernel** | | | | |
| `GetSystemParameters` | `NtOpenProcess(...)` | Có thể fail an toàn | Tuy nhiên gọi NT API là tín hiệu xấu | ⚠️ Static-evasion ngược |
| ... | (tương tự, fail an toàn nhưng không nên dùng) | | | |
| **normalize_crypto** | | | | |
| `CryptoInitProvider` | `CryptEncrypt(NULL, ...)` | Cần handle | Fail | ⚠️ Vô hại |
| `CryptoHashBuffer` | `CryptDecrypt(NULL, ...)` | Cần handle | Fail | ⚠️ Vô hại |
| ... | | | | |
| **mask_evasion** ⭐ | | | | |
| `CheckModuleVersion` | `IsDebuggerPresent()` | **Không cần args** | Trả `BOOL`, vô hại | ✅ **An toàn** |
| `InitPlatformRuntime` | `NtQueryInformationProcess(...)` | Cần handle | Fail | ⚠️ Vô hại |
| `QueryHardwareProfile` | `NtQuerySystemInformation(...)` | Cần buffer hợp lệ | Có thể crash | ❌ Risky |
| `GetDisplaySettings` | `NtSetInformationProcess(...)` | Cần handle | Fail | ⚠️ Vô hại |
| **mask_persistence** | | | | |
| `SaveApplicationData` | `CreateServiceW(handle, ...)` | Cần SCM handle | Fail | ⚠️ Vô hại |
| ... | | | | |
| **mask_timing** ⭐ | | | | |
| `WaitForResourceAvailable` | `NtDelayExecution(FALSE, ptr)` | Cần `LARGE_INTEGER*` | Crash với NULL | ❌ Cần buf |
| `BeginWorkTransaction` | `GetTickCount()` | **Không cần args** | Trả DWORD | ✅ **An toàn** |
| `EndWorkTransaction` | `GetTickCount64()` | **Không cần args** | Trả ULONGLONG | ✅ **An toàn** |
| `RollbackWorkUnit` | `NtQueryPerformanceCounter(ptr, ptr)` | Cần buf | OK với buf | ✅ **An toàn (buf)** |
| `PurgeCacheFile` | `GetSystemTimeAsFileTime(ptr)` | Cần `FILETIME*` (8B) | OK với buf | ✅ **An toàn (buf)** |
| **mask_fingerprint** ⭐ | | | | |
| `GetModuleConfig` | `GetSystemInfo(ptr)` | Cần `SYSTEM_INFO*` (~36B) | OK với buf 256B | ✅ **An toàn (buf)** |
| `QueryDeviceStatus` | `GetSystemMetrics(int)` | int 0 → SM_CXSCREEN | Trả int | ✅ **An toàn (zero)** |
| `UpdateDisplayState` | `GetCursorPos(POINT*)` | Cần `POINT*` (8B) | OK với buf | ✅ **An toàn (buf)** |
| `SetApplicationMode` | `GetComputerNameW(LPWSTR, LPDWORD)` | Cần `pcbBuffer` set sẵn → crash với NULL | ❌ Risky |
| `RefreshCacheEntry` | `GetUserNameW(LPWSTR, LPDWORD)` | Tương tự | ❌ Risky |
| `EnumerateResources` | `GlobalMemoryStatusEx(MEMORYSTATUSEX*)` | Cần `dwLength = sizeof(MEMORYSTATUSEX)` set trước | ❌ Crash nếu không init |
| **mask_window_enum** ⭐ | | | | |
| `NotifyStateChange` | `FindWindowA(NULL, NULL)` | OK với NULL | Trả NULL | ✅ **An toàn (zero,zero)** |
| `DispatchCallback` | `FindWindowW(NULL, NULL)` | OK với NULL | Trả NULL | ✅ **An toàn (zero,zero)** |
| `UpdateRenderState` | `FindWindowExA(NULL, NULL, NULL, NULL)` | OK | ✅ **An toàn (zero×4)** |
| `ReleaseSharedLock` | `FindWindowExW(NULL, NULL, NULL, NULL)` | OK | ✅ **An toàn (zero×4)** |
| `RegisterEventCallback` | `EnumWindows(NULL, 0)` | NULL callback → có thể crash hoặc fail | ❌ Risky |
| **mask_nt_registry** | | | | |
| ... | NT registry — kén args, NT level — không an toàn | | | ❌ Tránh |

### Subset có thể dùng

**~9 stub export an toàn cho action 16:**

| Stub | API thật | arg signature đề xuất |
|------|----------|------------------------|
| `CheckModuleVersion` | `IsDebuggerPresent` | `[]` |
| `BeginWorkTransaction` | `GetTickCount` | `[]` |
| `EndWorkTransaction` | `GetTickCount64` | `[]` |
| `RollbackWorkUnit` | `NtQueryPerformanceCounter` | `['buf', 'buf']` |
| `PurgeCacheFile` | `GetSystemTimeAsFileTime` | `['buf']` |
| `GetModuleConfig` | `GetSystemInfo` | `['buf']` |
| `QueryDeviceStatus` | `GetSystemMetrics` | `['zero']` |
| `UpdateDisplayState` | `GetCursorPos` | `['buf']` |
| `NotifyStateChange` | `FindWindowA` | `['zero', 'zero']` |
| `DispatchCallback` | `FindWindowW` | `['zero', 'zero']` |
| `UpdateRenderState` | `FindWindowExA` | `['zero', 'zero', 'zero', 'zero']` |
| `ReleaseSharedLock` | `FindWindowExW` | `['zero', 'zero', 'zero', 'zero']` |

---

## 3. Trade-off Khi Dùng stub.dll

### Lợi ích
✅ **Tên export "trung tính":** Static feature extractor sẽ thấy `BeginWorkTransaction`, `CheckModuleVersion`,... thay vì `GetTickCount`, `IsDebuggerPresent`. Một số detector đặt trọng số cao cho `GetTickCount` (anti-sandbox indicator) hoặc `IsDebuggerPresent` (anti-debug indicator) — ẩn được tên này có thể giảm score.

### Bất lợi quan trọng

❌ **Thêm import dependency tới `stub.dll`:**
- PE sau khi modify sẽ có entry `stub.dll` trong import table.
- Sandbox/host phải có `stub.dll` ở cùng folder hoặc trong DLL search path → mỗi mẫu malware phải đi kèm stub.dll.
- Detector dùng feature "imports DLL không phải hệ thống" sẽ flag mạnh hơn cả `GetTickCount` gốc.

❌ **Tên DLL `stub.dll` cực kỳ đáng nghi:**
- Tên `stub.dll` không khớp với DLL hệ thống nào → static analyzer/AV có thể cờ ngay.
- Có thể đổi tên thành `version2.dll`, `helper.dll`,... nhưng vẫn không phải DLL có sẵn trong Windows.

❌ **Phải copy stub.dll khi deploy mỗi mẫu modified:**
- Phá vỡ giả định "single-file PE" của các pipeline detection/sandbox.
- Cần infrastructure để embed/distribute stub.dll cùng PE.

❌ **Phá vỡ design hiện tại:**
- `inject_benign_api_call` đang dùng KERNEL32/USER32 trực tiếp → import table chỉ có DLL hệ thống → nhìn 100% benign về structure.
- Chuyển sang stub.dll → trade một static feature lấy một static feature đáng nghi hơn.

---

## 4. Khuyến Nghị

### Khuyến nghị chính: **KHÔNG nên dùng stub.dll cho action 16**

Lý do:
1. Action 16 hiện tại đã rất tốt: gọi `GetSystemTime`, `GetTickCount`,... trực tiếp từ KERNEL32 → import table chỉ thấy DLL hệ thống → benign 100%.
2. Thêm stub.dll vào import table tạo ra red flag mạnh hơn nhiều so với việc chỉ thấy `GetTickCount`.
3. Mất tính tự-chứa (self-contained) của PE đã modify.

### Trường hợp hiếm hoi cần dùng

Nếu detector đặc biệt nhạy với một vài API cụ thể và **bạn chấp nhận deploy stub.dll cùng PE**, có thể:

```python
# Mở rộng SAFE_INJECT_APIS với stub forwarders
SAFE_INJECT_APIS_VIA_STUB = [
    ("stub.dll", "CheckModuleVersion",      []),                # = IsDebuggerPresent
    ("stub.dll", "BeginWorkTransaction",    []),                # = GetTickCount
    ("stub.dll", "EndWorkTransaction",      []),                # = GetTickCount64
    ("stub.dll", "PurgeCacheFile",          ['buf']),           # = GetSystemTimeAsFileTime
    ("stub.dll", "GetModuleConfig",         ['buf']),           # = GetSystemInfo
    ("stub.dll", "QueryDeviceStatus",       ['zero']),          # = GetSystemMetrics
    ("stub.dll", "UpdateDisplayState",      ['buf']),           # = GetCursorPos
    ("stub.dll", "NotifyStateChange",       ['zero', 'zero']),  # = FindWindowA
    ("stub.dll", "DispatchCallback",        ['zero', 'zero']),  # = FindWindowW
    ("stub.dll", "UpdateRenderState",       ['zero', 'zero', 'zero', 'zero']),  # = FindWindowExA
    ("stub.dll", "ReleaseSharedLock",       ['zero', 'zero', 'zero', 'zero']),  # = FindWindowExW
    ("stub.dll", "RollbackWorkUnit",        ['buf', 'buf']),    # = NtQueryPerformanceCounter
]
```

Triển khai:
- Trong `inject_call.py`, mở rộng `_pick_apis()` để có chế độ `via_stub=True` → sample từ pool này.
- Trong `_ensure_imports`, đảm bảo `stub.dll` được copy vào output dir nếu PE modified được sandbox hóa.
- `_X86_SAFE_DLLS` cần thêm `"stub.dll"` (vì stub.dll built dùng x64 calling conv của Windows API thật → x86 stub cần build riêng từ `i686-w64-mingw32-gcc`).

### Cảnh báo bổ sung

- **stub.dll hiện tại chỉ có 64-bit:** nếu inject vào PE x86 sẽ fail load. Phải build `stub32.dll` riêng (xem `huong_dan_action_18_iat_patch.md` mục build 32-bit).
- **Lazy resolution của stub có race condition trên multi-thread x86** (x86 memory model yếu hơn x64). x64 OK theo comment trong `stub.c`.
- **stub forwarder không bảo toàn `errno`/`GetLastError`** một cách rõ ràng — chỉ trả raw return value. Đa số API safe ở trên không bị ảnh hưởng vì action 16 không đọc kết quả, nhưng cần lưu ý.

---

## 5. Tổng Kết

| Câu hỏi | Trả lời |
|---------|---------|
| stub.dll có function no-op không? | **Không.** Tất cả 72 export đều là forwarding stub gọi API thật. |
| Có function nào dùng được cho action 16? | **Có ~12 function** thoả mãn "an toàn với args zero/buf" (xem bảng subset). |
| Có nên dùng cho action 16 không? | **Không khuyến khích.** Trade-off bất lợi: ẩn được tên `GetTickCount` nhưng phơi bày import `stub.dll` đáng nghi hơn. Mất tính self-contained. |
| Khi nào nên cân nhắc? | Chỉ khi detector cụ thể đặt trọng số rất cao cho `IsDebuggerPresent`/`GetTickCount` và pipeline cho phép distribute stub.dll cùng PE. |

**Quan điểm:** Action 16 hiện tại đã optimal cho mục tiêu "thêm dynamic API surface giả benign". Việc đưa stub.dll vào sẽ phá vỡ tính chất "self-contained" và tạo ra một static signal (import unknown DLL) còn đáng nghi hơn signal mà nó định ẩn.