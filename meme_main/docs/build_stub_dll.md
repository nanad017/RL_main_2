# Build stub.dll cho Action 18 (`iat_patch_api`)

## Tổng quan

Action 18 dùng `IAT_Patcher_CLI.exe` để patch import table của PE malware — thay tên API suspicious bằng tên hàm từ `stub.dll`. File này ghi lại quá trình thiết kế và build `stub.dll`.

---

## stub.dll là gì

Một Windows DLL export các hàm **no-op** có tên benign-sounding. Khi IAT_Patcher chạy, nó:
1. Tìm API suspicious trong import table (ví dụ `VirtualAllocEx`)
2. Ghi đè entry đó thành `stub.dll.AllocateMemoryBlock`
3. Patch code bytes tại các CALL site tương ứng

Kết quả: binary vẫn structurally valid, static detector không thấy tên API nguy hiểm.

---

## Nguồn tham khảo: CAPEv2 / capemon

Để xác định API nào là "suspicious" (cần hook), ta nghiên cứu repo **capemon** — monitor DLL của sandbox CAPEv2, hook **530+ Windows APIs** để detect malware behavior.

Repo đã clone tại: `D:\model\capemon`  
Source CAPEv2: `D:\model\CAPEv2`

Capemon hook APIs chia thành 20 file chuyên biệt:
- `hook_process.c` — VirtualAlloc, WriteProcessMemory, NtCreateProcess, ...
- `hook_thread.c` — NtCreateThreadEx, CreateRemoteThread, NtQueueApcThread, ...
- `hook_network.c` — InternetOpen, HttpSendRequest, WinHttpOpen, ...
- `hook_crypto.c` — CryptEncrypt, CryptProtectData, CryptAcquireContext, ...
- `hook_misc.c` — IsDebuggerPresent, NtQueryInformationProcess, ...
- `hook_services.c` — CreateService, StartService, ...
- *(và 14 file khác)*

→ Đây là ground truth về API nào bị sandbox monitor → cũng là API mà static detector flag.

---

## IAT_HOOK_TARGETS (api_groups.py)

6 categories, tổng 51 APIs. Được mở rộng dựa trên capemon:

| Category | Số API | DLLs | Ý nghĩa |
|---|---|---|---|
| `mask_injection` | 11 | KERNEL32, NTDLL | Process injection: VirtualAllocEx, NtQueueApcThread, ... |
| `mask_network` | 12 | WININET, URLMON, WINHTTP | C2 comm: InternetOpen, WinHttpSendRequest, ... |
| `mask_suspicious_kernel` | 10 | NTDLL | Kernel ops: NtOpenProcess, NtDuplicateObject, ... |
| `normalize_crypto` | 8 | ADVAPI32 | Ransomware: CryptEncrypt, CryptProtectData, ... |
| `mask_evasion` | 4 | KERNEL32, NTDLL | Anti-debug/VM: IsDebuggerPresent, NtQuerySystemInformation, ... |
| `mask_persistence` | 6 | ADVAPI32 | Services: CreateServiceW, StartServiceW, ... |

Thêm từ capemon (so với version cũ):
- `mask_injection`: +NtProtectVirtualMemory, VirtualProtectEx, NtQueueApcThread
- `mask_network`: +WinHttpOpen, WinHttpConnect, WinHttpOpenRequest, WinHttpSendRequest
- `mask_suspicious_kernel`: +NtDuplicateObject, NtCreateUserProcess
- `normalize_crypto`: +CryptProtectData, CryptUnprotectData
- `mask_evasion`: **mới hoàn toàn** — nguồn `hook_misc.c`
- `mask_persistence`: **mới hoàn toàn** — nguồn `hook_services.c`

---

## STUB_REPLACEMENT_POOL (api_groups.py)

42 tên benign-sounding dùng làm tên thay thế khi patch. Phải khớp với exports của `stub.dll`.

```python
STUB_REPLACEMENT_POOL = [
    "GetSystemParameters", "QuerySystemInfo", "GetPlatformInfo",
    "AllocateMemoryBlock", "ReleaseMemoryBlock", "CreateSharedRegion",
    "InitAppContext", "FinalizeContext", "OpenContext",
    "ReadDataBuffer", "WriteDataBuffer", "FlushDataBuffer",
    "NetworkInitialize", "NetworkFinalize", "NetworkSendData",
    "CryptoInitProvider", "CryptoHashBuffer", "CryptoFinalizeHash",
    "ThreadInitialize", "ThreadFinalize", "ThreadExecute",
    "HandleAllocate", "HandleRelease", "HandleQuery",
    "RegistryReadValue", "RegistryWriteValue", "RegistryDeleteKey",
    "ValidateInputBuffer", "ProcessEventQueue", "SyncConfigData",
    "UpdateDisplayState", "RefreshCacheEntry", "CompactMemoryPool",
    "EnumerateResources", "ParseProtocolData", "SerializePayload",
    "NotifyStateChange", "DispatchCallback", "GetModuleConfig",
    "SetApplicationMode", "QueryDeviceStatus", "ReleaseSharedLock",
]
```

> **Lưu ý**: `InitializeContext` bị đổi thành `InitAppContext` vì `InitializeContext` là tên Windows API thật (trong `winbase.h`), gây conflict khi compile.

---

## Source code stub.c

File: `malware_rl/envs/controls/stub.c`

Mỗi export là một no-op wrapper — IAT_Patcher sẽ inject forward code khi patch.

```c
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID p) {
    (void)h; (void)reason; (void)p;
    return TRUE;
}

__declspec(dllexport) LPVOID GetSystemParameters(void)  { return NULL; }
__declspec(dllexport) LPVOID QuerySystemInfo(void)      { return NULL; }
// ... (42 exports total, xem file gốc)
```

---

## Build stub.dll

### Trên Windows (MSYS2 ucrt64 — đã build sẵn)

```bash
cd malware_rl/envs/controls
C:\msys64\ucrt64\bin\gcc.exe -shared -o stub.dll stub.c "-Wl,--out-implib,libstub.a"
```

Output: `stub.dll` (64-bit, ~98KB), 42 exports verified.

### Trên Linux (cross-compile, dùng khi training)

```bash
# 64-bit (cho malware x64 — dùng cái này trước)
x86_64-w64-mingw32-gcc -shared -o stub.dll stub.c -Wl,--out-implib,libstub.a

# 32-bit (cho malware x86)
i686-w64-mingw32-gcc -shared -o stub32.dll stub.c -Wl,--out-implib,libstub32.a

# Cài compiler nếu chưa có
apt install gcc-mingw-w64
```

---

## Verify exports

```bash
# Windows (MSYS2)
C:\msys64\ucrt64\bin\objdump.exe -p stub.dll | grep -A999 "Export Name"

# Linux
objdump -p stub.dll | grep -A999 "Export Name"
```

Phải thấy đúng 42 tên khớp với STUB_REPLACEMENT_POOL.

---

## Deploy trên máy Linux training

```
project/
├── IAT_Patcher_CLI.exe   ← build từ D:\model\GAMErl\IAT\IAT_patcher\
├── stub.dll              ← copy từ malware_rl/envs/controls/stub.dll
└── malware_rl/...
```

```bash
export IAT_PATCHER_CLI=/path/to/IAT_Patcher_CLI.exe

# Nếu chạy wine trên Linux:
export IAT_PATCHER_CLI="wine /path/to/IAT_Patcher_CLI.exe"
```

`stub.dll` phải nằm trong cùng thư mục với file malware khi IAT_Patcher chạy, hoặc trong PATH.

---

## Test nhanh

```python
from malware_rl.envs.controls.modifier import modify_sample

with open("test_malware.exe", "rb") as f:
    b = f.read()

b2 = modify_sample(b, "iat_patch_api")
print("Changed" if len(b2) != len(b) else "No match (no suspicious API in this sample)")
```

Nếu `no-op` (không thay đổi) dù IAT_Patcher có sẵn → malware sample không import statically bất kỳ API nào trong 6 categories. Bình thường — malware hay dùng dynamic resolution.

---

## Checklist hoàn chỉnh

```
☑ api_groups.py — IAT_HOOK_TARGETS mở rộng lên 6 categories / 51 APIs
☑ api_groups.py — STUB_REPLACEMENT_POOL mở rộng lên 42 tên
☑ stub.c        — source tại malware_rl/envs/controls/stub.c
☑ stub.dll      — compiled 64-bit tại malware_rl/envs/controls/stub.dll
□ IAT_Patcher_CLI.exe — build từ D:\model\GAMErl\IAT\IAT_patcher\
□ Deploy lên máy Linux training
□ Set env var IAT_PATCHER_CLI
□ (Optional) Build stub32.dll 32-bit trên Linux
```
