# Hướng Dẫn Chuẩn Bị Action 18: `iat_patch_api`

## Action Này Làm Gì

Dùng `IAT_Patcher_CLI.exe` để hook API suspicious trong PE file, thay thế bằng hàm từ `stub.dll`.

```
Trước khi patch:
  Import table: KERNEL32.DLL → VirtualAllocEx
  Code bytes:   CALL [IAT_VirtualAllocEx]

Sau khi patch:
  Import table: stub.dll → AllocateMemoryBlock
  Code bytes:   CALL [IAT_AllocateMemoryBlock]   ← code bytes thay đổi

stub.dll.AllocateMemoryBlock() chạy bên trong → forward lại VirtualAllocEx thật
```

Khác với action 17 (`iat_hook_suspicious`):
- Action 17 chỉ dùng LIEF xóa DLL khỏi import table, **không đổi code bytes**, binary bị broken
- Action 18 dùng IAT_Patcher patch cả import table lẫn code bytes, **binary vẫn chạy được**

---

## Bạn Cần Chuẩn Bị

| Thứ | Trạng thái | Ghi chú |
|---|---|---|
| `stub.dll` | **Đã có sẵn** tại `malware_rl/envs/controls/stub.dll` | 64-bit, ~100KB, 72 exports |
| `stub.c` | **Đã có sẵn** tại `malware_rl/envs/controls/stub.c` | Source để build lại nếu cần |
| `IAT_Patcher_CLI.exe` | **Chưa có** — cần build | Build từ `D:\model\GAMErl\IAT\IAT_patcher\` |

---

## Thứ 1: IAT_Patcher_CLI.exe

### Nguồn

Source code tại: `D:\model\GAMErl\IAT\IAT_patcher\`

### Build trên Windows (Qt Creator)

```bash
# Mở Qt Creator
# File → Open Project → chọn IAT_patcher.pro
# Build → Release
# Output: build/release/IAT_Patcher_CLI.exe
```

### Build bằng command line (qmake)

```bash
cd D:\model\GAMErl\IAT\IAT_patcher
qmake IAT_patcher.pro CONFIG+=release
nmake        # Windows với MSVC
# hoặc
mingw32-make # Windows với MinGW
```

### Sau khi build xong

Trên máy Linux chạy training:

```bash
# Copy file exe sang máy Linux
scp IAT_Patcher_CLI.exe user@linux-server:/path/to/tools/

# Set env var để modifier.py tìm được
export IAT_PATCHER_CLI=/path/to/tools/IAT_Patcher_CLI.exe

# Nếu chạy trên Linux cần Wine:
apt install wine
export IAT_PATCHER_CLI="wine /path/to/tools/IAT_Patcher_CLI.exe"
```

---

## Thứ 2: stub.dll

### stub.dll là gì

Một DLL Windows export 72 hàm no-op có tên benign-sounding. IAT_Patcher dùng chúng làm tên thay thế khi patch suspicious API.

**File đã có sẵn** tại `malware_rl/envs/controls/stub.dll` (64-bit, ~100KB).

### 72 tên export (STUB_REPLACEMENT_POOL trong api_groups.py)

```
GetSystemParameters    QuerySystemInfo        GetPlatformInfo
AllocateMemoryBlock    ReleaseMemoryBlock     CreateSharedRegion
InitAppContext         FinalizeContext        OpenContext
ReadDataBuffer         WriteDataBuffer        FlushDataBuffer
NetworkInitialize      NetworkFinalize        NetworkSendData
CryptoInitProvider     CryptoHashBuffer       CryptoFinalizeHash
ThreadInitialize       ThreadFinalize         ThreadExecute
HandleAllocate         HandleRelease          HandleQuery
RegistryReadValue      RegistryWriteValue     RegistryDeleteKey
ValidateInputBuffer    ProcessEventQueue      SyncConfigData
UpdateDisplayState     RefreshCacheEntry      CompactMemoryPool
EnumerateResources     ParseProtocolData      SerializePayload
NotifyStateChange      DispatchCallback       GetModuleConfig
SetApplicationMode     QueryDeviceStatus      ReleaseSharedLock
CheckModuleVersion     LoadConfigSection      InitPlatformRuntime
QueryHardwareProfile   GetDisplaySettings     UpdateRenderState
SaveApplicationData    LoadApplicationData    PurgeCacheFile
OpenDeviceStream       CloseDeviceStream      ReadDeviceState
WaitForResourceAvailable  AcquireTokenLock    ReleaseTokenLock
BeginWorkTransaction   EndWorkTransaction     RollbackWorkUnit
EnumerateNetworkPeers  ResolveHostEndpoint    CloseNetworkSession
EncodeDataBlock        DecodeDataBlock        VerifyBlockChecksum
SuspendWorkerThread    ResumeWorkerThread     TerminateWorkerThread
RegisterEventCallback  UnregisterEventCallback  PollEventSource
```

> **Lưu ý**: tên `InitAppContext` (không phải `InitializeContext`) — `InitializeContext` là Windows API thật trong `winbase.h`, gây conflict khi compile.

### Build lại stub.dll (nếu cần)

Source tại `malware_rl/envs/controls/stub.c`.

```bash
# Trên Linux (cross-compile cho Windows 64-bit)
x86_64-w64-mingw32-gcc -shared -o stub.dll stub.c -Wl,--out-implib,libstub.a

# Trên Linux (cross-compile cho Windows 32-bit)
i686-w64-mingw32-gcc -shared -o stub32.dll stub.c -Wl,--out-implib,libstub32.a

# Cài compiler nếu chưa có
apt install gcc-mingw-w64
```

```bash
# Trên Windows (MSYS2 ucrt64)
C:\msys64\ucrt64\bin\gcc.exe -shared -o stub.dll stub.c '-Wl,--out-implib,libstub.a'
```

### Verify exports

```bash
# Windows (MSYS2)
C:\msys64\ucrt64\bin\objdump.exe -p stub.dll | grep "Export Name" -A 999

# Linux
objdump -p stub.dll | grep "Export Name" -A 999
```

Phải thấy đúng 72 tên khớp với STUB_REPLACEMENT_POOL.

### Đặt stub.dll ở đâu

`stub.dll` phải nằm **cùng thư mục với file malware** khi IAT_Patcher chạy, hoặc trong PATH.

Modifier.py tạo temp file trong thư mục tạm nên cần copy stub.dll vào đó, hoặc set đường dẫn tuyệt đối trong `api_groups.py`:

```python
STUB_DLL_NAME = "stub.dll"  # đổi thành path tuyệt đối nếu cần
# STUB_DLL_NAME = "/path/to/stub.dll"
```

---

## Checklist Hoàn Chỉnh

```
☑ stub.c        — đã có tại malware_rl/envs/controls/stub.c
☑ stub.dll      — đã có tại malware_rl/envs/controls/stub.dll (64-bit, 72 exports)
□ IAT_Patcher_CLI.exe — cần build từ D:\model\GAMErl\IAT\IAT_patcher\
□ Copy IAT_Patcher_CLI.exe sang máy Linux training
□ Set env var: export IAT_PATCHER_CLI=/path/to/IAT_Patcher_CLI.exe
□ (Optional) Build stub32.dll 32-bit trên Linux cho malware x86
□ Test:
     python -c "
     from malware_rl.envs.controls.modifier import modify_sample
     with open('test.exe','rb') as f: b = f.read()
     b2 = modify_sample(b, 'iat_patch_api')
     print('OK' if len(b2) != len(b) else 'no change (no matching API)')
     "
```

---

## Nếu Chưa Có IAT_Patcher_CLI

Action 18 tự động trở thành **no-op** (trả về bytez gốc không thay đổi) khi `IAT_PATCHER_CLI` không tìm thấy. Training vẫn chạy bình thường với 17 actions còn lại.
