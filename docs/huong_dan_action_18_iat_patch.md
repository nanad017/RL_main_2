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

## Bạn Cần Chuẩn Bị 2 Thứ

---

## Thứ 1: IAT_Patcher_CLI.exe

### Nguồn
Source code đã có tại: `D:\model\GAMErl\IAT\IAT_patcher\`

### Build trên Windows (Qt)

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

Một DLL Windows export các hàm wrapper. Mỗi hàm chỉ là vỏ bọc — IAT_Patcher sẽ tự inject code forward call vào trong đó khi patch.

### Tên hàm cần export

Phải khớp với `STUB_REPLACEMENT_POOL` trong `api_groups.py`:

```
GetSystemParameters    QuerySystemInfo       GetPlatformInfo
AllocateMemoryBlock    ReleaseMemoryBlock    CreateSharedRegion
InitializeContext      FinalizeContext       OpenContext
ReadDataBuffer         WriteDataBuffer       FlushDataBuffer
NetworkInitialize      NetworkFinalize       NetworkSendData
CryptoInitProvider     CryptoHashBuffer      CryptoFinalizeHash
ThreadInitialize       ThreadFinalize        ThreadExecute
HandleAllocate         HandleRelease         HandleQuery
RegistryReadValue      RegistryWriteValue    RegistryDeleteKey
```

Tổng: 27 tên hàm.

### Source code stub.c

```c
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID p) {
    return TRUE;
}

// Mỗi hàm return 0/NULL — IAT_Patcher tự inject forward code khi patch
__declspec(dllexport) LPVOID GetSystemParameters(void)  { return NULL; }
__declspec(dllexport) LPVOID QuerySystemInfo(void)       { return NULL; }
__declspec(dllexport) LPVOID GetPlatformInfo(void)       { return NULL; }
__declspec(dllexport) LPVOID AllocateMemoryBlock(void)   { return NULL; }
__declspec(dllexport) BOOL   ReleaseMemoryBlock(void)    { return TRUE; }
__declspec(dllexport) HANDLE CreateSharedRegion(void)    { return NULL; }
__declspec(dllexport) LPVOID InitializeContext(void)     { return NULL; }
__declspec(dllexport) void   FinalizeContext(void)       { }
__declspec(dllexport) HANDLE OpenContext(void)           { return NULL; }
__declspec(dllexport) BOOL   ReadDataBuffer(void)        { return FALSE; }
__declspec(dllexport) BOOL   WriteDataBuffer(void)       { return FALSE; }
__declspec(dllexport) void   FlushDataBuffer(void)       { }
__declspec(dllexport) int    NetworkInitialize(void)     { return 0; }
__declspec(dllexport) void   NetworkFinalize(void)       { }
__declspec(dllexport) int    NetworkSendData(void)       { return 0; }
__declspec(dllexport) BOOL   CryptoInitProvider(void)   { return TRUE; }
__declspec(dllexport) BOOL   CryptoHashBuffer(void)     { return TRUE; }
__declspec(dllexport) BOOL   CryptoFinalizeHash(void)   { return TRUE; }
__declspec(dllexport) HANDLE ThreadInitialize(void)     { return NULL; }
__declspec(dllexport) void   ThreadFinalize(void)       { }
__declspec(dllexport) DWORD  ThreadExecute(void)        { return 0; }
__declspec(dllexport) HANDLE HandleAllocate(void)       { return NULL; }
__declspec(dllexport) BOOL   HandleRelease(void)        { return TRUE; }
__declspec(dllexport) DWORD  HandleQuery(void)          { return 0; }
__declspec(dllexport) BOOL   RegistryReadValue(void)    { return FALSE; }
__declspec(dllexport) BOOL   RegistryWriteValue(void)   { return FALSE; }
__declspec(dllexport) BOOL   RegistryDeleteKey(void)    { return FALSE; }
```

### Compile stub.dll trên Linux (cross-compile cho Windows)

```bash
# Cài MinGW cross-compiler
apt install gcc-mingw-w64

# Build 64-bit (cho malware x64)
x86_64-w64-mingw32-gcc -shared -o stub.dll stub.c \
    -Wl,--out-implib,libstub.a \
    -lkernel32

# Build 32-bit (cho malware x86)
i686-w64-mingw32-gcc -shared -o stub32.dll stub.c \
    -Wl,--out-implib,libstub32.a \
    -lkernel32
```

### Compile stub.dll trên Windows (MinGW)

```bash
gcc -shared -o stub.dll stub.c -Wl,--out-implib,libstub.a -lkernel32
```

### Đặt stub.dll ở đâu

`stub.dll` phải nằm **cùng thư mục với file malware** khi IAT_Patcher chạy, hoặc trong PATH. Modifier.py đã dùng temp file trong cùng thư mục nên sẽ tìm được.

Hoặc set đường dẫn tuyệt đối trong `api_groups.py`:

```python
# api_groups.py
STUB_DLL_NAME = "stub.dll"  # đổi thành path tuyệt đối nếu cần
# STUB_DLL_NAME = "/path/to/stub.dll"
```

---

## Checklist Hoàn Chỉnh

```
□ 1. Build IAT_Patcher_CLI.exe từ D:\model\GAMErl\IAT\IAT_patcher\
□ 2. Copy IAT_Patcher_CLI.exe sang máy Linux training
□ 3. Viết stub.c (dùng source code ở trên)
□ 4. Compile stub.dll (64-bit) và stub32.dll (32-bit)
□ 5. Đặt stub.dll vào thư mục training hoặc set PATH
□ 6. Set env var: export IAT_PATCHER_CLI=/path/to/IAT_Patcher_CLI.exe
□ 7. Test: python -c "
     from malware_rl.envs.controls.modifier import modify_sample
     with open('test.exe','rb') as f: b = f.read()
     b2 = modify_sample(b, 'iat_patch_api')
     print('OK' if len(b2) != len(b) else 'no change (no matching API)')
     "
```

---

## Nếu Chưa Chuẩn Bị Được

Action 18 tự động trở thành **no-op** (trả về bytez gốc không thay đổi) khi `IAT_PATCHER_CLI` không tìm thấy. Training vẫn chạy bình thường với 17 actions còn lại.
