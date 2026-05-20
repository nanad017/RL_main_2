/*
 * stub.dll -- Forwarding stub DLL for IAT_Patcher action 15.
 *
 * Each export resolves the real Windows API via LoadLibrary + GetProcAddress
 * on first call, then forwards all arguments to the real function.
 * This keeps the PE fully functional while hiding suspicious API names
 * from the static import table.
 *
 * Export names must match STUB_FORWARD_MAP keys in api_groups.py.
 *
 * Build (MinGW, 64-bit):
 *   gcc -shared -O2 -o stub.dll stub.c -Wl,--out-implib,libstub.a
 *
 * Build (MinGW cross-compile on Linux, 64-bit):
 *   x86_64-w64-mingw32-gcc -shared -O2 -o stub.dll stub.c -Wl,--out-implib,libstub.a
 *
 * Build (MinGW cross-compile on Linux, 32-bit):
 *   i686-w64-mingw32-gcc -shared -O2 -o stub32.dll stub.c -Wl,--out-implib,libstub32.a
 *
 * Design notes (x64):
 *   - All stubs accept 12 ULONG_PTR params to cover any Windows API signature.
 *   - On x64 there is only one calling convention, so param passthrough is safe.
 *   - First 4 args are in RCX/RDX/R8/R9; extras are on the stack.
 *   - The callee only reads what it needs; extra garbage args are harmless.
 *   - Lazy resolution is thread-safe on x64 (strong memory model, benign race).
 */

#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID p) {
    (void)h; (void)reason; (void)p;
    return TRUE;
}

typedef ULONG_PTR (WINAPI *GenericFunc)(
    ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
    ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
    ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);

#define FORWARD(stub_name, dll_str, api_str)                                \
__declspec(dllexport) ULONG_PTR stub_name(                                  \
    ULONG_PTR a1,  ULONG_PTR a2,  ULONG_PTR a3,  ULONG_PTR a4,           \
    ULONG_PTR a5,  ULONG_PTR a6,  ULONG_PTR a7,  ULONG_PTR a8,           \
    ULONG_PTR a9,  ULONG_PTR a10, ULONG_PTR a11, ULONG_PTR a12)          \
{                                                                           \
    static GenericFunc _real = NULL;                                         \
    if (!_real) {                                                           \
        HMODULE _h = LoadLibraryA(dll_str);                                 \
        if (_h) _real = (GenericFunc)GetProcAddress(_h, api_str);           \
    }                                                                       \
    if (!_real) return 0;                                                    \
    return _real(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12);      \
}

/* ── mask_injection (11) ── */
FORWARD(AllocateMemoryBlock,   "KERNEL32.DLL", "VirtualAllocEx")
FORWARD(ReleaseMemoryBlock,    "KERNEL32.DLL", "VirtualAlloc")
FORWARD(CreateSharedRegion,    "KERNEL32.DLL", "WriteProcessMemory")
FORWARD(ReadDataBuffer,        "KERNEL32.DLL", "ReadProcessMemory")
FORWARD(ThreadInitialize,      "KERNEL32.DLL", "CreateRemoteThread")
FORWARD(ThreadExecute,         "KERNEL32.DLL", "CreateRemoteThreadEx")
FORWARD(HandleAllocate,        "NTDLL.DLL",    "NtCreateThreadEx")
FORWARD(HandleRelease,         "NTDLL.DLL",    "RtlCreateUserThread")
FORWARD(HandleQuery,           "NTDLL.DLL",    "NtProtectVirtualMemory")
FORWARD(CompactMemoryPool,     "KERNEL32.DLL", "VirtualProtectEx")
FORWARD(ValidateInputBuffer,   "NTDLL.DLL",    "NtQueueApcThread")

/* ── mask_network (12) ── */
FORWARD(NetworkInitialize,     "WININET.DLL",  "InternetOpenW")
FORWARD(NetworkFinalize,       "WININET.DLL",  "InternetOpenA")
FORWARD(NetworkSendData,       "WININET.DLL",  "InternetConnectW")
FORWARD(ParseProtocolData,     "WININET.DLL",  "HttpOpenRequestW")
FORWARD(SerializePayload,      "WININET.DLL",  "HttpSendRequestW")
FORWARD(EnumerateNetworkPeers, "WININET.DLL",  "InternetReadFile")
FORWARD(ResolveHostEndpoint,   "WININET.DLL",  "InternetCloseHandle")
FORWARD(CloseNetworkSession,   "URLMON.DLL",   "URLDownloadToFileW")
FORWARD(OpenDeviceStream,      "WINHTTP.DLL",  "WinHttpOpen")
FORWARD(CloseDeviceStream,     "WINHTTP.DLL",  "WinHttpConnect")
FORWARD(ReadDeviceState,       "WINHTTP.DLL",  "WinHttpOpenRequest")
FORWARD(PollEventSource,       "WINHTTP.DLL",  "WinHttpSendRequest")

/* ── mask_suspicious_kernel (10) ── */
FORWARD(GetSystemParameters,   "NTDLL.DLL",    "NtOpenProcess")
FORWARD(QuerySystemInfo,       "NTDLL.DLL",    "NtAllocateVirtualMemory")
FORWARD(GetPlatformInfo,       "NTDLL.DLL",    "NtWriteVirtualMemory")
FORWARD(InitAppContext,        "NTDLL.DLL",    "NtCreateSection")
FORWARD(OpenContext,           "NTDLL.DLL",    "NtMapViewOfSection")
FORWARD(FinalizeContext,       "NTDLL.DLL",    "NtUnmapViewOfSection")
FORWARD(WriteDataBuffer,       "NTDLL.DLL",    "NtCreateProcess")
FORWARD(FlushDataBuffer,       "NTDLL.DLL",    "NtResumeThread")
FORWARD(ProcessEventQueue,     "NTDLL.DLL",    "NtDuplicateObject")
FORWARD(SyncConfigData,        "NTDLL.DLL",    "NtCreateUserProcess")

/* ── normalize_crypto (8) ── */
FORWARD(CryptoInitProvider,    "ADVAPI32.DLL", "CryptEncrypt")
FORWARD(CryptoHashBuffer,      "ADVAPI32.DLL", "CryptDecrypt")
FORWARD(CryptoFinalizeHash,    "ADVAPI32.DLL", "CryptImportKey")
FORWARD(EncodeDataBlock,       "ADVAPI32.DLL", "CryptExportKey")
FORWARD(DecodeDataBlock,       "ADVAPI32.DLL", "CryptSetKeyParam")
FORWARD(VerifyBlockChecksum,   "ADVAPI32.DLL", "CryptGenKey")
FORWARD(AcquireTokenLock,      "ADVAPI32.DLL", "CryptProtectData")
FORWARD(ReleaseTokenLock,      "ADVAPI32.DLL", "CryptUnprotectData")

/* ── mask_evasion (4) ── */
FORWARD(CheckModuleVersion,    "KERNEL32.DLL", "IsDebuggerPresent")
FORWARD(InitPlatformRuntime,   "NTDLL.DLL",    "NtQueryInformationProcess")
FORWARD(QueryHardwareProfile,  "NTDLL.DLL",    "NtQuerySystemInformation")
FORWARD(GetDisplaySettings,    "NTDLL.DLL",    "NtSetInformationProcess")

/* ── mask_persistence (6) ── */
FORWARD(SaveApplicationData,   "ADVAPI32.DLL", "CreateServiceW")
FORWARD(LoadApplicationData,   "ADVAPI32.DLL", "CreateServiceA")
FORWARD(RegistryReadValue,     "ADVAPI32.DLL", "StartServiceW")
FORWARD(RegistryWriteValue,    "ADVAPI32.DLL", "StartServiceA")
FORWARD(RegistryDeleteKey,     "ADVAPI32.DLL", "OpenServiceW")
FORWARD(LoadConfigSection,     "ADVAPI32.DLL", "OpenServiceA")

/* ── mask_timing (5) ── */
FORWARD(WaitForResourceAvailable, "NTDLL.DLL",    "NtDelayExecution")
FORWARD(BeginWorkTransaction,     "KERNEL32.DLL", "GetTickCount")
FORWARD(EndWorkTransaction,       "KERNEL32.DLL", "GetTickCount64")
FORWARD(RollbackWorkUnit,         "NTDLL.DLL",    "NtQueryPerformanceCounter")
FORWARD(PurgeCacheFile,           "KERNEL32.DLL", "GetSystemTimeAsFileTime")

/* ── mask_fingerprint (6) ── */
FORWARD(GetModuleConfig,       "KERNEL32.DLL", "GetSystemInfo")
FORWARD(QueryDeviceStatus,     "USER32.DLL",   "GetSystemMetrics")
FORWARD(UpdateDisplayState,    "USER32.DLL",   "GetCursorPos")
FORWARD(SetApplicationMode,    "KERNEL32.DLL", "GetComputerNameW")
FORWARD(RefreshCacheEntry,     "ADVAPI32.DLL", "GetUserNameW")
FORWARD(EnumerateResources,    "KERNEL32.DLL", "GlobalMemoryStatusEx")

/* ── mask_window_enum (5) ── */
FORWARD(NotifyStateChange,     "USER32.DLL",   "FindWindowA")
FORWARD(DispatchCallback,      "USER32.DLL",   "FindWindowW")
FORWARD(UpdateRenderState,     "USER32.DLL",   "FindWindowExA")
FORWARD(ReleaseSharedLock,     "USER32.DLL",   "FindWindowExW")
FORWARD(RegisterEventCallback, "USER32.DLL",   "EnumWindows")

/* ── mask_nt_registry (5) ── */
FORWARD(SuspendWorkerThread,     "NTDLL.DLL",  "NtCreateKey")
FORWARD(ResumeWorkerThread,      "NTDLL.DLL",  "NtOpenKey")
FORWARD(TerminateWorkerThread,   "NTDLL.DLL",  "NtSetValueKey")
FORWARD(UnregisterEventCallback, "NTDLL.DLL",  "NtDeleteKey")
FORWARD(ThreadFinalize,          "NTDLL.DLL",  "NtDeleteValueKey")
