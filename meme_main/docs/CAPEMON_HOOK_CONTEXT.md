# CAPEv2 / capemon Hook Context

Ngay kiem tra: 2026-05-15

Repo dang duoc kiem tra: `D:\model\CAPEv2`

Muc tieu cua ghi chu nay la tom tat ket qua dieu tra API/hook trong CAPEv2 de gui cho AI/nguoi khac tiep tuc phan tich.

## Ket luan ngan

- Cac ten API tru tuong/placeholder nhu `GetSystemParameters`, `QuerySystemInfo`, `AllocateMemoryBlock`, `NetworkInitialize`, `CryptoHashBuffer`, `RegistryWriteValue`, v.v. khong xuat hien truc tiep trong source CAPEv2 theo exact token.
- CAPEv2 co mapping/log table cho nhieu Windows API that trong `lib\cuckoo\common\logtbl.py`.
- CAPEv2 hien tai khong chua source hook monitor C/C++ nhu `hook_*.c`, `hooks.c`, `hooking.c`.
- Monitor hook that nam trong DLL build san: `analyzer\windows\dll\capemon.dll` va `analyzer\windows\dll\capemon_x64.dll`.
- README xac nhan source monitor nam o repo rieng `capemon`: `https://github.com/kevoreilly/capemon`.
- Repo `capemon` da duoc git clone local tai: `D:\model\capemon`.

## File can chu y

- `README.md`
  - Dong 140: section `capemon`.
  - Dong 141: ghi ro repository chua code monitor cua CAPE la repo rieng.
- `D:\model\capemon`
  - Local clone cua repo `https://github.com/kevoreilly/capemon`; nen tim source hook monitor tai day neu can implementation C/C++.
- `lib\cuckoo\common\logtbl.py`
  - Bang mapping API log/behavior. Day khong phai source hook C, ma la bang khai bao de parse/log API calls.
- `analyzer\windows\dll\`
  - Chua DLL monitor/proxy loader build san.
- `analyzer\windows\bin\`
  - Chua loader/tools build san dung de inject/chay package.
- `analyzer\windows\analyzer.py`
  - Dong 523-526 randomize/copy `capemon.dll`, `capemon_x64.dll`, `loader.exe`, `loader_x64.exe`.
- `analyzer\windows\lib\api\process.py`
  - Dong 225 dung `KERNEL32.GetSystemInfo(...)` trong Python analyzer.
  - Dong 933-934 copy `capemon.dll` va `version.dll` khi side-load.
  - Dong 1024+ deploy `version.dll` proxy loader.

## Mapping API trong `logtbl.py`

Nhung Windows API lien quan co trong `lib\cuckoo\common\logtbl.py`:

```text
29   NtClose
31   InternetReadFile
32   InternetWriteFile
44   RegDeleteKeyA
45   RegDeleteKeyW
52   NtDeleteKey
60   WSAStartup
64   send
79   WSASend
80   WSASendTo
98   NtReadFile
99   NtWriteFile
154  NtCreateSection
162  NtAllocateVirtualMemory
173  NtFreeVirtualMemory
183  RegSetValueExA
184  RegSetValueExA
185  RegSetValueExW
186  RegSetValueExW
187  RegQueryValueExA
188  RegQueryValueExA
189  RegQueryValueExW
190  RegQueryValueExW
226  NtSetValueKey
227  NtSetValueKey
228  NtQueryValueKey
229  NtQueryValueKey
278  NtCreateThread
281  CreateThread
288  NtMapViewOfSection
304  ZwQuerySystemInformation
318  ZwCreateThread
319  ZwCreateThreadEx
320  NtMapViewOfSection
```

Khong thay trong `logtbl.py` theo exact name:

```text
GetSystemInfo
SystemParametersInfo
NtQuerySystemInformation
NtDuplicateObject
CryptAcquireContext
CryptCreateHash
CryptHashData
CryptDestroyHash
```

Luu y: `NtQuerySystemInformation` khong co trong `logtbl.py` dung ten `Nt*`, nhung co `ZwQuerySystemInformation` tai dong 304.

## Binary co san trong CAPEv2

Trong `analyzer\windows\dll\`:

```text
capemon.dll        32-bit monitor DLL
capemon_x64.dll    64-bit monitor DLL
version.dll        32-bit proxy/sideloader DLL
version_x64.dll    64-bit proxy/sideloader DLL
```

Trong `analyzer\windows\bin\`:

```text
autoit3.exe
loader.exe
loader_x64.exe
PPLinject64.exe
psexec.exe
signtool.exe
```

## API strings thay trong monitor DLL

Quet string binary voi `rg -a` cho thay `capemon.dll` va `capemon_x64.dll` chua cac API name lien quan sau:

```text
CreateThread
CryptAcquireContext
CryptCreateHash
CryptDestroyHash
CryptHashData
GetSystemInfo
InternetReadFile
InternetWriteFile
NtAllocateVirtualMemory
NtClose
NtCreateSection
NtCreateThread
NtCreateThreadEx
NtDeleteKey
NtDuplicateObject
NtFreeVirtualMemory
NtMapViewOfSection
NtQuerySystemInformation
NtQueryValueKey
NtReadFile
NtSetValueKey
NtWriteFile
RegDeleteKey
RegQueryValueEx
RegSetValueEx
Send / send
SystemParametersInfo
WSASend
WSAStartup
```

Dieu nay cho thay cac hook/API that co kha nang nam trong monitor DLL build san, nhung source implementation khong nam trong repo CAPEv2 nay.

## Cac ten placeholder khong thay truc tiep

Khong thay exact token trong source CAPEv2 cho cac ten sau:

```text
GetSystemParameters
QuerySystemInfo
GetPlatformInfo
AllocateMemoryBlock
ReleaseMemoryBlock
CreateSharedRegion
InitializeContext
FinalizeContext
OpenContext
ReadDataBuffer
WriteDataBuffer
FlushDataBuffer
NetworkInitialize
NetworkFinalize
NetworkSendData
CryptoInitProvider
CryptoHashBuffer
CryptoFinalizeHash
ThreadInitialize
ThreadFinalize
ThreadExecute
HandleAllocate
HandleRelease
HandleQuery
RegistryReadValue
RegistryWriteValue
RegistryDeleteKey
```

## Source hook trong CAPEv2

Da tim toan repo voi cac pattern:

```text
hook_*.c
hooks.c
hooking.c
hook_*.cpp
hooks.cpp
hooking.cpp
hook_*.h
hooks.h
hooking.h
```

Ket qua: khong co file hook source nao theo cac pattern tren.

Toan repo chi thay mot file C lien quan khac:

```text
data\src\binpackage\execsc.c
```

File nay khong phai source hook monitor.

## Ghi chu ve workspace

Truoc khi tao file nay, `git status --short` da co thay doi san:

```text
D analyzer/windows/bin/PPLinject.exe
```

File do khong duoc dung/chinh sua trong qua trinh tao ghi chu nay.
