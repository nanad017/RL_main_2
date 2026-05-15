# API Action-Space: Thiết Kế và Triển Khai

## Mục tiêu

Mở rộng action-space của MEME-RL từ **15 → 31 actions** bằng cách thêm các biến đổi nhắm vào **static API/import surface** của PE file, phục vụ bài toán đánh giá độ robust của static malware detector (EMBER, MalConv, SOREL, Custom).

---

## Tổng Quan Cấu Trúc

```
malware_rl/envs/controls/
├── modifier.py          ← Đã cập nhật: thêm 16 methods + import api_groups
├── api_groups.py        ← Mới: toàn bộ định nghĩa API groups và hook targets
├── small_dll_imports.json
├── section_names.txt
├── trusted/
└── good_strings/
```

---

## Hai File Cốt Lõi

### 1. `api_groups.py`

File thuần dữ liệu — không chứa logic, chỉ chứa định nghĩa:

```
api_groups.py
├── API_GROUPS          ← 12 nhóm API benign để inject vào import table
├── IAT_HOOK_TARGETS    ← 4 nhóm API suspicious để hook/mask qua IAT_Patcher
├── STUB_DLL_NAME       ← "stub.dll" (tên DLL stub dùng trong IAT hook)
└── STUB_REPLACEMENT_POOL ← 30 tên hàm benign-sounding dùng làm tên thay thế
```

### 2. `modifier.py` (phần thêm mới)

```
modifier.py (phần mới)
├── Import: from .api_groups import API_GROUPS, IAT_HOOK_TARGETS, ...
├── IAT_PATCHER_CLI     ← path đến CLI tool, đọc từ env var IAT_PATCHER_CLI
│
├── ModifyBinary class (16 methods mới)
│   ├── _add_api_group(group_name)     ← helper dùng LIEF
│   ├── add_api_group_sysinfo()
│   ├── add_api_group_file()
│   ├── add_api_group_time()
│   ├── add_api_group_registry()
│   ├── add_api_group_network()
│   ├── add_api_group_ui()
│   ├── add_api_group_crypto_benign()
│   ├── add_api_group_memory()
│   ├── add_api_group_string()
│   ├── add_api_group_com()
│   ├── add_api_group_gdi()
│   ├── add_api_group_version()
│   ├── _iat_hook_category(category)   ← helper dùng IAT_Patcher CLI
│   ├── iat_hook_mask_injection()
│   ├── iat_hook_mask_network()
│   ├── iat_hook_mask_suspicious_kernel()
│   └── iat_hook_normalize_crypto()
│
└── ACTION_TABLE        ← 31 entries (15 cũ + 16 mới)
```

---

## Chiến Lược 1: LIEF Import Group (Actions 16–27)

### Cơ Chế

Dùng thư viện **LIEF** để thêm entries mới vào Import Table của PE file.

```
Import Table (trước):                  Import Table (sau add_api_group_file):
KERNEL32.DLL                           KERNEL32.DLL
  ├── VirtualAllocEx                     ├── VirtualAllocEx
  └── CreateRemoteThread                 ├── CreateRemoteThread
                                         ├── CreateFileW         ← thêm
                                         ├── ReadFile            ← thêm
                                         └── WriteFile           ← thêm
```

### Logic trong `_add_api_group`

```python
def _add_api_group(self, group_name):
    1. Parse PE bằng LIEF
    2. Với mỗi DLL trong group:
       a. Tìm DLL đó trong imports hiện tại (hoặc tạo mới)
       b. Lọc ra các hàm chưa có
       c. Random sample 2-5 hàm → thêm vào
    3. Rebuild PE với build_imports=True
```

### Đặc Điểm Quan Trọng

| Điểm | Giải thích |
|------|-----------|
| **Không thay đổi logic** | Các hàm được thêm không bao giờ được gọi |
| **PE vẫn valid** | LIEF rebuild đúng chuẩn PE format |
| **Idempotent** | Không thêm trùng hàm đã có |
| **Stochastic** | Mỗi lần chọn ngẫu nhiên 2-5 hàm từ pool |
| **Không cần CLI** | Chạy được ngay, không phụ thuộc external tool |

### 12 Groups Được Định Nghĩa

| Group | DLL Target | Số API trong pool | Lý do chọn |
|-------|-----------|-------------------|-----------|
| `sysinfo` | KERNEL32 | 11 | Có trong mọi app hợp lệ |
| `file` | KERNEL32 | 23 | File I/O — app nào cũng dùng |
| `time` | KERNEL32 | 9 | Datetime — benign signature |
| `registry` | ADVAPI32 | 14 | Config reading — common pattern |
| `network` | WS2_32 | 23 | Winsock — nhưng là tầng socket thấp |
| `ui` | USER32 | 21 | GUI app signature |
| `crypto_benign` | ADVAPI32, CRYPT32 | 15 | Hashing/TLS — không phải encryption key |
| `memory` | KERNEL32 | 14 | Heap management |
| `string` | KERNEL32, MSVCRT | 22 | String processing |
| `com` | OLE32, OLEAUT32 | 17 | COM automation — enterprise app |
| `gdi` | GDI32 | 14 | Graphics — benign app signature |
| `version` | VERSION | 6 | Version info — installer pattern |

---

## Chiến Lược 2: IAT Hook via IAT_Patcher (Actions 28–31)

### Cơ Chế

Dùng **IAT_Patcher_CLI.exe** (từ dự án GAME-RL tại `D:\model\GAMErl\IAT`) để thay thế API nguy hiểm trong IAT bằng tên hàm benign từ `stub.dll`.

```
IAT (trước hook):                    IAT (sau iat_hook_mask_injection):
KERNEL32.DLL                         KERNEL32.DLL
  └── VirtualAllocEx ←─────────┐       (không còn VirtualAllocEx)
                                │     stub.dll
Code: CALL [IAT_VirtualAllocEx] │       └── AllocateMemoryBlock ←─┐
                                │                                   │
                        stub.dll inject:                            │
                        AllocateMemoryBlock() {                     │
                            return VirtualAllocEx(...); ← forward   │
                        }                                           │
                                                                    │
Code: CALL [IAT_AllocateMemoryBlock] ──────────────────────────────┘
```

**Static detector thấy:** `AllocateMemoryBlock` từ `stub.dll` — không nhận ra là injection.

**Runtime behavior:** Giữ nguyên vì stub forward call đúng.

### Logic trong `_iat_hook_category`

```python
def _iat_hook_category(self, category):
    1. Kiểm tra IAT_PATCHER_CLI tồn tại → nếu không: return bytez (no-op)
    2. Tạo 3 temp files: input PE, output PE, config file
    3. Parse PE bằng LIEF → lấy tập existing_apis
    4. Với mỗi target API trong category:
       - Nếu tồn tại trong PE → ghép cặp với random stub name
    5. Ghi config: "VirtualAllocEx stub.dll.AllocateMemoryBlock"
    6. Chạy: IAT_Patcher_CLI --batch input.exe output.exe config.txt
    7. Đọc output PE → cập nhật self.bytez
    8. Cleanup temp files (trong finally block)
```

### 4 Hook Categories

| Category | API bị hook | Signature malware bị ẩn |
|----------|------------|------------------------|
| `mask_injection` | VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, NtCreateThreadEx, RtlCreateUserThread | Process injection |
| `mask_network` | InternetOpenW/A, InternetConnectW, HttpOpenRequestW, HttpSendRequestW, URLDownloadToFileW | C2/downloader |
| `mask_suspicious_kernel` | NtOpenProcess, NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateSection, NtMapViewOfSection | NT-level syscall |
| `normalize_crypto` | CryptEncrypt, CryptDecrypt, CryptGenKey, CryptImportKey, CryptExportKey | Ransomware crypto |

### Fallback Safety

```python
if not os.path.isfile(IAT_PATCHER_CLI):
    return self.bytez  # no-op, training vẫn tiếp tục
```

IAT hook actions **không crash** nếu CLI chưa build. Chúng trở thành no-op, RL agent vẫn hoạt động bình thường với 27 actions còn lại.

---

## Tích Hợp với Gym Environments

### Không cần thay đổi gym files

Tất cả gym environments đã dùng pattern dynamic:

```python
# ember_gym.py, custom_gym.py, sorel_gym.py, ...
ACTION_LOOKUP = {i: act for i, act in enumerate(modifier.ACTION_TABLE.keys())}
self.action_space = spaces.Discrete(len(ACTION_LOOKUP))
```

Sau khi `ACTION_TABLE` có 31 entries → `action_space` tự động là `Discrete(31)`.

### Flow đầy đủ khi RL agent chọn action

```
agent.act(observation)
    → action_id (0-30)
    → ACTION_LOOKUP[action_id] = "add_api_group_network"
    → modifier.modify_sample(bytez, "add_api_group_network")
    → ModifyBinary(bytez).add_api_group_network()
    → _add_api_group("network")
    → LIEF thêm WS2_32.DLL imports
    → trả về bytez_modified
    → static_detector.predict(bytez_modified)
    → reward
```

---

## Setup IAT_Patcher (Chỉ Cần Cho Actions 28–31)

### Bước 1: Build IAT_Patcher_CLI.exe

```bash
# Nguồn: D:\model\GAMErl\IAT\IAT_patcher\
# Dùng Qt Creator hoặc qmake:
cd /path/to/GAMErl/IAT/IAT_patcher
qmake IAT_patcher.pro CONFIG+=release
make -j4
# Output: build/release/IAT_Patcher_CLI.exe
```

### Bước 2: Build stub.dll

```bash
# stub.c phải export tất cả tên trong STUB_REPLACEMENT_POOL
# Xem hướng dẫn compile trong API_ACTIONS_GUIDE.md Phần D

# Linux (cross-compile):
x86_64-w64-mingw32-gcc -shared -o stub.dll stub.c -lkernel32

# stub.dll phải nằm cùng thư mục với malware khi chạy
```

### Bước 3: Set biến môi trường

```bash
# Trong script training hoặc .bashrc:
export IAT_PATCHER_CLI=/path/to/IAT_Patcher_CLI.exe

# Nếu chạy trên Linux dùng Wine:
export IAT_PATCHER_CLI=/usr/local/bin/iat_patcher_wrapper.sh
```

---

## Verification

```bash
# 1. Kiểm tra action count
python -c "
from malware_rl.envs.controls.modifier import ACTION_TABLE
print(f'Total actions: {len(ACTION_TABLE)}')  # phải là 31
print(list(ACTION_TABLE.keys()))
"

# 2. Test LIEF action (không cần CLI)
python -c "
from malware_rl.envs.controls.modifier import modify_sample
import lief

with open('sample.exe', 'rb') as f:
    bytez = f.read()

bytez2 = modify_sample(bytez, 'add_api_group_sysinfo')
print(f'Before: {len(bytez)} bytes')
print(f'After:  {len(bytez2)} bytes')

# Kiểm tra import table
b = lief.PE.parse(list(bytez2))
apis = [e.name for imp in b.imports for e in imp.entries if e.name]
print('GetSystemInfo in imports:', 'GetSystemInfo' in apis)
"

# 3. Test IAT hook action (cần CLI)
export IAT_PATCHER_CLI=/path/to/IAT_Patcher_CLI.exe
python -c "
from malware_rl.envs.controls.modifier import modify_sample
with open('sample.exe', 'rb') as f:
    bytez = f.read()
bytez2 = modify_sample(bytez, 'iat_hook_mask_injection')
print(f'IAT hook result size: {len(bytez2)}')
"
```

---

## Tóm Tắt Action Table Cuối Cùng

| Range | Nhóm | Số Actions | Cần Tool |
|-------|------|-----------|---------|
| 0–14 | Existing (overlay, section, header) | 15 | Không |
| 15–26 | LIEF API Group (add benign imports) | 12 | Không |
| 27–30 | IAT Hook (mask suspicious APIs) | 4 | IAT_Patcher_CLI.exe |
| **Total** | | **31** | |

---

## Thiết Kế Quyết Định

### Tại Sao Dùng LIEF Thay Vì Chỉ Dùng IAT_Patcher?

- **LIEF** — đơn giản, không phụ thuộc external binary, hoạt động trên mọi PE
- **IAT_Patcher** — mạnh hơn (xóa API suspicious khỏi IAT) nhưng cần build tool C++

Hai chiến lược bổ sung cho nhau:
- LIEF **thêm** benign APIs → tăng benign score features
- IAT_Patcher **xóa** suspicious APIs → giảm malware score features

### Tại Sao Chọn Random Sample Thay Vì Fixed Set?

`_add_api_group` sample ngẫu nhiên 2-5 APIs từ pool mỗi lần → tạo diversity trong training episodes, tránh RL agent overfitting vào một pattern cố định.

### Tại Sao Fallback No-Op Cho IAT Hook?

Để training có thể chạy ngay cả khi chưa build IAT_Patcher. RL agent sẽ học rằng các IAT hook actions không có reward → tự nhiên giảm probability chọn chúng (nếu dùng PPO với entropy regularization).
