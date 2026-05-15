# Context Dự Án MEME-RL

## Tổng Quan

Dự án xây dựng mô hình **Reinforcement Learning (RL) problem-space** biến đổi file PE malware thật để đánh giá độ robust của static malware detector.

```
Flow chính:
  PE malware file (bytez)
  → RL agent chọn action
  → modify PE file thật
  → đưa vào static detector
  → nhận score/reward trực tiếp
```

## Khác Với GAME-RL Gốc

| | GAME-RL (D:\model\GAMErl\IAT) | MEME-RL (D:\model\meme_main) |
|---|---|---|
| Approach | Feature-space RL trước, rồi hook PE sau | Problem-space RL trực tiếp |
| Target | API call sequence detector (RNN) | Static detector (EMBER, MalConv, SOREL, Custom) |
| Modify | IAT hooking thay đổi API call | Modify PE structure + imports |

## Detector

Dùng **STATIC detector** — không phải dynamic detector.

Detector nhìn vào:
- PE structure, import table, DLL/API names
- Strings, sections, bytes/embeddings
- Entropy, static features

**Không cần** runtime API execution, sandbox API trace, hay hook runtime behavior.

## Cấu Trúc Dự Án

```
meme_main/
├── malware_rl/envs/
│   ├── controls/
│   │   ├── modifier.py          ← 18 actions (15 gốc + 3 API mới)
│   │   ├── api_groups.py        ← data: 12 nhóm API benign + 4 nhóm suspicious
│   │   ├── small_dll_imports.json
│   │   ├── section_names.txt
│   │   ├── trusted/             ← file benign dùng cho overlay/section actions
│   │   └── good_strings/        ← strings benign
│   ├── custom_gym.py            ← CustomDetectorEnv
│   ├── ember_gym.py             ← EmberEnv
│   ├── malconv_gym.py           ← MalConvEnv
│   ├── sorel_gym.py             ← SorelEnv
│   ├── sorelFFNN_gym.py         ← SorelFFNNEnv
│   ├── AV_gym.py                ← AVEnv
│   ├── lgb_gym.py               ← LGBEnv
│   └── utils/
│       ├── interface.py         ← load samples
│       ├── custom_api.py        ← custom detector API
│       ├── ember.py             ← EMBER model wrapper
│       ├── malconv.py           ← MalConv wrapper
│       └── sorel.py             ← SOREL wrapper
├── ppo.py                       ← PPO training
├── ppo_model_extract.py         ← MEME algorithm (model-based RL)
├── surrogate.py                 ← surrogate model training
├── evaluate.py                  ← evaluation
└── docs/                        ← tài liệu
```

## 18 Actions Hiện Tại

### 15 Actions Gốc

| # | Nhóm | Action | Làm gì |
|---|------|--------|--------|
| 1 | Overlay | `pad_overlay` | Thêm 100K bytes ngẫu nhiên cuối file |
| 2 | Overlay | `append_benign_data_overlay` | Nối section từ file benign vào cuối |
| 3 | Overlay | `append_benign_binary_overlay` | Nối toàn bộ file benign vào cuối |
| 4 | Overlay | `add_strings_to_overlay` | Nối strings benign vào cuối |
| 5 | Section | `add_bytes_to_section_cave` | Điền random bytes vào vùng null trong section |
| 6 | Section | `add_section_strings` | Tạo section mới chứa strings benign |
| 7 | Section | `add_section_benign_data` | Tạo section mới chứa data từ file benign |
| 8 | Section | `rename_section` | Đổi tên section thành tên phổ biến |
| 9 | Import | `add_imports` | Thêm 1 API ngẫu nhiên từ small_dll_imports.json |
| 10 | Header | `modify_optional_header` | Thay đổi linker/OS/image version |
| 11 | Header | `modify_timestamp` | Đổi timestamp PE header |
| 12 | Header | `break_optional_header_checksum` | Đặt checksum = 0 |
| 13 | Header | `remove_debug` | Xóa debug directory |
| 14 | Packing | `upx_pack` | Nén bằng UPX |
| 15 | Packing | `upx_unpack` | Giải nén UPX |

### 3 Actions API Mới

| # | Action | Cơ chế | Cần tool? | Đổi code bytes? |
|---|--------|--------|-----------|-----------------|
| 16 | `add_api_group` | Random 1/12 nhóm benign → LIEF thêm 2-5 API vào import table | Không | Không |
| 17 | `iat_hook_suspicious` | Random 1/4 nhóm suspicious → LIEF xóa DLL chứa API đó khỏi import table | Không | Không |
| 18 | `iat_patch_api` | Random 1/4 nhóm suspicious → IAT_Patcher CLI hook API → stub.dll | Cần CLI + stub.dll | **Có** |

### Sự Khác Biệt Giữa 3 Actions API

```
add_api_group         → THÊM API benign vào import table (pha loãng)
iat_hook_suspicious   → XÓA DLL suspicious khỏi import table (binary broken)
iat_patch_api         → THAY TÊN API suspicious → stub.dll (binary vẫn chạy, code bytes thay đổi)
```

## Action 18: Yêu Cầu Setup

Cần 2 thứ do user tự build:

1. **IAT_Patcher_CLI.exe** — build từ source `D:\model\GAMErl\IAT\IAT_patcher\`
2. **stub.dll** — compile từ stub.c (source code trong `docs/huong_dan_action_18_iat_patch.md`)

Set env var trên máy Linux training:
```bash
export IAT_PATCHER_CLI=/path/to/IAT_Patcher_CLI.exe
```

Nếu chưa build → action 18 tự động no-op, training vẫn chạy với 17 actions còn lại.

## Gym Environments

Tất cả gym files dùng pattern dynamic:
```python
ACTION_LOOKUP = {i: act for i, act in enumerate(modifier.ACTION_TABLE.keys())}
self.action_space = spaces.Discrete(len(ACTION_LOOKUP))
```
→ Tự nhận đủ 18 actions, **không cần sửa gym files**.

## File Data

| File | Dùng bởi |
|------|----------|
| `small_dll_imports.json` | action 9 (`add_imports`) — 16 DLLs, hàng trăm functions |
| `api_groups.py` | action 16-18 — 12 nhóm API benign + 4 nhóm suspicious |
| `section_names.txt` | action 6, 7, 8 — tên section phổ biến |
| `trusted/` | action 2, 3, 7 — file benign |
| `good_strings/` | action 4, 6 — strings benign |

## Triển Khai

- Code ở `D:\model\meme_main` (Windows) — push lên GitHub
- Chạy training thật ở máy Linux — pull GitHub về
- Máy Windows chỉ dùng để code, không chạy training

## Docs

```
docs/
├── context_du_an.md                     ← file này
├── huong_dan_thiet_ke_action_space.md   ← thiết kế tổng quan action-space
├── danh_sach_thay_doi.md                ← những gì đã thêm/sửa
├── mo_ta_15_actions_goc.md              ← mô tả 15 actions gốc chi tiết
└── huong_dan_action_18_iat_patch.md     ← hướng dẫn build stub.dll + CLI
```
