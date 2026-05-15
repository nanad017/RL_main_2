# 15 Actions Gốc (Trước Khi Thay Đổi)

Tất cả nằm trong `malware_rl/envs/controls/modifier.py`, class `ModifyBinary`.

---

## Nhóm 1: Overlay (cuối file)

Overlay là phần dữ liệu nằm **sau phần PE hợp lệ**, detector vẫn đọc nhưng không execute.

| # | Action | Làm gì |
|---|--------|--------|
| 1 | `pad_overlay` | Thêm 100,000 bytes cùng giá trị ngẫu nhiên vào cuối file |
| 2 | `append_benign_data_overlay` | Lấy 1 section (thường là `.text`) từ file benign trong `trusted/`, nối vào cuối |
| 3 | `append_benign_binary_overlay` | Lấy toàn bộ 1 file benign trong `trusted/`, nối vào cuối |
| 4 | `add_strings_to_overlay` | Lấy chuỗi strings từ file benign trong `good_strings/`, nối vào cuối dạng ASCII |

**Tác động detector:** Thay đổi byte histogram, file size, string features ở phần cuối.

---

## Nhóm 2: Section

| # | Action | Làm gì |
|---|--------|--------|
| 5 | `add_bytes_to_section_cave` | Tìm vùng null bytes (cave) trong section, điền random bytes vào đó |
| 6 | `add_section_strings` | Tạo section mới, nhồi strings benign từ `good_strings/` vào |
| 7 | `add_section_benign_data` | Tạo section mới, nhồi data từ section của file benign vào |
| 8 | `rename_section` | Đổi tên 1 section ngẫu nhiên thành tên phổ biến (`.text`, `.data`, `.rdata`...) |

**Tác động detector:** Thay đổi section names, section count, section entropy, byte histogram.

---

## Nhóm 3: Import Table

| # | Action | Làm gì |
|---|--------|--------|
| 9 | `add_imports` | Chọn ngẫu nhiên 1 DLL và 1 hàm từ `small_dll_imports.json`, thêm vào import table |

**Tác động detector:** Thay đổi import API features, DLL list.

---

## Nhóm 4: PE Header

| # | Action | Làm gì |
|---|--------|--------|
| 10 | `modify_optional_header` | Thay đổi 1 trong 6 field của Optional Header: linker version, OS version, image version |
| 11 | `modify_timestamp` | Đổi timestamp trong PE header thành 1 trong 5 giá trị cố định (hoặc 0) |
| 12 | `break_optional_header_checksum` | Đặt checksum = 0 |
| 13 | `remove_debug` | Xóa debug directory (đặt RVA và size về 0) |

**Tác động detector:** Thay đổi header metadata features.

---

## Nhóm 5: Packing

| # | Action | Làm gì |
|---|--------|--------|
| 14 | `upx_pack` | Nén file bằng UPX với level ngẫu nhiên (1-9) và các option ngẫu nhiên |
| 15 | `upx_unpack` | Giải nén file nếu đang bị UPX pack |

**Tác động detector:** Thay đổi toàn bộ byte layout, entropy, section structure.

---

## Tổng Hợp

```
Overlay (4)     → tác động phần cuối file, string/byte features
Section (4)     → tác động section structure, entropy
Import (1)      → tác động import table features
Header (4)      → tác động metadata fields
Packing (2)     → tác động toàn bộ file layout
─────────────────────────────────────────
Tổng: 15 actions
```

## Nguồn Dữ Liệu Dùng Bởi Các Actions

| File/Folder | Dùng bởi action nào |
|-------------|---------------------|
| `trusted/` | append_benign_data_overlay, append_benign_binary_overlay, add_section_benign_data |
| `good_strings/` | add_strings_to_overlay, add_section_strings |
| `small_dll_imports.json` | add_imports |
| `section_names.txt` | rename_section, add_section_strings, add_section_benign_data |
| `upx` binary | upx_pack, upx_unpack |
