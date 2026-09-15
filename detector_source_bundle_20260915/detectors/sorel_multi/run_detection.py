import subprocess
import os
import json
import sys
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# --- Cấu hình ---
DETECTOR_SCRIPT = "detect.py"
BASE_DIR = Path("~/RL/dataset/RL_evasion/MAB").expanduser()
FFNN_MODEL = "./baselines"
LGBM_MODEL = "./baselines/lgbm_seed1.joblib"
THRESHOLD = 0.8327
TARGET_DIRS = ["minimal", "evasive"]  # Quét minimal trước để làm baseline
LABELS = ["Locker", "Mediyes", "Winwebsec", "Zbot", "Zeroaccess", "BENIGN"]

def run_detection(file_path):
    """Chạy detector SOREL-20M và lấy kết quả từ file JSON tạm"""
    output_json = "temp_result.json"
    cmd = [
        "python", DETECTOR_SCRIPT, 
        "--input", str(file_path), 
        "--ffnn-model", FFNN_MODEL,
        "--lgbm-model", LGBM_MODEL, 
        "--ensemble",
        "--threshold", str(THRESHOLD), 
        "--output", output_json
    ]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.path.exists(output_json):
            with open(output_json, 'r', encoding='utf-8') as f:
                data = json.load(f)
            os.remove(output_json)
            return data['results'][0]
    except Exception:
        return None
    return None

def process():
    # results[target_name][actual_family][predicted_label]
    results = {t: defaultdict(lambda: defaultdict(int)) for t in TARGET_DIRS}

    for target in TARGET_DIRS:
        print(f"\n[+] ĐANG XỬ LÝ NHÓM: {target.upper()}")
        target_path = BASE_DIR / target
        if not target_path.exists():
            print(f"    [!] Không tìm thấy thư mục: {target_path}")
            continue

        families = sorted([d for d in target_path.iterdir() if d.is_dir()])

        for family_dir in families:
            actual_fam = family_dir.name
            files = list(family_dir.glob("*"))
            print(f"    -> {actual_fam:<12}: Quét {len(files)} files...", end="\r")
            
            for file_path in files:
                if not file_path.is_file():
                    continue
                res = run_detection(file_path)
                if not res:
                    continue
                
                # Xác định nhãn dự đoán
                if res.get("verdict") == "BENIGN":
                    pred_label = "BENIGN"
                else:
                    pred_fam = str(res.get("malware_family")).lower()
                    pred_label = next((l for l in LABELS if l.lower() == pred_fam), "Other")
                
                results[target][actual_fam][pred_label] += 1
            print(f"    -> {actual_fam:<12}: Hoàn tất.                      ")

    # XUẤT BÁO CÁO TỔNG HỢP
    report = []
    report.append(f"\n{'='*100}\n BÁO CÁO PHÂN TÍCH HIỆU QUẢ EVASION (SOREL-20M)\n{'='*100}")

    for t in TARGET_DIRS:
        report.append(f"\n>>> PHÂN TÍCH NHÓM: {t.upper()}")

        # 1. Confusion Matrix
        report.append("\n[1] CONFUSION MATRIX (Row: Actual | Col: Predicted)")
        label_headers = " | ".join([f"{l[:6]:<6}" for l in LABELS])
        
        # Sửa lỗi SyntaxError: Tách chuỗi có backslash ra biến riêng
        row_title = "Actual \\ Pred"
        header = f"{row_title:<15} | {label_headers}"
        
        report.append(header)
        report.append("-" * len(header))
        
        malware_labels = [l for l in LABELS if l != "BENIGN"]
        for actual in malware_labels:
            row_data = [f"{actual:<15}"]
            for pred in LABELS:
                row_data.append(f"{results[t][actual][pred]:<6}")
            report.append(" | ".join(row_data))

        # 2. Chi tiết tỉ lệ Evasion
        report.append("\n[2] TỈ LỆ EVASION (Tỉ lệ vượt rào thành công)")
        report.append(f"{'Họ (Actual)':<15} | {'Tổng file':<10} | {'Bị phát hiện':<12} | {'Vượt rào (ADV)':<15} | {'Evasion Rate'}")
        report.append("-" * 85)

        t_files, t_evaded = 0, 0
        for fam in malware_labels:
            m = results[t][fam]
            total = sum(m.values())
            if total == 0:
                continue
            evaded = m["BENIGN"]
            detected = total - evaded
            rate = (evaded / total) * 100
            report.append(f"{fam:<15} | {total:<10} | {detected:<12} | {evaded:<15} | {rate:>10.2f}%")
            t_files += total
            t_evaded += evaded

        avg_rate = (t_evaded / t_files * 100) if t_files > 0 else 0
        report.append("-" * 85)
        report.append(f"{'TỔNG CỘNG':<15} | {t_files:<10} | {t_files - t_evaded:<12} | {t_evaded:<15} | {avg_rate:>10.2f}%")

    # 3. So sánh Minimal vs Evasive
    report.append(f"\n{'='*100}\n[3] TỔNG KẾT SO SÁNH: GỐC (MINIMAL) VS ĐỐI KHÁNG (EVASIVE)\n{'='*100}")
    for fam in malware_labels:
        min_evaded = results["minimal"][fam]["BENIGN"]
        eva_evaded = results["evasive"][fam]["BENIGN"]
        diff = eva_evaded - min_evaded
        report.append(f"Họ {fam:<12}: Gốc bị sót: {min_evaded:<4} | Sau MAB vượt thêm: {diff:<4} file.")

    final_text = "\n".join(report)
    print(final_text)
    
    output_file = "sorel_comprehensive_report.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(final_text)
    print(f"\n[OK] Báo cáo chi tiết đã lưu vào: {output_file}")

if __name__ == "__main__":
    process()