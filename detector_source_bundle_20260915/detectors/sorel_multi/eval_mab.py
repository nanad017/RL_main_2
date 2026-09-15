import subprocess
import os
import json
from pathlib import Path
from collections import defaultdict

# Cấu hình đường dẫn tuyệt đối
BASE_DIR = Path("/home/rl/RL/dataset/RL_evasion/MAB")
TARGET_DIRS = ["minimal", "evasive"]
LABELS = ["Locker", "Mediyes", "Winwebsec", "Zbot", "Zeroaccess", "BENIGN"]

def run_detection(file_path):
    cmd = [
        "python", "detect.py",
        "--input", str(file_path),
        "--ffnn-model", "./baselines",
        "--lgbm-model", "./baselines/lgbm_seed1.joblib",
        "--ensemble",
        "--threshold", "0.8327"
    ]
    
    # Bắt trực tiếp output màn hình thay vì dùng file JSON trung gian
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Cố gắng bóc tách chuỗi JSON từ output của màn hình
    for line in reversed(result.stdout.split('\n')):
        if '{' in line and '}' in line:
            try:
                # Xử lý đoạn JSON (nếu script detect.py in ra json)
                start_idx = line.find('{')
                end_idx = line.rfind('}') + 1
                data = json.loads(line[start_idx:end_idx])
                
                # Cấu trúc json có thể khác nhau, hỗ trợ cả 2 dạng thường gặp
                if 'results' in data:
                    return data['results'][0]
                return data
            except:
                continue
                
    # Fallback: Nếu không phải JSON, tìm keyword dạng text thông thường
    out_upper = result.stdout.upper()
    if "BENIGN" in out_upper:
        return {"verdict": "BENIGN", "malware_family": ""}
    for label in LABELS[:-1]:
        if label.upper() in out_upper:
            return {"verdict": "MALWARE", "malware_family": label}
            
    return None

def main():
    results = {t: defaultdict(lambda: defaultdict(int)) for t in TARGET_DIRS}
    
    print(f"{'='*60}\n BẮT ĐẦU QUÉT DATASET MAB\n{'='*60}")
    
    for target in TARGET_DIRS:
        target_path = BASE_DIR / target
        if not target_path.exists():
            print(f"[!] LỖI: Không tìm thấy {target_path}")
            continue

        print(f"\n[*] Đang xử lý nhóm: {target.upper()}")
        for fam in [l for l in LABELS if l != "BENIGN"]:
            fam_dir = target_path / fam
            if not fam_dir.exists() or not fam_dir.is_dir():
                continue
                
            files = [f for f in fam_dir.iterdir() if f.is_file()]
            print(f"    -> {fam:<12}: Đang quét {len(files)} files...")
            
            for file_path in files:
                res = run_detection(file_path)
                if not res:
                    results[target][fam]["LỖI_DETECT"] += 1
                    continue
                
                # Phân tích nhãn
                verdict = str(res.get("verdict", "")).upper()
                if verdict == "BENIGN":
                    pred_label = "BENIGN"
                else:
                    pred_fam = str(res.get("malware_family", "")).lower()
                    pred_label = next((l for l in LABELS if l.lower() == pred_fam), "Other")
                    
                results[target][fam][pred_label] += 1

    # ================= SINH BÁO CÁO =================
    report = []
    report.append("="*90)
    report.append(" BÁO CÁO PHÂN TÍCH HIỆU QUẢ EVASION - DATASET MAB")
    report.append("="*90)

    for t in TARGET_DIRS:
        report.append(f"\n>>> PHÂN TÍCH NHÓM: {t.upper()} <<<")
        report.append("\n[1] CONFUSION MATRIX (Row: Actual | Col: Predicted)")
        
        headers = [f"{l[:6]:<6}" for l in LABELS] + ["Other", "Error"]
        header_str = "Actual \\ Pred | " + " | ".join(headers)
        report.append(header_str)
        report.append("-" * len(header_str))
        
        t_files_all, t_evaded_all = 0, 0
        malware_labels = [l for l in LABELS if l != "BENIGN"]
        
        for actual in malware_labels:
            m = results[t][actual]
            row_data = [f"{actual:<13}"]
            for pred in LABELS + ["Other", "LỖI_DETECT"]:
                row_data.append(f"{m[pred]:<6}")
            report.append(" | ".join(row_data))
            
        report.append("\n[2] CHI TIẾT TỈ LỆ EVASION (Bypass SOREL)")
        report.append(f"{'Loại Malware':<15} | {'Tổng file Adv':<15} | {'Bị phát hiện':<15} | {'Vượt rào (Benign)':<18} | {'Evasion Rate'}")
        report.append("-" * 85)
        
        for fam in malware_labels:
            m = results[t][fam]
            total = sum(m.values())
            if total == 0: continue
            
            evaded = m["BENIGN"]
            detected = total - evaded - m["LỖI_DETECT"]
            rate = (evaded / total) * 100
            
            report.append(f"{fam:<15} | {total:<15} | {detected:<15} | {evaded:<18} | {rate:>6.2f}%")
            t_files_all += total
            t_evaded_all += evaded

        avg_rate = (t_evaded_all / t_files_all * 100) if t_files_all > 0 else 0
        report.append("-" * 85)
        report.append(f"{'TỔNG CỘNG':<15} | {t_files_all:<15} | {t_files_all - t_evaded_all:<15} | {t_evaded_all:<18} | {avg_rate:>6.2f}%\n")

    report.append("="*90)
    report.append("[3] SO SÁNH SỰ CẢI THIỆN: MINIMAL vs EVASIVE")
    report.append("="*90)
    for fam in malware_labels:
        min_ev = results["minimal"][fam]["BENIGN"]
        eva_ev = results["evasive"][fam]["BENIGN"]
        report.append(f"- Họ {fam:<12}: Minimal bypass {min_ev:<4} file --> Evasive bypass {eva_ev:<4} file (Chênh lệch: {eva_ev - min_ev:+})")

    with open("report_MAB.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(report))
    print("\n[OK] Đã xuất báo cáo thành công vào file: report_MAB.txt")

if __name__ == "__main__":
    main()