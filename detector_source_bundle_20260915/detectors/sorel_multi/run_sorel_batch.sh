#!/bin/bash

# ============================================================
#  Sorel Batch Malware Detection Script
#  Detector : sorel_multi
#  Input    : MAB + meme
# ============================================================

# ---- CẤU HÌNH ----
SOREL_DIR=~/detector/sorel_multi
FFNN_MODEL=$SOREL_DIR/baselines
LGBM_MODEL=$SOREL_DIR/baselines/lgbm_seed1.joblib
THRESHOLD=0.8327

PYTHON=/home/rl/miniconda3/envs/sorel-malware-detector/bin/python3

INPUT_DIRS=(
    "/home/rl/RL/dataset/RL_evasion/MAB"
    "/home/rl/RL/dataset/RL_evasion/meme"
)

BASE_OUTPUT=~/RL/results

echo "============================================"
echo " Sorel Batch Detection"
echo " Bắt đầu : $(date)"
echo " Python  : $PYTHON"
echo "============================================"

# ---- CHẠY TỪNG THƯ MỤC ----
for INPUT_DIR in "${INPUT_DIRS[@]}"; do
    DIRNAME=$(basename "$INPUT_DIR")
    OUTPUT_DIR=$BASE_OUTPUT/sorel_${DIRNAME}_batch
    CSV_FILE=$OUTPUT_DIR/results.csv
    SUMMARY_FILE=$OUTPUT_DIR/summary.txt

    mkdir -p "$OUTPUT_DIR"
    echo "filename,result,family,confidence" > "$CSV_FILE"

    total=0; malware=0; benign=0; error=0

    echo ""
    echo "--------------------------------------------"
    echo " Đang quét : $INPUT_DIR"
    echo " Kết quả   : $OUTPUT_DIR"
    echo "--------------------------------------------"

    for filepath in "$INPUT_DIR"/*; do
        [ -f "$filepath" ] || continue

        filename=$(basename "$filepath")
        result_file="$OUTPUT_DIR/${filename}.txt"
        total=$((total + 1))

        echo -n "[$total] $filename ... "

        # Phải chạy từ thư mục gốc của sorel
        cd "$SOREL_DIR" || { echo "ERROR: không vào được $SOREL_DIR"; exit 1; }

        $PYTHON detect.py \
            --input "$filepath" \
            --ffnn-model "$FFNN_MODEL" \
            --lgbm-model "$LGBM_MODEL" \
            --ensemble \
            --threshold "$THRESHOLD" \
            > "$result_file" 2>"$OUTPUT_DIR/${filename}.err"

        exit_code=$?

        if [ $exit_code -ne 0 ]; then
            echo "ERROR"
            error=$((error + 1))
            echo "$filename,ERROR,N/A" >> "$CSV_FILE"
            continue
        fi

        # Parse kết quả theo format sorel
        # "  Verdict : 🔴 MALWARE"  hoặc  "  Verdict : 🟢 BENIGN"
        verdict_line=$(grep "Verdict" "$result_file" | head -1)
        family=$(grep "  Family" "$result_file" | head -1 | awk -F': ' '{print $2}' | tr -d ' \r')
        confidence=$(grep "Confidence:" "$result_file" | head -1 | grep -oE "[0-9]+\.[0-9]+" | head -1)

        [ -z "$family" ]     && family="N/A"
        [ -z "$confidence" ] && confidence="N/A"

        if echo "$verdict_line" | grep -q "MALWARE"; then
            result="MALWARE"
            malware=$((malware + 1))
        elif echo "$verdict_line" | grep -q "BENIGN"; then
            result="BENIGN"
            benign=$((benign + 1))
        else
            result="UNKNOWN"
        fi

        echo "$result ($family) - ${confidence}%"
        echo "$filename,$result,$family,$confidence" >> "$CSV_FILE"
    done

    # ---- TỔNG KẾT MỖI THƯ MỤC ----
    echo ""
    echo "============================================"
    echo " Thống kê: $DIRNAME"
    echo "============================================"
    echo "  Tổng số file  : $total"
    echo "  Malware       : $malware"
    echo "  Benign        : $benign"
    echo "  Lỗi           : $error"

    if [ $total -gt 0 ]; then
        mal_pct=$(awk "BEGIN {printf \"%.1f\", $malware/$total*100}")
        ben_pct=$(awk "BEGIN {printf \"%.1f\", $benign/$total*100}")
        echo "  Tỉ lệ Malware : $mal_pct%"
        echo "  Tỉ lệ Benign  : $ben_pct%"
    fi
    echo "============================================"

    {
        echo "===== SOREL DETECTION SUMMARY: $DIRNAME ====="
        echo "Date        : $(date)"
        echo "Input Dir   : $INPUT_DIR"
        echo "Total Files : $total"
        echo "Malware     : $malware"
        echo "Benign      : $benign"
        echo "Errors      : $error"
    echo ""
    echo "--- Family Distribution ---"
    grep ",MALWARE," "$CSV_FILE" | awk -F',' '{print $3}' | sort | uniq -c | sort -rn
    } > "$SUMMARY_FILE"

    echo "[INFO] CSV     : $CSV_FILE"
    echo "[INFO] Summary : $SUMMARY_FILE"
done

echo ""
echo "============================================"
echo " Hoàn tất tất cả: $(date)"
echo "============================================"