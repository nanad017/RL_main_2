#!/usr/bin/env bash

# Quet 5 dataset bang ember_scan.py.
#
# Cau truc MAB:
#   MAB/evasive/benign/*
#   MAB/evasive/virus/{Locker,Mediyes,Winwebsec,Zbot,Zeroaccess}/*
#   MAB/minimal/benign/*
#   MAB/minimal/virus/{Locker,Mediyes,Winwebsec,Zbot,Zeroaccess}/*
#
# Cau truc cac dataset con lai:
#   {main,meme,PSP,RL_MAIN_FINAL}/{Locker,Mediyes,Winwebsec,Zbot,Zeroaccess}/*
#
# RL_MAIN_FINAL/logs khong duoc quet.

set -o pipefail

BASE_ROOT="/home/rl/RL/dataset/RL_evasion"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCAN_SCRIPT="$SCRIPT_DIR/ember_scan.py"

MAB_MODES=("evasive" "minimal")
FAMILY_DATASETS=("main" "meme" "PSP" "RL_MAIN_FINAL")
MALWARE_LABELS=("Locker" "Mediyes" "Winwebsec" "Zbot" "Zeroaccess")
TRUE_LABELS=("Benign" "Locker" "Mediyes" "Winwebsec" "Zbot" "Zeroaccess")
PRED_LABELS=("Benign" "Locker" "Mediyes" "Winwebsec" "Zbot" "Zeroaccess")

# So loi dau tien se in day du output cua ember_scan.py.
MAX_ERROR_DETAILS=5

# Neu 10 file dau tien deu khong scan duoc thi dung som, tranh lap 1.500+ loi.
EARLY_ABORT_ATTEMPTS=10

# key = unit|true_label|pred_label
declare -A CM
declare -A TOTAL
declare -A CORRECT
declare -A WRONG
declare -A PRED_BENIGN
declare -A ERRORS

declare -a UNITS

ATTEMPTS=0
SUCCESSFUL_SCANS=0
FAILED_SCANS=0
ERROR_DETAILS_PRINTED=0

DETECTOR_OUTPUT=""
DETECTOR_STATUS=0
DETECTOR_LABEL=""

increment_assoc() {
    local array_name="$1"
    local key="$2"
    local current

    eval 'current="${'"$array_name"'[$key]:-0}"'
    eval "$array_name"'["$key"]=$((current + 1))'
}

calc_percent() {
    local num="$1"
    local den="$2"

    if (( den == 0 )); then
        printf '0.00%%\n'
    else
        awk -v n="$num" -v d="$den" 'BEGIN { printf "%.2f%%\n", n * 100 / d }'
    fi
}

normalize_label() {
    local raw="$1"

    raw="$(
        printf '%s' "$raw" \
            | tr -d '\r' \
            | sed -E 's/^[[:space:]"'"'"'\[\(]+//; s/[[:space:]"'"'"'\]\),.]+$//' \
            | xargs \
            | tr '[:upper:]' '[:lower:]'
    )"

    case "$raw" in
        benign)     printf '%s\n' "Benign" ;;
        locker)     printf '%s\n' "Locker" ;;
        mediyes)    printf '%s\n' "Mediyes" ;;
        winwebsec)  printf '%s\n' "Winwebsec" ;;
        zbot)       printf '%s\n' "Zbot" ;;
        zeroaccess) printf '%s\n' "Zeroaccess" ;;
        *)          printf '%s\n' "" ;;
    esac
}

parse_predicted_label() {
    local output="$1"
    local raw=""

    # Khong dung IGNORECASE vi awk tren Ubuntu co the la mawk.
    # Dung tolower() de so khop khong phan biet hoa/thuong.
    raw="$(
        printf '%s\n' "$output" |
            awk '
                {
                    original = $0
                    lower = tolower($0)

                    if (lower ~ /^[[:space:]]*predicted[ _-]*(label|class)[[:space:]]*[:=]/ || lower ~ /^[[:space:]]*prediction[[:space:]]*[:=]/) {
                        sub(/^[^:=]*[:=][[:space:]]*/, "", original)
                        sub(/\r$/, "", original)
                        gsub(/^[[:space:]]+|[[:space:]]+$/, "", original)
                        print original
                        exit
                    }
                }
            '
    )"

    DETECTOR_LABEL="$(normalize_label "$raw")"

    if [[ -n "$DETECTOR_LABEL" ]]; then
        return 0
    fi

    # Fallback: mot dong chi chua dung ten lop.
    raw="$(
        printf '%s\n' "$output" |
            awk '
                {
                    original = $0
                    sub(/\r$/, "", original)
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", original)
                    lower = tolower(original)

                    if (lower == "benign" || lower == "locker" || lower == "mediyes" || lower == "winwebsec" || lower == "zbot" || lower == "zeroaccess") {
                        print original
                        exit
                    }
                }
            '
    )"

    DETECTOR_LABEL="$(normalize_label "$raw")"
    [[ -n "$DETECTOR_LABEL" ]]
}

run_detector() {
    local file="$1"

    # ember_scan.py doc truc tiep duoc cac file *.exe.OA, *.exe.OA.OA...
    DETECTOR_OUTPUT="$(python3 "$SCAN_SCRIPT" "$file" 2>&1)"
    DETECTOR_STATUS=$?
    DETECTOR_LABEL=""

    parse_predicted_label "$DETECTOR_OUTPUT"
}

print_detector_error() {
    local file="$1"

    ((ERROR_DETAILS_PRINTED++))

    printf '\n[ERROR] EMBER khong tra ve nhan hop le.\n' >&2
    printf 'File goc   : %s\n' "$file" >&2
    printf 'Exit status: %d\n' "$DETECTOR_STATUS" >&2
    printf '%s\n' '----- Output cua ember_scan.py -----' >&2

    if [[ -n "$DETECTOR_OUTPUT" ]]; then
        printf '%s\n' "$DETECTOR_OUTPUT" | sed -n '1,40p' >&2
    else
        printf '%s\n' '(khong co stdout/stderr)' >&2
    fi

    printf '%s\n' '------------------------------------' >&2
}

check_early_abort() {
    if (( ATTEMPTS >= EARLY_ABORT_ATTEMPTS && SUCCESSFUL_SCANS == 0 )); then
        echo >&2
        echo "[FATAL] $ATTEMPTS file dau tien deu khong scan duoc." >&2
        echo "Script dung som de tranh in hang nghin loi giong nhau." >&2
        echo >&2
        echo "Thu chay truc tiep file vua loi de xem day du thong bao:" >&2
        echo "python3 \"$SCAN_SCRIPT\" \"<duong-dan-file>\"" >&2
        exit 2
    fi
}

validate_environment() {
    if [[ ! -d "$BASE_ROOT" ]]; then
        echo "[FATAL] Khong ton tai BASE_ROOT: $BASE_ROOT" >&2
        exit 1
    fi

    if [[ ! -f "$SCAN_SCRIPT" ]]; then
        echo "[FATAL] Khong tim thay: $SCAN_SCRIPT" >&2
        echo "Hay dat script Bash cung thu muc voi ember_scan.py." >&2
        exit 1
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        echo "[FATAL] Khong tim thay python3 trong PATH." >&2
        exit 1
    fi

}

scan_label_dir() {
    local unit="$1"
    local true_label="$2"
    local label_dir="$3"
    local -a files=()
    local total_files current file pred_label total_key cm_key

    if [[ ! -d "$label_dir" ]]; then
        echo "[WARN] Khong ton tai, bo qua: $label_dir"
        return
    fi

    mapfile -d '' files < <(find "$label_dir" -type f -print0 2>/dev/null)
    total_files="${#files[@]}"
    current=0
    total_key="$unit|$true_label"

    echo
    echo "[+] Dang quet $unit/$true_label ($total_files file)"
    echo "    Thu muc: $label_dir"
    echo "------------------------------------------------------------"

    if (( total_files == 0 )); then
        echo "[WARN] Thu muc khong co file."
        return
    fi

    for file in "${files[@]}"; do
        ((current++))
        ((ATTEMPTS++))
        increment_assoc TOTAL "$total_key"

        printf '\rProgress [%s/%s]: [%d/%d] %s\033[0K' \
            "$unit" "$true_label" "$current" "$total_files" "$(basename "$file")"

        if run_detector "$file"; then
            pred_label="$DETECTOR_LABEL"
            ((SUCCESSFUL_SCANS++))

            cm_key="$unit|$true_label|$pred_label"
            increment_assoc CM "$cm_key"

            if [[ "$pred_label" == "$true_label" ]]; then
                increment_assoc CORRECT "$total_key"
            else
                increment_assoc WRONG "$total_key"

                if [[ "$pred_label" == "Benign" && "$true_label" != "Benign" ]]; then
                    increment_assoc PRED_BENIGN "$total_key"
                fi
            fi
        else
            ((FAILED_SCANS++))
            increment_assoc ERRORS "$total_key"

            if (( ERROR_DETAILS_PRINTED < MAX_ERROR_DETAILS )); then
                print_detector_error "$file"
            fi

            check_early_abort
        fi
    done

    printf '\n[+] Xong %s/%s\n' "$unit" "$true_label"
}

scan_mab_mode() {
    local mode="$1"
    local unit="MAB-$mode"
    local mode_dir="$BASE_ROOT/MAB/$mode"
    local family

    UNITS+=("$unit")

    echo
    echo "################################################################"
    echo "QUET: $unit"
    echo "################################################################"

    if [[ ! -d "$mode_dir" ]]; then
        echo "[WARN] Khong ton tai: $mode_dir"
        return
    fi

    scan_label_dir "$unit" "Benign" "$mode_dir/benign"

    for family in "${MALWARE_LABELS[@]}"; do
        scan_label_dir "$unit" "$family" "$mode_dir/virus/$family"
    done
}

scan_family_dataset() {
    local dataset="$1"
    local dataset_dir="$BASE_ROOT/$dataset"
    local family

    UNITS+=("$dataset")

    echo
    echo "################################################################"
    echo "QUET DATASET: $dataset"
    echo "################################################################"

    if [[ ! -d "$dataset_dir" ]]; then
        echo "[WARN] Khong ton tai: $dataset_dir"
        return
    fi

    for family in "${MALWARE_LABELS[@]}"; do
        scan_label_dir "$dataset" "$family" "$dataset_dir/$family"
    done
}

print_confusion_matrix() {
    local unit="$1"
    local true_label pred key total_key count total errors

    echo
    echo "============================================================"
    echo "CONFUSION MATRIX - $unit"
    echo "Hang = nhan that, cot = nhan EMBER predict"
    echo "============================================================"

    printf "%-15s" "True\\Pred"
    for pred in "${PRED_LABELS[@]}"; do
        printf "| %-12s" "$pred"
    done
    printf "| %-8s | %-8s\n" "Total" "Errors"

    printf "%-15s" "---------------"
    for pred in "${PRED_LABELS[@]}"; do
        printf "+ %-12s" "------------"
    done
    printf "+ %-8s + %-8s\n" "--------" "--------"

    for true_label in "${TRUE_LABELS[@]}"; do
        total_key="$unit|$true_label"
        total="${TOTAL[$total_key]:-0}"
        errors="${ERRORS[$total_key]:-0}"

        # Khong in dong hoan toan rong.
        if (( total == 0 )); then
            continue
        fi

        printf "%-15s" "$true_label"

        for pred in "${PRED_LABELS[@]}"; do
            key="$unit|$true_label|$pred"
            count="${CM[$key]:-0}"
            printf "| %-12s" "$count"
        done

        printf "| %-8s | %-8s\n" "$total" "$errors"
    done
}

print_detail_stats() {
    local unit="$1"
    local true_label key total correct wrong benign errors
    local grand_total=0
    local grand_correct=0
    local grand_wrong=0
    local grand_benign=0
    local grand_errors=0

    echo
    echo "============================================================"
    echo "THONG KE CHI TIET - $unit"
    echo "Wrong = sai nhan; ToBenign = malware bi predict thanh Benign"
    echo "============================================================"

    printf "%-12s | %-7s | %-7s | %-10s | %-7s | %-10s | %-8s | %-10s | %-6s\n" \
        "TrueLabel" "Total" "Correct" "Accuracy" "Wrong" "WrongRate" "ToBenign" "BenignRate" "Errors"

    echo "---------------------------------------------------------------------------------------------------"

    for true_label in "${TRUE_LABELS[@]}"; do
        key="$unit|$true_label"
        total="${TOTAL[$key]:-0}"

        if (( total == 0 )); then
            continue
        fi

        correct="${CORRECT[$key]:-0}"
        wrong="${WRONG[$key]:-0}"
        benign="${PRED_BENIGN[$key]:-0}"
        errors="${ERRORS[$key]:-0}"

        printf "%-12s | %-7s | %-7s | %-10s | %-7s | %-10s | %-8s | %-10s | %-6s\n" \
            "$true_label" "$total" "$correct" "$(calc_percent "$correct" "$total")" \
            "$wrong" "$(calc_percent "$wrong" "$total")" \
            "$benign" "$(calc_percent "$benign" "$total")" "$errors"

        grand_total=$((grand_total + total))
        grand_correct=$((grand_correct + correct))
        grand_wrong=$((grand_wrong + wrong))
        grand_benign=$((grand_benign + benign))
        grand_errors=$((grand_errors + errors))
    done

    echo "---------------------------------------------------------------------------------------------------"

    printf "%-12s | %-7s | %-7s | %-10s | %-7s | %-10s | %-8s | %-10s | %-6s\n" \
        "TOTAL" "$grand_total" "$grand_correct" "$(calc_percent "$grand_correct" "$grand_total")" \
        "$grand_wrong" "$(calc_percent "$grand_wrong" "$grand_total")" \
        "$grand_benign" "$(calc_percent "$grand_benign" "$grand_total")" "$grand_errors"
}

print_global_summary() {
    echo
    echo "============================================================"
    echo "TONG KET TOAN BO LAN CHAY"
    echo "============================================================"
    printf "Tong file da thu       : %d\n" "$ATTEMPTS"
    printf "Scan thanh cong        : %d\n" "$SUCCESSFUL_SCANS"
    printf "Scan loi               : %d\n" "$FAILED_SCANS"
    printf "Ti le scan thanh cong  : %s\n" "$(calc_percent "$SUCCESSFUL_SCANS" "$ATTEMPTS")"
}

main() {
    local mode dataset unit

    validate_environment

    echo "============================================================"
    echo "EMBER DETECTION + EVASION STATISTICS"
    echo "BASE_ROOT   : $BASE_ROOT"
    echo "SCAN_SCRIPT : $SCAN_SCRIPT"
    echo "============================================================"

    for mode in "${MAB_MODES[@]}"; do
        scan_mab_mode "$mode"
    done

    for dataset in "${FAMILY_DATASETS[@]}"; do
        scan_family_dataset "$dataset"
    done

    for unit in "${UNITS[@]}"; do
        print_confusion_matrix "$unit"
        print_detail_stats "$unit"
    done

    print_global_summary

    echo
    echo "============================================================"
    echo "HOAN TAT"
    echo "============================================================"
}

main "$@"
