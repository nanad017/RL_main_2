#!/usr/bin/env bash
# ============================================================
# run_mab_sorel_v2.sh — Batch MAB detection với resume support
#
# Usage:
#   cd ~/detector/sorel_multi
#   conda activate sorel-malware-detector
#   bash run_mab_sorel_v2.sh
# ============================================================

set -uo pipefail

# ── Cấu hình ─────────────────────────────────────────────────
DETECTOR_DIR="$HOME/detector/sorel_multi"
MAB_DIR="$HOME/RL/dataset/RL_evasion/MAB"
FFNN_MODEL="$DETECTOR_DIR/baselines"
LGBM_MODEL="$DETECTOR_DIR/baselines/lgbm_seed1.joblib"
THRESHOLD="0.8327"
OUT_DIR="$DETECTOR_DIR/results/mab_batch"
PY="python"   # conda env dùng "python", không phải "python3"

FAMILIES=("Locker" "Mediyes" "Winwebsec" "Zbot" "Zeroaccess")
SETS=("evasive" "minimal")

mkdir -p "$OUT_DIR"

# ── Helper: detect 1 file → append vào JSONL ─────────────────
run_detect_py() {
    local filepath="$1"
    local true_family="$2"
    local jsonl="$3"
    local tmpjson
    tmpjson=$(mktemp /tmp/sorel_XXXXXX.json)

    $PY "$DETECTOR_DIR/detect.py" \
        --input "$filepath" \
        --ffnn-model "$FFNN_MODEL" \
        --lgbm-model "$LGBM_MODEL" \
        --ensemble \
        --threshold "$THRESHOLD" \
        --output "$tmpjson" 2>/dev/null

    $PY -c "
import json
data = json.load(open('$tmpjson'))
r = data['results'][0]
r['true_family'] = '$true_family'
with open('$jsonl', 'a') as f:
    f.write(json.dumps(r) + '\n')
verdict = r.get('verdict', '?')
family  = r.get('malware_family') or 'benign'
conf    = r.get('confidence', 0)
print(f'{verdict} {family} {conf:.1f}%')
"
    local rc=$?
    rm -f "$tmpjson"
    return $rc
}

# ── Helper: đọc tên file từ JSONL để resume ──────────────────
get_done_files() {
    local jsonl="$1"
    [[ -f "$jsonl" ]] || return
    $PY -c "
import json
with open('$jsonl') as f:
    for line in f:
        line = line.strip()
        if line:
            try:
                print(json.loads(line).get('file',''))
            except:
                pass
"
}

# ═══════════════════════════════════════════════════════════════
# MAIN LOOP
# ═══════════════════════════════════════════════════════════════
for SET in "${SETS[@]}"; do

    JSONL="$OUT_DIR/${SET}_results.jsonl"
    REPORT="$OUT_DIR/${SET}_report.txt"

    echo ""
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║  SET: $SET"
    echo "╚══════════════════════════════════════════════════════╝"

    declare -A DONE_FILES=()
    if [[ -f "$JSONL" ]]; then
        while IFS= read -r fname; do
            [[ -n "$fname" ]] && DONE_FILES["$fname"]=1
        done < <(get_done_files "$JSONL")
        echo "  ▸ Resume: ${#DONE_FILES[@]} file(s) đã xử lý → SKIP"
    else
        echo "  ▸ Bắt đầu mới"
    fi

    total=0; skipped=0; success=0; failed=0

    for FAMILY in "${FAMILIES[@]}"; do
        FAMILY_DIR="$MAB_DIR/$SET/$FAMILY"
        [[ -d "$FAMILY_DIR" ]] || { echo "  [WARN] Không tìm thấy: $FAMILY_DIR"; continue; }

        echo ""
        echo "  ── Family: $FAMILY ──"

        for filepath in "$FAMILY_DIR"/*; do
            [[ -f "$filepath" ]] || continue
            fname=$(basename "$filepath")
            total=$((total + 1))

            if [[ -v DONE_FILES["$fname"] ]]; then
                echo "  [SKIP] $fname"
                skipped=$((skipped + 1))
                continue
            fi

            echo -n "  [RUN]  $fname ... "
            verdict=$(run_detect_py "$filepath" "$FAMILY" "$JSONL" 2>/dev/null)
            if [[ $? -eq 0 && -n "$verdict" ]]; then
                success=$((success + 1))
                echo "→ $verdict"
            else
                echo "→ ERROR"
                echo "{\"file\": \"$fname\", \"true_family\": \"$FAMILY\", \"error\": \"detection failed\"}" >> "$JSONL"
                failed=$((failed + 1))
            fi
        done
    done

    unset DONE_FILES

    echo ""
    echo "  ▸ $total total | $skipped skipped | $success OK | $failed errors"

    # ── Báo cáo thống kê ─────────────────────────────────────
    $PY - "$JSONL" "$SET" > "$REPORT" << 'PYEOF'
import json, sys
from collections import defaultdict

jsonl_path = sys.argv[1]
set_name   = sys.argv[2]
FAMILIES   = ["Locker", "Mediyes", "Winwebsec", "Zbot", "Zeroaccess"]

records = []
with open(jsonl_path) as f:
    for line in f:
        line = line.strip()
        if line:
            try:
                records.append(json.loads(line))
            except Exception:
                pass

by_family = defaultdict(list)
for r in records:
    by_family[r.get("true_family", "UNKNOWN")].append(r)

SEP1 = "=" * 70
SEP2 = "-" * 70

def predicted_family(r):
    if "error" in r:
        return None
    if r.get("verdict") == "BENIGN":
        return "benign"
    return r.get("malware_family") or "unknown"

lines = []
lines.append(SEP1)
lines.append(f"  MAB DETECTION REPORT (sorel) -- {set_name.upper()}")
lines.append(f"  Total records : {len(records)}")
lines.append(SEP1)

grand = {"total": 0, "correct": 0, "wrong": 0, "error": 0}
all_wrong = []

for fam in FAMILIES:
    recs = by_family.get(fam, [])
    if not recs:
        continue

    n_total   = len(recs)
    n_error   = sum(1 for r in recs if "error" in r)
    n_correct = sum(1 for r in recs
                    if "error" not in r and
                    (predicted_family(r) or "").lower() == fam.lower())
    n_wrong   = n_total - n_error - n_correct
    acc       = n_correct / n_total * 100 if n_total else 0

    grand["total"]   += n_total
    grand["correct"] += n_correct
    grand["wrong"]   += n_wrong
    grand["error"]   += n_error

    lines.append(f"\n  True Family: {fam}")
    lines.append(f"    Total   : {n_total}")
    lines.append(f"    Correct : {n_correct}  ({acc:.1f}%)")
    lines.append(f"    Wrong   : {n_wrong}")
    lines.append(f"    Error   : {n_error}")

    wrong_recs = [r for r in recs
                  if "error" not in r and
                  (predicted_family(r) or "").lower() != fam.lower()]
    if wrong_recs:
        lines.append(f"    Wrong files:")
        for r in wrong_recs:
            pred = predicted_family(r) or "unknown"
            conf = r.get("confidence", 0)
            lines.append(f"      - {r['file']}")
            lines.append(f"          predicted={pred}  conf={conf:.1f}%")
            all_wrong.append((fam, r["file"], pred, conf))

g_total = grand["total"]
g_acc   = grand["correct"] / g_total * 100 if g_total else 0

lines.append("")
lines.append(SEP1)
lines.append("  SUMMARY TABLE")
lines.append(SEP1)
lines.append(f"  {'Family':<14} {'Total':>6} {'Correct':>8} {'Wrong':>7} {'Error':>7} {'Acc':>8}")
lines.append("  " + SEP2)
for fam in FAMILIES:
    recs = by_family.get(fam, [])
    if not recs:
        continue
    n = len(recs)
    e = sum(1 for r in recs if "error" in r)
    c = sum(1 for r in recs if "error" not in r and (predicted_family(r) or "").lower() == fam.lower())
    w = n - e - c
    a = c / n * 100 if n else 0
    lines.append(f"  {fam:<14} {n:>6} {c:>8} {w:>7} {e:>7} {a:>7.1f}%")
lines.append("  " + SEP2)
lines.append(f"  {'TOTAL':<14} {g_total:>6} {grand['correct']:>8} {grand['wrong']:>7} {grand['error']:>7} {g_acc:>7.1f}%")
lines.append(SEP1)

if all_wrong:
    lines.append("")
    lines.append("  DANH SACH FILE DETECT SAI:")
    lines.append(f"  {'True':^12} {'Predicted':^14} {'Conf':>6}  File")
    lines.append("  " + SEP2)
    for tf, fname, pred, conf in sorted(all_wrong, key=lambda x: x[0]):
        lines.append(f"  {tf:<12} {pred:<14} {conf:>5.1f}%  {fname}")
    lines.append(SEP1)

print("\n".join(lines))
PYEOF

    echo ""
    echo "  ▸ Report da luu: $REPORT"
    echo ""
    cat "$REPORT"

done

echo ""
echo "ALL DONE"
echo "Ket qua: $OUT_DIR"