#!/usr/bin/env bash
set -euo pipefail

# Huong dan:
# Script nay copy cac file sample that nam trong test split sang mot folder rieng.
#
# Chay mac dinh tu root project:
#   bash scripts/copy_test_split.sh
#
# Mac dinh script se doc danh sach test o:
#   data/splits/samples/test.txt
#
# Neu dang dung split co san cho training/evaluation, chay env voi:
#   export MALWARE_RL_SPLIT_FILE=data/splits/samples/split.json
#
# Bien MALWARE_RL_SPLIT_FILE dung file split.json co ca "train" va "test".
# Script nay chi copy file sample nen doc file test.txt.
#
# File sample goc duoc lay tu:
#   malware_rl/envs/utils/samples
#
# Output mac dinh:
#   data/test_samples
#
# Neu muon chi dinh duong dan rieng:
#   bash scripts/copy_test_split.sh <split_file> <source_samples_dir> <output_dir>
#
# Vi du:
#   bash scripts/copy_test_split.sh data/splits/samples/test.txt malware_rl/envs/utils/samples data/test_samples
#
# Tren Linux co the cap quyen execute roi chay:
#   chmod +x scripts/copy_test_split.sh
#   ./scripts/copy_test_split.sh

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'EOF'
Copy real sample files listed in the saved test split.

Usage:
  bash scripts/copy_test_split.sh
  bash scripts/copy_test_split.sh <split_file> <source_samples_dir> <output_dir>

Default paths:
  split_file:         data/splits/samples/test.txt
  source_samples_dir: malware_rl/envs/utils/samples
  output_dir:         data/test_samples

Related env option:
  export MALWARE_RL_SPLIT_FILE=data/splits/samples/split.json

Notes:
  MALWARE_RL_SPLIT_FILE is used by the Python env loader and points to split.json.
  This copy script reads test.txt because it only needs the test sample list.

Example:
  bash scripts/copy_test_split.sh data/splits/samples/test.txt malware_rl/envs/utils/samples data/test_samples

Linux:
  chmod +x scripts/copy_test_split.sh
  ./scripts/copy_test_split.sh
EOF
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SPLIT_FILE="${1:-$PROJECT_ROOT/data/splits/samples/test.txt}"
SOURCE_DIR="${2:-$PROJECT_ROOT/malware_rl/envs/utils/samples}"
OUTPUT_DIR="${3:-$PROJECT_ROOT/data/test_samples}"

if [[ ! -f "$SPLIT_FILE" ]]; then
  echo "Split file not found: $SPLIT_FILE" >&2
  exit 1
fi

if [[ ! -d "$SOURCE_DIR" ]]; then
  echo "Source samples directory not found: $SOURCE_DIR" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

copied=0
missing=0

while IFS= read -r sample || [[ -n "$sample" ]]; do
  [[ -z "$sample" ]] && continue

  src="$SOURCE_DIR/$sample"
  dst="$OUTPUT_DIR/$sample"

  if [[ ! -f "$src" ]]; then
    echo "Missing sample: $src" >&2
    missing=$((missing + 1))
    continue
  fi

  mkdir -p "$(dirname "$dst")"
  cp -p "$src" "$dst"
  copied=$((copied + 1))
done < "$SPLIT_FILE"

echo "Copied $copied test samples to: $OUTPUT_DIR"

if [[ "$missing" -gt 0 ]]; then
  echo "Missing $missing samples. Check messages above." >&2
  exit 2
fi
