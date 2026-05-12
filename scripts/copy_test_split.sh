#!/usr/bin/env bash
set -euo pipefail

# Copy real sample files listed in the saved test split.
# Usage:
#   bash scripts/copy_test_split.sh
#   bash scripts/copy_test_split.sh <split_file> <source_samples_dir> <output_dir>

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
