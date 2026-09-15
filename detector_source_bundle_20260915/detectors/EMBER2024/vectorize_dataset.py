import argparse
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import thrember


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Vectorize dataset jsonl thanh X_*.dat va y_*.dat."
    )
    parser.add_argument("data_dir", help="Thu muc chua pe_train.jsonl, pe_test.jsonl, pe_challenge.jsonl")
    parser.add_argument("--label-type", default="family", help="Loai nhan de vectorize")
    parser.add_argument("--class-min", type=int, default=1, help="So mau toi thieu cho moi class")
    args = parser.parse_args()

    thrember.create_vectorized_features(
        args.data_dir,
        label_type=args.label_type,
        class_min=args.class_min,
    )


if __name__ == "__main__":
    main()
