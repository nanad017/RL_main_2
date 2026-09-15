import argparse
import json
import sys
from pathlib import Path

import lightgbm as lgb
import numpy as np

SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import thrember

MODEL_DIR = SCRIPT_DIR / "models"
DATASET_JSON_DIR = SCRIPT_DIR / "dataset_json"
DEFAULT_MODEL = "custom_multiclass.model"
DEFAULT_LABELS = str(DATASET_JSON_DIR / "family_labels.json")


def load_model(model_name: str) -> lgb.Booster:
    model_path = Path(model_name)
    if not model_path.exists() and not model_path.is_absolute():
        model_path = MODEL_DIR / model_name
    if not model_path.exists():
        raise FileNotFoundError(f"Không tìm thấy model: {model_path}")
    return lgb.Booster(model_file=str(model_path))


def load_labels(labels_path: str) -> list[str]:
    meta_path = Path(labels_path)
    if not meta_path.exists() and not meta_path.is_absolute():
        meta_path = MODEL_DIR / labels_path
    if not meta_path.exists():
        raise FileNotFoundError(f"Khong tim thay file labels: {meta_path}")
    with meta_path.open("r") as fin:
        meta = json.load(fin)
    return list(meta["labels"])


def extract_features(path: Path) -> np.ndarray:
    data = path.read_bytes()
    extractor = thrember.PEFeatureExtractor()
    return np.array(extractor.feature_vector(data), dtype=np.float32)


def main():
    parser = argparse.ArgumentParser(description="Scan PE bang 1 model da lop: benign + malware families.")
    parser.add_argument("file", help="Duong dan toi file PE (exe/dll)")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Model multiclass")
    parser.add_argument("--labels", default=DEFAULT_LABELS, help="File json chua danh sach nhan")
    args = parser.parse_args()

    pe_path = Path(args.file).resolve()
    if not pe_path.is_file():
        print(f"[!] Không tìm thấy file: {pe_path}")
        return

    model = load_model(args.model)
    labels = load_labels(args.labels)
    features = extract_features(pe_path)

    print(f"[+] Scan file: {pe_path}")
    scores = model.predict([features])[0]
    pred_idx = int(np.argmax(scores))
    pred_label = labels[pred_idx] if pred_idx < len(labels) else f"class_{pred_idx}"
    pred_score = float(scores[pred_idx])

    print("-" * 60)
    print(f"File: {pe_path}")
    print(f"Model: {args.model}")
    print(f"Predicted label: {pred_label}")
    print(f"Confidence: {pred_score:.6f}")
    print("-" * 60)


if __name__ == "__main__":
    main()
