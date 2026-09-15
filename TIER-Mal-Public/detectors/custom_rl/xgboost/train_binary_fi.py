#!/usr/bin/env python3
"""Train a binary malware detector from fi_dataset using static PE features.

Label mapping:
- 0: benign
- 1: malware (all families under virus/)
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

import joblib
import numpy as np
import pefile
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from tqdm import tqdm

try:
    import xgboost as xgb
except Exception:  # pragma: no cover
    xgb = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train binary detector on fi_dataset")
    parser.add_argument("--data-root", type=Path, default=Path("fi_dataset"), help="Dataset root")
    parser.add_argument("--max-train", type=int, default=0, help="Cap training samples (0 = no cap)")
    parser.add_argument("--max-val", type=int, default=0, help="Cap validation samples (0 = no cap)")
    parser.add_argument(
        "--model",
        choices=["xgboost", "random_forest"],
        default="xgboost",
        help="Model to train",
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts"),
        help="Directory for model and metrics",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Decision threshold for malware probability",
    )
    parser.add_argument(
        "--tune-threshold",
        action="store_true",
        help="Tune threshold on validation set before final evaluation",
    )
    parser.add_argument(
        "--threshold-metric",
        choices=["f1", "balanced_accuracy", "precision", "recall"],
        default="f1",
        help="Metric used when tuning threshold",
    )
    parser.add_argument(
        "--min-recall",
        type=float,
        default=0.0,
        help="Minimum recall constraint during threshold tuning",
    )
    return parser.parse_args()


def collect_files(split_dir: Path) -> Tuple[List[Path], np.ndarray]:
    benign = sorted((split_dir / "benign").rglob("*.exe"))
    malware = sorted((split_dir / "virus").rglob("*.exe"))
    files = benign + malware
    labels = np.array([0] * len(benign) + [1] * len(malware), dtype=np.int32)
    return files, labels


def maybe_subsample(
    file_paths: Sequence[Path], labels: np.ndarray, max_samples: int, seed: int
) -> Tuple[List[Path], np.ndarray]:
    if max_samples <= 0 or len(file_paths) <= max_samples:
        return list(file_paths), labels

    rng = np.random.default_rng(seed)
    idx = np.arange(len(file_paths))

    benign_idx = idx[labels == 0]
    malware_idx = idx[labels == 1]

    # Keep class ratio after subsampling.
    benign_take = int(max_samples * (len(benign_idx) / len(idx)))
    benign_take = max(1, min(benign_take, len(benign_idx)))
    malware_take = max_samples - benign_take
    malware_take = max(1, min(malware_take, len(malware_idx)))

    chosen = np.concatenate(
        [
            rng.choice(benign_idx, size=benign_take, replace=False),
            rng.choice(malware_idx, size=malware_take, replace=False),
        ]
    )
    rng.shuffle(chosen)

    sampled_files = [file_paths[i] for i in chosen]
    sampled_labels = labels[chosen]
    return sampled_files, sampled_labels


def _safe_ratio(numer: float, denom: float) -> float:
    return float(numer / denom) if denom > 0 else 0.0


def extract_static_features(path: Path) -> np.ndarray:
    """Extract robust, fixed-size static features from a PE file.

    Feature vector layout:
    - 256 dims: normalized byte histogram
    - 7 dims: generic byte-level statistics
    - 8 dims: PE structure/import statistics
    Total: 271 features
    """
    bytez = path.read_bytes()
    arr = np.frombuffer(bytez, dtype=np.uint8)
    if arr.size == 0:
        raise ValueError("Empty file")

    hist = np.bincount(arr, minlength=256).astype(np.float32)
    hist /= max(1, arr.size)

    probs = hist[hist > 0]
    entropy = float(-(probs * np.log2(probs)).sum())
    printable = ((arr >= 32) & (arr <= 126)).sum()

    raw_stats = np.array(
        [
            math.log1p(arr.size),
            float(arr.mean()),
            float(arr.std()),
            float(arr.min()),
            float(arr.max()),
            _safe_ratio(int((arr == 0).sum()), arr.size),
            _safe_ratio(int(printable), arr.size),
        ],
        dtype=np.float32,
    )

    pe_stats = np.zeros(8, dtype=np.float32)
    try:
        pe = pefile.PE(data=bytez, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])

        sections = pe.sections if pe.sections is not None else []
        sec_entropies = [float(s.get_entropy()) for s in sections]
        sec_raw_sizes = [float(s.SizeOfRawData) for s in sections]
        sec_virt_sizes = [float(s.Misc_VirtualSize) for s in sections]

        import_dlls = 0
        import_funcs = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") and pe.DIRECTORY_ENTRY_IMPORT:
            import_dlls = len(pe.DIRECTORY_ENTRY_IMPORT)
            import_funcs = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)

        pe_stats = np.array(
            [
                float(len(sections)),
                float(np.mean(sec_entropies)) if sec_entropies else 0.0,
                float(np.std(sec_entropies)) if sec_entropies else 0.0,
                float(np.mean(sec_raw_sizes)) if sec_raw_sizes else 0.0,
                float(np.mean(sec_virt_sizes)) if sec_virt_sizes else 0.0,
                float(import_dlls),
                float(import_funcs),
                float(getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0)),
            ],
            dtype=np.float32,
        )
    except Exception:
        # Keep zero-filled PE stats for malformed/unparsable executables.
        pass

    return np.concatenate([hist, raw_stats, pe_stats]).astype(np.float32)


def extract_features(
    file_paths: Iterable[Path], labels: np.ndarray
) -> Tuple[np.ndarray, np.ndarray, int]:
    x_rows: List[np.ndarray] = []
    y_rows: List[int] = []
    skipped = 0

    for path, label in tqdm(
        zip(file_paths, labels),
        total=len(labels),
        desc="Extracting static features",
    ):
        try:
            features = extract_static_features(path)
            x_rows.append(features)
            y_rows.append(int(label))
        except Exception:
            skipped += 1

    if not x_rows:
        raise RuntimeError("No features extracted. Check dataset and dependencies.")

    x = np.vstack(x_rows)
    y = np.asarray(y_rows, dtype=np.int32)
    return x, y, skipped


def build_model(model_name: str, seed: int):
    if model_name == "random_forest":
        return RandomForestClassifier(
            n_estimators=300,
            max_depth=None,
            n_jobs=-1,
            random_state=seed,
            class_weight="balanced",
        )

    if xgb is None:
        raise ImportError("xgboost is not installed. Use --model random_forest or install xgboost.")

    return xgb.XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        eval_metric="logloss",
        tree_method="hist",
        n_jobs=-1,
        random_state=seed,
    )


def tune_threshold(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    optimize: str,
    min_recall: float,
) -> Tuple[float, dict]:
    best_score = -1.0
    best_threshold = 0.5
    best_metrics = {}

    for threshold in np.linspace(0.01, 0.99, 99):
        y_pred = (y_prob >= threshold).astype(np.int32)
        recall = float(recall_score(y_true, y_pred, zero_division=0))
        if recall < min_recall:
            continue

        metrics = {
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall": recall,
            "f1": float(f1_score(y_true, y_pred, zero_division=0)),
            "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        }

        score = metrics[optimize]
        if score > best_score:
            best_score = score
            best_threshold = float(threshold)
            best_metrics = metrics

    if best_score < 0:
        raise ValueError("No threshold satisfies constraints. Lower --min-recall.")

    return best_threshold, best_metrics


def evaluate(model, x_val: np.ndarray, y_val: np.ndarray, threshold: float = 0.5) -> dict:
    y_prob = model.predict_proba(x_val)[:, 1]
    y_pred = (y_prob >= threshold).astype(np.int32)

    return {
        "threshold": float(threshold),
        "accuracy": float(accuracy_score(y_val, y_pred)),
        "precision": float(precision_score(y_val, y_pred, zero_division=0)),
        "recall": float(recall_score(y_val, y_pred, zero_division=0)),
        "f1": float(f1_score(y_val, y_pred, zero_division=0)),
        "balanced_accuracy": float(balanced_accuracy_score(y_val, y_pred)),
        "roc_auc": float(roc_auc_score(y_val, y_prob)),
        "confusion_matrix": confusion_matrix(y_val, y_pred).tolist(),
    }


def main() -> None:
    args = parse_args()
    np.random.seed(args.seed)

    train_dir = args.data_root / "train"
    val_dir = args.data_root / "val"

    if not train_dir.exists() or not val_dir.exists():
        raise FileNotFoundError(f"Missing dataset splits under {args.data_root}")

    train_files, train_labels = collect_files(train_dir)
    val_files, val_labels = collect_files(val_dir)

    train_files, train_labels = maybe_subsample(train_files, train_labels, args.max_train, args.seed)
    val_files, val_labels = maybe_subsample(val_files, val_labels, args.max_val, args.seed)

    print(f"Train files: {len(train_files):,} | benign={(train_labels == 0).sum():,} malware={(train_labels == 1).sum():,}")
    print(f"Val files:   {len(val_files):,} | benign={(val_labels == 0).sum():,} malware={(val_labels == 1).sum():,}")

    print("\n[1/3] Extracting training features...")
    x_train, y_train, skipped_train = extract_features(train_files, train_labels)

    print("\n[2/3] Extracting validation features...")
    x_val, y_val, skipped_val = extract_features(val_files, val_labels)

    print(f"Skipped files: train={skipped_train}, val={skipped_val}")
    print(f"Feature shapes: train={x_train.shape}, val={x_val.shape}")

    print("\n[3/3] Training model...")
    model = build_model(args.model, args.seed)
    model.fit(x_train, y_train)

    threshold = float(args.threshold)
    if args.tune_threshold:
        y_prob_val = model.predict_proba(x_val)[:, 1]
        threshold, threshold_metrics = tune_threshold(
            y_val,
            y_prob_val,
            optimize=args.threshold_metric,
            min_recall=args.min_recall,
        )
        print(
            "Tuned threshold "
            f"({args.threshold_metric}, min_recall={args.min_recall:.2f}): {threshold:.2f} "
            f"| precision={threshold_metrics['precision']:.4f} "
            f"recall={threshold_metrics['recall']:.4f} "
            f"f1={threshold_metrics['f1']:.4f}"
        )

    metrics = evaluate(model, x_val, y_val, threshold=threshold)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    model_path = args.output_dir / f"binary_{args.model}.joblib"
    metrics_path = args.output_dir / f"metrics_{args.model}.json"

    joblib.dump(model, model_path)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print("\nTraining complete")
    print(f"Model saved to:   {model_path}")
    print(f"Metrics saved to: {metrics_path}")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
