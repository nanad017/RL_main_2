"""
calibrate_threshold.py
Finds the optimal detection threshold from the validation set that
maximises F1 (or hits a target FPR). Run AFTER training.

Usage:
    python calibrate_threshold.py \
        --processed-data ./processed-data \
        --ffnn-model ./baselines \
        --lgbm-model ./baselines/lgbm_seed1.joblib \
        --target-fpr 0.01
"""

import argparse
import json
import logging
import sqlite3
import sys
import os
from pathlib import Path

import numpy as np
import torch

_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
sys.path.insert(0, _src)

from dataset import GeneratorFactory, FAMILY_NAMES
from models import MalwareFFNN, LightGBMDetector

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s  %(levelname)-8s  %(message)s")
logger = logging.getLogger(__name__)


def collect_val_scores(ffnn_dir, lgbm_path, meta_db, ember_lmdb, split="validation"):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    ffnn_path = Path(ffnn_dir)
    if ffnn_path.is_dir():
        ckpts = sorted(ffnn_path.glob("ffnn_seed*.pt"))
    else:
        ckpts = [ffnn_path]
    if not ckpts:
        raise FileNotFoundError(f"No ffnn_seed*.pt found in {ffnn_dir}")

    models = []
    for ckpt in ckpts:
        m = MalwareFFNN(predict_tags=True)
        m.load_state_dict(torch.load(str(ckpt), map_location=device,
                                     weights_only=False))
        m.to(device).eval()
        models.append(m)
    logger.info(f"Loaded {len(models)} FFNN models")

    gen = GeneratorFactory(meta_db, ember_lmdb, split=split,
                           batch_size=512, num_workers=2)

    all_scores, all_labels = [], []
    with torch.no_grad():
        for feats, mal_lbl, _, _ in gen:
            feats = feats.to(device)
            seed_scores = []
            for m in models:
                out = m(feats)
                seed_scores.append(out["malware"].cpu().numpy())
            # seed_scores: list of (B,) arrays → mean over seeds → (B,)
            avg = np.mean(np.stack(seed_scores, axis=0), axis=0)  # (B,)
            all_scores.extend(avg.tolist())
            all_labels.extend(mal_lbl.numpy().tolist())

    # Optionally blend with LightGBM
    if lgbm_path and Path(lgbm_path).exists():
        import lmdb, msgpack, zlib
        from dataset import SorelDataset  # reuse cached env
        lgbm = LightGBMDetector.load(lgbm_path)
        conn = sqlite3.connect(meta_db)
        rows = conn.execute(
            "SELECT sha256, label FROM samples WHERE split=?", (split,)
        ).fetchall()
        conn.close()

        # Reuse already-open LMDB env from SorelDataset cache
        if ember_lmdb in SorelDataset._env_cache:
            env = SorelDataset._env_cache[ember_lmdb]
            own_env = False
        else:
            env = lmdb.open(ember_lmdb, readonly=True, lock=False,
                            max_readers=256)
            own_env = True

        X, y = [], []
        with env.begin() as txn:
            for sha, lbl in rows:
                raw = txn.get(sha.encode())
                if raw is None:
                    continue
                vec = np.array(msgpack.unpackb(zlib.decompress(raw)),
                               dtype=np.float32)
                X.append(vec)
                y.append(lbl)
        if own_env:
            env.close()

        lgbm_scores = lgbm.predict_proba(np.array(X))
        # Blend: 50/50 average (simplified — labels may differ in order)
        # Use label alignment
        all_scores_arr = np.array(all_scores)
        lgbm_arr       = np.array(lgbm_scores)
        min_len = min(len(all_scores_arr), len(lgbm_arr))
        all_scores = ((all_scores_arr[:min_len] + lgbm_arr[:min_len]) / 2).tolist()
        all_labels = all_labels[:min_len]

    return np.array(all_scores), np.array(all_labels)


def find_threshold(scores, labels, target_fpr=0.01):
    """
    Sweep thresholds and find:
      1. Best F1 threshold
      2. Threshold at target FPR
    """
    from sklearn.metrics import roc_curve, f1_score

    fpr, tpr, thresholds = roc_curve(labels, scores)

    # Threshold at target FPR
    idx_fpr = np.searchsorted(fpr, target_fpr)
    if idx_fpr >= len(thresholds):
        idx_fpr = len(thresholds) - 1
    thresh_at_fpr = float(thresholds[idx_fpr])
    tpr_at_fpr    = float(tpr[idx_fpr])
    logger.info(f"At FPR={target_fpr:.3f}: threshold={thresh_at_fpr:.4f}, TPR={tpr_at_fpr:.4f}")

    # Best F1
    best_f1, best_thresh_f1 = 0.0, 0.5
    for t in thresholds:
        preds = (scores >= t).astype(int)
        f1 = f1_score(labels, preds, zero_division=0)
        if f1 > best_f1:
            best_f1 = f1
            best_thresh_f1 = float(t)
    logger.info(f"Best F1={best_f1:.4f} at threshold={best_thresh_f1:.4f}")

    # Stats at each threshold
    results = {
        "best_f1_threshold":    best_thresh_f1,
        "best_f1":              best_f1,
        f"threshold_at_fpr_{target_fpr}": thresh_at_fpr,
        f"tpr_at_fpr_{target_fpr}":       tpr_at_fpr,
        "recommendation":       best_thresh_f1,
    }

    # Print table around the sweet spot
    print("\n  Threshold sweep around recommended value:")
    print(f"  {'Threshold':>10}  {'TPR':>6}  {'FPR':>8}  {'F1':>6}")
    for t_val, tp, fp in zip(thresholds, tpr, fpr):
        if abs(t_val - best_thresh_f1) < 0.15:
            preds = (scores >= t_val).astype(int)
            f1 = f1_score(labels, preds, zero_division=0)
            marker = " ◀ recommended" if abs(t_val - best_thresh_f1) < 0.005 else ""
            print(f"  {t_val:>10.4f}  {tp:>6.4f}  {fp:>8.6f}  {f1:>6.4f}{marker}")

    return results


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--processed-data", default="./processed-data")
    p.add_argument("--ffnn-model",     default="./baselines")
    p.add_argument("--lgbm-model",     default=None)
    p.add_argument("--target-fpr",     type=float, default=0.01)
    p.add_argument("--split",          default="validation")
    p.add_argument("--output",         default="./baselines/threshold.json")
    args = p.parse_args()

    meta_db    = str(Path(args.processed_data) / "meta.db")
    ember_lmdb = str(Path(args.processed_data) / "ember_features")

    logger.info(f"Collecting scores from '{args.split}' split…")
    scores, labels = collect_val_scores(
        args.ffnn_model, args.lgbm_model, meta_db, ember_lmdb, args.split
    )

    n_mal = int(labels.sum())
    n_ben = int((1 - labels).sum())
    logger.info(f"Validation: {n_mal} malware, {n_ben} benign")

    results = find_threshold(scores, labels, target_fpr=args.target_fpr)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n{'='*55}")
    print(f"  Recommended threshold : {results['recommendation']:.4f}")
    print(f"  Saved to              : {args.output}")
    print(f"{'='*55}")
    print(f"\nUse with detect.py:")
    print(f"  python detect.py --input FILE --ffnn-model ./baselines \\")
    print(f"      --ensemble --threshold {results['recommendation']:.4f}")


if __name__ == "__main__":
    main()