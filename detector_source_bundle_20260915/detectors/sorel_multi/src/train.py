"""
train.py — SOREL-20M style training script
Usage:
    # Step 1 – build processed-data (only once)
    python train.py --build-db --dataset-root ./dataset --processed-data ./processed-data

    # Step 2 – train FFNN (5 seeds, mirrors SOREL paper)
    python train.py --model ffnn --processed-data ./processed-data --output-dir ./baselines

    # Step 3 – train LightGBM
    python train.py --model lgbm --processed-data ./processed-data --output-dir ./baselines
"""

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Dict, List

import numpy as np
import torch
import torch.optim as optim
from sklearn.metrics import roc_auc_score

# Allow running from project root
# Only insert src/ to avoid circular imports
_src = str(Path(__file__).resolve().parent)
if _src not in sys.path:
    sys.path.insert(0, _src)

from dataset import (
    EMBER_FEATURE_DIM, NUM_FAMILIES, NUM_TAGS,
    SorelDataset, GeneratorFactory, build_databases, FAMILY_LABELS
)
from models import MalwareFFNN, MultiTargetLoss, LightGBMDetector, LIGHTGBM_CONFIG

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

SEEDS: List[int] = [1, 2, 3, 4, 5]   # mirrors SOREL paper


# ═══════════════════════════════════════════════════════════════════════════════
# FFNN training
# ═══════════════════════════════════════════════════════════════════════════════

def train_ffnn_one_seed(
    seed: int,
    meta_db: str,
    ember_lmdb: str,
    output_dir: str,
    epochs: int = 15,
    batch_size: int = 512,
    lr: float = 1e-3,
    predict_tags: bool = True,
    num_workers: int = 4,
    device_str: str = "auto",
) -> Dict:
    """Train one FFNN model with a fixed random seed."""
    torch.manual_seed(seed)
    np.random.seed(seed)

    if device_str == "auto":
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    else:
        device = torch.device(device_str)
    logger.info(f"[seed={seed}] Device: {device}")

    # Generators
    train_gen = GeneratorFactory(
        meta_db, ember_lmdb, split="train",
        batch_size=batch_size, num_workers=num_workers,
        predict_tags=predict_tags,
    )
    val_gen = GeneratorFactory(
        meta_db, ember_lmdb, split="validation",
        batch_size=batch_size, num_workers=num_workers,
        predict_tags=predict_tags,
    )

    model = MalwareFFNN(predict_tags=predict_tags).to(device)
    criterion = MultiTargetLoss(predict_tags=predict_tags)
    optimizer = optim.Adam(model.parameters(), lr=lr)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    best_auc   = 0.0
    best_epoch = 0
    history    = []

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    ckpt_path = output_dir / f"ffnn_seed{seed}.pt"

    for epoch in range(1, epochs + 1):
        # ── Train ────────────────────────────────────────────────────────────
        model.train()
        t0 = time.time()
        train_loss = 0.0
        n_batches  = 0

        for feats, mal_lbl, fam_lbl, tag_lbl in train_gen:
            feats   = feats.to(device)
            mal_lbl = mal_lbl.to(device)
            fam_lbl = fam_lbl.to(device)
            tag_lbl = tag_lbl.to(device)

            optimizer.zero_grad()
            outputs = model(feats)
            loss, _ = criterion(outputs, mal_lbl, fam_lbl, tag_lbl)
            loss.backward()
            optimizer.step()

            train_loss += loss.item()
            n_batches  += 1

        scheduler.step()
        avg_train_loss = train_loss / max(n_batches, 1)

        # ── Validate ─────────────────────────────────────────────────────────
        model.eval()
        all_scores, all_labels = [], []
        val_loss   = 0.0
        n_val_batches = 0

        with torch.no_grad():
            for feats, mal_lbl, fam_lbl, tag_lbl in val_gen:
                feats   = feats.to(device)
                mal_lbl = mal_lbl.to(device)
                fam_lbl = fam_lbl.to(device)
                tag_lbl = tag_lbl.to(device)

                outputs = model(feats)
                loss, _ = criterion(outputs, mal_lbl, fam_lbl, tag_lbl)
                val_loss += loss.item()
                n_val_batches += 1

                all_scores.extend(outputs["malware"].cpu().numpy())
                all_labels.extend(mal_lbl.cpu().numpy())

        avg_val_loss = val_loss / max(n_val_batches, 1)

        try:
            val_auc = roc_auc_score(all_labels, all_scores)
        except Exception:
            val_auc = 0.0

        elapsed = time.time() - t0
        logger.info(
            f"[seed={seed}] Epoch {epoch:>2}/{epochs} | "
            f"train_loss={avg_train_loss:.4f}  val_loss={avg_val_loss:.4f}  "
            f"val_AUC={val_auc:.4f}  ({elapsed:.1f}s)"
        )

        history.append({
            "epoch": epoch,
            "train_loss": avg_train_loss,
            "val_loss": avg_val_loss,
            "val_auc": val_auc,
        })

        if val_auc > best_auc:
            best_auc   = val_auc
            best_epoch = epoch
            torch.save(model.state_dict(), ckpt_path)
            logger.info(f"  ✓ New best AUC={best_auc:.4f} → {ckpt_path}")

    logger.info(f"[seed={seed}] Best AUC={best_auc:.4f} at epoch {best_epoch}")
    return {"seed": seed, "best_auc": best_auc, "best_epoch": best_epoch, "history": history}


def train_ffnn(args):
    meta_db    = str(Path(args.processed_data) / "meta.db")
    ember_lmdb = str(Path(args.processed_data) / "ember_features")

    all_results = []
    for seed in SEEDS:
        result = train_ffnn_one_seed(
            seed=seed,
            meta_db=meta_db,
            ember_lmdb=ember_lmdb,
            output_dir=args.output_dir,
            epochs=args.epochs,
            batch_size=args.batch_size,
            lr=args.lr,
            predict_tags=args.predict_tags,
            num_workers=args.num_workers,
        )
        all_results.append(result)

    # Summary stats (mean ± std)
    aucs = [r["best_auc"] for r in all_results]
    logger.info(
        f"\n=== FFNN Results (5 seeds) ===\n"
        f"AUC: {np.mean(aucs):.3f} ± {np.std(aucs):.3f} "
        f"[{min(aucs):.3f} – {max(aucs):.3f}]"
    )

    results_path = Path(args.output_dir) / "ffnn_results.json"
    with open(results_path, "w") as f:
        json.dump(all_results, f, indent=2)
    logger.info(f"Results saved → {results_path}")


# ═══════════════════════════════════════════════════════════════════════════════
# LightGBM training
# ═══════════════════════════════════════════════════════════════════════════════

def build_numpy_arrays(meta_db: str, ember_lmdb: str, split: str) -> tuple:
    """
    Mirror build_numpy_arrays_for_lightgbm.py from SOREL-20M.
    Returns (X, y_mal, y_fam) numpy arrays.
    """
    import lmdb, msgpack, zlib, sqlite3

    logger.info(f"Loading {split} split into numpy arrays…")
    conn = sqlite3.connect(meta_db)
    rows = conn.execute(
        "SELECT sha256, label, family FROM samples WHERE split=?", (split,)
    ).fetchall()
    conn.close()

    env = lmdb.open(ember_lmdb, readonly=True, lock=False)
    X, y_mal, y_fam = [], [], []

    with env.begin() as txn:
        for sha256, label, family in rows:
            raw = txn.get(sha256.encode())
            if raw is None:
                continue
            vec = np.array(msgpack.unpackb(zlib.decompress(raw)), dtype=np.float32)
            X.append(vec)
            y_mal.append(label)
            y_fam.append(family)

    env.close()
    return np.array(X), np.array(y_mal), np.array(y_fam)


def train_lgbm(args):
    meta_db    = str(Path(args.processed_data) / "meta.db")
    ember_lmdb = str(Path(args.processed_data) / "ember_features")

    logger.info("Building numpy arrays for LightGBM training…")
    X_train, y_train, _ = build_numpy_arrays(meta_db, ember_lmdb, "train")
    X_val,   y_val,   _ = build_numpy_arrays(meta_db, ember_lmdb, "validation")
    X_test,  y_test,  _ = build_numpy_arrays(meta_db, ember_lmdb, "test")

    all_aucs = []
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    for seed in SEEDS:
        logger.info(f"\n=== LightGBM seed={seed} ===")
        cfg = {**LIGHTGBM_CONFIG, "random_state": seed}
        early = cfg.pop("early_stopping_rounds", 10)

        detector = LightGBMDetector(cfg)
        detector.early_stopping_rounds = early
        detector.fit(X_train, y_train, X_val, y_val)

        test_scores = detector.predict_proba(X_test)
        test_auc = roc_auc_score(y_test, test_scores)
        logger.info(f"[seed={seed}] Test AUC = {test_auc:.4f}")
        all_aucs.append(test_auc)

        detector.save(str(output_dir / f"lgbm_seed{seed}.joblib"))

    logger.info(
        f"\n=== LightGBM Results (5 seeds) ===\n"
        f"AUC: {np.mean(all_aucs):.3f} ± {np.std(all_aucs):.3f} "
        f"[{min(all_aucs):.3f} – {max(all_aucs):.3f}]"
    )
    results = {"aucs": all_aucs, "mean": float(np.mean(all_aucs)), "std": float(np.std(all_aucs))}
    with open(output_dir / "lgbm_results.json", "w") as f:
        json.dump(results, f, indent=2)


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(description="SOREL-20M style malware detector trainer")

    p.add_argument("--build-db", action="store_true",
                   help="Build processed-data databases from raw dataset dir")
    p.add_argument("--dataset-root", default="./dataset",
                   help="Root of raw dataset (benign/ and virus/ subdirs)")
    p.add_argument("--processed-data", default="./processed-data",
                   help="Where to store / load meta.db and LMDB files")

    p.add_argument("--model", choices=["ffnn", "lgbm", "both"], default="ffnn",
                   help="Which baseline model to train")
    p.add_argument("--output-dir", default="./baselines",
                   help="Where to save model checkpoints and results")

    # FFNN hyperparams
    p.add_argument("--epochs",       type=int,   default=15)
    p.add_argument("--batch-size",   type=int,   default=512)
    p.add_argument("--lr",           type=float, default=1e-3)
    p.add_argument("--num-workers",  type=int,   default=4)
    p.add_argument("--predict-tags", action="store_true", default=True)
    p.add_argument("--no-tags",      action="store_false", dest="predict_tags")

    return p.parse_args()


def main():
    args = parse_args()

    if args.build_db:
        logger.info("=== Building processed-data databases ===")
        build_databases(
            dataset_root=args.dataset_root,
            processed_data_dir=args.processed_data,
        )
        logger.info("=== Database build complete. Run: python src/train.py --model ffnn ===")
        return  # stop here; do not fall into training automatically

    if args.model in ("ffnn", "both"):
        logger.info("\n=== Training FFNN ===")
        train_ffnn(args)

    if args.model in ("lgbm", "both"):
        logger.info("\n=== Training LightGBM ===")
        train_lgbm(args)


if __name__ == "__main__":
    main()