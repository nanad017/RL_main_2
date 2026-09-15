"""
evaluate.py — SOREL-20M style evaluation script
Generates ROC curves (Figure 4, 5, 6 from the paper) and per-family metrics.

Usage:
    python evaluate.py \
        --processed-data ./processed-data \
        --ffnn-model ./baselines \
        --output-dir ./results
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).parent / "src"))

from dataset import (
    EMBER_FEATURE_DIM, FAMILY_NAMES, NUM_FAMILIES,
    NUM_TAGS, TAG_NAMES, GeneratorFactory,
)
from models import MalwareFFNN, LightGBMDetector

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(message)s")
logger = logging.getLogger(__name__)

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_MPL = True
except ImportError:
    HAS_MPL = False
    logger.warning("matplotlib not found; skipping plot generation")


# ── Evaluation helpers ────────────────────────────────────────────────────────

def compute_roc(labels: np.ndarray, scores: np.ndarray):
    from sklearn.metrics import roc_curve, auc
    fpr, tpr, _ = roc_curve(labels, scores)
    return fpr, tpr, auc(fpr, tpr)


@torch.no_grad()
def collect_scores_ffnn(
    model_paths: List[str],
    meta_db: str,
    ember_lmdb: str,
    split: str = "test",
    batch_size: int = 1024,
    num_workers: int = 4,
) -> Dict:
    """Collect malware scores + tag scores + family scores for all test samples."""
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    gen = GeneratorFactory(meta_db, ember_lmdb, split=split,
                           batch_size=batch_size, num_workers=num_workers)

    all_mal_scores  = []
    all_mal_labels  = []
    all_fam_labels  = []
    all_tag_labels  = []
    seed_tag_scores = []   # per-seed
    seed_fam_probs  = []

    for ckpt_path in model_paths:
        m = MalwareFFNN(predict_tags=True)
        m.load_state_dict(torch.load(ckpt_path, map_location=device))
        m.to(device).eval()
        logger.info(f"Evaluating {Path(ckpt_path).name} …")

        mal_s, tag_s, fam_s = [], [], []
        if not all_mal_labels:
            mal_l, fam_l, tag_l = [], [], []

        for feats, mal_lbl, fam_lbl, tag_lbl in gen:
            feats = feats.to(device)
            out   = m(feats)
            mal_s.extend(out["malware"].cpu().numpy())
            if "tags" in out:
                tag_s.extend(out["tags"].cpu().numpy())
            fam_s.extend(torch.softmax(out["family"], dim=-1).cpu().numpy())
            if not all_mal_labels:
                mal_l.extend(mal_lbl.numpy())
                fam_l.extend(fam_lbl.numpy())
                tag_l.extend(tag_lbl.numpy())

        if not all_mal_labels:
            all_mal_labels = np.array(mal_l)
            all_fam_labels = np.array(fam_l)
            all_tag_labels = np.array(tag_l)

        seed_tag_scores.append(np.array(tag_s) if tag_s else None)
        seed_fam_probs.append(np.array(fam_s))
        all_mal_scores.append(np.array(mal_s))

    return {
        "mal_labels":  all_mal_labels,
        "fam_labels":  all_fam_labels,
        "tag_labels":  all_tag_labels,
        "mal_scores":  np.stack(all_mal_scores),       # (n_seeds, n_samples)
        "tag_scores":  seed_tag_scores,
        "fam_probs":   np.stack(seed_fam_probs),       # (n_seeds, n_samples, NUM_FAM)
    }


# ── ROC plotting (mirrors SOREL paper Figures 4, 5, 6) ───────────────────────

def plot_roc_ensemble(
    fpr_list, tpr_list, auc_list, title: str, save_path: str
):
    """Plot mean ± std ROC over seeds. Mirrors SOREL Figure 4 / 5."""
    if not HAS_MPL:
        return

    # Interpolate to common FPR grid
    base_fpr = np.logspace(-6, 0, 500)
    interp_tpr = [np.interp(base_fpr, fpr, tpr) for fpr, tpr in zip(fpr_list, tpr_list)]
    mean_tpr = np.mean(interp_tpr, axis=0)
    std_tpr  = np.std(interp_tpr,  axis=0)
    min_tpr  = np.min(interp_tpr,  axis=0)
    max_tpr  = np.max(interp_tpr,  axis=0)
    mean_auc = float(np.mean(auc_list))
    std_auc  = float(np.std(auc_list))

    fig, ax = plt.subplots(figsize=(7, 7))
    ax.fill_between(base_fpr, min_tpr,  max_tpr,  alpha=0.15, color="grey")
    ax.fill_between(base_fpr, mean_tpr - std_tpr, mean_tpr + std_tpr, alpha=0.30, color="grey")
    ax.plot(base_fpr, mean_tpr, color="black",
            label=f"malware: {mean_auc:.3f}±{std_auc:.3f} [{min(auc_list):.3f}-{max(auc_list):.3f}]")
    ax.set_xscale("log")
    ax.set_xlim(1e-6, 1.0)
    ax.set_ylim(0.0, 1.0)
    ax.set_xlabel("False Positive Rate (FPR)")
    ax.set_ylabel("True Positive Rate (TPR)")
    ax.set_title(title)
    ax.legend(loc="lower right")
    ax.grid(True, which="both", alpha=0.3)
    fig.tight_layout()
    fig.savefig(save_path, dpi=150)
    plt.close(fig)
    logger.info(f"Saved ROC plot → {save_path}")


def plot_tag_rocs(tag_scores_list, tag_labels, auc_dict: Dict, save_path: str):
    """Per-tag ROC curves. Mirrors SOREL Figure 6."""
    if not HAS_MPL:
        return

    from sklearn.metrics import roc_curve, auc as sk_auc
    colors = plt.cm.tab10.colors
    fig, ax = plt.subplots(figsize=(9, 7))

    for i, tag in enumerate(TAG_NAMES):
        tag_col = tag_labels[:, i]
        if tag_col.sum() == 0:
            continue
        scores_per_seed = [ts[:, i] for ts in tag_scores_list if ts is not None]
        if not scores_per_seed:
            continue
        avg_scores = np.mean(scores_per_seed, axis=0)
        fpr, tpr, _ = roc_curve(tag_col, avg_scores)
        roc_auc     = sk_auc(fpr, tpr)
        ax.plot(fpr, tpr, linestyle="--", color=colors[i % len(colors)],
                label=f"{tag}_tag:{roc_auc:.3f}")

    ax.set_xscale("log")
    ax.set_xlim(1e-6, 1.0)
    ax.set_ylim(0.0, 1.0)
    ax.set_xlabel("False Positive Rate (FPR)")
    ax.set_ylabel("True Positive Rate (TPR)")
    ax.set_title("Per-tag ROC (FFNN, predict_tags=True)")
    ax.legend(loc="lower right", fontsize=8)
    ax.grid(True, which="both", alpha=0.3)
    fig.tight_layout()
    fig.savefig(save_path, dpi=150)
    plt.close(fig)
    logger.info(f"Saved tag ROC plot → {save_path}")


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--processed-data", default="./processed-data")
    p.add_argument("--ffnn-model",     default="./baselines")
    p.add_argument("--lgbm-model",     default=None)
    p.add_argument("--output-dir",     default="./results")
    p.add_argument("--split",          default="test")
    return p.parse_args()


def main():
    from sklearn.metrics import roc_curve, auc as sk_auc, classification_report
    args = parse_args()

    meta_db    = str(Path(args.processed_data) / "meta.db")
    ember_lmdb = str(Path(args.processed_data) / "ember_features")
    out_dir    = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    model_dir  = Path(args.ffnn_model)
    ckpts      = sorted(model_dir.glob("ffnn_seed*.pt")) if model_dir.is_dir() else [model_dir]

    logger.info(f"Evaluating {len(ckpts)} FFNN checkpoints on '{args.split}' split…")
    data = collect_scores_ffnn(
        [str(c) for c in ckpts], meta_db, ember_lmdb, split=args.split
    )

    mal_labels = data["mal_labels"]
    mal_scores = data["mal_scores"]   # (n_seeds, n_samples)

    # ── Per-seed ROC ─────────────────────────────────────────────────────────
    fpr_list, tpr_list, auc_list = [], [], []
    for s in range(mal_scores.shape[0]):
        fpr, tpr, a = compute_roc(mal_labels, mal_scores[s])
        fpr_list.append(fpr); tpr_list.append(tpr); auc_list.append(a)

    plot_roc_ensemble(fpr_list, tpr_list, auc_list,
                      "FFNN – Malware ROC",
                      str(out_dir / "ffnn_roc_malware.png"))

    # ── Tag ROC ──────────────────────────────────────────────────────────────
    if data["tag_scores"] and data["tag_scores"][0] is not None:
        plot_tag_rocs(data["tag_scores"], data["tag_labels"], {}, str(out_dir / "ffnn_roc_tags.png"))

    # ── Family classification report ──────────────────────────────────────────
    avg_fam_probs = np.mean(data["fam_probs"], axis=0)          # (n_samples, NUM_FAM)
    pred_fam      = np.argmax(avg_fam_probs, axis=1)
    true_fam      = data["fam_labels"]

    fam_names = [FAMILY_NAMES[i] for i in sorted(FAMILY_NAMES)]
    report = classification_report(true_fam, pred_fam, target_names=fam_names, zero_division=0)
    logger.info(f"\nFamily Classification Report:\n{report}")
    with open(out_dir / "family_classification_report.txt", "w") as f:
        f.write(report)

    # ── LightGBM ROC ─────────────────────────────────────────────────────────
    if args.lgbm_model:
        import sqlite3, lmdb, msgpack, zlib
        lgbm = LightGBMDetector.load(args.lgbm_model)
        conn = sqlite3.connect(meta_db)
        rows = conn.execute(
            "SELECT sha256, label FROM samples WHERE split=?", (args.split,)
        ).fetchall()
        conn.close()

        env = lmdb.open(ember_lmdb, readonly=True, lock=False)
        X_test, y_test = [], []
        with env.begin() as txn:
            for sha, lbl in rows:
                raw = txn.get(sha.encode())
                if raw is None:
                    continue
                X_test.append(np.array(msgpack.unpackb(zlib.decompress(raw)), dtype=np.float32))
                y_test.append(lbl)
        env.close()

        X_test = np.array(X_test)
        y_test = np.array(y_test)
        lgbm_scores = lgbm.predict_proba(X_test)

        fpr, tpr, a = compute_roc(y_test, lgbm_scores)
        logger.info(f"LightGBM test AUC = {a:.4f}")
        plot_roc_ensemble([fpr], [tpr], [a],
                          "LightGBM GBDT – Malware ROC",
                          str(out_dir / "lgbm_roc_malware.png"))

    # ── Save summary JSON ─────────────────────────────────────────────────────
    summary = {
        "split":    args.split,
        "n_seeds":  mal_scores.shape[0],
        "ffnn": {
            "mean_auc": float(np.mean(auc_list)),
            "std_auc":  float(np.std(auc_list)),
            "min_auc":  float(min(auc_list)),
            "max_auc":  float(max(auc_list)),
        },
    }
    with open(out_dir / "evaluation_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    logger.info(f"Summary → {out_dir / 'evaluation_summary.json'}")
    logger.info(f"FFNN AUC: {summary['ffnn']['mean_auc']:.3f} ± {summary['ffnn']['std_auc']:.3f}")


if __name__ == "__main__":
    main()