"""
plot.py — mirrors SOREL-20M plot.py
Takes a JSON file listing run paths and outputs ROC plots.

Usage:
    python plot.py --runs baselines/ffnn_results.json --output-dir ./plots
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    print("matplotlib required: pip install matplotlib")
    sys.exit(1)


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--runs",       required=True, help="JSON file with run metadata")
    p.add_argument("--output-dir", default="./plots")
    return p.parse_args()


def plot_training_curves(runs, out_dir: Path):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    for run in runs:
        seed    = run["seed"]
        history = run.get("history", [])
        if not history:
            continue
        epochs   = [h["epoch"]     for h in history]
        val_aucs = [h["val_auc"]   for h in history]
        val_loss = [h["val_loss"]  for h in history]

        ax1.plot(epochs, val_aucs, label=f"seed {seed}", alpha=0.8)
        ax2.plot(epochs, val_loss, label=f"seed {seed}", alpha=0.8)

    ax1.set_xlabel("Epoch"); ax1.set_ylabel("Validation AUC")
    ax1.set_title("FFNN – Validation AUC per seed")
    ax1.legend(); ax1.grid(alpha=0.3)

    ax2.set_xlabel("Epoch"); ax2.set_ylabel("Validation Loss")
    ax2.set_title("FFNN – Validation Loss per seed")
    ax2.legend(); ax2.grid(alpha=0.3)

    fig.tight_layout()
    save_path = out_dir / "training_curves.png"
    fig.savefig(str(save_path), dpi=150)
    plt.close(fig)
    print(f"Saved → {save_path}")


def main():
    args   = parse_args()
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    with open(args.runs) as f:
        runs = json.load(f)

    plot_training_curves(runs, out_dir)

    aucs = [r["best_auc"] for r in runs]
    print(f"\nBest AUC across seeds: {np.mean(aucs):.4f} ± {np.std(aucs):.4f} "
          f"[{min(aucs):.4f} – {max(aucs):.4f}]")


if __name__ == "__main__":
    main()