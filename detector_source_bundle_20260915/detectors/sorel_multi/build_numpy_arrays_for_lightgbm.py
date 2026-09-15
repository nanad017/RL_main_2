"""
build_numpy_arrays_for_lightgbm.py
Mirrors the SOREL-20M utility script of the same name.
Iterates over a generator and writes features to .npz files
suitable for training the LightGBM model.

Usage:
    python build_numpy_arrays_for_lightgbm.py \
        --processed-data ./processed-data \
        --output-dir ./numpy_cache \
        --split train
"""

import argparse
import logging
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent / "src"))

from dataset import GeneratorFactory

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
logger = logging.getLogger(__name__)


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--processed-data", default="./processed-data")
    p.add_argument("--output-dir",     default="./numpy_cache")
    p.add_argument("--split",          default="train",
                   choices=["train", "validation", "test"])
    p.add_argument("--batch-size",     type=int, default=4096)
    p.add_argument("--num-workers",    type=int, default=4)
    return p.parse_args()


def main():
    args    = parse_args()
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    meta_db    = str(Path(args.processed_data) / "meta.db")
    ember_lmdb = str(Path(args.processed_data) / "ember_features")

    gen = GeneratorFactory(
        meta_db, ember_lmdb,
        split=args.split,
        batch_size=args.batch_size,
        num_workers=args.num_workers,
    )

    X_list, y_mal_list, y_fam_list, y_tag_list = [], [], [], []

    logger.info(f"Building numpy arrays for split='{args.split}'…")
    for feats, mal_lbl, fam_lbl, tag_lbl in gen:
        X_list.append(feats.numpy())
        y_mal_list.append(mal_lbl.numpy())
        y_fam_list.append(fam_lbl.numpy())
        y_tag_list.append(tag_lbl.numpy())

    X      = np.concatenate(X_list,     axis=0)
    y_mal  = np.concatenate(y_mal_list, axis=0)
    y_fam  = np.concatenate(y_fam_list, axis=0)
    y_tag  = np.concatenate(y_tag_list, axis=0)

    out_path = out_dir / f"{args.split}.npz"
    np.savez_compressed(str(out_path),
                        X=X, y_mal=y_mal, y_fam=y_fam, y_tag=y_tag)
    logger.info(f"Saved {X.shape[0]:,} samples → {out_path}  ({out_path.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()