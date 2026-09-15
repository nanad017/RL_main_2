"""
test_evaluation.py — Đánh giá toàn bộ tập test
Chấm điểm theo quy tắc:
  - Đúng hoàn toàn (benign→benign hoặc malware→đúng family) : 1.0 điểm
  - Đúng malware nhưng sai family                           : 0.5 điểm
  - Sai hoàn toàn (benign→malware hoặc malware→benign)      : 0.0 điểm

Usage:
    python test_evaluation.py \
        --test-dir ./test \
        --ffnn-model ./baselines \
        --lgbm-model ./baselines/lgbm_seed1.joblib \
        --threshold 0.8327 \
        --output ./results/test_report.json
"""

import argparse
import json
import logging
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
import torch

_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
sys.path.insert(0, _src)

from detect_impl import load_ffnn_models, load_lgbm_model, detect_file, DEFAULT_THRESHOLD

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

FAMILY_LABELS = ["benign", "Locker", "Mediyes", "Winwebsec", "Zbot", "Zeroaccess"]
MALWARE_FAMILIES = [f for f in FAMILY_LABELS if f != "benign"]


def scan_test_dir(test_dir: str):
    """
    Quét thư mục test, trả về list (file_path, true_label, true_family).
    Cấu trúc: test/benign/* và test/virus/<family>/*
    """
    test_dir = Path(test_dir)
    samples = []

    # Benign
    for candidate in ["benign", "Benign", "BENIGN"]:
        d = test_dir / candidate
        if d.exists():
            for fp in sorted(d.rglob("*")):
                if fp.is_file():
                    samples.append((str(fp), "benign", "benign"))
            break

    # Malware families
    search_roots = []
    for candidate in ["virus", "malware", "Virus", "Malware"]:
        d = test_dir / candidate
        if d.exists():
            search_roots.append(d)
    search_roots.append(test_dir)

    found = set()
    for root in search_roots:
        for fdir in sorted(root.iterdir()):
            if fdir.is_dir() and fdir.name in MALWARE_FAMILIES and fdir.name not in found:
                for fp in sorted(fdir.rglob("*")):
                    if fp.is_file():
                        samples.append((str(fp), "malware", fdir.name))
                found.add(fdir.name)

    return samples


def score_prediction(true_family: str, pred_verdict: str, pred_family: str) -> float:
    """
    Chấm điểm 1 file:
      1.0 — đúng hoàn toàn
      0.5 — đúng malware/benign nhưng sai family
      0.0 — sai hoàn toàn
    """
    is_truly_malware = (true_family != "benign")
    is_pred_malware  = (pred_verdict == "MALWARE")

    if not is_truly_malware and not is_pred_malware:
        return 1.0   # benign → BENIGN ✓
    if is_truly_malware and is_pred_malware:
        if pred_family == true_family:
            return 1.0   # malware → đúng family ✓
        else:
            return 0.5   # malware → sai family (được nửa điểm)
    return 0.0           # sai hoàn toàn


def run_evaluation(args):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    logger.info("Loading models…")
    ffnn_models = load_ffnn_models(args.ffnn_model, ensemble=True)
    lgbm_model  = load_lgbm_model(args.lgbm_model)
    threshold   = args.threshold

    logger.info(f"Threshold: {threshold}")
    logger.info(f"Scanning test directory: {args.test_dir}")
    samples = scan_test_dir(args.test_dir)
    logger.info(f"Found {len(samples)} test files")

    results = []
    scores_by_family  = defaultdict(list)   # true_family → list of scores
    errors_by_family  = defaultdict(list)   # true_family → list of (file, pred)
    t0 = time.time()

    for i, (fpath, true_label, true_family) in enumerate(samples, 1):
        fname = Path(fpath).name

        result = detect_file(
            file_path=fpath,
            ffnn_models=ffnn_models,
            lgbm_model=lgbm_model,
            threshold=threshold,
            device=device,
        )

        if "error" in result:
            logger.warning(f"  [{i}/{len(samples)}] ERROR: {fname} — {result['error']}")
            scores_by_family[true_family].append(0.0)
            errors_by_family[true_family].append({
                "file": fname, "true": true_family, "pred": "ERROR", "score": 0.0
            })
            continue

        pred_verdict = result["verdict"]
        pred_family  = result.get("malware_family") or "benign"
        point        = score_prediction(true_family, pred_verdict, pred_family)

        status = "✓" if point == 1.0 else ("½" if point == 0.5 else "✗")
        if point < 1.0:
            logger.info(
                f"  [{i:>4}/{len(samples)}] {status} {fname[:45]:<45} "
                f"true={true_family:<12} pred={pred_family}"
            )

        scores_by_family[true_family].append(point)
        if point < 1.0:
            errors_by_family[true_family].append({
                "file":        fname,
                "true_family": true_family,
                "pred_verdict": pred_verdict,
                "pred_family": pred_family,
                "confidence":  result["confidence"],
                "score":       point,
            })

        results.append({
            "file":         fname,
            "true_family":  true_family,
            "pred_verdict": pred_verdict,
            "pred_family":  pred_family,
            "confidence":   result["confidence"],
            "point":        point,
            "ensemble_score": result["scores"]["ensemble"],
        })

    elapsed = time.time() - t0

    # ── Aggregate stats ───────────────────────────────────────────────────────
    all_points  = [r["point"] for r in results]
    total       = len(all_points)
    perfect     = sum(1 for p in all_points if p == 1.0)
    half        = sum(1 for p in all_points if p == 0.5)
    wrong       = sum(1 for p in all_points if p == 0.0)
    total_score = sum(all_points)
    accuracy    = total_score / total * 100 if total else 0

    # Per-family stats
    family_stats = {}
    for fam in FAMILY_LABELS:
        pts = scores_by_family.get(fam, [])
        if not pts:
            continue
        family_stats[fam] = {
            "total":   len(pts),
            "perfect": sum(1 for p in pts if p == 1.0),
            "half":    sum(1 for p in pts if p == 0.5),
            "wrong":   sum(1 for p in pts if p == 0.0),
            "score":   sum(pts),
            "accuracy": sum(pts) / len(pts) * 100,
        }

    # Confusion: for malware, what did we predict?
    confusion = defaultdict(lambda: defaultdict(int))
    for r in results:
        confusion[r["true_family"]][r["pred_family"]] += 1

    # ── Print report ──────────────────────────────────────────────────────────
    SEP = "═" * 65
    print(f"\n{SEP}")
    print(f"  TEST EVALUATION REPORT")
    print(f"  Threshold : {threshold}  |  Files : {total}  |  Time : {elapsed:.1f}s")
    print(SEP)
    print(f"  {'Category':<14}  {'Total':>5}  {'✓ Full':>6}  {'½ Half':>6}  {'✗ Wrong':>7}  {'Accuracy':>9}")
    print(f"  {'-'*60}")

    for fam in FAMILY_LABELS:
        s = family_stats.get(fam)
        if not s:
            continue
        print(f"  {fam:<14}  {s['total']:>5}  {s['perfect']:>6}  "
              f"{s['half']:>6}  {s['wrong']:>7}  {s['accuracy']:>8.1f}%")

    print(f"  {'-'*60}")
    print(f"  {'TOTAL':<14}  {total:>5}  {perfect:>6}  {half:>6}  {wrong:>7}  {accuracy:>8.1f}%")
    print(SEP)
    print(f"\n  Scoring: Full(×1.0) + Half(×0.5) + Wrong(×0.0)")
    print(f"  Total score : {total_score:.1f} / {total:.1f}  ({accuracy:.2f}%)")
    print(SEP)

    # Confusion matrix
    print(f"\n  CONFUSION MATRIX (true → predicted)")
    print(f"  {'True // Pred':<14}", end="")
    all_preds = sorted({r["pred_family"] for r in results} | {"benign"})
    for p in all_preds:
        print(f"  {p[:10]:>10}", end="")
    print()
    print(f"  {'-'*60}")
    for true_fam in FAMILY_LABELS:
        if true_fam not in family_stats:
            continue
        print(f"  {true_fam:<14}", end="")
        for pred_fam in all_preds:
            cnt = confusion[true_fam].get(pred_fam, 0)
            print(f"  {cnt:>10}", end="")
        print()

    # Top errors
    all_errors = []
    for errs in errors_by_family.values():
        all_errors.extend(errs)
    all_errors.sort(key=lambda x: x.get("confidence", 0), reverse=True)

    if all_errors:
        print(f"\n  TOP MISTAKES (high confidence wrong predictions):")
        print(f"  {'File':<45}  {'True':<12}  {'Predicted':<12}  {'Conf':>6}")
        print(f"  {'-'*82}")
        for e in all_errors[:20]:
            print(f"  {e['file'][:44]:<45}  {e['true_family']:<12}  "
                  f"{e['pred_family']:<12}  {e.get('confidence', 0):>5.1f}%")

    print(f"\n{SEP}\n")

    # ── Save JSON report ──────────────────────────────────────────────────────
    report = {
        "threshold":    threshold,
        "total_files":  total,
        "total_score":  total_score,
        "accuracy_pct": accuracy,
        "perfect":      perfect,
        "half":         half,
        "wrong":        wrong,
        "elapsed_sec":  elapsed,
        "family_stats": family_stats,
        "confusion":    {k: dict(v) for k, v in confusion.items()},
        "errors":       all_errors,
        "per_file":     results,
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(str(out_path), "w") as f:
        json.dump(report, f, indent=2)
    logger.info(f"Full report saved → {out_path}")

    return report


def parse_args():
    p = argparse.ArgumentParser(description="Evaluate detector on test set")
    p.add_argument("--test-dir",    default="./test",
                   help="Test directory (same structure as dataset/)")
    p.add_argument("--ffnn-model",  default="./baselines")
    p.add_argument("--lgbm-model",  default=None)
    p.add_argument("--threshold",   type=float, default=DEFAULT_THRESHOLD)
    p.add_argument("--output",      default="./results/test_report.json")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_evaluation(args)