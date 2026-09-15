#!/usr/bin/env python3
"""Batch-evaluate the trained binary XGBoost detector on PE samples."""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import joblib

XGB_DIR = Path("/home/rl/sup_detector/Malware-Detection-System")
if str(XGB_DIR) not in sys.path:
    sys.path.insert(0, str(XGB_DIR))

from detect_binary_fi import extract_static_features, load_threshold  # noqa: E402

FAMILIES = ["Locker", "Mediyes", "Winwebsec", "Zbot", "Zeroaccess"]


def discover_samples(root: Path):
    samples = []
    for family in FAMILIES:
        family_dir = root / family
        if not family_dir.is_dir():
            continue
        for path in sorted(family_dir.iterdir()):
            if path.is_file():
                samples.append((path, family))
    return samples


def load_done(path: Path):
    done = set()
    if not path.exists():
        return done
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        done.add((row.get("true_family"), row.get("file")))
    return done


def write_report(jsonl: Path, report: Path, dataset_root: Path, threshold: float):
    rows = []
    if jsonl.exists():
        for line in jsonl.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    grouped = defaultdict(list)
    for row in rows:
        grouped[row.get("true_family", "UNKNOWN")].append(row)

    lines = [
        "=" * 80,
        "DETECTION REPORT: xgboost",
        f"Dataset: {dataset_root}",
        f"Threshold: {threshold}",
        f"Total records: {len(rows)}",
        "=" * 80,
        "",
        f"{'True':<14} {'Total':>7} {'MalwarePred':>12} {'BenignPred':>11} {'Error':>8}",
        "-" * 80,
    ]

    total = Counter()
    for family in FAMILIES:
        family_rows = grouped.get(family, [])
        if not family_rows:
            continue
        errors = sum("error" in row for row in family_rows)
        benign = sum(row.get("label") == "benign" for row in family_rows)
        malware = sum(row.get("label") == "malware" for row in family_rows)
        lines.append(f"{family:<14} {len(family_rows):>7} {malware:>12} {benign:>11} {errors:>8}")
        total.update(total=len(family_rows), malware=malware, benign=benign, error=errors)

    lines.extend([
        "-" * 80,
        f"{'TOTAL':<14} {total['total']:>7} {total['malware']:>12} {total['benign']:>11} {total['error']:>8}",
        "",
        f"Malware files predicted benign: {total['benign']}/{total['total']}",
        f"Evasion rate: {(total['benign'] / total['total'] * 100) if total['total'] else 0:.2f}%",
    ])
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset-root", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    root = Path(args.dataset_root).expanduser().resolve()
    out = Path(args.output_dir).expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    jsonl = out / "results.jsonl"
    report = out / "report.txt"
    status = out / "status.json"
    model_path = XGB_DIR / "artifacts/binary_xgboost.joblib"
    metrics_path = XGB_DIR / "artifacts/metrics_xgboost.json"
    threshold = load_threshold(metrics_path, None)
    model = joblib.load(model_path)
    samples = discover_samples(root)
    done = load_done(jsonl)

    status.write_text(json.dumps({
        "status": "running", "detector": "xgboost", "label": args.label,
        "dataset_root": str(root), "total_samples": len(samples),
        "already_done": len(done), "pid": __import__("os").getpid(),
    }, indent=2), encoding="utf-8")
    print(f"[START] detector=xgboost label={args.label} samples={len(samples)}")
    print(f"[OUT] {out}", flush=True)

    processed = skipped = failed = 0
    with jsonl.open("a", encoding="utf-8") as handle:
        for index, (path, family) in enumerate(samples, 1):
            key = (family, path.name)
            if key in done:
                skipped += 1
                continue
            try:
                features = extract_static_features(path).reshape(1, -1)
                probability = float(model.predict_proba(features)[0, 1])
                label = "malware" if probability >= threshold else "benign"
                row = {
                    "file": path.name, "path": str(path), "true_family": family,
                    "detector": "xgboost", "dataset_label": args.label,
                    "prob_malware": probability, "threshold": threshold,
                    "label": label, "confidence": probability if label == "malware" else 1 - probability,
                }
            except Exception as exc:
                failed += 1
                row = {"file": path.name, "path": str(path), "true_family": family,
                       "detector": "xgboost", "dataset_label": args.label,
                       "error": repr(exc)}
            handle.write(json.dumps(row) + "\n")
            handle.flush()
            processed += 1
            if processed % 25 == 0 or index == len(samples):
                write_report(jsonl, report, root, threshold)
                status.write_text(json.dumps({
                    "status": "running", "detector": "xgboost", "label": args.label,
                    "dataset_root": str(root), "total_samples": len(samples),
                    "processed_this_run": processed, "skipped_existing": skipped,
                    "failed_this_run": failed, "last_index": index,
                    "pid": __import__("os").getpid(),
                }, indent=2), encoding="utf-8")
                print(f"[PROGRESS] {index}/{len(samples)} processed={processed} failed={failed}", flush=True)

    write_report(jsonl, report, root, threshold)
    status.write_text(json.dumps({
        "status": "complete", "detector": "xgboost", "label": args.label,
        "dataset_root": str(root), "total_samples": len(samples),
        "processed_this_run": processed, "skipped_existing": skipped,
        "failed_this_run": failed, "pid": __import__("os").getpid(),
    }, indent=2), encoding="utf-8")
    print(f"[DONE] detector=xgboost processed={processed} skipped={skipped} failed={failed}", flush=True)


if __name__ == "__main__":
    main()
