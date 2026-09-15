#!/usr/bin/env python3
"""Run malware detection using a trained binary model.

This script reuses the same static feature extractor used in training.
"""



import argparse
import json
import math
from pathlib import Path
from typing import List

import joblib
import numpy as np
import pefile


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect malware using trained binary model")
    parser.add_argument("--file", type=Path, help="Path to one executable file")
    parser.add_argument("--dir", type=Path, help="Directory containing executable files")
    parser.add_argument(
        "--model-path",
        type=Path,
        default=Path("artifacts/binary_xgboost.joblib"),
        help="Path to saved model",
    )
    parser.add_argument(
        "--metrics-path",
        type=Path,
        default=Path("artifacts/metrics_xgboost.json"),
        help="Path to metrics JSON that may contain tuned threshold",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Manual decision threshold. If omitted, script uses metrics threshold or 0.5",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="When using --dir, scan subdirectories recursively",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional path to save detection results as JSON",
    )
    args = parser.parse_args()

    if args.file is None and args.dir is None:
        raise ValueError("Provide --file or --dir")

    return args


def _safe_ratio(numer: float, denom: float) -> float:
    return float(numer / denom) if denom > 0 else 0.0


def extract_static_features(path: Path) -> np.ndarray:
    path = Path(path)
    print("extract_static_features path:", path)
    bytez = path.read_bytes()
    print("bytes_len:", len(bytez))	
    """Extract fixed-size static features from a PE file (271 dims)."""
    bytez = path.read_bytes()
    arr = np.frombuffer(bytez, dtype=np.uint8)
    if arr.size == 0:
        raise ValueError("Empty file")

    hist = np.bincount(arr, minlength=256).astype(np.float32)
    hist /= max(1, arr.size)

    probs = hist[hist > 0]
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
        pass

    return np.concatenate([hist, raw_stats, pe_stats]).astype(np.float32)


def load_threshold(metrics_path: Path, manual_threshold: float | None) -> float:
    if manual_threshold is not None:
        return float(manual_threshold)

    if metrics_path.exists():
        try:
            data = json.loads(metrics_path.read_text(encoding="utf-8"))
            if "threshold" in data:
                return float(data["threshold"])
        except Exception:
            pass

    return 0.5


def collect_targets(file_path: Path | None, dir_path: Path | None, recursive: bool) -> List[Path]:
    if file_path is not None:
        return [file_path]

    if recursive:
        files = sorted(p for p in dir_path.rglob("*.exe") if p.is_file())
    else:
        files = sorted(p for p in dir_path.glob("*.exe") if p.is_file())
    return files


def main() -> None:
    args = parse_args()

    model = joblib.load(args.model_path)
    threshold = load_threshold(args.metrics_path, args.threshold)
    targets = collect_targets(args.file, args.dir, args.recursive)

    if not targets:
        raise RuntimeError("No .exe files found to scan")

    results = []
    for path in targets:
        try:
            x = extract_static_features(path).reshape(1, -1)
            prob = float(model.predict_proba(x)[0, 1])
            pred = int(prob >= threshold)
            label = "malware" if pred == 1 else "benign"
            confidence = prob if pred == 1 else 1.0 - prob

            row = {
                "file": str(path),
                "prob_malware": prob,
                "threshold": threshold,
                "prediction": pred,
                "label": label,
                "confidence": confidence,
            }
            results.append(row)
        except Exception as exc:
            results.append(
                {
                    "file": str(path),
                    "error": str(exc),
                }
            )

    for row in results:
        if "error" in row:
            print(f"[ERROR] {row['file']}: {row['error']}")
        else:
            print(
                f"{row['file']} -> {row['label']} "
                f"(p_malware={row['prob_malware']:.4f}, threshold={row['threshold']:.2f}, confidence={row['confidence']:.4f})"
            )

    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nSaved JSON results to {args.json_out}")


if __name__ == "__main__":
    main()
