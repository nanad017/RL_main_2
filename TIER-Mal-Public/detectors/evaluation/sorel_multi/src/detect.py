"""
detect.py — SOREL-20M style detection script
Loads a trained FFNN (and optionally LightGBM) model and runs inference
on one or more PE files.  Outputs a detailed report (JSON + human-readable).

Usage:
    # Single file
    python detect.py --input suspicious.exe --ffnn-model baselines/ffnn_seed1.pt

    # Directory
    python detect.py --input ./samples/ --ffnn-model baselines/ffnn_seed1.pt

    # Ensemble all 5 seeds
    python detect.py --input ./samples/ --ffnn-model baselines/ --ensemble

    # Also run LightGBM
    python detect.py --input suspicious.exe \
        --ffnn-model baselines/ffnn_seed1.pt \
        --lgbm-model baselines/lgbm_seed1.joblib
"""

import argparse
import hashlib
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import torch
import torch.nn.functional as F

# Only insert src/ — adding project root causes circular imports
_src = str(Path(__file__).resolve().parent)
if _src not in sys.path:
    sys.path.insert(0, _src)

from dataset import (
    EMBER_FEATURE_DIM, FAMILY_NAMES, NUM_FAMILIES, NUM_TAGS,
    TAG_NAMES, extract_ember_features
)
from models import MalwareFFNN, LightGBMDetector

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# Detection threshold (adjust for desired FPR trade-off)
DEFAULT_THRESHOLD: float = 0.50


# ── Model loaders ─────────────────────────────────────────────────────────────

def load_ffnn_models(model_path: str, ensemble: bool = False) -> List[MalwareFFNN]:
    """Load one or all FFNN seed checkpoints."""
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    p = Path(model_path)

    if p.is_dir() and ensemble:
        ckpts = sorted(p.glob("ffnn_seed*.pt"))
        if not ckpts:
            raise FileNotFoundError(f"No ffnn_seed*.pt found in {p}")
        logger.info(f"Ensemble: loading {len(ckpts)} FFNN checkpoints")
    elif p.is_dir():
        ckpts = sorted(p.glob("ffnn_seed*.pt"))[:1]
        if not ckpts:
            raise FileNotFoundError(f"No ffnn_seed*.pt found in {p}")
    else:
        ckpts = [p]

    models = []
    for ckpt in ckpts:
        m = MalwareFFNN(predict_tags=True)
        m.load_state_dict(torch.load(str(ckpt), map_location=device))
        m.to(device)
        m.eval()
        models.append(m)
        logger.info(f"  Loaded {ckpt.name}")
    return models


def load_lgbm_model(model_path: Optional[str]) -> Optional[LightGBMDetector]:
    if not model_path:
        return None
    try:
        det = LightGBMDetector.load(model_path)
        logger.info(f"Loaded LightGBM model: {model_path}")
        return det
    except Exception as e:
        logger.warning(f"Could not load LightGBM model: {e}")
        return None


# ── Inference ─────────────────────────────────────────────────────────────────

@torch.no_grad()
def infer_ffnn(
    models: List[MalwareFFNN],
    feature_vec: np.ndarray,
    device: torch.device,
) -> Dict:
    """Run ensemble inference with FFNN models."""
    x = torch.tensor(feature_vec, dtype=torch.float32).unsqueeze(0).to(device)

    mal_scores, fam_logits_list, tag_scores_list = [], [], []

    for m in models:
        out = m(x)
        mal_scores.append(out["malware"].item())
        fam_logits_list.append(out["family"].cpu().numpy()[0])
        if "tags" in out:
            tag_scores_list.append(out["tags"].cpu().numpy()[0])

    # Average over ensemble
    avg_mal  = float(np.mean(mal_scores))
    avg_fam  = np.mean(fam_logits_list, axis=0)          # (NUM_FAMILIES,)
    fam_prob = F.softmax(torch.tensor(avg_fam), dim=-1).numpy()

    result = {
        "malware_score":  avg_mal,
        "family_probs":   {FAMILY_NAMES[i]: float(fam_prob[i]) for i in range(NUM_FAMILIES)},
        "predicted_family_idx": int(np.argmax(fam_prob)),
    }

    if tag_scores_list:
        avg_tags = np.mean(tag_scores_list, axis=0)
        result["tag_scores"] = {TAG_NAMES[i]: float(avg_tags[i]) for i in range(NUM_TAGS)}

    return result


# ── Per-file detection ────────────────────────────────────────────────────────

def detect_file(
    file_path: str,
    ffnn_models: List[MalwareFFNN],
    lgbm_model: Optional[LightGBMDetector],
    threshold: float = DEFAULT_THRESHOLD,
    device: Optional[torch.device] = None,
) -> Dict:
    """
    Run full detection on a single PE file.
    Returns a structured result dict.
    """
    if device is None:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    fp = Path(file_path)
    if not fp.is_file():
        return {"error": f"File not found: {file_path}"}

    # SHA-256
    with open(str(fp), "rb") as f:
        raw = f.read()
    sha256 = hashlib.sha256(raw).hexdigest()

    # Feature extraction
    features = extract_ember_features(str(fp))
    if features is None:
        return {
            "file": fp.name,
            "sha256": sha256,
            "error": "Feature extraction failed (not a valid PE file?)",
        }

    # FFNN inference
    ffnn_out = infer_ffnn(ffnn_models, features, device)

    # LightGBM inference (optional)
    lgbm_score = None
    if lgbm_model is not None:
        lgbm_score = float(lgbm_model.predict_proba(features.reshape(1, -1))[0])

    # Final score: average FFNN + LGBM if available
    if lgbm_score is not None:
        final_score = (ffnn_out["malware_score"] + lgbm_score) / 2.0
    else:
        final_score = ffnn_out["malware_score"]

    is_malware   = final_score >= threshold
    fam_idx      = ffnn_out["predicted_family_idx"]
    fam_name     = FAMILY_NAMES[fam_idx]

    # If predicted family is "benign" but score says malware, pick top malware family
    if is_malware and fam_name == "benign":
        # Exclude benign (index 0) and pick next best
        probs_no_benign = {k: v for k, v in ffnn_out["family_probs"].items() if k != "benign"}
        fam_name = max(probs_no_benign, key=probs_no_benign.get)

    result = {
        "file":             fp.name,
        "sha256":           sha256,
        "file_size_bytes":  len(raw),
        "timestamp":        datetime.now(timezone.utc).isoformat(),

        # ── Verdict ──────────────────────────────────────────────────────────
        "verdict":          "MALWARE" if is_malware else "BENIGN",
        "malware_family":   fam_name if is_malware else None,
        "confidence":       round(final_score * 100, 2),        # 0–100 %

        # ── Scores ───────────────────────────────────────────────────────────
        "scores": {
            "ffnn":      round(ffnn_out["malware_score"], 6),
            "lightgbm":  round(lgbm_score, 6) if lgbm_score is not None else None,
            "ensemble":  round(final_score, 6),
            "threshold": threshold,
        },

        # ── Family probabilities ──────────────────────────────────────────────
        "family_probabilities": {
            k: round(v * 100, 2)
            for k, v in sorted(
                ffnn_out["family_probs"].items(),
                key=lambda x: -x[1]
            )
        },

        # ── Behavioural tags ─────────────────────────────────────────────────
        "behavioral_tags": {
            k: round(v * 100, 2)
            for k, v in ffnn_out.get("tag_scores", {}).items()
        },
    }

    return result


# ── Human-readable report ────────────────────────────────────────────────────

def format_report(result: Dict) -> str:
    if "error" in result:
        return f"[ERROR] {result.get('file', '?')}: {result['error']}"

    verdict  = result["verdict"]
    family   = result.get("malware_family") or "—"
    conf     = result["confidence"]
    sha      = result["sha256"]
    size     = result["file_size_bytes"]

    sep = "═" * 60
    lines = [
        sep,
        f"  File    : {result['file']}",
        f"  SHA-256 : {sha}",
        f"  Size    : {size:,} bytes",
        sep,
        f"  Verdict : {'🔴 MALWARE' if verdict == 'MALWARE' else '🟢 BENIGN'}",
    ]
    if verdict == "MALWARE":
        lines.append(f"  Family  : {family}")
    lines.append(f"  Confidence: {conf:.1f} %")
    lines.append("")

    sc = result["scores"]
    lines.append("  Scores:")
    lines.append(f"    FFNN      : {sc['ffnn']:.4f}")
    if sc["lightgbm"] is not None:
        lines.append(f"    LightGBM  : {sc['lightgbm']:.4f}")
    lines.append(f"    Ensemble  : {sc['ensemble']:.4f}  (threshold={sc['threshold']})")
    lines.append("")

    lines.append("  Family probabilities (%):")
    for fam, pct in list(result["family_probabilities"].items())[:6]:
        bar = "█" * int(pct / 5)
        lines.append(f"    {fam:<12} {pct:>6.2f}  {bar}")

    if result.get("behavioral_tags"):
        lines.append("")
        lines.append("  Behavioural tags (%):")
        for tag, pct in result["behavioral_tags"].items():
            bar = "█" * int(pct / 5)
            lines.append(f"    {tag:<14} {pct:>6.2f}  {bar}")

    lines.append(sep)
    return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="SOREL-style malware detector")
    p.add_argument("--input",      required=True,
                   help="PE file or directory of PE files to scan")
    p.add_argument("--ffnn-model", default="./baselines",
                   help="Path to ffnn_seed*.pt checkpoint or directory")
    p.add_argument("--lgbm-model", default=None,
                   help="Path to lgbm_seed*.joblib (optional)")
    p.add_argument("--ensemble",   action="store_true",
                   help="Average all ffnn_seed*.pt models in the directory")
    p.add_argument("--threshold",  type=float, default=DEFAULT_THRESHOLD,
                   help=f"Detection threshold (default {DEFAULT_THRESHOLD})")
    p.add_argument("--output",     default=None,
                   help="Write JSON results to this file")
    return p.parse_args()


def main():
    args = parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    ffnn_models = load_ffnn_models(args.ffnn_model, ensemble=args.ensemble)
    lgbm_model  = load_lgbm_model(args.lgbm_model)

    # Collect files
    inp = Path(args.input)
    if inp.is_dir():
        files = [f for f in sorted(inp.rglob("*")) if f.is_file()]
    else:
        files = [inp]

    logger.info(f"Scanning {len(files)} file(s)…")
    all_results = []

    for fp in files:
        logger.info(f"  → {fp.name}")
        result = detect_file(
            file_path=str(fp),
            ffnn_models=ffnn_models,
            lgbm_model=lgbm_model,
            threshold=args.threshold,
            device=device,
        )
        all_results.append(result)
        print(format_report(result))

    # Summary
    malware_count = sum(1 for r in all_results if r.get("verdict") == "MALWARE")
    benign_count  = sum(1 for r in all_results if r.get("verdict") == "BENIGN")
    error_count   = sum(1 for r in all_results if "error" in r)
    print(f"\nSummary: {len(files)} scanned | "
          f"🔴 {malware_count} malware | 🟢 {benign_count} benign | ⚠ {error_count} errors")

    # Family breakdown
    if malware_count:
        from collections import Counter
        fam_counts = Counter(
            r["malware_family"] for r in all_results
            if r.get("verdict") == "MALWARE" and r.get("malware_family")
        )
        print("\nMalware families detected:")
        for fam, cnt in fam_counts.most_common():
            print(f"  {fam:<14} : {cnt}")

    # JSON output
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(str(out_path), "w") as f:
            json.dump(
                {"scan_time": datetime.now(timezone.utc).isoformat(), "results": all_results},
                f, indent=2,
            )
        logger.info(f"Results saved → {out_path}")


if __name__ == "__main__":
    main()