#!/usr/bin/env python3
import argparse
import json
import math
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path


FAMILIES = ["Locker", "Mediyes", "Winwebsec", "Zbot", "Zeroaccess"]

TIER_ROOT = Path(__file__).resolve().parents[1]
EVALUATION_ROOT = TIER_ROOT / "detectors" / "evaluation"


def env_path(name: str, default: Path) -> Path:
    return Path(os.getenv(name, str(default))).expanduser().resolve()


SOREL_DIR = env_path("SOREL_DETECTOR_DIR", EVALUATION_ROOT / "sorel_multi")
SOREL_PY = env_path("SOREL_PYTHON", Path(sys.executable))
SOREL_FFNN = env_path("SOREL_FFNN_MODEL", SOREL_DIR / "baselines")
SOREL_LGBM = env_path("SOREL_LGBM_MODEL", SOREL_DIR / "baselines/lgbm_seed1.joblib")
SOREL_THRESHOLD = os.getenv("SOREL_THRESHOLD", "0.8327")

DEEPMAL_DIR = env_path("DEEPMAL_DETECTOR_DIR", EVALUATION_ROOT / "deep-malware-detection")
DEEPMAL_PY = env_path("DEEPMAL_PYTHON", Path(sys.executable))
DEEPMAL_CHECKPOINT = env_path("DEEPMAL_CHECKPOINT", DEEPMAL_DIR / "assets/checkpoints/run1.pt")

CNN_DIR = env_path("CNN_DETECTOR_DIR", EVALUATION_ROOT / "malware-classification-CNN")
CNN_MODEL = env_path("CNN_MODEL_PATH", CNN_DIR / "artifacts/combined_local/modellozzo_ckpt.keras")
CNN_CLASS_INDICES = env_path("CNN_CLASS_INDICES", CNN_DIR / "artifacts/combined_local/class_indices.json")

EMBER_DIR = env_path("EMBER_DETECTOR_DIR", EVALUATION_ROOT / "EMBER2024")
EMBER_MODEL = env_path("EMBER_MODEL_PATH", EMBER_DIR / "models/custom_multiclass.model")
EMBER_LABELS = env_path("EMBER_LABELS_PATH", EMBER_DIR / "dataset_json/family_labels.json")

_CNN_STATE = None
_EMBER_STATE = None


def discover_samples(dataset_root: Path):
    """Support both Family/* and RL_MAIN_FINAL_2/{virus/Family,benign/*} layouts."""
    samples = []
    root = dataset_root.expanduser().resolve()

    family_base = root / "virus" if (root / "virus").is_dir() else root
    for family in FAMILIES:
        family_dir = family_base / family
        if not family_dir.is_dir():
            continue
        for fp in sorted(p for p in family_dir.iterdir() if p.is_file()):
            samples.append((fp, family))

    benign_dir = root / "benign"
    if benign_dir.is_dir():
        for fp in sorted(p for p in benign_dir.iterdir() if p.is_file()):
            samples.append((fp, "benign"))

    return samples


def load_done(jsonl_path: Path):
    done = set()
    if not jsonl_path.exists():
        return done
    with jsonl_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            done.add((rec.get("true_family"), rec.get("file")))
    return done


def append_jsonl(jsonl_path: Path, record: dict):
    with jsonl_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def run_sorel(filepath: Path):
    with tempfile.NamedTemporaryFile(prefix="sorel_", suffix=".json", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        cmd = [
            str(SOREL_PY),
            str(SOREL_DIR / "detect.py"),
            "--input",
            str(filepath),
            "--ffnn-model",
            str(SOREL_FFNN),
            "--lgbm-model",
            str(SOREL_LGBM),
            "--ensemble",
            "--threshold",
            SOREL_THRESHOLD,
            "--output",
            str(tmp_path),
        ]
        proc = subprocess.run(
            cmd,
            cwd=str(SOREL_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=180,
        )
        if proc.returncode != 0:
            return {
                "error": "sorel detect failed",
                "returncode": proc.returncode,
                "stderr": proc.stderr[-2000:],
            }
        data = json.loads(tmp_path.read_text(encoding="utf-8"))
        result = data["results"][0]
        return {
            "verdict": result.get("verdict"),
            "malware_family": result.get("malware_family") or (
                "benign" if result.get("verdict") == "BENIGN" else None
            ),
            "confidence": result.get("confidence"),
            "raw": result,
        }
    except Exception as exc:
        return {"error": repr(exc)}
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass


def run_deepmal(filepath: Path):
    with tempfile.NamedTemporaryFile(prefix="deepmal_", suffix=".txt", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        cmd = [
            str(DEEPMAL_PY),
            str(DEEPMAL_DIR / "src/deep_malware_detection/detect.py"),
            f"--input={filepath}",
            f"--checkpoint={DEEPMAL_CHECKPOINT}",
            f"--output={tmp_path}",
        ]
        proc = subprocess.run(
            cmd,
            cwd=str(DEEPMAL_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=180,
        )
        text = ""
        if tmp_path.exists():
            text = tmp_path.read_text(encoding="utf-8", errors="replace")
        combined = "\n".join([proc.stdout or "", text])
        if proc.returncode != 0:
            return {
                "error": "deepmal detect failed",
                "returncode": proc.returncode,
                "stderr": proc.stderr[-2000:],
                "stdout": proc.stdout[-2000:],
            }

        verdict_match = re.search(r"^Result\s*:\s*(\w+)", combined, re.MULTILINE)
        family_match = re.search(r"^Family\s*:\s*(\w+)", combined, re.MULTILINE)
        conf_match = re.search(r"^Confidence\s*:\s*([\d.]+)", combined, re.MULTILINE)
        verdict = verdict_match.group(1).upper() if verdict_match else "UNKNOWN"
        family = family_match.group(1) if family_match else None
        if verdict == "BENIGN":
            family = "benign"
        return {
            "verdict": verdict,
            "malware_family": family,
            "confidence": float(conf_match.group(1)) if conf_match else None,
        }
    except Exception as exc:
        return {"error": repr(exc)}
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass


def normalize_label(label):
    if label is None:
        return None
    raw = str(label).strip().lower()
    mapping = {
        "benign": "benign",
        "locker": "Locker",
        "mediyes": "Mediyes",
        "winwebsec": "Winwebsec",
        "zbot": "Zbot",
        "zeroaccess": "Zeroaccess",
    }
    return mapping.get(raw, label)


def run_cnn(filepath: Path):
    global _CNN_STATE
    try:
        if _CNN_STATE is None:
            import numpy as np
            from PIL import Image
            from tensorflow.keras.models import load_model

            class_indices = json.loads(CNN_CLASS_INDICES.read_text(encoding="utf-8"))
            index_to_class = {int(index): class_name for class_name, index in class_indices.items()}
            model = load_model(CNN_MODEL)
            _CNN_STATE = {
                "np": np,
                "Image": Image,
                "model": model,
                "index_to_class": index_to_class,
            }

        np = _CNN_STATE["np"]
        Image = _CNN_STATE["Image"]
        model = _CNN_STATE["model"]
        index_to_class = _CNN_STATE["index_to_class"]

        raw = filepath.read_bytes()
        if not raw:
            return {"error": "empty file"}
        byte_array = np.frombuffer(raw, dtype=np.uint8)
        width_guess = max(1, int(math.sqrt(byte_array.size)))
        width = 1 << math.ceil(math.log2(width_guess))
        height = max(1, byte_array.size // width)
        usable = height * width
        byte_array = byte_array[:usable]

        image = byte_array.reshape((height, width))
        pil_image = Image.fromarray(image, mode="L").convert("RGB")
        pil_image = pil_image.resize((256, 256))
        array = np.asarray(pil_image, dtype=np.float32) / 255.0
        prediction = model.predict(np.expand_dims(array, axis=0), verbose=0)[0]

        best_index = int(np.argmax(prediction))
        best_label = normalize_label(index_to_class[best_index])
        best_score = float(prediction[best_index])
        predictions = {
            normalize_label(index_to_class[int(i)]): float(prediction[int(i)])
            for i in np.argsort(prediction)[::-1]
        }
        return {
            "verdict": "BENIGN" if str(best_label).lower() == "benign" else "MALWARE",
            "malware_family": best_label,
            "confidence": best_score * 100.0,
            "scores": predictions,
        }
    except Exception as exc:
        return {"error": repr(exc)}


def run_ember(filepath: Path):
    global _EMBER_STATE
    try:
        if _EMBER_STATE is None:
            import lightgbm as lgb
            import numpy as np

            src_dir = EMBER_DIR / "src"
            if str(src_dir) not in sys.path:
                sys.path.insert(0, str(src_dir))
            import thrember

            model = lgb.Booster(model_file=str(EMBER_MODEL))
            meta = json.loads(EMBER_LABELS.read_text(encoding="utf-8"))
            labels = list(meta["labels"])
            extractor = thrember.PEFeatureExtractor()
            _EMBER_STATE = {
                "np": np,
                "model": model,
                "labels": labels,
                "extractor": extractor,
            }

        np = _EMBER_STATE["np"]
        model = _EMBER_STATE["model"]
        labels = _EMBER_STATE["labels"]
        extractor = _EMBER_STATE["extractor"]

        features = np.array(extractor.feature_vector(filepath.read_bytes()), dtype=np.float32)
        scores = model.predict([features])[0]
        best_index = int(np.argmax(scores))
        best_label = normalize_label(labels[best_index] if best_index < len(labels) else f"class_{best_index}")
        best_score = float(scores[best_index])
        score_map = {
            normalize_label(labels[int(i)] if int(i) < len(labels) else f"class_{int(i)}"): float(scores[int(i)])
            for i in np.argsort(scores)[::-1]
        }
        return {
            "verdict": "BENIGN" if str(best_label).lower() == "benign" else "MALWARE",
            "malware_family": best_label,
            "confidence": best_score * 100.0,
            "scores": score_map,
        }
    except Exception as exc:
        return {"error": repr(exc)}


def predicted_family(record: dict):
    if "error" in record:
        return None
    if str(record.get("verdict", "")).upper() == "BENIGN":
        return "benign"
    return record.get("malware_family") or "unknown"


def generate_report(jsonl_path: Path, report_path: Path, detector: str, label: str, dataset_root: Path):
    records = []
    if jsonl_path.exists():
        with jsonl_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    by_family = defaultdict(list)
    for record in records:
        by_family[record.get("true_family", "UNKNOWN")].append(record)

    lines = []
    lines.append("=" * 80)
    lines.append(f"DETECTION REPORT: {detector} / {label}")
    lines.append(f"Dataset: {dataset_root}")
    lines.append(f"Total records: {len(records)}")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"{'True':<14} {'Total':>7} {'Correct':>8} {'Wrong':>8} {'Error':>8} {'BenignPred':>10} {'Acc':>8}")
    lines.append("-" * 80)

    grand = Counter()
    family_order = FAMILIES + ["benign"]
    for family in family_order:
        recs = by_family.get(family, [])
        if not recs:
            continue
        total = len(recs)
        errors = sum(1 for r in recs if "error" in r)
        correct = sum(
            1
            for r in recs
            if "error" not in r and str(predicted_family(r)).lower() == family.lower()
        )
        benign_pred = sum(1 for r in recs if predicted_family(r) == "benign")
        wrong = total - errors - correct
        acc = correct / total * 100 if total else 0
        lines.append(
            f"{family:<14} {total:>7} {correct:>8} {wrong:>8} {errors:>8} {benign_pred:>10} {acc:>7.2f}%"
        )
        grand.update(
            total=total,
            correct=correct,
            wrong=wrong,
            error=errors,
            benign_pred=benign_pred,
        )

    g_total = grand["total"]
    g_acc = grand["correct"] / g_total * 100 if g_total else 0
    lines.append("-" * 80)
    lines.append(
        f"{'TOTAL':<14} {g_total:>7} {grand['correct']:>8} {grand['wrong']:>8} "
        f"{grand['error']:>8} {grand['benign_pred']:>10} {g_acc:>7.2f}%"
    )

    malware_records = [r for r in records if r.get("true_family") != "benign"]
    if malware_records:
        evaded = sum(1 for r in malware_records if predicted_family(r) == "benign")
        lines.append("")
        lines.append(f"Malware files predicted benign: {evaded}/{len(malware_records)}")
        lines.append(f"Evasion rate: {(evaded / len(malware_records) * 100):.2f}%")

    lines.append("")
    lines.append("Wrong/error files:")
    any_wrong = False
    for record in records:
        pred = predicted_family(record)
        true = record.get("true_family")
        if "error" in record or str(pred).lower() != str(true).lower():
            any_wrong = True
            lines.append(
                f"- true={true} pred={pred} verdict={record.get('verdict')} "
                f"conf={record.get('confidence')} file={record.get('file')}"
            )
    if not any_wrong:
        lines.append("- none")

    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--detector", choices=["sorel", "deepmal", "cnn", "ember"], required=True)
    parser.add_argument("--dataset-root", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    dataset_root = Path(args.dataset_root).expanduser().resolve()
    out_dir = Path(args.output_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = out_dir / "results.jsonl"
    report_path = out_dir / "report.txt"
    status_path = out_dir / "status.json"

    samples = discover_samples(dataset_root)
    done = load_done(jsonl_path)

    status_path.write_text(
        json.dumps(
            {
                "status": "running",
                "detector": args.detector,
                "label": args.label,
                "dataset_root": str(dataset_root),
                "total_samples": len(samples),
                "already_done": len(done),
                "pid": os.getpid(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    runners = {
        "sorel": run_sorel,
        "deepmal": run_deepmal,
        "cnn": run_cnn,
        "ember": run_ember,
    }
    runner = runners[args.detector]
    processed = 0
    skipped = 0
    failed = 0

    print(f"[START] detector={args.detector} label={args.label} samples={len(samples)}")
    print(f"[OUT] {out_dir}")
    sys.stdout.flush()

    for idx, (filepath, true_family) in enumerate(samples, start=1):
        key = (true_family, filepath.name)
        if key in done:
            skipped += 1
            continue

        result = runner(filepath)
        record = {
            "file": filepath.name,
            "path": str(filepath),
            "true_family": true_family,
            "detector": args.detector,
            "dataset_label": args.label,
        }
        record.update(result)
        if "error" in result:
            failed += 1
        append_jsonl(jsonl_path, record)
        processed += 1

        if processed % 25 == 0 or idx == len(samples):
            generate_report(jsonl_path, report_path, args.detector, args.label, dataset_root)
            status_path.write_text(
                json.dumps(
                    {
                        "status": "running",
                        "detector": args.detector,
                        "label": args.label,
                        "dataset_root": str(dataset_root),
                        "total_samples": len(samples),
                        "processed_this_run": processed,
                        "skipped_existing": skipped,
                        "failed_this_run": failed,
                        "last_index": idx,
                        "pid": os.getpid(),
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            print(f"[PROGRESS] {idx}/{len(samples)} processed={processed} skipped={skipped} failed={failed}")
            sys.stdout.flush()

    generate_report(jsonl_path, report_path, args.detector, args.label, dataset_root)
    status_path.write_text(
        json.dumps(
            {
                "status": "complete",
                "detector": args.detector,
                "label": args.label,
                "dataset_root": str(dataset_root),
                "total_samples": len(samples),
                "processed_this_run": processed,
                "skipped_existing": skipped,
                "failed_this_run": failed,
                "pid": os.getpid(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"[DONE] detector={args.detector} label={args.label} processed={processed} skipped={skipped} failed={failed}")


if __name__ == "__main__":
    main()
