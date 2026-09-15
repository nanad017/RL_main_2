"""
server.py — Minimal Flask REST wrapper for SOREL LightGBM detector.

Endpoints:
    POST /scan       — multipart file upload, returns {"malware_score": float, ...}
    GET  /health     — liveness check
    GET  /healthz    — alias for /health

Usage:
    cd /home/rl/detector/sorel_multi
    python server.py --host 127.0.0.1 --port 5000
"""

import argparse
import hashlib
import io
import os
import sys
import tempfile
import time

# Insert src/ so dataset + models resolve
_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
sys.path.insert(0, _src)

from flask import Flask, jsonify, request
import numpy as np

from dataset import extract_ember_features
from models import LightGBMDetector

app = Flask(__name__)

# Globals — loaded once at startup
_lgbm = None
_threshold = 0.5
_start_time = time.time()


def _load_model(model_path: str, threshold: float):
    global _lgbm, _threshold
    print(f"[server] Loading LightGBM model from {model_path} ...")
    _lgbm = LightGBMDetector.load(model_path)
    _threshold = threshold
    print(f"[server] Model loaded. Threshold={_threshold:.4f}")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "backend": "lightgbm",
        "model_loaded": _lgbm is not None,
        "uptime_s": round(time.time() - _start_time, 1),
    })


@app.route("/healthz", methods=["GET"])
def healthz():
    return "ok" if _lgbm is not None else ("not ready", 503)


@app.route("/scan", methods=["POST"])
def scan():
    if _lgbm is None:
        return jsonify({"error": "model not loaded"}), 503

    # Accept multipart file upload
    if "file" not in request.files:
        return jsonify({"error": "no 'file' field in multipart upload"}), 400

    f = request.files["file"]
    raw = f.read()
    if len(raw) == 0:
        return jsonify({"error": "empty file"}), 400

    sha256 = hashlib.sha256(raw).hexdigest()

    # Write to temp file for feature extraction (ember needs a path)
    tmp = None
    try:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
        tmp.write(raw)
        tmp.close()

        features = extract_ember_features(tmp.name)
        if features is None:
            return jsonify({
                "error": "feature extraction failed",
                "sha256": sha256,
                "malware_score": 0.0,
            }), 200

        score = float(_lgbm.predict_proba(features.reshape(1, -1))[0])
        verdict = "MALWARE" if score >= _threshold else "BENIGN"

        return jsonify({
            "malware_score": round(score, 6),
            "threshold": _threshold,
            "verdict": verdict,
            "sha256": sha256,
            "file_size": len(raw),
        })
    except Exception as e:
        return jsonify({
            "error": str(e),
            "sha256": sha256,
            "malware_score": 0.0,
        }), 500
    finally:
        if tmp and os.path.exists(tmp.name):
            os.unlink(tmp.name)


def main():
    parser = argparse.ArgumentParser(description="SOREL LightGBM REST server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--model", default="baselines/lgbm_seed1.joblib",
                        help="Path to LightGBM joblib model")
    parser.add_argument("--threshold", type=float, default=0.5,
                        help="Detection threshold (default 0.5)")
    args = parser.parse_args()

    _load_model(args.model, args.threshold)

    print(f"[server] Listening on http://{args.host}:{args.port}")
    print(f"[server] Endpoints:")
    print(f"  POST /scan       — multipart file upload")
    print(f"  GET  /health     — health check")
    print(f"  GET  /healthz    — alias")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
