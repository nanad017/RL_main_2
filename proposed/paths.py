"""Canonical locations for the reorganized source tree."""

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
RUNTIME_DIR = PROJECT_ROOT / "runtime"
MODEL_DIR = PROJECT_ROOT / "models"
