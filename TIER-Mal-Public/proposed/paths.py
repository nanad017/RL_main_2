"""Canonical locations for the reorganized source tree."""

from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent
RUNTIME_DIR = PROJECT_ROOT / "runtime"
MODEL_DIR = PACKAGE_ROOT / "models"
