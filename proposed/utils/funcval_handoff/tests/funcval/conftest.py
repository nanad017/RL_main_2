"""Path setup for the funcval test package (handoff-package layout).

The suite resolves ``import funcval`` from the INSTALLED package when funcval has
been ``pip install``-ed into the environment. As a convenience for running the
tests straight from an unpacked source tree (``pytest tests/funcval`` with no
install), this also puts the package's ``src/`` directory on ``sys.path`` so the
src-layout package is importable. Both inserts are guarded, so when funcval is
already importable (installed or ``PYTHONPATH=src``) this is a harmless no-op.
"""
from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = _HERE.parents[1]  # artifacts/dist/funcval_pkg/
_SRC = _PKG_ROOT / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
