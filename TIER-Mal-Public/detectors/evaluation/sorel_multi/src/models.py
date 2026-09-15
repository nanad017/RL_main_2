"""
models.py — SOREL-20M baseline models
  • FFNN: 3-block feed-forward neural network with multi-target heads
    (malware binary output + per-family tag outputs)
    Mirrors the architecture in SOREL-20M / ALOHA (Rudd et al. 2019)
  • LightGBM: gradient-boosted decision tree (single-task malware only,
    same hyper-parameters as SOREL lightgbm_config.json)
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import torch
import torch.nn as nn

from dataset import EMBER_FEATURE_DIM, NUM_TAGS, NUM_FAMILIES, TAG_NAMES, FAMILY_NAMES

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# FFNN  —  100 % mirrors SOREL-20M nets.py
# ═══════════════════════════════════════════════════════════════════════════════

class Block(nn.Module):
    """
    One SOREL block: Linear → LayerNorm → ELU → Dropout
    (exactly as described in Section 3 of the paper)
    """

    def __init__(self, in_dim: int, out_dim: int, dropout: float = 0.05):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, out_dim),
            nn.LayerNorm(out_dim),
            nn.ELU(),
            nn.Dropout(p=dropout),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class MalwareFFNN(nn.Module):
    """
    SOREL-20M Feed-Forward Neural Network.

    Architecture (mirrors SOREL / ALOHA):
      Input (2381-d EMBER features)
      → Block-1 (2381 → 1024)
      → Block-2 (1024 → 512)
      → Block-3 ( 512 → 128)
      → Head: malware  (128 → 1, sigmoid)   — binary malware score
      → Head: tags     (128 → NUM_TAGS, sigmoid) — per-family soft scores
      → Head: family   (128 → NUM_FAMILIES, softmax) — family classification
      → Head: counts   (128 → 1, relu)       — optional detection-count regression

    Training uses multi-target loss (Auxiliary Loss Optimisation, ALOHA):
      L = L_malware + λ_tag * L_tags + λ_fam * L_family
    """

    def __init__(
        self,
        input_dim: int       = EMBER_FEATURE_DIM,
        layer_sizes: Tuple   = (1024, 512, 128),
        dropout: float       = 0.05,
        predict_tags: bool   = True,
        predict_counts: bool = False,
    ):
        super().__init__()
        self.predict_tags   = predict_tags
        self.predict_counts = predict_counts

        dims = [input_dim] + list(layer_sizes)
        self.blocks = nn.Sequential(
            *[Block(dims[i], dims[i + 1], dropout) for i in range(len(dims) - 1)]
        )
        last = dims[-1]

        # Output heads
        self.head_malware = nn.Sequential(nn.Linear(last, 1),  nn.Sigmoid())
        self.head_family  = nn.Linear(last, NUM_FAMILIES)      # CrossEntropy → no softmax here

        if predict_tags:
            self.head_tags = nn.Sequential(nn.Linear(last, NUM_TAGS), nn.Sigmoid())
        if predict_counts:
            self.head_counts = nn.Sequential(nn.Linear(last, 1), nn.ReLU())

    def forward(self, x: torch.Tensor) -> Dict[str, torch.Tensor]:
        h = self.blocks(x)
        out: Dict[str, torch.Tensor] = {
            "malware": self.head_malware(h).squeeze(-1),   # (B,)
            "family":  self.head_family(h),                # (B, NUM_FAMILIES)
        }
        if self.predict_tags:
            out["tags"] = self.head_tags(h)                # (B, NUM_TAGS)
        if self.predict_counts:
            out["counts"] = self.head_counts(h).squeeze(-1)
        return out


# ═══════════════════════════════════════════════════════════════════════════════
# Multi-target loss  (ALOHA)
# ═══════════════════════════════════════════════════════════════════════════════

class MultiTargetLoss(nn.Module):
    """
    Combined loss for multi-target learning:
      L = BCE(malware) + λ_tag * BCE(tags) + λ_fam * CE(family)
    where CE is only computed over malware samples (label==1).
    """

    def __init__(
        self,
        lambda_tag: float = 0.5,
        lambda_family: float = 0.5,
        predict_tags: bool = True,
    ):
        super().__init__()
        self.lambda_tag    = lambda_tag
        self.lambda_family = lambda_family
        self.predict_tags  = predict_tags
        self.bce = nn.BCELoss()
        self.ce  = nn.CrossEntropyLoss()

    def forward(
        self,
        outputs: Dict[str, torch.Tensor],
        mal_labels: torch.Tensor,
        fam_labels: torch.Tensor,
        tag_labels: torch.Tensor,
    ) -> Tuple[torch.Tensor, Dict[str, float]]:

        loss_mal = self.bce(outputs["malware"], mal_labels)
        total    = loss_mal

        loss_tag = torch.tensor(0.0)
        if self.predict_tags and "tags" in outputs:
            # Only compute tag loss on malware samples
            mal_mask = mal_labels == 1
            if mal_mask.sum() > 0:
                loss_tag = self.bce(outputs["tags"][mal_mask], tag_labels[mal_mask])
                total = total + self.lambda_tag * loss_tag

        loss_fam = torch.tensor(0.0)
        mal_mask = mal_labels == 1
        if mal_mask.sum() > 0:
            loss_fam = self.ce(outputs["family"][mal_mask], fam_labels[mal_mask])
            total = total + self.lambda_family * loss_fam

        breakdown = {
            "total":  total.item(),
            "malware": loss_mal.item(),
            "tags":    loss_tag.item() if isinstance(loss_tag, float) else loss_tag.item(),
            "family":  loss_fam.item() if isinstance(loss_fam, float) else loss_fam.item(),
        }
        return total, breakdown


# ═══════════════════════════════════════════════════════════════════════════════
# LightGBM wrapper  (mirrors SOREL lightgbm_config.json)
# ═══════════════════════════════════════════════════════════════════════════════

LIGHTGBM_CONFIG: Dict = {
    "objective":          "binary",
    "metric":             "auc",
    "num_leaves":         64,
    "max_depth":          -1,           # unbounded — same as SOREL
    "bagging_fraction":   0.9,
    "feature_fraction":   0.9,          # tree-level subselection
    "feature_fraction_bynode": 0.9,     # node-level subselection
    "n_estimators":       500,
    "early_stopping_rounds": 10,
    "learning_rate":      0.05,
    "verbose":            -1,
    "n_jobs":             -1,
    "random_state":       42,
}


class LightGBMDetector:
    """
    Thin wrapper around lightgbm.LGBMClassifier using SOREL hyper-parameters.
    Trained only on the binary malware label (no multi-target in LightGBM,
    same limitation noted in the paper).
    """

    def __init__(self, config: Optional[Dict] = None):
        try:
            import lightgbm as lgb
            self._lgb = lgb
        except ImportError:
            raise ImportError("Install LightGBM: pip install lightgbm")

        cfg = config or LIGHTGBM_CONFIG
        early = cfg.pop("early_stopping_rounds", 10)
        self.early_stopping_rounds = early
        self.model = self._lgb.LGBMClassifier(**cfg)

    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray,
    ):
        callbacks = [
            self._lgb.early_stopping(self.early_stopping_rounds, verbose=True),
            self._lgb.log_evaluation(50),
        ]
        self.model.fit(
            X_train, y_train,
            eval_set=[(X_val, y_val)],
            callbacks=callbacks,
        )

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)[:, 1]

    def save(self, path: str):
        import joblib
        joblib.dump(self.model, path)
        logger.info(f"LightGBM model saved → {path}")

    @classmethod
    def load(cls, path: str) -> "LightGBMDetector":
        import joblib
        obj = cls.__new__(cls)
        try:
            import lightgbm as lgb
            obj._lgb = lgb
        except ImportError:
            raise ImportError("Install LightGBM: pip install lightgbm")
        obj.model = joblib.load(path)
        obj.early_stopping_rounds = 10
        return obj