"""
dataset.py — SOREL-20M style dataset loader
Loads PE files from dataset/{benign, virus/{Locker,Mediyes,Winwebsec,Zbot,Zeroaccess}}
Extracts EMBER v2 features identical to SOREL-20M pipeline.
"""

import os
import json
import hashlib
import pickle
import sqlite3
import logging
from pathlib import Path
from typing import Optional, Tuple, List, Dict

import numpy as np
import torch
from torch.utils.data import Dataset, DataLoader
import lmdb
import msgpack
import zlib

# Self-contained EMBER v2 extractor — no external ember package needed
import sys as _sys, pathlib as _pl
_this_dir    = str(_pl.Path(__file__).resolve().parent)          # src/
_project_dir = str(_pl.Path(__file__).resolve().parent.parent)  # project root
for _d in [_this_dir, _project_dir]:
    if _d not in _sys.path:
        _sys.path.insert(0, _d)
from ember_features import extract_ember_features_v2

logger = logging.getLogger(__name__)

# ── Label maps (mirrors SOREL meta.db schema) ────────────────────────────────
FAMILY_LABELS: Dict[str, int] = {
    "benign":      0,
    "Locker":      1,
    "Mediyes":     2,
    "Winwebsec":   3,
    "Zbot":        4,
    "Zeroaccess":  5,
}
FAMILY_NAMES: Dict[int, str] = {v: k for k, v in FAMILY_LABELS.items()}
NUM_FAMILIES: int = len(FAMILY_LABELS)   # 6

MALWARE_LABEL: Dict[str, int] = {k: (0 if k == "benign" else 1) for k in FAMILY_LABELS}

TAG_NAMES: List[str] = ["Locker", "Mediyes", "Winwebsec", "Zbot", "Zeroaccess"]
NUM_TAGS: int = len(TAG_NAMES)

EMBER_FEATURE_DIM: int = 2381


# ── EMBER v2 feature extraction ───────────────────────────────────────────────

def extract_ember_features(file_path: str) -> Optional[np.ndarray]:
    """Extract 2381-dim EMBER v2 features using self-contained extractor."""
    try:
        vec = extract_ember_features_v2(file_path)
        if vec is None:
            logger.warning(f"Feature extraction returned None for {file_path}")
        return vec
    except Exception as e:
        logger.warning(f"Feature extraction failed for {file_path}: {e}")
        return None


# ── SQLite meta.db ────────────────────────────────────────────────────────────

def init_meta_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS samples (
            sha256          TEXT PRIMARY KEY,
            label           INTEGER NOT NULL,
            family          INTEGER NOT NULL,
            split           TEXT NOT NULL,
            first_seen      INTEGER DEFAULT 0,
            detection_count INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tags (
            sha256  TEXT NOT NULL,
            tag     TEXT NOT NULL,
            PRIMARY KEY (sha256, tag),
            FOREIGN KEY (sha256) REFERENCES samples(sha256)
        )
    """)
    conn.commit()
    return conn


# ── Dataset scanner ───────────────────────────────────────────────────────────

def scan_dataset_dir(
    dataset_root: str,
    train_ratio: float = 0.65,
    val_ratio: float = 0.13,
    seed: int = 42,
) -> List[Dict]:
    """
    Walk dataset root and find all PE samples.
    Accepts these layouts:
      dataset/benign/         and  dataset/virus/Locker/ ...
      dataset/benign/              dataset/Locker/ ...       (families at root)
    """
    rng = np.random.RandomState(seed)
    samples = []

    dataset_root = Path(dataset_root).resolve()
    logger.info(f"Scanning dataset root: {dataset_root}")

    if not dataset_root.exists():
        logger.error(f"Dataset root does not exist: {dataset_root}")
        return samples

    # ── Benign: try common case-variations ───────────────────────────────────
    benign_dir = None
    for candidate in ["benign", "Benign", "BENIGN"]:
        d = dataset_root / candidate
        if d.exists():
            benign_dir = d
            break

    if benign_dir:
        count = 0
        for fp in sorted(benign_dir.rglob("*")):
            if fp.is_file():
                samples.append({"path": str(fp), "family": "benign"})
                count += 1
        logger.info(f"  benign/  : {count} files")
    else:
        logger.warning(f"  No benign/ directory found under {dataset_root}")

    # ── Malware families ─────────────────────────────────────────────────────
    # Search order: dataset/virus/<family>/  then  dataset/<family>/
    search_roots = []
    for candidate in ["virus", "malware", "Virus", "Malware", "VIRUS", "MALWARE"]:
        d = dataset_root / candidate
        if d.exists():
            search_roots.append(d)
    search_roots.append(dataset_root)   # families directly under root (fallback)

    found_families: set = set()
    for search in search_roots:
        for family_dir in sorted(search.iterdir()):
            name = family_dir.name
            if (family_dir.is_dir()
                    and name in FAMILY_LABELS
                    and name != "benign"
                    and name not in found_families):
                count = 0
                for fp in sorted(family_dir.rglob("*")):
                    if fp.is_file():
                        samples.append({"path": str(fp), "family": name})
                        count += 1
                found_families.add(name)
                logger.info(f"  {name}/   : {count} files")

    if not samples:
        logger.error(
            "No samples found! Check that your dataset folder contains:\n"
            "  dataset/benign/         (benign PE files)\n"
            "  dataset/virus/Locker/   (or dataset/Locker/ etc.)\n"
            "  dataset/virus/Mediyes/\n"
            "  dataset/virus/Winwebsec/\n"
            "  dataset/virus/Zbot/\n"
            "  dataset/virus/Zeroaccess/"
        )
        return samples

    # ── Shuffle and assign splits ─────────────────────────────────────────────
    indices = rng.permutation(len(samples))
    n       = len(indices)
    n_train = int(n * train_ratio)
    n_val   = int(n * val_ratio)

    split_map: Dict[int, str] = {}
    for i, idx in enumerate(indices):
        if i < n_train:
            split_map[idx] = "train"
        elif i < n_train + n_val:
            split_map[idx] = "validation"
        else:
            split_map[idx] = "test"

    for i, s in enumerate(samples):
        s["split"] = split_map[i]

    logger.info(
        f"Total {len(samples)} samples → "
        f"{sum(1 for s in samples if s['split']=='train')} train / "
        f"{sum(1 for s in samples if s['split']=='validation')} val / "
        f"{sum(1 for s in samples if s['split']=='test')} test"
    )
    return samples


# ── Build processed-data databases ───────────────────────────────────────────

def build_databases(
    dataset_root: str,
    processed_data_dir: str,
    map_size_gb: int = 50,
):
    processed_data_dir = Path(processed_data_dir)
    processed_data_dir.mkdir(parents=True, exist_ok=True)

    db_path   = str(processed_data_dir / "meta.db")
    lmdb_emb  = str(processed_data_dir / "ember_features")
    lmdb_meta = str(processed_data_dir / "pe_metadata")

    conn = init_meta_db(db_path)

    map_size = map_size_gb * 1024 ** 3
    emb_env  = lmdb.open(lmdb_emb,  map_size=map_size, max_dbs=1)
    meta_env = lmdb.open(lmdb_meta, map_size=map_size, max_dbs=1)

    samples = scan_dataset_dir(dataset_root)
    ok, fail = 0, 0

    for s in samples:
        path   = s["path"]
        family = s["family"]
        split  = s["split"]

        with open(path, "rb") as f:
            raw = f.read()
        sha256 = hashlib.sha256(raw).hexdigest()

        label  = MALWARE_LABEL[family]
        fam_id = FAMILY_LABELS[family]

        vec = extract_ember_features(path)
        if vec is None:
            fail += 1
            continue

        packed      = zlib.compress(msgpack.packb(vec.tolist()))
        packed_meta = zlib.compress(msgpack.packb({"path": path, "sha256": sha256, "family": family}))

        key = sha256.encode()
        with emb_env.begin(write=True) as txn:
            txn.put(key, packed)
        with meta_env.begin(write=True) as txn:
            txn.put(key, packed_meta)

        conn.execute(
            "INSERT OR REPLACE INTO samples VALUES (?,?,?,?,?,?)",
            (sha256, label, fam_id, split, 0, 0),
        )
        if family != "benign":
            conn.execute("INSERT OR REPLACE INTO tags VALUES (?,?)", (sha256, family))

        ok += 1
        if ok % 200 == 0:
            conn.commit()
            logger.info(f"  Processed {ok}/{len(samples)} samples (failed={fail})…")

    conn.commit()
    conn.close()
    emb_env.close()
    meta_env.close()
    logger.info(f"Build complete. ok={ok}, failed={fail}")
    return db_path, lmdb_emb, lmdb_meta


# ── PyTorch Dataset ───────────────────────────────────────────────────────────

class SorelDataset(Dataset):
    _env_cache: dict = {}  # shared LMDB envs across instances

    def __init__(
        self,
        meta_db_path: str,
        ember_lmdb_path: str,
        split: str = "train",
        mode: str = "all",
        predict_tags: bool = True,
    ):
        self.split        = split
        self.mode         = mode
        self.predict_tags = predict_tags

        # Reuse existing LMDB environment if already open in this process
        if ember_lmdb_path not in SorelDataset._env_cache:
            SorelDataset._env_cache[ember_lmdb_path] = lmdb.open(
                ember_lmdb_path, readonly=True, lock=False,
                max_readers=256, max_spare_txns=4
            )
        self.emb_env = SorelDataset._env_cache[ember_lmdb_path]

        conn  = sqlite3.connect(meta_db_path)
        rows  = conn.execute(
            "SELECT sha256, label, family FROM samples WHERE split=?", (split,)
        ).fetchall()
        tag_rows = conn.execute("SELECT sha256, tag FROM tags").fetchall()
        conn.close()

        self.tag_index: Dict[str, set] = {}
        for sha, tag in tag_rows:
            self.tag_index.setdefault(sha, set()).add(tag)

        if mode == "malware_only":
            rows = [(s, l, f) for s, l, f in rows if l == 1]
        elif mode == "benign_only":
            rows = [(s, l, f) for s, l, f in rows if l == 0]

        self.index = rows
        logger.info(f"SorelDataset [{split}/{mode}]: {len(self.index)} samples")

    def __len__(self) -> int:
        return len(self.index)

    def __getitem__(self, idx: int) -> Tuple:
        sha256, label, family_id = self.index[idx]
        key = sha256.encode()

        with self.emb_env.begin() as txn:
            raw = txn.get(key)

        if raw is None:
            vec = np.zeros(EMBER_FEATURE_DIM, dtype=np.float32)
        else:
            vec = np.array(msgpack.unpackb(zlib.decompress(raw)), dtype=np.float32)

        features = torch.tensor(vec, dtype=torch.float32)
        mal_lbl  = torch.tensor(label,     dtype=torch.float32)
        fam_lbl  = torch.tensor(family_id, dtype=torch.long)

        tags = self.tag_index.get(sha256, set())
        tag_vec = torch.zeros(NUM_TAGS, dtype=torch.float32)
        for i, t in enumerate(TAG_NAMES):
            if t in tags:
                tag_vec[i] = 1.0

        return features, mal_lbl, fam_lbl, tag_vec

    def close(self):
        self.emb_env.close()


# ── GeneratorFactory ──────────────────────────────────────────────────────────

class GeneratorFactory:
    def __init__(
        self,
        meta_db_path: str,
        ember_lmdb_path: str,
        split: str = "train",
        batch_size: int = 512,
        num_workers: int = 4,
        predict_tags: bool = True,
        mode: str = "all",
        pin_memory: bool = False,
    ):
        self.dataset = SorelDataset(
            meta_db_path=meta_db_path,
            ember_lmdb_path=ember_lmdb_path,
            split=split,
            mode=mode,
            predict_tags=predict_tags,
        )
        if len(self.dataset) == 0:
            raise RuntimeError(
                f"Dataset split '{split}' has 0 samples. "
                "Run --build-db first and check your dataset directory structure."
            )
        self.loader = DataLoader(
            self.dataset,
            batch_size=batch_size,
            shuffle=(split == "train"),
            num_workers=num_workers,
            pin_memory=pin_memory,
            drop_last=False,
        )

    def __iter__(self):
        return iter(self.loader)

    def __len__(self):
        return len(self.loader)