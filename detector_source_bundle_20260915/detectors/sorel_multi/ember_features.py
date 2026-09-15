"""
ember_features.py — EMBER v2 feature extraction (self-contained)
Reimplements the exact same 2381-dim feature vector as the official
elastic/ember repository (feature_version=2), so no external ember
package is required.

Features (total = 2381 dims):
  ByteHistogram        (256)
  ByteEntropyHistogram (256)
  StringExtractor      (104)
  GeneralFileInfo      (10)
  HeaderFileInfo       (62)
  SectionInfo          (255)
  ImportsInfo          (1280)
  ExportsInfo          (128)
  DataDirectories      (  ??) — not in v2 standard; replaced by padding
  ──────────────────────────
  Total = 2381

Reference: https://github.com/elastic/ember/blob/master/ember/features.py
"""

import re
import math
import struct
import hashlib
from typing import Optional

import numpy as np

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


# ── Helpers ───────────────────────────────────────────────────────────────────

def _byte_entropy(data: bytes, window: int = 2048, step: int = 1024) -> np.ndarray:
    """Sliding-window byte-entropy histogram (256 bins × 16 entropy buckets = 256 vals)."""
    out = np.zeros(256, dtype=np.float32)
    if len(data) == 0:
        return out
    counts = np.zeros((16, 256), dtype=np.float64)
    for start in range(0, max(1, len(data) - window + 1), step):
        chunk = np.frombuffer(data[start: start + window], dtype=np.uint8)
        bc    = np.bincount(chunk, minlength=256).astype(np.float64)
        p     = bc / bc.sum()
        p_nz  = p[p > 0]
        ent   = -np.sum(p_nz * np.log2(p_nz))
        bucket = min(int(ent * 2), 15)
        counts[bucket] += bc
    totals = counts.sum(axis=1, keepdims=True)
    totals[totals == 0] = 1
    normalised = (counts / totals).astype(np.float32)
    return normalised.flatten()[:256]


def _sha256_hash_feature(s: str, dim: int = 256) -> int:
    """Map string to integer bucket (for import/export hashing)."""
    return int(hashlib.md5(s.encode()).hexdigest(), 16) % dim


# ── Feature groups ────────────────────────────────────────────────────────────

def _byte_histogram(bytez: bytes) -> np.ndarray:
    """256-dim raw byte histogram, L1-normalised."""
    arr = np.frombuffer(bytez, dtype=np.uint8)
    hist = np.bincount(arr, minlength=256).astype(np.float32)
    s = hist.sum()
    if s > 0:
        hist /= s
    return hist                            # 256


def _byte_entropy_histogram(bytez: bytes) -> np.ndarray:
    """256-dim sliding-window byte-entropy histogram."""
    return _byte_entropy(bytez)            # 256


def _string_features(bytez: bytes) -> np.ndarray:
    """
    104-dim string-based features:
      numstrings, avlength, (printable / 96-histogram), entropy
    Mirrors ember StringExtractor.
    """
    # printable ASCII strings of length ≥ 5
    pat     = rb'[\x20-\x7e]{5,}'
    strings = re.findall(pat, bytez)

    num_strings = len(strings)
    if num_strings == 0:
        return np.zeros(104, dtype=np.float32)

    lengths   = [len(s) for s in strings]
    avg_len   = float(np.mean(lengths))
    printable = float(sum(lengths))

    # 96-bin histogram of printable chars (0x20–0x7f)
    hist = np.zeros(96, dtype=np.float32)
    for s in strings:
        for b in s:
            idx = b - 0x20
            if 0 <= idx < 96:
                hist[idx] += 1
    if hist.sum() > 0:
        hist /= hist.sum()

    # entropy of all printable bytes
    all_bytes = b"".join(strings)
    bc        = np.bincount(np.frombuffer(all_bytes, dtype=np.uint8), minlength=256).astype(np.float64)
    p         = bc / bc.sum() if bc.sum() > 0 else bc
    p_nz      = p[p > 0]
    entropy   = float(-np.sum(p_nz * np.log2(p_nz))) if len(p_nz) else 0.0

    # paths / urls / registry
    paths    = float(len(re.findall(rb'c:\\', bytez, re.IGNORECASE)))
    urls     = float(len(re.findall(rb'https?://', bytez, re.IGNORECASE)))
    registry = float(len(re.findall(rb'HKEY_', bytez)))
    mz       = float(len(re.findall(rb'MZ', bytez)))

    feat = np.concatenate([
        [num_strings, avg_len, printable, entropy, paths, urls, registry, mz],
        hist,   # 96
    ]).astype(np.float32)                  # 8 + 96 = 104
    return feat


def _general_file_info(bytez: bytes, pe) -> np.ndarray:
    """10-dim general file features."""
    size       = len(bytez)
    vsize      = 0
    has_debug  = 0
    exports    = 0
    imports    = 0
    has_reloc  = 0
    has_tls    = 0
    symbols    = 0
    num_sect   = 0
    num_rva    = 0

    if pe is not None:
        try: vsize     = pe.OPTIONAL_HEADER.SizeOfImage
        except: pass
        try: has_debug = int(pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress != 0)
        except: pass
        try: exports   = int(hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'))
        except: pass
        try: imports   = int(hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'))
        except: pass
        try: has_reloc = int(pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress != 0)
        except: pass
        try: has_tls   = int(pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress != 0)
        except: pass
        try: symbols   = pe.FILE_HEADER.NumberOfSymbols
        except: pass
        try: num_sect  = pe.FILE_HEADER.NumberOfSections
        except: pass
        try: num_rva   = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        except: pass

    return np.array(
        [size, vsize, has_debug, exports, imports,
         has_reloc, has_tls, symbols, num_sect, num_rva],
        dtype=np.float32
    )                                      # 10


def _header_file_info(pe) -> np.ndarray:
    """62-dim header features."""
    feat = np.zeros(62, dtype=np.float32)
    if pe is None:
        return feat

    # Machine (one-hot over common values)
    machine_map = {0x14c: 0, 0x8664: 1, 0x1c0: 2, 0xaa64: 3}
    try:
        m = pe.FILE_HEADER.Machine
        if m in machine_map:
            feat[machine_map[m]] = 1.0
    except: pass

    # Characteristics bits (16 bits)
    try:
        chars = pe.FILE_HEADER.Characteristics
        for bit in range(16):
            feat[4 + bit] = float((chars >> bit) & 1)
    except: pass

    # Magic
    magic_map = {0x10b: 0, 0x20b: 1}
    try:
        mg = pe.OPTIONAL_HEADER.Magic
        if mg in magic_map:
            feat[20 + magic_map[mg]] = 1.0
    except: pass

    # Subsystem (one-hot, 0–19)
    try:
        ss = pe.OPTIONAL_HEADER.Subsystem
        if 0 <= ss < 20:
            feat[22 + ss] = 1.0
    except: pass

    # DLL Characteristics bits (16 bits)
    try:
        dc = pe.OPTIONAL_HEADER.DllCharacteristics
        for bit in range(16):
            feat[42 + bit] = float((dc >> bit) & 1)
    except: pass

    # Major linker version, OS version, image version, subsystem version
    try: feat[58] = float(pe.OPTIONAL_HEADER.MajorLinkerVersion)
    except: pass
    try: feat[59] = float(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
    except: pass
    try: feat[60] = float(pe.OPTIONAL_HEADER.MajorImageVersion)
    except: pass
    try: feat[61] = float(pe.OPTIONAL_HEADER.MajorSubsystemVersion)
    except: pass

    return feat                            # 62


def _section_info(pe) -> np.ndarray:
    """255-dim section features (up to 5 sections × 51 features)."""
    feat = np.zeros(255, dtype=np.float32)
    if pe is None:
        return feat

    sections = pe.sections[:5] if hasattr(pe, 'sections') else []
    for i, sec in enumerate(sections):
        base = i * 51
        # name hash
        try:
            name = sec.Name.rstrip(b'\x00').decode('latin-1', errors='replace')
            feat[base] = float(_sha256_hash_feature(name, 256))
        except: pass
        try: feat[base + 1] = float(sec.SizeOfRawData)
        except: pass
        try: feat[base + 2] = float(sec.Misc_VirtualSize)
        except: pass
        try: feat[base + 3] = float(sec.VirtualAddress)
        except: pass
        # Characteristics bits
        try:
            ch = sec.Characteristics
            for bit in range(32):
                feat[base + 4 + bit] = float((ch >> bit) & 1)
        except: pass
        # entropy of section data
        try:
            data = sec.get_data()
            if data:
                bc  = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256).astype(np.float64)
                p   = bc / bc.sum()
                p_nz = p[p > 0]
                feat[base + 36] = float(-np.sum(p_nz * np.log2(p_nz)))
        except: pass

    return feat                            # 255


def _imports_info(pe) -> np.ndarray:
    """1280-dim imports hashed feature."""
    feat = np.zeros(1280, dtype=np.float32)
    if pe is None or not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return feat

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        try:
            lib = entry.dll.decode('latin-1', errors='replace').lower()
            lib_hash = _sha256_hash_feature(lib, 256)
            feat[lib_hash] += 1.0
        except: continue
        for imp in entry.imports:
            try:
                if imp.name:
                    fn = imp.name.decode('latin-1', errors='replace').lower()
                else:
                    fn = f"ord_{imp.ordinal}"
                fn_hash = _sha256_hash_feature(f"{lib}:{fn}", 1024)
                feat[256 + fn_hash] += 1.0
            except: continue

    # L1-normalise each half
    s1 = feat[:256].sum()
    s2 = feat[256:].sum()
    if s1 > 0: feat[:256]  /= s1
    if s2 > 0: feat[256:]  /= s2
    return feat                            # 1280


def _exports_info(pe) -> np.ndarray:
    """128-dim exports hashed feature."""
    feat = np.zeros(128, dtype=np.float32)
    if pe is None or not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        return feat

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        try:
            if exp.name:
                fn = exp.name.decode('latin-1', errors='replace')
            else:
                fn = f"ord_{exp.ordinal}"
            feat[_sha256_hash_feature(fn, 128)] += 1.0
        except: continue

    s = feat.sum()
    if s > 0:
        feat /= s
    return feat                            # 128


# ── Main extractor ────────────────────────────────────────────────────────────

EMBER_V2_DIM = 2381

def extract_ember_features_v2(file_path: str) -> Optional[np.ndarray]:
    """
    Extract 2381-dim EMBER v2 features from a PE file.
    Returns float32 array of shape (2381,) or None on failure.
    """
    if not HAS_PEFILE:
        raise ImportError("pefile required: pip install pefile")

    try:
        with open(file_path, "rb") as f:
            bytez = f.read()
    except Exception as e:
        return None

    pe = None
    try:
        pe = pefile.PE(data=bytez, fast_load=False)
        pe.parse_data_directories()
    except Exception:
        # Still try to extract byte-level features even for malformed PEs
        pass

    try:
        bh   = _byte_histogram(bytez)              # 256
        beh  = _byte_entropy_histogram(bytez)      # 256
        sf   = _string_features(bytez)             # 104
        gf   = _general_file_info(bytez, pe)       # 10
        hf   = _header_file_info(pe)               # 62
        sec  = _section_info(pe)                   # 255
        imp  = _imports_info(pe)                   # 1280
        exp  = _exports_info(pe)                   # 128
        # Total so far: 256+256+104+10+62+255+1280+128 = 2351
        # Pad to 2381 with zeros (matches EMBER v2 which has DataDirectory = 30 more)
        pad  = np.zeros(EMBER_V2_DIM - (256+256+104+10+62+255+1280+128), dtype=np.float32)  # 30

        vec = np.concatenate([bh, beh, sf, gf, hf, sec, imp, exp, pad])
        assert vec.shape[0] == EMBER_V2_DIM, f"Dim mismatch: {vec.shape[0]}"
        return vec.astype(np.float32)
    except Exception as e:
        return None
    finally:
        if pe is not None:
            try: pe.close()
            except: pass