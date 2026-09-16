import glob
import json
import os.path
import re
import sys
from collections import defaultdict

module_path = os.path.dirname(os.path.abspath(sys.modules[__name__].__file__))
SAMPLE_PATH = os.path.join(module_path, "samples")
_SAMPLE_ROOT_BY_ID = {}


def _normalize_sample_root(sample_root):
    return os.path.abspath(os.path.expanduser(sample_root))


def _resolve_sample_path(sample_root, sample_id):
    root = _normalize_sample_root(sample_root)
    sample_path = os.path.abspath(os.path.join(root, sample_id))
    if os.path.commonpath([root, sample_path]) != root:
        raise ValueError(f"Sample id escapes dataset root: {sample_id}")
    return sample_path


def register_sample_roots(sample_ids, sample_root):
    root = _normalize_sample_root(sample_root)
    for sample_id in sample_ids:
        previous_root = _SAMPLE_ROOT_BY_ID.get(sample_id)
        if previous_root and previous_root != root:
            raise ValueError(
                "Sample id appears in multiple dataset roots: "
                f"{sample_id}. Use unique relative paths for train/test samples."
            )
        _SAMPLE_ROOT_BY_ID[sample_id] = root


def fetch_file(sample_path):
    with open(sample_path, "rb") as f:
        bytez = f.read()
    return bytez


def fetch_sample(sample_id):
    sample_root = _SAMPLE_ROOT_BY_ID.get(sample_id, SAMPLE_PATH)
    return fetch_file(_resolve_sample_path(sample_root, sample_id))


def get_sample_family(sample_id):
    parts = sample_id.replace("\\", "/").split("/")
    return parts[0] if len(parts) > 1 else "Uncategorized"


def get_evasion_output_path(output_path, original_sample_id, output_name):
    relative_dir = os.path.dirname(original_sample_id)
    evade_dir = os.path.join(output_path, relative_dir)
    os.makedirs(evade_dir, exist_ok=True)
    return os.path.join(evade_dir, output_name)


def save_dataset_split(
    train_samples,
    holdout_samples,
    output_dir,
    train_root=None,
    test_root=None,
):
    os.makedirs(output_dir, exist_ok=True)

    split = {
        "train": list(train_samples),
        "test": list(holdout_samples),
    }
    if train_root or test_root:
        split["source_roots"] = {
            "train": _normalize_sample_root(train_root) if train_root else None,
            "test": _normalize_sample_root(test_root) if test_root else None,
        }

    with open(os.path.join(output_dir, "split.json"), "w", encoding="utf-8") as f:
        json.dump(split, f, indent=2)

    for split_name, samples in (("train", split["train"]), ("test", split["test"])):
        with open(os.path.join(output_dir, f"{split_name}.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(samples))
            if samples:
                f.write("\n")

        by_family = defaultdict(list)
        for sample in samples:
            by_family[get_sample_family(sample)].append(sample)

        for family, family_samples in by_family.items():
            family_dir = os.path.join(output_dir, split_name, family)
            os.makedirs(family_dir, exist_ok=True)
            with open(os.path.join(family_dir, "samples.txt"), "w", encoding="utf-8") as f:
                f.write("\n".join(family_samples))
                if family_samples:
                    f.write("\n")


def load_dataset_split(split_path):
    with open(split_path, "r", encoding="utf-8") as f:
        split = json.load(f)

    missing_keys = [key for key in ("train", "test") if key not in split]
    if missing_keys:
        raise ValueError(
            "Split file is missing required key(s): " + ", ".join(missing_keys)
        )

    source_roots = split.get("source_roots", {})
    train_root = source_roots.get("train")
    test_root = source_roots.get("test")
    if train_root:
        register_sample_roots(split["train"], train_root)
    if test_root:
        register_sample_roots(split["test"], test_root)

    return list(split["train"]), list(split["test"])


def get_available_sha256(sample_root=None):
    sample_root = _normalize_sample_root(sample_root or SAMPLE_PATH)
    sha256list = []
    for fp in glob.glob(os.path.join(sample_root, "**", "*"), recursive=True):
        if not os.path.isfile(fp):
            continue
        fn = os.path.relpath(fp, sample_root)
        parts = fn.replace(os.sep, "/").split("/")
        if any(part.startswith(".") for part in parts):
            continue
        sha256list.append(fn.replace(os.sep, "/"))
        # require filenames to be sha256
        # result = re.match(r"^[0-9a-fA-F]{64}$", fn)
        # if result:
        #     sha256list.append(result.group(0))
    # no files found in SAMLPE_PATH with sha256 names
    assert len(sha256list) > 0, f"No sample files found in: {sample_root}"
    return sha256list
