import argparse
import hashlib
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SRC_DIR = SCRIPT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from thrember.features import PEFeatureExtractor


PE_SUFFIXES = {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".drv"}


def collect_samples(dataset_dir: Path) -> list[tuple[Path, int, str | None]]:
    samples: list[tuple[Path, int, str | None]] = []

    benign_dir = dataset_dir / "benign"
    if benign_dir.is_dir():
        for path in sorted(benign_dir.rglob("*")):
            if path.is_file() and path.suffix.lower() in PE_SUFFIXES:
                samples.append((path, 0, None))

    virus_dir = dataset_dir / "virus"
    if virus_dir.is_dir():
        for family_dir in sorted(virus_dir.iterdir()):
            if not family_dir.is_dir():
                continue
            family = family_dir.name
            for path in sorted(family_dir.rglob("*")):
                if path.is_file() and path.suffix.lower() in PE_SUFFIXES:
                    samples.append((path, 1, family))

    if not samples:
        raise ValueError(
            "Khong tim thay mau nao. Dataset can co dang benign/*.exe va virus/<family>/*.exe"
        )
    return samples


def collect_samples_from_split(split_dir: Path) -> list[tuple[Path, int, str | None]]:
    samples: list[tuple[Path, int, str | None]] = []

    benign_dir = split_dir / "benign"
    if benign_dir.is_dir():
        for path in sorted(benign_dir.rglob("*")):
            if path.is_file() and path.suffix.lower() in PE_SUFFIXES:
                samples.append((path, 0, None))

    virus_dir = split_dir / "virus"
    if virus_dir.is_dir():
        for family_dir in sorted(virus_dir.iterdir()):
            if not family_dir.is_dir():
                continue
            family = family_dir.name
            for path in sorted(family_dir.rglob("*")):
                if path.is_file() and path.suffix.lower() in PE_SUFFIXES:
                    samples.append((path, 1, family))

    return samples


def summarize_samples(split_name: str, split_samples_list: list[tuple[Path, int, str | None]]) -> None:
    counts: dict[str, int] = defaultdict(int)
    for _, label, family in split_samples_list:
        class_name = "benign" if label == 0 else str(family)
        counts[class_name] += 1

    total = sum(counts.values())
    print(f"[{split_name}] tong cong {total} mau")
    for class_name in sorted(counts):
        print(f"[{split_name}] {class_name}: {counts[class_name]}")


def split_samples(
    samples: list[tuple[Path, int, str | None]],
    test_ratio: float,
    challenge_ratio: float,
    seed: int,
) -> dict[str, list[tuple[Path, int, str | None]]]:
    grouped: dict[str, list[tuple[Path, int, str | None]]] = defaultdict(list)
    for sample in samples:
        label = "benign" if sample[1] == 0 else str(sample[2])
        grouped[label].append(sample)

    rng = random.Random(seed)
    splits = {"train": [], "test": [], "challenge": []}

    for class_name, class_samples in grouped.items():
        rng.shuffle(class_samples)
        total = len(class_samples)

        test_count = int(round(total * test_ratio))
        challenge_count = int(round(total * challenge_ratio))

        if total >= 3:
            if test_count == 0:
                test_count = 1
            if challenge_count == 0:
                challenge_count = 1
            if test_count + challenge_count >= total:
                challenge_count = max(1, challenge_count - 1)
                if test_count + challenge_count >= total:
                    test_count = max(1, total - challenge_count - 1)
        else:
            test_count = 0
            challenge_count = 0

        test_end = test_count
        challenge_end = test_count + challenge_count
        splits["test"].extend(class_samples[:test_end])
        splits["challenge"].extend(class_samples[test_end:challenge_end])
        splits["train"].extend(class_samples[challenge_end:])

        print(
            f"[{class_name}] total={total} train={len(class_samples[challenge_end:])} "
            f"test={len(class_samples[:test_end])} challenge={len(class_samples[test_end:challenge_end])}"
        )

    return splits


def build_record(extractor: PEFeatureExtractor, path: Path, label: int, family: str | None) -> dict:
    file_bytes = path.read_bytes()
    raw = extractor.raw_features(file_bytes)
    raw["sha256"] = hashlib.sha256(file_bytes).hexdigest()
    raw["label"] = label
    raw["family"] = "benign" if label == 0 else family
    raw["family_confidence"] = 1.0
    raw["behavior"] = []
    raw["file_property"] = []
    raw["packer"] = []
    raw["exploit"] = []
    raw["group"] = []
    raw["file_type"] = "PE"
    raw["source_path"] = str(path)
    return raw


def write_split(
    split_name: str,
    split_samples_list: list[tuple[Path, int, str | None]],
    output_path: Path,
    extractor: PEFeatureExtractor,
) -> None:
    with output_path.open("w") as fout:
        for idx, (path, label, family) in enumerate(split_samples_list, start=1):
            try:
                record = build_record(extractor, path, label, family)
                fout.write(json.dumps(record) + "\n")
            except Exception as exc:
                print(f"[skip] {path}: {exc}")
            if idx % 100 == 0:
                print(f"[{split_name}] da xu ly {idx}/{len(split_samples_list)} mau")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Chuyen thu muc benign/virus/<family> thanh cac file jsonl de train voi thrember."
    )
    parser.add_argument("dataset_dir", help="Thu muc dataset goc.")
    parser.add_argument("output_dir", help="Thu muc output jsonl.")
    parser.add_argument("--test-ratio", type=float, default=0.2, help="Ti le tap test.")
    parser.add_argument(
        "--challenge-ratio",
        type=float,
        default=0.1,
        help="Ti le tap challenge. Dat 0 neu khong muon tach rieng.",
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed.")
    args = parser.parse_args()

    dataset_dir = Path(args.dataset_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    predefined_train_dir = dataset_dir / "train"
    predefined_test_dir = dataset_dir / "test"
    predefined_challenge_dir = dataset_dir / "challenge"

    if predefined_train_dir.is_dir() and predefined_test_dir.is_dir():
        print("Phat hien dataset da duoc chia san train/test. Se bo qua buoc chia ngau nhien.")
        splits = {
            "train": collect_samples_from_split(predefined_train_dir),
            "test": collect_samples_from_split(predefined_test_dir),
            "challenge": collect_samples_from_split(predefined_challenge_dir) if predefined_challenge_dir.is_dir() else [],
        }
        summarize_samples("train", splits["train"])
        summarize_samples("test", splits["test"])
        if splits["challenge"]:
            summarize_samples("challenge", splits["challenge"])
        else:
            print("[challenge] khong co, se tao file jsonl rong")
    else:
        samples = collect_samples(dataset_dir)
        print(f"Tim thay tong cong {len(samples)} mau")
        splits = split_samples(samples, args.test_ratio, args.challenge_ratio, args.seed)

    extractor = PEFeatureExtractor()

    output_files = {
        "train": output_dir / "pe_train.jsonl",
        "test": output_dir / "pe_test.jsonl",
        "challenge": output_dir / "pe_challenge.jsonl",
    }

    for split_name, output_path in output_files.items():
        print(f"Ghi {split_name} vao {output_path}")
        write_split(split_name, splits[split_name], output_path, extractor)

    print("Hoan tat tao dataset jsonl")


if __name__ == "__main__":
    main()
