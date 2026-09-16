#!/usr/bin/env python3
"""Build benign action resources from user-provided PE files.

The script copies benign PE files into ``proposed/actions/trusted`` and writes
``strings`` output for each file into ``proposed/actions/good_strings``. It does
not download executables; users must provide a lawful benign corpus.
"""

import argparse
import shutil
import subprocess
from pathlib import Path


DEFAULT_EXTENSIONS = (".exe", ".dll", ".sys", ".scr")


def parse_args():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Create TIER-Mal action resources from benign PE files.",
    )
    parser.add_argument(
        "--benign-dir",
        required=True,
        type=Path,
        help="Directory containing benign PE files supplied by the user.",
    )
    parser.add_argument(
        "--trusted-dir",
        default=root / "proposed" / "actions" / "trusted",
        type=Path,
        help="Destination for copied benign PE files.",
    )
    parser.add_argument(
        "--strings-dir",
        default=root / "proposed" / "actions" / "good_strings",
        type=Path,
        help="Destination for extracted strings text files.",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Search benign-dir recursively.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing copied files and strings outputs.",
    )
    return parser.parse_args()


def iter_pe_files(root, recursive):
    pattern = "**/*" if recursive else "*"
    for path in sorted(root.glob(pattern)):
        if path.is_file() and path.suffix.lower() in DEFAULT_EXTENSIONS:
            yield path


def copy_file(src, dst, overwrite):
    if dst.exists() and not overwrite:
        return False
    shutil.copy2(str(src), str(dst))
    return True


def write_strings(src, dst, overwrite):
    if dst.exists() and not overwrite:
        return False
    with dst.open("w", encoding="utf-8", errors="ignore") as handle:
        subprocess.run(["strings", str(src)], stdout=handle, check=True)
    return True


def main():
    args = parse_args()
    benign_dir = args.benign_dir.expanduser().resolve()
    trusted_dir = args.trusted_dir.expanduser().resolve()
    strings_dir = args.strings_dir.expanduser().resolve()

    if not benign_dir.is_dir():
        raise SystemExit(f"benign-dir does not exist or is not a directory: {benign_dir}")

    if shutil.which("strings") is None:
        raise SystemExit("missing 'strings' executable; install binutils first")

    trusted_dir.mkdir(parents=True, exist_ok=True)
    strings_dir.mkdir(parents=True, exist_ok=True)

    files = list(iter_pe_files(benign_dir, args.recursive))
    if not files:
        raise SystemExit(f"no PE-like files found in: {benign_dir}")

    copied = 0
    generated = 0
    for src in files:
        trusted_path = trusted_dir / src.name
        strings_path = strings_dir / f"{src.name}.strings.txt"
        copied += int(copy_file(src, trusted_path, args.overwrite))
        generated += int(write_strings(src, strings_path, args.overwrite))

    print(f"Input files: {len(files)}")
    print(f"Copied to trusted: {copied}")
    print(f"Generated strings: {generated}")
    print(f"Trusted dir: {trusted_dir}")
    print(f"Strings dir: {strings_dir}")


if __name__ == "__main__":
    main()
