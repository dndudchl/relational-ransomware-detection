#!/usr/bin/env python3
"""
Filter benign PE samples into a CAPE submission list.

Rejects files that would occupy an analysis slot without producing behaviour:
  - non-PE files (corrupt or mislabelled)
  - DLLs (no entry point reachable by plain execution)
  - native-subsystem binaries (drivers)
  - files above CAPE's max_sample_size

Deduplicates by SHA-256 across all input directories.

Usage:
    python3 filter_benign_pe.py --input ./DikeDataset/files/benign ./system32 \
                                --out-dir ./benign_filtered
"""

import argparse
import csv
import hashlib
import sys
from pathlib import Path

try:
    import pefile
except ImportError:
    sys.exit("pefile is required: pip install pefile")


# Must match max_sample_size in CAPE's web.conf
MAX_SAMPLE_SIZE = 50 * 1024 * 1024

# IMAGE_FILE_CHARACTERISTICS
IMAGE_FILE_DLL = 0x2000
IMAGE_FILE_SYSTEM = 0x1000

# IMAGE_SUBSYSTEM
SUBSYSTEM_NATIVE = 1
SUBSYSTEM_GUI = 2
SUBSYSTEM_CUI = 3

SUBSYSTEM_NAMES = {
    0: "UNKNOWN",
    SUBSYSTEM_NATIVE: "NATIVE",
    SUBSYSTEM_GUI: "GUI",
    SUBSYSTEM_CUI: "CUI",
}

MACHINE_NAMES = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "ARM",
    0xAA64: "ARM64",
}


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def classify(path: Path) -> dict:
    """Inspect one file and decide whether it should be submitted."""
    record = {
        "path": str(path),
        "sha256": "",
        "size": 0,
        "machine": "",
        "subsystem": "",
        "is_dll": "",
        "entry_point": "",
        "decision": "",
        "reason": "",
    }

    try:
        record["size"] = path.stat().st_size
    except OSError as exc:
        record["decision"] = "SKIP"
        record["reason"] = f"STAT_ERROR: {exc}"
        return record

    if record["size"] == 0:
        record["decision"] = "SKIP"
        record["reason"] = "EMPTY_FILE"
        return record

    if record["size"] > MAX_SAMPLE_SIZE:
        record["decision"] = "SKIP"
        record["reason"] = "OVERSIZE"
        return record

    try:
        record["sha256"] = sha256_of(path)
    except OSError as exc:
        record["decision"] = "SKIP"
        record["reason"] = f"READ_ERROR: {exc}"
        return record

    # fast=True parses headers only; section data is not needed here
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except pefile.PEFormatError as exc:
        record["decision"] = "SKIP"
        record["reason"] = f"NOT_PE: {exc}"
        return record
    except Exception as exc:  # noqa: BLE001 - defensive, keep the batch running
        record["decision"] = "SKIP"
        record["reason"] = f"PARSE_ERROR: {exc}"
        return record

    try:
        characteristics = pe.FILE_HEADER.Characteristics
        subsystem = pe.OPTIONAL_HEADER.Subsystem
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        record["machine"] = MACHINE_NAMES.get(
            pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)
        )
        record["subsystem"] = SUBSYSTEM_NAMES.get(subsystem, str(subsystem))
        record["is_dll"] = bool(characteristics & IMAGE_FILE_DLL)
        record["entry_point"] = hex(entry_point)

        if characteristics & IMAGE_FILE_DLL:
            record["decision"] = "SKIP"
            record["reason"] = "DLL"
        elif subsystem == SUBSYSTEM_NATIVE or (characteristics & IMAGE_FILE_SYSTEM):
            record["decision"] = "SKIP"
            record["reason"] = "DRIVER_OR_NATIVE"
        elif entry_point == 0:
            record["decision"] = "SKIP"
            record["reason"] = "NO_ENTRY_POINT"
        else:
            record["decision"] = "SUBMIT"
            record["reason"] = "OK"
    finally:
        pe.close()

    return record


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Filter benign PE samples for CAPE submission."
    )
    parser.add_argument(
        "--input",
        nargs="+",
        required=True,
        help="One or more directories to scan recursively.",
    )
    parser.add_argument(
        "--out-dir",
        default="./benign_filtered",
        help="Directory for the manifest and submission list.",
    )
    parser.add_argument(
        "--copy-to",
        default=None,
        help="Optional directory to copy accepted samples into, renamed to <sha256>.",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    records = []
    seen_hashes = set()
    duplicate_count = 0

    for root in args.input:
        root_path = Path(root)
        if not root_path.is_dir():
            print(f"[warn] not a directory, skipped: {root}", file=sys.stderr)
            continue

        for file_path in sorted(root_path.rglob("*")):
            if not file_path.is_file():
                continue

            record = classify(file_path)

            if record["decision"] == "SUBMIT":
                if record["sha256"] in seen_hashes:
                    record["decision"] = "SKIP"
                    record["reason"] = "DUPLICATE_SHA256"
                    duplicate_count += 1
                else:
                    seen_hashes.add(record["sha256"])

            records.append(record)

    manifest_path = out_dir / "benign_manifest.csv"
    with manifest_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(records[0].keys()))
        writer.writeheader()
        writer.writerows(records)

    accepted = [r for r in records if r["decision"] == "SUBMIT"]

    submit_path = out_dir / "submit_list.txt"
    with submit_path.open("w", encoding="utf-8") as handle:
        for record in accepted:
            handle.write(f"{record['path']}\n")

    if args.copy_to:
        import shutil

        copy_dir = Path(args.copy_to)
        copy_dir.mkdir(parents=True, exist_ok=True)
        for record in accepted:
            shutil.copy2(record["path"], copy_dir / f"{record['sha256']}.exe")
        print(f"copied {len(accepted)} samples to {copy_dir}")

    # Summary
    reason_counts = {}
    for record in records:
        key = record["reason"] if record["decision"] == "SKIP" else "SUBMIT"
        reason_counts[key] = reason_counts.get(key, 0) + 1

    print(f"\nscanned:   {len(records)}")
    print(f"accepted:  {len(accepted)}")
    print(f"manifest:  {manifest_path}")
    print(f"list:      {submit_path}\n")

    print("breakdown:")
    for reason, count in sorted(
        reason_counts.items(), key=lambda item: item[1], reverse=True
    ):
        print(f"  {count:6d}  {reason}")

    subsystem_counts = {}
    for record in accepted:
        subsystem_counts[record["subsystem"]] = (
            subsystem_counts.get(record["subsystem"], 0) + 1
        )
    print("\naccepted by subsystem:")
    for subsystem, count in sorted(
        subsystem_counts.items(), key=lambda item: item[1], reverse=True
    ):
        print(f"  {count:6d}  {subsystem}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
