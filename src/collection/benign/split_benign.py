#!/usr/bin/env python3
"""
split_benign.py - Turn the DikeDataset listing into manifests the pipeline
can use, one per host.

Two jobs in one pass. The source CSV describes each PE (path, architecture,
subsystem) but has none of the columns the pipeline reads, so it is rewritten
into the manifest format first. Then it is divided between the machines that
will run the analyses.

Why the split is stratified rather than sequential
--------------------------------------------------
The set is 44% console programs, and a console program launched with no
arguments usually prints its usage and exits within seconds. A window
application is far more likely to sit there for the full ten minutes. Cutting
the list in half by position would hand one host most of the quick ones and
the other most of the slow ones, and they would finish hours apart.

Dealing the samples round-robin within each (subsystem, architecture) group
keeps both halves the same shape, so both hosts take about the same time and
either half remains representative on its own.

Usage
-----
  # Look at the split without writing anything
  python3 split_benign.py --source ~/benign_manifest.csv --samples ~/benign_samples

  # Write manifest_benign_a.csv and manifest_benign_b.csv
  python3 split_benign.py --source ~/benign_manifest.csv --samples ~/benign_samples \\
      --out-dir ../../../data --hosts a b --apply
"""

import os
import csv
import argparse
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime, timezone

MANIFEST_FIELDS = [
    "sha256", "original_filename", "family", "source", "label",
    "added_date", "status", "cape_task_id", "result", "notes",
]


def load_source(path, present):
    """
    Read the DikeDataset listing, keeping only entries whose file is on disk.

    Anything the listing mentions but the sample directory does not hold
    cannot be analysed, and leaving it in the manifest would make the host
    look like it had work outstanding that it can never do.
    """
    rows, missing, dupes = [], 0, 0
    seen = set()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            sha = (r.get("sha256") or "").strip()
            if not sha:
                continue
            if sha in seen:
                dupes += 1
                continue
            if sha not in present:
                missing += 1
                continue
            seen.add(sha)
            rows.append({
                "sha256": sha,
                "original_filename": os.path.basename(r.get("path", "")),
                "family": "",
                "source": "DikeDataset",
                "label": "benign",
                "added_date": now,
                "status": "pending",
                "cape_task_id": "",
                "result": "",
                "notes": "arch=%s;subsystem=%s;is_dll=%s" % (
                    r.get("machine", ""), r.get("subsystem", ""),
                    r.get("is_dll", "")),
                # not written out, only used for the split
                "_arch": r.get("machine", "?"),
                "_sub": r.get("subsystem", "?"),
            })
    return rows, missing, dupes


def stratified_split(rows, n):
    """Deal each (subsystem, architecture) group round-robin across n parts."""
    groups = defaultdict(list)
    for r in rows:
        groups[(r["_sub"], r["_arch"])].append(r)

    parts = [[] for _ in range(n)]
    for key in sorted(groups):
        # Sorting by hash keeps the assignment stable between runs without
        # making it depend on the order the source file happened to be in.
        for i, r in enumerate(sorted(groups[key], key=lambda x: x["sha256"])):
            parts[i % n].append(r)
    for p in parts:
        p.sort(key=lambda r: r["sha256"])
    return parts


def describe(name, rows):
    subs = Counter(r["_sub"] for r in rows)
    arch = Counter(r["_arch"] for r in rows)
    print(f"   {name:<10} {len(rows):>5}   subsystem={dict(subs)}  arch={dict(arch)}")


def main():
    parser = argparse.ArgumentParser(
        description="Convert and split the benign manifest across hosts.")
    parser.add_argument("--source", required=True, help="DikeDataset CSV")
    parser.add_argument("--samples", required=True, help="Directory holding the samples")
    parser.add_argument("--hosts", nargs="+", default=["a", "b"],
                         help="Suffixes for the output manifests (default: a b)")
    parser.add_argument("--out-dir", default=".", help="Where to write them")
    parser.add_argument("--limit", type=int, default=None,
                         help="Use only this many samples in total, taken evenly "
                              "across the groups. Useful for a smaller run.")
    parser.add_argument("--apply", action="store_true",
                         help="Write the files (default: report only)")
    args = parser.parse_args()

    sample_dir = Path(args.samples).expanduser()
    if not sample_dir.is_dir():
        print(f"[!] not a directory: {sample_dir}")
        return

    present = {p.name.rsplit(".", 1)[0] if "." in p.name else p.name
               for p in sample_dir.iterdir() if p.is_file()}
    print(f"samples on disk : {len(present)}")

    rows, missing, dupes = load_source(Path(args.source).expanduser(), present)
    print(f"usable entries  : {len(rows)}"
          f"  (listed but absent: {missing}, duplicate hashes: {dupes})")
    if not rows:
        return

    if args.limit and args.limit < len(rows):
        # Trim by dealing into 1 part and cutting, so the reduction is also
        # spread evenly across the groups rather than taken off one end.
        rows = stratified_split(rows, 1)[0][:args.limit]
        print(f"limited to      : {len(rows)}")

    print()
    describe("total", rows)
    print()

    parts = stratified_split(rows, len(args.hosts))
    for host, part in zip(args.hosts, parts):
        describe(f"host {host}", part)

    if not args.apply:
        print("\nreport only. add --apply to write the manifests")
        return

    out_dir = Path(args.out_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    print()
    for host, part in zip(args.hosts, parts):
        path = out_dir / f"manifest_benign_{host}.csv"
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=MANIFEST_FIELDS)
            w.writeheader()
            for r in part:
                w.writerow({k: r.get(k, "") for k in MANIFEST_FIELDS})
        print(f"[saved] {path}  ({len(part)} samples)")

    print()
    print("Each host analyses only its own manifest, so the two never collide")
    print("and the results can be merged afterwards by sample hash.")


if __name__ == "__main__":
    main()
