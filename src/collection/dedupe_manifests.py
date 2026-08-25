#!/usr/bin/env python3
"""
dedupe_manifests.py - Find samples this host has that another host already
has, and stop them being analysed twice.

When this is needed
-------------------
Two machines collecting from the same source will fetch many of the same
samples. Preventing that up front means each host reading the other's
manifest before downloading; this is for when the downloads have already
happened.

What it does and does not touch
-------------------------------
Only entries still waiting to be submitted are excluded. A sample the other
host has but this one has already analysed represents work that is done --
discarding it gains nothing, and the result is worth keeping even if it
duplicates. Those are reported and left alone.

Which host should keep a shared sample, when both are still waiting, is
arbitrary. The rule here is that the host running the tool gives way, so run
it on one host only or the sample will be dropped by both.

Sample files can be deleted as well, which is usually the point: a few
hundred duplicates is several gigabytes of malware sitting on disk for no
reason.

Usage
-----
  # See what overlaps, change nothing
  python3 dedupe_manifests.py --manifest ../../data/manifests/manifest_all.csv \\
      --other ../../data/manifests/manifest_all.csv

  # Exclude the pending duplicates, and delete their files
  python3 dedupe_manifests.py --manifest ../../data/manifests/manifest_all.csv \\
      --other ../../data/manifests/manifest_all.csv --apply --samples-dir ~/samples
"""

import os
import csv
import sys
import argparse
from pathlib import Path
from collections import Counter

MANIFEST_FIELDNAMES = [
    "sha256", "original_filename", "family", "source", "label",
    "added_date", "status", "cape_task_id", "result", "notes",
]

# Statuses meaning nothing has been spent on this sample yet.
UNSPENT = {"pending", "", None}

EXCLUDED_STATUS = "duplicate_elsewhere"


def load(path):
    rows = []
    try:
        with open(path, newline="") as f:
            rows = list(csv.DictReader(f))
    except OSError as e:
        print(f"[!] cannot read {path}: {e}")
        sys.exit(1)
    return rows


def main():
    parser = argparse.ArgumentParser(
        description="Exclude samples another host has already collected.")
    parser.add_argument("--manifest", required=True, help="This host's manifest")
    parser.add_argument("--other", nargs="+", required=True,
                         help="Manifests belonging to other hosts, read only")
    parser.add_argument("--samples-dir", default=None,
                         help="Delete the sample files of excluded entries from here")
    parser.add_argument("--apply", action="store_true",
                         help="Actually make the changes (default: report only)")
    args = parser.parse_args()

    mine = load(args.manifest)
    theirs = set()
    for path in args.other:
        rows = load(path)
        theirs |= {r["sha256"] for r in rows if r.get("sha256")}
        print(f"other host: {path}  ({len(rows)} entries)")

    print(f"this host : {args.manifest}  ({len(mine)} entries)\n")

    shared = [r for r in mine if r.get("sha256") in theirs]
    pending = [r for r in shared if (r.get("status") or "") in UNSPENT]
    spent = [r for r in shared if (r.get("status") or "") not in UNSPENT]

    print(f"held by both hosts        : {len(shared)}")
    print(f"   still waiting here     : {len(pending)}  <- can be dropped")
    print(f"   already worked on here : {len(spent)}  <- kept; the analysis is done")

    if spent:
        by_status = Counter(r.get("status") for r in spent)
        print(f"      {dict(by_status)}")

    if not shared:
        print("\nno overlap; nothing to do")
        return

    fams = Counter(r.get("family") or "(unattributed)" for r in pending)
    if fams:
        print(f"\npending duplicates by family:")
        for fam, n in fams.most_common(12):
            print(f"   {fam:<20} {n}")

    remaining = sum(1 for r in mine
                    if (r.get("status") or "") in UNSPENT and r not in pending)
    print(f"\nafter dropping them, still to analyse here: {remaining}")

    if not args.apply:
        print("\nreport only. add --apply to exclude them"
              + (" and delete their files" if args.samples_dir else ""))
        return

    # ---- exclude ----
    to_drop = {r["sha256"] for r in pending}
    for row in mine:
        if row.get("sha256") in to_drop:
            row["status"] = EXCLUDED_STATUS
            note = row.get("notes") or ""
            row["notes"] = (note + ";held_by_another_host").strip(";")

    with open(args.manifest, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=MANIFEST_FIELDNAMES)
        w.writeheader()
        for row in mine:
            w.writerow({k: row.get(k, "") for k in MANIFEST_FIELDNAMES})
    print(f"\n[manifest] {len(to_drop)} entries marked {EXCLUDED_STATUS}")
    print(f"           they will not be picked up by --submit-pending")

    # ---- delete the files ----
    if args.samples_dir:
        base = Path(args.samples_dir).expanduser()
        removed = freed = 0
        for sha in to_drop:
            path = base / sha
            if path.exists():
                try:
                    freed += path.stat().st_size
                    path.unlink()
                    removed += 1
                except OSError:
                    pass
        print(f"[files]    deleted {removed} sample files, {freed/1e9:.2f} GB freed")


if __name__ == "__main__":
    main()
