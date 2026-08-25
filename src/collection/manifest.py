#!/usr/bin/env python3
"""
manifest.py - Track sha256 hashes of ransomware samples to prevent
duplicate CAPE submissions and to keep a running record of what has
been collected (family, source, submission status).

Background
----------
Earlier in this project, legacy Cuckoo reports 38/39/43 turned out to be
duplicate submissions of the same underlying sample (same sha256), which
was only discovered by chance. As sample collection scales up (e.g. via
MalwareBazaar), manually noticing duplicates becomes unreliable. This
script computes sha256 for candidate samples and checks them against a
running manifest CSV before they get submitted to CAPE, and records
metadata (family, source, submission task id) once they are.

The manifest itself (hashes + metadata) contains NO malware binaries and
is safe to commit to the git repo -- unlike the samples themselves.

Usage
-----
  # Check a candidate file/directory against the manifest BEFORE submitting
  # to CAPE. Prints which are new vs already-seen duplicates.
  python3 manifest.py check <file_or_directory>

  # Add a new sample to the manifest (after deciding to submit it)
  python3 manifest.py add <file> --family cuba --source malwarebazaar

  # Record that a manifest entry was submitted to CAPE with a given task id
  python3 manifest.py mark-submitted <sha256> --task-id 61

  # Record the triage/verify outcome for a submitted sample
  python3 manifest.py mark-result <sha256> --result TRUE_ENCRYPTION

  # List manifest contents, optionally filtered
  python3 manifest.py list
  python3 manifest.py list --family cuba
  python3 manifest.py list --status pending

  # Summary counts (family x status)
  python3 manifest.py summary

Manifest file: manifest.csv in the current directory by default, or
--manifest <path> to use another location.
"""

import sys
import os
import csv
import hashlib
import argparse
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

FIELDNAMES = [
    "sha256", "original_filename", "family", "source", "label",
    "added_date", "status", "cape_task_id", "result", "notes",
]

DEFAULT_MANIFEST = "manifest.csv"


def sha256_of_file(path, chunk_size=1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def load_manifest(manifest_path):
    if not os.path.exists(manifest_path):
        return {}
    entries = {}
    with open(manifest_path, newline="") as f:
        for row in csv.DictReader(f):
            entries[row["sha256"]] = row
    return entries


def save_manifest(manifest_path, entries):
    with open(manifest_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for sha, row in sorted(entries.items(), key=lambda kv: kv[1].get("added_date", "")):
            writer.writerow({k: row.get(k, "") for k in FIELDNAMES})


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------- Commands ----------------

def cmd_check(args):
    manifest = load_manifest(args.manifest)
    path = Path(args.path)
    manifest_name = Path(args.manifest).name
    if path.is_file():
        candidates = [path]
    else:
        candidates = sorted(
            p for p in path.iterdir()
            if p.is_file() and p.name != manifest_name and p.suffix != ".csv"
        )

    if not candidates:
        print(f"[!] No files found at {path}")
        return

    new_files, dupes = [], []
    for p in candidates:
        sha = sha256_of_file(p)
        if sha in manifest:
            dupes.append((p, sha, manifest[sha]))
        else:
            new_files.append((p, sha))

    print(f"Checked {len(candidates)} file(s) against manifest ({len(manifest)} known hashes)")
    print(f"  New (not in manifest):     {len(new_files)}")
    print(f"  Duplicates (already known): {len(dupes)}")

    if new_files:
        print("\n[NEW] safe to add / submit:")
        for p, sha in new_files:
            print(f"   {p.name:<50} {sha}")

    if dupes:
        print("\n[DUPLICATE] already in manifest -- do not resubmit:")
        for p, sha, existing in dupes:
            print(f"   {p.name:<50} {sha}")
            print(f"      -> matches existing entry: family={existing.get('family','?')} "
                  f"status={existing.get('status','?')} task_id={existing.get('cape_task_id','')}")


def cmd_add(args):
    manifest = load_manifest(args.manifest)
    path = Path(args.file)
    if not path.is_file():
        print(f"[!] Not a file: {path}")
        sys.exit(1)

    sha = sha256_of_file(path)
    if sha in manifest:
        existing = manifest[sha]
        print(f"[!] Duplicate: this file's sha256 already exists in the manifest.")
        print(f"    Existing entry: family={existing.get('family','?')} "
              f"status={existing.get('status','?')} added={existing.get('added_date','?')}")
        print(f"    Not adding a second entry. Use 'mark-submitted' / 'mark-result' to update it.")
        return

    manifest[sha] = {
        "sha256": sha,
        "original_filename": path.name,
        "family": args.family or "",
        "source": args.source or "",
        "label": args.label or "ransomware",
        "added_date": now_iso(),
        "status": "pending",
        "cape_task_id": "",
        "result": "",
        "notes": args.notes or "",
    }
    save_manifest(args.manifest, manifest)
    print(f"[added] {path.name} -> sha256={sha} family={args.family or '(none)'}")


def cmd_mark_submitted(args):
    manifest = load_manifest(args.manifest)
    if args.sha256 not in manifest:
        print(f"[!] sha256 not found in manifest: {args.sha256}")
        sys.exit(1)
    manifest[args.sha256]["status"] = "submitted"
    manifest[args.sha256]["cape_task_id"] = args.task_id
    save_manifest(args.manifest, manifest)
    print(f"[updated] {args.sha256[:16]}... -> status=submitted task_id={args.task_id}")


def cmd_mark_result(args):
    manifest = load_manifest(args.manifest)
    if args.sha256 not in manifest:
        print(f"[!] sha256 not found in manifest: {args.sha256}")
        sys.exit(1)
    manifest[args.sha256]["status"] = "analyzed"
    manifest[args.sha256]["result"] = args.result
    save_manifest(args.manifest, manifest)
    print(f"[updated] {args.sha256[:16]}... -> status=analyzed result={args.result}")


def cmd_list(args):
    manifest = load_manifest(args.manifest)
    rows = list(manifest.values())
    if args.family:
        rows = [r for r in rows if r.get("family", "").lower() == args.family.lower()]
    if args.status:
        rows = [r for r in rows if r.get("status", "") == args.status]

    if not rows:
        print("(no matching entries)")
        return

    header = f"{'sha256':<18} {'filename':<30} {'family':<14} {'status':<11} {'task_id':<8} {'result':<20}"
    print(header)
    print("-" * len(header))
    for r in sorted(rows, key=lambda r: r.get("added_date", "")):
        print(f"{r['sha256'][:16]:<18} {r.get('original_filename','')[:28]:<30} "
              f"{r.get('family',''):<14} {r.get('status',''):<11} "
              f"{r.get('cape_task_id',''):<8} {r.get('result',''):<20}")
    print(f"\n{len(rows)} entries")


def cmd_summary(args):
    manifest = load_manifest(args.manifest)
    if not manifest:
        print("(manifest is empty)")
        return

    by_family_status = defaultdict(lambda: defaultdict(int))
    for row in manifest.values():
        fam = row.get("family") or "(unknown)"
        status = row.get("status") or "(unknown)"
        by_family_status[fam][status] += 1

    statuses = sorted({s for fs in by_family_status.values() for s in fs})
    header = f"{'family':<16} " + " ".join(f"{s:<12}" for s in statuses) + " total"
    print(header)
    print("-" * len(header))
    for fam in sorted(by_family_status):
        counts = by_family_status[fam]
        total = sum(counts.values())
        row = f"{fam:<16} " + " ".join(f"{counts.get(s,0):<12}" for s in statuses) + f" {total}"
        print(row)
    print(f"\nTotal samples in manifest: {len(manifest)}")

    # result breakdown for analyzed samples
    results = defaultdict(int)
    for row in manifest.values():
        if row.get("result"):
            results[row["result"]] += 1
    if results:
        print("\nResult breakdown:")
        for r, c in sorted(results.items(), key=lambda x: -x[1]):
            print(f"   {r:<20} {c}")


def main():
    parser = argparse.ArgumentParser(description="Sample sha256 manifest and duplicate detector.")
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST, help="Path to manifest CSV")
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="Check file(s) against the manifest before submitting")
    p_check.add_argument("path", help="A file or a directory of files")
    p_check.set_defaults(func=cmd_check)

    p_add = sub.add_parser("add", help="Add a new sample to the manifest")
    p_add.add_argument("file")
    p_add.add_argument("--family", default=None)
    p_add.add_argument("--source", default=None, help="e.g. malwarebazaar, legacy_cuckoo")
    p_add.add_argument("--label", default=None, help="default: ransomware")
    p_add.add_argument("--notes", default=None)
    p_add.set_defaults(func=cmd_add)

    p_sub = sub.add_parser("mark-submitted", help="Record a CAPE task id for a manifest entry")
    p_sub.add_argument("sha256")
    p_sub.add_argument("--task-id", required=True)
    p_sub.set_defaults(func=cmd_mark_submitted)

    p_res = sub.add_parser("mark-result", help="Record the triage/verify result for a sample")
    p_res.add_argument("sha256")
    p_res.add_argument("--result", required=True,
                        help="e.g. TRUE_ENCRYPTION, WEAK_VICTIM_ACTIVITY, NO_VICTIM_ACTIVITY, FAILED")
    p_res.set_defaults(func=cmd_mark_result)

    p_list = sub.add_parser("list", help="List manifest entries")
    p_list.add_argument("--family", default=None)
    p_list.add_argument("--status", default=None)
    p_list.set_defaults(func=cmd_list)

    p_sum = sub.add_parser("summary", help="Show family x status summary")
    p_sum.set_defaults(func=cmd_summary)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()