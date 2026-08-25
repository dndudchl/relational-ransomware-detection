#!/usr/bin/env python3
"""
diagnose_victims.py - Measure how each analysis touched the planted decoy
files, under several counting rules, so a detection threshold can be chosen
from data rather than guessed.

Why
---
The current verdict counts destructive EVENTS on decoy files whose extension
appears in a hardcoded allowlist. Two blind spots showed up in practice:

  1. In-place overwrite. WannaCry reads a file, writes an encrypted copy and
     deletes the original: roughly three events per file. AvosLocker just
     overwrites the file where it sits: one event per file. Both encrypt the
     same decoys, but the event count differs by an order of magnitude, so a
     threshold tuned on one badly misjudges the other.

  2. Unknown decoy types. The decoy set contains real coursework files, some
     with extensions (.vdfx, .2mdl) that were never added to the allowlist,
     so genuine attacks on them were silently discarded.

This script reports, per analysis:
  - distinct decoy files touched destructively (write/delete/move)
  - the same figure under the old extension allowlist, for comparison
  - distinct decoy files only read (the 7-Zip case: reading many decoys
    without damaging any must NOT count as encryption)

Run it over the existing analyses and compare the columns against what is
known to be true from the sandbox screenshots.

Usage
-----
  sudo python3 diagnose_victims.py /opt/CAPEv2/storage/analyses
  sudo python3 diagnose_victims.py /opt/CAPEv2/storage/analyses --show-files 70
"""

import sys
import json
import argparse
from pathlib import Path
from collections import defaultdict

DECOY_DIRS = ["\\Users\\admin\\Desktop",
              "\\Users\\admin\\Documents",
              "\\Users\\admin\\Downloads"]

# The old allowlist, kept only to quantify what it was discarding.
OLD_EXTENSIONS = {
    "docx", "doc", "docm", "pptx", "ppt", "xlsx", "xls", "csv", "pdf",
    "txt", "rtf", "py", "pyw", "ipynb", "rmd", "png", "jpg", "jpeg", "zip",
}

# Files that appear inside user folders but are not decoys: browser caches,
# shell metadata, thumbnail databases and similar.
NOISE_FRAGMENTS = [
    "\\appdata\\", "desktop.ini", "thumbs.db", "\\.ssh\\",
    "\\searches\\", "\\contacts\\", "\\favorites\\", "\\links\\",
    "ntuser.dat", "\\microsoft\\",
]

DESTRUCTIVE = ("write", "delete", "move")


def is_decoy_path(path):
    if not path:
        return False
    lowered = path.lower()
    if not any(d.lower() in lowered for d in DECOY_DIRS):
        return False
    return not any(n in lowered for n in NOISE_FRAGMENTS)


def get_ext(path):
    tail = path.split("\\")[-1]
    return tail.split(".")[-1].lower() if "." in tail else "(none)"


def analyze(report_path):
    try:
        with open(report_path, "r", errors="replace") as f:
            report = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    destroyed = set()          # distinct decoy files hit destructively
    destroyed_oldfilter = set()  # same, restricted to the old allowlist
    read_only = set()          # decoy files that were only read
    events_destructive = 0
    ext_counts = defaultdict(int)

    for e in report.get("behavior", {}).get("enhanced", []) or []:
        if e.get("object") != "file":
            continue
        path = e.get("data", {}).get("file", "") or ""
        if not is_decoy_path(path):
            continue
        event = e.get("event")
        if event in DESTRUCTIVE:
            destroyed.add(path)
            events_destructive += 1
            ext_counts[get_ext(path)] += 1
            if get_ext(path) in OLD_EXTENSIONS:
                destroyed_oldfilter.add(path)
        elif event == "read":
            read_only.add(path)

    read_only -= destroyed  # a file both read and destroyed counts as destroyed

    info = report.get("info", {}) or {}
    return {
        "task": str(info.get("id", Path(report_path).parent.parent.name)),
        "sha256": (report.get("target", {}) or {}).get("file", {}).get("sha256", "")[:12],
        "duration": info.get("duration", ""),
        "hit_timeout": info.get("timeout", ""),
        "files_destroyed": len(destroyed),
        "files_destroyed_oldfilter": len(destroyed_oldfilter),
        "files_read_only": len(read_only),
        "destructive_events": events_destructive,
        "ext_counts": dict(ext_counts),
        "destroyed_paths": sorted(destroyed),
    }


def main():
    parser = argparse.ArgumentParser(description="Measure decoy-file damage per analysis.")
    parser.add_argument("analyses_dir")
    parser.add_argument("--show-files", metavar="TASK",
                         help="Print every decoy file destroyed in one analysis")
    args = parser.parse_args()

    base = Path(args.analyses_dir)
    results = []
    for d in sorted((p for p in base.iterdir() if p.is_dir() and p.name.isdigit()),
                     key=lambda p: int(p.name)):
        report = d / "reports" / "report.json"
        if not report.exists():
            continue
        r = analyze(report)
        if r:
            results.append(r)

    if args.show_files:
        for r in results:
            if r["task"] == args.show_files:
                print(f"Task {r['task']} -- {r['files_destroyed']} decoy files destroyed\n")
                for p in r["destroyed_paths"]:
                    print(f"   {p}")
                print(f"\nBy extension: {r['ext_counts']}")
                return
        print(f"[!] task {args.show_files} not found")
        return

    header = (f"{'task':<6} {'sha256':<14} {'dur':>5} {'t/o':<5} "
              f"{'FILES_DESTROYED':>16} {'old_filter':>11} {'read_only':>10} {'events':>7}")
    print(header)
    print("-" * len(header))
    for r in results:
        print(f"{r['task']:<6} {r['sha256']:<14} {str(r['duration']):>5} "
              f"{str(r['hit_timeout']):<5} {r['files_destroyed']:>16} "
              f"{r['files_destroyed_oldfilter']:>11} {r['files_read_only']:>10} "
              f"{r['destructive_events']:>7}")

    print("\nFILES_DESTROYED is the proposed metric: distinct decoy files written,")
    print("deleted or moved. It is independent of whether the sample overwrites in")
    print("place or writes-then-deletes, and it stays at 0 for a program that only")
    print("reads the decoys (such as an archiver).")
    print("\nCompare FILES_DESTROYED against what the sandbox screenshots showed, then")
    print("pick a threshold that separates the encrypting runs from the rest.")


if __name__ == "__main__":
    main()
