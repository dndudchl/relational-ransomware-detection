#!/usr/bin/env python3
"""
join_grid.py - Attach the grid parameters to the analysis results, and fold
the outcome along one axis at a time.

Why this is a separate step
---------------------------
The feature extraction knows what a run did. It does not know what the run
was asked to do. Those are different things, and the whole design depends on
the second: a variant is interesting because it sits at a known point in the
grid, and the point is recorded in the manifest, not in the report.

So the manifest has to be joined on before any of the per-axis questions can
be asked. After that they are all the same operation -- hold everything else
constant, vary one factor, compare -- and this does each of them.

The four comparisons the grid was built for
-------------------------------------------
    B vs C            same read and write counts; the sets coincide or not
    D vs J            same file operations; one encrypts
    D vs K            same destruction; one writes a replacement
    sweep vs random   same everything; only the order files are visited in

The last is the cleanest. Every count is identical, so a difference in the
flag rate cannot come from volume, and a model that shows no difference is
not using order at all.

A note on what is being folded
------------------------------
The rate reported is the model's, not the verdict logic's. analyze_result.py
decides whether a run reached encryption, which is how the ransomware set was
labelled; it was never meant to judge benign software, and its output on
these variants says nothing about detection. Only model predictions are
counted here.

Usage
-----
  python3 join_grid.py --features /tmp/feat.csv \\
      --manifest ~/hn3/shape_manifest.csv \\
      --scripts ~/hn3/scripts/script_manifest.csv \\
      --scores /tmp/hn_scores.csv --out /tmp/grid_joined.csv
"""

import os
import csv
import math
import argparse
from collections import defaultdict


def read(path):
    with open(os.path.expanduser(path), newline="") as f:
        return list(csv.DictReader(f))


def wilson(hits, n, z=1.96):
    """
    An interval that stays inside nought and one and behaves at the edges.

    The normal approximation gives a symmetric interval around the observed
    rate, which for a cell where every variant was flagged runs above one and
    reports plus or minus nothing. Several cells here will be at nought or
    one, so the interval has to be one that copes.
    """
    if n == 0:
        return (float("nan"), float("nan"), float("nan"))
    p = hits / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (p, max(0.0, centre - half), min(1.0, centre + half))


def stem(name):
    """The filename as it appears in a task id or a features row."""
    return os.path.splitext(os.path.basename(name))[0]


def load_names(path):
    """
    sample_id -> the filename the sandbox was given.

    The scores are keyed by task number, which says nothing about what the
    program was; the manifests are keyed by filename, which is the only thing
    that does. Without this table the two cannot be joined and every fold
    below is empty.
    """
    if not path:
        return {}
    out = {}
    for r in read(path):
        if r.get("sample_id") and r.get("filename"):
            out[r["sample_id"]] = r["filename"]
    return out


def load_manifests(manifest, scripts):
    """
    One table describing every variant, from however many manifests.

    The compiled grid and the scripts record different columns -- one has a
    toolchain and an order, the other has a language -- so they are brought
    to a common set here rather than being handled separately everywhere
    downstream.
    """
    rows = {}
    for r in read(manifest):
        rows[stem(r["filename"])] = {
            "family": "grid",
            "tool": r["tool"],
            "shape": r["shape"],
            "limit": int(r["limit"]),
            "order": int(r["order"]),
            "timing": int(r["timing"]),
            "fake_imports": int(r.get("fake_imports", 0)),
            "rep": int(r.get("rep", 0)),
            "category": r["category"],
        }
    if scripts and os.path.exists(os.path.expanduser(scripts)):
        for r in read(scripts):
            lang = r["language"]
            method = r["method"]
            # The scripts use the same shape letters; the application
            # batches use task names and have no shape.
            shape = method if method in list("ABCDEFHIJK") else ""
            rows[stem(r["filename"])] = {
                "family": "script" if lang != "app" else "app",
                "tool": lang,
                "shape": shape,
                "limit": int(r.get("limit") or 0),
                "order": 0,
                "timing": 0,
                "fake_imports": 0,
                "rep": 0,
                "category": ("harmless" if shape in ("A", "C")
                             else "destroys" if shape in ("D", "K")
                             else "unclassified"),
            }
    return rows


def fold(rows, key, label, min_n=5):
    """Group by one factor and report the flag rate with an interval."""
    buckets = defaultdict(lambda: [0, 0])
    for r in rows:
        v = r.get(key)
        if v in (None, ""):
            continue
        b = buckets[v]
        b[0] += r["flagged"]
        b[1] += 1

    if not buckets:
        return
    print(f"\n{label}")
    print(f"   {'':<14}{'n':>5}{'flagged':>9}{'rate':>8}{'95% interval':>18}")
    for v in sorted(buckets, key=lambda x: (isinstance(x, str), x)):
        hits, n = buckets[v]
        if n < min_n:
            continue
        p, lo, hi = wilson(hits, n)
        print(f"   {str(v):<14}{n:>5}{hits:>9}{p:>8.3f}"
              f"{f'[{lo:.3f}, {hi:.3f}]':>18}")


def compare(rows, key, a, b, label, holding=()):
    """
    Two levels of one factor, with everything in `holding` matched.

    Matching matters: shape B against shape C across the whole set compares
    two groups that also differ in which volumes happened to be drawn. Paired
    on volume and order, the only difference left is the one being asked
    about.
    """
    pairs = defaultdict(lambda: {a: [0, 0], b: [0, 0]})
    for r in rows:
        v = r.get(key)
        if v not in (a, b):
            continue
        cell = tuple(r.get(h) for h in holding)
        pairs[cell][v][0] += r["flagged"]
        pairs[cell][v][1] += 1

    ha = na = hb = nb = 0
    used = 0
    for cell, d in pairs.items():
        if d[a][1] == 0 or d[b][1] == 0:
            continue          # nothing to pair with
        used += 1
        ha += d[a][0]; na += d[a][1]
        hb += d[b][0]; nb += d[b][1]

    if na == 0 or nb == 0:
        print(f"\n{label}: no matched cells")
        return

    pa, loa, hia = wilson(ha, na)
    pb, lob, hib = wilson(hb, nb)
    print(f"\n{label}")
    print(f"   {a:<10}{na:>5} runs   {pa:.3f}  [{loa:.3f}, {hia:.3f}]")
    print(f"   {b:<10}{nb:>5} runs   {pb:.3f}  [{lob:.3f}, {hib:.3f}]")
    print(f"   difference {pa - pb:+.3f}"
          f"   across {used} matched cells on {', '.join(holding) or 'nothing'}")
    if (loa > hib) or (lob > hia):
        print("   the intervals do not overlap")
    else:
        print("   the intervals overlap; this is not evidence of a difference")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--scripts")
    parser.add_argument("--names",
                         help="CSV of sample_id,filename joining the score "
                              "file's task numbers to the manifests")
    parser.add_argument("--scores", required=True,
                         help="Model predictions: sample_id, flag_rate")
    parser.add_argument("--features",
                         help="Optional; adds measured columns to the output")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--out", default="/tmp/grid_joined.csv")
    args = parser.parse_args()

    spec = load_manifests(args.manifest, args.scripts)
    names = load_names(args.names)
    print(f"{len(spec)} variants described"
          + (f", {len(names)} sample ids resolved to filenames" if names else ""))

    feat = {}
    if args.features:
        for r in read(args.features):
            key = stem(r.get("sample_id") or r.get("task_id") or "")
            feat[key] = r

    rows, unmatched = [], 0
    for r in read(args.scores):
        sid = r.get("sample_id") or r.get("task_id") or ""
        # Three ways in: the id is already a variant name, the names table
        # maps it to one, or the feature row carries one.
        s = spec.get(stem(sid))
        if s is None and sid in names:
            s = spec.get(stem(names[sid]))
        if s is None and sid in feat:
            s = spec.get(stem(feat[sid].get("filename", "")))
        if s is None:
            unmatched += 1
            continue
        try:
            rate = float(r.get("flag_rate", ""))
        except ValueError:
            continue
        row = dict(s)
        row["sample_id"] = sid
        row["flag_rate"] = rate
        row["flagged"] = 1 if rate >= args.threshold else 0
        for c in ("n_paths", "n_calls", "n_write", "n_delete",
                   "rw_jaccard", "walk_same_dir_rate", "gap_cv"):
            if sid in feat and c in feat[sid]:
                row[c] = feat[sid][c]
        rows.append(row)

    print(f"{len(rows)} matched to a score" +
          (f", {unmatched} unmatched" if unmatched else ""))
    if not rows:
        print()
        print("Nothing to fold. The score file is keyed by sandbox task "
              "number and the manifests by filename, so the two need a table")
        print("joining them:  --names ~/work/hardneg_names.csv")
        return

    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print(f"[saved] {args.out}")

    grid = [r for r in rows if r["family"] == "grid"]

    print("\n" + "=" * 68)
    print("Folded along one axis at a time")
    print("=" * 68)
    fold(grid, "shape", "by shape")
    fold(grid, "limit", "by volume (files the variant was told to process)")
    fold(grid, "order", "by traversal order (0 sweep, 1 shuffled)")
    fold(grid, "tool", "by toolchain")
    fold([r for r in grid if r["timing"] or True], "timing", "by timing")
    fold(grid, "fake_imports", "by import table (0 plain, 1 ransomware-shaped)")
    fold(rows, "category", "by whether anything was destroyed")
    fold([r for r in rows if r["family"] != "grid"], "tool",
         "scripts and applications, by language")

    print("\n" + "=" * 68)
    print("The pairs the grid was built for")
    print("=" * 68)
    compare(grid, "shape", "B", "C",
            "B vs C: same counts, the read and write sets coincide or not",
            holding=("limit", "order", "tool"))
    compare(grid, "shape", "D", "J",
            "D vs J: same file operations, one of them encrypts",
            holding=("limit", "order", "tool"))
    compare(grid, "shape", "D", "K",
            "D vs K: same destruction, one writes a replacement",
            holding=("limit", "order", "tool"))
    compare(grid, "order", 0, 1,
            "sweep vs shuffled: every count identical, only the order differs",
            holding=("shape", "limit", "tool"))
    compare(grid, "fake_imports", 1, 0,
            "ransomware-shaped imports vs plain, same behaviour",
            holding=("shape", "limit"))

    print("\n  A difference here is a difference the model makes between two")
    print("  groups that were built to be identical except in one respect.")
    print("  Overlapping intervals mean the model did not distinguish them,")
    print("  which for the order pair means it is not using sequence at all.")


if __name__ == "__main__":
    main()
