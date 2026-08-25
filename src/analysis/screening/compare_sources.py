#!/usr/bin/env python3
"""
compare_sources.py - Measure the candidate features against benign software,
which is the comparison the thesis actually rests on.

Why a separate script
---------------------
explore_relational.py splits on the verdict: runs that reached encryption
against everything else. Every sample it saw was ransomware, so that answered
a narrow question -- what accompanies reaching the encryption stage -- and
the answer was dominated by activity, because runs that stopped short did
less of everything.

With benign runs and hand-built hard negatives in the same table, the split
that matters is by where the sample came from. The task id prefix records
that: nothing or B for ransomware from either analysis host, NA or NB for
DikeDataset benign, H for the constructed variants.

Three comparisons, because they answer different things:

  ransomware vs benign
      The headline number, and the one to be most suspicious of. Four fifths
      of the benign set never executed, so most of them score zero on
      everything and any feature that counts anything separates them. A high
      figure here is close to meaningless on its own.

  ransomware vs benign that actually ran
      Restricting to benign runs the sandbox recorded activity for removes
      the easy cases. Smaller, and the only honest version of the first
      comparison.

  ransomware vs hard negatives
      Sixty-eight programs built to be as active as ransomware while doing
      something a person asked for. Too few to train on, but the only place
      where a feature has to distinguish behaviour rather than volume.

Usage
-----
  python3 compare_sources.py --relational /tmp/rel_all.csv \\
      --results /tmp/res_all_v2.csv
"""

import csv
import argparse
from collections import Counter

# Bounded by construction: a share, ratio or fraction, which cannot rise
# merely because the run lasted longer or touched more files.
BOUNDED = {
    "ext_top_share", "api_top_bigram_share", "api_compress_ratio",
    "chain_top_shape_share", "cat_switch_rate", "api_bigram_entropy",
    "api_branching",
    "chain_read_only", "chain_write_only", "chain_read_write",
    "chain_read_destroy", "chain_write_destroy", "chain_full",
    "sel_rate_document", "sel_rate_media", "sel_rate_executable",
    "sel_rate_spread", "sel_doc_minus_exe",
    "sel_destroyed_exe_share", "sel_destroyed_doc_share",
    "sel_system_touch_share",
    "rw_jaccard", "write_not_read", "read_not_write",
    "read_then_destroy", "write_then_destroy",
}


def source_of(task_id):
    """Which set a row came from, read off the prefix the extraction added."""
    if task_id.startswith("NA") or task_id.startswith("NB"):
        return "benign"
    if task_id.startswith("H"):
        return "hardneg"
    return "ransomware"


def num(row, key):
    v = row.get(key, "")
    if v is None or v == "":
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def auc(pos, neg):
    pos = [x for x in pos if x is not None]
    neg = [x for x in neg if x is not None]
    if len(pos) < 5 or len(neg) < 5:
        return None, 0
    allv = sorted([(v, 1) for v in pos] + [(v, 0) for v in neg])
    ranks = {}
    i = 0
    while i < len(allv):
        j = i
        while j + 1 < len(allv) and allv[j + 1][0] == allv[i][0]:
            j += 1
        r = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[k] = r
        i = j + 1
    rp = sum(ranks[i] for i, (_v, l) in enumerate(allv) if l == 1)
    return (rp - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)), len(pos)


def median(values):
    v = sorted(x for x in values if x is not None)
    return v[len(v) // 2] if v else float("nan")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--relational", required=True)
    parser.add_argument("--results", required=True,
                         help="analyze_result output, for verdicts and call counts")
    parser.add_argument("--min-calls", type=int, default=500,
                         help="A benign run counts as having executed above this "
                              "many API calls -- the same threshold the verdict "
                              "logic uses to decide a sample ran at all.")
    parser.add_argument("--top", type=int, default=25)
    args = parser.parse_args()

    meta = {}
    with open(args.results, newline="") as f:
        for r in csv.DictReader(f):
            meta[str(r.get("task_id", "")).strip()] = r

    rows = []
    with open(args.relational, newline="") as f:
        for r in csv.DictReader(f):
            r["_src"] = source_of(r["task_id"])
            m = meta.get(r["task_id"], {})
            r["_verdict"] = m.get("verdict", "")
            try:
                r["_calls"] = int(m.get("total_calls") or 0)
            except ValueError:
                r["_calls"] = 0
            rows.append(r)

    counts = Counter(r["_src"] for r in rows)
    print(f"{len(rows)} runs: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))

    ransomware = [r for r in rows if r["_src"] == "ransomware"]
    benign = [r for r in rows if r["_src"] == "benign"]
    hardneg = [r for r in rows if r["_src"] == "hardneg"]
    benign_ran = [r for r in benign if r["_calls"] >= args.min_calls]

    print(f"   benign that executed (>= {args.min_calls} calls): "
          f"{len(benign_ran)} of {len(benign)}")
    print()

    features = [c for c in rows[0]
                if not c.startswith("_") and c not in ("task_id", "_error")]

    comparisons = [
        ("vs benign", benign),
        ("vs benign that ran", benign_ran),
        ("vs hard negatives", hardneg),
    ]

    scored = []
    for c in features:
        pos = [num(r, c) for r in ransomware]
        entry = {"name": c, "cov": sum(1 for x in pos if x is not None) / max(1, len(pos))}
        for label, neg_rows in comparisons:
            a, _ = auc(pos, [num(r, c) for r in neg_rows])
            entry[label] = a
        entry["med_r"] = median(pos)
        entry["med_h"] = median([num(r, c) for r in hardneg])
        scored.append(entry)

    # Rank by the hard negatives, since that is the comparison the easy
    # separation cannot carry.
    key = "vs hard negatives"
    usable = [e for e in scored if e[key] is not None]
    usable.sort(key=lambda e: -abs(e[key] - 0.5))

    head = (f"{'feature':<26}{'cov':>5}{'benign':>9}{'ran':>8}{'hardneg':>9}"
            f"   median ransomware / hardneg")
    print(head)
    print("-" * len(head))
    for e in usable[:args.top]:
        def fmt(v):
            return f"{v:.3f}" if v is not None else "    -"
        star = " *" if e["name"] in BOUNDED else "  "
        print(f"{e['name']:<24}{star}{e['cov']*100:>4.0f}%"
              f"{fmt(e['vs benign']):>9}{fmt(e['vs benign that ran']):>8}"
              f"{fmt(e[key]):>9}   {e['med_r']:>10.4g} / {e['med_h']:<10.4g}")

    print()
    print("  * bounded by construction")
    print()
    print("  Ranked by the hard negative column. The benign column is inflated:")
    print(f"  {len(benign) - len(benign_ran)} of {len(benign)} benign runs never")
    print("  executed, so they score zero on everything and anything that counts")
    print("  separates them. The hard negatives were built to be as busy as")
    print("  ransomware, so a feature that still separates them is describing")
    print("  behaviour rather than volume.")


if __name__ == "__main__":
    main()
