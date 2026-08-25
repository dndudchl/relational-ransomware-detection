#!/usr/bin/env python3
"""
band_auc.py - Re-measure candidate features inside bands of similar activity.

The plain ranking is dominated by volume. Runs that stopped short have a
median of 408 API calls and 8 file paths against 70,690 and 581 for runs that
encrypted, so any feature that counts anything separates them, and the top of
the table reads as a list of counts: extensions touched, paths touched, calls
made, distinct bigrams. None of that says the feature describes ransomware.
It says one group did more.

Holding activity roughly constant answers the narrower question the data can
actually settle: among runs that were equally busy, which features still tell
the two apart. A gap that survives inside a band is between comparable runs.
A gap that only exists across the whole set is the volume confound.

Ratios are reported alongside, because a feature whose value is bounded --
a share, a compression ratio, a fraction of chains -- cannot grow simply
because the run was longer, and is the more likely candidate to survive.

Usage
-----
  python3 band_auc.py --relational /tmp/relational.csv --results /tmp/res_all.csv
"""

import csv
import argparse
from collections import defaultdict

# Defaults suit n_calls. Banding on anything else needs its own edges:
# n_paths runs two orders of magnitude smaller, so these would put every run
# in one band and the comparison would report nothing.
DEFAULT_BANDS = {
    "n_calls": [500, 5_000, 25_000, 75_000],
    "n_paths": [1, 10, 100, 1_000],
}

# Features bounded by construction: a share, a ratio, a fraction. These
# cannot rise merely because the run was longer.
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
}


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
        return None
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
    return (rp - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--relational", required=True)
    parser.add_argument("--results", required=True)
    parser.add_argument("--band-on", default="n_calls",
                         help="Column the bands are formed from. n_calls holds API "
                              "volume constant but not file activity -- a run can make "
                              "fifty thousand registry calls without touching a file. "
                              "Banding on n_paths asks which features survive when both "
                              "groups handled a comparable number of files.")
    parser.add_argument("--min-band", type=int, default=25,
                         help="Skip a band with fewer than this many runs on either side")
    parser.add_argument("--edges", type=float, nargs="+", default=None,
                         help="Lower edge of each band. Defaults are set for n_calls "
                              "and n_paths; any other column needs them given.")
    args = parser.parse_args()

    edges = args.edges or DEFAULT_BANDS.get(args.band_on)
    if not edges:
        print(f"[!] no default bands for '{args.band_on}'. Pass --edges.")
        return
    bands = [(edges[i], edges[i + 1] if i + 1 < len(edges) else 10**12)
             for i in range(len(edges))]

    verdict = {}
    with open(args.results, newline="") as f:
        for r in csv.DictReader(f):
            verdict[str(r.get("task_id", "")).strip()] = r.get("verdict", "")

    rows = []
    with open(args.relational, newline="") as f:
        for r in csv.DictReader(f):
            v = verdict.get(r["task_id"])
            if not v:
                continue
            r["_enc"] = (v == "TRUE_ENCRYPTION")
            rows.append(r)

    features = [c for c in rows[0]
                if c not in ("task_id", "_enc", "_error", args.band_on)]

    print(f"{len(rows)} runs with a verdict "
          f"({sum(r['_enc'] for r in rows)} encrypting)\n")

    # Per-band AUC, plus a note of how consistent the direction is.
    per_band = defaultdict(dict)
    band_sizes = {}
    for lo, hi in bands:
        band = [r for r in rows
                if (c := num(r, args.band_on)) is not None and lo <= c < hi]
        enc = [r for r in band if r["_enc"]]
        non = [r for r in band if not r["_enc"]]
        band_sizes[(lo, hi)] = (len(enc), len(non))
        if len(enc) < args.min_band or len(non) < args.min_band:
            continue
        for c in features:
            a = auc([num(r, c) for r in enc], [num(r, c) for r in non])
            if a is not None:
                per_band[c][(lo, hi)] = a

    def name(v):
        v = int(v)
        return f"{v//1000}k" if v >= 1000 else str(v)
    label = {b: (f"{name(b[0])}-{name(b[1])}" if b[1] < 10**12
                 else f"{name(b[0])}+") for b in bands}
    usable = [b for b in bands
              if any(b in per_band[c] for c in features)] if features else []
    if not usable:
        print(f"[!] no band on '{args.band_on}' had at least {args.min_band} runs "
              f"on both sides. Sizes were:")
        for b in bands:
            print(f"      {label[b]:>12}  encrypting {band_sizes[b][0]:>5}, "
                  f"other {band_sizes[b][1]:>5}")
        return

    header = f"{'feature':<26}" + "".join(f"{label[b]:>10}" for b in usable) + f"{'worst':>9}  "
    print("Bands used: " + ", ".join(
        f"{label[b]} (enc {band_sizes[b][0]}, other {band_sizes[b][1]})" for b in usable))
    print()
    print(header)
    print("-" * len(header))

    scored = []
    for c in features:
        vals = [per_band[c].get(b) for b in usable]
        if any(v is None for v in vals):
            continue
        # Distance from 0.5 in the band where the feature does worst. A
        # feature that only works in one band is measuring that band, not
        # the behaviour.
        worst = min(abs(v - 0.5) for v in vals)
        # Direction has to agree across bands, otherwise the feature means
        # different things at different activity levels.
        consistent = len({v > 0.5 for v in vals}) == 1
        scored.append((worst, consistent, c, vals))

    for worst, consistent, c, vals in sorted(scored, key=lambda x: -x[0]):
        mark = "" if consistent else "  <- direction flips"
        bounded = " *" if c in BOUNDED else "  "
        line = f"{c:<24}{bounded}" + "".join(f"{v:>10.3f}" for v in vals)
        print(f"{line}{worst:>9.3f}{mark}")

    print()
    print("  * bounded by construction (a share, ratio or fraction), so it")
    print("    cannot grow with the length of the run")
    print()
    print("  'worst' is the distance from 0.5 in the band where the feature is")
    print("  weakest. A feature that holds in every band is measuring something")
    print("  other than how much the sample did; one that works in a single")
    print("  band is describing that band.")
    print()
    print("  Both groups remain ransomware. This says what accompanies reaching")
    print("  encryption among equally busy runs -- the comparison against")
    print("  ordinary software still needs benign data.")


if __name__ == "__main__":
    main()
