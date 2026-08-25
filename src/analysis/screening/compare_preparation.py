#!/usr/bin/env python3
"""
compare_preparation.py - Ask whether ground-clearing behaviour separates the
runs that reached encryption from the runs that executed and did not.

The question, and what it is not
-------------------------------
Both groups here are ransomware. This comparison therefore cannot say whether
preparation distinguishes ransomware from ordinary software -- that needs
benign programs run through the same sandbox, which has not been done yet.

What it can say is narrower and still useful: among samples that ran, does
preparation accompany reaching the encryption stage? If a family deletes
shadow copies and stops, preparation is not a reliable precursor. If almost
everything that encrypted prepared first, and almost nothing that stopped
short did, then preparation is worth acting on before any files are lost.

Why activity has to be held constant
------------------------------------
The obvious comparison is misleading. Runs that did not encrypt are, on
average, runs that did less of everything -- some barely got going. Any
behaviour will then look more common among the encrypting group simply
because that group was busier.

So the comparison is made within bands of similar API-call volume. A gap that
survives inside a band is a gap between samples that were equally active, and
means something. A gap that only exists across the whole set does not.

Usage
-----
  python3 compare_preparation.py --features ../../../data/features.csv \\
      --results /tmp/results11.csv
"""

import csv
import sys
import argparse
from collections import defaultdict

# Bands of API-call volume. Chosen so that each holds enough of both groups to
# compare; the boundaries are round numbers, not fitted to anything.
ACTIVITY_BANDS = [
    (500, 5_000, "500 - 5k"),
    (5_000, 25_000, "5k - 25k"),
    (25_000, 75_000, "25k - 75k"),
    (75_000, 10**12, "75k+"),
]

# Features that describe preparation, split by whether they are counts or
# statements about ordering.
COUNT_FEATURES = [
    "n_shadow_delete", "n_recovery_disable", "n_service_stop", "n_process_kill",
    "n_log_clear", "n_lateral_movement", "n_persistence",
    "n_services_created", "n_services_started", "n_prep_processes",
    "n_prep_categories",
]
ORDER_FEATURES = [
    "prep_precedes_destroy", "n_prep_before_destroy",
]
TIMING_FEATURES = [
    "prep_to_first_destroy_sec", "destroy_span_after_prep_sec",
]


def load_csv(path, key):
    out = {}
    try:
        with open(path, newline="") as f:
            for row in csv.DictReader(f):
                k = str(row.get(key, "")).strip()
                if k:
                    out[k] = row
    except OSError as e:
        print(f"[!] cannot read {path}: {e}")
        sys.exit(1)
    return out


def num(row, key):
    v = row.get(key, "")
    if v is None or v == "":
        return None
    try:
        return float(v)
    except ValueError:
        return None


def prevalence(group, key):
    """Share of the group where the feature is present, and the group size
    over which that share was computed."""
    vals = [num(r, key) for r in group]
    usable = [v for v in vals if v is not None]
    if not usable:
        return None, 0
    return sum(1 for v in usable if v > 0) / len(usable) * 100, len(usable)


def median(values):
    v = sorted(values)
    return v[len(v) // 2] if v else None


def main():
    parser = argparse.ArgumentParser(
        description="Compare preparation behaviour between encrypting and "
                    "non-encrypting runs, holding activity constant.")
    parser.add_argument("--features", default="../../../data/features.csv")
    parser.add_argument("--results", required=True,
                         help="analyze_result.py output, for the API call counts")
    parser.add_argument("--min-band", type=int, default=8,
                         help="Skip a band unless both groups have at least this many "
                              "runs in it (default: 8)")
    args = parser.parse_args()

    features = load_csv(args.features, "sample_id")
    results = load_csv(args.results, "task_id")

    rows = []
    for sid, frow in features.items():
        if frow.get("coverage") != "full":
            continue
        rrow = results.get(sid)
        if not rrow:
            continue
        calls = num(rrow, "total_calls")
        if calls is None:
            continue
        merged = dict(frow)
        merged["total_calls"] = calls
        merged["verdict"] = frow.get("verdict") or rrow.get("verdict", "")
        rows.append(merged)

    enc = [r for r in rows if r["verdict"] == "TRUE_ENCRYPTION"]
    non = [r for r in rows if r["verdict"] and r["verdict"] != "TRUE_ENCRYPTION"]

    print(f"executed runs matched across both files : {len(rows)}")
    print(f"   reached encryption                   : {len(enc)}")
    print(f"   executed without encrypting          : {len(non)}\n")
    if not enc or not non:
        print("[!] one group is empty; nothing to compare")
        sys.exit(1)

    print("Both groups are ransomware. This says which behaviours accompany")
    print("reaching the encryption stage -- not what separates ransomware from")
    print("ordinary software, which needs benign runs for comparison.\n")

    # ---------- unmatched, for reference ----------
    print("=== whole set, activity not held constant ===")
    print(f"{'feature':<26}{'encrypting':>12}{'stopped short':>15}{'gap':>9}")
    print("-" * 62)
    for key in COUNT_FEATURES + ORDER_FEATURES:
        e, ne = prevalence(enc, key)
        n, nn = prevalence(non, key)
        if e is None or n is None:
            continue
        print(f"{key:<26}{e:>11.1f}%{n:>14.1f}%{e-n:>8.1f}")

    print("\n   These numbers are inflated. Runs that stopped short did less of")
    print("   everything, so any behaviour looks commoner among the others.")

    # ---------- matched by activity ----------
    print("\n\n=== within bands of similar API-call volume ===")
    for lo, hi, name in ACTIVITY_BANDS:
        be = [r for r in enc if lo <= r["total_calls"] < hi]
        bn = [r for r in non if lo <= r["total_calls"] < hi]
        if len(be) < args.min_band or len(bn) < args.min_band:
            print(f"\n   {name:<12} encrypting={len(be):<4} stopped short={len(bn):<4}"
                  f"   -- too few to compare")
            continue

        print(f"\n   {name}   encrypting={len(be)}  stopped short={len(bn)}")
        print(f"   {'feature':<26}{'encrypting':>12}{'stopped short':>15}{'gap':>9}")
        print("   " + "-" * 62)
        for key in COUNT_FEATURES + ORDER_FEATURES:
            e, _ = prevalence(be, key)
            n, _ = prevalence(bn, key)
            if e is None or n is None:
                continue
            mark = "  <<" if abs(e - n) >= 25 else ""
            print(f"   {key:<26}{e:>11.1f}%{n:>14.1f}%{e-n:>8.1f}{mark}")

    # ---------- timing, encrypting runs only ----------
    print("\n\n=== timing, among runs that both prepared and destroyed ===")
    for key in TIMING_FEATURES:
        vals = [num(r, key) for r in enc]
        vals = [v for v in vals if v is not None]
        if not vals:
            print(f"   {key:<30} no data")
            continue
        v = sorted(vals)
        print(f"   {key:<30} n={len(v):<4} min={v[0]:>8.1f}  "
              f"median={median(v):>8.1f}  max={v[-1]:>9.1f}")

    ordered = [r for r in enc if num(r, "prep_precedes_destroy") == 1]
    prepped = [r for r in enc if (num(r, "n_prep_processes") or 0) > 0]
    if prepped:
        print(f"\n   of {len(prepped)} encrypting runs that launched a preparation tool,")
        print(f"   {len(ordered)} did so before the first file was destroyed "
              f"({len(ordered)/len(prepped)*100:.0f}%)")

    print("\n\nA gap that holds inside a band is between samples that were equally")
    print("active. A gap that appears only in the whole-set table is an artefact")
    print("of one group having done less of everything.")


if __name__ == "__main__":
    main()
