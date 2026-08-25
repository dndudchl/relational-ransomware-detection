#!/usr/bin/env python3
"""
check_against_labels.py - Compare the verdict logic against the hand-made
labels, so a change to the detection code can be checked in one command.

Why keep this
-------------
Nine faults in the verification logic were found by comparing its output
against labels made by looking at the sandbox screenshots and summaries. Each
was invisible from inside the event data: the counts looked healthy and the
reasoning looked sound. Only an independent record of what actually happened
exposed them.

That record is worth preserving and re-running. A change that improves
detection on one family can silently break another, and the labels are the
only thing that would show it.

What the labels mean
--------------------
  A   encryption seen on screen
  A2  not visible on screen, confirmed from the analysis summary
  N   no encryption observed
  X   not an encrypting program (mislabelled by the source)
  F   the analysis did not stand up; excluded from scoring

A and A2 are both confirmed encryption and are scored together. F is
excluded, because a run the sandbox never completed says nothing about the
detection logic.

Caveats worth remembering
-------------------------
The thresholds in the verdict logic were chosen by looking at these same
labels, so the agreement reported here is optimistic. It measures whether a
change breaks something, not how the logic would fare on families it has
never seen. An honest figure needs labels made after the thresholds were
fixed -- which is what a fresh batch of families provides.

The labels themselves are not perfect either. Two runs recorded as N were
later found to have made 42 and 48 append-renames, which is encryption the
manual pass missed. Disagreements are worth reading in both directions.

Usage
-----
  python3 check_against_labels.py --labels ../../../data/manual_labels.csv \\
      --results /tmp/results11.csv
"""

import csv
import sys
import argparse
from collections import defaultdict

CONFIRMED = {"A", "A2"}
EXCLUDED = {"F"}


def load_labels(path):
    labels = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            tid = str(row.get("task_id", "")).strip()
            if tid:
                labels[tid] = row
    return labels


def load_results(path):
    results = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            tid = str(row.get("task_id", "")).strip()
            if tid:
                results[tid] = row
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Check the verdict logic against the manual labels.")
    parser.add_argument("--labels", default="../../../data/manual_labels.csv")
    parser.add_argument("--results", required=True,
                         help="analyze_result.py output CSV")
    parser.add_argument("--show", type=int, default=25,
                         help="How many disagreements to list (default: 25)")
    args = parser.parse_args()

    labels = load_labels(args.labels)
    results = load_results(args.results)

    paired = [t for t in labels if t in results]
    print(f"labelled: {len(labels)}   with a verdict: {len(paired)}   "
          f"not analysed: {len(labels) - len(paired)}\n")

    # ---- cross-tab ----
    ct = defaultdict(lambda: defaultdict(int))
    for t in paired:
        ct[labels[t]["label"]][results[t]["verdict"]] += 1

    verdicts = sorted({results[t]["verdict"] for t in paired})
    print(f"{'label':<7}" + "".join(f"{v[:15]:>18}" for v in verdicts) + f"{'total':>8}")
    print("-" * (7 + 18 * len(verdicts) + 8))
    for label in ["A", "A2", "N", "X", "F"]:
        if label not in ct:
            continue
        row = ct[label]
        print(f"{label:<7}" + "".join(f"{row.get(v,0):>18}" for v in verdicts) +
              f"{sum(row.values()):>8}")

    # ---- scoring, excluding F ----
    scored = [t for t in paired if labels[t]["label"] not in EXCLUDED]
    confirmed = [t for t in scored if labels[t]["label"] in CONFIRMED]
    negative = [t for t in scored if labels[t]["label"] not in CONFIRMED]

    detected = [t for t in confirmed if results[t]["verdict"] == "TRUE_ENCRYPTION"]
    missed = [t for t in confirmed if results[t]["verdict"] != "TRUE_ENCRYPTION"]
    flagged = [t for t in negative if results[t]["verdict"] == "TRUE_ENCRYPTION"]

    print(f"\nconfirmed encryption detected : {len(detected)}/{len(confirmed)}"
          f"  ({len(detected)/len(confirmed)*100:.0f}%)" if confirmed else "")
    print(f"negatives flagged as encrypting: {len(flagged)}/{len(negative)}")

    def describe(tid):
        r = results[tid]
        bits = []
        for key, short in [("destroyed_decoy_files", "decoys"),
                           ("append_renames", "append"),
                           ("ransom_note_dirs", "note"),
                           ("total_calls", "calls")]:
            if key in r:
                bits.append(f"{short}={r[key]}")
        note = labels[tid].get("note", "")
        return "  ".join(bits) + (f"   [{note[:50]}]" if note else "")

    if missed:
        print(f"\n=== confirmed encryption, not detected ({len(missed)}) ===")
        for t in sorted(missed, key=int)[:args.show]:
            print(f"   {t:<5} ({labels[t]['label']:<2}) {results[t]['verdict']:<20} "
                  f"{describe(t)}")
        if len(missed) > args.show:
            print(f"   ... {len(missed) - args.show} more")

    if flagged:
        print(f"\n=== labelled as no encryption, verdict says otherwise ({len(flagged)}) ===")
        print("    read these in both directions -- the label may be the thing that is wrong")
        for t in sorted(flagged, key=int)[:args.show]:
            print(f"   {t:<5} ({labels[t]['label']:<2}) {results[t].get('reason','')[:44]}")
            print(f"         {describe(t)}")

    # ---- how each detected run was caught, if the columns are present ----
    if detected and "destroyed_decoy_files" in results[detected[0]]:
        by_axis = defaultdict(int)
        for t in detected:
            r = results[t]
            axes = []
            if int(r.get("destroyed_decoy_files") or 0) > 0: axes.append("decoy")
            if int(r.get("append_renames") or 0) > 0: axes.append("append")
            if int(r.get("ransom_note_dirs") or 0) > 0: axes.append("note")
            by_axis[" + ".join(axes) if axes else "(none)"] += 1
        print(f"\n=== which evidence was present on the runs that were detected ===")
        for combo, n in sorted(by_axis.items(), key=lambda x: -x[1]):
            print(f"   {combo:<24} {n}")

    sys.exit(0 if not missed and not flagged else 1)


if __name__ == "__main__":
    main()
