#!/usr/bin/env python3
"""
screenshot_diff.py - Measure how much the guest desktop changed during each
analysis, and cross-check that against the behavioural verdict.

Why
---
The behavioural verdict comes from the same event log the detection features
come from, so validating it against that log is circular. Screenshots are
independent evidence: pixels, not API traces.

They have already caught a real error. AvosLocker samples encrypted the decoy
files, the screenshots showed it plainly, and the verdict said
WEAK_VICTIM_ACTIVITY -- because the verdict counted destructive events and
AvosLocker overwrites in place, one event per file instead of three. Nothing
inside the event data hinted at the mistake.

Reviewing screenshots by hand does not scale, but it does not have to. What
matters is finding the analyses where the two kinds of evidence disagree.

How the measurement works, and why it is built this way
------------------------------------------------------
Every design choice below was forced by measurements on real CAPE
screenshots. The obvious implementations do not work:

**Colour, not greyscale.** Encryption turns coloured file icons into blank
white document icons. In greyscale a green Excel icon and a white page have
similar luminance, so converting to greyscale destroyed almost the entire
signal: a fully encrypted desktop measured 2.0% changed, *less* than an
analysis where a tooltip had merely popped up. Comparing RGB channels
recovers it.

**Grid cells, not a whole-screen pixel fraction.** The wallpaper is most of
the screen and never changes, which dilutes everything. Measured across the
full frame, full encryption came out at only 3% of pixels -- indistinguishable
from noise. Counting how many cells of a 16x12 grid changed instead measures
*how widely* the screen changed, which is the real difference: encryption
alters every icon across the whole desktop, while UI noise alters one
contiguous blob.

**Masking the taskbar and the notification corner.** The taskbar clock ticks
over in every analysis. Windows also raises toast notifications in the
bottom-right corner, unprompted, and one of those alone moved the reading by
26 grid cells -- comparable to encryption itself. With both regions masked,
two analyses in the same encrypted end state measured 16.7% and 17.9%
regardless of whether a notification happened to appear, which is the
consistency the metric needs.

Observed signal levels on confirmed-encrypting runs:

    ransom note dropped, icons not yet rewritten   8.3% of cells
    all icons blank, .skynet appended to names    16.7% - 17.9% of cells

The threshold below is provisional. Setting it properly needs readings from
analyses where nothing happened, which means running this over a batch that
includes NO_VICTIM_ACTIVITY cases and looking at where the two groups fall.
Until then, treat the numbers as the output and the verdict as a suggestion.

Reading the output
------------------
    behaviour says encrypted  +  screen changed    -> agree, no review
    behaviour says nothing    +  screen unchanged   -> agree, no review
    behaviour says nothing    +  screen changed     -> possible false negative
    behaviour says encrypted  +  screen unchanged   -> possible false positive

Only the last two need human eyes.

A caveat: screenshots show the desktop, not Documents or Downloads, and
in-place overwriting leaves filenames unchanged. Visible change is strong
evidence something happened; its absence is weak evidence that nothing did.
This is a false-negative detector, not a labelling tool.

Usage
-----
  python3 screenshot_diff.py --analyses-dir /opt/CAPEv2/storage/analyses \\
      --results analysis_results.csv --out visual.csv \\
      --save-flagged ~/flagged_screenshots

  # Show the distribution, to calibrate the threshold
  python3 screenshot_diff.py --analyses-dir /opt/CAPEv2/storage/analyses \\
      --results analysis_results.csv --out visual.csv --calibrate

Requires Pillow:  pip install pillow
"""

import os
import sys
import csv
import shutil
import argparse
from pathlib import Path
from collections import defaultdict

# A pixel counts as changed when any RGB channel differs by more than this.
PIXEL_TOLERANCE = 40

# Grid used to measure how widely the screen changed.
GRID_X, GRID_Y = 16, 12

# A grid cell counts as changed when this fraction of its pixels changed.
CELL_CHANGE_FRACTION = 0.08

# Rows of the taskbar to ignore, in pixels from the bottom. Removes the clock.
TASKBAR_HEIGHT = 48

# Bottom-right region where Windows raises toast notifications, as fractions
# of width and height. Ignored because an unprompted notification shifted the
# reading as much as encryption did.
TOAST_X_FROM, TOAST_Y_FROM = 0.60, 0.66

# Region the decoy icons occupy, as fractions of width and height. Measured
# from the analysis VM's desktop layout, which is fixed because every run
# starts from the same snapshot.
#
# Restricting the measurement here fixes a specific failure. In a batch of 101
# hand-labelled analyses, nine runs where nothing was encrypted read 28-33%
# because a decryptor application window had opened. That window sits in the
# middle of the screen; the decoy icons sit in the left column. Measuring only
# the icon region ignores centred windows while still catching encryption,
# which alters every icon.
ICON_REGION_X_TO, ICON_REGION_Y_TO = 0.34, 0.91

# A screenshot whose pixels are this uniform is a transition artefact (screen
# blanking, a full-screen solid colour) rather than a view of the desktop.
# Two analyses ended on an all-black frame and read 100% changed, which is
# true but says nothing about encryption.
UNIFORM_SHOT_STD_MAX = 6.0

# How many screenshots to compare the first one against. Comparing only the
# last one misses encryption that was undone before the run ended: two
# analyses re-created the original icons at the end and read 3.6% and 5.4%
# despite having encrypted the decoys mid-run. Sampling across the whole
# sequence and keeping the maximum catches those, without the cost of
# comparing against all of what can be a hundred frames.
MAX_COMPARISONS = 20

# Provisional. Confirmed encrypting runs measured 16-33% of icon-region cells;
# runs where nothing happened measured 0-6%. Calibrate with --calibrate once
# verdicts are available for a batch.
CELL_CHANGE_THRESHOLD = 0.10


def list_shots(analysis_dir):
    """Screenshots in capture order. CAPE names them numerically."""
    shots_dir = Path(analysis_dir) / "shots"
    if not shots_dir.is_dir():
        return []
    shots = [p for p in shots_dir.iterdir()
             if p.suffix.lower() in (".png", ".jpg", ".jpeg", ".bmp")]

    def sort_key(p):
        return (0, int(p.stem)) if p.stem.isdigit() else (1, p.stem)

    return sorted(shots, key=sort_key)


def changed_pixel_mask(first_path, last_path):
    """
    Binary mask of changed pixels, built with Pillow's C-level operations
    rather than a Python loop -- a per-pixel loop over 786k pixels for every
    analysis in a batch is too slow to run from cron.
    """
    try:
        from PIL import Image, ImageChops
    except ImportError:
        print("[!] Pillow is required: pip install pillow")
        sys.exit(1)

    try:
        a = Image.open(first_path).convert("RGB")
        b = Image.open(last_path).convert("RGB")
    except Exception:
        return None

    if a.size != b.size:
        b = b.resize(a.size)

    diff = ImageChops.difference(a, b)
    r, g, bl = diff.split()
    # Max across channels: a colour change in any one channel counts.
    max_channel = ImageChops.lighter(ImageChops.lighter(r, g), bl)
    return max_channel.point(lambda v: 255 if v > PIXEL_TOLERANCE else 0), a.size


def cell_is_masked(x0, y0, x1, y1, w, h, icon_region_only):
    """
    True for grid cells that should not be measured.

    Always excluded: the taskbar (its clock changes every minute) and the
    bottom-right corner where Windows raises toast notifications unprompted --
    one such notification shifted a reading by 26 grid cells, as much as
    encryption itself.

    Additionally excluded when icon_region_only is set: everything outside the
    left-hand column where the decoy icons live. This is what separates
    encryption from a centred application window.
    """
    if y0 >= h - TASKBAR_HEIGHT:
        return True
    if x0 >= int(w * TOAST_X_FROM) and y0 >= int(h * TOAST_Y_FROM):
        return True
    if icon_region_only:
        if x0 >= int(w * ICON_REGION_X_TO) or y0 >= int(h * ICON_REGION_Y_TO):
            return True
    return False


def is_uniform(path):
    """
    True when a screenshot is a near-solid colour, which means it captured a
    blank or transitioning screen rather than the desktop.
    """
    try:
        from PIL import Image, ImageStat
        img = Image.open(path).convert("L")
        return ImageStat.Stat(img).stddev[0] < UNIFORM_SHOT_STD_MAX
    except Exception:
        return False


def sample_shots(shots, limit):
    """
    Evenly spaced subset of the later screenshots, always including the last.
    Comparing the first frame against several later ones catches encryption
    that was reverted before the run finished.
    """
    later = shots[1:]
    if len(later) <= limit:
        return later
    step = len(later) / limit
    picked = [later[int(i * step)] for i in range(limit)]
    if later[-1] not in picked:
        picked[-1] = later[-1]
    return picked


def measure(first_path, other_path, icon_region_only=True):
    """Fraction of usable grid cells that changed, plus supporting numbers."""
    result = changed_pixel_mask(first_path, other_path)
    if result is None:
        return None
    mask, (w, h) = result

    cw, ch = w // GRID_X, h // GRID_Y
    changed_cells = usable_cells = 0
    changed_pixels_total = usable_pixels_total = 0

    for gy in range(GRID_Y):
        for gx in range(GRID_X):
            x0, y0 = gx * cw, gy * ch
            x1, y1 = min(x0 + cw, w), min(y0 + ch, h)
            if cell_is_masked(x0, y0, x1, y1, w, h, icon_region_only):
                continue
            usable_cells += 1
            cell = mask.crop((x0, y0, x1, y1))
            # histogram()[255] counts the changed pixels without a Python loop
            changed = cell.histogram()[255]
            area = (x1 - x0) * (y1 - y0)
            changed_pixels_total += changed
            usable_pixels_total += area
            if changed / area > CELL_CHANGE_FRACTION:
                changed_cells += 1

    if not usable_cells:
        return None

    return {
        "cell_change_fraction": changed_cells / usable_cells,
        "cells_changed": changed_cells,
        "cells_usable": usable_cells,
        "pixel_change_fraction": (changed_pixels_total / usable_pixels_total
                                   if usable_pixels_total else 0),
    }


def analyse_one(analysis_dir, threshold, icon_region_only=True,
                 max_comparisons=MAX_COMPARISONS):
    """
    Compare the opening screenshot against several later ones and keep the
    largest change. The peak is what matters: encryption that was reverted
    before the run ended still happened.
    """
    shots = list_shots(analysis_dir)
    task = Path(analysis_dir).name
    blank = {
        "task_id": task, "n_shots": len(shots),
        "cells_changed": "", "cells_usable": "",
        "cell_change_fraction": "", "pixel_change_fraction": "",
        "visual_change": "unknown", "peak_shot": "",
        "first_shot": str(shots[0]) if shots else "", "last_shot": "",
    }

    if len(shots) < 2:
        return blank

    candidates = [p for p in sample_shots(shots, max_comparisons) if not is_uniform(p)]
    if not candidates:
        # Every later frame was blank; nothing comparable was captured.
        blank["visual_change"] = "unreadable"
        blank["last_shot"] = str(shots[-1])
        return blank

    best, best_path = None, None
    for path in candidates:
        m = measure(shots[0], path, icon_region_only)
        if m and (best is None or m["cell_change_fraction"] > best["cell_change_fraction"]):
            best, best_path = m, path

    if best is None:
        blank["visual_change"] = "unreadable"
        blank["last_shot"] = str(shots[-1])
        return blank

    return {
        "task_id": task,
        "n_shots": len(shots),
        "cells_changed": best["cells_changed"],
        "cells_usable": best["cells_usable"],
        "cell_change_fraction": round(best["cell_change_fraction"], 4),
        "pixel_change_fraction": round(best["pixel_change_fraction"], 4),
        "visual_change": "yes" if best["cell_change_fraction"] >= threshold else "no",
        "peak_shot": Path(best_path).name,
        "first_shot": str(shots[0]),
        "last_shot": str(shots[-1]),
    }


def load_verdicts(results_csv):
    if not results_csv or not os.path.exists(results_csv):
        return {}
    verdicts = {}
    with open(results_csv, newline="") as f:
        for row in csv.DictReader(f):
            tid = str(row.get("task_id", "")).strip()
            if tid:
                verdicts[tid] = {
                    "verdict": row.get("verdict", ""),
                    "destroyed": row.get("destroyed_decoy_files", ""),
                }
    return verdicts


def classify_agreement(verdict, visual_change):
    if not verdict or visual_change in ("unknown", "unreadable"):
        return ""
    claims_encryption = verdict == "TRUE_ENCRYPTION"
    changed = visual_change == "yes"
    if claims_encryption == changed:
        return "agree"
    if changed:
        return "REVIEW: screen changed but verdict says no encryption"
    return "REVIEW: verdict says encryption but screen unchanged"


FIELDNAMES = ["task_id", "n_shots", "cells_changed", "cells_usable",
              "cell_change_fraction", "pixel_change_fraction", "visual_change",
              "peak_shot", "verdict", "destroyed_decoy_files", "agreement",
              "first_shot", "last_shot"]


def print_calibration(rows):
    """
    Show where each verdict group falls, which is what a threshold has to
    separate. Without readings from analyses where nothing happened, any
    threshold is guesswork.
    """
    by_verdict = defaultdict(list)
    for r in rows:
        if r["cell_change_fraction"] == "" or not r["verdict"]:
            continue
        by_verdict[r["verdict"]].append(r["cell_change_fraction"])

    if not by_verdict:
        print("\n[calibration] no verdicts available to compare against")
        return

    print("\n[calibration] cell-change fraction by verdict")
    print(f"   {'verdict':<24} {'n':>4} {'min':>8} {'median':>8} {'max':>8}")
    print("   " + "-" * 56)
    for verdict in sorted(by_verdict):
        vals = sorted(by_verdict[verdict])
        median = vals[len(vals) // 2]
        print(f"   {verdict:<24} {len(vals):>4} {vals[0]*100:>7.1f}% "
              f"{median*100:>7.1f}% {vals[-1]*100:>7.1f}%")

    positives = by_verdict.get("TRUE_ENCRYPTION", [])
    negatives = [v for k, vals in by_verdict.items()
                 if k != "TRUE_ENCRYPTION" for v in vals]
    if positives and negatives:
        print(f"\n   highest non-encrypting reading : {max(negatives)*100:.1f}%")
        print(f"   lowest encrypting reading      : {min(positives)*100:.1f}%")
        if max(negatives) < min(positives):
            midpoint = (max(negatives) + min(positives)) / 2
            print(f"   the two groups separate cleanly; a threshold near "
                  f"{midpoint*100:.1f}% would divide them")
        else:
            print("   the groups overlap, so no single threshold separates them --")
            print("   inspect the overlapping analyses before trusting either signal")


def main():
    parser = argparse.ArgumentParser(
        description="Measure desktop change per analysis and cross-check verdicts.")
    parser.add_argument("--analyses-dir", required=True,
                         help="CAPE storage/analyses directory")
    parser.add_argument("--results", default=None,
                         help="analyze_result.py output CSV, to cross-check verdicts")
    parser.add_argument("--out", default="visual.csv", help="CSV output path")
    parser.add_argument("--save-flagged", default=None, metavar="DIR",
                         help="Copy the first and last screenshot of every disagreeing "
                              "analysis here, so they outlive the cleanup stage")
    parser.add_argument("--threshold", type=float, default=CELL_CHANGE_THRESHOLD,
                         help=f"Cell-change fraction above which the desktop counts as "
                              f"changed (default: {CELL_CHANGE_THRESHOLD}, provisional)")
    parser.add_argument("--whole-screen", action="store_true",
                         help="Measure the whole frame instead of just the icon region. "
                              "Restricting to the icon region is the default because a "
                              "centred application window otherwise reads as encryption.")
    parser.add_argument("--max-comparisons", type=int, default=MAX_COMPARISONS,
                         help=f"How many later screenshots to compare the first against "
                              f"(default: {MAX_COMPARISONS})")
    parser.add_argument("--calibrate", action="store_true",
                         help="Print the distribution of readings per verdict, to choose "
                              "a threshold from data instead of guessing")
    args = parser.parse_args()

    base = Path(args.analyses_dir)
    if not base.is_dir():
        print(f"[!] not a directory: {args.analyses_dir}")
        sys.exit(1)

    verdicts = load_verdicts(args.results)
    dirs = sorted((p for p in base.iterdir() if p.is_dir() and p.name.isdigit()),
                   key=lambda p: int(p.name))
    if not dirs:
        print(f"[!] no analysis directories under {args.analyses_dir}")
        sys.exit(1)

    region = "whole frame" if args.whole_screen else "icon region only"
    print(f"Comparing the opening screenshot of {len(dirs)} analyses against up to "
          f"{args.max_comparisons} later ones, keeping the peak change")
    print(f"(threshold: {args.threshold} of grid cells; {region}; taskbar and "
          f"notification corner ignored)\n")

    header = (f"{'task':<7} {'shots':>6} {'cells':>8} {'changed':>9} {'visual':<9} "
              f"{'verdict':<22} {'files':>6} agreement")
    print(header)
    print("-" * (len(header) + 20))

    rows = []
    for d in dirs:
        row = analyse_one(d, args.threshold,
                          icon_region_only=not args.whole_screen,
                          max_comparisons=args.max_comparisons)
        info = verdicts.get(row["task_id"], {})
        row["verdict"] = info.get("verdict", "")
        row["destroyed_decoy_files"] = info.get("destroyed", "")
        row["agreement"] = classify_agreement(row["verdict"], row["visual_change"])
        rows.append(row)

        frac = row["cell_change_fraction"]
        pct = f"{frac*100:.1f}%" if frac != "" else "-"
        cells = (f"{row['cells_changed']}/{row['cells_usable']}"
                 if row["cells_changed"] != "" else "-")
        mark = row["agreement"] if row["agreement"] != "agree" else ""
        print(f"{row['task_id']:<7} {row['n_shots']:>6} {cells:>8} {pct:>9} "
              f"{row['visual_change']:<9} {row['verdict'][:20]:<22} "
              f"{str(row['destroyed_decoy_files']):>6} {mark}")

    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in FIELDNAMES})
    print(f"\n[saved] {args.out}")

    changed = sum(1 for r in rows if r["visual_change"] == "yes")
    unmeasurable = sum(1 for r in rows if r["visual_change"] in ("unknown", "unreadable"))
    flagged = [r for r in rows if r["agreement"].startswith("REVIEW")]

    print(f"\nvisibly changed : {changed}/{len(rows)}")
    if unmeasurable:
        print(f"not measurable  : {unmeasurable} (fewer than two screenshots, or unreadable)")
    if verdicts:
        print(f"agree with verdict : {sum(1 for r in rows if r['agreement'] == 'agree')}")
        print(f"NEED REVIEW        : {len(flagged)}")
        for r in flagged:
            frac = r["cell_change_fraction"]
            pct = f"{frac*100:.1f}%" if frac != "" else "-"
            print(f"   task {r['task_id']:<6} changed={pct:<7} verdict={r['verdict']}")

    if args.calibrate:
        print_calibration(rows)

    if args.save_flagged and flagged:
        dest = Path(args.save_flagged).expanduser()
        dest.mkdir(parents=True, exist_ok=True)
        n = 0
        for r in flagged:
            for label, path in (("first", r["first_shot"]), ("last", r["last_shot"])):
                if path and os.path.exists(path):
                    shutil.copyfile(path, dest / f"task{r['task_id']}_{label}{Path(path).suffix}")
                    n += 1
        print(f"\n[saved] {n} screenshots from {len(flagged)} flagged analyses -> {dest}")
        print("        These survive cleanup; review them to decide whether the")
        print("        verdict logic needs adjusting.")


if __name__ == "__main__":
    main()
