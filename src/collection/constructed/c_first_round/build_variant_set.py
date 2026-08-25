#!/usr/bin/env python3
"""
build_variant_set.py - Sample the behaviour matrix instead of hand-picking
from it.

Why sampling rather than a longer hand-written list
---------------------------------------------------
The first set of 68 was chosen to isolate one factor at a time, which is the
right design for asking what each factor does. It is the wrong design for
two other things.

It is too small to put an interval on anything. The relational features lower
the false positive rate on those 68 by about 5 programs, and an effect that
size on that many samples has a confidence interval wide enough to include
zero. Several hundred variants narrows it to the point where the claim can be
made or withdrawn.

And it cannot separate interacting factors. Holding everything constant but
the method says what changing the method does at that one baseline. It says
nothing about whether the effect of the method depends on the volume, which
is a question the matrix can answer only if the combinations are populated.

The parameter space is 9 methods x 3 scopes x 5 volume limits x 4 file type
filters x 3 timing patterns x 2 naming rules x 2 orderings x the side effect
mask -- more combinations than there is time to run. Drawing from it at
random, with the constraints that keep a combination coherent, gives a set
that supports regression on the factors rather than comparison against a
baseline.

Usage
-----
  python3 build_variant_set.py --count 400 --outdir ~/variants
  python3 build_variant_set.py --count 400 --outdir ~/variants --manifest-only
"""

import os
import csv
import random
import argparse
from collections import Counter
import subprocess

CC = "x86_64-w64-mingw32-gcc"

METHODS = {
    1: "overwrite in place",
    2: "copy then delete",
    3: "rename only",
    4: "many inputs, one output",
    5: "write without reading",
    6: "read, encrypt, write, delete",
    7: "overwrite with random, then delete",
    8: "copy, keep the original",
    9: "move to another directory",
    10: "scratch files, written then removed",
}
SCOPES = {1: "user profile", 2: "Program Files", 3: "walk C:\\",
          4: "AppData", 5: "several roots at once"}
# Spaced roughly logarithmically, because the quantity being traced spans
# three orders of magnitude and the interesting part is at the bottom.
#
# The benign programs that executed touch a median of 3 distinct paths and
# are almost never flagged; the hard negatives touch 95 and are flagged 72%
# of the time. Everything that decides the false positive rate happens
# between those two numbers, and the first set of variants had nothing
# between 10 and 50. Ransomware touches a median of 578, so the upper end
# has to reach past that as well -- and since the decoy set is only 176
# files, the counts above it can only come from generated targets.
LIMITS = [0, 1, 3, 5, 10, 20, 35, 50, 75, 100, 140, 176]
FILTERS = {0: "all types", 1: "documents", 2: "media", 3: "executables"}
TIMINGS = {0: "burst", 1: "spread", 2: "batched"}

EFFECT_BITS = {1: "note", 2: "wallpaper", 4: "shadow", 8: "recovery", 16: "service"}


def coherent(p):
    """
    Reject combinations that cannot do what they say.

    Filtering for executables inside the user profile finds nothing: the
    decoy set has no .exe in it, which is why selectivity could only ever be
    tested against Program Files. Generating files and then filtering by type
    is similarly empty, since everything generated has the same extension.
    """
    if p["FILTER"] == 3 and p["SCOPE"] == 1:
        return False
    if p["GENERATE"] and (p["FILTER"] != 0 or p["SCOPE"] != 1):
        return False
    if p["METHOD"] == 4 and p["GENERATE"]:
        return False
    # Scratch files are named after the file they were staged from, so the
    # method needs something to enumerate, and its output has one extension
    # whatever the filter says.
    if p["METHOD"] == 10 and p["FILTER"] == 3 and p["SCOPE"] not in (2, 3, 5):
        return False
    # A run doing no file work at all is the FILES_ONLY=0 case, and those are
    # worth having, but only with at least one side behaviour to perform.
    if not p["FILES_ONLY"] and p["EFFECTS"] == 0:
        return False
    return True


def expected_paths(p):
    """
    Roughly how many distinct files the variant will reach.

    An estimate, not a measurement -- the run may find fewer -- but accurate
    enough to spread the set across the range, which is all it is used for.
    """
    if p["GENERATE"]:
        n = p["GENERATE"]
    elif p["SCOPE"] == 1:
        n = 176                    # the decoy set
    elif p["SCOPE"] == 4:
        n = 900                    # AppData, smaller than Program Files
    else:
        n = 2000                   # capped by the timeout, not by the tree
    if p["LIMIT"]:
        n = min(n, p["LIMIT"])
    if p["FILTER"]:
        n = int(n * 0.35)          # one file type out of the mix
    return max(1, n)


def draw(rng):
    p = {
        "METHOD": rng.choice(list(METHODS)),
        "SCOPE": rng.choice(list(SCOPES)),
        "LIMIT": rng.choice(LIMITS),
        "FILTER": rng.choice(list(FILTERS)),
        "TIMING": rng.choice(list(TIMINGS)),
        "RENAME_MODE": rng.choice([0, 0, 1]),      # append is the common case
        "BATCH": rng.choice([0, 0, 0, 1]),
        # Generated targets are the only way past the 176 decoys, so they
        # carry the top of the range on their own and are drawn more often
        # than the one-in-seven the first set used.
        "GENERATE": rng.choice([0, 0, 0, 0, 0, 0,
                                 50, 100, 250, 400, 600, 900, 1400, 2000]),
        "FILES_ONLY": rng.choice([1, 1, 1, 1, 1, 1, 1, 1, 1, 0]),
        "EFFECTS": 0,
    }
    # Side behaviours are drawn independently so that combinations of them
    # appear, rather than only the all-or-nothing cases the first set had.
    for bit in EFFECT_BITS:
        if rng.random() < 0.22:
            p["EFFECTS"] |= bit
    return p


def name_of(p):
    parts = [f"m{p['METHOD']}", f"s{p['SCOPE']}"]
    if p["LIMIT"]:
        parts.append(f"l{p['LIMIT']}")
    if p["FILTER"]:
        parts.append(f"f{p['FILTER']}")
    if p["TIMING"]:
        parts.append(f"t{p['TIMING']}")
    if p["RENAME_MODE"]:
        parts.append("rp")
    if p["BATCH"]:
        parts.append("b")
    if p["GENERATE"]:
        parts.append(f"g{p['GENERATE']}")
    if p["EFFECTS"]:
        parts.append(f"e{p['EFFECTS']}")
    if not p["FILES_ONLY"]:
        parts.append("nofile")
    return "v_" + "_".join(parts)


def describe(p):
    bits = [METHODS[p["METHOD"]], SCOPES[p["SCOPE"]]]
    if p["LIMIT"]:
        bits.append(f"{p['LIMIT']} files")
    if p["FILTER"]:
        bits.append(FILTERS[p["FILTER"]])
    if p["TIMING"]:
        bits.append(TIMINGS[p["TIMING"]])
    if p["RENAME_MODE"]:
        bits.append("name discarded")
    if p["BATCH"]:
        bits.append("read all first")
    if p["GENERATE"]:
        bits.append(f"{p['GENERATE']} generated files")
    if p["EFFECTS"]:
        bits.append("+" + ",".join(v for k, v in EFFECT_BITS.items()
                                    if p["EFFECTS"] & k))
    if not p["FILES_ONLY"]:
        bits = ["side behaviour only"] + bits[2:]
    return "; ".join(bits)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=400)
    parser.add_argument("--outdir", default="./variants")
    parser.add_argument("--source", default="hardneg_matrix.c")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--manifest-only", action="store_true",
                         help="Write the manifest without compiling, to see "
                              "what would be built")
    args = parser.parse_args()

    outdir = os.path.expanduser(args.outdir)
    os.makedirs(outdir, exist_ok=True)
    rng = random.Random(args.seed)

    # Drawing each parameter independently spreads the factors evenly but not
    # the quantity that matters. Volume is set by three of them at once --
    # the limit, whether targets are generated, and the file type filter --
    # so uniform draws pile up at the low end, and the decade around the
    # ransomware median ends up with a handful of variants in it.
    #
    # Accepting into path-count buckets instead fills the range. Factors stay
    # near-uniform because every bucket is reachable by many combinations of
    # them; what changes is that no decade is left empty.
    BUCKETS = [(1, 3), (4, 10), (11, 30), (31, 100),
               (101, 300), (301, 1000), (1001, 10**9)]
    per_bucket = max(1, args.count // len(BUCKETS))

    chosen, seen = [], set()
    filled = Counter()
    attempts = 0
    while len(chosen) < args.count and attempts < args.count * 400:
        attempts += 1
        p = draw(rng)
        if not coherent(p):
            continue
        n = name_of(p)
        if n in seen:
            continue
        v = expected_paths(p)
        b = next(f"{lo}-{hi}" for lo, hi in BUCKETS if lo <= v <= hi)
        # Once a bucket has its share, keep drawing for the others. The last
        # few slots go to whoever turns up, so a bucket the parameter space
        # can barely reach does not stall the whole draw.
        if filled[b] >= per_bucket and len(chosen) < args.count * 0.9:
            continue
        filled[b] += 1
        seen.add(n)
        chosen.append((n, p))

    # How many paths each variant will actually reach, which is the axis the
    # false positive curve is drawn against. Reported here because a set that
    # leaves a decade empty cannot show where the threshold is, and that is
    # not visible from the parameter counts alone.
    buckets = Counter()
    for _n, p in chosen:
        v = expected_paths(p)
        for lo, hi in [(1, 3), (4, 10), (11, 30), (31, 100), (101, 300),
                       (301, 1000), (1001, 10**9)]:
            if lo <= v <= hi:
                buckets[f"{lo}-{hi if hi < 10**9 else ''}"] += 1
                break

    print(f"drew {len(chosen)} distinct combinations from {attempts} attempts")
    print("\nexpected distinct paths touched, which is the axis the false")
    print("positive rate turned out to depend on:")
    for k in ["1-3", "4-10", "11-30", "31-100", "101-300", "301-1000", "1001-"]:
        n = buckets.get(k, 0)
        bar = "#" * int(n / max(1, max(buckets.values())) * 34)
        flag = "" if n >= 20 else "   <- thin"
        print(f"   {k:>10}  {n:>4}  {bar}{flag}")
    if len(chosen) < args.count:
        print(f"[note] the space of coherent combinations is smaller than "
              f"{args.count} under these constraints")

    manifest = os.path.join(outdir, "variant_manifest.csv")
    fields = ["variant", "METHOD", "SCOPE", "LIMIT", "FILTER", "TIMING",
              "RENAME_MODE", "BATCH", "GENERATE", "FILES_ONLY", "EFFECTS",
              "description"]
    with open(manifest, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for n, p in chosen:
            w.writerow({"variant": n + ".exe", "description": describe(p), **p})
    print(f"[saved] {manifest}")

    if args.manifest_only:
        for n, p in chosen[:10]:
            print(f"   {n:<34}{describe(p)}")
        print(f"   ... and {len(chosen) - 10} more")
        return

    src = args.source
    if not os.path.exists(src):
        print(f"[!] {src} not found; run this from the directory holding it")
        return

    built, failed = 0, []
    for i, (n, p) in enumerate(chosen, 1):
        flags = [f"-D{k}={v}" for k, v in p.items()]
        cmd = [CC, "-O2"] + flags + ["-o", os.path.join(outdir, n + ".exe"), src]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode:
            failed.append((n, r.stderr.strip().splitlines()[:1]))
        else:
            built += 1
        if i % 25 == 0 or i == len(chosen):
            print(f"\r   built {built}/{len(chosen)}", end="", flush=True)
    print()

    if failed:
        print(f"[!] {len(failed)} failed to compile")
        for n, err in failed[:5]:
            print(f"    {n}: {err}")
    print(f"\n{built} executables in {outdir}")
    print("\nEach is a distinct binary with its own hash, so the feature table")
    print("gets one row per variant rather than one row repeated.")


if __name__ == "__main__":
    main()
