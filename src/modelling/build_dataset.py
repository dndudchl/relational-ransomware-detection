#!/usr/bin/env python3
"""
build_dataset.py - Join the feature tables into one and settle the decisions
that have to be made before any model sees the data.

Four decisions, each of which changes what the numbers afterwards mean:

positives
    Only runs the sandbox recorded as reaching encryption. Of 3,455
    ransomware analyses, 1,569 executed without encrypting anything -- the
    sample checked for a debugger, waited for a key that never came, or was
    a build that needed an argument. Their behaviour is not distinguishable
    from benign software because, in the recording, they did not do
    anything. Training on them teaches the model that doing nothing is
    ransomware, and the false positive rate follows.

    The cost is that the trained model only recognises ransomware that runs.
    It is the honest trade, but it has to be stated: nothing here says
    anything about detecting a sample before it triggers.

hard negatives held out
    Programs that touch a folder's worth of files for a reason a person
    asked for. They are held out of training entirely and used only to
    measure, which is what lets the false positive rate on them be quoted:
    the model never saw them.

    They are not as busy as ransomware, and the earlier claim in this file
    that they were is withdrawn. Measured afterwards, the median hard
    negative makes 1,305 API calls against the ransomware's 70,788 -- by
    call count they sit with the benign programs. What separates them from
    the benign set is the number of distinct files touched, 95 against 3,
    and that turns out to be the whole story: two groups with almost the
    same call count are classified at 0.6% and 72%.

    Holding all of them out was the right call at sixty-eight. It is worth
    revisiting now the set runs to several hundred, since half of them could
    train and half could measure, which would answer whether training on
    active benign software fixes the false positive rate or whether the
    problem is deeper than the training data. That experiment is not in this
    file yet.

duplicates
    The same binary was analysed more than once, from retries and from both
    hosts collecting it independently. Left in, the same file lands in a
    training fold and a test fold and the score goes up for no reason. Where
    the repeats disagree on the verdict, the run that got furthest is kept:
    a sample that encrypted once can encrypt, and the run where it did not
    was a run where conditions were wrong.

family groups
    Families that are the same lineage under different names, and the
    capitalisation variants, are merged so a leave-one-family-out split does
    not train on Sodinokibi and test on REvil.

Usage
-----
  python3 build_dataset.py --features-dir ../../data \\
      --relational ../../data/rel_all.csv --out ../../data/modelling_simple.csv
"""

import os
import csv
import random
import argparse
from collections import Counter, defaultdict

# Verdicts ordered by how far the run got. When one binary was analysed more
# than once and the runs disagree, the furthest is the one that says what the
# sample is capable of.
VERDICT_RANK = {
    "TRUE_ENCRYPTION": 3,
    "WEAK_VICTIM_ACTIVITY": 2,
    "NO_VICTIM_ACTIVITY": 1,
    "FAILED": 0,
    "": 0,
}

# Names that refer to one lineage. Splitting on family is meant to ask whether
# the model generalises to an implementation it has not seen; two names for
# one codebase in different folds defeats that.
FAMILY_ALIASES = {
    "revil": "Sodinokibi",
    "sodin": "Sodinokibi",
    "alphv": "BlackCat",
    "blackcat": "BlackCat",
    "noberus": "BlackCat",
    "rook": "Babuk",
    "nightsky": "Babuk",
    "night sky": "Babuk",
    "blackmatter": "DarkSide",
    "darkside": "DarkSide",
    "conti": "Conti",
    "ryuk": "Conti",
    "trigona": "Trigona",
    "global": "GLOBAL",
    "interlock": "Interlock",
}


def canon_family(name):
    if not name:
        return ""
    return FAMILY_ALIASES.get(name.strip().lower(), name.strip())


def read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features-dir", default="../../data")
    parser.add_argument("--behaviour",
                         help="features_behaviour.csv: behaviour presence and "
                              "pairwise order, joined on sample_id the same "
                              "way as the relational table. Order columns are "
                              "blank where the pair never occurred, which the "
                              "model reads as missing rather than as a third "
                              "direction.")
    parser.add_argument("--relational", required=True)
    parser.add_argument("--out", default="../../data/modelling_simple.csv")
    parser.add_argument("--hardneg-names",
                         help="CSV of sample_id,filename for the hard "
                              "negatives. Without it the split cannot group "
                              "a variant with its siblings, because the "
                              "sample id is a task number and carries no "
                              "information about what the program was.")
    parser.add_argument("--hardneg-manifest", nargs="*", default=[],
                         help="Manifests carrying a category column, used to "
                              "decide which hard negatives may be trained on")
    parser.add_argument("--seed", type=int, default=0,
                         help="Seed for the training split, so the same "
                              "division can be reproduced")
    parser.add_argument("--simple-split", type=float, default=0.0,
                         help="Put this fraction of every negative -- the "
                              "benign runs that executed and all the hard "
                              "negatives alike -- into training, and hold the "
                              "rest back. Replaces the separate handling of "
                              "the two, and drops the benign runs that never "
                              "executed.")
    parser.add_argument("--hardneg-train-frac", type=float, default=0.0,
                         help="Fraction of the harmless hard negatives to put "
                              "into training. The rest, and everything that "
                              "destroyed anything, stay held out.")
    parser.add_argument("--exclude-failed-only", action="store_true",
                         help="Keep every ransomware run that executed, "
                              "encrypting or not, and drop only the ones that "
                              "never started. A middle position between the "
                              "two below.")
    parser.add_argument("--keep-nonencrypting", action="store_true",
                         help="Keep ransomware runs that executed without "
                              "encrypting, as positives. Off by default; see "
                              "the note at the top of this file.")
    args = parser.parse_args()

    d = args.features_dir
    ransom = read_csv(f"{d}/features.csv")
    benign = read_csv(f"{d}/features_benign.csv")
    hardneg = read_csv(f"{d}/features_hardneg.csv")
    print(f"read: ransomware {len(ransom)}, benign {len(benign)}, "
          f"hard negatives {len(hardneg)}")
    if not ransom:
        print("[!] no ransomware features found"); return

    rel = {r["task_id"]: r for r in read_csv(args.relational)}
    beh = ({r["task_id"]: r for r in read_csv(args.behaviour)}
           if args.behaviour else {})
    # n_calls is kept: the feature tables record total_calls only for rows
    # that were extracted with dynamic coverage, and the volume group and the
    # executed-only filter both need a call count that is present for every
    # row.
    rel_cols = [c for c in (next(iter(rel.values())).keys() if rel else [])
                if c != "task_id"]
    print(f"relational features: {len(rel_cols)} columns for {len(rel)} runs")
    beh_cols = [c for c in (next(iter(beh.values())).keys() if beh else [])
                if c != "task_id"]
    if beh_cols:
        print(f"behaviour features: {len(beh_cols)} columns for {len(beh)} runs")

    rows = []
    for src, table in (("ransomware", ransom), ("benign", benign),
                       ("hardneg", hardneg)):
        for r in table:
            r["source"] = src
            rows.append(r)

    # --- attach relational features ---
    missing_rel = 0
    for r in rows:
        extra = rel.get(r["sample_id"])
        if extra is None:
            missing_rel += 1
            for c in rel_cols:
                r[c] = ""
        else:
            for c in rel_cols:
                r[c] = extra.get(c, "")
    if missing_rel:
        print(f"[warn] {missing_rel} rows had no relational features")

    # A run with no behaviour row gets blanks rather than zeros: "no sequence
    # was extracted" is not the same as "the behaviour did not happen", and
    # the order columns already use blank for a pair that never occurred.
    if beh_cols:
        missing_beh = 0
        for r in rows:
            extra = beh.get(r["sample_id"])
            if extra is None:
                missing_beh += 1
                for c in beh_cols:
                    r[c] = ""
            else:
                for c in beh_cols:
                    r[c] = extra.get(c, "")
        if missing_beh:
            print(f"[warn] {missing_beh} rows had no behaviour features")

    # --- label ---
    kept, dropped_middle = [], 0
    for r in rows:
        if r["source"] == "ransomware":
            v = r.get("verdict", "")
            if v == "TRUE_ENCRYPTION":
                r["y"] = "1"
            elif args.keep_nonencrypting:
                r["y"] = "1"
            elif args.exclude_failed_only and v not in ("FAILED", ""):
                # It ran; it just did not encrypt anything the sandbox saw.
                # Whether that belongs in the positive class depends on what
                # the model is for: a detector meant to catch ransomware
                # before it triggers has to recognise these, and one meant to
                # recognise encryption cannot learn it from runs where none
                # happened.
                r["y"] = "1"
            else:
                dropped_middle += 1
                continue
        else:
            r["y"] = "0"
        kept.append(r)
    if dropped_middle:
        print(f"excluded {dropped_middle} ransomware runs that executed "
              f"without encrypting")

    # --- duplicates ---
    by_sha = defaultdict(list)
    for r in kept:
        sha = (r.get("sha256") or "").strip()
        by_sha[sha or f"__no_sha_{id(r)}"].append(r)

    deduped, removed, disagreed = [], 0, 0
    for sha, group in by_sha.items():
        if len(group) == 1:
            deduped.append(group[0]); continue
        if len({g.get("verdict", "") for g in group}) > 1:
            disagreed += 1
        best = max(group, key=lambda g: (VERDICT_RANK.get(g.get("verdict", ""), 0),
                                          int(g.get("n_calls") or 0)))
        deduped.append(best)
        removed += len(group) - 1
    print(f"removed {removed} duplicate analyses of the same binary "
          f"({disagreed} of the duplicated binaries disagreed on the verdict)")

    # --- which hard negatives may be trained on ---
    #
    # Holding all of them out is what lets the false positive rate on them be
    # quoted, and with sixty-eight it was the only option. At several hundred
    # a split becomes possible and answers a question the held-out
    # arrangement cannot: does showing the model active benign software fix
    # the false positive rate, or is the problem deeper than the training
    # data?
    #
    # Only the harmless ones are eligible. A variant that read a folder,
    # wrote replacements and deleted the originals cannot be labelled benign
    # for training without contradicting the positives, which do exactly
    # that. Those stay in the measurement set whatever the fraction.
    #
    # The split is by variant kind rather than at random. Splitting randomly
    # would put shape C at fifty files in training and shape C at two hundred
    # in the holdout, which are the same program at two sizes -- the model
    # would be tested on what it had already seen. Splitting on the kind asks
    # whether training on some kinds of active software generalises to
    # others, which is the question worth asking.
    # What each hard negative actually was. The sample id is the sandbox task
    # number, which says nothing about the program, so without this the split
    # is random and a variant can be trained on at one size and tested at
    # another -- which is testing on what was already seen.
    name_of = {}
    if args.hardneg_names:
        for r in read_csv(os.path.expanduser(args.hardneg_names)):
            if r.get("sample_id") and r.get("filename"):
                name_of[r["sample_id"]] = r["filename"]
        print(f"hard negative names: {len(name_of)} resolved")

    category = {}
    for path in args.hardneg_manifest:
        for r in read_csv(os.path.expanduser(path)):
            name = os.path.splitext(r.get("filename", ""))[0]
            if name and r.get("category"):
                category[name] = r["category"]
    if args.hardneg_manifest:
        print(f"hard negative categories: {len(category)} described")

    def kind_of(sample_id):
        """
        A key that groups a variant with its siblings.

        Siblings are the same program at another size or another repeat:
        xc_D_l200_rand_r3 and xc_D_l1000_rand_r0 do the same thing to
        different numbers of files. Training on one and testing on the other
        measures nothing, so the volume and the repeat are dropped from the
        key and what remains -- the shape, the toolchain, the traversal
        order -- decides the group.
        """
        base = name_of.get(sample_id, sample_id)
        base = os.path.splitext(base)[0]
        parts = [p for p in base.split("_") if p]
        keep = [p for p in parts
                if not (len(p) > 1 and p[0] in "lr" and p[1:].isdigit())]
        return "_".join(keep[:3]) if keep else base

    n_train = 0
    if args.simple_split > 0:
        # One negative class, split once.
        #
        # The arrangement this replaces treated the two kinds of negative
        # differently: the benign corpus was divided across the folds and the
        # hard negatives were held out entirely. That made sense when there
        # were sixty-eight of the latter and they were the only way to
        # measure anything. It does not now.
        #
        # It also left the classes badly matched. Of 1,563 benign programs,
        # 1,262 never executed, and a run with no behaviour to describe adds
        # nothing to a model built on behaviour -- measured directly, removing
        # them changes the false positive rate by 0.012. What remains, 301
        # benign runs and 1,513 hard negatives, is 1,814 against 1,849
        # positives, which needs no special handling at all.
        #
        # The split is by kind rather than at random, for the same reason as
        # before: a variant at fifty files and the same variant at a thousand
        # are one program, and putting one in training and the other in the
        # test set measures nothing.
        for r in deduped:
            r["split"] = ""
        negatives = []
        for r in deduped:
            if r["source"] == "hardneg":
                negatives.append(r)
            elif r["source"] == "benign":
                if r.get("coverage") == "full":
                    negatives.append(r)
                else:
                    r["_drop"] = True     # never executed
        dropped_inert = sum(1 for r in deduped if r.get("_drop"))
        deduped = [r for r in deduped if not r.get("_drop")]

        # The two kinds of negative are split differently, because "kind"
        # means something for one and nothing for the other.
        #
        # A hard negative has siblings: the same variant at another size, or
        # another repeat. Those have to stay on the same side, or the model
        # is tested on a program it trained on at a different volume.
        #
        # A benign program has none. Its identifier is a hash and every one
        # is its own kind, so splitting them by kind is splitting them at
        # random with extra steps -- and worse, it lets 700 benign
        # single-member kinds crowd out the hard negatives when the quota is
        # counted in kinds rather than rows.
        hard = [r for r in negatives if r["source"] == "hardneg"]
        ben = [r for r in negatives if r["source"] == "benign"]

        # Shuffled, not sorted.
        #
        # Taking the first eighty percent of a sorted list of kinds sorts by
        # name, and the names carry meaning: everything from the designed
        # grid begins with x, so an alphabetical cut put all 920 of those on
        # one side and none of them in training. The model then never saw a
        # compiled variant, which is not the split that was asked for.
        #
        # A fixed seed keeps it repeatable.
        hkinds = sorted({kind_of(r["sample_id"]) for r in hard})
        random.Random(args.seed).shuffle(hkinds)
        train_kinds = set(hkinds[:int(len(hkinds) * args.simple_split)])
        for r in hard:
            r["split"] = ("train" if kind_of(r["sample_id"]) in train_kinds
                          else "holdout")

        ben.sort(key=lambda r: r["sample_id"])
        random.Random(args.seed + 1).shuffle(ben)
        cut_b = int(len(ben) * args.simple_split)
        for i, r in enumerate(ben):
            r["split"] = "train" if i < cut_b else "holdout"

        n_train = sum(1 for r in negatives if r.get("split") == "train")
        n_hold = sum(1 for r in negatives if r.get("split") == "holdout")
        print(f"   hard negatives {sum(1 for r in hard if r['split']=='train')}"
              f" / {sum(1 for r in hard if r['split']=='holdout')}"
              f" from {len(train_kinds)} of {len(hkinds)} kinds")
        print(f"   benign         {cut_b} / {len(ben)-cut_b}")
        print(f"simple split: dropped {dropped_inert} benign runs that never "
              f"executed")
        print(f"   negatives {n_train} training / {n_hold} held out")

    elif args.hardneg_train_frac > 0:
        harmless = []
        for r in deduped:
            if r["source"] != "hardneg":
                continue
            base = os.path.splitext(name_of.get(r["sample_id"],
                                                  r["sample_id"]))[0]
            cat = category.get(base, "")
            if not cat:
                # No manifest entry: fall back to whether the run destroyed
                # anything the sandbox recorded. Conservative -- anything
                # uncertain stays out of training.
                try:
                    destroyed = int(float(r.get("n_delete") or 0)) > 0
                except ValueError:
                    destroyed = True
                cat = "destroys" if destroyed else "harmless"
            r["_category"] = cat
            if cat == "harmless":
                harmless.append(r)

        kinds = sorted({kind_of(r["sample_id"]) for r in harmless})
        cut = int(len(kinds) * args.hardneg_train_frac)
        train_kinds = set(kinds[:cut])
        for r in deduped:
            if r.get("_category") == "harmless" and kind_of(r["sample_id"]) in train_kinds:
                r["split"] = "train"
                n_train += 1
            elif r["source"] == "hardneg":
                r["split"] = "holdout"
            else:
                r["split"] = ""
        print(f"hard negatives: {n_train} of {len(harmless)} harmless variants "
              f"put into training, from {len(train_kinds)} of {len(kinds)} kinds")
    else:
        for r in deduped:
            r["split"] = "holdout" if r["source"] == "hardneg" else ""

    # --- family ---
    for r in deduped:
        r["family_group"] = canon_family(r.get("family", ""))

    pos = [r for r in deduped if r["y"] == "1"]
    fams = Counter(r["family_group"] or "(unknown)" for r in pos)
    big = [f for f, n in fams.items() if n >= 20 and f != "(unknown)"]
    print(f"\npositives {len(pos)}, families {len(fams)}, "
          f"with 20 or more members {len(big)}")
    for f, n in fams.most_common(12):
        print(f"   {f:<20}{n:>5}")

    counts = Counter((r["source"], r["y"]) for r in deduped)
    print(f"\nfinal table {len(deduped)} rows")
    for k in sorted(counts):
        print(f"   {k[0]:<12} y={k[1]}  {counts[k]:>5}")

    lead = ["sample_id", "sha256", "y", "source", "family_group", "coverage",
            "verdict", "label", "split"]
    # Union across rows rather than the first row alone: the three sources
    # were extracted separately and a column present in one may be absent
    # from another, and the relational columns were attached afterwards.
    seen = list(lead)
    for r in deduped:
        for c in r:
            if c not in seen:
                seen.append(c)
    fields = seen
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in sorted(deduped, key=lambda x: (x["source"], x["sample_id"])):
            w.writerow({k: r.get(k, "") for k in fields})
    print(f"\n[saved] {args.out}")


if __name__ == "__main__":
    main()
