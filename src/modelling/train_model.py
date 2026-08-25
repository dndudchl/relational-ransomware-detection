#!/usr/bin/env python3
"""
train_model.py - Train, and take the feature groups apart to see which of
them the performance actually rests on.

The number that is easy to produce
----------------------------------
Train on everything, test on a random split, report the AUC. It will be
high. Four fifths of the benign set never executed, so those rows are zero
on every dynamic feature and any count separates them. That number measures
the sandbox's ability to notice that a program ran.

So three things are done differently here.

Circular features are removed outright
    The positive label is the verdict, and the verdict is computed from
    decoy destruction, append-renames, ransom notes and shared extensions.
    A model given those features is being told the answer. They are dropped
    before anything else happens.

The split is by family, not at random
    Twenty-one families have twenty or more encrypting runs. Each becomes a
    fold: train on the other twenty, test on that one. This asks whether the
    model recognises ransomware it has not seen an example of, which is the
    only question a detector faces in deployment. Random splits put LockBit
    in both halves and answer nothing.

Three false positive rates are reported, not one
    On the whole benign set, on the benign runs that actually executed, and
    on the hard negatives -- programs that open a folder's worth of files
    for a reason a person asked for. The three differ by a lot, and the
    third is the one worth quoting.

    Not because those programs are as busy as ransomware; they are not. By
    call count they sit with the benign set, 1,305 against 1,182 at the
    median, while the ransomware median is 70,788. What makes them the
    useful comparison is that they touch 95 distinct files where the benign
    runs touch 3, and that alone moves the classification from 0.6% to 72%.

Feature groups
--------------
Cumulative, so each line shows what the group above it added:

    static      the import table, available without running anything
    volume      how much happened: calls, paths, bytes, distinct APIs
    sequence    the shape of the API stream and the rhythm of the file
                operations, independent of which files
    relation    how reads relate to writes: which paths coincide, how many
                bytes came back out, whether the walk swept a tree or
                jumped about, and how long each file waited between being
                read and written
    indicator   counts of the particular things ransomware does -- deleting
                shadow copies, disabling recovery, killing processes. Kept
                out of the relational group because they are counts of
                actions rather than relations between events, and mixing
                them made the ablation unreadable: a drop in the false
                positive rate could have come from either and the two
                support different claims
    destruction features counting what was destroyed -- reported separately
                because they overlap with the verdict's own inputs, even
                though none of them restates one

Usage
-----
  python3 train_model.py --data ../../data/modelling_simple.csv
"""

import os
import csv
import math
import argparse
from collections import Counter, defaultdict

# Computed by the verdict logic itself. Including any of these hands the
# model the label for the positive class.
CIRCULAR = {
    "destroyed_decoy_files", "append_renames", "distinct_rename_suffixes",
    "shared_extension_renames", "ransom_note_dirs", "ransom_note_explicit",
    "ransom_note_candidates", "ransom_note_name", "corroborating_axes",
    "destructive_events", "destructive_extension_variety",
    "destructive_chain_windows", "replacement_extension",
    "extension_replacements", "distinct_target_extensions",
    "verdict", "reason", "malscore",
}

# Bookkeeping, not behaviour.
NON_FEATURES = {
    "sample_id", "sha256", "y", "source", "family_group", "family", "label",
    "coverage", "cape_family", "original_filename", "added_date", "notes",
    "source_dataset", "task_id", "_error",
}

GROUPS_SPEC = {
    "static": [
        "total_imports", "indicative_category_count", "imp_crypto",
        "imp_file_unlock", "imp_network_spread", "imp_process_control",
        "imp_persistence", "imp_discovery", "imp_anti_analysis",
        "crypto_imported_not_called", "crypto_called_not_imported",
        "static_dynamic_agreement", "n_sections", "entropy_mean",
    ],
    "volume": [
        "n_calls", "n_paths", "n_read", "n_write", "n_copy", "n_execute",
        "bytes_read", "bytes_written",
        "n_registry_writes", "n_registry_deletes",
        "n_services_created", "n_services_started", "n_executed_commands",
        "active_windows", "other_windows", "write_only_nondestructive_windows",
        "ext_variety_all", "api_distinct", 
        "chain_distinct_shapes", "n_stages_all",
        "n_stages_clean", "stage_span_sec",
    ],
    "sequence": [
        "api_branching", "api_bigram_entropy", "api_top_bigram_share",
        "api_compress_ratio", "cat_switch_rate",
        "fs_to_crypto", "crypto_to_fs", 
        "n_crypto_calls", "crypto_buffer_entropy_mean",
        # How evenly spaced the file operations are. A loop encrypting a
        # thousand files keeps time, and the gaps between operations cluster
        # around the cost of one iteration; software reacting to a person, or
        # to what it finds, scatters across orders of magnitude. These are
        # the only features here that describe the intervals rather than the
        # order, and they cost nothing to compute from timestamps already in
        # the report.
        "gap_cv", "gap_median_ms", "gap_below_median", "burst_share",
    ],
    "relation": [
        "rw_jaccard", "write_not_read", "read_not_write", "rw_size_ratio",
        # Bytes rather than files. Encryption returns a ciphertext the size
        # of its plaintext; compression returns a third of it. Everything
        # else in this table counts files, and on files an archiver deleting
        # its inputs and a family encrypting them are the same program.
        "byte_io_ratio", "mean_read_size", "mean_write_size",
        "write_size_uniformity",
        "chain_read_only", "chain_write_only", "chain_read_write",
        "chain_top_shape_share", "ext_top_share",
        "sel_rate_document", "sel_rate_media", "sel_rate_executable",
        "sel_rate_spread", "sel_system_touch_share", "sel_system_spared",

        # Whether the file accesses walk a tree or pick things out of it.
        # Two runs touching the same files the same number of times differ
        # here if one swept and the other jumped about, so these are the
        # features the sweep/shuffled pair of variants exists to test -- and
        # the only ones in the set that can separate that pair, since every
        # count is identical across it.
        "walk_same_dir_rate", "walk_dir_switches", "walk_revisit_rate",
        "walk_run_length", "walk_distinct_dirs",
        # How long a file waits between being read and written. Every other
        # timing feature measures gaps between consecutive events whoever
        # they belonged to; this pairs the two events on the same file, which
        # is what separates a loop from a person editing a document.
        "rw_latency_median_ms", "rw_latency_cv", "rw_latency_under_100ms",
        "n_read_write_pairs",
    ],
    # Which category of call follows which, and how often the two were more
    # than a millisecond apart.
    #
    # Its own group because there are two hundred of them and they would
    # otherwise swamp the fourteen features already in "sequence", making the
    # ablation step unreadable: a change when sequence is added could be the
    # transition matrix or could be everything else, and the two say
    # different things.
    #
    # The vocabulary is CAPE's own call categories rather than one derived
    # from what ransomware does, which is what keeps these out of the
    # circular set. Most are near zero for any given run; the model is left
    # to find which matter.
    "transition": [
        f"{p}_{a[:4]}_{b[:4]}"
        for p in ("tr", "trgap")
        for a in ("filesystem", "registry", "process", "crypto", "network",
                  "system", "threading", "synchronization", "windows", "misc")
        for b in ("filesystem", "registry", "process", "crypto", "network",
                  "system", "threading", "synchronization", "windows", "misc")
    ],

    # Actions specific to ransomware, kept apart from the relational group.
    #
    # These were in "relation" because they are ransomware-shaped, but they
    # are counts of particular commands rather than relations between events,
    # and mixing them made the ablation unreadable: a four-point drop in the
    # false positive rate when the relational group is added could have come
    # from rw_jaccard or from n_shadow_delete, and those support completely
    # different claims. Separated, each group answers for itself.
    "indicator": [
        "n_shadow_delete", "n_recovery_disable", "n_service_stop",
        "n_process_kill", "n_log_clear", "n_prep_categories",
        "stage_ground_clearing", "stage_has_enumerate", "stage_has_wallpaper",
        "stage_has_persistence",
    ],
    # Behaviour presence and pairwise order, from behaviour_sequence.py.
    # These are listed by prefix rather than by name because the order
    # columns are generated from whichever pairs occur in the data, and
    # hard-coding 187 names here would go stale the moment the vocabulary
    # or the corpus changes.
    "behaviour": "PREFIX:has_",
    "order": "PREFIX:ord_",
    "destruction": [
        "chain_read_destroy", "chain_write_destroy", "chain_full",
        "read_then_destroy", "write_then_destroy",
        "sel_destroyed_doc_share", "sel_destroyed_exe_share",
        "sel_doc_minus_exe", "n_move", "n_delete",
        "move_to_write_ratio", "delete_to_write_ratio",
    ],
}

# The order matters and is not arbitrary. Each group is added after the ones
# that could explain its effect away, so that whatever it adds is what it
# adds on its own: volume after static, relation after volume and sequence,
# and the ransomware-specific indicators last but one -- if they help only
# once everything else is present, they are not carrying the result.
CUMULATIVE = [
    # The transition matrix is left out: on the corrected negative set it
    # moved the false positive rate from 0.030 to 0.074, and its 200 columns
    # were beaten throughout by relation's 28. Behaviour and order come last
    # so that the step from one to the other isolates what the *order* of
    # two behaviours adds once their presence is already known.
    ("static", ["static"]),
    ("+ volume", ["static", "volume"]),
    ("+ sequence", ["static", "volume", "sequence"]),
    ("+ relation", ["static", "volume", "sequence", "relation"]),
    ("+ indicator", ["static", "volume", "sequence", "relation", "indicator"]),
    ("+ destruction", ["static", "volume", "sequence", "relation",
                       "indicator", "destruction"]),
    ("+ behaviour", ["static", "volume", "sequence", "relation",
                     "indicator", "destruction", "behaviour"]),
    ("+ order", ["static", "volume", "sequence", "relation",
                 "indicator", "destruction", "behaviour", "order"]),
]

# ---------------------------------------------------------------- A / S axis
#
# The six groups above are organised by what a feature describes. The two
# below cut the same columns a different way: does the feature depend on the
# ORDER in which two events happened, or only on what happened and how much.
#
# This exists because the ablation over the six groups cannot answer the
# research question. Roughly a third of the original columns already encode
# order -- rw_latency_* is the delay between a read and a write on one file,
# chain_* is the shape of one file's event sequence, the api bigram features
# are adjacency in the call stream -- so adding an explicit order group to
# them measures order against order and finds little. Separating the two
# makes "individual" mean individual.
#
# Where a feature is arguable it is placed in INDIVIDUAL, which is the
# conservative choice: it strengthens the baseline and understates what
# sequence adds, so the comparison cannot flatter the hypothesis.
SEQUENCE_COLS = [
    # adjacency in the API stream
    "api_branching", "api_bigram_entropy", "api_top_bigram_share",
    "api_compress_ratio", "cat_switch_rate",
    # one category of call following another
    "fs_to_crypto", "crypto_to_fs",
    # spacing between consecutive events
    "gap_cv", "gap_median_ms", "gap_below_median", "burst_share",
    # a read and a write on the same file, and how far apart
    "rw_latency_median_ms", "rw_latency_cv", "rw_latency_under_100ms",
    # the shape of one file's event sequence
    "chain_read_only", "chain_write_only", "chain_read_write",
    "chain_read_destroy", "chain_write_destroy", "chain_full",
    "read_then_destroy", "write_then_destroy",
    # the order in which directories were visited
    "walk_same_dir_rate", "walk_dir_switches", "walk_revisit_rate",
    "walk_run_length",
    # a stage reached before another stage
    "stage_ground_clearing",
]


# Also run each group on its own, which shows what it carries unaided.
ALONE = ["static", "volume", "sequence", "relation", "indicator",
         "destruction", "behaviour", "order"]


def to_float(v):
    if v is None or v == "":
        return float("nan")
    try:
        return float(v)
    except (TypeError, ValueError):
        return float("nan")


def auc_score(y_true, scores):
    pairs = sorted(zip(scores, y_true))
    n_pos = sum(y_true)
    n_neg = len(y_true) - n_pos
    if n_pos == 0 or n_neg == 0:
        return float("nan")
    ranks, i = {}, 0
    while i < len(pairs):
        j = i
        while j + 1 < len(pairs) and pairs[j + 1][0] == pairs[i][0]:
            j += 1
        r = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[k] = r
        i = j + 1
    rp = sum(ranks[i] for i, (_s, y) in enumerate(pairs) if y == 1)
    return (rp - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", required=True)
    parser.add_argument("--min-family", type=int, default=20,
                         help="A family needs this many encrypting runs to be "
                              "its own fold")
    parser.add_argument("--min-calls", type=int, default=500)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--volume-shift", type=float, default=0.0,
                         help="Train only on negatives below this many files "
                              "and measure only on those above it. Volume "
                              "features are then trained on a range they will "
                              "not be tested in; relational ones are not, "
                              "because a relation does not move with scale.")
    parser.add_argument("--volume-band", type=float, nargs=2, default=None,
                         metavar=("LOW", "HIGH"),
                         help="Keep only rows opening between LOW and HIGH "
                              "files, so volume is near-constant and cannot "
                              "separate anything")
    parser.add_argument("--match-volume", action="store_true",
                         help="Subsample the training set so the two classes "
                              "have the same distribution of file counts, "
                              "which removes volume as something the model "
                              "can use rather than merely discouraging it")
    parser.add_argument("--match-bins", type=int, default=8,
                         help="How many bands to match within")
    parser.add_argument("--two-stage", action="store_true",
                         help="Train and evaluate only on runs that opened at "
                              "least --stage1-paths files, as a second stage "
                              "behind a filter that keeps those")
    parser.add_argument("--stage1-paths", type=float, default=50,
                         help="Files a run must open to reach the second "
                              "stage. Fifty is where the false positive rate "
                              "on the hard negatives crosses one half.")
    parser.add_argument("--jobs", type=int, default=4,
                         help="How many leave-one-out retrainings to run at "
                              "once. Each is independent; the default suits a "
                              "machine with eight cores.")
    parser.add_argument("--executed-only", action="store_true",
                         help="Drop rows the sandbox never saw run. Four fifths "
                              "of the benign set is inert, and a model given it "
                              "reaches a perfect score by learning to tell a "
                              "program that ran from one that did not. This "
                              "restricts both classes to runs with recorded "
                              "behaviour, which is a far harder and far more "
                              "meaningful comparison.")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", default="/tmp/ablation.csv")
    parser.add_argument("--importance", action="store_true",
                         help="Rank individual features three ways: by the gain "
                              "the trees record, by how much shuffling the column "
                              "costs the AUC, and by how much shuffling it changes "
                              "the hard negative false positive rate. The third is "
                              "the one that says which feature is responsible for "
                              "calling active software ransomware.")
    parser.add_argument("--leave-one-out", action="store_true",
                         help="Retrain without each feature in turn. Expensive, and "
                              "usually uninformative here: the features are heavily "
                              "correlated, so removing one leaves the others to "
                              "cover for it and nothing moves. Permutation "
                              "importance measures the same thing without that "
                              "problem, and without retraining.")
    parser.add_argument("--importance-out", default="/tmp/importance.csv")
    parser.add_argument("--cv-rotation", type=int, default=0,
                         help="Which rotation to run, 0 to K-1.")
    parser.add_argument("--negative-cv", type=int, default=0,
                         help="Rotate the negatives through K folds rather "
                              "than holding one fixed fifth out. Under the "
                              "simple split only a fifth of the negatives is "
                              "ever measured, so a rate of 0.005 rests on one "
                              "flagged program in about two hundred and "
                              "cannot be told apart from 0.010. With K "
                              "rotations every negative is measured once, by "
                              "a model that did not train on it, and the "
                              "denominator becomes the whole set.")
    parser.add_argument("--pos-out",
                         help="Per-positive detection, one column per feature "
                              "group. Lets the recall be read separately for "
                              "runs that reached encryption and runs that did "
                              "not, which is the check on whether the model "
                              "learnt the malware or only the encryption.")
    parser.add_argument("--hard-out-groups",
                         help="Per-variant flag rate under every feature set, "
                              "one column per group. The single-model file "
                              "says which programs the detector confuses with "
                              "ransomware; this one says which feature sets "
                              "are doing the confusing, which is the question "
                              "an ablation is actually asking.")
    parser.add_argument("--hard-out", default="/tmp/hardneg_scores.csv",
                         help="Per-variant record of how often each hard "
                              "negative was flagged, which is what turns "
                              "'44 of 68' into an account of why.")
    args = parser.parse_args()

    import numpy as np
    from xgboost import XGBClassifier

    rows = []
    with open(args.data, newline="") as f:
        for r in csv.DictReader(f):
            rows.append(r)
    print(f"{len(rows)} rows")
    if args.executed_only:
        before = len(rows)
        rows = [r for r in rows if r.get("coverage") == "full"]
        print(f"executed only: kept {len(rows)} of {before}")

    all_cols = list(rows[0].keys())
    def expand_group(spec, columns):
        """
        A group is either an explicit list of column names or a prefix.

        The behaviour and order groups are generated: which order columns
        exist depends on which behaviour pairs occur in the corpus, so
        naming them here would go stale. Everything else stays an explicit
        list, because a prefix would silently absorb any new column that
        happened to start with the same letters.
        """
        if isinstance(spec, str) and spec.startswith("PREFIX:"):
            pre = spec[len("PREFIX:"):]
            return sorted(c for c in columns if c.startswith(pre))
        return list(spec)

    GROUPS = {g: expand_group(spec, all_cols)
              for g, spec in GROUPS_SPEC.items()}

    # The A/S axis is derived from the six groups rather than listed twice,
    # so a column can never be in one axis and missing from the other.
    _named = [c for g, cols in GROUPS.items() if g != "transition"
              for c in cols]
    seq_cols = [c for c in _named
                if c in SEQUENCE_COLS or c.startswith("ord_")]
    ind_cols = [c for c in _named if c not in set(seq_cols)]
    GROUPS["sequence_axis"] = seq_cols
    GROUPS["individual_axis"] = ind_cols

    # Order is not one thing. The same run can be described as a sequence of
    # API calls, of events on one file, or of behaviours, and the three are
    # different claims. The 200-column API transition matrix failed and the
    # behaviour pairs did not, which is a fact about the level of
    # abstraction rather than about order as such -- so the levels are
    # measured separately rather than pooled into one "sequence" group.
    ORDER_API = ["api_branching", "api_bigram_entropy", "api_top_bigram_share",
                 "api_compress_ratio", "cat_switch_rate", "fs_to_crypto",
                 "crypto_to_fs", "gap_cv", "gap_median_ms",
                 "gap_below_median", "burst_share"]
    ORDER_FILE = ["rw_latency_median_ms", "rw_latency_cv",
                  "rw_latency_under_100ms", "chain_read_only",
                  "chain_write_only", "chain_read_write", "chain_read_destroy",
                  "chain_write_destroy", "chain_full", "read_then_destroy",
                  "write_then_destroy", "walk_same_dir_rate",
                  "walk_dir_switches", "walk_revisit_rate", "walk_run_length",
                  "stage_ground_clearing"]
    # A_reduced: the individual features with the aggregate ratios and the
    # read-write set relations removed. Those are where an aggregate quietly
    # encodes a sequence -- n_read_write_pairs says a file was both read and
    # written, byte_io_ratio says how much came back out against what went
    # in -- so leaving them in means the baseline already contains what the
    # sequence group is meant to add.
    A_REDUCED_EXCLUDE = [
        "rw_jaccard", "write_not_read", "read_not_write", "n_read_write_pairs",
        "rw_size_ratio", "byte_io_ratio", "mean_read_size", "mean_write_size",
        "write_size_uniformity", "chain_top_shape_share", "ext_top_share",
        "sel_rate_document", "sel_rate_media", "sel_rate_executable",
        "sel_rate_spread", "sel_system_touch_share", "sel_system_spared",
        "sel_destroyed_doc_share", "sel_destroyed_exe_share",
        "sel_doc_minus_exe", "move_to_write_ratio", "delete_to_write_ratio",
        "crypto_buffer_entropy_mean",
    ]
    GROUPS["a_reduced"] = [c for c in ind_cols if c not in A_REDUCED_EXCLUDE]

    # The individual features split by what kind of quantity they are, which
    # is a different cut from the six descriptive groups: relation there
    # mixes set overlap with read-to-write latency, and this separates them.
    A_RELATION = ["rw_jaccard", "write_not_read", "read_not_write",
                  "n_read_write_pairs"]
    A_AGGREGATE = [c for c in A_REDUCED_EXCLUDE if c not in A_RELATION]
    A_STATIC = ["total_imports", "indicative_category_count", "imp_crypto",
                "imp_file_unlock", "imp_network_spread", "imp_anti_analysis",
                "crypto_imported_not_called", "crypto_called_not_imported",
                "static_dynamic_agreement"]
    A_PRESENCE = [c for c in ind_cols
                  if c.startswith("has_") or c.startswith("stage_has_")]
    _assigned = set(A_RELATION + A_AGGREGATE + A_STATIC + A_PRESENCE)
    # Experiment 1: A is the twenty behaviour-presence columns alone, which
    # are the MITRE-derived ransomware behaviours. S1 is the relation group,
    # S2 the pairwise order. A narrow A avoids the situation where one strong
    # column in a wide baseline decides everything.
    GROUPS["a_behaviour"] = [c for c in _named if c.startswith("has_")]
    GROUPS["s1_relation"] = [c for c in GROUPS.get("relation", [])]
    GROUPS["s2_order"] = [c for c in _named if c.startswith("ord_")]

    # Experiment 2: a baseline with the ransomware-specific columns removed.
    #
    # Selection is by documented design intent, not by measured overlap
    # between the classes. Choosing columns because ransomware and benign
    # look alike on them would be choosing on the label, and would bias the
    # baseline downwards by construction; excluding columns that exist
    # *because* someone knew what ransomware does is a statement about where
    # the feature came from, which the label plays no part in.
    A_GENERIC_EXCLUDE = set(
        [c for c in _named if c.startswith("imp_")] +
        ["total_imports", "indicative_category_count",
         "crypto_imported_not_called", "crypto_called_not_imported",
         "static_dynamic_agreement",
         "n_shadow_delete", "n_recovery_disable", "n_service_stop",
         "n_process_kill", "n_log_clear", "n_prep_categories",
         "stage_ground_clearing", "stage_has_enumerate",
         "stage_has_wallpaper", "stage_has_persistence",
         "has_shadow_delete", "has_recovery_disable", "has_backup_delete",
         "has_firewall_disable", "has_eventlog_clear", "has_ransom_note",
         "has_wallpaper_set", "has_crypto_api", "has_self_copy",
         "sel_destroyed_doc_share", "sel_destroyed_exe_share",
         "sel_doc_minus_exe", "n_crypto_calls",
         "crypto_buffer_entropy_mean"])
    GROUPS["a_generic"] = [c for c in ind_cols if c not in A_GENERIC_EXCLUDE]
    GROUPS["a_relation"] = [c for c in ind_cols if c in A_RELATION]
    GROUPS["a_aggregate"] = [c for c in ind_cols if c in A_AGGREGATE]
    GROUPS["a_static"] = [c for c in ind_cols if c in A_STATIC]
    GROUPS["a_presence"] = [c for c in ind_cols if c in A_PRESENCE]
    GROUPS["a_count"] = [c for c in ind_cols if c not in _assigned]
    GROUPS["order_api"] = [c for c in _named if c in ORDER_API]
    GROUPS["order_file"] = [c for c in _named if c in ORDER_FILE]
    GROUPS["order_behaviour"] = [c for c in _named if c.startswith("ord_")]
    grouped = {c for cols in GROUPS.values() for c in cols}
    known = grouped | CIRCULAR | NON_FEATURES
    unassigned = [c for c in all_cols if c not in known]
    if unassigned:
        print(f"[note] {len(unassigned)} columns are in no group and are unused:")
        print("       " + ", ".join(unassigned[:18])
              + (" ..." if len(unassigned) > 18 else ""))

    present = {g: [c for c in cols if c in all_cols] for g, cols in GROUPS.items()}
    print()
    for g, cols in present.items():
        print(f"   {g:<12}{len(cols):>3} features")

    y = np.array([int(r["y"]) for r in rows])
    source = [r["source"] for r in rows]
    family = [r["family_group"] or "(unknown)" for r in rows]
    calls = np.array([to_float(r.get("n_calls") or r.get("total_calls"))
                      for r in rows])
    # coverage is set during extraction from whether the sandbox saw the
    # sample run, and is present on every row, so it is the reliable way to
    # ask that question even when a call count is missing.
    executed = np.array([r.get("coverage") == "full" for r in rows])

    # Folds. Each family with enough members is held out in turn; the
    # negatives carry no family, so each is assigned to one fold at random and
    # tested exactly once. The hard negatives sit in the test set of every
    # fold, since there are too few to divide and they are never trained on.
    pos_fams = Counter(family[i] for i in range(len(rows))
                       if y[i] == 1 and family[i] != "(unknown)")
    fold_families = sorted(f for f, n in pos_fams.items() if n >= args.min_family)
    if not fold_families:
        print("[!] no family has enough members for a fold"); return
    print(f"\n{len(fold_families)} folds: " + ", ".join(fold_families))

    rng = np.random.default_rng(args.seed)
    benign_idx = [i for i in range(len(rows)) if source[i] == "benign"]
    # A hard negative marked "train" by build_dataset joins the negatives the
    # model learns from; everything else stays out and is only measured. The
    # false positive rate is always reported on the held-out ones, so it
    # remains a rate on software the model has not seen however the split
    # falls.
    # When build_dataset used --simple-split, every negative carries a
    # split and the benign corpus is no longer divided across the folds:
    # the held-out negatives are the test set, whichever kind they are.
    # Filled in below, once hard_idx is settled: under the simple split it
    # also holds the benign runs that were held out.
    hard_fold = {}

    simple = any(rows[i].get("split") in ("train", "holdout")
                 and source[i] == "benign" for i in range(len(rows)))

    hard_all = [i for i in range(len(rows)) if source[i] == "hardneg"]
    hard_train = [i for i in hard_all if rows[i].get("split") == "train"]
    hard_idx = [i for i in hard_all if i not in set(hard_train)]

    if args.negative_cv > 1:
        # Every negative takes a turn in the held-out part. Rotation r holds
        # out the negatives whose position in a fixed shuffle is congruent to
        # r modulo K and trains on the rest; the caller loops over r and
        # pools the results, so each negative is scored exactly once by a
        # model that never saw it.
        K, r = args.negative_cv, args.cv_rotation
        neg_all = sorted(set(benign_idx) | set(hard_all))
        order = np.random.default_rng(args.seed).permutation(len(neg_all))
        for pos, i in enumerate(neg_all):
            rows[i]["split"] = "holdout" if order[pos] % K == r else "train"
        hard_train = [i for i in hard_all if rows[i]["split"] == "train"]
        hard_idx = [i for i in hard_all if rows[i]["split"] == "holdout"]
        print(f"negative CV: rotation {r} of {K}")

    if simple:
        # One negative class."" The benign runs that executed and the hard
        # negatives are the same thing for this purpose -- software that ran
        # and did something -- so they are trained on and measured together,
        # and the two false positive columns become one number reported
        # twice.
        benign_train = [i for i in benign_idx if rows[i].get("split") == "train"]
        benign_hold = [i for i in benign_idx if rows[i].get("split") == "holdout"]
        hard_idx = hard_idx + benign_hold
        benign_idx = benign_train
        print(f"simple split: {len(benign_train)} benign and "
              f"{len(hard_train)} hard negatives in training, "
              f"{len(hard_idx)} negatives held out and measured")

    hard_fold.update({i: int(k) for i, k in
                      zip(hard_idx,
                          rng.integers(0, len(fold_families), len(hard_idx)))})
    benign_fold = {i: int(k) for i, k in
                   zip(benign_idx, rng.integers(0, len(fold_families), len(benign_idx)))}
    if simple:
        pass
    elif hard_train:
        print(f"negatives: benign {len(benign_idx)} split across folds, "
              f"{len(hard_train)} hard negatives in training, "
              f"{len(hard_idx)} held out and measured")
    else:
        print(f"negatives: benign {len(benign_idx)} split across folds, "
              f"hard negatives {len(hard_idx)} held out of training entirely")

    def paths_of_row(i):
        v = to_float(rows[i].get("n_paths"))
        return 0.0 if math.isnan(v) else v

    # A band of near-constant volume.
    #
    # The two-stage filter cut at a threshold and left a range above it that
    # the ransomware still sat higher in. Keeping only the rows inside a band
    # removes that: everything left opens roughly the same number of files,
    # so the count cannot separate the classes and whatever does is something
    # else.
    band_keep = None
    if args.volume_band:
        lo, hi = args.volume_band
        band_keep = {i for i in range(len(rows)) if lo <= paths_of_row(i) < hi}
        pos_n = sum(1 for i in band_keep if y[i] == 1)
        print(f"\nvolume band {lo:.0f}-{hi:.0f}: {len(band_keep)} rows, "
              f"{pos_n} positive, {len(band_keep) - pos_n} negative")
        benign_idx = [i for i in benign_idx if i in band_keep]
        hard_idx = [i for i in hard_idx if i in band_keep]
        hard_train = [i for i in hard_train if i in band_keep]

    # Trained low, measured high.
    #
    # A count learned on runs that open fifty files says nothing useful about
    # a run that opens two thousand: the thresholds a tree picked are all in
    # the wrong place. A relation does not have that problem, because the
    # share of reads that were followed by a write is the same quantity at
    # either scale.
    #
    # So this is the sharpest test of whether the relational features are
    # doing work the volume features cannot. If the volume group collapses
    # and the relational group holds, they measure different things.
    shift_train = shift_test = None
    if args.volume_shift > 0:
        cut = args.volume_shift
        shift_train = {i for i in range(len(rows)) if paths_of_row(i) < cut}
        shift_test = {i for i in range(len(rows)) if paths_of_row(i) >= cut}
        print(f"\nvolume shift at {cut:.0f} files")
        for name, s_ in (("train", shift_train), ("measure", shift_test)):
            p_ = sum(1 for i in s_ if y[i] == 1)
            print(f"   {name:<9}{len(s_):>6} rows, {p_} positive, "
                  f"{len(s_) - p_} negative")
        # Negatives above the cut become the measurement set whether or not
        # they were marked for training, since nothing above the cut is
        # trained on at all.
        hard_idx = [i for i in range(len(rows))
                    if source[i] in ("hardneg", "benign") and i in shift_test]
        hard_train = [i for i in hard_train if i in shift_train]
        benign_idx = [i for i in benign_idx if i in shift_train]
        hard_fold.update({i: int(k) for i, k in
                          zip(hard_idx,
                              rng.integers(0, len(fold_families), len(hard_idx)))})

    # Matched volume.
    #
    # The two-stage filter cuts at a threshold, and above that threshold the
    # ransomware is still busier than the negatives -- a median of 578 files
    # against rather fewer. So volume is reduced but not removed, and a model
    # can still lean on what is left.
    #
    # Matching removes it properly. The rows are placed in bands by file
    # count, and within each band the larger class is cut down to the size of
    # the smaller. The marginal distribution of file count is then identical
    # for the two classes, and a model that separates them is separating them
    # on something else, because there is nothing left in the file count to
    # separate on.
    #
    # The cost is samples: bands where one class is absent contribute
    # nothing, and the training set shrinks to roughly twice the size of the
    # smaller class summed over bands.
    match_keep = None
    if args.match_volume:
        def paths_of(i):
            v = to_float(rows[i].get("n_paths"))
            return 0.0 if math.isnan(v) else v

        edges = [0, 1, 10, 50, 200, 500, 1000, 2000, float("inf")]
        edges = edges[:args.match_bins + 1]
        keep = set()
        print("\nmatched volume: bands of file count, "
              "each class cut to the smaller")
        print(f"   {'band':<14}{'positives':>10}{'negatives':>10}{'kept each':>11}")
        for lo, hi in zip(edges, edges[1:]):
            pos = [i for i in range(len(rows))
                   if y[i] == 1 and lo <= paths_of(i) < hi]
            neg = [i for i in range(len(rows))
                   if y[i] == 0 and lo <= paths_of(i) < hi]
            take = min(len(pos), len(neg))
            label = f"{lo:.0f}-{'' if hi == float('inf') else f'{hi:.0f}'}"
            print(f"   {label:<14}{len(pos):>10}{len(neg):>10}{take:>11}")
            if take == 0:
                continue
            # numpy's Generator shuffles arrays, not lists; permutation
            # gives indices back in a form that works for both.
            pos = [pos[k] for k in rng.permutation(len(pos))]
            neg = [neg[k] for k in rng.permutation(len(neg))]
            keep.update(pos[:take]); keep.update(neg[:take])
        match_keep = keep
        print(f"   {len(keep)} rows retained of {len(rows)}")

    # Two stages.
    #
    # The whole difficulty is that the file count separates the classes on
    # its own, so the model never has to look at anything else. A first stage
    # that keeps everything above a threshold and a second trained only on
    # what it kept removes that: inside the second stage the file count is
    # roughly constant, and a model that wants to do better than chance has
    # to use something else.
    #
    # It also narrows the claim, and the narrowing should be stated rather
    # than hidden. The system no longer says "this is ransomware"; it says
    # "among programs that opened a folder's worth of files, this is
    # ransomware". That is what a detector deployed on a real machine is
    # doing anyway, since watching processes that touch nothing costs more
    # than it returns.
    if args.two_stage:
        def paths_of(i):
            v = to_float(rows[i].get("n_paths"))
            return 0.0 if math.isnan(v) else v
        keep = [i for i in range(len(rows)) if paths_of(i) >= args.stage1_paths]
        dropped_pos = sum(1 for i in range(len(rows))
                          if y[i] == 1 and i not in set(keep))
        print(f"\ntwo-stage: the second stage sees only the "
              f"{len(keep)} runs that opened {args.stage1_paths:.0f} files "
              f"or more")
        print(f"  positives the first stage would lose: {dropped_pos} "
              f"of {int((y == 1).sum())}")
        keep_set = set(keep)
        benign_idx = [i for i in benign_idx if i in keep_set]
        hard_idx = [i for i in hard_idx if i in keep_set]
        hard_train = [i for i in hard_train if i in keep_set]
        stage2_only = keep_set

        # Almost no benign program survives the filter, and that is the point
        # rather than an inconvenience: of 1,563 programs in the benign set,
        # six open fifty files. The corpus contains nothing that behaves like
        # a backup script.
        #
        # So the second stage has no negatives unless some hard negatives are
        # trained on. The two experiments turn out to be one: asking what the
        # model learns when volume is held constant requires having active
        # negatives to learn from, and only the hard negatives are active.
        print(f"  benign programs that reach the second stage: "
              f"{len(benign_idx)} of "
              f"{sum(1 for i in range(len(rows)) if source[i] == 'benign')}")
        if len(benign_idx) < 5 * len(fold_families) and not hard_train:
            print()
            print("  [!] Not enough negatives to evaluate. Every fold needs a")
            print("      few negatives in its test set and the benign corpus")
            print("      cannot supply them at this threshold.")
            print()
            print("      Rebuild with some of the harmless hard negatives in")
            print("      training and the rest held back:")
            print()
            print("        python3 build_dataset.py --features-dir ~/work \\")
            print("          --relational ~/work/rel_all.csv \\")
            print("          --hardneg-manifest <manifest.csv> \\")
            print("          --hardneg-train-frac 0.5 \\")
            print("          --out ~/work/modelling_split.csv")
            print()
            print("      The held-out half then supplies the negatives, and")
            print("      the false positive rate is still measured on")
            print("      software the model has not seen.")
            return
    else:
        stage2_only = None

    # Build the matrix once and take column slices out of it.
    #
    # Rebuilding it inside evaluate() meant converting every cell again on
    # every call: 3,661 rows by 99 columns is 360,000 conversions, and the
    # leave-one-out pass calls evaluate a hundred times. That is 36 million
    # conversions in Python, which is both the bulk of the runtime and the
    # reason threading the loop changed nothing -- the work was holding the
    # interpreter lock, not sitting inside XGBoost.
    matrix_cols = [c for g in GROUPS for c in present[g]]
    col_index = {c: i for i, c in enumerate(matrix_cols)}
    FULL = np.array([[to_float(r.get(c)) for c in matrix_cols] for r in rows])

    def evaluate(feature_cols, tag, threads=4):
        X = FULL[:, [col_index[c] for c in feature_cols]]
        per_fold = []
        hard_flagged = np.zeros(len(hard_idx))
        # Which positives were caught, kept per sample rather than as a rate.
        # A model trained on runs that reached encryption may be recognising
        # the encryption rather than the ransomware, and the runs that
        # executed without reaching it are the only way to tell: same
        # malware, minus the one behaviour the label was defined by. Indexed
        # by row so it can be joined back to the verdict afterwards.
        pos_flagged = np.zeros(len(rows))
        pos_folds = np.zeros(len(rows))
        hard_scores = []

        for k, fam in enumerate(fold_families):
            scope = (stage2_only if stage2_only is not None
                     else band_keep if band_keep is not None
                     else shift_test if shift_test is not None
                     else range(len(rows)))
            test_pos = [i for i in scope
                        if y[i] == 1 and family[i] == fam]
            test_neg = [i for i in benign_idx if benign_fold.get(i) == k]
            if simple or shift_test is not None:
                # The held-out negatives are spread across the folds so that
                # every fold has some to be wrong about.
                test_neg = [i for i in hard_idx if hard_fold.get(i) == k]
            if stage2_only is not None:
                # With the benign corpus gone from this stage, the held-out
                # hard negatives are the negatives. They are split across the
                # folds the same way, and none of them was trained on.
                test_neg += [i for i in hard_idx if hard_fold.get(i) == k]
            test = test_pos + test_neg
            pool = stage2_only if stage2_only is not None else range(len(rows))
            if band_keep is not None:
                pool = [i for i in pool if i in band_keep]
            if shift_train is not None:
                pool = [i for i in pool if i in shift_train]
            if match_keep is not None:
                pool = [i for i in pool if i in match_keep]
            train = [i for i in pool
                     if i not in set(test) and i not in set(hard_idx)
                     and not (y[i] == 1 and family[i] == fam)]
            if not test_pos or len(test_neg) < 5:
                continue

            model = XGBClassifier(
                n_estimators=300, max_depth=5, learning_rate=0.08,
                subsample=0.9, colsample_bytree=0.9,
                eval_metric="logloss", n_jobs=threads,
                random_state=args.seed,
                scale_pos_weight=max(1.0, (y[train] == 0).sum() / max(1, (y[train] == 1).sum())),
            )
            model.fit(X[train], y[train])

            p_test = model.predict_proba(X[test])[:, 1]
            a = auc_score(list(y[test]), list(p_test))

            pt = model.predict_proba(X[test_pos])[:, 1]
            pn = model.predict_proba(X[test_neg])[:, 1]
            ph = model.predict_proba(X[hard_idx])[:, 1] if hard_idx else np.array([])

            ran = [i for i in test_neg if executed[i]]
            pr = model.predict_proba(X[ran])[:, 1] if ran else np.array([])

            hard_flagged += (ph >= args.threshold).astype(float)
            for pos_i, i in enumerate(test_pos):
                pos_flagged[i] += float(pt[pos_i] >= args.threshold)
                pos_folds[i] += 1
            hard_scores.append(ph)
            per_fold.append({
                "family": fam, "n_pos": len(test_pos), "auc": a,
                "tpr": float((pt >= args.threshold).mean()),
                "fpr_benign": float((pn >= args.threshold).mean()),
                "fpr_benign_ran": float((pr >= args.threshold).mean()) if len(pr) else float("nan"),
                "fpr_hard": float((ph >= args.threshold).mean()) if len(ph) else float("nan"),
            })

        def avg(key):
            vals = [f[key] for f in per_fold if not math.isnan(f[key])]
            return sum(vals) / len(vals) if vals else float("nan")

        mean_score = (np.mean(hard_scores, axis=0) if hard_scores
                      else np.zeros(len(hard_idx)))
        return {
            "group": tag, "n_features": len(feature_cols),
            "hard_flagged": hard_flagged, "hard_mean_score": mean_score,
            "pos_flagged": pos_flagged, "pos_folds": pos_folds,
            "n_folds": len(per_fold),
            "auc": avg("auc"), "tpr": avg("tpr"),
            "fpr_benign": avg("fpr_benign"),
            "fpr_benign_ran": avg("fpr_benign_ran"),
            "fpr_hard": avg("fpr_hard"),
            "folds": per_fold,
            "hard_always": int((hard_flagged == len(per_fold)).sum()),
        }

    def rank_features(feature_cols):
        """
        Three views of what the model is using.

        gain is what the trees report: how much each split on that feature
        improved the objective. It is free but it rewards features that were
        available rather than features that were necessary, and it says
        nothing about held-out behaviour.

        permutation on AUC shuffles one column in the test fold and measures
        what the score loses. Because no retraining happens, a feature whose
        information is also carried elsewhere still shows a loss -- which is
        the right answer to "is the model using this", even if the answer to
        "would removing it hurt" is no.

        permutation on the hard negative rate asks the question the rest of
        this file has been circling: which column is responsible for calling
        a busy, legitimate program ransomware. A feature that costs AUC when
        shuffled but also lowers the false positive rate is doing both jobs,
        and that trade is the thing worth reporting.
        """
        X = np.array([[to_float(r.get(c)) for c in feature_cols] for r in rows])
        gain = defaultdict(float)
        perm_auc = defaultdict(list)
        perm_hard = defaultdict(list)
        prng = np.random.default_rng(args.seed + 1)

        for k, fam in enumerate(fold_families):
            scope = (stage2_only if stage2_only is not None
                     else band_keep if band_keep is not None
                     else shift_test if shift_test is not None
                     else range(len(rows)))
            test_pos = [i for i in scope
                        if y[i] == 1 and family[i] == fam]
            test_neg = [i for i in benign_idx if benign_fold.get(i) == k]
            if simple or shift_test is not None:
                # The held-out negatives are spread across the folds so that
                # every fold has some to be wrong about.
                test_neg = [i for i in hard_idx if hard_fold.get(i) == k]
            if stage2_only is not None:
                # With the benign corpus gone from this stage, the held-out
                # hard negatives are the negatives. They are split across the
                # folds the same way, and none of them was trained on.
                test_neg += [i for i in hard_idx if hard_fold.get(i) == k]
            test = test_pos + test_neg
            pool = stage2_only if stage2_only is not None else range(len(rows))
            if band_keep is not None:
                pool = [i for i in pool if i in band_keep]
            if shift_train is not None:
                pool = [i for i in pool if i in shift_train]
            if match_keep is not None:
                pool = [i for i in pool if i in match_keep]
            train = [i for i in pool
                     if i not in set(test) and i not in set(hard_idx)
                     and not (y[i] == 1 and family[i] == fam)]
            if not test_pos or len(test_neg) < 5:
                continue

            model = XGBClassifier(
                n_estimators=300, max_depth=5, learning_rate=0.08,
                subsample=0.9, colsample_bytree=0.9,
                eval_metric="logloss", n_jobs=4, random_state=args.seed,
                scale_pos_weight=max(1.0, (y[train] == 0).sum() / max(1, (y[train] == 1).sum())),
            )
            model.fit(X[train], y[train])

            for c, g in zip(feature_cols, model.feature_importances_):
                gain[c] += float(g)

            base_auc = auc_score(list(y[test]), list(model.predict_proba(X[test])[:, 1]))
            base_hard = float((model.predict_proba(X[hard_idx])[:, 1]
                               >= args.threshold).mean()) if hard_idx else float("nan")

            for j, c in enumerate(feature_cols):
                Xt = X[test].copy()
                Xt[:, j] = prng.permutation(Xt[:, j])
                perm_auc[c].append(base_auc -
                                   auc_score(list(y[test]),
                                             list(model.predict_proba(Xt)[:, 1])))
                if hard_idx:
                    Xh = X[hard_idx].copy()
                    Xh[:, j] = prng.permutation(Xh[:, j])
                    shuffled = float((model.predict_proba(Xh)[:, 1]
                                      >= args.threshold).mean())
                    perm_hard[c].append(base_hard - shuffled)

        n = max(1, len(fold_families))
        table = []
        for c in feature_cols:
            table.append({
                "feature": c,
                "group": next(g for g in GROUPS if c in present[g]),
                "gain": gain[c] / n,
                "perm_auc": sum(perm_auc[c]) / max(1, len(perm_auc[c])),
                "perm_hard": sum(perm_hard[c]) / max(1, len(perm_hard[c])),
            })

        table.sort(key=lambda t: -t["perm_auc"])
        print(f"\n{'feature':<28}{'group':<12}{'gain':>8}{'AUC lost':>10}"
              f"{'FP hard':>10}")
        print("-" * 68)
        for t in table[:25]:
            print(f"{t['feature']:<28}{t['group']:<12}{t['gain']:>8.3f}"
                  f"{t['perm_auc']:>10.4f}{t['perm_hard']:>10.4f}")

        with open(args.importance_out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["feature", "group", "gain",
                                               "perm_auc", "perm_hard"])
            w.writeheader()
            for t in table:
                w.writerow({k: (f"{v:.5f}" if isinstance(v, float) else v)
                            for k, v in t.items()})
        print(f"\n[saved] {args.importance_out}")
        print("  'FP hard' is the change in the hard negative false positive")
        print("  rate when the column is shuffled, base minus shuffled. Positive")
        print("  means the feature was driving those false positives; negative")
        print("  means it was holding them down and destroying it makes matters")
        print("  worse. n_paths comes out negative because the hard negatives")
        print("  touch fewer paths than the ransomware, so the model was using it")
        print("  to keep some of them on the right side.")

    results = []
    print(f"\n{'':<16}{'feat':>5}{'AUC':>8}{'TPR':>8}"
          f"{'FP benign':>11}{'FP ran':>9}{'FP hard':>9}")
    print("-" * 66)

    for tag, groups in CUMULATIVE:
        cols = [c for g in groups for c in present[g]]
        if not cols:
            continue
        r = evaluate(cols, tag)
        results.append(r)
        print(f"{tag:<16}{r['n_features']:>5}{r['auc']:>8.3f}{r['tpr']:>8.3f}"
              f"{r['fpr_benign']:>11.3f}{r['fpr_benign_ran']:>9.3f}"
              f"{r['fpr_hard']:>9.3f}")

    print()
    for g in ALONE:
        cols = present[g]
        if not cols:
            continue
        r = evaluate(cols, f"{g} alone")
        results.append(r)
        print(f"{g + ' alone':<16}{r['n_features']:>5}{r['auc']:>8.3f}{r['tpr']:>8.3f}"
              f"{r['fpr_benign']:>11.3f}{r['fpr_benign_ran']:>9.3f}"
              f"{r['fpr_hard']:>9.3f}")

    # A / S / A+S: the comparison the research question actually asks for.
    print()
    for tag, groups in (("individual (A)", ["individual_axis"]),
                        ("sequence (S)", ["sequence_axis"]),
                        ("A + S", ["individual_axis", "sequence_axis"]),
                        ("order: api", ["order_api"]),
                        ("order: file", ["order_file"]),
                        ("order: behav", ["order_behaviour"]),
                        ("A + ord api", ["individual_axis", "order_api"]),
                        ("A + ord file", ["individual_axis", "order_file"]),
                        ("A + ord behav", ["individual_axis", "order_behaviour"]),
                        ("A_reduced", ["a_reduced"]),
                        ("A_red + S", ["a_reduced", "sequence_axis"]),
                        ("A_red + ordbeh", ["a_reduced", "order_behaviour"]),
                        ("a: static", ["a_static"]),
                        ("a: count", ["a_count"]),
                        ("a: presence", ["a_presence"]),
                        ("a: aggregate", ["a_aggregate"]),
                        ("a: relation", ["a_relation"]),
                        ("count+relation", ["a_count", "a_relation"]),
                        ("count+aggregate", ["a_count", "a_aggregate"]),
                        ("--- exp 1 ---", ["a_behaviour"]),
                        ("A(behav)", ["a_behaviour"]),
                        ("S1(relation)", ["s1_relation"]),
                        ("S2(order)", ["s2_order"]),
                        ("S1+S2", ["s1_relation", "s2_order"]),
                        ("A+S1", ["a_behaviour", "s1_relation"]),
                        ("A+S2", ["a_behaviour", "s2_order"]),
                        ("A+S1+S2", ["a_behaviour", "s1_relation", "s2_order"]),
                        ("--- exp 2 ---", ["a_generic"]),
                        ("A_gen", ["a_generic"]),
                        ("A_gen+S1", ["a_generic", "s1_relation"]),
                        ("A_gen+S2", ["a_generic", "s2_order"]),
                        ("A_gen+S1+S2", ["a_generic", "s1_relation", "s2_order"])):
        cols = [c for g in groups for c in present[g]]
        r = evaluate(cols, tag)
        results.append(r)
        print(f"{tag:<16}{r['n_features']:>5}{r['auc']:>8.3f}{r['tpr']:>8.3f}"
              f"{r['fpr_benign']:>11.3f}{r['fpr_benign_ran']:>9.3f}"
              f"{r['fpr_hard']:>9.3f}")

    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["group", "n_features", "auc", "tpr",
                    "fpr_benign", "fpr_benign_ran", "fpr_hard"])
        for r in results:
            w.writerow([r["group"], r["n_features"], f"{r['auc']:.4f}",
                        f"{r['tpr']:.4f}", f"{r['fpr_benign']:.4f}",
                        f"{r['fpr_benign_ran']:.4f}", f"{r['fpr_hard']:.4f}"])
    print(f"\n[saved] {args.out}")

    # Which hard negatives were flagged, not just how many. The count alone
    # says the detector fails on active software; the list says which kinds
    # of activity it cannot tell apart from encryption, and those are not the
    # same failure.
    full_for_hard = results[len(CUMULATIVE) - 1]
    if hard_idx:
        with open(args.hard_out, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["sample_id", "folds_flagged", "n_folds",
                        "flag_rate", "mean_score"])
            for pos, i in enumerate(hard_idx):
                w.writerow([rows[i]["sample_id"],
                            int(full_for_hard["hard_flagged"][pos]),
                            full_for_hard["n_folds"],
                            f"{full_for_hard['hard_flagged'][pos] / max(1, full_for_hard['n_folds']):.4f}",
                            f"{full_for_hard['hard_mean_score'][pos]:.4f}"])
        print(f"[saved] {args.hard_out}")

    # The same variants scored under each feature set. Every group's run
    # already computed this; only the last one was being kept.
    if hard_idx and args.hard_out_groups:
        with open(args.hard_out_groups, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["sample_id"] + [r["group"] for r in results])
            for pos, i in enumerate(hard_idx):
                w.writerow([rows[i]["sample_id"]] +
                           [f"{r['hard_flagged'][pos] / max(1, r['n_folds']):.4f}"
                            for r in results])
        print(f"[saved] {args.hard_out_groups}")

    if args.pos_out:
        cols = [r for r in results]
        pos_rows = [i for i in range(len(rows)) if y[i] == 1]
        with open(args.pos_out, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["sample_id", "verdict", "n_folds"] +
                       [r["group"] for r in cols])
            for i in pos_rows:
                nf = cols[0]["pos_folds"][i] if cols else 0
                if nf == 0:
                    continue
                w.writerow([rows[i]["sample_id"], rows[i].get("verdict", ""),
                            int(nf)] +
                           [f"{r['pos_flagged'][i] / max(1, r['pos_folds'][i]):.4f}"
                            for r in cols])
        print(f"[saved] {args.pos_out}")

    if args.importance:
        all_cols = [c for g in GROUPS for c in present[g]]
        rank_features(all_cols)

    if args.leave_one_out:
        all_cols = [c for g in GROUPS for c in present[g]]
        print(f"\nretraining without each of {len(all_cols)} features in turn"
              f" ({args.jobs} at a time)")
        base = evaluate(all_cols, "all")

        # Each removal is independent of every other, so they run together.
        # Threads rather than processes: the work is inside XGBoost, which
        # releases the interpreter lock, and the training matrix would have
        # to be copied to every process otherwise.
        #
        # XGBoost is given one thread each when they run in parallel. Left at
        # four, ninety-nine jobs would ask for four hundred threads on eight
        # cores and spend the time switching between them.
        loo = []
        done = [0]
        from concurrent.futures import ThreadPoolExecutor
        import threading
        lock = threading.Lock()

        def one(c):
            r = evaluate([x for x in all_cols if x != c], f"-{c}",
                         threads=1 if args.jobs > 1 else 4)
            with lock:
                done[0] += 1
                print(f"\r   {done[0]}/{len(all_cols)}", end="", flush=True)
            return (c, base["auc"] - r["auc"], r["fpr_hard"] - base["fpr_hard"])

        if args.jobs > 1:
            with ThreadPoolExecutor(max_workers=args.jobs) as pool:
                loo = list(pool.map(one, all_cols))
        else:
            loo = [one(c) for c in all_cols]
        print()
        print(f"\n{'feature':<28}{'AUC lost':>10}{'FP hard gained':>16}")
        for c, da, dh in sorted(loo, key=lambda x: -x[1])[:20]:
            print(f"{c:<28}{da:>10.4f}{dh:>16.4f}")
        biggest = max(abs(d) for _c, d, _h in loo) if loo else 0.0
        print(f"\n  Largest AUC change from removing any single feature: {biggest:.4f}")
        print("  A feature can matter and still show nothing here, because another")
        print("  correlated with it takes over when it is removed. When nothing at")
        print("  all moves, the set is redundant throughout -- which is itself the")
        print("  result, and a stronger one than any group ablation: it is not that")
        print("  a particular group is unnecessary, it is that no single column is.")

    full = results[len(CUMULATIVE) - 1]
    print(f"\nper-family, using all groups:")
    print(f"   {'family':<18}{'n':>5}{'AUC':>8}{'TPR':>8}")
    for f_ in sorted(full["folds"], key=lambda x: x["auc"]):
        print(f"   {f_['family']:<18}{f_['n_pos']:>5}{f_['auc']:>8.3f}{f_['tpr']:>8.3f}")

    print(f"\n{full['hard_always']} of {len(hard_idx)} hard negatives were flagged "
          f"in every fold")

    # The rate over the whole set is a property of how the set was assembled
    # rather than of the detector. Half of these programs are Sysinternals
    # tools run without arguments, which print their usage and exit: they
    # touch nothing, so of course nothing flags them, and adding more of them
    # would drive the figure to zero without changing what the model does.
    #
    # Split by how many distinct files each program opened, the number stops
    # moving with the composition of the set and starts describing the
    # detector. It also locates the boundary, which no single figure can.
    if hard_idx:
        rate_by_pos = [full["hard_flagged"][p_] / max(1, full["n_folds"])
                       for p_ in range(len(hard_idx))]
        bands = [(0, 10, "under 10"), (10, 50, "10 to 49"),
                 (50, 200, "50 to 199"), (200, 10**9, "200 or more")]
        print("\n  by how many distinct files the program opened:")
        print(f"   {'':<14}{'n':>5}{'flagged':>9}{'rate':>8}")
        for lo, hi, label in bands:
            sel = []
            for p_, i in enumerate(hard_idx):
                v = to_float(rows[i].get("n_paths"))
                v = 0.0 if math.isnan(v) else v
                if lo <= v < hi:
                    sel.append(p_)
            if not sel:
                continue
            hits = sum(1 for p_ in sel if rate_by_pos[p_] >= 0.5)
            print(f"   {label:<14}{len(sel):>5}{hits:>9}"
                  f"{hits / len(sel):>8.3f}")
        print("   The ransomware median is 578 distinct files. A backup")
        print("   script, a bulk rename or an archiver reaches the band")
        print("   where almost everything is flagged.")
    print("\nThe benign column is the number that looks best and means least:")
    print("most of that set never executed. The hard negative column is the")
    print("one to quote: the model never saw those programs, and they open a")
    print("folder's worth of files the way legitimate software does. They are")
    print("not as active as the ransomware -- by call count they sit with the")
    print("benign set -- which makes the gap between the two benign columns")
    print("the thing to explain, since it is not explained by how much each")
    print("of them did.")


if __name__ == "__main__":
    main()
