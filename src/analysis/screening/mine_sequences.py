#!/usr/bin/env python3
"""
mine_sequences.py - Find behaviour sub-sequences that are frequent in
ransomware and rare in everything else, and turn the discriminative ones
into features.

The two halves
--------------
Mining what recurs in ransomware is only half the question. A sub-sequence
that is common in ransomware but equally common in archivers and installers
separates nothing. So this does contrast mining: a pattern earns its place
by the *gap* between how often it appears in ransomware and how often it
appears in the hard negatives. That gap is the direct test of the original
hypothesis -- that hard negatives lack ransomware's behavioural sequence
even when they compress, encrypt or install.

Why PrefixSpan
--------------
The sequences are short (six to twelve behaviours) but the alphabet is small
and patterns repeat across families, so a frequent-subsequence miner is the
right tool. PrefixSpan grows patterns by projecting the database on each
frequent prefix; it finds subsequences that preserve order but allow gaps,
which is exactly the model chosen in the last discussion -- ENCRYPT then
NOTE counts whether or not something happened between them, and concurrent
acts whose order is random simply fail to reach support and drop out, which
is itself the finding that they have no order.

Support is counted per sample, not per occurrence: a pattern that appears
five times in one run counts once. Otherwise a single long run would
dominate.

Input
-----
Two or more .jsonl files from behaviour_sequence.py, one per class. The
positive class is ransomware; every other file is a negative to contrast
against.

    python3 mine_sequences.py \\
        --positive ~/work/seq_ransom.jsonl \\
        --negative ~/work/seq_hardneg.jsonl \\
        --min-support 0.10 --max-len 5 \\
        --out ~/work/sequence_patterns.csv

Output
------
A table of patterns with support in each class and the contrast, sorted by
contrast. And, with --features, a per-sample 0/1 matrix over the patterns
that clear a contrast threshold, ready to join into the modelling table as
a new feature group.
"""

import os
import csv
import json
import argparse
from collections import defaultdict


def load_sequences(path):
    seqs = {}
    with open(os.path.expanduser(path)) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            seqs[r["task_id"]] = r["sequence"]
    return seqs


def load_verdicts(paths):
    """task_id -> verdict from one or more analyze_result.py CSVs."""
    v = {}
    for p in paths:
        with open(os.path.expanduser(p), newline="") as f:
            for r in csv.DictReader(f):
                tid = r.get("task_id") or r.get("task")
                if tid:
                    v[str(tid)] = r.get("verdict", "")
    return v


# --------------------------------------------------------- PrefixSpan

def prefixspan(sequences, min_count, max_len):
    """
    Frequent subsequences by per-sequence support.

    sequences: list of lists of tokens.
    Returns {pattern_tuple: support_count}, support counted once per
    sequence that contains the pattern as a subsequence (order preserved,
    gaps allowed).
    """
    results = {}

    def contains(seq, pattern):
        it = iter(seq)
        return all(tok in it for tok in pattern)

    # First-level frequent items.
    from collections import Counter
    item_support = Counter()
    for seq in sequences:
        for tok in set(seq):
            item_support[tok] += 1
    frequent = [(tok,) for tok, c in item_support.items() if c >= min_count]

    def grow(prefix, projected):
        # projected: list of (sequence, start_index_after_prefix_match)
        if len(prefix) >= max_len:
            return
        # count possible next items in the projected suffixes
        nxt = Counter()
        for seq, start in projected:
            seen = set()
            for tok in seq[start:]:
                if tok not in seen:
                    nxt[tok] += 1
                    seen.add(tok)
        for tok, c in nxt.items():
            if c < min_count:
                continue
            pattern = prefix + (tok,)
            results[pattern] = c
            # re-project: advance past the first occurrence of tok
            new_proj = []
            for seq, start in projected:
                for k in range(start, len(seq)):
                    if seq[k] == tok:
                        new_proj.append((seq, k + 1))
                        break
            grow(pattern, new_proj)

    for (tok,) in frequent:
        results[(tok,)] = item_support[tok]
        proj = []
        for seq in sequences:
            for k, t in enumerate(seq):
                if t == tok:
                    proj.append((seq, k + 1))
                    break
        grow((tok,), proj)

    return results


def support_of(pattern, sequences):
    """Fraction of sequences containing pattern as a subsequence."""
    def contains(seq):
        it = iter(seq)
        return all(tok in it for tok in pattern)
    hits = sum(1 for s in sequences if contains(s))
    return hits, len(sequences)


# ------------------------------------------------------------- driver

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--positive", required=True,
                    help="ransomware sequences (.jsonl)")
    ap.add_argument("--negative", nargs="+", required=True,
                    help="one or more negative-class .jsonl files")
    ap.add_argument("--min-support", type=float, default=0.10,
                    help="minimum support in the positive class")
    ap.add_argument("--max-len", type=int, default=5)
    ap.add_argument("--min-contrast", type=float, default=0.30,
                    help="keep patterns whose positive minus negative "
                         "support is at least this")
    ap.add_argument("--positive-verdicts", nargs="*",
                    help="analyze_result.py CSVs for the positive archives; "
                         "when given, only runs whose verdict is "
                         "--keep-verdict count as positives")
    ap.add_argument("--keep-verdict", default="TRUE_ENCRYPTION")
    ap.add_argument("--out", required=True)
    ap.add_argument("--features",
                    help="also write a per-sample 0/1 matrix here")
    args = ap.parse_args()

    pos = load_sequences(args.positive)
    if args.positive_verdicts:
        v = load_verdicts(args.positive_verdicts)
        before = len(pos)
        pos = {t: s for t, s in pos.items() if v.get(t) == args.keep_verdict}
        print(f"positive: {before} sequences, {len(pos)} with verdict "
              f"{args.keep_verdict} kept")
    pos_seqs = list(pos.values())
    neg = {}
    for path in args.negative:
        neg.update(load_sequences(path))
    neg_seqs = list(neg.values())

    print(f"positive {len(pos_seqs)} sequences, negative {len(neg_seqs)}")
    min_count = max(2, int(args.min_support * len(pos_seqs)))
    print(f"mining patterns with support >= {min_count} "
          f"({args.min_support:.0%}), length <= {args.max_len}")

    patterns = prefixspan(pos_seqs, min_count, args.max_len)
    print(f"{len(patterns)} frequent patterns in the positive class")

    rows = []
    for pat, pos_count in patterns.items():
        p_hits, p_n = pos_count, len(pos_seqs)
        n_hits, n_n = support_of(pat, neg_seqs)
        p_sup = p_hits / p_n
        n_sup = n_hits / n_n if n_n else 0.0
        rows.append({
            "pattern": " -> ".join(pat),
            "length": len(pat),
            "pos_support": round(p_sup, 4),
            "neg_support": round(n_sup, 4),
            "contrast": round(p_sup - n_sup, 4),
            "pos_hits": p_hits,
            "neg_hits": n_hits,
        })

    # A longer pattern that separates no better than a prefix of it adds
    # nothing; keep it only if its contrast beats every prefix already kept.
    rows.sort(key=lambda r: (-r["contrast"], -r["length"]))

    with open(os.path.expanduser(args.out), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["pattern", "length", "pos_support",
                                          "neg_support", "contrast",
                                          "pos_hits", "neg_hits"])
        w.writeheader()
        w.writerows(rows)
    print(f"[saved] {args.out}")

    kept = [r for r in rows if r["contrast"] >= args.min_contrast]
    print(f"\n{len(kept)} patterns clear contrast >= {args.min_contrast}:\n")
    print(f"{'pattern':<52}{'pos':>7}{'neg':>7}{'contr':>7}")
    print("-" * 73)
    for r in kept[:30]:
        print(f"{r['pattern']:<52}{r['pos_support']:>7.2f}"
              f"{r['neg_support']:>7.2f}{r['contrast']:>7.2f}")

    if args.features and kept:
        feat_pats = [tuple(r["pattern"].split(" -> ")) for r in kept]
        all_seqs = {**pos, **neg}
        def contains(seq, pat):
            it = iter(seq)
            return all(t in it for t in pat)
        cols = [f"seq_{i:02d}" for i in range(len(feat_pats))]
        with open(os.path.expanduser(args.features), "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["task_id"] + cols)
            for tid, seq in all_seqs.items():
                w.writerow([tid] + [int(contains(seq, p)) for p in feat_pats])
        # a legend mapping column name to the pattern it encodes
        legend = os.path.splitext(os.path.expanduser(args.features))[0] + "_legend.csv"
        with open(legend, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["column", "pattern", "pos_support", "neg_support", "contrast"])
            for c, r in zip(cols, kept):
                w.writerow([c, r["pattern"], r["pos_support"],
                            r["neg_support"], r["contrast"]])
        print(f"\n[saved] {args.features}  ({len(feat_pats)} pattern features)")
        print(f"[saved] {legend}")


if __name__ == "__main__":
    main()
