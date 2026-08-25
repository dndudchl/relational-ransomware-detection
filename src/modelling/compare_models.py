#!/usr/bin/env python3
"""
compare_models.py - Three checks that the main result does not depend on the
choice of classifier, on having labels at all, or on the class balance of the
test set.

Why each one is here
--------------------

**Other classifiers.** A reviewer is entitled to ask whether an AUC of 1.000
and a 78% false positive rate on active software are properties of gradient
boosting rather than of the data. Logistic regression assumes a linear
boundary, a random forest bags rather than boosts, and k-nearest-neighbours
fits nothing at all -- it just looks for the closest training example. If the
last of those reaches the same score, no learning was required, and that is
a stronger statement about the problem than any comparison of the first two.

**One-class detection, in both directions.** Supervised training needs both
labels; anomaly detection needs one, and which one changes the question.

    trained on benign      "is this unlike ordinary software"
    trained on ransomware  "is this like ransomware"

Neither is the correct choice. The first will flag anything active, because
four fifths of the benign set never ran and so "ordinary" was learned as
"quiet". The second asks the question the hard negatives were built for.
Running both and comparing is the point: if they disagree sharply on the hard
negatives, what counts as normal is doing the work, not the algorithm.

**Precision at a realistic base rate.** Ransomware is rare. The test folds
here are roughly balanced, so precision looks excellent, but a detector
deployed where one program in a thousand is malicious faces a different
arithmetic. Reweighting the same predictions to that base rate needs no
retraining and shows what the AUC was concealing.

Usage
-----
  python3 compare_models.py --data ../../data/modelling_simple.csv
"""

import csv
import math
import argparse
import warnings
from collections import Counter

# One line per fold per model otherwise, which is several hundred lines of
# the same message in front of the table.
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

CIRCULAR = {
    "destroyed_decoy_files", "append_renames", "distinct_rename_suffixes",
    "shared_extension_renames", "ransom_note_dirs", "ransom_note_explicit",
    "ransom_note_candidates", "ransom_note_name", "corroborating_axes",
    "destructive_events", "destructive_extension_variety",
    "destructive_chain_windows", "replacement_extension",
    "extension_replacements", "distinct_target_extensions",
    "verdict", "reason", "malscore",
}
NON_FEATURES = {
    "sample_id", "sha256", "y", "source", "family_group", "family", "label",
    "coverage", "cape_family", "original_filename", "added_date", "notes",
    "source_dataset", "task_id", "_error", "static_readable",
    "replacement_extension", "ransom_note_name",
}


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


def mean(xs):
    xs = [x for x in xs if not math.isnan(x)]
    return sum(xs) / len(xs) if xs else float("nan")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", required=True)
    parser.add_argument("--min-family", type=int, default=20)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--base-rate", type=float, default=0.001,
                         help="Fraction of programs that are ransomware in the "
                              "population the detector would be deployed into")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", default="/tmp/model_comparison.csv")
    args = parser.parse_args()

    import numpy as np
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.impute import SimpleImputer
    from xgboost import XGBClassifier

    rows = list(csv.DictReader(open(args.data, newline="")))
    features = [c for c in rows[0]
                if c not in CIRCULAR and c not in NON_FEATURES]
    print(f"{len(rows)} rows, {len(features)} features")

    X = np.array([[to_float(r.get(c)) for c in features] for r in rows])

    # A column that is empty in every row cannot be imputed and carries no
    # information; sklearn warns once per fit about it, which buries the
    # output. Drop them here and say which they were, because a feature that
    # was never computed at all is worth knowing about.
    observed = ~np.all(np.isnan(X), axis=0)
    if not observed.all():
        dropped = [c for c, keep in zip(features, observed) if not keep]
        print(f"[note] {len(dropped)} features are empty for every row and are "
              f"dropped: {', '.join(dropped)}")
        features = [c for c, keep in zip(features, observed) if keep]
        X = X[:, observed]
    y = np.array([int(r["y"]) for r in rows])
    source = [r["source"] for r in rows]
    family = [r["family_group"] or "(unknown)" for r in rows]

    pos_fams = Counter(family[i] for i in range(len(rows))
                       if y[i] == 1 and family[i] != "(unknown)")
    folds = sorted(f for f, n in pos_fams.items() if n >= args.min_family)
    benign_idx = [i for i in range(len(rows)) if source[i] == "benign"]
    hard_idx = [i for i in range(len(rows)) if source[i] == "hardneg"]
    rng = np.random.default_rng(args.seed)
    benign_fold = {i: int(k) for i, k in
                   zip(benign_idx, rng.integers(0, len(folds), len(benign_idx)))}
    print(f"{len(folds)} folds, {len(hard_idx)} hard negatives held out\n")

    def split(k, fam):
        test_pos = [i for i in range(len(rows)) if y[i] == 1 and family[i] == fam]
        test_neg = [i for i in benign_idx if benign_fold[i] == k]
        test = test_pos + test_neg
        train = [i for i in range(len(rows))
                 if i not in set(test) and i not in set(hard_idx)
                 and not (y[i] == 1 and family[i] == fam)]
        return train, test, test_pos, test_neg

    # NaN means the feature could not be computed for that run -- a program
    # that touched no files has no read-to-write ratio. Trees handle that
    # natively; the others do not, so those get imputation and scaling. The
    # median is used rather than zero because zero is a real value for most
    # of these columns and would be indistinguishable from missing.
    def make(name):
        if name == "xgboost":
            return XGBClassifier(n_estimators=300, max_depth=5, learning_rate=0.08,
                                  subsample=0.9, colsample_bytree=0.9,
                                  eval_metric="logloss", n_jobs=4,
                                  random_state=args.seed)
        if name == "random forest":
            return make_pipeline(
                SimpleImputer(strategy="median"),
                RandomForestClassifier(n_estimators=300, n_jobs=4,
                                        random_state=args.seed,
                                        class_weight="balanced"))
        if name == "logistic regression":
            return make_pipeline(
                SimpleImputer(strategy="median"), StandardScaler(),
                LogisticRegression(max_iter=2000, class_weight="balanced",
                                    random_state=args.seed))
        if name == "k-nearest neighbours":
            return make_pipeline(
                SimpleImputer(strategy="median"), StandardScaler(),
                KNeighborsClassifier(n_neighbors=5, n_jobs=4))
        raise ValueError(name)

    results = []

    for name in ["xgboost", "random forest", "logistic regression",
                 "k-nearest neighbours"]:
        aucs, tprs, fps, fph, precs, precs_active = [], [], [], [], [], []
        for k, fam in enumerate(folds):
            train, test, test_pos, test_neg = split(k, fam)
            if not test_pos or len(test_neg) < 5:
                continue
            model = make(name)
            model.fit(X[train], y[train])
            p_test = model.predict_proba(X[test])[:, 1]
            aucs.append(auc_score(list(y[test]), list(p_test)))
            tpr = float((model.predict_proba(X[test_pos])[:, 1] >= args.threshold).mean())
            fpr = float((model.predict_proba(X[test_neg])[:, 1] >= args.threshold).mean())
            tprs.append(tpr)
            fps.append(fpr)
            if hard_idx:
                fph.append(float((model.predict_proba(X[hard_idx])[:, 1]
                                  >= args.threshold).mean()))
            # Precision if the same rates held in a population where the
            # base rate is what it is in the world rather than in this table.
            b = args.base_rate
            denom = tpr * b + fpr * (1 - b)
            precs.append(tpr * b / denom if denom > 0 else float("nan"))
            # The same arithmetic against the hard negative rate. The benign
            # figure assumes the software a detector meets in deployment is
            # as inert as this benign set, four fifths of which never ran.
            # Real machines run programs that touch files, and that is what
            # the hard negatives are.
            fh = fph[-1] if fph else float("nan")
            d2 = tpr * b + fh * (1 - b)
            precs_active.append(tpr * b / d2 if d2 > 0 else float("nan"))

        results.append({
            "approach": name, "auc": mean(aucs), "tpr": mean(tprs),
            "fpr_benign": mean(fps), "fpr_hard": mean(fph),
            "precision_at_base_rate": mean(precs),
            "precision_vs_active": mean(precs_active),
        })

    # --- one-class, in both directions -------------------------------------
    #
    # Isolation Forest scores how easily a point is separated from the rest of
    # the training set. Fitted on one class only, it never sees the other, so
    # a high score here means the two classes are far apart in feature space
    # -- not that anything was learned about ransomware specifically.
    # --- one-class, in both directions -------------------------------------
    #
    # Isolation Forest returns a score that is high for points resembling the
    # training set and low for outliers. Fitted on one class only, it never
    # sees the other.
    #
    # Fitted on ransomware, this comes out inverted on the real data, and the
    # reason is worth stating rather than hiding: the method assumes the
    # fitted class is the compact one. Ransomware here is not. Activity spans
    # five hundred to two hundred thousand API calls across a hundred and
    # five families, while the benign set is a tight cluster of low values
    # sitting inside that spread. A point inside a dense cluster is hard to
    # isolate whatever the cluster is made of, so the benign rows score as
    # more typical of ransomware than most ransomware does.
    #
    # Reproduced deliberately: with a diffuse positive class and a compact
    # negative class placed inside it, the AUC goes to 0.00; placed outside
    # it, 1.00. The row is kept because a detector that scores confidently
    # backwards is a more useful thing to report than a missing line, and
    # because it says something about the shape of the ransomware class that
    # the supervised numbers do not.
    #
    # Orientation matters and is easy to get backwards. Fitted on benign, a
    # ransomware run should look anomalous, so the ransomware score is the
    # negated resemblance. Fitted on ransomware, a ransomware run should look
    # familiar, so it is the resemblance itself. The threshold has to follow
    # the same logic: flag what the fitted class rarely produces in the first
    # case, and what it commonly produces in the second.
    for direction, fit_on in [("one-class, fit on benign", 0),
                              ("one-class, fit on ransomware", 1)]:
        aucs, tprs, fps, fph = [], [], [], []
        for k, fam in enumerate(folds):
            train, test, test_pos, test_neg = split(k, fam)
            fit_idx = [i for i in train if y[i] == fit_on]
            if len(fit_idx) < 30 or not test_pos or len(test_neg) < 5:
                continue
            # The preprocessing is fitted on the whole training set; only
            # the forest sees one class.
            #
            # Fitting the imputer on one class as well looks natural and is
            # badly wrong. A missing value means the feature could not be
            # computed -- a program that touched no files has no read-to-write
            # ratio -- and the benign set is full of them. Imputing those with
            # the median of the ransomware training set rewrites every inert
            # benign row into the most typical ransomware run in the data, so
            # the detector scores them as more ransomware-like than ransomware
            # is. Done that way this row came out at an AUC of 0.198: not
            # uninformative, but confidently inverted.
            prep = make_pipeline(SimpleImputer(strategy="median"),
                                  StandardScaler())
            prep.fit(X[train])
            forest = IsolationForest(n_estimators=300, contamination=0.05,
                                      random_state=args.seed, n_jobs=4)
            forest.fit(prep.transform(X[fit_idx]))

            def ransomware_score(idx):
                """Higher always means more likely ransomware."""
                resembles_fitted = forest.score_samples(prep.transform(X[idx]))
                return -resembles_fitted if fit_on == 0 else resembles_fitted

            aucs.append(auc_score(list(y[test]), list(ransomware_score(test))))

            # An operating point that is not tuned on the test data: the
            # score exceeded by 5% of the fitted class. Fitted on benign that
            # is the top of the anomaly range; fitted on ransomware it is the
            # bottom of the resemblance range, and in both cases the
            # comparison is the same because the score was already oriented.
            fitted = ransomware_score(fit_idx)
            cut = float(np.percentile(fitted, 95 if fit_on == 0 else 5))

            tprs.append(float((ransomware_score(test_pos) >= cut).mean()))
            fps.append(float((ransomware_score(test_neg) >= cut).mean()))
            if hard_idx:
                fph.append(float((ransomware_score(hard_idx) >= cut).mean()))

        results.append({
            "approach": direction, "auc": mean(aucs), "tpr": mean(tprs),
            "fpr_benign": mean(fps), "fpr_hard": mean(fph),
            "precision_at_base_rate": float("nan"),
            "precision_vs_active": float("nan"),
        })

    head = (f"{'approach':<28}{'AUC':>8}{'TPR':>8}{'FP benign':>11}"
            f"{'FP hard':>9}{'prec/inert':>12}{'prec/active':>13}")
    print(head)
    print("-" * len(head))
    for r in results:
        def fmt(k):
            return "-" if math.isnan(r[k]) else f"{r[k]:.4f}"
        print(f"{r['approach']:<28}{r['auc']:>8.3f}{r['tpr']:>8.3f}"
              f"{r['fpr_benign']:>11.3f}{r['fpr_hard']:>9.3f}"
              f"{fmt('precision_at_base_rate'):>12}{fmt('precision_vs_active'):>13}")

    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader()
        for r in results:
            w.writerow({k: (f"{v:.4f}" if isinstance(v, float) else v)
                        for k, v in r.items()})
    print(f"\n[saved] {args.out}")

    print(f"\n  Both precision columns assume {args.base_rate:.1%} of programs are")
    print(f"  ransomware, against roughly half in these folds. 'prec/inert' uses")
    print(f"  the false positive rate on the benign set, four fifths of which")
    print(f"  never executed; 'prec/active' uses the rate on the hard negatives,")
    print(f"  which is what software that actually runs looks like. The AUC is")
    print(f"  identical in both cases.")
    print(f"\n  The two one-class rows never saw the other class. Where they")
    print(f"  reach the supervised score, the supervised model was not using")
    print(f"  its labels for anything the data did not already make obvious.")
    for r in results:
        if r["approach"].startswith("one-class") and r["auc"] < 0.4:
            print(f"\n  {r['approach']} scores below 0.5, which is not noise: it is")
            print(f"  the ranking inverted. Isolation Forest treats the fitted class")
            print(f"  as the compact one, and ransomware is the diffuse class here,")
            print(f"  with the benign cluster sitting inside its spread. Points in a")
            print(f"  tight cluster resist isolation, so benign reads as the more")
            print(f"  typical ransomware. The method is reporting the shape of the")
            print(f"  data, not a property of the samples.")


if __name__ == "__main__":
    main()
