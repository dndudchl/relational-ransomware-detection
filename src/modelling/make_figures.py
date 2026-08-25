#!/usr/bin/env python3
"""
make_figures.py - The five figures the final results need.

Why a third script. The first set argued that the detector was measuring
activity rather than encryption, which is no longer true. The second set was
drawn before the installer batch, when 6 pieces of real software opened 50 or
more files rather than 115, and before the order result turned negative. Both
carry arguments the thesis no longer makes, so neither can be reused by
swapping numbers.

The five here, and what each has to carry:

  1  saturation      the false positive rate is a property of the negative
                     set: 0.667 to 0.000 with the feature set untouched.
                     Confidence intervals are drawn because the held-out
                     part shrinks as training grows, and the right-hand end
                     rests on 310 programs.

  2  volume shift    at one cut, every feature group, split by who wrote the
                     negative. The 51 programs other people wrote are drawn
                     separately from the 910 we built, because pooling them
                     is the mistake this thesis is about.

  3  cut sweep       the same experiment at five cuts. Volume never
                     recovers; everything else improves by an order of
                     magnitude. This is what stops "why 300?" being a
                     question the reader has to ask.

  4  order coverage  the structural finding, and the one figure that has to
                     work on its own: 86 behaviour pairs plotted by how
                     often each is measurable in ransomware against how
                     often in benign software. Everything sits against the
                     left edge. Order cannot be measured where the
                     combination has already separated the classes.

  5  trade-off       recall on ransomware that never encrypted against
                     false positives on real software. The two move
                     together, and the thesis reports the trade rather than
                     choosing a side.

Usage
-----
  python3 make_figures.py --outdir ~/work/figures_v3 \\
      --modelling ~/work/modelling_cov.csv \\
      --behaviour ~/work/features_behaviour.csv \\
      --names ~/work/hardneg_names.csv

Figures 1, 3 and 5 are drawn from measurements that live in several run logs
rather than one file, so their numbers are defaults in the source and can be
overridden on the command line. Figures 2 and 4 are computed from the CSVs.
"""

import os
import csv
import math
import argparse
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

INK, MID, LIGHT = "#1a1a1a", "#8a8a8a", "#d4d4d4"
ACCENT, ACCENT2, ACCENT3 = "#b03030", "#2f5d8a", "#6b8f3a"

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 9,
    "axes.edgecolor": MID, "axes.linewidth": 0.8,
    "axes.labelcolor": INK, "text.color": INK,
    "xtick.color": INK, "ytick.color": INK,
    "axes.spines.top": False, "axes.spines.right": False,
    "figure.dpi": 150, "savefig.dpi": 300, "savefig.bbox": "tight",
})


def wilson(h, n, z=1.96):
    if n == 0:
        return 0.0, 0.0, 0.0
    p = h / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - half), min(1.0, c + half)


def read(path):
    with open(os.path.expanduser(path), newline="") as f:
        return list(csv.DictReader(f))


# ----------------------------------------------------------------- figure 1

# training negatives, kinds, held-out n, flagged
SATURATION = [(0, 0, 1975, 1317), (285, 129, 2406, 433), (782, 408, 1909, 32),
              (1403, 676, 1288, 6), (1901, 985, 790, 2), (2381, 1253, 310, 0)]


def fig_saturation(points, outdir):
    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    xs = [p[0] for p in points]
    rates, los, his = [], [], []
    for _, _, n, h in points:
        p, lo, hi = wilson(h, n)
        rates.append(p); los.append(lo); his.append(hi)

    ax.fill_between(xs, los, his, color=ACCENT, alpha=0.15, linewidth=0)
    ax.plot(xs, rates, "-o", color=ACCENT, lw=1.6, ms=6)

    for (x, k, n, h), r in zip(points, rates):
        ax.annotate(f"{r:.3f}\n{h:,} of {n:,}", xy=(x, r), xytext=(7, 9),
                    textcoords="offset points", fontsize=7.5, color=INK)

    ax.set_xlabel("active negatives in training")
    ax.set_ylabel("false positives, held-out negatives\n(lower is better)")
    ax.set_ylim(-0.04, max(his) * 1.18)
    ax.annotate("feature set unchanged throughout", xy=(0.98, 0.92),
                xycoords="axes fraction", ha="right", fontsize=8, color=MID)
    out = os.path.join(outdir, "fig1_saturation.png")
    fig.savefig(out); plt.close(fig)
    return out


# ----------------------------------------------------------------- figure 2

def fig_volume_shift(scores_path, modelling_path, outdir):
    """Per-group false positives at one cut, split by who wrote the negative."""
    K = {r["sample_id"]: r.get("klass", "") for r in read(modelling_path)}
    rows = read(scores_path)
    if not rows:
        return None
    groups = [("static alone", "static"), ("volume alone", "volume"),
              ("sequence alone", "sequence"), ("relation alone", "relation"),
              ("behaviour alone", "behaviour"), ("order: behav", "order"),
              ("A+S1", "behaviour + relation")]
    have = set(rows[0].keys())
    groups = [(c, lbl) for c, lbl in groups if c in have]

    def rate(col, kind):
        sel = [r for r in rows if K.get(r["sample_id"]) == kind]
        h = sum(1 for r in sel
                if r.get(col) not in (None, "") and float(r[col]) >= 0.5)
        return h, len(sel)

    # Ordered by the rate on software other people wrote, because that is the
    # column the thesis quotes. Sorting by the constructed column instead
    # would put the groups in a different order from the text.
    groups.sort(key=lambda g: -(rate(g[0], "benign_active")[0] /
                                max(1, rate(g[0], "benign_active")[1])))

    fig, ax = plt.subplots(figsize=(7.4, 4.2))
    y = range(len(groups))
    h = 0.36
    real, cons, counts = [], [], []
    for col, _ in groups:
        hr, nr = rate(col, "benign_active")
        hc, nc = rate(col, "constructed")
        real.append(hr / nr if nr else 0)
        cons.append(hc / nc if nc else 0)
        counts.append((hr, nr, hc, nc))

    nr0, nc0 = counts[0][1], counts[0][3]
    ax.barh([i + h/2 for i in y], real, height=h, color=ACCENT,
            label=f"software others wrote (n={nr0})")
    ax.barh([i - h/2 for i in y], cons, height=h, color=LIGHT,
            label=f"our constructed samples (n={nc0:,})")

    ax.set_yticks(list(y))
    ax.set_yticklabels([lbl for _, lbl in groups], fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel("false positive rate (lower is better)")
    ax.set_xlim(0, max(max(real), max(cons)) * 1.34)
    # Counts, not only rates: 0.059 of 51 is three programs and 0.029 of 910
    # is twenty-six, and the bars alone give those equal visual weight.
    for i, ((hr, nr, hc, nc), a, b) in enumerate(zip(counts, real, cons)):
        ax.text(a + 0.007, i + h/2, f"{a:.3f}   {hr}/{nr}",
                va="center", fontsize=7.5)
        ax.text(b + 0.007, i - h/2, f"{b:.3f}   {hc}/{nc:,}",
                va="center", fontsize=7.5, color=INK)
    # The point of the figure is that volume is in a different régime, so it
    # is marked rather than left for the reader to find.
    for i, (_, lbl) in enumerate(groups):
        if lbl == "volume":
            ax.axhspan(i - 0.5, i + 0.5, color=ACCENT, alpha=0.06, zorder=0)
    ax.legend(loc="lower right", frameon=False, fontsize=8)
    out = os.path.join(outdir, "fig2_volume_shift.png")
    fig.savefig(out); plt.close(fig)
    return out


# ----------------------------------------------------------------- figure 3

# Which column in the score files backs each line in figure 3.
CUT_LINES = [
    ("volume", "volume alone"),
    ("sequence", "sequence alone"),
    ("order", "order: behav"),
    ("relation", "relation alone"),
    ("behaviour + relation + order", "A+S1+S2"),
]
# Evenly spaced, and stopping at 500 because the number of programs other
# people wrote falls from 51 at the 300 cut to 24 at 800, too few to break
# the rate down by who wrote the sample.
CUT_VALUES = (150, 200, 300, 500, 800)


def load_cuts(pattern, cuts=CUT_VALUES):
    """
    Read each cut's rates straight from its per-sample score file, under the
    protocol in Part I: flagged at 0.5, denominator every measured negative.
    Reading rather than transcribing keeps this figure and the robustness
    table from drifting apart, which they did once already.
    """
    out = []
    for cut in cuts:
        path = os.path.expanduser(pattern.format(cut=cut))
        if not os.path.exists(path):
            continue
        rows = read(path)
        if not rows:
            continue
        rates = {}
        for label, col in CUT_LINES:
            if col not in rows[0]:
                continue
            h = sum(1 for r in rows
                    if r.get(col) not in (None, "") and float(r[col]) >= 0.5)
            rates[label] = h / len(rows)
        out.append((cut, len(rows), rates))
    return out


def fig_cut_sweep(cuts, outdir):
    fig, ax = plt.subplots(figsize=(6.8, 4.4))
    # Categorical spacing: the cuts are 150, 200, 300, 500, 800, and on a
    # linear axis the first two collide while the last two leave a gap that
    # means nothing. What matters is the ordering, not the arithmetic.
    xs = list(range(len(cuts)))
    # Five lines, not seven. Figure 2 already ranks all the groups at one
    # cut; this figure asks only whether that ranking survives the choice of
    # cut, and seven overlapping lines answered it less clearly than five.
    # sequence and order are both kept because the gap between them is the
    # second point the figure makes: API-level order and behaviour-level
    # order are not the same claim.
    # relation and the combined set coincide exactly at the two highest cuts
    # (1/816 and 2/574), so a solid line for each would hide one of them.
    # relation is dashed and drawn last; where the two agree the black shows
    # through the gaps.
    styles = {
        "volume": (ACCENT, "-o", 2.2),
        "sequence": (MID, "--v", 1.3),
        "order": (ACCENT3, "-^", 1.5),
        "behaviour + relation + order": (INK, "-s", 1.8),
        "relation": (ACCENT2, "--o", 1.6),
    }
    # A rate of exactly zero cannot be placed on a log axis, and matplotlib
    # draws the segment running off the bottom of the plot rather than
    # omitting it. Zeros are put on a floor below the smallest real value and
    # marked hollow, so the reader can see that the point is "none observed"
    # and not a measured rate.
    seen = [v for c in cuts for v in c[2].values() if v]
    floor = (min(seen) / 2.2) if seen else 1e-4
    for name, (colour, style, lw) in styles.items():
        raw = [c[2].get(name) for c in cuts]
        if any(v is None for v in raw):
            continue
        ys = [v if v else floor for v in raw]
        ax.plot(xs, ys, style, color=colour, lw=lw, ms=4, label=name)
        for x, v, y in zip(xs, raw, ys):
            if not v:
                ax.plot(x, y, "o", ms=7, mfc="white", mec=colour, mew=1.4,
                        zorder=5)

    ax.set_yscale("log")
    ax.set_ylim(floor / 1.6, None)
    ax.set_xlabel("files opened: training below the cut, measurement at or above")
    ax.set_ylabel("false positives, log scale (lower is better)")
    ax.set_xticks(xs)
    ax.set_xticklabels([f"{c[0]}\nn={c[1]:,}" for c in cuts], fontsize=8)
    ax.set_xlim(-0.25, len(cuts) - 0.75)
    ax.legend(frameon=False, fontsize=8, ncol=3, loc="upper center",
              bbox_to_anchor=(0.5, -0.20))
    out = os.path.join(outdir, "fig3_cut_sweep.png")
    fig.savefig(out); plt.close(fig)
    return out


# ----------------------------------------------------------------- figure 4

def fig_order_coverage(behaviour_path, modelling_path, names_path, outdir):
    """
    Each behaviour pair placed by how often its order is *measurable* in each
    class. A pair is measurable only when both behaviours occurred, so a
    point near the left edge is a pair whose order cannot be asked about in
    benign software at all -- which is most of them.
    """
    import re
    K = {r["sample_id"]: r.get("klass", "") for r in read(modelling_path)}
    rows = read(behaviour_path)
    if not rows:
        return None
    ordc = [c for c in rows[0] if c.startswith("ord_")]
    pos = [r for r in rows if K.get(r["task_id"]) == "ransomware"]
    neg = [r for r in rows if K.get(r["task_id"]) == "benign_active"]
    if not pos or not neg:
        return None

    pts = []
    for c in ordc:
        cp = sum(1 for r in pos if r[c] != "") / len(pos)
        cn = sum(1 for r in neg if r[c] != "") / len(neg)
        if cp >= 0.10:
            pts.append((cn, cp, c))
    if not pts:
        return None

    fig, ax = plt.subplots(figsize=(6.2, 4.2))
    lim = max(max(p[0] for p in pts), max(p[1] for p in pts)) * 1.08
    ax.plot([0, lim], [0, lim], color=LIGHT, lw=1)
    ax.axvline(0.10, color=MID, lw=0.8, ls=":")

    for cn, cp, c in pts:
        live = cn >= 0.10
        ax.plot(cn, cp, "o", ms=6 if live else 4,
                color=ACCENT if live else MID, alpha=1.0 if live else 0.45)
        if live:
            ax.annotate(c.replace("ord_", "").replace("_", " → "),
                        xy=(cn, cp), xytext=(9, -2),
                        textcoords="offset points", fontsize=8, color=INK)

    n_live = sum(1 for p in pts if p[0] >= 0.10)
    print(f"    [fig4] {len(pts)} pairs, {n_live} measurable in both classes")
    ax.set_xlabel("share of benign software where the pair is measurable")
    ax.set_ylabel("share of ransomware where the pair is measurable")
    ax.set_xlim(-0.01, lim); ax.set_ylim(0, lim)
    out = os.path.join(outdir, "fig4_order_coverage.png")
    fig.savefig(out); plt.close(fig)
    return out


# ----------------------------------------------------------------- figure 5

# label, false positives on real software, recall on non-encrypting ransomware
# Reader-facing names. A, A_generic and the S1/S2 shorthand are internal
# labels and appear nowhere in the paper, so a legend using them would be
# unreadable.
TRADE = [
    ("behaviour", .0484, .546),
    ("behaviour + relation", .0706, .613),
    ("behaviour + relation + order", .0725, .619),
    ("domain-free", .0861, .742),
    ("domain-free + relation + order", .0793, .765),
]


def fig_tradeoff(points, outdir):
    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    xs = [p[1] for p in points]
    ys = [p[2] for p in points]
    # No connecting line: the five feature sets are not a path anyone walks,
    # and drawing one in list order produced a zigzag that implied a
    # trajectory. The frontier is what matters, so only that is drawn.
    front, best = [], -1
    for label, x, y in sorted(points, key=lambda t: t[1]):
        if y > best:
            front.append((x, y)); best = y
    ax.plot([p[0] for p in front], [p[1] for p in front], "-",
            color=LIGHT, lw=1.2, zorder=1)
    ax.scatter(xs, ys, s=170, color=ACCENT, zorder=2)
    # Labels alternate above and below so the two points 0.002 apart on the
    # x axis do not collide.
    # Numbered rather than labelled in place. Five points with labels up to
    # thirty characters cannot be placed without one crossing another or its
    # own marker; the numbers sit clear of the markers and the key carries
    # the names.
    for i, (label, x, y) in enumerate(points, 1):
        ax.annotate(str(i), xy=(x, y), xytext=(0, 0), ha="center",
                    va="center", textcoords="offset points",
                    fontsize=8, color="white", weight="bold", zorder=3)
    key = "\n".join(f"{i}  {label}" for i, (label, _, _) in
                     enumerate(points, 1))
    # Top left: every point sits on the diagonal from bottom-left to
    # top-right, so that corner is the only region the key cannot cross.
    ax.annotate(key, xy=(0.03, 0.97), xycoords="axes fraction",
                ha="left", va="top", fontsize=8.5, linespacing=1.5)

    ax.set_xlabel("false positives on software others wrote (n = 1,034)")
    ax.set_ylabel("recall on ransomware that never encrypted (n = 722)")
    # From zero on the false positive axis. The five points span 0.048 to
    # 0.086, and a zoomed axis makes a difference of forty programs in a
    # thousand look like a cliff.
    ax.set_xlim(0, max(xs) * 1.18)
    ax.set_ylim(min(ys) - 0.07, max(ys) + 0.07)
    out = os.path.join(outdir, "fig5_tradeoff.png")
    fig.savefig(out); plt.close(fig)
    return out


# ---------------------------------------------------------------------- main

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--outdir", default="~/work/figures_v3")
    p.add_argument("--modelling", default="~/work/modelling_cov.csv")
    p.add_argument("--behaviour", default="~/work/features_behaviour.csv")
    p.add_argument("--names", default="~/work/hardneg_names.csv")
    p.add_argument("--shift-scores", default="/tmp/vsgrp_300.csv")
    p.add_argument("--shift-pattern", default="/tmp/vsgrp_{cut}.csv",
                   help="Per-sample score file for each cut, {cut} substituted")
    args = p.parse_args()

    outdir = os.path.expanduser(args.outdir)
    os.makedirs(outdir, exist_ok=True)
    made = []

    for fn in (lambda: fig_saturation(SATURATION, outdir),
               lambda: fig_volume_shift(args.shift_scores, args.modelling, outdir),
               lambda: fig_cut_sweep(load_cuts(args.shift_pattern), outdir),
               lambda: fig_order_coverage(args.behaviour, args.modelling,
                                          args.names, outdir),
               lambda: fig_tradeoff(TRADE, outdir)):
        try:
            f = fn()
            if f:
                made.append(f)
        except Exception as e:
            print(f"[skip] {type(e).__name__}: {e}")

    for f in made:
        print(f"[saved] {f}")


if __name__ == "__main__":
    main()
