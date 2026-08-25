# Relational Ransomware Detection

Code and feature data for the study *Evaluating Behavioural Ransomware
Detection: Same-Target Event Relations and the Impact of Negative Set
Construction*.

The project runs ransomware and benign programs in a CAPEv2 sandbox, extracts
behavioural features from the reports, and trains a gradient-boosted tree
classifier. It looks at two things: how much a reported false positive rate
depends on how the benign set was assembled rather than on the detector itself,
and whether a feature describing the relation between two events on the same
file separates ransomware from benign software when a plain activity count no
longer can. The order experiment is a negative result, and the paper explains
why.

## Repository structure

```
src/
├── collection/          Gather and build what goes into the sandbox
│   ├── ransomware/       Pull samples from MalwareBazaar
│   ├── benign/           Fetch installers, filter PEs, generate decoy documents
│   ├── constructed/      Programs written to imitate part of ransomware's
│   │   ├── c/  go/  rust/    file activity: a designed grid across three
│   │   └── c_first_round/    toolchains, plus the earlier variant set
│   ├── sandbox/          CAPE health checks and retry selection
│   ├── manifest.py       Track collection by sha256
│   └── dedupe_manifests.py
│
├── analysis/            Read the reports the sandbox produced
│   ├── analyze_result.py        Verdict per run (executed? encrypted?)
│   ├── run_pipeline.py          analyze -> extract -> archive, end to end
│   ├── features/                Turn a report into feature columns
│   ├── ground_truth/            Check the verdicts against independent evidence
│   └── screening/               Check whether a feature measures what it seems to
│
└── modelling/           Build the dataset and train / evaluate the model
    ├── build_dataset.py
    ├── train_model.py
    ├── compare_models.py  join_grid.py  classify_failures.py
    └── make_figures.py

data/                    Feature tables and manifests (see data/README.md)
```

## Code overview

### Pipeline (report to model)

| Script | Role |
|---|---|
| `analysis/analyze_result.py` | Decides whether a CAPE analysis ran and whether it encrypted the planted decoy files. Labelling only — its verdict on benign software is out of domain and is never a detection result. |
| `analysis/features/extract_features.py` | Reads one report into the static, volume and destruction feature columns. |
| `analysis/features/explore_relational.py` | Computes the relational and sequence columns — quantities defined over two events on the same target (read/write overlap, read-to-write delay, per-file event shape, directory-walk regularity). This is the group the study's main claim rests on. |
| `analysis/features/behaviour_sequence.py` | Detects the 20 behaviour tokens and records, for each behaviour pair, the order in which they occurred. |
| `analysis/features/static_imports.py` | Import-table and crypto-string features from the PE. |
| `analysis/run_pipeline.py` | Runs `analyze_result` then `extract_features` over a directory of analyses and archives the raw report. |
| `modelling/build_dataset.py` | Joins the feature tables and settles the positive/negative definitions and the split. Everything downstream inherits these decisions. |
| `modelling/train_model.py` | Trains XGBoost under leave-one-family-out folds and takes the feature groups apart by ablation. Reports the false positive rate split by who wrote the negative. |
| `modelling/make_figures.py` | Produces the five figures in the paper. |

### Supporting analysis

`screening/` asks whether a candidate feature measures ransomware or merely
activity volume (`band_auc.py` re-measures inside narrow activity bands;
`compare_sources.py` contrasts against real software). `ground_truth/` checks
that the verdicts themselves are correct using evidence outside the event log —
`screenshot_diff.py` compares desktop screenshots before and after a run, and
`diagnose_victims.py` measures what happened to the decoy files.

### Building the negatives

`collection/constructed/` holds the programs written for this study. The grid
is compiled from one C source under three toolchains (`c/`, `go/`, `rust/`) so
that a result cannot be an artefact of the compiler; `verify_toolchains.sh`
confirms all three produce a Windows binary before `build_shape_grid.py` runs.
`c_first_round/` keeps the earlier variant set for the samples still present in
the held-out data.

## Main options

`train_model.py`:

| Option | Meaning |
|---|---|
| `--data` | Modelling CSV to train on |
| `--volume-shift K` | Train on runs opening fewer than K files, measure on K or more |
| `--negative-cv` | Rotate the negatives through five folds so every one is scored once |
| `--leave-one-out` | Leave-one-family-out cross-validation (the default protocol) |
| `--hard-out` | Write per-negative predicted probabilities for paired testing |

`build_dataset.py`:

| Option | Meaning |
|---|---|
| `--features-dir` | Directory holding `features*.csv` |
| `--relational` | The relational feature table (`rel_all.csv`) |
| `--behaviour` | The behaviour-token table |
| `--hardneg-names` | Name mapping for the constructed negatives |
| `--simple-split` | Train fraction for the simple split |

## Basic usage

Scripts read their data with paths relative to the repository, so run them from
their own directory.

```bash
# Build the main dataset from the feature tables
cd src/modelling
python3 build_dataset.py --features-dir ../../data \
    --relational ../../data/rel_all.csv \
    --hardneg-names ../../data/manifests/hardneg_names.csv \
    --simple-split 0.8 --out ../../data/modelling_simple.csv

# Train and run the group ablation
python3 train_model.py --data ../../data/modelling_simple.csv

# Reproduce the figures
python3 make_figures.py --modelling ../../data/modelling_cov.csv
```

## Workflow

```
CAPE report.json
      |  analyze_result.py        (verdict)
      |  extract_features.py      (static / volume / destruction)
      |  explore_relational.py    (relation / sequence)
      |  behaviour_sequence.py    (behaviour presence + order)
      v
build_dataset.py                  (join + define classes + split)
      v
train_model.py                    (leave-one-family-out, group ablation)
      v
make_figures.py
```

## Installation

```bash
pip install -r requirements.txt
```

Python 3.10+. Feature extraction reads CAPEv2 JSON reports; the sandbox itself
is not included. The constructed grid additionally needs `mingw-w64`, and
optionally Go and Rust with the `x86_64-pc-windows-gnu` target, to rebuild.

## License

MIT — see [LICENSE](LICENSE).
