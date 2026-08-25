# Data

Feature tables and manifests for the experiments. Raw CAPE reports and sample
binaries are not included; these are the extracted features the modelling reads.

## Files

| File | Rows | What it is |
|---|---|---|
| `features.csv` | 3,456 | Static, volume and destruction features for the ransomware runs |
| `features_benign.csv` | 1,564 | The same features for the DikeDataset benign corpus |
| `features_hardneg.csv` | 2,000 | The same features for the constructed negatives and other-authored software |
| `rel_all.csv` | 7,018 | Relational and sequence features for every run, all sources combined |
| `features_beh_cov.csv` | 7,017 | Behaviour-token table used to build the cross-validation dataset |
| `modelling_simple.csv` | 4,540 | Main dataset (Fig. 1, Fig. 2, Table III) |
| `modelling_cov.csv` | 4,540 | Dataset for negative cross-validation (Table IV, Section IV-H) |
| `manifests/` | — | Collection and tracking records (see below) |

`manifests/manifest_all.csv` is the combined collection log by sha256;
`hardneg_names.csv` maps the constructed negatives to their names;
`inst_manifest.csv` and `repos_found.csv` record which installers were fetched.

## The `source` column

`build_dataset.py` and `train_model.py` read a `source` column with three
values: `ransomware`, `benign` and `hardneg`. Note that this does **not** line
up one-to-one with the sample classes in the paper (Table II):

- `ransomware` — the encrypting runs (1,849).
- `benign` — the DikeDataset corpus only (716).
- `hardneg` — the constructed grid and scripts (1,657) **together with** the
  318 other-authored programs (installers, Sysinternals, documents).

So the paper's **benign, active** class (1,034) is the `benign` rows plus the
318 other-authored rows that sit inside `hardneg`; the paper's **constructed**
class (1,657) is the rest of `hardneg`. The names differ because the code
labels a negative by how it was handled in training, while the paper labels it
by who wrote it.

## Reproducing the modelling tables

Run from `src/modelling/`:

```bash
# modelling_simple.csv — the main dataset
python3 build_dataset.py --features-dir ../../data \
    --relational ../../data/rel_all.csv \
    --hardneg-names ../../data/manifests/hardneg_names.csv \
    --simple-split 0.8 --out ../../data/modelling_simple.csv

# modelling_cov.csv — adds the behaviour table for cross-validation
python3 build_dataset.py --features-dir ../../data \
    --relational ../../data/rel_all.csv \
    --behaviour ../../data/features_beh_cov.csv \
    --hardneg-names ../../data/manifests/hardneg_names.csv \
    --simple-split 0.8 --out ../../data/modelling_cov.csv
```

The order experiment (Section IV-E) is a negative result — order adds nothing
beyond behaviour presence — and its intermediate tables are not shipped here;
see the paper for the figures and the reasoning.
