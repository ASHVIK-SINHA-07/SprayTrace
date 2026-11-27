# Evaluation Results

Generated 2026-11-26 16:18 UTC. Protocol: whole-scenario split, train-fitted models, validation-only calibration, held-out test.

Full fusion uses the operating configuration in `configs/thresholds.yaml`.
The validation recommendation is written to that file only with `--freeze`.

## Operating configuration

```
theta_b        5
theta_u        12
weights        {'brute_force': 0.2, 'password_spray': 0.2, 'distributed_spray': 0.2, 'impossible_travel': 0.2, 'isolation_forest': 0.2}
rule_floor     {'brute_force': 0.45, 'password_spray': 0.45, 'distributed_spray': 0.45, 'impossible_travel': 0.41}
contamination  0.01
gate           {'critical': 0.8, 'high': 0.6, 'medium': 0.4}
```

## Validation recommendation

```
theta_b        5
theta_u        12
weights        {'brute_force': 0.2, 'password_spray': 0.2, 'distributed_spray': 0.2, 'impossible_travel': 0.2, 'isolation_forest': 0.2}
rule_floor     {'brute_force': 0.45, 'password_spray': 0.45, 'distributed_spray': 0.45, 'impossible_travel': 0.41}
contamination  0.01
gate           {'critical': 0.8, 'high': 0.6, 'medium': 0.4}
```

## Weighted-only ablation configuration

```
theta_b        5
theta_u        12
weights        {'brute_force': 0.45, 'password_spray': 0.1, 'distributed_spray': 0.25, 'impossible_travel': 0.1, 'isolation_forest': 0.1}
rule_floor     None
contamination  0.01
gate           {'critical': 0.8, 'high': 0.6, 'medium': 0.4}
```

Validation evaluated 540 combinations including gate cutoffs.

## Held-out ablation

| Configuration | Precision | Recall | F1 | Alerts | FP | FN | Alert-to-TP | Event-alert reduction |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Naive threshold baseline | 1.000 | 0.240 | 0.388 | 56 | 0 | 177 | 1.0 | — |
| A · Brute force only | 1.000 | 0.232 | 0.376 | 54 | 0 | 179 | 1.0 | — |
| B · Per-source spray only | 0.000 | 0.000 | 0.000 | 0 | 0 | 233 | — | — |
| B2 · Distributed spray only | 0.980 | 0.820 | 0.892 | 195 | 4 | 42 | 1.02 | — |
| C · Travel only | 0.727 | 0.034 | 0.066 | 11 | 3 | 225 | 1.38 | — |
| D · Isolation Forest only | 0.000 | 0.000 | 0.000 | 0 | 0 | 233 | — | — |
| E · Rules only | 0.971 | 1.000 | 0.985 | 240 | 7 | 0 | 1.03 | — |
| F · Full fusion | 0.971 | 1.000 | 0.985 | 240 | 7 | 0 | 1.03 | -328.6% |
| G · Tuned weighted fusion without rule floors | 1.000 | 0.232 | 0.376 | 54 | 0 | 179 | 1.0 | — |

## Recall by attack type

A scenario is detected when at least one labeled attack event crosses the gate.

| Attack type | Events detected | Events labeled | Event recall | Scenarios detected |
|---|---:|---:|---:|---:|
| brute_force | 54 | 54 | 1.000 | 3/3 |
| impossible_travel | 8 | 8 | 1.000 | 4/4 |
| password_spray | 171 | 171 | 1.000 | 2/2 |

## Event and campaign counts

**3,894 test events → 240 escalatable events → 5 campaigns.**

The baseline flags 56 events. Event-alert reduction uses event counts for both systems. The campaign count describes how SprayTrace groups its escalations for review.

## Gate sensitivity

| Risk cutoff | Event alerts | False negatives | Event-alert reduction vs baseline |
|---|---:|---:|---:|
| 0.35 | 240 | 0 | -328.6% |
| 0.40 | 240 | 0 | -328.6% |
| 0.45 | 240 | 0 | -328.6% |
| 0.60 | 239 | 0 | -326.8% |
| 0.80 | 155 | 78 | -176.8% |

## Measurement notes

- The Isolation Forest is fitted on train for both validation and test.
  Contamination changes the prediction offset. The scores used in fusion
  are derived from `score_samples`, which is independent of that offset.
- A benign sign-in adjacent to a planted impossible-travel pair may also
  imply impossible speed and count as an event-level false positive.
- These measurements describe the generated scenarios and labels.
