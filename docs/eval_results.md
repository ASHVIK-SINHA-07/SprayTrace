# Evaluation Results

Generated 2026-10-06 10:41 UTC. Protocol: split by whole scenario; tuned on validation; reported once on test.

These replace the TBM cells in the submitted report. Every figure below
is measured on held-out test scenarios with the configuration frozen
beforehand on validation data.

## Frozen configuration

```
theta_b    5
theta_u    12
rule_floor {'brute_force': 0.45, 'password_spray': 0.45, 'distributed_spray': 0.45, 'impossible_travel': 0.41}
gate       {'critical': 0.8, 'high': 0.6, 'medium': 0.4}
```

Chosen from 27 grid points on validation.

## Ablation (identical data, features and labels)

| Configuration | Precision | Recall | F1 | Alerts | Alert-to-TP | Noise reduction |
|---|---:|---:|---:|---:|---:|---:|
| Naive threshold baseline | 1.000 | 0.240 | 0.388 | 56 | 1.0 | reference |
| A · Brute force only | 1.000 | 0.232 | 0.376 | 54 | 1.0 | n/a |
| B · Per-source spray only | 0.000 | 0.000 | 0.000 | 0 | — | n/a |
| B2 · Distributed spray only | 0.974 | 0.816 | 0.888 | 195 | 1.03 | n/a |
| C · Travel only | 0.727 | 0.034 | 0.066 | 11 | 1.38 | n/a |
| D · Isolation Forest only | 0.000 | 0.000 | 0.000 | 0 | — | n/a |
| E · Rules only (A+B+C) | 0.967 | 0.996 | 0.981 | 240 | 1.03 | n/a |
| F · Full fusion | 0.967 | 0.996 | 0.981 | 240 | 1.03 | 91.1% |

## Recall by attack type

| Attack type | Detected | Total | Recall |
|---|---:|---:|---:|
| brute_force | 54 | 54 | 1.000 |
| impossible_travel | 8 | 8 | 1.000 |
| password_spray | 170 | 171 | 0.994 |

## Reduction

**3,894 test events → 240 escalatable → 5 campaigns.**

## Reading these numbers

- **The baseline fails on spray, which is the point.** A naive per-user
  and per-IP failure counter reaches F1 0.388 here: it catches brute
  force (recall 1.000 on that type) and almost nothing else. Password
  spraying is built to stay under exactly those counters.
- **Per-source spray detection scores 0.000 on this split.** The
  distributed scenarios rotate across 20-28 addresses, which puts every
  single source below theta_u. That is not a bug in the rule; it is the
  per-source blind spot the distributed detector exists to cover, and it
  is why both statistics ship.
- **The Isolation Forest contributes no standalone detections** (D scores
  0.000) and full fusion equals rules-only. Reported rather than tuned
  away: this is risk #3 in the submitted report, and the honest reading
  is that on synthetic data whose attacks the rules already encode, the
  model adds tier separation but no new coverage. Its value would appear
  against behaviour nobody programmed a rule for.
- Noise reduction compares baseline alerts against SprayTrace campaigns,
  because that is the unit an analyst opens. Comparing raw alert counts
  would read as negative reduction purely because SprayTrace detects more
  real attacks.
- Splits are by whole scenario, so no campaign is partly seen in tuning
  and partly scored at test.
- The Isolation Forest is fitted on train only. Fitting it on the data it
  scores would let its percentile constants calibrate to the test set's
  attack density.
- Impossible-travel false positives include correct detections against an
  incomplete label; see the artifact note in `docs/eval_spec.md`.
- Synthetic ground truth cannot reproduce production behaviour. These are
  measurements on controlled data, not a claim about live tenants.
