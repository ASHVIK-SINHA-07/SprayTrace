# Evaluation Spec

The submitted report marks every performance cell **TBM (to be measured)**. The
job here is to replace them with real measurements. An honest low number beats a
fabricated high one — judges will ask how it was computed.

## Protocol

1. Split by whole `scenario_id` into train / validation / test.
2. Grid search on **validation only**: θB ∈ {5, 8, 12}, θU around 15, fusion
   weights `wi`, contamination ∈ {0.01, 0.02}, gate τ.
3. **Freeze** the configuration to `configs/thresholds.yaml`.
4. Report once on held-out test scenarios. No tuning after this point.

Reporting a number that was tuned on the same split it is measured on is the
single easiest way to lose credibility in questioning.

## Baseline

Naive per-user and per-IP failed-count thresholds — the "basic SIEM threshold"
from the report's alternatives table. This is what SprayTrace must beat, and the
reference for noise reduction.

## Ablation

| ID | Configuration |
|---|---|
| A | Brute force only |
| B | Spray only |
| C | Travel only |
| D | Isolation Forest only |
| E | Rules only (A+B+C) |
| F | Full fusion |

All on identical data, features and labels. Same-data ablation is the only valid
comparison — published numbers from other datasets differ in schema, labels and
protocol and are not SprayTrace results.

## Metrics

```
Precision      = TP / (TP + FP)
Recall         = TP / (TP + FN)
F1             = 2PR / (P + R)
Alert-to-TP    = total alerts / TP
Noise reduction % = (BaselineAlerts − SprayTraceAlerts) / BaselineAlerts × 100
```

Report per attack type as well as overall — a detector that nails spray and misses
travel entirely should not hide behind an average.

## Output

`docs/eval_results.md`, written by `src/scripts/evaluate.py`, with the frozen
config, the ablation table, per-type breakdown, and the raw event -> alert ->
campaign reduction for the headline `10,000 -> N` claim.

Also record **false negatives alongside alert reduction**. A gate that suppresses
a real low-score campaign is the report's own risk #2; surfacing it is the honest
move, and it reads as rigor rather than weakness.

## Known measurement artifact: travel false positives

Rules-only on the current dataset gives P=0.936 / R=1.000, and **every false
positive comes from `impossible_travel`**.

Cause: a planted travel attack puts the victim in an attacker city, but that
user's ordinary background traffic continues from their office. The detector
pairs the attacker login with the victim's next normal login and reports a real
impossible speed. Ground truth labels only the two planted events, so those
adjacent-but-genuine detections score as false positives.

This was deliberately **not** fixed by widening the labels. Relabelling benign
events as attacks until the metric improves is how synthetic evaluations become
meaningless -- the report's own risk #1. The number stands, and the artifact is
explained here and in `docs/eval_results.md`.

The honest reading: travel precision on *scenario* granularity is higher than the
event-level figure suggests, because these are correct detections against an
incomplete label. Report both, and say which is which.
