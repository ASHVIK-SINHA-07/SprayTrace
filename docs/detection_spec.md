# Detection Spec

Authoritative. Values come from the Final Technical Report (1 Oct 2026) submitted to
judges. Where `instructions.md` disagrees, this file wins.

## Detectors

| Detector | Grouping / window | Statistic | Trigger | ATT&CK |
|---|---|---|---|---|
| Brute force | failed, by `(username, source_ip)`, 5-min rolling | `B` = failed count | `B > θB`, θB candidates {5, 8, 12} | T1110.001 |
| Password spray | failed, by `source_ip`, 1-hour window | `U` distinct users, `A` attempts, `S = U/A` | `U > θU` (15) **and** `A/U <= 3` | T1110.003 |
| Impossible travel | per user, consecutive successes by time | haversine `d`, implied `v = d/Δt` | `v > 1000` km/h | T1078 |
| Isolation Forest | per user/session feature vector | `a(x) = -score_samples(x)` rescaled | no standalone alert, contributes `I` | — |

### SprayScore

```
S = U / A            # A/U = mean failures per targeted account, so S = 1 / mean attempts
S -> 1   many accounts barely tried   (spray-like)
S -> 0   few accounts hammered        (brute-force-like)
```

A single failed login gives `U/A = 1`, so **S is only meaningful alongside the
breadth condition `U > θU`**. Never fire spray on S alone.

### Haversine / implied speed

```
a = sin²(Δφ/2) + cos φ1 · cos φ2 · sin²(Δλ/2)
c = 2 · atan2(√a, √(1−a))
d = R · c                     R = 6371 km
v = d / Δt(hours)             flag if v > 1000 km/h
```

Guards: require `Δt > 0`; skip identical or missing coordinates. Commercial flight
is ~900 km/h, so 1000 is the boundary — legitimate travel must stay below it.

### Cyclic hour encoding

```
hour_sin = sin(2π · hour / 24)
hour_cos = cos(2π · hour / 24)      # keeps 23:00 and 01:00 adjacent
```

## Isolation Forest

- Features: failed attempts in last hour, distinct IPs, distinct countries,
  `hour_sin`, `hour_cos`, device/user-agent change flag.
- `IsolationForest(n_estimators=100, contamination=0.01, random_state=42)`;
  evaluate 0.02 as well.
- Rescale `a(x)` to [0,1] with training-window percentiles: 50th -> 0,
  99.9th -> 1, clipped. Version the constants with the model.
- The raw score is **not** a probability of maliciousness. `contamination` only
  sets the offset used by `predict()`; the rescaled `score_samples` path used here
  does not depend on it.

## Fusion

```
R = w1·B + w2·S + w3·T + w4·I        Σ wi = 1,  each component scaled to [0,1]
```

B and T are binary flags (or graded by margin over threshold). S is graded by
SprayScore once the breadth condition holds.

**Calibration constraint.** Because `Σ wi = 1`, a single detector can lift R above
0.40 on its own only if its weight exceeds 0.40. Equal weights (0.25 each) would
therefore *suppress an incident that only one rule detects*, even at maximum
strength. Weights are chosen by grid search on validation data — not fixed in
advance. Also evaluate a **rule-floor variant** (a fired rule guarantees a minimum
R) as an ablation.

## Decision gate

| Tier | Risk | Action |
|---|---|---|
| Critical | `R >= 0.80` | auto-escalate with evidence |
| High | `0.60 <= R < 0.80` | auto-escalate |
| Medium | `0.40 <= R < 0.60` | analyst review queue |
| Low | `R < 0.40` | suppressed internally; audit log only, no analyst/end-user contact |

τ values (0.40 / 0.60 / 0.80) are **operating policy**, to be validated on labeled
hold-out data — not universal security thresholds. Sweep them in evaluation and
report false negatives next to alert reduction.

## Campaign reconstruction

Group escalatable events (`R >= 0.40`) sharing source, time window and target set
into one campaign. Campaign evidence (breadth, time span, success after failures)
refines the incident *after* fusion.

Evidence text is rendered from rule evidence, e.g.:

> 84 failed attempts across 42 distinct usernames (2.0 per account, SprayScore
> 0.50) from 203.0.113.7 within 37 minutes — consistent with password spraying
> (T1110.003).

## Worked examples (regression fixtures)

| Case | Inputs | Expected |
|---|---|---|
| Spray | 1 IP, 42 usernames, 2 failures each, 37 min (A=84) | U=42, A/U=2.0, S=0.50 -> spray fires |
| Brute force | 1 username, 1 IP, 12 failures in 5 min | B=12 > 8, S=1/12=0.083 -> brute fires, spray does not |
| Impossible travel | Delhi (28.614, 77.209) -> London (51.507, −0.128), 3 h | d≈6711 km, v≈2237 km/h -> flagged |
| Legitimate travel | same pair, 8.5 h apart | v≈790 km/h -> not flagged |

These four belong in `src/tests/` as asserted test cases.

## NAT awareness

IP is one contextual feature, never identity. Spray flags require breadth across
many usernames and are checked against device/user-agent context. Rotating-IP
attackers are addressed by correlating target set and time rather than IP alone.
