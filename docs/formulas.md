# Mathematical and Statistical Formulas

Every formula SprayTrace computes, in one place, with the source file that
implements it and the configured constant it uses.

Constants are read from [configs/thresholds.yaml](../configs/thresholds.yaml) at
runtime — nothing below is hard-coded in the detectors. Thresholds were frozen on
validation data before the test measurement; see [eval_spec.md](eval_spec.md).

Notation: an *event* is one authentication attempt. A *window* is a trailing or
tumbling time interval. `𝟙[·]` is the indicator function (1 if true, 0 if false).

---

## 1 · Notation and base quantities

For a set of events `E` inside a window:

| Symbol | Definition | Meaning |
|---|---|---|
| `A` | `A = \|{e ∈ E : ¬success(e)}\|` | total failed attempts |
| `U` | `U = \|{username(e) : e ∈ E, ¬success(e)}\|` | distinct accounts targeted |
| `P` | `P = \|{source_ip(e) : e ∈ E, ¬success(e)}\|` | distinct source addresses |
| `B` | failures in a 5-min window for one `(username, source_ip)` | brute-force count |

---

## 2 · Brute force — T1110.001

**Implementation:** [`detect_brute_force`](../src/backend/detection.py#L26)

Group failures by `(username, source_ip)`. Over a trailing window `W = 5 min`,
compute the rolling count at each event `t`:

```
B(t) = Σ_{e ∈ failures}  𝟙[ t − W  <  timestamp(e)  ≤  t ]
```

**Trigger condition**

```
fire  ⟺  max_t B(t) > θ_B                    θ_B = 5
```

**Confidence score** — graded by margin over the threshold, so a 20-failure burst
outranks a 9-failure one:

```
                   B_peak − θ_B
score  =  min( 1,  ──────────────  +  0.5 )
                   max(θ_B, 1)
```

At `B_peak = θ_B + 1` the score is `0.5 + 1/5 = 0.70`; it saturates at `B_peak ≥ 3θ_B = 15`.

---

## 3 · Password spray, per source — T1110.003

**Implementation:** [`detect_password_spray`](../src/backend/detection.py#L84)

Group failures by `source_ip` into tumbling windows of `W = 60 min`. Each window
is evaluated twice — at offset `0` and at offset `W/2 = 30 min` — so a campaign
straddling a bin boundary is not split below the threshold.

### SprayScore

```
        U        distinct accounts targeted
S  =  ─────  =  ────────────────────────────
        A           total failed attempts
```

Equivalently, since `A/U` is the mean attempts per targeted account:

```
        1
S  =  ─────────────
      mean attempts
```

| `S` | Shape | Reading |
|---|---|---|
| `S → 1` | many accounts, ~1 try each | spray-like |
| `S → 0` | few accounts, many tries | brute-force-like |

**The breadth guard is load-bearing.** A single failed login gives `U = A = 1`,
hence `S = 1.0` — the maximum. So `S` is never evaluated alone:

```
fire  ⟺  U > θ_U   ∧   A/U  ≤  m
```

with `θ_U = 12` (breadth) and `m = 3` max attempts per user (shallowness).

**Confidence score** — driven by how far breadth exceeds the threshold:

```
                              U − θ_U
score  =  min( 1,  0.6 + 0.4 · ───────── )     clipped to [0.6, 1.0]
                                θ_U
```

Saturates at `U ≥ 2θ_U = 24`.

---

## 4 · Distributed spray — T1110.003

**Implementation:** [`detect_distributed_spray`](../src/backend/detection.py#L148)

The key structural difference: **`source_ip` is not in the grouping key.** Any
statistic computed per source can be defeated by spreading across sources. This
detector groups by *time window alone* and asks a question rotation cannot evade.

```
fire  ⟺  U ≥ U_min  ∧  P ≥ P_min  ∧  A/U ≤ m_u  ∧  A/P ≤ m_p
```

| Constant | Value | Role |
|---|---|---|
| `U_min` | 25 | breadth across accounts |
| `P_min` | 8 | breadth across sources |
| `m_u` | 3 | each account barely touched |
| `m_p` | 12 | each source individually unremarkable |

The last condition is what keeps it from double-reporting ordinary noisy traffic:
if one source exceeds it, the per-source rule already covers that case.

**Confidence score** — driven by source breadth:

```
                                  P
score  =  min( 1,  0.55 + 0.45 · ────── )      clipped to [0.55, 1.0]
                                 2·P_min
```

---

## 5 · Impossible travel — T1078

**Implementation:** [`detect_impossible_travel`](../src/backend/detection.py#L228),
[`src/backend/geo.py`](../src/backend/geo.py)

Per user, sort successful logins by time and test each consecutive pair.

### Haversine great-circle distance

For coordinates `(φ₁, λ₁)` and `(φ₂, λ₂)` in radians:

```
a  =  sin²( Δφ / 2 )  +  cos φ₁ · cos φ₂ · sin²( Δλ / 2 )

c  =  2 · atan2( √a , √(1 − a) )

d  =  R · c                                    R = 6371 km
```

### Implied speed

```
       d
v  =  ────                 Δt in hours
       Δt
```

**Trigger condition**

```
fire  ⟺  v  >  v_max                           v_max = 1000 km/h
```

Guards: require `Δt > 0`; skip pairs with missing coordinates. Commercial cruise
is ~900 km/h, so 1000 km/h is the boundary — legitimate travel stays below it.

**Confidence score**

```
                                v − v_max
score  =  min( 1,  0.7 + 0.3 · ─────────── )   clipped to [0.7, 1.0]
                                 2·v_max
```

**Worked example.** Delhi `(28.614, 77.209)` → London `(51.507, −0.128)`, 3 h apart:
`d ≈ 6711 km`, `v ≈ 2237 km/h` → fires. The same pair 8.5 h apart: `v ≈ 790 km/h` → does not.

---

## 6 · Behavioural features for the anomaly model

**Implementation:** [`src/backend/features.py`](../src/backend/features.py)

Six features per event, all computed **per user** and **strictly backward-looking** —
an event may use its own history but never its future, so the frame cannot leak
information a live detector would not have.

| Feature | Definition |
|---|---|
| `failed_last_hour` | `Σ 𝟙[¬success]` over the trailing 1 h for that user |
| `distinct_ips_last_hour` | `\|{source_ip}\|` over the trailing 1 h |
| `distinct_countries_last_day` | `\|{country}\|` over the trailing 24 h |
| `hour_sin` | see below |
| `hour_cos` | see below |
| `device_change` | `𝟙[` first sighting of this `device_id\|user_agent` pair `]`, 0 for the user's first event |

### Cyclic hour encoding

Hour-of-day is circular: 23:00 and 01:00 are two hours apart, not twenty-two. A
raw integer hour would place them at opposite ends of the feature range. Encoding
onto the unit circle fixes this:

```
         h = hour + minute/60

hour_sin  =  sin( 2π · h / 24 )
hour_cos  =  cos( 2π · h / 24 )
```

The Euclidean distance between two hours then reflects true clock proximity.

---

## 7 · Isolation Forest anomaly score

**Implementation:** [`src/backend/model.py`](../src/backend/model.py)

```
IsolationForest(n_estimators = 100, contamination = 0.01, random_state = 42)
```

Isolation Forest isolates points by random recursive partitioning. Anomalies
require fewer splits to isolate, so they sit at shorter average path length. For
a point `x` with average path length `E[h(x)]` over the ensemble and `c(n)` the
expected path length of an unsuccessful BST search over `n` points:

```
                   − E[h(x)] / c(n)
s(x, n)  =  2

c(n)  =  2·H(n−1) − 2(n−1)/n              H(i) ≈ ln i + 0.5772156649
```

scikit-learn exposes an offset form of this via `score_samples`. SprayTrace uses:

```
a(x)  =  − score_samples(x)               higher = more anomalous
```

### Percentile rescaling

The raw score is **not a probability of maliciousness** and is not on the same
scale as rule scores, so it cannot be mixed with them directly. It is rescaled
against percentiles learned **at fit time on the training window**:

```
q_lo  =  percentile( a(X_train), 50.0 )
q_hi  =  percentile( a(X_train), 99.9 )

                a(x) − q_lo
I(x)  =  clip( ───────────────── , 0, 1 )
                q_hi − q_lo
```

Two deliberate properties:

- The constants are **stored with the model**, not recomputed on the data being
  scored. Rescaling against the scored data would make the output depend on how
  many attacks happen to be present in it.
- `contamination` only sets the offset used by `predict()`. The rescaled
  `score_samples` path used here **does not depend on it**, which is why the
  0.01 / 0.02 sweep moves nothing in the ablation.

The model never raises a standalone alert; it contributes `I` to fusion only.

---

## 8 · Risk fusion

**Implementation:** [`src/backend/fusion.py`](../src/backend/fusion.py)

### 8.1 The weighted sum, and why it alone fails

The report's stated form:

```
R  =  w₁·B + w₂·S + w₃·T + w₄·I            Σ wᵢ = 1,   each component ∈ [0,1]
```

**The calibration constraint.** Because `Σ wᵢ = 1`, a single detector can lift `R`
above a gate `τ` only if its own weight exceeds `τ`. With equal weights
(`wᵢ = 0.2` across five components), a maximum-strength rule plus a perfect
anomaly score reaches:

```
R  =  0.2 · 1.0  +  0.2 · 1.0  =  0.400
```

High (`≥0.60`) and Critical (`≥0.80`) would be **mathematically unreachable** and
the tier system would be decorative. This is not a tuning problem; it is an
arithmetic property of a convex combination.

### 8.2 Rule-floor fusion (the shipped path)

A fired rule enters at its own floor, then earns the remaining headroom through
corroboration.

**Entry point** — the maximum floor among detectors that fired:

```
entry(e)  =  max over detectors d of   𝟙[ score_d(e) > 0 ] · floor_d
```

| Detector | `floor_d` |
|---|---|
| `brute_force` | 0.45 |
| `password_spray` | 0.45 |
| `distributed_spray` | 0.45 |
| `impossible_travel` | 0.41 |

Travel enters lower because geolocation is the noisier signal.

The floor is **not** scaled by the detector's own score. Scaling it
(`floor · score`) would put a genuine 1342 km/h impossible travel at
`0.41 × 0.825 = 0.338` — below the gate, suppressed, never seen. Confidence
belongs in the headroom term, not in the entry point.

**Corroboration** — three independent sources of confidence:

```
corr(e)  =  clip(  0.4 · max_d score_d(e)                    rule strength
                 + 0.4 · I(e)                                anomaly agreement
                 + 0.2 · 𝟙[ |{d : score_d(e) > 0}| > 1 ] ,   second detector
                 0, 1 )
```

**Final risk**

```
          ⎧  entry(e)  +  (1 − entry(e)) · corr(e)       if any rule fired
R(e)  =   ⎨
          ⎩  Σᵢ wᵢ · componentᵢ(e)                       otherwise
```

The `(1 − entry)` headroom factor guarantees `R ≤ 1` while letting a strong,
corroborated rule reach Critical and leaving a lone moderate rule at Medium.

---

## 9 · Decision gate

**Implementation:** [`classify`](../src/backend/fusion.py#L104)

```
             ⎧ critical   R ≥ 0.80      auto-escalate with evidence
             ⎪ high       0.60 ≤ R < 0.80   auto-escalate
tier(R)  =   ⎨ medium     0.40 ≤ R < 0.60   analyst review queue
             ⎪ low        R < 0.40      suppressed; audit log only
             ⎩
```

τ values are **operating policy**, validated on labelled hold-out data — not
universal security constants. Suppressed events are retained and queryable at
`/api/audit`: a suppression nobody can inspect is a claim, not a control.

---

## 10 · Evaluation metrics

**Implementation:** [`src/scripts/evaluate.py`](../src/scripts/evaluate.py)

```
Precision  =  TP / (TP + FP)

Recall     =  TP / (TP + FN)

               2 · Precision · Recall
F1         =  ───────────────────────
                Precision + Recall

Alert-to-TP  =  total alerts / TP
```

### Noise reduction

```
                        Baseline_alerts − SprayTrace_campaigns
Noise reduction %  =  ──────────────────────────────────────── × 100
                               Baseline_alerts
```

Measured against **campaigns**, not raw alerts, because a campaign is the unit an
analyst actually opens. Comparing raw alert counts would read as *negative*
reduction purely because SprayTrace detects more real attacks than the baseline.

Measured values: baseline F1 **0.388**, SprayTrace F1 **0.981**, noise reduction
**91.1 %** — see [eval_results.md](eval_results.md).

---

## 11 · Reproducibility

```
random.seed(42)        numpy.random.seed(42)        IsolationForest(random_state = 42)
```

Splits are by **whole `scenario_id`**, so every event of a campaign lands in one
split and no campaign is partly tuned on and partly scored. Ground-truth labels
live in a separate file read only by `evaluate.py` — never a model input, never a
feature.
