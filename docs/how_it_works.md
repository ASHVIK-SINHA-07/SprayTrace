# How It Works

The mechanism, for anyone who has to explain it without having built it. Read
this before the panel — "Demonstration Depth" is 15 marks and it is tested by
follow-up questions, not by the demo itself.

---

## The whole pipeline

```
          ┌──────────────────────────────────────────┐
          │  auth logs  (CSV, or Entra sign-in export)│
          └────────────────────┬─────────────────────┘
                               │
                         ┌─────▼─────┐
                         │ normalize │  UTC, types, geo
                         └─────┬─────┘  bad rows quarantined
                               │
        ┌──────────────┬───────┼───────┬──────────────┐
        │              │       │       │              │
   ┌────▼────┐   ┌─────▼───┐ ┌─▼─────┐ ┌──▼────────┐ ┌▼──────────┐
   │ brute   │   │ spray   │ │ dist. │ │ travel    │ │ Isolation │
   │ force   │   │ per-src │ │ spray │ │           │ │ Forest    │
   │T1110.001│   │T1110.003│ │T1110. │ │  T1078    │ │ (anomaly) │
   └────┬────┘   └─────┬───┘ │  003  │ └──┬────────┘ └┬──────────┘
        │              │     └─┬─────┘    │           │
        └──────────────┴───────┼──────────┴───────────┘
                               │   each emits a score in [0,1]
                        ┌──────▼───────┐
                        │ risk fusion  │  R = weighted combine
                        └──────┬───────┘  + per-detector floor
                               │
                        ┌──────▼───────┐
                        │  tier gate   │
                        ├──────────────┤
                        │ ≥0.80 CRITICAL  escalate
                        │ ≥0.60 HIGH      escalate
                        │ ≥0.40 MEDIUM    review queue
                        │ <0.40 LOW       audit log only
                        └──────┬───────┘
                               │  only ≥0.40 continues
                        ┌──────▼──────────┐
                        │   campaign      │  group by shared source
                        │ reconstruction  │  / target set / window
                        └──────┬──────────┘
                               │
                   ┌───────────▼────────────┐
                   │ evidence + ATT&CK + UI │
                   └────────────────────────┘
```

**The one-line version:** normalize → four detectors in parallel → weighted
fusion → tier gate → campaign reconstruction → explained alert.

---

## Each stage, in one paragraph

### 1 · Normalize
Any supported format becomes one canonical shape: timestamp (UTC), username,
source IP, country, city, lat, lon, success, device id, user agent. Rows missing
a timestamp, username or IP are **quarantined, not guessed** — a fabricated
timestamp corrupts every rolling window it touches. An unknown success value is
treated as a failure, because that is the direction that cannot hide an attack.

Entra exports map here too, so **nothing downstream knows which format arrived**.

### 2 · Four detectors, in parallel

| Detector | Groups by | Fires when |
|---|---|---|
| Brute force | (username, source_ip), 5-min window | failures > 5 |
| Password spray | source_ip, 1-hour window | >12 distinct users **and** ≤3 tries each |
| Distributed spray | **time window only** | ≥25 users, ≥8 sources, each source quiet |
| Impossible travel | user, consecutive successes | implied speed > 1000 km/h |

**SprayScore** `S = U / A` — distinct users over total attempts. Near 1 means
many accounts barely tried (spray). Near 0 means few accounts hammered (brute
force). A single failed login also scores 1.0, which is exactly why it only
fires **alongside a breadth condition**.

**Why the distributed detector has no source in its grouping key** is the key
insight of the project: any statistic computed per source can be defeated by
spreading across sources. Grouping by window instead asks a question the
attacker cannot evade by rotating IPs — *in this hour, are many accounts each
failing once or twice, from many individually-unremarkable addresses?*

### 3 · Fusion
Each detector emits a score in [0,1]. A fired rule enters at its own floor
(spray/brute 0.45, travel 0.41 — travel is lower because geolocation is noisier),
then earns the remaining headroom through corroboration: how far past threshold
it sits, whether the anomaly model agrees, and whether a second detector fired on
the same event.

**Why not a plain weighted sum?** We tried it. With equal weights summing to 1, a
maximum-strength rule plus a perfect anomaly score caps at exactly **0.500** —
High and Critical were mathematically unreachable and the tier system was
decorative. A single scalar floor is no better: it clamps every fired rule to one
value and collapses all tiers into one band.

### 4 · Tier gate
Critical ≥0.80 · High ≥0.60 · Medium ≥0.40 · below that, suppressed.

Suppressed events are **retained, not deleted** — queryable at `/api/audit`. A
suppression nobody can inspect is a claim, not a control, and it is where a
missed low-score campaign would be found.

Tiers track truth: Critical **1.00** true-attack rate, High **0.977**.

### 5 · Campaign reconstruction
Events above the gate are grouped into incidents by shared source, shared target
set, and time proximity. A rotating-IP campaign stays one campaign because
correlation keys on the target set too — but cross-source joins must interleave
within 10 minutes of the cluster's start, otherwise independent campaigns that
happen to share one victim would chain into one.

The distributed detector's members merge on the shared window, since that
detector already identified them as one incident.

### 6 · Evidence
Each campaign carries a sentence generated from **the same numbers that
triggered the detection**, so explanation cannot drift from detection:

> "133 failed attempts across 60 distinct usernames from 22 source addresses
> (2.2 per account, 6.0 per source, SprayScore 0.45) within 59 minutes —
> distributed password spraying: no single source exceeds a per-IP threshold
> (T1110.003)."

---

## Data flow in the demo

```
data/raw/auth_logs.csv ──┐
                         ├──▶ pipeline ──▶ in-memory store ──▶ FastAPI ──▶ React
POST /api/analyze ───────┘                        ▲
  (uploaded CSV or                                │
   Entra export)         POST /api/inject ────────┘
                           (plants a live spray, re-runs everything)
```

Ground truth labels live in a **separate file** that only `evaluate.py` reads.
A test asserts they never appear in the event file — the leak that would
invalidate every metric is made structurally hard, not merely discouraged.

---

## Numbers to have in your head

| | |
|---|---|
| Throughput | **5,450 events/sec** (1M events ≈ 3 min) |
| Full dataset | 11,229 → 1,329 escalatable → **29 campaigns** |
| Held-out test | 3,894 → 240 → 5 campaigns |
| Baseline F1 | **0.388** |
| SprayTrace F1 | **0.981** |
| Noise reduction | **91.1%** |
| Tests | 47 passing |
