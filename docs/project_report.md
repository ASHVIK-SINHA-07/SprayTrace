# SprayTrace — Complete Project Report

**Explainable attack reconstruction for authentication logs**

Microsoft Innovate 2026 · Problem Statement #22 · Team MacroHard (ID 244) · Bennett University

Live deployment: <https://spraytrace.ambitiousfield-440a14b7.eastasia.azurecontainerapps.io>

---

## Contents

1. [What problem this solves](#1-what-problem-this-solves)
2. [The idea in one page](#2-the-idea-in-one-page)
3. [Where the data comes from](#3-where-the-data-comes-from)
4. [What one log line looks like](#4-what-one-log-line-looks-like)
5. [Step 1 — Normalisation](#5-step-1--normalisation)
6. [Step 2 — The four detectors](#6-step-2--the-four-detectors)
7. [Step 3 — The machine-learning layer](#7-step-3--the-machine-learning-layer)
8. [Step 4 — Combining the signals](#8-step-4--combining-the-signals)
9. [Step 5 — The decision gate](#9-step-5--the-decision-gate)
10. [Step 6 — Campaign reconstruction](#10-step-6--campaign-reconstruction)
11. [Step 7 — Explaining the alert](#11-step-7--explaining-the-alert)
12. [How we tested it](#12-how-we-tested-it)
13. [Results](#13-results)
14. [Testing against three million real events](#14-testing-against-three-million-real-events)
15. [What we deliberately did not do](#15-what-we-deliberately-did-not-do)
16. [Known limitations](#16-known-limitations)
17. [How it is built and deployed](#17-how-it-is-built-and-deployed)
18. [Glossary](#18-glossary)

---

## 1 · What problem this solves

When someone tries to break into a company's accounts, they leave traces in the
**authentication log** — the record of every sign-in attempt, successful or
failed. A large organisation generates tens of thousands of these lines a day.

The difficulty is not that attacks are invisible. It is that they are *buried*,
and that the obvious way of looking for them does not work.

**The obvious way.** Most basic security tooling counts failures: "alert me if an
account fails to sign in more than ten times in five minutes." This catches the
loud attacker who hammers one account. It is genuinely useful.

**Why attackers stopped doing that.** A **password spray** inverts the shape. The
attacker takes one very common password — `Autumn2026!` — and tries it against
*five hundred different accounts, once each*. No account fails more than once. The
counter never trips. The attack is invisible to the control designed to stop it,
and it only has to work on one account out of five hundred.

It gets worse. If a defender then starts counting failures *per source address*,
the attacker spreads the same attack across twenty-five different IP addresses.
Now each address looks ordinary too.

**And the second problem: too many alerts.** Security teams suffer from alert
fatigue. A tool that surfaces 1,300 individual suspicious events has not helped
anybody — a human cannot read 1,300 things. What an analyst needs is "there are
29 incidents here, this one is the worst, and here is the sentence explaining
why."

**SprayTrace addresses both.** It detects attacks that are *shaped* to evade
counting, and it collapses thousands of events into a handful of explained
incidents.

---

## 2 · The idea in one page

SprayTrace reads authentication logs and passes them through seven stages:

```
  authentication logs  (CSV, or Microsoft Entra sign-in export)
            │
            ▼
   1. NORMALISE          one common format; bad rows quarantined
            │
            ▼
   2. FOUR DETECTORS     run in parallel, each looking for one attack shape
      ├─ brute force         many tries, one account
      ├─ password spray      few tries, many accounts, one source
      ├─ distributed spray   few tries, many accounts, many sources
      └─ impossible travel   same account, two places, impossible speed
            │
            ▼
   3. ANOMALY MODEL      Isolation Forest — learns "normal", flags the unusual
            │
            ▼
   4. RISK FUSION        combine all signals into one score 0.00 – 1.00
            │
            ▼
   5. DECISION GATE      Critical / High / Medium / suppressed
            │
            ▼
   6. CAMPAIGN RECONSTRUCTION   group related events into one incident
            │
            ▼
   7. EVIDENCE          a plain-English sentence naming the numbers
```

**The headline result on our dataset: 11,229 raw events become 29 campaigns.**
An analyst reads 29 things instead of 11,229.

**The core insight**, and the part that is genuinely ours: *any statistic you
compute per source address can be defeated by spreading across source addresses.*
So our fourth detector does not have the source address in its grouping key at
all. It groups by **time window alone** and asks a question the attacker cannot
evade by rotating IPs — *in this hour, are many accounts each failing once or
twice, from many individually unremarkable addresses?*

---

## 3 · Where the data comes from

This question matters for judging the work honestly, so the answer is explicit.

### 3.1 The primary dataset is synthetic — generated by us

**It is not from Kaggle.** It is not downloaded from anywhere. It is produced by
our own generator, [`src/scripts/generate_data.py`](../src/scripts/generate_data.py),
and committed to `data/raw/auth_logs.csv`.

| | |
|---|---|
| Events | **11,229** |
| Users | ~100 simulated employees |
| Time span | 14 days |
| Attack events | 1,295 (11.5 %) |
| Benign events | 9,934 (88.5 %) |
| Distinct scenarios | 84 |
| Random seed | 42 (fully reproducible) |

Attack events break down as: 1,180 password spray · 97 brute force · 18 impossible travel.

### 3.2 Why synthetic, and not a public dataset

This is a deliberate choice, not a shortcut. **No public authentication dataset
carries labelled password sprays together with usernames, source IPs and
geolocation.** Our detectors need all four. We checked the three sources named in
our original report:

| Dataset | Can our detectors run on it? |
|---|---|
| **LANL auth** | Partly — has user, source, success/failure, timestamps. **No source IP, no geolocation, no spray labels.** |
| UNSW-NB15 | No — network flows: ports, protocols, packet counts. No usernames at all. Different problem domain. |
| LogHub (OpenStack) | No — infrastructure logs, not authentication events. |

Generating our own data is also the only way to get **ground truth**: we know
exactly which events are attacks, because we planted them. Without that, no
precision or recall figure is possible.

### 3.3 What we planted, and the part that matters more

**Attacks (the easy part):**

| Scenario | How it is built |
|---|---|
| Brute force | one account, one IP, a burst of failures inside 5 minutes |
| Password spray | one IP, many accounts, 1–3 failures each inside an hour |
| Slow spray | the same, throttled across many hours |
| Rotating-IP spray | the same target set, IP pool rotating per batch |
| Impossible travel | consecutive successes implying over 1000 km/h |

**Hard negatives (the part that decides whether any of this is credible):**

| Scenario | How it is built | Why it is there |
|---|---|---|
| Corporate NAT | many legitimate users behind one shared office IP | looks like one IP touching many accounts — exactly like a spray |
| Legitimate flight | consecutive successes implying ≤ ~900 km/h | looks like impossible travel, but is a real flight |
| Typo failures | 1–3 failures then a success, same user, same IP | looks like a small brute-force attempt |
| VPN egress change | same user, abrupt country change, plausible timing | looks like account takeover |

**This is the most important paragraph in this section.** Without hard negatives,
precision is meaningless. On a dataset containing only attacks and quiet
background noise, *every* detector scores 1.00 and the number proves nothing. We
built traffic specifically designed to fool our own detectors, and then measured
how often it did.

### 3.4 A real-data check as well

Because synthetic data can only tell you so much, we also ran SprayTrace against
**3,000,000 real authentication events** from the LANL *Comprehensive Multi-Source
Cyber-Security Events* dataset — 58 days of de-identified traffic from Los Alamos
National Laboratory's internal corporate network. Section 14 covers what that
showed.

### 3.5 Real Microsoft logs work too

SprayTrace accepts a **Microsoft Entra ID sign-in log export** directly. The
reader detects the format from the header row and maps it to our internal schema:

| Entra column | Our field |
|---|---|
| `TimeGenerated` / `createdDateTime` | `timestamp` |
| `UserPrincipalName` | `username` |
| `IPAddress` | `source_ip` |
| `LocationDetails.countryOrRegion` | `country` |
| `LocationDetails.city` | `city` |
| `LocationDetails.geoCoordinates.latitude` / `longitude` | `latitude` / `longitude` |
| `ResultType` | `success` — `"0"` means success; `50126` is a bad-credentials failure |
| `DeviceDetail.deviceId` | `device_id` |
| `UserAgent` | `user_agent` |

Everything downstream is identical. **Nothing after the reader knows which format
arrived**, which is what makes the Entra path a genuine integration rather than a
separate code path that might behave differently.

---

## 4 · What one log line looks like

Ten fields. Every one of them is used.

| Field | Example | What it is for |
|---|---|---|
| `timestamp` | `2026-09-20 06:28:05+00:00` | which time window an event falls in; the Δt for travel speed |
| `username` | `jeffreymorgan32@contoso.com` | the account being targeted — the grouping key |
| `source_ip` | `203.0.113.200` | where the attempt came from |
| `country` | `GB` | counting how many countries a user appears from |
| `city` | `London` | display, and the evidence sentence |
| `latitude` | `51.5074` | distance calculation |
| `longitude` | `-0.1278` | distance calculation |
| `success` | `True` | failures drive spray and brute force; successes drive travel |
| `device_id` | `dev-96a402f2` | spotting a new device; telling users apart behind one shared IP |
| `user_agent` | `Mozilla/5.0 (X11; Linux x86_64)…` | the same |

Coordinates are assigned when the data is generated, so **no GeoIP lookup service
is required** — the system has no external network dependency.

### Ground truth lives somewhere else, on purpose

The answer key — which events are really attacks — is in a **separate file**,
`data/raw/ground_truth.csv`, with four columns: `event_id`, `attack_label`,
`attack_type`, `scenario_id`.

It is read by **exactly one file**: the evaluation script. It is never joined into
the data the detectors see, and never becomes a feature.

This matters more than it may appear. If the answers leak into the model's input,
every score becomes meaningless — the system is just reading the answer key. By
keeping labels in a physically separate file, that mistake becomes *structurally
hard* rather than a matter of remembering not to do it. An automated test asserts
the labels never appear in the event file.

---

## 5 · Step 1 — Normalisation

Everything becomes one common shape before any detection happens: timestamps
converted to UTC, types coerced, fields renamed.

Two decisions are worth stating:

**Bad rows are quarantined, not guessed.** A row missing a timestamp, username or
IP is set aside rather than filled in with a default. A fabricated timestamp
corrupts every rolling time window it touches — one invented value can push a
real attack outside its detection window.

**An unknown success value is treated as a failure.** This is the direction that
*cannot hide an attack*. Treating unknowns as successes would let malformed data
silently suppress detections.

---

## 6 · Step 2 — The four detectors

Four detectors run **in parallel** over the same normalised data. Each one looks
for a different *shape*. Each emits a score between 0 and 1, a MITRE ATT&CK
technique ID, and a sentence of evidence.

The full mathematics is in [docs/formulas.md](formulas.md). Here is what each one
does in words.

### 6.1 Brute force — ATT&CK T1110.001

*Many attempts against one account.*

Group the failures by `(account, source IP)`. In any rolling 5-minute window,
count them. **More than 5 failures fires the detector.**

> *12 failed sign-ins for `alice@contoso.com` from `198.18.5.218` within 5
> minutes — consistent with password guessing.*

The score is graded by how far past the threshold it goes, so a 20-failure burst
ranks above a 9-failure one rather than both being "an alert".

### 6.2 Password spray, per source — ATT&CK T1110.003

*Few attempts against many accounts, from one place.*

Group failures by source IP into 1-hour windows. Two conditions must **both**
hold:

- **Breadth** — more than 12 distinct accounts targeted
- **Shallowness** — an average of 3 or fewer attempts per account

#### SprayScore

We grade the attack's shape with a single number:

```
SprayScore  =  distinct accounts ÷ total attempts
```

- Near **1.0** → many accounts, barely tried → *spray-like*
- Near **0.0** → few accounts, hammered → *brute-force-like*

**Why SprayScore alone would be useless, and this is the subtle part.** One single
failed login gives 1 account ÷ 1 attempt = **1.0**, the maximum possible score.
Every lone typo in the company would look like the most severe spray in the
dataset. That is why SprayScore is *never* evaluated on its own — it only grades
severity *after* the breadth condition has already been satisfied.

**A detail that matters in practice:** each hour is evaluated twice — once on the
hour, and once offset by thirty minutes. Without this, an attack running from
10:45 to 11:15 would be split across two windows, with half its accounts in each,
and might fall under the threshold in both. A real attacker would not politely
align to our clock.

### 6.3 Distributed spray — ATT&CK T1110.003

*The one we are most pleased with.*

The per-source detector above groups by IP. So an attacker with 24 addresses
hitting 60 accounts leaves about 2–3 accounts per address — **under the threshold
everywhere**. Nothing fires. This is the same per-source blind spot a naive
counter has, just at a higher level.

**The fix is structural: remove the source from the grouping key entirely.**

What survives distribution is the shape of *the time window itself*. This detector
groups by window alone and fires when all four conditions hold:

| Condition | Threshold | Why |
|---|---|---|
| Many accounts targeted | ≥ 25 | it is broad |
| Many source addresses | ≥ 8 | it is distributed |
| Few attempts per account | ≤ 3 | it is a spray, not brute force |
| Few attempts per source | ≤ 12 | *every source is individually unremarkable* |

That last condition is what stops it double-reporting ordinary noisy traffic. If
one source is loud, the per-source rule already covers it.

> *133 failed attempts across 60 distinct usernames from 22 source addresses
> (2.2 per account, 6.0 per source, SprayScore 0.45) within 59 minutes —
> distributed password spraying: no single source exceeds a per-IP threshold.*

Both detectors ship, because they cover each other's blind spots. Section 13 shows
the per-source rule scoring **0.000** on the held-out test split while the
distributed rule scores **0.888** — and explains why that is the system working
as designed rather than a bug.

### 6.4 Impossible travel — ATT&CK T1078

*One account, two places, a speed no aircraft achieves.*

For each user, take successful sign-ins in time order and check consecutive pairs.
Compute the great-circle distance between the two locations (the **haversine
formula** — the standard way to measure distance across a sphere), divide by the
time between them, and get an implied travel speed.

**Above 1000 km/h, it fires.** A commercial airliner cruises at about 900 km/h, so
1000 is the boundary: real travel stays below it.

> *`bob@contoso.com` signed in from Delhi, IN then London, GB 3.0 h later —
> 6711 km apart, implying 2237 km/h (threshold 1000) — consistent with use of
> valid credentials from a new location.*

The technique is tagged **T1078 (Valid Accounts)**, not a brute-force ID, because
this is not guessing — the credentials already worked. Someone else has them.

---

## 7 · Step 3 — The machine-learning layer

The four detectors above are **rules**: we told them what to look for. That means
they can only catch attacks whose shape we anticipated.

The **Isolation Forest** covers the other case. It is an unsupervised anomaly
detection algorithm — it is never shown which events are attacks. It learns what
ordinary behaviour looks like and flags whatever sits far from it.

### How Isolation Forest works, intuitively

The algorithm repeatedly splits the data at random. A point that is deep in the
middle of normal behaviour takes many splits to isolate from its neighbours. A
point that is unusual gets separated almost immediately. **Anomalies are the
points that are easy to isolate** — hence the name.

### What it looks at

Six behavioural features per event, each computed **per user**:

1. failed attempts in the last hour
2. distinct IP addresses in the last hour
3. distinct countries in the last day
4. & 5. the time of day, encoded cyclically
6. whether this is a new device/browser combination for this user

**Why the time of day needs special handling.** If you feed the hour in as a plain
number 0–23, the model thinks 23:00 and 01:00 are twenty-two hours apart — nearly
maximally distant — when they are actually two hours apart and both "the middle of
the night". We map the hour onto a circle using sine and cosine, so late night
wraps around to early morning correctly.

### Two safeguards

**Strictly backward-looking.** Every rolling count uses only an event's *past*,
never its future. A model that could see forward in time would score beautifully
in testing and fail completely in production, where the future has not happened
yet.

**Rescaling constants are frozen at training time.** The raw anomaly score is not
a probability and is not on the same scale as rule scores, so it is rescaled onto
0–1 before it can be combined. Those rescaling constants are learned on training
data and **stored with the model** — if they were recomputed on the data being
scored, the output would change depending on how many attacks happened to be
present in it.

**The model never raises an alert on its own.** It contributes to the combined
score only. Section 13 is honest about how much it contributed in our tests:
on this data, nothing.

---

## 8 · Step 4 — Combining the signals

Five signals, one number: a **risk score from 0.00 to 1.00**.

### Why the obvious method does not work

The natural approach is a weighted average, with the weights summing to 1:

```
Risk = w₁·(brute) + w₂·(spray) + w₃·(travel) + w₄·(anomaly)
```

We implemented it. It is mathematically broken for this purpose, and the reason is
worth spelling out because it is not obvious.

With five signals weighted equally at 0.2 each, consider the **best possible
case**: a textbook password spray scoring a perfect 1.0, with the anomaly model
also scoring a perfect 1.0. The combined score is:

```
0.2 × 1.0  +  0.2 × 1.0  =  0.400
```

**0.400.** Our "Critical" band starts at 0.80 and "High" at 0.60. A maximally
obvious, perfectly corroborated attack could *never* reach either one. The tier
system would be decorative.

This is not a bad choice of weights — it is an arithmetic property of averaging.
Because the weights must sum to 1, **no single detector can push the score past a
threshold unless its own weight exceeds that threshold.** Any incident that only
one rule catches gets suppressed by construction.

### What we do instead: floors plus earned headroom

A fired rule **enters at its own floor**:

| Detector | Entry floor |
|---|---|
| Brute force | 0.45 |
| Password spray | 0.45 |
| Distributed spray | 0.45 |
| Impossible travel | 0.41 |

Travel enters lower because geolocation is the noisier signal.

The remaining distance to 1.00 — the **headroom** — is then *earned* through three
forms of corroboration:

- **40 %** — how far past its threshold the firing rule sits
- **40 %** — whether the anomaly model independently agrees
- **20 %** — whether a *second, different* detector fired on the same event

So a lone moderate rule stays in Medium and goes to a review queue. A strong rule
backed by the anomaly model and a second detector reaches Critical.

**One more design detail.** The floor is deliberately *not* scaled by the
detector's own confidence. If it were, a genuine 1342 km/h impossible travel would
compute to 0.41 × 0.825 = **0.338** — below the gate, suppressed, never seen by
anyone. Confidence belongs in the headroom, not in the entry point.

---

## 9 · Step 5 — The decision gate

The risk score sorts every event into one of four bands:

| Tier | Risk | What happens |
|---|---|---|
| 🔴 **Critical** | ≥ 0.80 | escalate immediately, with evidence |
| 🟠 **High** | 0.60 – 0.80 | escalate |
| 🔵 **Medium** | 0.40 – 0.60 | analyst review queue |
| ⚪ **Low** | < 0.40 | suppressed — audit log only |

**Suppressed does not mean deleted.** Low-risk events are retained and remain
queryable through the `/api/audit` endpoint.

This is a point of principle. A gate that silently discards data is a *claim* that
nothing important was dropped. A gate whose suppressions you can inspect is a
**control**. And if SprayTrace ever misses a genuine low-scoring campaign, the
audit log is exactly where it would be found. We built the place where our own
failures would show up.

These thresholds are **operating policy**, tuned on validation data — not
universal security constants. A different organisation with different tolerance
for false positives would set them differently.

---

## 10 · Step 6 — Campaign reconstruction

This is the stage that turns a wall of alerts into something a human can read.

Events above the gate are grouped into **campaigns** — single incidents — based on
shared source addresses, overlapping target accounts, and time proximity.

**A rotating-IP attack stays one campaign**, because correlation keys on the
*target set* as well as the source. An attacker using 24 addresses against the
same 60 accounts produces one incident, not 24.

**One guard rail:** cross-source joins must interleave within 10 minutes of the
cluster's start. Without that constraint, two genuinely independent attacks that
happen to share a single victim account would chain together into one misleading
mega-incident.

The result is the headline number: **11,229 events → 1,329 above the gate → 29
campaigns.**

---

## 11 · Step 7 — Explaining the alert

Every campaign carries a sentence written from **the same numbers that triggered
the detection**:

> *38 failed attempts across 20 distinct usernames (1.9 per account, SprayScore
> 0.53) from 203.0.113.159 within 59 minutes — consistent with password spraying
> (T1110.003).*

The evidence text is generated in the detector itself, right next to the
computation. This is a structural choice: **the explanation cannot drift from the
detection**, because there is no second code path that could describe the alert
differently from how it was actually produced.

Every alert also carries its **MITRE ATT&CK technique ID** (T1110.001, T1110.003,
T1078) — the industry-standard catalogue of attacker techniques. This lets the
output slot into existing security workflows rather than being yet another tool
with its own private vocabulary.

---

## 12 · How we tested it

### The protocol

1. **Split the data by whole scenario.** Every event belonging to one attack
   campaign lands in a single split. If half a spray were in training and half in
   testing, the system would effectively be tested on an attack it had already
   seen.
2. **Tune on validation data only.** We grid-searched 27 configurations —
   thresholds, fusion weights, contamination, gate values.
3. **Freeze the configuration** into `configs/thresholds.yaml`.
4. **Measure once on the held-out test set.** No tuning afterwards.

Reporting a number that was tuned on the same data it was measured on is the
fastest way to lose credibility under questioning. The configuration was frozen
before the test measurement was taken.

### The baseline we must beat

A naive per-user and per-IP failed-count threshold — the "basic SIEM threshold"
approach that is standard practice today. If SprayTrace does not beat this, it has
no reason to exist.

### The ablation

To show each piece earns its place, we measured six configurations on **identical
data, features and labels**: each detector alone, then rules combined, then full
fusion. Same-data ablation is the only valid comparison — published numbers from
other projects use different datasets, labels and protocols, and are not our
results.

### The metrics

- **Precision** — of everything flagged, what fraction was really an attack
- **Recall** — of all real attacks, what fraction was caught
- **F1** — the balance of the two
- **Noise reduction** — how much less there is for a human to read

---

## 13 · Results

All figures measured on **held-out test scenarios** with the configuration frozen
beforehand.

### Head-to-head

| | Precision | Recall | F1 |
|---|---:|---:|---:|
| Naive threshold baseline | 1.000 | 0.240 | **0.388** |
| **SprayTrace (full fusion)** | 0.967 | 0.996 | **0.981** |

The baseline has perfect precision — everything it flags is real. But it finds
**under a quarter** of the attacks. It catches brute force and misses almost
everything else, because password spraying is specifically built to stay under
exactly those counters. That is the entire point.

### Full ablation

| Configuration | Precision | Recall | F1 | Alerts |
|---|---:|---:|---:|---:|
| Naive baseline | 1.000 | 0.240 | 0.388 | 56 |
| A · Brute force only | 1.000 | 0.232 | 0.376 | 54 |
| B · Per-source spray only | 0.000 | 0.000 | 0.000 | 0 |
| B2 · Distributed spray only | 0.974 | 0.816 | 0.888 | 195 |
| C · Travel only | 0.727 | 0.034 | 0.066 | 11 |
| D · Isolation Forest only | 0.000 | 0.000 | 0.000 | 0 |
| E · Rules only (A+B+C) | 0.967 | 0.996 | 0.981 | 240 |
| **F · Full fusion** | **0.967** | **0.996** | **0.981** | 240 |

### Recall by attack type

| Attack type | Detected | Total | Recall |
|---|---:|---:|---:|
| Brute force | 54 | 54 | **1.000** |
| Impossible travel | 8 | 8 | **1.000** |
| Password spray | 170 | 171 | **0.994** |

### Noise reduction

**3,894 test events → 240 escalatable → 5 campaigns.** Against the baseline's 56
alerts, that is **91.1 % noise reduction** — measured in campaigns, because a
campaign is the unit an analyst actually opens.

### Three results we are reporting rather than hiding

**1 · The per-source spray rule scored 0.000.** On this split, the spray scenarios
rotate across 20–28 addresses, which puts every individual source below the
breadth threshold. The rule did not fail — it hit precisely the per-source blind
spot that the distributed detector exists to cover. This is the clearest possible
evidence that both detectors are necessary, and it only shows up because we
measured them separately.

**2 · The Isolation Forest contributed no standalone detections.** Configuration D
scores 0.000, and full fusion (F) exactly equals rules-only (E). The honest
reading: on synthetic data whose attacks our rules already encode by construction,
the model adds tier separation but no new coverage. Its value would appear against
behaviour nobody wrote a rule for — which is, by definition, not in a dataset we
generated ourselves. We are reporting this rather than tuning it away; it is
risk #3 in our submitted report.

**3 · Impossible-travel false positives include correct detections.** Precision on
travel is 0.727, and every false positive has the same cause: a planted travel
attack puts the victim in an attacker's city, but that user's ordinary background
traffic continues from their real office. The detector pairs the attacker's login
with the victim's next genuine login and reports a real impossible speed. Ground
truth only labels the two planted events, so these correct detections score as
false positives against an incomplete label.

**We deliberately did not fix this by widening the labels.** Relabelling benign
events as attacks until the metric improves is how synthetic evaluations become
meaningless — it is risk #1 in our own report. The number stands as measured, and
the artifact is documented.

---

## 14 · Testing against three million real events

Synthetic data cannot tell you whether a detector drowns a real network in alerts.
So we ran against the **LANL Comprehensive Multi-Source Cyber-Security Events**
dataset — real de-identified authentication traffic from Los Alamos National
Laboratory's internal corporate network.

| | |
|---|---|
| Events processed | **3,000,000** |
| Failures | 20,036 |
| Distinct users | 14,290 |
| Distinct source computers | 5,820 |

### The result

| Detector | Alerts | % of events |
|---|---:|---:|
| Per-source spray | 994 | 0.0331 % |
| **Distributed spray** | **0** | **0 %** |

**The distributed detector fired zero times on three million events of real
enterprise traffic.** Its conditions — breadth across sources *and* shallowness
per source *and* shallowness per account — are what keep it quiet on benign
behaviour.

### What this proves, and what it does not

**It proves** our detectors do not carpet-flag real authentication traffic. A
detector that fired on 5 % of a real network would be unusable no matter how good
its synthetic recall looked, and **we could not have learned that from our own
generator**.

**It does not prove** the 994 per-source alerts are false positives. LANL's public
release labels only red-team *lateral movement*, not spraying, so those alerts are
**unverified, not confirmed wrong**. The most likely explanation is service
accounts and authentication servers legitimately touching many identities — which
is the NAT collision problem we listed as risk #4, appearing in real data exactly
where we predicted it would.

The travel detector **cannot run** on LANL — there is no geolocation in the data —
so it was skipped rather than fed fabricated coordinates.

---

## 15 · What we deliberately did not do

Choices we made that cost us numbers, listed because they are the reason the other
numbers can be trusted.

| Decision | What it cost | Why |
|---|---|---|
| Kept ground truth in a separate file | some engineering friction | makes label leakage structurally hard, not just discouraged |
| Built hard negatives designed to fool us | lower precision | without them every detector scores 1.00 and proves nothing |
| Did not relabel travel false positives | precision 0.727 instead of ~1.0 | relabelling until the metric improves is how evaluations become meaningless |
| Reported the Isolation Forest's 0.000 | a weaker-looking ML story | it is the truth, and the reason is interesting |
| Froze config before testing | possibly better-looking numbers | tuning on the test set invalidates everything |
| Split by whole scenario | a harder test | otherwise half a campaign leaks into training |
| Did not claim unusable public datasets | a shorter data-sources list | UNSW-NB15 and LogHub genuinely cannot run our detectors |

---

## 16 · Known limitations

Stated plainly.

1. **The primary evaluation is on synthetic data.** Controlled measurements, not a
   claim about live tenants. Section 14 is a partial mitigation, not a substitute.
2. **The Isolation Forest adds no coverage on this data.** Honest reporting of a
   negative result.
3. **Travel precision is measured against an incomplete label** (section 13).
4. **Shared IPs remain hard.** Corporate NAT genuinely looks like a spray. We use
   device and user-agent context, and we built NAT hard negatives, but this is
   mitigated rather than solved — and LANL showed it appearing in real data.
5. **Thresholds are tuned for this dataset.** A real deployment needs
   recalibration against its own traffic.
6. **No real-time streaming.** SprayTrace analyses logs in batch. Throughput is
   about 5,450 events/sec (one million events in roughly three minutes), which is
   sufficient for scheduled analysis but it is not a live stream processor.

---

## 17 · How it is built and deployed

### The stack

| Layer | Technology |
|---|---|
| Detection | Python 3.13, pandas, scikit-learn |
| API | FastAPI |
| Dashboard | React + TypeScript (strict), Vite, Cytoscape for the attack graph |
| Container | Docker, multi-stage |
| Cloud | Azure Container Apps |

### Running it locally

```bash
./run.sh                               # generate → analyse → serve API + UI
python -m src.scripts.generate_data    # regenerate the dataset (seed 42)
python -m src.scripts.evaluate         # reproduce every number in section 13
pytest src/tests -q                    # 47 tests
```

### Cloud deployment

One container on Azure Container Apps serves both the API and the built
dashboard — a single deployable unit with no cross-origin configuration. The
dataset is generated **at build time** from seed 42, so every container starts
from byte-identical reproducible input and the image carries no external
dependency.

**The local path remains primary.** `./run.sh` runs the entire system on a laptop
with no cloud dependency at all. Azure is additive. If the venue network fails,
the demonstration runs exactly as it does here.

Full deployment instructions, including the Azure region policy and container
manifest issues we hit, are in [docs/deploy.md](deploy.md).

---

## 18 · Glossary

| Term | Meaning |
|---|---|
| **Authentication log** | the record of every sign-in attempt, successful or failed |
| **Brute force** | many password guesses against one account |
| **Password spray** | one common password tried against many accounts, once each |
| **Distributed spray** | a password spray spread across many source addresses to evade per-IP counting |
| **Impossible travel** | the same account signing in from two places too far apart for the time elapsed |
| **MITRE ATT&CK** | the industry-standard catalogue of attacker techniques; T1110.001, T1110.003, T1078 here |
| **False positive** | a benign event incorrectly flagged as an attack |
| **False negative** | a real attack that was missed |
| **Precision** | of everything flagged, the fraction that was really an attack |
| **Recall** | of all real attacks, the fraction that was caught |
| **F1 score** | the balanced combination of precision and recall |
| **Ground truth** | the known correct answer; here, which events we planted as attacks |
| **Hard negative** | benign traffic deliberately built to resemble an attack |
| **Ablation** | removing one component at a time to measure what each contributes |
| **Isolation Forest** | an unsupervised algorithm that flags points which are unusually easy to isolate |
| **NAT** | network address translation — many users sharing one public IP address |
| **Entra ID** | Microsoft's identity service, formerly Azure Active Directory |
| **SIEM** | security information and event management — the log platform a security team runs |

---

### Reference documents

| Document | Contents |
|---|---|
| [formulas.md](formulas.md) | every mathematical and statistical formula |
| [dashboard_guide.md](dashboard_guide.md) | screenshots and the function of every UI control |
| [detection_spec.md](detection_spec.md) | authoritative thresholds and definitions |
| [data_spec.md](data_spec.md) | schema, scenarios, Entra mapping |
| [eval_spec.md](eval_spec.md) | evaluation protocol |
| [eval_results.md](eval_results.md) | measured results |
| [external_validation.md](external_validation.md) | the LANL three-million-event run |
| [how_it_works.md](how_it_works.md) | the mechanism, for the panel |
| [deploy.md](deploy.md) | Azure deployment |
| [risk_register.md](risk_register.md) | known risks |
