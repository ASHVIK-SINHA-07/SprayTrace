# SprayTrace

**Explainable attack reconstruction for authentication logs.**

Microsoft Innovate 2026 · Problem #22 — *Someone's Spraying the VPN* ·
Team MacroHard (ID 244) · Bennett University

SprayTrace turns thousands of noisy sign-in events into a handful of scored,
explainable attack campaigns — each one carrying the evidence that produced it
and a MITRE ATT&CK mapping.

```
11,229 raw events  →  1,329 escalatable  →  29 campaigns
```

---

## The problem

Password spraying is a **cross-user** attack. One or two common passwords are
tried against hundreds of accounts, so every account stays under its lockout
threshold and no per-user alarm ever fires. The attack is invisible to a
per-user statistic and visible only across the whole target set.

A distributed spray goes further: rotate the source across a pool of addresses
and the per-**IP** counter goes quiet too. On our held-out test data a naive
per-user/per-IP threshold detector reaches **F1 0.388** — it catches brute force
and almost nothing else.

SprayTrace reaches **F1 0.981** on the same data, same labels, same split.

## How it works

```
auth logs ──▶ normalize ──▶ ┌─ brute force        (T1110.001)
 (CSV or                    ├─ password spray     (T1110.003)
  Entra export)             ├─ distributed spray  (T1110.003)
                            ├─ impossible travel  (T1078)
                            └─ Isolation Forest   (anomaly)
                                      │
                      weighted fusion ▼  risk ∈ [0,1]
                            ┌─────────────────────┐
                            │ ≥0.80  critical     │
                            │ ≥0.60  high         │  escalate
                            │ ≥0.40  medium       │  review queue
                            │ <0.40  suppressed   │  audit log only
                            └─────────────────────┘
                                      │
                       campaign reconstruction ▼
                            evidence + ATT&CK + graph
```

**SprayScore** `S = U / A` (distinct users ÷ attempts) is the cross-user
statistic: near 1 means many accounts barely tried (spray-like), near 0 means
few accounts hammered (brute-force-like). It only fires alongside a breadth
condition — a single failed login also scores 1.0.

The **distributed detector** groups by time window rather than by source,
because grouping by `source_ip` has the same blind spot the naive baseline has.
That gap is the single most important finding in this project; see
[docs/eval_results.md](docs/eval_results.md).

## Results

Measured on held-out test scenarios. Tuned on validation, frozen, reported once.

| Configuration | Precision | Recall | F1 |
|---|---:|---:|---:|
| Naive threshold baseline | 1.000 | 0.240 | 0.388 |
| A · Brute force only | 1.000 | 0.232 | 0.376 |
| B · Per-source spray only | 0.000 | 0.000 | 0.000 |
| B2 · Distributed spray only | 0.974 | 0.816 | 0.888 |
| C · Travel only | 0.727 | 0.034 | 0.066 |
| D · Isolation Forest only | 0.000 | 0.000 | 0.000 |
| E · Rules only | 0.967 | 0.996 | 0.981 |
| **F · Full fusion** | **0.967** | **0.996** | **0.981** |

**91.1% noise reduction** versus the baseline, measured in campaigns — the unit
an analyst actually opens.

Two honest negatives, both reported rather than tuned away:

- The **Isolation Forest contributes no standalone detections** on this data.
  Full fusion exactly equals rules-only. On synthetic attacks the rules already
  encode, the model adds tier separation but no new coverage.
- **Per-source spray scores 0.000** on this split, because every spray in the
  test partition is a distributed one. That is the blind spot B2 exists to cover.

## Quick start

```bash
python3.13 -m venv .venv
.venv/bin/pip install -r requirements.txt
cd src/frontend && npm install && cd ../..

./run.sh                 # generate data, start API + dashboard
```

Dashboard at <http://localhost:5173>, API at <http://localhost:8000>.

```bash
.venv/bin/python -m src.scripts.generate_data   # regenerate synthetic logs
.venv/bin/python -m src.scripts.report          # terminal incident report
.venv/bin/python -m src.scripts.evaluate        # measure, write eval_results
.venv/bin/python -m pytest src/tests -q         # 47 tests
```

`report.py` runs the whole pipeline in the terminal and is the fallback demo if
the dashboard is unavailable.

## Data

No public dataset carries labelled spray campaigns with source IP, username and
geolocation together, so the attacks are **planted by us** and the labels kept
in a separate file that only `evaluate.py` reads. Generation is deterministic
(seed 42).

Planted: brute force · concentrated spray · slow spray · rotating-IP spray ·
**distributed spray** (20–28 addresses, ≤2 attempts per account) ·
impossible travel.

Hard negatives matter as much as the attacks — without them precision is
measured against data containing only attacks and quiet noise:

| Scenario | Why it is hard |
|---|---|
| Corporate NAT | 46 legitimate users behind one office IP — breadth without shallowness |
| Legitimate flights | Real travel at ≤900 km/h, below the 1000 km/h threshold |
| VPN egress change | Abrupt country change with plausible timing |
| Typo failures | 1–3 failures then a success |

A test asserts the distributed spray stays under both naive thresholds. If it
ever becomes loud, the baseline comparison stops meaning anything and CI says so.

## Microsoft ecosystem

`POST /api/analyze` accepts an **Entra ID sign-in log export** and maps it onto
the canonical schema (`UserPrincipalName`, `IPAddress`, `ResultType` where
`50126` is the credential failure a spray generates). The same detectors run
unchanged — no code path knows which format arrived.

Sentinel, Conditional Access and Azure ML remain pilot targets, not MVP claims.

## Layout

```
src/backend/    normalize · detection · features · model · fusion · correlation
                baseline · pipeline · store · main (FastAPI)
src/scripts/    generate_data · evaluate · report
src/frontend/   Vite + React + TypeScript dashboard
src/tests/      47 tests
configs/        thresholds.yaml — every tunable, frozen by evaluate.py
docs/           specs + measured results
```

## Documentation

| File | Contents |
|---|---|
| [docs/detection_spec.md](docs/detection_spec.md) | Thresholds, formulas, fusion, tiers |
| [docs/data_spec.md](docs/data_spec.md) | Schema, scenarios, Entra mapping |
| [docs/eval_spec.md](docs/eval_spec.md) | Protocol, baseline, ablation |
| [docs/eval_results.md](docs/eval_results.md) | Measured numbers |
| [docs/demo_script.md](docs/demo_script.md) | Five-minute walkthrough |
| [SECURITY.md](SECURITY.md) | Handling, validation, limitations |

## Limitations

Synthetic ground truth cannot reproduce production behaviour. Thresholds need
per-environment calibration. There is no live Sentinel ingestion. Production
geolocation is noisier than coordinates assigned at generation. A spray spread
thinly enough across both time and sources will evade a one-hour window — that
is a property of the stated design, not a claim we have solved it.

## Team

Ashvik Sinha (lead/architect) · Hritika Singh (detection & ML) ·
Shuryansh Kashyap (data) · Kapil Meena (backend) · Atharva Chauhan (frontend) ·
Abhash Raj (research & evaluation). Mentor: Shailza Kanwar, SCSET.
