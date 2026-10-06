# PPT Updates Needed

Your Round 1 deck and Final Report were written at **pre-development** stage.
Several claims are now either measured, superseded, or wrong. Fix these before
presenting — a judge who has read the report and sees a contradiction on screen
will stop trusting the rest.

Ordered by how badly they need fixing.

---

## MUST FIX — these are now wrong

### 1 · Slide 5 "Planned tech stack"

| Slide says | Reality | Action |
|---|---|---|
| Next.js | **Vite + React + TypeScript** | change |
| PostgreSQL | **In-memory + CSV** (no DB) | change or drop |
| Microsoft Azure | ✅ Azure Container Apps — **live** | keep, upgrade to a URL |
| GitHub Actions | not set up | drop |
| Python · FastAPI | ✅ correct | keep |
| pandas · scikit-learn | ✅ correct | keep |

Replace the "PostgreSQL" tile with something true and more interesting:
**"Deterministic synthetic data, seed 42."**

### 2 · Slide 5 status badge

Says **"STATUS · PRE-DEVELOPMENT"**. Change to **"STATUS · BUILT AND MEASURED"**
or similar. This badge is the single most outdated thing in the deck.

### 3 · Report §5 flowchart — three detectors

Both the report and deck show **three rule detectors**. There are now **four**.
The fourth is the most important one:

```
4a Brute force        (username, source_ip), 5 min
4b Password spray     source_ip, 1 hour, S = U/A
4c Distributed spray  time window only — NEW
4d Impossible travel  haversine speed > 1000 km/h
4e Isolation Forest   anomaly
```

If you only change one diagram, change this one.

### 4 · Every "TBM" cell

Report §8 has a table where every Precision / Recall / F1 / Alert-to-TP /
Noise-reduction cell says **TBM (to be measured)**. They are measured now:

| Configuration | Precision | Recall | F1 | Alerts |
|---|---:|---:|---:|---:|
| Naive threshold baseline | 1.000 | 0.240 | 0.388 | 56 |
| A · Brute force only | 1.000 | 0.232 | 0.376 | 54 |
| B · Per-source spray only | 0.000 | 0.000 | 0.000 | 0 |
| B2 · Distributed spray only | 0.974 | 0.816 | 0.888 | 195 |
| C · Travel only | 0.727 | 0.034 | 0.066 | 11 |
| D · Isolation Forest only | 0.000 | 0.000 | 0.000 | 0 |
| E · Rules only | 0.967 | 0.996 | 0.981 | 240 |
| **F · Full fusion** | **0.967** | **0.996** | **0.981** | **240** |

Held-out test: 3,894 events, 26 scenarios. Noise reduction **91.1%**.

### 5 · Slide 6 "10,000 → 3-5"

Slide says *"Target demo... final performance will be measured after
implementation."* It is measured. Replace with the real figure:

> **11,229 → 1,329 → 29 campaigns** (full dataset)
> **3,894 → 240 → 5 campaigns** (held-out test)

Note it is 29, not 3–5. That is **honest and better** — 29 campaigns from 11,229
events is a 387× reduction, and we planted roughly 25 attack scenarios, so
finding 29 incidents is close to correct rather than suspiciously tidy. Do not
force the number down to match an old slide.

### 6 · Report §7.3 fusion weights

The report proposes equal weights with `Σw = 1` and a scalar `rule_floor`. We
implemented it and **it does not work**: a maximum-strength rule plus a perfect
anomaly score caps at exactly **0.500**, so High and Critical were mathematically
unreachable. A scalar floor is no better — it clamps every fired rule to one
value and collapses all tiers into one band.

What ships: **detector-specific entry points** (spray/brute 0.45, travel 0.41),
with the rest earned through corroboration. Tiers now track truth —
Critical 1.00, High 0.977 true-attack rate.

This is worth a slide of its own. See "New slides" below.

---

## SHOULD FIX — overclaims

### 7 · Slide 5 "Public datasets"

Says data strategy is *"Public authentication/log datasets plus team-generated
synthetic logs."* We used **only** synthetic. LANL, UNSW-NB15 and LogHub were
never ingested. Say synthetic only, and say why: no public dataset carries
labelled sprays with source IP, username and geolocation together.

### 8 · Report §10 "[Pilot]" framing

Report lists Sentinel, Entra Conditional Access, Azure ML as pilots, and flags
risk #5: *"Microsoft integration remains a slide."* It no longer is:

- ✅ Entra sign-in log export imports and runs through the same detectors
- ✅ Deployed and live on Azure Container Apps
- ⬜ Sentinel ingestion — still pilot
- ⬜ Conditional Access response — still pilot

Keep the pilot framing for the last two. Upgrade the first two to built.

### 9 · "Lateral movement" in the Round 1 title area

Early framing mentions lateral movement. We do not detect lateral movement.
Impossible travel is **T1078 Valid Accounts** — use of stolen credentials from a
new location. Say that instead; it is accurate and still strong.

---

## NEW SLIDES — the material that wins

These did not exist at submission and are the most compelling content you have.

### New slide A — "We tested our own design and found a hole"

The single best story in the project:

> Our submitted report said breadth is the signature of spraying. The rule we
> specified grouped by **source IP**.
>
> We built an honest baseline — a naive per-user and per-IP counter — and tested
> against a spray rotating across 24 addresses.
>
> The baseline scored **0.000**. So did our own spray rule. Each IP saw only
> ~2 accounts, below any threshold. **Our rule had the same blind spot as the
> approach we were criticising.**
>
> The distributed detector groups by time window instead. It catches those
> campaigns at **~1.0 recall**.

Why it lands: it shows you tested rather than assumed, and that you found it
yourselves. Judges have seen a hundred teams present only their best case.

### New slide B — "What we are not claiming"

| Result | What we say |
|---|---|
| Isolation Forest: 0.000 standalone | Rules already encode our planted attacks. An unsupervised model earns its place against behaviour nobody wrote a rule for. We report it rather than tune it. |
| Travel precision 0.727 | Most false positives are correct detections against an incomplete label. We documented it rather than widening labels to improve the number. |
| Synthetic data | No public set has labelled sprays with IP + username + geo. We control for it with hard negatives and whole-scenario splits. |

Volunteering these is a strength. Being caught on them is not.

### New slide C — Evaluation protocol

One slide, because it is what separates a real result from a plausible one:

> Split by **whole scenario** — no campaign half-seen in tuning and half-scored
> at test. Tuned on validation only. **Frozen.** Reported **once** on held-out
> test. 33 train / 25 validation / 26 test scenarios.

### New slide D — Live system

Screenshot of the dashboard plus the URL. The campaign graph of CAMP-002
(21 sources → 52 accounts) is the most visually striking asset you have.

---

## Quick checklist

- [ ] Status badge: pre-development → built and measured
- [ ] Tech stack: Next.js → Vite+React; drop PostgreSQL and GitHub Actions
- [ ] Flowchart: three detectors → four
- [ ] Fill every TBM cell
- [ ] 10,000 → 3–5 becomes 11,229 → 1,329 → 29
- [ ] Data strategy: synthetic only, and say why
- [ ] Microsoft section: Entra import and Azure deploy are built
- [ ] Remove "lateral movement" → T1078 Valid Accounts
- [ ] Add slide A (the hole we found)
- [ ] Add slide B (what we are not claiming)
- [ ] Add slide C (protocol)
- [ ] Add slide D (live system + URL)

**Owner: Abhash** (research & evaluation), with Ashvik reviewing. The numbers
are all in `docs/eval_results.md` — copy them, do not retype from memory.
