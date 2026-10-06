# Team Briefing — Microsoft Innovate 2026

Read your own section in full. Read "Everyone" first. Budget 45 minutes.

The goal is not that six people can explain everything. It is that **whoever is
asked can answer, and knows who to pass to** when it is not their area.

---

## Everyone (15 min — non-negotiable)

### The one-sentence pitch

> SprayTrace turns thousands of noisy sign-in events into a handful of scored,
> explainable attack campaigns.

### The problem, in plain terms

Password spraying is a **cross-user** attack. One common password, hundreds of
accounts, one or two tries each. Every account stays under its lockout
threshold, so **no per-user alarm ever fires**. The attack is invisible to a
per-user statistic and only visible across the whole target set.

If you defend by counting failures per IP instead, attackers rotate the source.
Now the per-IP counter is quiet too.

### The four numbers everyone must know cold

| Number | Meaning |
|---|---|
| **11,229 → 1,329 → 29** | raw events → escalatable → campaigns, on the full dataset |
| **0.388** | F1 of a naive per-user/per-IP threshold detector (what most shops run) |
| **0.981** | F1 of SprayTrace, same data, same labels, same split |
| **91.1%** | noise reduction, measured in campaigns — what an analyst opens |

If you remember nothing else: **0.388 versus 0.981**. That gap is the project.

### The honest answer nobody should dodge

Two results we report rather than hide:

1. **The Isolation Forest contributes zero standalone detections.** Full fusion
   exactly equals rules-only.
2. **Our original per-source spray rule scores 0.000** on the test split.

If asked about either, the answer is: *"Yes, we measured that and we publish it.
Here's why."* Do not improvise a defence. Hand to Abhash or Ashvik.

### If you are asked something you do not know

> "That's Hritika's area — Hritika?"

That is a *good* answer. Six people pretending to be experts in everything reads
worse than a team that knows its own structure.

### The mechanism

Read [how_it_works.md](how_it_works.md) — it has the full flowchart and each
stage in a paragraph. Everyone needs this, not just the engineers.

### Your slot is 7-10 minutes TOTAL

Including the panel's questions. Follow [panel_7min.md](panel_7min.md), not the
longer demo_script.md. Stop demoing at 4:40 whatever happens -- Demonstration
Depth (15) and Team Effort (10) are won in the questions.

### Have your code file open BEFORE you walk in

The brief says "be ready to walk the panel through your code." Searching for a
file on screen costs marks in Technical Implementation (20).

### Links

- Live: <https://spraytrace.ambitiousfield-440a14b7.eastasia.azurecontainerapps.io>
- Repo: <https://github.com/ASHVIK-SINHA-07/SprayTrace>

---

## Ashvik — Lead / Architect

**You drive the demo and take architecture questions.**

Learn: `docs/demo_script.md` end to end. Rehearse it twice aloud.

Your three moments:
1. **Open with your own incident.** Last week someone tried to get into your
   Microsoft account. Email never published, 2FA held. The point: *you had no
   way to know if you were a target or one of forty thousand.* Fifteen seconds,
   stated plainly, no embellishment.
2. **Click "Launch attack"** and watch a new CRITICAL campaign appear.
3. **Volunteer the negatives** in section 6 before anyone asks.

Own these questions:
- *"Why not just use a threshold?"* → The baseline **is** the threshold
  approach. It scores 0.388. That is what the gap measures.
- *"Why four detectors?"* → Different attack geometries need different
  statistics. One threshold cannot represent one-to-many, many-to-one and
  location-jump at once.
- *"What would you build next?"* → Multi-window correlation. A spray spread
  thinly across both time *and* sources defeats a one-hour window. We know it;
  it is in our limitations.

Know the pipeline order without notes:
`normalize → 4 detectors in parallel → weighted fusion → tier gate → campaign reconstruction → evidence + ATT&CK`

---

## Hritika — Detection & ML

**You own the detection logic and the model.**

Read: `docs/detection_spec.md` (all of it), `src/backend/detection.py`,
`src/backend/fusion.py`.

Know these four detectors and what each catches:

| Detector | Groups by | Fires when | ATT&CK |
|---|---|---|---|
| Brute force | (username, source_ip), 5 min | failures > θB (5) | T1110.001 |
| Password spray | source_ip, 1 hour | U > θU (12) **and** ≤3 tries/account | T1110.003 |
| Distributed spray | **time window only** | ≥25 users, ≥8 sources, each quiet | T1110.003 |
| Impossible travel | user, consecutive successes | implied speed > 1000 km/h | T1078 |

**SprayScore** `S = U / A` (distinct users ÷ attempts). Near 1 = many accounts
barely tried (spray). Near 0 = few accounts hammered (brute force). Critical
detail: a single failed login also scores 1.0, which is why it only fires
**alongside a breadth condition**. Expect this question.

**Why the distributed detector exists** — this is the strongest technical story
in the project, so know it properly:

> Our original spray rule grouped by `source_ip`. When we tested against a spray
> rotating across 24 addresses, each IP saw only ~2 accounts — below the
> threshold. It scored **0.000**. Our rule had the same per-source blind spot as
> the baseline we were criticising. The distributed detector groups by time
> window instead, and catches those at ~1.0 recall.

**The ML layer.** Isolation Forest, 100 trees, contamination 0.01, six
behavioural features. It contributes **no standalone detections** on our data.
Your answer:

> "The rules already encode the attacks we planted. An unsupervised model earns
> its place against behaviour nobody wrote a rule for — synthetic data that only
> contains rule-shaped attacks can't show that. We report it rather than tune
> until it looks good. It still contributes to tier separation."

Also know **the fusion bug we found and fixed**: with equal 0.25 weights, a
maximum-strength rule plus a perfect anomaly score capped at 0.500 — High and
Critical were mathematically unreachable, so the tier system was decorative. Now
each fired rule enters at its own floor and earns the rest through
corroboration. Tiers now track truth: Critical 1.00, High 0.977.

---

## Shuryansh — Data

**You own the dataset, and the credibility of every number depends on it.**

Read: `docs/data_spec.md`, `src/scripts/generate_data.py`.

Know the schema: 10 canonical fields. Labels (`attack_label`, `attack_type`,
`scenario_id`) live in a **separate file** that only `evaluate.py` reads — so a
feature bug cannot reach them. A test asserts they never appear in the event
file. That is a structural guarantee, not a discipline.

Planted attacks: brute force · concentrated spray · slow spray · rotating-IP
spray · **distributed spray** · impossible travel. Deterministic, seed 42.

**The hard negatives are your headline.** Without them, precision is measured
against data containing only attacks and quiet noise:

| Scenario | Why it is hard |
|---|---|
| Corporate NAT | 46 legitimate users behind one office IP — breadth without shallowness |
| Legitimate flights | real travel at ≤900 km/h, just under the 1000 threshold |
| VPN egress change | abrupt country change, plausible timing |
| Typo failures | 1–3 failures then a success |

Expect: *"Isn't synthetic data circular?"* Your answer:

> "Partly, and we say so. No public dataset carries labelled sprays with source
> IP, username and geolocation together. What we control for is the hard
> negatives — a 46-user corporate NAT, real flights under the speed threshold —
> and a test that asserts our evasive spray stays under both naive thresholds,
> so the baseline comparison can't quietly become unfair."

Know the story of **the generator bug the evaluation caught**: our first sprays
fired 42–109 failures per hour from one IP. A dumb per-IP counter caught them
trivially, and the baseline scored 0.987 — tied with us. That was a *loud* spray,
not an evasive one. Fixing the data is what made the comparison meaningful.

---

## Kapil — Backend & API

**You own the service layer and the Microsoft integration path.**

Read: `docs/api_spec.md`, `src/backend/main.py`, `docs/deploy.md`.

Endpoints worth naming: `/api/summary`, `/api/campaigns`, `/api/campaigns/{id}`,
`/api/audit`, `/api/analyze`, `/api/inject`, `/api/replay`.

**Two you should bring up unprompted:**

- **`/api/audit`** — events below the 0.40 gate are suppressed but **never
  deleted**. They stay queryable. *"A suppression nobody can inspect is a claim,
  not a control."* It is also where a missed low-score campaign would be found.
- **`/api/analyze` accepts an Entra sign-in export** — `UserPrincipalName`,
  `IPAddress`, `ResultType` where 50126 is the credential failure a spray
  generates. Same detectors, **no code change**. Nothing downstream knows which
  format arrived.

The Microsoft question — *"how would this run on real data?"*:

> "It already does, in format terms. Drop in an Entra sign-in log export and the
> same four detectors run unchanged. Sentinel ingestion and Conditional Access
> response are pilot targets, and we're not claiming them as built."

Deployment: one container on Azure Container Apps, FastAPI serving both API and
the built dashboard. Data generated at build time, non-root user. If asked about
the deploy, `docs/deploy.md` has the four Azure-for-Students constraints we hit.

---

## Atharva — Frontend & Dashboard

**You own what the judges actually look at.**

Read: `src/frontend/src/components/`, and have the UI open the whole time.

Be able to drive it without hesitating:
- **Stat bar** = the reduction claim, left to right.
- **Campaign cards** ranked by risk, tier on the left border.
- **"Why this fired"** panel — this is the product. It is generated from the
  same numbers that triggered the detection, so the explanation cannot drift
  from the detection.
- **Attack graph** — *the shape is the diagnosis*: one hub with a wide fan is a
  concentrated spray, a pool of hubs sharing victims is distributed, a single
  thick edge is brute force. You read the attack type before reading a word.
- **Replay** — scrub or play; the account count climbing *is* the moment
  breadth becomes obvious, and the moment a per-user threshold still sees
  nothing.
- **Deep links**: `#CAMP-002` jumps straight to a campaign. Use it instead of
  scrolling on stage.

Good campaigns to show: **CAMP-002** (21 sources, 52 accounts — the distributed
case) and **CAMP-001** (single source, star topology).

If the graph fails to render: the event table below it carries the same
information. Keep talking, scroll down.

---

## Abhash — Research & Evaluation

**You own the numbers and the MITRE mapping. You are the credibility backstop.**

Read: `docs/eval_spec.md`, `docs/eval_results.md`. Know this table:

| Configuration | P | R | F1 |
|---|---:|---:|---:|
| Naive threshold baseline | 1.000 | 0.240 | 0.388 |
| A · Brute force only | 1.000 | 0.232 | 0.376 |
| B · Per-source spray only | 0.000 | 0.000 | 0.000 |
| B2 · Distributed spray only | 0.974 | 0.816 | 0.888 |
| C · Travel only | 0.727 | 0.034 | 0.066 |
| D · Isolation Forest only | 0.000 | 0.000 | 0.000 |
| E · Rules only | 0.967 | 0.996 | 0.981 |
| **F · Full fusion** | **0.967** | **0.996** | **0.981** |

**The protocol is your strongest card.** Say it unprompted:

> "Split by whole scenario, so no campaign is half-seen in tuning and
> half-scored at test. Tuned on validation only, frozen, then reported once on
> held-out test. 33 train / 25 validation / 26 test scenarios."

Per-type recall: brute force 54/54, impossible travel 8/8, spray 170/171.

**MITRE mapping** — know these four cold:
- T1110.001 Brute Force: Password Guessing
- T1110.003 Brute Force: Password Spraying
- T1078 Valid Accounts (impossible travel = stolen credentials, **not** travel)
- T1621 MFA Request Generation — not detected by us; relevant because it is what
  Ashvik's own account experienced

Own the uncomfortable questions:

*"Why does the ML contribute nothing?"* → Covered above; it is risk #3 in our
own submitted report, predicted before we measured it.

*"Your impossible-travel precision is 0.727 — why?"* → Most of those false
positives are **correct detections against an incomplete label**. The detector
pairs an attack login with the victim's own later office login. We documented it
rather than widening labels to improve the number. That would be the synthetic-
data overfitting our report lists as risk #1.

*"What breaks it?"* → A spray spread thinly across both time and sources defeats
a one-hour window. Property of the design we specified, not something we solved.

---

## Rehearsal plan (60–75 min)

**Round 1 — solo, 20 min.** Everyone reads their section and the shared section
aloud, alone. Reading silently is not the same as saying it.

**Round 2 — full run, 15 min.** Ashvik runs the demo start to finish. Everyone
else watches and writes down any moment they could not have explained.

**Round 3 — question drill, 20 min.** Two people play judges and ask from the
list below, in random order. The person who owns it answers; everyone else stays
quiet. Target: an answer starts within three seconds.

**Round 4 — failure drill, 10 min.** Ashvik kills the API mid-demo. Recover
using the terminal report. Do it once so it is not the first time tomorrow.

**Round 5 — record the backup, 10 min.** Screen-record a clean five-minute run.
If the venue network dies, you still have a demo.

### Question bank

1. How is this different from a threshold? *(Ashvik)*
2. Walk me through SprayScore. *(Hritika)*
3. Why does your own spray rule score 0.000? *(Hritika)*
4. Isn't synthetic data circular? *(Shuryansh)*
5. What stops a corporate NAT from being flagged? *(Shuryansh)*
6. How would this run on real Microsoft data? *(Kapil)*
7. What happens to suppressed events? *(Kapil)*
8. Why should I trust 0.981? *(Abhash)*
9. Why does the ML layer contribute nothing? *(Abhash)*
10. What's your false positive rate in production? *(Abhash)*
11. Show me why that alert fired. *(Atharva)*
12. What does the graph tell me that the table doesn't? *(Atharva)*
13. What breaks this? *(Ashvik)*
14. What would you build next? *(Ashvik)*

---

## Three rules for the room

1. **Never invent a number.** If you are unsure, "I'd want to check that" is
   fine. A wrong figure that gets caught costs more than the question was worth.
2. **Volunteer the negatives.** The ML result and the 0.000 spray rule are
   strengths when you raise them and weaknesses when a judge finds them.
3. **Hand off cleanly.** "That's Abhash's area" is a sign of a real team.
