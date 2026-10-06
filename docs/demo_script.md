# Demo Script

Five minutes, live. Timings are generous — if you are running short, cut
section 6 first, then 5.

**Before you start**
- `./run.sh` is up; dashboard on <http://localhost:5173>, API on `:8000`.
- Browser at the dashboard, zoomed so the stat bar is legible from the back.
- A second terminal ready with `.venv/bin/python -m src.scripts.report`.
- `docs/eval_results.md` open in a tab.
- Click **Reset** so the event count starts clean.

---

## 1 · Open with the real incident (40s)

> "Three days ago someone tried to get into my own Microsoft account. My email
> has never been published anywhere. Two-factor stopped them, so nothing was
> breached — but here is the part that bothers me: I had no way to know whether
> I was being targeted, or whether I was one of forty thousand accounts someone
> was walking through."

> "That question — *am I a target or a statistic?* — is the one a SOC has to
> answer, and it is the one SprayTrace exists to answer."

Why this works: it is true, it is yours, and it reframes the problem from
academic to concrete in fifteen seconds. Don't oversell it; state it plainly.

## 2 · Why ordinary detection misses this (45s)

> "Password spraying is a cross-user attack. One common password, hundreds of
> accounts, one or two tries each. Every account stays under its lockout
> threshold, so no per-user alarm ever fires."

> "The usual answer is to count failures per IP instead. So attackers rotate the
> source. Now the per-IP counter is quiet too."

> "We measured that. A naive per-user and per-IP threshold detector — which is
> what most shops actually run — scores **F1 0.388** on our test data. It catches
> brute force and essentially nothing else."

## 3 · The reduction (45s)

Point at the stat bar.

> "Eleven thousand raw sign-in events. One thousand three hundred cross the
> escalation gate. Those collapse into **29 campaigns** — that is what an analyst
> actually opens."

> "Below 0.40 we suppress — four thousand events — but we never delete them.
> They stay in an audit log at `/api/audit`, because a suppression nobody can
> query is a claim, not a control."

## 4 · One campaign, explained (70s)

Open **CAMP-002** (`#CAMP-002` in the URL, or click it).

> "This is a distributed spray. Fifty-two accounts, twenty-one source
> addresses, fifty-four minutes."

Read the **Why this fired** panel aloud — it is the product.

> "133 failed attempts across 60 distinct usernames from 22 source addresses —
> 2.2 per account, 6 per source. No single source exceeds a per-IP threshold.
> That sentence is generated from the same numbers that triggered the
> detection, so the explanation cannot drift from the detection."

Point at the graph.

> "The shape is the diagnosis. A pool of sources in the middle, the victim set
> fanned around them. A concentrated spray is one hub with a wide fan. Brute
> force is a single thick edge. You read the attack type before you read a word."

Hit **Replay**.

> "And this is it arriving. Watch the account count climb — that is the moment
> the breadth becomes obvious, and that is the moment a per-user threshold still
> sees nothing."

## 5 · Live attack (50s)

Click **Launch attack**.

> "That just injected ninety sign-in attempts against forty-five accounts from
> an address the system has never seen. The pipeline re-ran on everything."

Point at the new CRITICAL card.

> "New campaign, critical tier, SprayScore 0.50 — forty-five accounts, two
> attempts each. Detected, scored, correlated and explained, with no
> configuration change."

## 6 · Honest numbers (50s)

Switch to `docs/eval_results.md`.

> "Split by whole scenario so no campaign is half-seen in tuning. Tuned on
> validation, frozen, reported once on held-out test."

> "Baseline F1 0.388. Full fusion **0.981**. Ninety-one percent fewer things for
> an analyst to open."

Then volunteer the negatives before anyone asks:

> "Two results we are not hiding. Our Isolation Forest contributes **zero**
> standalone detections — full fusion exactly equals rules-only. And our
> original per-source spray rule scores **0.000** on this split, because every
> spray in the test partition is distributed."

> "That second one is the most useful thing we found. Our own submitted report
> said breadth was the signature, but the rule we specified grouped by source
> IP — which has exactly the same blind spot as the baseline we were criticising.
> We only found it because we built the baseline honestly instead of building a
> strawman. The distributed detector is the fix, and it is why the gap in that
> table is real."

## 7 · Close (20s)

> "Rules plus anomaly plus correlation, every alert carrying its evidence and an
> ATT&CK technique, running locally with no cloud dependency. It accepts an
> Entra sign-in export unchanged, so the path to real tenant data is a file
> format, not a rewrite."

---

## Questions you should expect

**"Is this just a threshold?"**
No. The spray statistic is cross-user, and the distributed detector groups by
time window rather than by source. That is what the 0.388 versus 0.981 gap
measures — the baseline *is* the threshold approach.

**"Your data is synthetic, so isn't this circular?"**
Partly, and we say so. No public dataset carries labelled sprays with source IP,
username and geolocation together. What we control for: hard negatives (a 46-user
corporate NAT, real flights at ≤900 km/h, VPN egress changes, typo failures),
splitting by whole scenario, and a test asserting our evasive spray stays under
both naive thresholds — so the baseline comparison cannot quietly become unfair.

**"Why does the ML layer contribute nothing?"**
Because the rules already encode the attacks we planted. An unsupervised model
earns its place against behaviour nobody wrote a rule for, and synthetic data
that only contains rule-shaped attacks cannot show that. We report it rather
than tune until it looks good.

**"What about false positives in production?"**
Our impossible-travel false positives are mostly correct detections against an
incomplete label — the detector pairs an attack login with the victim's own
later office login. We documented that rather than widening labels to improve
the number. In production the real risks are NAT collisions and geolocation
quality, which is why IP is one feature and never identity.

**"How would this run on real Microsoft data?"**
`POST /api/analyze` takes an Entra sign-in export today — `UserPrincipalName`,
`IPAddress`, `ResultType` 50126. Same detectors, no code change. Sentinel and
Conditional Access are pilot targets, and we are not claiming them as built.

**"What breaks it?"**
A spray spread thinly enough across both time and sources evades a one-hour
window. That is a property of the design we specified, not something we have
solved. Multi-window correlation is the next step.

---

## If something fails

| Failure | Fallback |
|---|---|
| Dashboard won't load | `python -m src.scripts.report` — same pipeline, terminal output |
| API won't start | `report.py` runs standalone, no server needed |
| Injection fails | Campaigns 1–29 are already on screen; skip section 5 |
| Everything is broken | `docs/eval_results.md` plus the backup recording |

Keep the terminal report running in a second window the whole time. It costs
nothing and it means no single failure ends the demo.
