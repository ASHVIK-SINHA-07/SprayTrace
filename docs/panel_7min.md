# 7-Minute Panel Plan

## 0:00–0:40 · Hook (Ashvik & Hritika)

> "Last week someone tried to break into my own Microsoft account. My email has
> never been published anywhere. Two-factor stopped them — but I had no way to
> know whether I was being targeted, or whether I was one of forty thousand
> accounts someone was walking through."

> "Password spraying is a cross-user attack. One password, hundreds of accounts,
> one or two tries each. Every account stays under its lockout threshold, so no
> per-user alarm ever fires. Count failures per IP instead, and attackers just
> rotate the source."

Stop. Do not explain the architecture yet.

## 0:40–1:10 · The gap (Abhash & Hritika)

> "We built the obvious defence first — a naive per-user and per-IP threshold
> detector, what most shops actually run — and measured it honestly on held-out
> data. It scores **F1 0.388**. It catches brute force and almost nothing else."

> "SprayTrace scores **0.981** on the same data, same labels, same split."

## 1:10–3:10 · Live demo (Atharva drives, Ashvik narrates)

Atharva has the laptop. Ashvik speaks. Do not both talk.

1. **Stat bar** — "11,229 events, 1,329 cross the gate, 29 campaigns. That last
   number is what an analyst opens."
2. **Click CAMP-002** — "52 accounts, 21 source addresses, 54 minutes."
3. **Read the evidence panel aloud.** This is the product. "Generated from the
   same numbers that triggered the detection, so the explanation cannot drift
   from the detection."
4. **Point at the graph** — "The shape is the diagnosis. Pool of sources in the
   middle, victims fanned around. A concentrated spray is one hub. Brute force
   is a single thick edge."
5. **Launch attack** — "Ninety attempts against forty-five accounts from an
   address the system has never seen." New CRITICAL card appears. "Detected,
   scored, correlated, explained. No configuration change."

If anything hangs, say *"while that loads —"* and keep talking. Never watch a
spinner in silence.

## 3:10–3:50 · Code walkthrough (Ashvik Shuryansh)

**The email says: "be ready to walk the panel through your code."** Have
`src/backend/detection.py` open at `detect_distributed_spray` **before you
start**. Do not search for it live.

> "This is the detector that matters most. Our original spray rule grouped by
> source IP — line 104. Against a spray rotating across 24 addresses, each IP
> saw only two accounts, below any threshold. It scored zero. Our own rule had
> the same blind spot as the baseline we were criticising."

> "This one groups by **time window** instead — no source in the grouping key at
> all. It asks: in this hour, are many accounts each failing once or twice, from
> many sources that are individually unremarkable? That is a property of the
> window, not of any address."

Then scroll to the evidence string and show it is built from the same variables
as the detection.

## 3:50–4:20 · Scale and Microsoft (Kapil)

> "It processes **5,450 events per second** on a laptop — a million events in
> about three minutes. Stateless, so it scales horizontally."

> "It already accepts an **Entra ID sign-in log export** — UserPrincipalName,
> IPAddress, ResultType 50126. Same four detectors, no code change. And it's
> **deployed live on Azure Container Apps** right now."

> "Sentinel ingestion and Conditional Access response are the next step, and
> we're not claiming them as built."

## 4:20–4:40 · What we are not claiming (Abhash)

> "Two results we publish rather than hide. Our Isolation Forest contributes
> **zero** standalone detections — full fusion exactly equals rules-only. And
> our per-source spray rule scores **zero** on this split, because every spray in
> the test partition is distributed. We found that by building an honest
> baseline instead of a strawman."

Volunteering this is worth more than hiding it. Panels have seen a hundred teams
present only their best case.

---

## Cut order if running long

1. Drop the graph commentary (step 4) — keep the click
2. Drop the scale number, keep Entra + Azure
3. Drop the code walkthrough — **only if the panel is visibly impatient**; it is
   worth 20 marks

Never cut: the injection, the evidence panel, the 0.388/0.981 gap.
