# Risk Register — Panel Day

What is handled, what is not, and what to do when it goes wrong.

---

## Handled

| Risk | Mitigation | Verified |
|---|---|---|
| Dashboard fails | `python -m src.scripts.report` — same pipeline, terminal output | ✅ runs, 29 campaigns |
| API fails | `report.py` needs no server | ✅ standalone |
| Venue network down | Everything runs local; Azure is additive | ✅ `./run.sh` offline |
| Stale server shows old data | `run.sh` frees ports 8000/5173 before starting | ✅ in script |
| Data missing | Regenerates in **0.4s**, seed 42, identical every time | ✅ measured |
| Laptop dies | Pushed to GitHub + live on Azure | ✅ both current |
| Azure down | Local is primary; Azure is the "and it's deployed" line | ✅ up now |
| ML layer contributes nothing | Documented and volunteered, not hidden | ✅ in eval_results |
| Loud spray makes baseline look good | Distributed scenario added; a test asserts it stays under both naive thresholds | ✅ test passes |
| Label leakage | Ground truth in a separate file; test asserts it never enters the event file | ✅ test passes |

---

## OPEN — decide before you present

### R1 · Shared state on the public URL (**act on this**)

The Azure deployment has **no authentication** and **one shared analysis**. If a
teammate — or a curious judge from another panel — clicks "Launch attack" while
you are presenting, your campaign list changes under you.

**Options:**
- Demo from **localhost** and only *mention* the Azure URL. Simplest, recommended.
- Or: tell the team nobody touches the URL between 12:00 and 16:00 tomorrow.

Do not discover this live.

### R2 · Nobody but Hritika can open the code

The email says *"be ready to walk the panel through your code."* That is part of
**Technical Implementation (20)** and **Demonstration Depth (15)**.

If the panel asks Kapil to show the API, or Shuryansh the generator, they must
not be searching for the file on screen.

**Action:** each member opens their own file in an editor tab **before** entering
the room:
- Hritika → `src/backend/detection.py` at `detect_distributed_spray`
- Shuryansh → `src/scripts/generate_data.py` at `distributed_spray`
- Kapil → `src/backend/main.py` at `post_analyze`
- Atharva → `src/frontend/src/components/CampaignGraph.tsx`
- Abhash → `docs/eval_results.md`

### R3 · Product Potential & Scalability (15 marks) is under-prepared

We have the evidence but it is not rehearsed. Kapil owns it:

> "5,450 events per second on a laptop — a million events in about three
> minutes. The pipeline is stateless, so it scales horizontally. The limit is
> the one-hour window, which is a fixed memory cost, not a growing one."

Add the commercial framing if asked where this goes:
> "Deployed as a Sentinel analytics rule, this is a detection an enterprise
> already pays for — our contribution is the cross-user statistic and the
> campaign layer, not the ingestion."

### R4 · Demo over-runs the slot

7–10 minutes **total**. The old `demo_script.md` is a 5-minute monologue plus
Q&A, which does not fit. Use `panel_7min.md` instead and **stop at 4:40**
regardless of where you are.

### R5 · Someone invents a number

The fastest way to lose a panel. Rule: if you are not certain, say *"I'd want to
check that — the exact figure is in our eval results."* Nobody is penalised for
precision.

---

## If it breaks mid-demo

| What happens | What you say | What you do |
|---|---|---|
| UI hangs | "While that loads — the key number here is 0.388 versus 0.981" | Keep narrating, it usually recovers |
| UI dead | "Let me show you the same pipeline in the terminal" | Switch to `report.py` |
| Injection fails | "The campaigns already on screen are the same detection path" | Skip it, continue |
| Everything dead | "Our measured results are here" | Open `docs/eval_results.md` + backup recording |
| A number is challenged | "Let me check" | Open `docs/eval_results.md` — never argue from memory |

**Have the terminal report running in a second window the whole time.** It costs
nothing and means no single failure ends the demo.

---

## Pre-flight, 20 minutes before

- [ ] `./run.sh` — dashboard loads, 29 campaigns visible
- [ ] Second terminal: `python -m src.scripts.report` run once, left on screen
- [ ] Each member's code file open in a tab
- [ ] `docs/eval_results.md` open in a tab
- [ ] Backup recording accessible offline
- [ ] Laptop charged, charger in bag, screen brightness up
- [ ] Browser zoom set so the stat bar is readable from the back
- [ ] Click **Reset** so the demo starts clean
- [ ] Phone silent
