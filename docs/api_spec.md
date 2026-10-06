# API Spec

FastAPI, served at `127.0.0.1:8000`. Vite proxies `/api` here in development.
TypeScript mirrors of these shapes live in `src/frontend/src/types.ts` — change
both together.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/analyze` | Upload a CSV (canonical or Entra), run the pipeline, return a summary |
| `GET` | `/api/summary` | Counts for the headline bar: events, alerts, campaigns, suppressed, by tier |
| `GET` | `/api/campaigns` | Campaign list, sorted by risk descending |
| `GET` | `/api/campaigns/{id}` | One campaign with its events and alerts |
| `GET` | `/api/events` | Scored events; filters `tier`, `username`, `source_ip`, `technique` |
| `GET` | `/api/users/{username}` | One user's events and risk history |
| `GET` | `/api/metrics` | Evaluation table from the last `evaluate.py` run |
| `GET` | `/api/audit` | Suppressed low-risk events (R < 0.40) — proves gating is auditable |
| `POST` | `/api/inject` | Demo: plant a fresh spray campaign, re-run, return the new campaign |
| `GET` | `/api/replay` | Events ordered for timeline playback, with campaign edges |

## Notes

- `/api/analyze` sniffs the header row to pick the canonical or Entra reader. The
  response states which format was detected, so the demo can show an Entra export
  flowing through unchanged.
- `/api/audit` exists because the report promises low-risk events are "retained in
  an audit log for retrospective hunting". A gate nobody can inspect is a claim,
  not a control.
- `/api/inject` returns the campaign it created so the UI can highlight it. It
  mutates in-memory state only; `data/raw/` stays immutable.
- Analysis results are held in a module-level store. Single-user demo, so no
  database — `docs/data_spec.md` keeps the schema honest regardless.
