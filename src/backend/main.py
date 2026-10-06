"""SprayTrace REST API. Contract in docs/api_spec.md.

Serves the analysis the dashboard renders, plus the demo-only injection
endpoint. Response shapes mirror src/frontend/src/types.ts -- change both
together.
"""

from __future__ import annotations

import io
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from src.backend import store
from src.backend.config import DOCS, TECHNIQUE_NAMES
from src.backend.fusion import suppressed
from src.backend.normalize import read_events
from src.backend.pipeline import analyze

app = FastAPI(title="SprayTrace", version="0.1.0")

# Local demo only: the Vite dev server runs on a different port.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _json_safe(frame: pd.DataFrame) -> list[dict[str, Any]]:
    """Frame -> JSON rows with timestamps as ISO strings."""
    if frame.empty:
        return []
    out = frame.copy()
    for column in out.columns:
        if pd.api.types.is_datetime64_any_dtype(out[column]):
            out[column] = out[column].dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return out.replace({pd.NA: None}).to_dict("records")


def _events_for(event_ids: list[int]) -> list[dict[str, Any]]:
    analysis = store.get_analysis()
    scored = analysis.scored[analysis.scored["event_id"].isin(event_ids)]
    alerts = analysis.alerts[analysis.alerts["event_id"].isin(event_ids)]
    evidence = alerts.sort_values("score", ascending=False).groupby("event_id")[
        "evidence"
    ].first()
    enriched = scored.copy()
    enriched["evidence"] = enriched["event_id"].map(evidence).fillna("")
    return _json_safe(enriched.sort_values("timestamp"))


@app.get("/api/summary")
def get_summary() -> dict[str, Any]:
    return store.get_analysis().summary


@app.get("/api/campaigns")
def list_campaigns() -> list[dict[str, Any]]:
    analysis = store.get_analysis()
    if analysis.campaigns.empty:
        return []
    return _json_safe(analysis.campaigns.sort_values("risk", ascending=False))


@app.get("/api/campaigns/{campaign_id}")
def get_campaign(campaign_id: str) -> dict[str, Any]:
    analysis = store.get_analysis()
    match = analysis.campaigns[analysis.campaigns["campaign_id"] == campaign_id]
    if match.empty:
        raise HTTPException(status_code=404, detail=f"No campaign {campaign_id}")

    event_ids = analysis.membership.get(campaign_id, [])
    campaign = _json_safe(match)[0]
    campaign["events"] = _events_for(event_ids)
    campaign["technique_name"] = TECHNIQUE_NAMES.get(campaign["technique"], "")
    return campaign


@app.get("/api/events")
def list_events(
    tier: str | None = None,
    username: str | None = None,
    source_ip: str | None = None,
    technique: str | None = None,
    limit: int = Query(500, le=5000),
) -> list[dict[str, Any]]:
    analysis = store.get_analysis()
    frame = analysis.scored
    if tier:
        frame = frame[frame["tier"] == tier]
    if username:
        frame = frame[
            frame["username"].str.contains(username, case=False, na=False, regex=False)
        ]
    if source_ip:
        frame = frame[frame["source_ip"] == source_ip]
    if technique:
        ids = analysis.alerts[analysis.alerts["attack_technique"] == technique][
            "event_id"
        ]
        frame = frame[frame["event_id"].isin(ids)]
    frame = frame.sort_values("risk", ascending=False).head(limit)
    return _events_for(frame["event_id"].tolist())


@app.get("/api/users/{username}")
def get_user(username: str) -> dict[str, Any]:
    analysis = store.get_analysis()
    events = analysis.scored[analysis.scored["username"] == username]
    if events.empty:
        raise HTTPException(status_code=404, detail=f"No events for {username}")

    campaigns = []
    if not analysis.campaigns.empty:
        campaigns = _json_safe(
            analysis.campaigns[
                analysis.campaigns["usernames"].apply(lambda u: username in u)
            ]
        )
    return {
        "username": username,
        "event_count": int(len(events)),
        "max_risk": float(events["risk"].max()),
        "failed_count": int((~events["success"]).sum()),
        "distinct_ips": int(events["source_ip"].nunique()),
        "distinct_countries": int(events["country"].nunique()),
        "campaigns": campaigns,
        "events": _events_for(events["event_id"].tolist()),
    }


@app.get("/api/audit")
def get_audit(limit: int = Query(200, le=2000)) -> dict[str, Any]:
    """Below-gate events, retained for retrospective hunting.

    The report promises these are kept rather than discarded; exposing them is
    what makes the suppression claim auditable.
    """
    analysis = store.get_analysis()
    low = suppressed(analysis.scored).sort_values("risk", ascending=False)
    return {
        "total": int(len(low)),
        "note": "Risk below the 0.40 gate: never escalated, retained for hunting.",
        "events": _json_safe(low.head(limit)),
    }


@app.get("/api/metrics")
def get_metrics() -> dict[str, Any]:
    """Evaluation results, once src/scripts/evaluate.py has written them."""
    results = DOCS / "eval_results.json"
    if not results.exists():
        return {
            "calibrated": False,
            "note": "Run python -m src.scripts.evaluate to measure.",
            "configurations": [],
        }
    import json

    return json.loads(results.read_text())


@app.post("/api/analyze")
async def post_analyze(file: UploadFile = File(...)) -> dict[str, Any]:
    """Upload a CSV in canonical or Entra format and re-run the pipeline."""
    payload = await file.read()
    try:
        events = read_events(io.BytesIO(payload))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if events.empty:
        raise HTTPException(status_code=400, detail="No usable rows in upload.")

    analysis = store.set_analysis(analyze(events))
    summary = analysis.summary
    summary["filename"] = file.filename
    return summary


@app.post("/api/inject")
def post_inject(
    # Below theta_u the spray rule cannot fire, so the demo would return 200
    # with campaign: None. Floor the input at a value that can actually detect.
    accounts: int = Query(40, ge=20, le=90),
    minutes: int = Query(25, ge=5, le=240),
) -> dict[str, Any]:
    """Demo: plant a live spray campaign and re-run the pipeline.

    Appends to the in-memory frame only -- data/raw stays immutable.
    """
    analysis = store.get_analysis()
    events = analysis.events

    source_ip = "198.51.100.66"
    start = events["timestamp"].max() + timedelta(minutes=5)
    targets = (
        events["username"].drop_duplicates().head(accounts).tolist()
        or [f"user{i}@contoso.com" for i in range(accounts)]
    )

    rows: list[dict[str, Any]] = []
    next_id = int(events["event_id"].max()) + 1
    for index, username in enumerate(targets):
        for attempt in range(2):
            rows.append(
                {
                    "event_id": next_id,
                    "timestamp": start
                    + timedelta(minutes=(index / max(len(targets), 1)) * minutes,
                                seconds=20 * attempt),
                    "username": username,
                    "source_ip": source_ip,
                    "country": "RU",
                    "city": "Moscow",
                    "latitude": 55.7558,
                    "longitude": 37.6173,
                    "success": False,
                    "device_id": "unknown",
                    "user_agent": "python-requests/2.32.3",
                }
            )
            next_id += 1

    injected = pd.DataFrame(rows)
    injected["timestamp"] = pd.to_datetime(injected["timestamp"], utc=True)
    combined = pd.concat([events, injected], ignore_index=True)
    combined.attrs["source_format"] = analysis.source_format

    updated = store.set_analysis(analyze(combined))
    fresh = updated.campaigns[
        updated.campaigns["source_ips"].apply(lambda ips: source_ip in ips)
    ]
    return {
        "injected_events": len(rows),
        "accounts_targeted": len(targets),
        "source_ip": source_ip,
        "campaign": _json_safe(fresh)[0] if not fresh.empty else None,
        "summary": updated.summary,
    }


@app.get("/api/replay")
def get_replay() -> dict[str, Any]:
    """Escalatable events in time order, with the edges to draw per step."""
    analysis = store.get_analysis()
    if analysis.campaigns.empty:
        return {"steps": [], "campaigns": []}

    member_of = {
        event_id: campaign_id
        for campaign_id, ids in analysis.membership.items()
        for event_id in ids
    }
    frame = analysis.scored[analysis.scored["event_id"].isin(member_of)].copy()
    frame["campaign_id"] = frame["event_id"].map(member_of)
    frame = frame.sort_values("timestamp")

    return {
        "steps": _json_safe(
            frame[["event_id", "timestamp", "username", "source_ip", "risk",
                   "tier", "success", "campaign_id"]]
        ),
        "campaigns": _json_safe(analysis.campaigns),
    }


@app.post("/api/reset")
def post_reset() -> dict[str, Any]:
    """Drop back to the generated dataset."""
    store.reset()
    return store.get_analysis().summary


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "spraytrace"}


# ---------------------------------------------------------------- static site
#
# In a container the built dashboard is served from this same app, so there is
# one deployable unit and no cross-origin configuration in production. Mounted
# last so every /api route above still wins.

_static = Path(os.environ.get("SPRAYTRACE_STATIC", "")) if os.environ.get(
    "SPRAYTRACE_STATIC"
) else None

if _static and _static.is_dir():
    app.mount("/assets", StaticFiles(directory=_static / "assets"), name="assets")

    @app.get("/{full_path:path}")
    def spa(full_path: str) -> FileResponse:
        """Serve the dashboard, falling back to index.html for client routes."""
        candidate = _static / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(_static / "index.html")
