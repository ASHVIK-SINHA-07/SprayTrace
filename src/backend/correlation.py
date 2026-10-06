"""Campaign reconstruction: many alerts -> one incident.

Groups escalatable events that share a source, a time window and a target set.
Correlating on more than source IP is what lets a rotating-IP spray stay one
campaign instead of fragmenting into one alert per address.
"""

from __future__ import annotations

import pandas as pd

from src.backend.config import TECHNIQUE_NAMES, load_config

TECHNIQUE_BY_DETECTOR = {
    "brute_force": "T1110.001",
    "password_spray": "T1110.003",
    "impossible_travel": "T1078",
}
# A spray that also triggers brute force is still a spray; order decides the
# campaign's headline technique.
PRIORITY = ["password_spray", "brute_force", "impossible_travel"]


def _dominant_detector(frame: pd.DataFrame) -> str:
    present = {d for row in frame["detectors"] for d in row if d in TECHNIQUE_BY_DETECTOR}
    for detector in PRIORITY:
        if detector in present:
            return detector
    return "isolation_forest"


def build_campaigns(
    scored: pd.DataFrame,
    alerts: pd.DataFrame,
    config: dict | None = None,
) -> tuple[pd.DataFrame, dict[str, list[int]]]:
    """Return a campaign table and the event ids belonging to each campaign."""
    cfg = config or load_config()
    gate = cfg["gate"]["medium"]
    window = pd.Timedelta(minutes=cfg["correlation"]["window_minutes"])
    min_events = cfg["correlation"]["min_events"]

    candidates = scored[scored["risk"] >= gate].sort_values("timestamp")
    if candidates.empty:
        return pd.DataFrame(), {}

    evidence_by_event = (
        alerts.sort_values("score", ascending=False)
        .groupby("event_id")["evidence"]
        .first()
    )

    clusters: list[dict] = []
    for _, event in candidates.iterrows():
        detectors = [d for d in event["detectors"] if d in TECHNIQUE_BY_DETECTOR]
        kind = next((d for d in PRIORITY if d in detectors), "isolation_forest")

        placed = False
        for cluster in clusters:
            if cluster["kind"] != kind:
                continue
            if event["timestamp"] - cluster["last_seen"] > window:
                continue
            # Same source, or the same victims seen from a new address. The
            # second branch is what survives IP rotation.
            shares_source = event["source_ip"] in cluster["source_ips"]
            shares_target = event["username"] in cluster["usernames"]
            if kind == "impossible_travel":
                # Travel is per-identity: one compromised account, one incident.
                if not shares_target:
                    continue
            elif not (shares_source or shares_target):
                continue

            cluster["event_ids"].append(int(event["event_id"]))
            cluster["source_ips"].add(event["source_ip"])
            cluster["usernames"].add(event["username"])
            cluster["last_seen"] = event["timestamp"]
            cluster["risk"] = max(cluster["risk"], float(event["risk"]))
            cluster["failed"] += int(not event["success"])
            cluster["succeeded"] += int(bool(event["success"]))
            placed = True
            break

        if not placed:
            clusters.append(
                {
                    "kind": kind,
                    "event_ids": [int(event["event_id"])],
                    "source_ips": {event["source_ip"]},
                    "usernames": {event["username"]},
                    "first_seen": event["timestamp"],
                    "last_seen": event["timestamp"],
                    "risk": float(event["risk"]),
                    "failed": int(not event["success"]),
                    "succeeded": int(bool(event["success"])),
                }
            )

    rows: list[dict] = []
    membership: dict[str, list[int]] = {}
    ranked = [c for c in clusters if len(c["event_ids"]) >= min_events]
    ranked.sort(key=lambda c: c["risk"], reverse=True)
    for index, cluster in enumerate(ranked, start=1):
        campaign_id = f"CAMP-{index:03d}"
        technique = TECHNIQUE_BY_DETECTOR.get(cluster["kind"], "")
        span = (cluster["last_seen"] - cluster["first_seen"]).total_seconds() / 60
        sources = sorted(cluster["source_ips"])
        headline = (
            evidence_by_event.get(cluster["event_ids"][0])
            or f"{len(cluster['event_ids'])} correlated events."
        )
        label = TECHNIQUE_NAMES.get(technique, cluster["kind"].replace("_", " ").title())
        origin = sources[0] if len(sources) == 1 else f"{len(sources)} sources"

        rows.append(
            {
                "campaign_id": campaign_id,
                "name": f"{label} from {origin}",
                "technique": technique,
                "risk": round(cluster["risk"], 4),
                "tier": _tier(cluster["risk"], cfg),
                "first_seen": cluster["first_seen"],
                "last_seen": cluster["last_seen"],
                "span_minutes": round(span, 1),
                "source_ips": sources,
                "usernames": sorted(cluster["usernames"]),
                "event_count": len(cluster["event_ids"]),
                "failed_count": cluster["failed"],
                "success_count": cluster["succeeded"],
                "evidence": headline,
            }
        )
        membership[campaign_id] = cluster["event_ids"]

    return pd.DataFrame(rows), membership


def _tier(risk: float, config: dict) -> str:
    from src.backend.fusion import classify

    return classify(risk, config)
