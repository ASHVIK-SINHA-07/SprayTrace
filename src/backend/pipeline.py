"""End-to-end analysis: events in, campaigns out.

One call so the API, the CLI report and the tests all exercise the same path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from src.backend.correlation import build_campaigns
from src.backend.detection import run_rules
from src.backend.fusion import fuse, suppressed
from src.backend.model import fit_and_score
from src.backend.normalize import read_events


@dataclass
class Analysis:
    events: pd.DataFrame
    alerts: pd.DataFrame
    scored: pd.DataFrame
    campaigns: pd.DataFrame
    membership: dict[str, list[int]] = field(default_factory=dict)
    source_format: str = "canonical"

    @property
    def summary(self) -> dict:
        gate_counts = self.scored["tier"].value_counts().to_dict()
        return {
            "total_events": int(len(self.events)),
            "alerts": int(self.scored["risk"].gt(0).sum()),
            "escalated": int(self.scored["tier"].isin(["critical", "high", "medium"]).sum()),
            "campaigns": int(len(self.campaigns)),
            "suppressed": int(len(suppressed(self.scored))),
            "by_tier": {tier: int(gate_counts.get(tier, 0))
                        for tier in ("critical", "high", "medium", "low")},
            "source_format": self.source_format,
        }


def analyze(
    source: str | Path | pd.DataFrame,
    config: dict | None = None,
    use_model: bool = True,
) -> Analysis:
    """Run the full pipeline over a CSV path or an already-loaded frame."""
    if isinstance(source, pd.DataFrame):
        events = source
        source_format = events.attrs.get("source_format", "canonical")
    else:
        events = read_events(source)
        source_format = events.attrs.get("source_format", "canonical")

    alerts = run_rules(events, config)

    anomaly = None
    if use_model and len(events) > 50:
        try:
            anomaly = fit_and_score(events, config)
        except Exception:
            # Rules stay authoritative if the ML layer fails -- the report's
            # contingency, and the reason fusion treats anomaly as optional.
            anomaly = None

    scored = fuse(events, alerts, anomaly, config)
    campaigns, membership = build_campaigns(scored, alerts, config)

    return Analysis(
        events=events,
        alerts=alerts,
        scored=scored,
        campaigns=campaigns,
        membership=membership,
        source_format=source_format,
    )
