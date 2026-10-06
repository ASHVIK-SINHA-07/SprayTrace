"""Fusion, gating and correlation behaviour.

The calibration constraint in docs/detection_spec.md 7.3 is the thing most
likely to break silently: a weighting that cannot reach the upper tiers still
produces plausible-looking output, so it gets an explicit test.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest

from src.backend.config import load_config
from src.backend.correlation import build_campaigns
from src.backend.fusion import classify, escalatable, fuse, suppressed

START = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)


def _events(n: int = 4) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "event_id": range(n),
            "timestamp": pd.to_datetime(
                [START + timedelta(minutes=i) for i in range(n)], utc=True
            ),
            "username": [f"u{i}@contoso.com" for i in range(n)],
            "source_ip": ["203.0.113.7"] * n,
            "country": ["RU"] * n,
            "city": ["Moscow"] * n,
            "success": [False] * n,
        }
    )


def _alerts(event_ids, detector="password_spray", score=1.0) -> pd.DataFrame:
    technique = {
        "password_spray": "T1110.003",
        "brute_force": "T1110.001",
        "impossible_travel": "T1078",
    }[detector]
    return pd.DataFrame(
        [
            {
                "event_id": eid,
                "detector": detector,
                "score": score,
                "attack_technique": technique,
                "evidence": f"{detector} evidence",
            }
            for eid in event_ids
        ]
    )


def test_gate_boundaries_match_the_spec() -> None:
    assert classify(0.80) == "critical"
    assert classify(0.79) == "high"
    assert classify(0.60) == "high"
    assert classify(0.59) == "medium"
    assert classify(0.40) == "medium"
    assert classify(0.39) == "low"


def test_single_strong_rule_can_reach_an_actionable_tier() -> None:
    """The calibration constraint, as a test.

    With weights summing to 1 and no floor, one max-strength detector yields
    0.25 -- below the 0.40 gate. A textbook spray that no other detector sees
    would be suppressed entirely. The configured floor must prevent that.
    """
    events = _events()
    scored = fuse(events, _alerts(range(4)), None)
    assert scored["risk"].max() >= 0.40, (
        "a max-confidence single-detector incident must be escalatable"
    )


def test_tiers_are_reachable_under_the_shipped_config() -> None:
    """Critical must be attainable, or the top tier is decorative."""
    events = _events()
    alerts = pd.concat([
        _alerts(range(4), "password_spray"),
        _alerts(range(4), "brute_force"),
    ])
    anomaly = pd.DataFrame({"event_id": range(4), "anomaly": [1.0] * 4})
    scored = fuse(events, alerts, anomaly)
    assert scored["tier"].eq("critical").any()


def test_corroboration_raises_risk_above_a_lone_rule() -> None:
    events = _events()
    alerts = _alerts(range(4))
    alone = fuse(events, alerts, None)["risk"].max()
    with_model = fuse(
        events, alerts, pd.DataFrame({"event_id": range(4), "anomaly": [1.0] * 4})
    )["risk"].max()
    assert with_model > alone


def test_events_with_no_signal_score_zero() -> None:
    scored = fuse(_events(), pd.DataFrame(columns=[
        "event_id", "detector", "score", "attack_technique", "evidence"]), None)
    assert (scored["risk"] == 0).all()
    assert (scored["tier"] == "low").all()


def test_suppressed_excludes_zero_risk_and_escalated() -> None:
    """The audit log holds real-but-low signal, not every quiet event."""
    events = _events()
    anomaly = pd.DataFrame({"event_id": range(4), "anomaly": [0.0, 0.3, 0.5, 1.0]})
    scored = fuse(events, pd.DataFrame(columns=[
        "event_id", "detector", "score", "attack_technique", "evidence"]), anomaly)
    low = suppressed(scored)
    assert (low["risk"] > 0).all()
    assert (low["risk"] < load_config()["gate"]["medium"]).all()
    assert set(low["event_id"]).isdisjoint(set(escalatable(scored)["event_id"]))


def test_campaign_groups_related_events_into_one_incident() -> None:
    events = _events(6)
    scored = fuse(events, _alerts(range(6)), None)
    campaigns, membership = build_campaigns(scored, _alerts(range(6)))
    assert len(campaigns) == 1, "one source, one window, one technique -> one campaign"
    assert campaigns.iloc[0]["event_count"] == 6
    assert campaigns.iloc[0]["technique"] == "T1110.003"
    assert len(membership[campaigns.iloc[0]["campaign_id"]]) == 6


def test_rotating_source_stays_one_campaign() -> None:
    """IP rotation must not fragment one campaign into many.

    Correlation keys on the shared target set as well as the source, which is
    the stated answer to rotating-IP attackers.
    """
    events = _events(6)
    events.loc[3:, "source_ip"] = "203.0.113.8"
    events["username"] = ["a@x", "b@x", "c@x", "a@x", "b@x", "c@x"]
    alerts = _alerts(range(6))
    campaigns, _ = build_campaigns(fuse(events, alerts, None), alerts)
    assert len(campaigns) == 1
    assert len(campaigns.iloc[0]["source_ips"]) == 2


def test_distant_events_do_not_merge() -> None:
    events = _events(4)
    events.loc[2:, "timestamp"] = events.loc[2:, "timestamp"] + pd.Timedelta(hours=6)
    alerts = _alerts(range(4))
    campaigns, _ = build_campaigns(fuse(events, alerts, None), alerts)
    assert len(campaigns) == 2, "a 6-hour gap exceeds the correlation window"


@pytest.mark.parametrize("detector,technique", [
    ("password_spray", "T1110.003"),
    ("brute_force", "T1110.001"),
    ("impossible_travel", "T1078"),
])
def test_campaign_carries_the_right_attack_technique(detector, technique) -> None:
    events = _events(4)
    if detector == "impossible_travel":
        events["success"] = True
        events["username"] = "victim@contoso.com"
    alerts = _alerts(range(4), detector)
    campaigns, _ = build_campaigns(fuse(events, alerts, None), alerts)
    assert not campaigns.empty
    assert campaigns.iloc[0]["technique"] == technique
