"""Detector tests built from the worked examples in docs/detection_spec.md.

Those four cases appear in the report submitted to judges, so they double as a
reconciliation check: if one fails, the code and the document disagree.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest

from src.backend.config import load_config
from src.backend.detection import (
    detect_brute_force,
    detect_impossible_travel,
    detect_password_spray,
)

START = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)
DELHI = (28.614, 77.209, "Delhi", "IN")
LONDON = (51.507, -0.128, "London", "GB")


def _event(event_id, ts, username, ip, success, place=DELHI, **kw):
    lat, lon, city, country = place
    return {
        "event_id": event_id, "timestamp": ts, "username": username,
        "source_ip": ip, "country": country, "city": city,
        "latitude": lat, "longitude": lon, "success": success,
        "device_id": kw.get("device_id", "dev-1"),
        "user_agent": kw.get("user_agent", "ua-1"),
    }


def _frame(rows: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df


# --------------------------------------------------------------- spray

def test_spray_worked_example_fires() -> None:
    """Report: 1 IP, 42 usernames, 2 failures each in 37 min -> S = 0.50."""
    rows = []
    eid = 0
    for user in range(42):
        for attempt in range(2):
            rows.append(_event(
                eid, START + timedelta(minutes=(user / 42) * 37, seconds=20 * attempt),
                f"user{user}@contoso.com", "203.0.113.7", False,
            ))
            eid += 1

    alerts = detect_password_spray(_frame(rows))
    assert not alerts.empty, "42 usernames at 2 attempts each must fire the spray rule"
    assert (alerts["attack_technique"] == "T1110.003").all()
    # The evidence sentence must carry the numbers that justify it.
    evidence = alerts.iloc[0]["evidence"]
    assert "42 distinct usernames" in evidence
    assert "SprayScore 0.50" in evidence


def test_brute_force_burst_does_not_fire_spray() -> None:
    """Report: 1 username, 1 IP, 12 failures in 5 min -> S = 0.083, spray silent.

    U = 1 fails the breadth condition, which is exactly what stops SprayScore
    from flagging depth attacks.
    """
    rows = [
        _event(i, START + timedelta(seconds=20 * i), "victim@contoso.com",
               "198.18.0.5", False)
        for i in range(12)
    ]
    assert detect_password_spray(_frame(rows)).empty


def test_single_failure_does_not_fire_spray() -> None:
    """One failed login gives U/A = 1.0, the maximum SprayScore.

    Without the breadth condition this would be the highest-scoring event in the
    dataset. It must stay silent.
    """
    rows = [_event(0, START, "someone@contoso.com", "10.0.0.5", False)]
    assert detect_password_spray(_frame(rows)).empty


def test_nat_breadth_with_deep_attempts_does_not_fire() -> None:
    """Many users on one IP, but each with many failures -> not a spray.

    A busy corporate egress IP has breadth. What it lacks is shallowness, so
    A/U > 3 must keep the rule quiet.
    """
    rows, eid = [], 0
    for user in range(30):
        for attempt in range(6):          # A/U = 6, well over the limit
            rows.append(_event(eid, START + timedelta(minutes=attempt),
                               f"staff{user}@contoso.com", "203.0.113.200", False))
            eid += 1
    assert detect_password_spray(_frame(rows)).empty


# --------------------------------------------------------- brute force

def test_brute_force_worked_example_fires() -> None:
    """Report: 12 failures in 5 min against one account, theta_b = 8."""
    rows = [
        _event(i, START + timedelta(seconds=20 * i), "victim@contoso.com",
               "198.18.0.5", False)
        for i in range(12)
    ]
    alerts = detect_brute_force(_frame(rows))
    assert not alerts.empty
    assert (alerts["attack_technique"] == "T1110.001").all()
    assert "victim@contoso.com" in alerts.iloc[0]["evidence"]


def test_brute_force_below_threshold_stays_quiet() -> None:
    theta = load_config()["brute_force"]["theta_b"]
    rows = [
        _event(i, START + timedelta(seconds=30 * i), "victim@contoso.com",
               "198.18.0.5", False)
        for i in range(theta)           # exactly at threshold, not above
    ]
    assert detect_brute_force(_frame(rows)).empty


def test_brute_force_spread_over_hours_stays_quiet() -> None:
    """Same failure count, spread wide enough that no 5-min window breaches."""
    rows = [
        _event(i, START + timedelta(minutes=30 * i), "victim@contoso.com",
               "198.18.0.5", False)
        for i in range(20)
    ]
    assert detect_brute_force(_frame(rows)).empty


# ------------------------------------------------------ impossible travel

def test_impossible_travel_worked_example_fires() -> None:
    """Report: Delhi -> London in 3 h = ~2237 km/h."""
    rows = [
        _event(0, START, "traveller@contoso.com", "10.0.0.1", True, DELHI),
        _event(1, START + timedelta(hours=3), "traveller@contoso.com",
               "198.51.100.9", True, LONDON),
    ]
    alerts = detect_impossible_travel(_frame(rows))
    assert len(alerts) == 2, "both ends of the pair are evidence"
    assert (alerts["attack_technique"] == "T1078").all()
    assert "2237 km/h" in alerts.iloc[0]["evidence"]


def test_legitimate_flight_does_not_fire() -> None:
    """Report: same city pair at 8.5 h = ~790 km/h, below the 1000 threshold."""
    rows = [
        _event(0, START, "traveller@contoso.com", "10.0.0.1", True, DELHI),
        _event(1, START + timedelta(hours=8.5), "traveller@contoso.com",
               "198.51.100.9", True, LONDON),
    ]
    assert detect_impossible_travel(_frame(rows)).empty


def test_failed_logins_never_fire_travel() -> None:
    """Travel reasons about successful sessions. A failure proves no access."""
    rows = [
        _event(0, START, "traveller@contoso.com", "10.0.0.1", False, DELHI),
        _event(1, START + timedelta(minutes=10), "traveller@contoso.com",
               "198.51.100.9", False, LONDON),
    ]
    assert detect_impossible_travel(_frame(rows)).empty


def test_identical_coordinates_are_skipped() -> None:
    """Two logins from one place, seconds apart, imply no travel at all."""
    rows = [
        _event(0, START, "user@contoso.com", "10.0.0.1", True, DELHI),
        _event(1, START + timedelta(seconds=5), "user@contoso.com",
               "10.0.0.2", True, DELHI),
    ]
    assert detect_impossible_travel(_frame(rows)).empty


@pytest.mark.parametrize("detector", [
    detect_brute_force, detect_password_spray, detect_impossible_travel,
])
def test_detectors_handle_empty_input(detector) -> None:
    empty = _frame([_event(0, START, "u@contoso.com", "10.0.0.1", True)]).iloc[0:0]
    result = detector(empty)
    assert result.empty
    assert list(result.columns) == [
        "event_id", "detector", "score", "attack_technique", "evidence",
    ]
