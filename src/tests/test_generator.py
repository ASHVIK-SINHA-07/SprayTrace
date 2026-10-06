"""Generated data must keep the properties the detectors are tuned against.

These are data-contract tests, not detector tests. If a generator change makes
legitimate travel exceed 1000 km/h, every precision number downstream becomes
meaningless -- so that gets caught here rather than in the evaluation.
"""

from __future__ import annotations

import pandas as pd
import pytest

from src.backend.config import EVENTS_CSV, GROUND_TRUTH_CSV, load_config
from src.backend.geo import haversine_km, implied_speed_kmh

pytestmark = pytest.mark.skipif(
    not EVENTS_CSV.exists(), reason="run: python -m src.scripts.generate_data"
)


@pytest.fixture(scope="module")
def merged() -> pd.DataFrame:
    events = pd.read_csv(EVENTS_CSV)
    truth = pd.read_csv(GROUND_TRUTH_CSV)
    df = events.merge(truth, on="event_id")
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601", utc=True)
    return df


def _max_speed(df: pd.DataFrame, prefix: str) -> float:
    speeds: list[float] = []
    subset = df[df["scenario_id"].str.startswith(prefix)]
    for _, group in subset.groupby("scenario_id"):
        group = group[group["success"]].sort_values("timestamp")
        for i in range(1, len(group)):
            a, b = group.iloc[i - 1], group.iloc[i]
            hours = (b["timestamp"] - a["timestamp"]).total_seconds() / 3600
            km = haversine_km(a["latitude"], a["longitude"], b["latitude"], b["longitude"])
            speed = implied_speed_kmh(km, hours)
            if speed is not None:
                speeds.append(speed)
    return max(speeds) if speeds else 0.0


def test_schema_and_integrity(merged: pd.DataFrame) -> None:
    assert merged["event_id"].is_unique
    assert merged[["timestamp", "username", "source_ip", "success"]].notna().all().all()
    assert merged["timestamp"].is_monotonic_increasing


def test_volume_supports_the_headline_claim(merged: pd.DataFrame) -> None:
    """The report and slides both promise ~10,000 events."""
    assert len(merged) >= 10_000


def test_legitimate_travel_stays_below_threshold(merged: pd.DataFrame) -> None:
    """Hard negative: real flights must not be flagged (commercial ~900 km/h)."""
    limit = load_config()["impossible_travel"]["max_speed_kmh"]
    assert _max_speed(merged, "legit_travel") < limit
    assert _max_speed(merged, "vpn_egress") < limit


def test_attack_travel_exceeds_threshold(merged: pd.DataFrame) -> None:
    limit = load_config()["impossible_travel"]["max_speed_kmh"]
    assert _max_speed(merged, "travel_") > limit


def test_spray_scenarios_satisfy_breadth_and_depth(merged: pd.DataFrame) -> None:
    cfg = load_config()["password_spray"]
    for scenario in ("spray_fast", "spray_slow", "spray_rotating"):
        failures = merged[(merged["scenario_id"] == scenario) & (~merged["success"])]
        distinct_users = failures["username"].nunique()
        attempts = len(failures)
        assert distinct_users > cfg["theta_u"], scenario
        assert attempts / distinct_users <= cfg["max_attempts_per_user"], scenario


def test_nat_hard_negative_never_satisfies_spray_rule(merged: pd.DataFrame) -> None:
    """Many legitimate users behind one office IP must not look like a spray.

    This is the report's risk #4 (NAT collision) expressed as a test.
    """
    cfg = load_config()["password_spray"]
    failures = merged[(merged["scenario_id"] == "nat_benign") & (~merged["success"])]
    windows = (
        failures.set_index("timestamp")
        .groupby(pd.Grouper(freq=f"{cfg['window_minutes']}min"))
        .agg(users=("username", "nunique"), attempts=("username", "size"))
    )
    windows = windows[windows["users"] > 0]
    fired = windows[
        (windows["users"] > cfg["theta_u"])
        & (windows["attempts"] / windows["users"] <= cfg["max_attempts_per_user"])
    ]
    assert fired.empty, f"NAT traffic would fire the spray rule in {len(fired)} window(s)"


def test_ground_truth_is_not_in_the_event_file() -> None:
    """Labels must stay out of the feature path -- enforced structurally."""
    columns = pd.read_csv(EVENTS_CSV, nrows=0).columns
    for leaked in ("attack_label", "attack_type", "scenario_id"):
        assert leaked not in columns
