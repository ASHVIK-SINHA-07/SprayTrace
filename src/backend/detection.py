"""The three deterministic detectors. Thresholds come from docs/detection_spec.md.

Every detector returns the same frame shape so fusion can treat them uniformly:
    event_id, detector, score, attack_technique, evidence

`evidence` is the analyst-facing sentence. It is built here, next to the numbers
that justify it, so the explanation can never drift from the detection.
"""

from __future__ import annotations

import pandas as pd

from src.backend.config import load_config
from src.backend.geo import haversine_km, implied_speed_kmh

ALERT_COLUMNS = ["event_id", "detector", "score", "attack_technique", "evidence"]


def _empty() -> pd.DataFrame:
    return pd.DataFrame(columns=ALERT_COLUMNS)


def detect_brute_force(events: pd.DataFrame, config: dict | None = None) -> pd.DataFrame:
    """Many failures against ONE account from one source in a short window.

    Grouped by (username, source_ip) over a 5-minute rolling window, B > theta_b.
    ATT&CK T1110.001.
    """
    cfg = (config or load_config())["brute_force"]
    window = f"{cfg['window_minutes']}min"
    theta = cfg["theta_b"]

    failures = events[~events["success"]]
    if failures.empty:
        return _empty()

    alerts: list[dict] = []
    for (username, source_ip), group in failures.groupby(["username", "source_ip"]):
        group = group.sort_values("timestamp")
        indexed = group.set_index("timestamp")
        # Rolling count of failures in the trailing window, evaluated at each event.
        counts = indexed["event_id"].rolling(window).count()
        if counts.max() <= theta:
            continue

        peak = int(counts.max())
        span = (group["timestamp"].max() - group["timestamp"].min()).total_seconds() / 60
        # Grade by margin over threshold so a 20-failure burst outranks a 9.
        score = min(1.0, (peak - theta) / max(theta, 1) + 0.5)
        evidence = (
            f"{peak} failed sign-ins for {username} from {source_ip} within "
            f"{cfg['window_minutes']} minutes (threshold {theta}; burst spanned "
            f"{span:.1f} min) — consistent with password guessing (T1110.001)."
        )
        # Flag only the events inside the window that breached, not the whole group.
        breaching = counts[counts > theta].index
        if len(breaching):
            window_start = breaching.min() - pd.Timedelta(minutes=cfg["window_minutes"])
            member_ids = indexed.loc[window_start:breaching.max(), "event_id"]
        else:
            member_ids = group["event_id"]
        for event_id in member_ids:
            alerts.append(
                {
                    "event_id": int(event_id),
                    "detector": "brute_force",
                    "score": round(score, 4),
                    "attack_technique": "T1110.001",
                    "evidence": evidence,
                }
            )

    return pd.DataFrame(alerts, columns=ALERT_COLUMNS)


def detect_password_spray(events: pd.DataFrame, config: dict | None = None) -> pd.DataFrame:
    """Few attempts against MANY accounts from one source.

    Grouped by source_ip over a 1-hour window. Fires on breadth (U > theta_u)
    AND shallowness (A/U <= max_attempts_per_user). SprayScore S = U/A grades it.
    ATT&CK T1110.003.

    The breadth condition is load-bearing: a single failed login gives U/A = 1,
    the maximum SprayScore, so S alone would flag every lone typo.
    """
    cfg = (config or load_config())["password_spray"]
    window = cfg["window_minutes"]
    theta_u = cfg["theta_u"]
    max_per_user = cfg["max_attempts_per_user"]

    failures = events[~events["success"]]
    if failures.empty:
        return _empty()

    alerts: list[dict] = []
    for source_ip, group in failures.groupby("source_ip"):
        group = group.sort_values("timestamp")
        indexed = group.set_index("timestamp")

        # Tumbling hourly bins, then the same bins offset by half a window, so a
        # campaign straddling a bin boundary is not split below the threshold.
        offsets = ["0min", f"{window // 2}min"]
        seen: set[int] = set()
        for offset in offsets:
            binned = indexed.groupby(pd.Grouper(freq=f"{window}min", offset=offset))
            for bin_start, bucket in binned:
                if bucket.empty:
                    continue
                distinct_users = bucket["username"].nunique()
                attempts = len(bucket)
                if distinct_users <= theta_u:
                    continue
                if attempts / distinct_users > max_per_user:
                    continue

                spray_score = distinct_users / attempts
                span = (
                    bucket.index.max() - bucket.index.min()
                ).total_seconds() / 60
                # Breadth beyond the threshold drives confidence; cap at 1.0.
                score = min(1.0, 0.6 + 0.4 * min(1.0, (distinct_users - theta_u) / theta_u))
                evidence = (
                    f"{attempts} failed attempts across {distinct_users} distinct "
                    f"usernames ({attempts / distinct_users:.1f} per account, "
                    f"SprayScore {spray_score:.2f}) from {source_ip} within "
                    f"{span:.0f} minutes — consistent with password spraying "
                    f"(T1110.003)."
                )
                for event_id in bucket["event_id"]:
                    if int(event_id) in seen:
                        continue
                    seen.add(int(event_id))
                    alerts.append(
                        {
                            "event_id": int(event_id),
                            "detector": "password_spray",
                            "score": round(score, 4),
                            "attack_technique": "T1110.003",
                            "evidence": evidence,
                        }
                    )

    return pd.DataFrame(alerts, columns=ALERT_COLUMNS)


def detect_impossible_travel(
    events: pd.DataFrame, config: dict | None = None
) -> pd.DataFrame:
    """Consecutive successful logins implying a speed no aircraft achieves.

    Per user, successes sorted by time, each consecutive pair checked.
    ATT&CK T1078 -- this is credential reuse from a new geography, not travel.
    """
    cfg = (config or load_config())["impossible_travel"]
    limit = cfg["max_speed_kmh"]

    successes = events[events["success"]]
    if successes.empty:
        return _empty()

    alerts: list[dict] = []
    for username, group in successes.groupby("username"):
        group = group.sort_values("timestamp")
        if len(group) < 2:
            continue
        rows = group.to_dict("records")
        for previous, current in zip(rows, rows[1:]):
            if pd.isna(previous["latitude"]) or pd.isna(current["latitude"]):
                continue
            hours = (current["timestamp"] - previous["timestamp"]).total_seconds() / 3600
            distance = haversine_km(
                previous["latitude"], previous["longitude"],
                current["latitude"], current["longitude"],
            )
            speed = implied_speed_kmh(distance, hours)
            if speed is None or speed <= limit:
                continue

            score = min(1.0, 0.7 + 0.3 * min(1.0, (speed - limit) / (limit * 2)))
            evidence = (
                f"{username} signed in from {previous['city']}, {previous['country']} "
                f"then {current['city']}, {current['country']} "
                f"{hours:.1f} h later — {distance:.0f} km apart, implying "
                f"{speed:.0f} km/h (threshold {limit}) — consistent with use of "
                f"valid credentials from a new location (T1078)."
            )
            # Both ends are evidence: the earlier login establishes the anomaly.
            for event in (previous, current):
                alerts.append(
                    {
                        "event_id": int(event["event_id"]),
                        "detector": "impossible_travel",
                        "score": round(score, 4),
                        "attack_technique": "T1078",
                        "evidence": evidence,
                    }
                )

    return pd.DataFrame(alerts, columns=ALERT_COLUMNS)


def run_rules(events: pd.DataFrame, config: dict | None = None) -> pd.DataFrame:
    """All three detectors over one frame."""
    cfg = config or load_config()
    frames = [
        detect_brute_force(events, cfg),
        detect_password_spray(events, cfg),
        detect_impossible_travel(events, cfg),
    ]
    frames = [f for f in frames if not f.empty]
    if not frames:
        return _empty()
    return pd.concat(frames, ignore_index=True)
