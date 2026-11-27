"""Deterministic authentication detectors. Thresholds come from docs/detection_spec.md.

Every detector returns the same frame shape so fusion can treat them uniformly:
    event_id, detector, score, attack_technique, evidence

`evidence` is the analyst-facing sentence. It is built here, next to the numbers
that justify it, so the explanation can never drift from the detection.
"""

from __future__ import annotations

from collections import Counter
from heapq import heappop, heappush

import pandas as pd

from src.backend.config import load_config
from src.backend.geo import haversine_km, implied_speed_kmh

ALERT_COLUMNS = ["event_id", "detector", "score", "attack_technique", "evidence"]


def _empty() -> pd.DataFrame:
    return pd.DataFrame(columns=ALERT_COLUMNS)


def trailing_window_starts(timestamps: pd.DatetimeIndex, minutes: int):
    """Positions in trailing windows with an open left edge."""
    return timestamps.searchsorted(timestamps - pd.Timedelta(minutes=minutes), side="right")


def _best_windows(event_ids, windows):
    """Yield each event with the highest-ranked qualifying window covering it.

    Windows arrive in start order. Heap entries rank the supporting evidence
    and retain the window's inclusive end position.
    """
    pending = iter(windows)
    window = next(pending, None)
    active = []
    for position, event_id in enumerate(event_ids):
        while window is not None and window[0] <= position:
            start, end, rank, score, evidence = window
            heappush(active, (rank, start, end, score, evidence))
            window = next(pending, None)
        while active and active[0][2] < position:
            heappop(active)
        if active:
            _, _, _, score, evidence = active[0]
            yield int(event_id), score, evidence


def detect_brute_force(events: pd.DataFrame, config: dict | None = None) -> pd.DataFrame:
    """Grade each failure using its strongest breaching five-minute window."""
    cfg = (config or load_config())["brute_force"]
    minutes = cfg["window_minutes"]
    theta = cfg["theta_b"]
    technique = cfg["technique"]
    alerts = []

    failures = events[~events["success"]]
    for (username, source_ip), group in failures.groupby(["username", "source_ip"]):
        if len(group) <= theta:
            continue
        group = group.sort_values("timestamp", kind="stable")
        timestamps = pd.DatetimeIndex(group["timestamp"])
        starts = trailing_window_starts(timestamps, minutes)
        windows = []
        for end, start in enumerate(starts):
            count = end - start + 1
            if count <= theta:
                continue
            span = (timestamps[end] - timestamps[start]).total_seconds() / 60
            score = min(1.0, (count - theta) / max(theta, 1) + 0.5)
            evidence = (
                f"{count} failed sign-ins for {username} from {source_ip} within "
                f"{minutes} minutes (threshold {theta}; burst spanned "
                f"{span:.1f} min) — consistent with password guessing ({technique})."
            )
            windows.append((start, end, (-count,), score, evidence))

        for event_id, score, evidence in _best_windows(group["event_id"], windows):
            alerts.append({
                "event_id": event_id, "detector": "brute_force", "score": round(score, 4),
                "attack_technique": technique, "evidence": evidence,
            })

    return pd.DataFrame(alerts, columns=ALERT_COLUMNS)


def detect_password_spray(events: pd.DataFrame, config: dict | None = None) -> pd.DataFrame:
    """Score shallow, broad failure windows per source using SprayScore U/A."""
    cfg = (config or load_config())["password_spray"]
    window = pd.Timedelta(minutes=cfg["window_minutes"])
    theta_u = cfg["theta_u"]
    max_per_user = cfg["max_attempts_per_user"]
    technique = cfg["technique"]
    alerts = []

    failures = events[~events["success"]]
    for source_ip, group in failures.groupby("source_ip"):
        if len(group) <= theta_u:
            continue
        group = group.sort_values("timestamp", kind="stable")
        timestamps = pd.DatetimeIndex(group["timestamp"])
        usernames = group["username"].tolist()
        ends = timestamps.searchsorted(timestamps + window, side="left")
        counts: Counter[str] = Counter()
        left = right = 0
        windows = []
        for start, end in enumerate(ends):
            # A window with the same end as its predecessor is contained in
            # that predecessor. Including the full window keeps the shallowness
            # check meaningful when users retry throughout the hour.
            if end == right:
                continue
            while right < end:
                counts[usernames[right]] += 1
                right += 1
            while left < start:
                username = usernames[left]
                counts[username] -= 1
                if counts[username] == 0:
                    del counts[username]
                left += 1

            distinct_users = len(counts)
            attempts = end - start
            if distinct_users <= theta_u or attempts / distinct_users > max_per_user:
                continue

            score = distinct_users / attempts
            span = (timestamps[end - 1] - timestamps[start]).total_seconds() / 60
            evidence = (
                f"{attempts} failed attempts across {distinct_users} distinct "
                f"usernames ({attempts / distinct_users:.1f} per account, "
                f"SprayScore {score:.2f}) from {source_ip} within "
                f"{span:.0f} minutes — consistent with password spraying ({technique})."
            )
            # Prefer the widest supporting evidence, then the fuller window.
            windows.append((start, end - 1, (-distinct_users, -attempts), score, evidence))

        for event_id, score, evidence in _best_windows(group["event_id"], windows):
            alerts.append({
                "event_id": event_id, "detector": "password_spray", "score": round(score, 4),
                "attack_technique": technique, "evidence": evidence,
            })

    return pd.DataFrame(alerts, columns=ALERT_COLUMNS)


def detect_distributed_spray(
    events: pd.DataFrame, config: dict | None = None
) -> pd.DataFrame:
    """Spray that is quiet from every single source but broad in aggregate.

    The per-source rule above groups by source_ip, so a pool of addresses
    splits one campaign's target set below theta_u and nothing fires -- the
    same per-source blind spot a naive IP counter has. A rotating pool of 24
    addresses hitting 60 accounts leaves ~2 accounts per IP.

    What survives distribution is the shape of the *window*: an unusual number
    of distinct accounts failing in one period, each only once or twice, from
    sources that are mostly unfamiliar. That is a property of the time window
    rather than of any address, so this detector groups by window alone and
    then requires the failures to be shallow and spread across many sources.

    ATT&CK T1110.003, same technique seen through a different statistic.
    """
    cfg_all = config or load_config()
    cfg = cfg_all["password_spray"]
    dist = cfg_all.get("distributed_spray", {})
    window = cfg["window_minutes"]
    min_users = dist.get("min_users", 25)
    min_sources = dist.get("min_sources", 8)
    max_per_user = dist.get("max_attempts_per_user", 3)
    max_per_source = dist.get("max_attempts_per_source", 12)

    failures = events[~events["success"]]
    if failures.empty:
        return _empty()

    indexed = failures.sort_values("timestamp").set_index("timestamp")
    alerts: list[dict] = []
    seen: set[int] = set()

    for offset in ("0min", f"{window // 2}min"):
        for _, bucket in indexed.groupby(
            pd.Grouper(freq=f"{window}min", offset=offset)
        ):
            if bucket.empty:
                continue
            distinct_users = bucket["username"].nunique()
            distinct_sources = bucket["source_ip"].nunique()
            attempts = len(bucket)

            if distinct_users < min_users or distinct_sources < min_sources:
                continue
            if attempts / distinct_users > max_per_user:
                continue
            # Each source must be individually unremarkable; otherwise the
            # per-source rule already covers it and this would double-report
            # ordinary noisy traffic.
            if attempts / distinct_sources > max_per_source:
                continue

            spray_score = distinct_users / attempts
            span = (bucket.index.max() - bucket.index.min()).total_seconds() / 60
            score = min(1.0, 0.55 + 0.45 * min(1.0, distinct_sources / (min_sources * 2)))
            evidence = (
                f"{attempts} failed attempts across {distinct_users} distinct "
                f"usernames from {distinct_sources} source addresses "
                f"({attempts / distinct_users:.1f} per account, "
                f"{attempts / distinct_sources:.1f} per source, SprayScore "
                f"{spray_score:.2f}) within {span:.0f} minutes — distributed "
                f"password spraying: no single source exceeds a per-IP "
                f"threshold (T1110.003)."
            )
            for event_id in bucket["event_id"]:
                if int(event_id) in seen:
                    continue
                seen.add(int(event_id))
                alerts.append(
                    {
                        "event_id": int(event_id),
                        "detector": "distributed_spray",
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
            coordinates = (
                previous["latitude"], previous["longitude"],
                current["latitude"], current["longitude"],
            )
            bounds = (90, 180, 90, 180)
            if any(pd.isna(value) or not -limit <= value <= limit
                   for value, limit in zip(coordinates, bounds)):
                continue
            hours = (current["timestamp"] - previous["timestamp"]).total_seconds() / 3600
            distance = haversine_km(*coordinates)
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
    """Run all deterministic detectors over one frame."""
    cfg = config or load_config()
    frames = [
        detect_brute_force(events, cfg),
        detect_password_spray(events, cfg),
        detect_distributed_spray(events, cfg),
        detect_impossible_travel(events, cfg),
    ]
    frames = [f for f in frames if not f.empty]
    if not frames:
        return _empty()
    return pd.concat(frames, ignore_index=True)
