"""Per-event behavioural features for the Isolation Forest.

Features are the ones named in docs/detection_spec.md. Ground truth is never
read here -- the labels live in a separate file precisely so this module cannot
reach them by accident.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

FEATURE_COLUMNS = [
    "failed_last_hour",
    "distinct_ips_last_hour",
    "distinct_countries_last_day",
    "hour_sin",
    "hour_cos",
    "device_change",
]


def build_features(events: pd.DataFrame) -> pd.DataFrame:
    """One feature row per event, aligned on event_id.

    Rolling counts are computed per user and are strictly backward-looking: an
    event may use its own history but never its future, so the frame cannot leak
    information a live detector would not have.
    """
    df = events.sort_values("timestamp").copy()

    hours = df["timestamp"].dt.hour + df["timestamp"].dt.minute / 60.0
    df["hour_sin"] = np.sin(2 * np.pi * hours / 24)
    df["hour_cos"] = np.cos(2 * np.pi * hours / 24)

    parts: list[pd.DataFrame] = []
    for _, group in df.groupby("username", sort=False):
        group = group.sort_values("timestamp").set_index("timestamp")

        failed = (~group["success"]).astype(float)
        group["failed_last_hour"] = failed.rolling("1h").sum()

        # nunique is unavailable on a rolling window, so count distinct values
        # over each trailing span directly.
        group["distinct_ips_last_hour"] = _rolling_nunique(group, "source_ip", "1h")
        group["distinct_countries_last_day"] = _rolling_nunique(group, "country", "24h")

        # First sighting of a device/user-agent pair for this user. Attack
        # tooling shows up as a change; so does a new laptop, which is why this
        # is a feature and not a rule.
        signature = group["device_id"].astype(str) + "|" + group["user_agent"].astype(str)
        group["device_change"] = (~signature.duplicated()).astype(float)
        group.loc[signature.index[:1], "device_change"] = 0.0

        parts.append(group.reset_index())

    out = pd.concat(parts, ignore_index=True).sort_values("event_id")
    out[FEATURE_COLUMNS] = out[FEATURE_COLUMNS].fillna(0.0)
    return out[["event_id", *FEATURE_COLUMNS]].reset_index(drop=True)


def _rolling_nunique(group: pd.DataFrame, column: str, window: str) -> pd.Series:
    """Distinct values of `column` within each trailing time window."""
    codes = group[column].astype("category").cat.codes
    timestamps = group.index
    span = pd.Timedelta(window)
    counts = np.empty(len(group), dtype=float)
    start = 0
    seen: dict[int, int] = {}
    for end in range(len(group)):
        code = int(codes.iloc[end])
        seen[code] = seen.get(code, 0) + 1
        while timestamps[end] - timestamps[start] > span:
            old = int(codes.iloc[start])
            seen[old] -= 1
            if seen[old] == 0:
                del seen[old]
            start += 1
        counts[end] = len(seen)
    return pd.Series(counts, index=group.index)
