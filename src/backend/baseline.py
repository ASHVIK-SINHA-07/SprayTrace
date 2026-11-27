"""Naive threshold baseline -- the "basic SIEM threshold" alternative.

Alerts when failures per user, or per IP, exceed a fixed count in a window. This
is the reference for the event-alert comparison.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from src.backend.detection import trailing_window_starts

DEFAULT_PER_USER = 5
DEFAULT_PER_IP = 20
WINDOW_MINUTES = 60


def naive_threshold_alerts(
    events: pd.DataFrame,
    per_user: int = DEFAULT_PER_USER,
    per_ip: int = DEFAULT_PER_IP,
    window_minutes: int = WINDOW_MINUTES,
) -> set[int]:
    """Event ids a per-user or per-IP failure counter would flag."""
    failures = events[~events["success"]]
    if failures.empty:
        return set()

    flagged: set[int] = set()

    for key, threshold in (("username", per_user), ("source_ip", per_ip)):
        for _, group in failures.groupby(key):
            if len(group) <= threshold:
                continue
            group = group.sort_values("timestamp", kind="stable")
            starts = trailing_window_starts(pd.DatetimeIndex(group["timestamp"]), window_minutes)
            ends = np.flatnonzero(np.arange(len(group)) - starts + 1 > threshold)
            coverage = np.zeros(len(group) + 1, dtype=int)
            np.add.at(coverage, starts[ends], 1)
            coverage[ends + 1] -= 1
            flagged.update(group.loc[coverage.cumsum()[:-1] > 0, "event_id"].astype(int))

    return flagged
