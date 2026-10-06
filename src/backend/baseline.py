"""Naive threshold baseline -- the "basic SIEM threshold" alternative.

Alerts when failures per user, or per IP, exceed a fixed count in a window. This
is what most shops actually run, and it is the reference for the noise-reduction
claim. Keeping it honest matters: a strawman baseline makes the comparison
worthless, so the thresholds here are tuned on validation data exactly as
SprayTrace's are.
"""

from __future__ import annotations

import pandas as pd

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

    window = f"{window_minutes}min"
    flagged: set[int] = set()

    for key, threshold in (("username", per_user), ("source_ip", per_ip)):
        for _, group in failures.groupby(key):
            indexed = group.sort_values("timestamp").set_index("timestamp")
            counts = indexed["event_id"].rolling(window).count()
            breaching = counts[counts > threshold]
            if breaching.empty:
                continue
            start = breaching.index.min() - pd.Timedelta(minutes=window_minutes)
            flagged.update(
                int(e) for e in indexed.loc[start:breaching.index.max(), "event_id"]
            )

    return flagged
