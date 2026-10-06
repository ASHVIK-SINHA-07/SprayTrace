"""In-memory analysis store.

Single-user demo, so the current analysis lives in a module-level slot rather
than a database. docs/data_spec.md keeps the schema honest regardless, and
swapping this for SQLite later touches nothing outside this file.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pandas as pd

from src.backend.config import EVENTS_CSV
from src.backend.pipeline import Analysis, analyze

_lock = threading.Lock()
_current: Analysis | None = None


def get_analysis() -> Analysis:
    """Current analysis, running the default dataset on first access."""
    global _current
    with _lock:
        if _current is None:
            _current = analyze(EVENTS_CSV)
        return _current


def set_analysis(analysis: Analysis) -> Analysis:
    global _current
    with _lock:
        _current = analysis
        return _current


def reanalyze(source: str | Path | pd.DataFrame) -> Analysis:
    return set_analysis(analyze(source))


def reset() -> None:
    global _current
    with _lock:
        _current = None
