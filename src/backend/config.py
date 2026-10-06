"""Loads configs/thresholds.yaml. Single source for every tunable value."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "configs" / "thresholds.yaml"
DATA_RAW = ROOT / "data" / "raw"
DATA_PROCESSED = ROOT / "data" / "processed"
MODELS = ROOT / "models"
DOCS = ROOT / "docs"

EVENTS_CSV = DATA_RAW / "auth_logs.csv"
GROUND_TRUTH_CSV = DATA_RAW / "ground_truth.csv"

# Canonical schema -- docs/data_spec.md. Ground-truth columns are deliberately
# absent: they live in a separate file so they cannot leak into features.
EVENT_COLUMNS = [
    "event_id",
    "timestamp",
    "username",
    "source_ip",
    "country",
    "city",
    "latitude",
    "longitude",
    "success",
    "device_id",
    "user_agent",
]

GROUND_TRUTH_COLUMNS = ["event_id", "attack_label", "attack_type", "scenario_id"]

TECHNIQUE_NAMES = {
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1078": "Valid Accounts",
}


@lru_cache(maxsize=1)
def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Read thresholds.yaml once and cache it."""
    target = Path(path) if path else CONFIG_PATH
    with open(target) as fh:
        return yaml.safe_load(fh)


def save_config(config: dict[str, Any], path: str | Path | None = None) -> None:
    """Write back a calibrated config and drop the cache."""
    target = Path(path) if path else CONFIG_PATH
    with open(target, "w") as fh:
        yaml.safe_dump(config, fh, sort_keys=False, default_flow_style=False)
    load_config.cache_clear()
