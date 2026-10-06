"""Risk fusion and the decision gate. See docs/detection_spec.md sections 5-6.

R = w1*B + w2*S + w3*T + w4*I, with sum(w) = 1.

The calibration constraint is the subtle part: because the weights sum to 1, a
single detector can only push R past 0.40 if its own weight exceeds 0.40. Equal
weights (0.25 each) would therefore suppress every incident that only one rule
catches -- including a textbook spray that no other detector sees. The optional
rule_floor exists for exactly that case and is evaluated as an ablation.
"""

from __future__ import annotations

import pandas as pd

from src.backend.config import load_config

DETECTORS = ["brute_force", "password_spray", "impossible_travel"]
TIERS = ["critical", "high", "medium", "low"]


def fuse(
    events: pd.DataFrame,
    alerts: pd.DataFrame,
    anomaly: pd.DataFrame | None = None,
    config: dict | None = None,
) -> pd.DataFrame:
    """Combine rule and anomaly signals into one risk score per event."""
    cfg = config or load_config()
    weights = cfg["fusion"]["weights"]
    rule_floor = cfg["fusion"].get("rule_floor")

    scored = events[["event_id", "timestamp", "username", "source_ip", "country",
                     "city", "success"]].copy()

    # Highest score per detector per event: an event caught twice by the same
    # rule is not more suspicious than once.
    for detector in DETECTORS:
        subset = alerts[alerts["detector"] == detector]
        column = subset.groupby("event_id")["score"].max() if not subset.empty else None
        scored[detector] = (
            scored["event_id"].map(column).fillna(0.0) if column is not None else 0.0
        )

    if anomaly is not None and not anomaly.empty:
        scored["isolation_forest"] = (
            scored["event_id"].map(anomaly.set_index("event_id")["anomaly"]).fillna(0.0)
        )
    else:
        scored["isolation_forest"] = 0.0

    weighted = sum(scored[name] * float(weights[name]) for name in weights)

    if rule_floor is None:
        scored["risk"] = weighted.round(4)
    else:
        # Detector-specific floors. A plain scalar floor clamps every fired rule
        # to the same value, collapsing the tier system into one band -- the
        # weighted sum cannot lift it because sum(w)=1 divides each component
        # below the gate spacing.
        #
        # Instead each rule's own confidence sets the entry point, and the
        # remaining headroom is earned: anomaly agreement and a second detector
        # each add evidence. A lone moderate rule stays Medium; a strong rule
        # corroborated by the model reaches High or Critical.
        floors = (
            rule_floor
            if isinstance(rule_floor, dict)
            else {name: float(rule_floor) for name in DETECTORS}
        )
        entry = pd.Series(0.0, index=scored.index)
        for name in DETECTORS:
            base = float(floors.get(name, 0.0))
            entry = entry.combine(scored[name] * base, max)

        headroom = 1.0 - entry
        corroboration = (
            0.6 * scored["isolation_forest"]
            + 0.4 * (scored[DETECTORS].gt(0).sum(axis=1) > 1).astype(float)
        ).clip(0.0, 1.0)

        fired = scored[DETECTORS].max(axis=1) > 0
        scored["risk"] = weighted.where(
            ~fired, (entry + headroom * corroboration).clip(upper=1.0)
        ).round(4)

    scored["tier"] = scored["risk"].map(lambda r: classify(r, cfg))
    scored["detectors"] = [
        [name for name in DETECTORS + ["isolation_forest"] if row[name] > 0]
        for _, row in scored.iterrows()
    ]
    return scored


def classify(risk: float, config: dict | None = None) -> str:
    gate = (config or load_config())["gate"]
    if risk >= gate["critical"]:
        return "critical"
    if risk >= gate["high"]:
        return "high"
    if risk >= gate["medium"]:
        return "medium"
    return "low"


def escalatable(scored: pd.DataFrame, config: dict | None = None) -> pd.DataFrame:
    """Events at or above the medium gate -- what reaches an analyst."""
    gate = (config or load_config())["gate"]
    return scored[scored["risk"] >= gate["medium"]]


def suppressed(scored: pd.DataFrame, config: dict | None = None) -> pd.DataFrame:
    """Below-gate events. Retained for the audit log, never shown as alerts.

    The report promises these are "retained in an audit log for retrospective
    hunting". Keeping them queryable is what makes that a control rather than a
    claim -- and it is where a missed low-score campaign would be found.
    """
    gate = (config or load_config())["gate"]
    return scored[(scored["risk"] > 0) & (scored["risk"] < gate["medium"])]
