"""Isolation Forest anomaly layer. See docs/detection_spec.md section 7.2.

Contributes a graded component to fusion; never raises a standalone alert. The
raw score is not a probability of maliciousness, so it is rescaled against
training-window percentiles before it can be mixed with rule scores.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from src.backend.config import MODELS, load_config
from src.backend.features import FEATURE_COLUMNS, build_features

MODEL_PATH = MODELS / "isolation_forest.joblib"


class AnomalyScorer:
    """Fits on behavioural features and emits a [0,1] anomaly component.

    The percentile constants are learned at fit time and stored with the model.
    Rescaling with constants derived from the data being scored would make the
    output depend on how many attacks happen to be present.
    """

    def __init__(self, config: dict | None = None) -> None:
        cfg = (config or load_config())["isolation_forest"]
        self.forest = IsolationForest(
            n_estimators=cfg["n_estimators"],
            contamination=cfg["contamination"],
            random_state=cfg["random_state"],
            n_jobs=-1,
        )
        self.low_percentile = cfg["scale_low_percentile"]
        self.high_percentile = cfg["scale_high_percentile"]
        self.low_: float | None = None
        self.high_: float | None = None

    def fit(self, events: pd.DataFrame) -> "AnomalyScorer":
        features = build_features(events)[FEATURE_COLUMNS].to_numpy()
        self.forest.fit(features)
        raw = -self.forest.score_samples(features)
        self.low_ = float(np.percentile(raw, self.low_percentile))
        self.high_ = float(np.percentile(raw, self.high_percentile))
        return self

    def score(self, events: pd.DataFrame) -> pd.DataFrame:
        """Return event_id and a rescaled anomaly score in [0,1]."""
        if self.low_ is None or self.high_ is None:
            raise RuntimeError("AnomalyScorer.fit must run before score")

        frame = build_features(events)
        raw = -self.forest.score_samples(frame[FEATURE_COLUMNS].to_numpy())
        spread = max(self.high_ - self.low_, 1e-9)
        scaled = np.clip((raw - self.low_) / spread, 0.0, 1.0)
        return pd.DataFrame(
            {"event_id": frame["event_id"].to_numpy(), "anomaly": np.round(scaled, 4)}
        )

    def save(self, path: Path | None = None) -> Path:
        target = path or MODEL_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {"forest": self.forest, "low": self.low_, "high": self.high_}, target
        )
        return target

    @classmethod
    def load(cls, path: Path | None = None) -> "AnomalyScorer":
        payload = joblib.load(path or MODEL_PATH)
        scorer = cls()
        scorer.forest = payload["forest"]
        scorer.low_ = payload["low"]
        scorer.high_ = payload["high"]
        return scorer


def fit_and_score(events: pd.DataFrame, config: dict | None = None) -> pd.DataFrame:
    """Convenience path for the single-pass demo pipeline."""
    return AnomalyScorer(config).fit(events).score(events)
