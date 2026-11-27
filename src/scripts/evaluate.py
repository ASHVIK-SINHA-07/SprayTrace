"""Measure SprayTrace honestly. Protocol in docs/eval_spec.md.

Split by whole scenario -> grid search on validation -> freeze -> report once on
held-out test. Writes docs/eval_results.md and docs/eval_results.json.
Use --freeze to adopt the validation recommendation before running the test.

Run: python -m src.scripts.evaluate
"""

from __future__ import annotations

import argparse
import json
import random
from collections.abc import Iterable
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from itertools import product

import pandas as pd

from src.backend.baseline import naive_threshold_alerts
from src.backend.config import (
    DOCS,
    EVENTS_CSV,
    GROUND_TRUTH_CSV,
    load_config,
    save_config,
)
from src.backend.correlation import build_campaigns
from src.backend.detection import (
    ALERT_COLUMNS,
    detect_brute_force,
    detect_distributed_spray,
    detect_impossible_travel,
    detect_password_spray,
)
from src.backend.fusion import fuse
from src.backend.model import AnomalyScorer
from src.backend.normalize import read_events

SEED = 42
SPLITS = {"train": 0.4, "validation": 0.3, "test": 0.3}


@dataclass
class Scores:
    name: str
    precision: float
    recall: float
    f1: float
    alerts: int
    true_positives: int
    false_positives: int
    false_negatives: int
    alert_to_tp: float | None
    noise_reduction: float | None = None


def score(flagged: set[int], truth: pd.DataFrame, name: str) -> Scores:
    labels = truth.set_index("event_id")["attack_label"]
    positives = set(labels[labels].index)

    tp = len(flagged & positives)
    fp = len(flagged - positives)
    fn = len(positives - flagged)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return Scores(
        name=name,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
        alerts=len(flagged),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        alert_to_tp=round(len(flagged) / tp, 2) if tp else None,
    )


def split_by_scenario(truth: pd.DataFrame) -> dict[str, set[str]]:
    """Partition whole scenarios, never individual events.

    Every event sharing a scenario_id lands in one split, so no campaign is
    half-seen during tuning and half-scored at test. Splitting by event would
    leak a campaign's shape across the boundary and inflate every number.
    """
    scenarios = sorted(truth["scenario_id"].unique())
    attack_scenarios = sorted(
        truth[truth["attack_label"]]["scenario_id"].unique()
    )
    benign_scenarios = [s for s in scenarios if s not in set(attack_scenarios)]

    rng = random.Random(SEED)
    rng.shuffle(attack_scenarios)
    rng.shuffle(benign_scenarios)

    assigned: dict[str, set[str]] = {k: set() for k in SPLITS}

    # Stratify: each split needs attack scenarios of its own, or precision and
    # recall are undefined there.
    for pool in (attack_scenarios, benign_scenarios):
        cursor = 0
        for name, fraction in SPLITS.items():
            take = round(len(pool) * fraction)
            if name == "test":
                take = len(pool) - cursor
            assigned[name].update(pool[cursor:cursor + take])
            cursor += take

    return assigned


def events_for(
    events: pd.DataFrame, truth: pd.DataFrame, scenarios: set[str]
) -> tuple[pd.DataFrame, pd.DataFrame]:
    ids = truth[truth["scenario_id"].isin(scenarios)]["event_id"]
    subset = events[events["event_id"].isin(ids)].copy()
    subset_truth = truth[truth["event_id"].isin(ids)].copy()
    return subset, subset_truth


def detector_alerts(events: pd.DataFrame, config: dict) -> dict[str, pd.DataFrame]:
    return {
        "brute_force": detect_brute_force(events, config),
        "password_spray": detect_password_spray(events, config),
        "distributed_spray": detect_distributed_spray(events, config),
        "impossible_travel": detect_impossible_travel(events, config),
    }


def flagged_from(scored: pd.DataFrame, gate: float) -> set[int]:
    return set(scored[scored["risk"] >= gate]["event_id"].astype(int))


def combine_alerts(frames: Iterable[pd.DataFrame]) -> pd.DataFrame:
    nonempty = [frame for frame in frames if not frame.empty]
    return pd.concat(nonempty, ignore_index=True) if nonempty else pd.DataFrame(columns=ALERT_COLUMNS)


def grid_search(
    training: pd.DataFrame, validation: pd.DataFrame, truth: pd.DataFrame, base: dict
) -> tuple[dict, dict, list[dict]]:
    """Select operating-policy candidates on validation with train-fitted models."""
    candidates_b = [5, 8, 12]
    candidates_u = [12, 15, 18]
    base_weights = base["fusion"]["weights"]
    weight_options = [
        base_weights,
        {"brute_force": 0.20, "password_spray": 0.25, "distributed_spray": 0.25,
         "impossible_travel": 0.15, "isolation_forest": 0.15},
        {"brute_force": 0.25, "password_spray": 0.15, "distributed_spray": 0.20,
         "impossible_travel": 0.25, "isolation_forest": 0.15},
        {"brute_force": 0.45, "password_spray": 0.10, "distributed_spray": 0.25,
         "impossible_travel": 0.10, "isolation_forest": 0.10},
        {"brute_force": 0.20, "password_spray": 0.45, "distributed_spray": 0.15,
         "impossible_travel": 0.10, "isolation_forest": 0.10},
        {"brute_force": 0.20, "password_spray": 0.10, "distributed_spray": 0.45,
         "impossible_travel": 0.15, "isolation_forest": 0.10},
        {"brute_force": 0.20, "password_spray": 0.10, "distributed_spray": 0.15,
         "impossible_travel": 0.45, "isolation_forest": 0.10},
    ]
    floor_options = [
        base["fusion"].get("rule_floor"),
        {"brute_force": 0.50, "password_spray": 0.50,
         "distributed_spray": 0.50, "impossible_travel": 0.42},
        {"brute_force": 0.60, "password_spray": 0.60,
         "distributed_spray": 0.55, "impossible_travel": 0.45},
    ]
    fusion_options = [(base_weights, floors) for floors in floor_options if floors is not None]
    fusion_options += [(weights, None) for weights in weight_options]

    config = deepcopy(base)
    brute = {}
    for theta in candidates_b:
        config["brute_force"]["theta_b"] = theta
        brute[theta] = detect_brute_force(validation, config)
    spray = {}
    for theta in candidates_u:
        config["password_spray"]["theta_u"] = theta
        spray[theta] = detect_password_spray(validation, config)
    distributed = detect_distributed_spray(validation, base)
    travel = detect_impossible_travel(validation, base)

    anomaly_by_contamination = {}
    for contamination in (0.01, 0.02):
        config["isolation_forest"]["contamination"] = contamination
        anomaly_by_contamination[contamination] = AnomalyScorer(config).fit(training).score(validation)

    gate = base["gate"]["medium"]
    medium_options = sorted({round(gate - 0.05, 2), gate, round(gate + 0.05, 2)})
    positives = set(truth.loc[truth["attack_label"], "event_id"])
    trace = []
    best = best_weighted = None
    for theta_b, theta_u in product(candidates_b, candidates_u):
        alerts = combine_alerts((brute[theta_b], spray[theta_u], distributed, travel))
        for (weights, floors), (contamination, anomaly) in product(
            fusion_options, anomaly_by_contamination.items()
        ):
            config["brute_force"]["theta_b"] = theta_b
            config["password_spray"]["theta_u"] = theta_u
            config["fusion"] = {"weights": weights, "rule_floor": floors}
            config["isolation_forest"]["contamination"] = contamination
            scored = fuse(validation, alerts, anomaly, config)
            for medium in medium_options:
                flagged = flagged_from(scored, medium)
                tp = len(flagged & positives)
                fn = len(positives) - tp
                f1 = 2 * tp / (len(flagged) + len(positives)) if flagged or positives else 0.0
                trace.append({
                    "theta_b": theta_b, "theta_u": theta_u, "weights": weights,
                    "floors": floors, "contamination": contamination,
                    "medium_gate": medium, "f1": round(f1, 4), "false_negatives": fn,
                })

                # The other gates are sensitivity checks. Select for the
                # submitted operating policy, which stays fixed on adoption.
                if medium != gate:
                    continue
                rank = (f1, -fn)
                if best is None or rank > best[0]:
                    best = (rank, deepcopy(config))
                if floors is None and (best_weighted is None or rank > best_weighted[0]):
                    best_weighted = (rank, deepcopy(config))

    assert best is not None and best_weighted is not None
    return best[1], best_weighted[1], trace


def ablation(
    events: pd.DataFrame, truth: pd.DataFrame, config: dict, scorer: AnomalyScorer
) -> tuple[list[Scores], pd.DataFrame, pd.DataFrame]:
    """Configurations A-F on identical data, features and labels."""
    alerts = detector_alerts(events, config)
    anomaly = scorer.score(events)
    gate = config["gate"]["medium"]
    empty = combine_alerts(())

    results: list[Scores] = []

    baseline_flagged = naive_threshold_alerts(events)
    results.append(score(baseline_flagged, truth, "Naive threshold baseline"))

    singles = [
        ("A · Brute force only", ["brute_force"]),
        ("B · Per-source spray only", ["password_spray"]),
        ("B2 · Distributed spray only", ["distributed_spray"]),
        ("C · Travel only", ["impossible_travel"]),
    ]
    for label, names in singles:
        subset = combine_alerts(alerts[n] for n in names)
        scored = fuse(events, subset, None, config)
        results.append(score(flagged_from(scored, gate), truth, label))

    # D: model alone. No rule fires, so the floor never applies and the raw
    # weighted anomaly decides -- which is the honest way to show what the ML
    # layer contributes by itself.
    model_only = fuse(events, empty, anomaly, config)
    results.append(score(flagged_from(model_only, gate), truth, "D · Isolation Forest only"))

    rules = combine_alerts(alerts.values())
    rules_only = fuse(events, rules, None, config)
    results.append(score(flagged_from(rules_only, gate), truth, "E · Rules only"))

    full = fuse(events, rules, anomaly, config)
    results.append(score(flagged_from(full, gate), truth, "F · Full fusion"))

    baseline_alerts = len(baseline_flagged)
    if baseline_alerts:
        results[-1].noise_reduction = round(
            (baseline_alerts - results[-1].alerts) / baseline_alerts * 100, 1
        )

    return results, full, rules


def per_type_recall(truth: pd.DataFrame, flagged: set[int]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    attacks = truth[truth["attack_label"]]
    for attack_type, group in attacks.groupby("attack_type"):
        matched = group[group["event_id"].isin(flagged)]
        out[str(attack_type)] = {
            "detected": len(matched),
            "total": len(group),
            "recall": round(len(matched) / len(group), 4),
            "scenarios_detected": int(matched["scenario_id"].nunique()),
            "scenarios_total": int(group["scenario_id"].nunique()),
        }
    return out


def config_summary(config: dict) -> dict:
    return {
        "theta_b": config["brute_force"]["theta_b"],
        "theta_u": config["password_spray"]["theta_u"],
        "weights": config["fusion"]["weights"],
        "rule_floor": config["fusion"].get("rule_floor"),
        "contamination": config["isolation_forest"]["contamination"],
        "gate": config["gate"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate SprayTrace")
    parser.add_argument("--freeze", action="store_true",
                        help="write the tuned config back to configs/thresholds.yaml")
    args = parser.parse_args(argv)

    events = read_events(EVENTS_CSV)
    truth = pd.read_csv(GROUND_TRUTH_CSV)
    base = load_config()

    if not truth["event_id"].is_unique or set(truth["event_id"]) != set(events["event_id"]):
        raise ValueError("The canonical events and ground truth must have matching unique event IDs.")

    splits = split_by_scenario(truth)
    print("scenarios per split:", {k: len(v) for k, v in splits.items()})

    validation_events, validation_truth = events_for(events, truth, splits["validation"])
    test_events, test_truth = events_for(events, truth, splits["test"])
    train_events, _ = events_for(events, truth, splits["train"])

    print(f"\ntuning on validation ({len(validation_events):,} events)…")
    recommended, weighted_config, trace = grid_search(
        train_events, validation_events, validation_truth, base
    )
    frozen = recommended if args.freeze else base
    if args.freeze:
        frozen["calibrated"] = True
        frozen["version"] = int(base.get("version", 0)) + 1
        save_config(frozen)
        print("froze validation-selected configuration to configs/thresholds.yaml")

    scorer = AnomalyScorer(frozen).fit(train_events)
    print(f"\nreporting on held-out test ({len(test_events):,} events)…")
    results, scored, rules = ablation(test_events, test_truth, frozen, scorer)
    by_type = per_type_recall(test_truth, flagged_from(scored, frozen["gate"]["medium"]))

    campaigns, _ = build_campaigns(scored, rules, frozen)
    weighted_rules = combine_alerts(detector_alerts(test_events, weighted_config).values())
    weighted_scorer = AnomalyScorer(weighted_config).fit(train_events)
    weighted_scored = fuse(
        test_events, weighted_rules, weighted_scorer.score(test_events), weighted_config
    )
    results.append(score(
        flagged_from(weighted_scored, weighted_config["gate"]["medium"]),
        test_truth, "G · Tuned weighted fusion without rule floors",
    ))

    sensitivity = []
    gates = frozen["gate"]
    for gate in sorted({row["medium_gate"] for row in trace} | {gates["high"], gates["critical"]}):
        flagged = flagged_from(scored, gate)
        row = score(flagged, test_truth, f"{gate:.2f}")
        baseline_alerts = results[0].alerts
        sensitivity.append({
            "gate": gate, "alerts": row.alerts, "false_negatives": row.false_negatives,
            "alert_reduction": round((baseline_alerts - row.alerts) / baseline_alerts * 100, 1)
            if baseline_alerts else None,
        })

    baseline_alerts = results[0].alerts
    payload = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "calibrated": bool(frozen.get("calibrated")),
        "protocol": (
            "whole-scenario split, train-fitted models, validation-only calibration, held-out test"
        ),
        "splits": {k: {"scenarios": len(v)} for k, v in splits.items()},
        "test_events": int(len(test_events)),
        "frozen_config": config_summary(frozen),
        "validation_recommendation": config_summary(recommended),
        "weighted_ablation_config": config_summary(weighted_config),
        "configurations": [asdict(r) for r in results],
        "per_attack_type": by_type,
        "gate_sensitivity": sensitivity,
        "reduction": {
            "raw_events": int(len(test_events)),
            "escalatable": int((scored["risk"] >= gates["medium"]).sum()),
            "campaigns": int(len(campaigns)),
            "baseline_event_alerts": baseline_alerts,
        },
        "grid_search_points": len(trace),
    }

    DOCS.mkdir(exist_ok=True)
    (DOCS / "eval_results.json").write_text(json.dumps(payload, indent=2))
    (DOCS / "eval_results.md").write_text(render_markdown(payload))

    print_summary(payload)
    return 0


def print_summary(payload: dict) -> None:
    width = max(len(row["name"]) for row in payload["configurations"])
    separator = "─" * (width + 43)
    print("\n" + separator)
    print(f"{'configuration':<{width}} {'P':>7} {'R':>7} {'F1':>7} {'alerts':>8} {'alert Δ':>9}")
    print(separator)
    for row in payload["configurations"]:
        noise = f"{row['noise_reduction']}%" if row["noise_reduction"] is not None else "—"
        print(
            f"{row['name']:<{width}} {row['precision']:>7.3f} {row['recall']:>7.3f} "
            f"{row['f1']:>7.3f} {row['alerts']:>8} {noise:>9}"
        )
    print(separator)
    reduction = payload["reduction"]
    print(
        f"\n{reduction['raw_events']:,} test events → "
        f"{reduction['escalatable']} escalatable → {reduction['campaigns']} campaigns"
    )
    print("\nrecall by attack type:")
    for name, stats in payload["per_attack_type"].items():
        print(f"  {name:<20} {stats['detected']:>4}/{stats['total']:<4} = {stats['recall']:.3f}")


def render_markdown(payload: dict) -> str:
    lines = [
        "# Evaluation Results",
        "",
        f"Generated {payload['generated']}. Protocol: {payload['protocol']}.",
        "",
        "Full fusion uses the operating configuration in `configs/thresholds.yaml`.",
        "The validation recommendation is written to that file only with `--freeze`.",
        "",
    ]
    for title, key in (
        ("Operating configuration", "frozen_config"),
        ("Validation recommendation", "validation_recommendation"),
        ("Weighted-only ablation configuration", "weighted_ablation_config"),
    ):
        lines.extend([f"## {title}", "", "```"])
        lines.extend(f"{name:<14} {value}" for name, value in payload[key].items())
        lines.extend(["```", ""])

    lines.extend([
        f"Validation evaluated {payload['grid_search_points']} combinations including gate cutoffs.",
        "",
        "## Held-out ablation",
        "",
        "| Configuration | Precision | Recall | F1 | Alerts | FP | FN | Alert-to-TP | Event-alert reduction |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for row in payload["configurations"]:
        reduction = row["noise_reduction"]
        reduction_text = f"{reduction:+.1f}%" if reduction is not None else "—"
        ratio = row["alert_to_tp"] if row["alert_to_tp"] is not None else "—"
        lines.append(
            f"| {row['name']} | {row['precision']:.3f} | {row['recall']:.3f} | "
            f"{row['f1']:.3f} | {row['alerts']} | {row['false_positives']} | "
            f"{row['false_negatives']} | {ratio} | {reduction_text} |"
        )

    lines.extend([
        "",
        "## Recall by attack type",
        "",
        "A scenario is detected when at least one labeled attack event crosses the gate.",
        "",
        "| Attack type | Events detected | Events labeled | Event recall | Scenarios detected |",
        "|---|---:|---:|---:|---:|",
    ])
    for name, stats in payload["per_attack_type"].items():
        lines.append(
            f"| {name} | {stats['detected']} | {stats['total']} | {stats['recall']:.3f} | "
            f"{stats['scenarios_detected']}/{stats['scenarios_total']} |"
        )

    reduction = payload["reduction"]
    lines.extend([
        "",
        "## Event and campaign counts",
        "",
        f"**{reduction['raw_events']:,} test events → {reduction['escalatable']} "
        f"escalatable events → {reduction['campaigns']} campaigns.**",
        "",
        f"The baseline flags {reduction['baseline_event_alerts']} events. Event-alert reduction "
        "uses event counts for both systems. The campaign count describes how SprayTrace "
        "groups its escalations for review.",
        "",
        "## Gate sensitivity",
        "",
        "| Risk cutoff | Event alerts | False negatives | Event-alert reduction vs baseline |",
        "|---|---:|---:|---:|",
    ])
    for row in payload["gate_sensitivity"]:
        reduction = row["alert_reduction"]
        reduction_text = f"{reduction:+.1f}%" if reduction is not None else "—"
        lines.append(
            f"| {row['gate']:.2f} | {row['alerts']} | {row['false_negatives']} | {reduction_text} |"
        )

    lines.extend([
        "",
        "## Measurement notes",
        "",
        "- The Isolation Forest is fitted on train for both validation and test.",
        "  Contamination changes the prediction offset. The scores used in fusion",
        "  are derived from `score_samples`, which is independent of that offset.",
        "- A benign sign-in adjacent to a planted impossible-travel pair may also",
        "  imply impossible speed and count as an event-level false positive.",
        "- These measurements describe the generated scenarios and labels.",
    ])
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
