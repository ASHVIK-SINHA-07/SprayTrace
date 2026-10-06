# SprayTrace

Explainable attack reconstruction for authentication logs. Microsoft Innovate 2026,
Problem #22, Team MacroHard (ID 244), Bennett University.

Pipeline: auth logs -> normalize -> 3 rules + Isolation Forest -> weighted risk
fusion -> tier gate -> campaign reconstruction -> FastAPI -> React dashboard.

## Specs (read the relevant one instead of asking)

| File | Contents |
|---|---|
| `docs/detection_spec.md` | Thresholds, formulas, fusion weights, tiers. **Authoritative.** |
| `docs/data_spec.md` | Canonical schema, ground truth, planted scenarios, Entra mapping |
| `docs/eval_spec.md` | Split protocol, baseline, ablation, metrics |
| `docs/api_spec.md` | Endpoint contracts |
| `instructions.md` | Original build plan (superseded on detection by `detection_spec.md`) |

## Ground rules

- Thresholds in `docs/detection_spec.md` come from the report already submitted to
  judges. Do not silently change one; if a value looks wrong, flag it.
- Ground truth (`attack_label`, `attack_type`, `scenario_id`) lives in a separate
  file and is read **only** by `evaluate.py`. Never a model input, never a feature.
- Seeds are fixed at 42 (`random`, `numpy`, `IsolationForest`). Generation must be
  reproducible.
- No cloud dependency in the core path. Azure deploy is additive and optional.
- Every alert carries a MITRE ATT&CK ID and human-readable evidence text.

## Layout

```
src/backend/    normalize.py detection.py model.py fusion.py correlation.py main.py
src/scripts/    generate_data.py evaluate.py
src/frontend/   Vite + React + TypeScript
data/raw/       generated CSVs (immutable)
configs/        thresholds.yaml
```

## Commands

```bash
./run.sh                                  # generate -> analyze -> serve api + ui
python -m src.scripts.generate_data       # regenerate data/raw/auth_logs.csv
python -m src.scripts.evaluate            # fill docs/eval_results.md
pytest src/tests -q
```

## Conventions

- Python 3.13, pandas, scikit-learn. Frontend TypeScript, strict.
- Detector functions take a DataFrame, return a DataFrame of alerts with columns
  `event_id, detector, score, attack_technique, evidence`.
- Run `/code-review` on a feature branch before merging to `main`.
