# Data Spec

## Canonical event schema (10 fields)

| Field | Type | Role |
|---|---|---|
| `timestamp` | datetime (UTC) | window membership, Δt for travel speed, hour encoding |
| `username` | string | grouping key |
| `source_ip` | string | grouping key: `(username, source_ip)` brute, `source_ip` spray |
| `country` | string | distinct-country feature |
| `city` | string | display |
| `latitude` | float | haversine |
| `longitude` | float | haversine |
| `success` | bool | failures feed B and S; successes feed T |
| `device_id` | string | device-change flag, NAT disambiguation |
| `user_agent` | string | device-change flag, NAT disambiguation |

Coordinates are assigned at generation, so **no GeoIP API is needed**.

## Ground truth — separate file

`data/raw/ground_truth.csv`: `event_id`, `attack_label` (bool), `attack_type`
(enum), `scenario_id` (string).

Read **only** by `src/scripts/evaluate.py`. Never joined into the feature frame,
never a model input. Keeping it in a separate file makes that leak structurally
hard rather than a matter of discipline.

## Generation

Deterministic: `random.seed(42)`, `numpy.random.seed(42)`. Faker for usernames,
devices and user agents. Target ~10,000 events.

### Planted scenarios

| Scenario | Construction | Label |
|---|---|---|
| Brute force | one username, one source IP, burst of failures inside 5 min | `1 · brute_force` |
| Password spray | one source IP, many usernames, 1–3 failures each inside 1 h | `1 · password_spray` |
| Slow spray | same, throttled across many hours | `1 · password_spray` |
| Rotating-IP spray | same target set, IP pool rotating per batch | `1 · password_spray` |
| Impossible travel | consecutive successes, implied speed > 1000 km/h | `1 · impossible_travel` |

### Hard negatives — these decide whether the demo is credible

| Scenario | Construction | Label |
|---|---|---|
| Corporate NAT | many legitimate users, one shared office IP, ordinary failure rate | `0 · benign` |
| Legitimate flight | consecutive successes implying <= ~900 km/h | `0 · benign` |
| Typo-driven failures | 1–3 failures then a success, same user, same IP | `0 · benign` |
| VPN egress change | same user, abrupt country change, plausible timing | `0 · benign` |

Without these, precision is meaningless — every detector scores 1.00 on data that
contains only attacks and quiet noise.

### Background traffic

~100 users, each with a home office location, a few logins per day, occasional
ordinary failures, working-hours bias with weekend dip.

## Splits

By **complete scenario**: every event sharing a `scenario_id` lands in one split.
Prevents leakage of a campaign across train/validation/test.

## Entra SigninLogs import

Accept a CSV exported in Entra sign-in log shape and map to canonical:

| Entra column | Canonical |
|---|---|
| `TimeGenerated` / `createdDateTime` | `timestamp` |
| `UserPrincipalName` | `username` |
| `IPAddress` | `source_ip` |
| `LocationDetails.countryOrRegion` / `Location` | `country` |
| `LocationDetails.city` | `city` |
| `LocationDetails.geoCoordinates.latitude` / `longitude` | `latitude` / `longitude` |
| `ResultType` | `success` (`"0"` -> True; `50126` = bad credentials -> False) |
| `DeviceDetail.deviceId` | `device_id` |
| `UserAgent` | `user_agent` |

`ResultType` is a string in exports. `"0"` is success; everything else is a
failure, with `50126` the credential failure that spray generates.

Detection must be identical for both sources — the reader normalizes, nothing
downstream knows which format arrived.
