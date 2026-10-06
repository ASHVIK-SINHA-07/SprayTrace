# Security

SprayTrace is a local analysis tool for a hackathon MVP. This file states what
it does and does not do, so nobody mistakes the demo for a production control.

## What it handles

Authentication **event metadata** only: timestamp, username, source IP,
geolocation, success flag, device id, user agent.

It never handles passwords. There is no field for one, no parser for one, and
nothing in the pipeline reads credential material. A spray is detected from the
*shape* of failures across accounts, never from what was tried.

## Input validation

- Uploads are parsed as data. Fields are coerced to their declared types and
  never evaluated, formatted into a query, or executed.
- Rows missing a timestamp, username or source IP are **quarantined** rather
  than guessed at — a fabricated timestamp would corrupt every rolling window
  it touches.
- An unknown `success` value is treated as a failure, not a success. The safe
  direction is the one that cannot silently hide an attack.
- Unrecognised CSV shapes are rejected with HTTP 400 rather than coerced.
- The username filter runs as a literal substring, not a regular expression, so
  user input cannot build a pattern.

## What is deliberately absent

| Missing | Why |
|---|---|
| Authentication on the API | Local single-user demo. A production deployment needs auth before anything else. |
| Transport encryption | Binds `127.0.0.1`. Nothing leaves the machine. |
| Multi-tenant isolation | One analysis in memory at a time. |
| Rate limiting | No untrusted network exposure. |
| Persistent storage | Results live in memory; `data/raw` is immutable input. |

**If this were deployed anywhere reachable**, all five become required, starting
with authentication. `/api/analyze` and `/api/inject` mutate shared state and
are unauthenticated by design for the demo.

## Ground truth isolation

Attack labels (`attack_label`, `attack_type`, `scenario_id`) live in a separate
file from the events. Only `evaluate.py` reads them. Feature engineering cannot
reach them by accident, and a test asserts they never appear in the event file.

This is a structural guarantee rather than a discipline: the leak that would
invalidate every metric is made hard to write, not merely discouraged.

## Dependencies

Pinned exactly in `requirements.txt` and `package.json`. No external API calls
at runtime — geolocation coordinates are assigned at generation, so there is no
GeoIP service, no key, and no outbound request from the detection path.

## Demo-only endpoints

`POST /api/inject` plants a synthetic spray to demonstrate live detection. It
appends to the in-memory frame only; `data/raw` is never written. It exists for
the demo and would not ship in a real deployment.

## Reporting

This is student coursework for Microsoft Innovate 2026, not a maintained
product. Issues: <https://github.com/ashviksinha/SprayTrace/issues>.
