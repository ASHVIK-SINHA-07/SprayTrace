# External Validation — LANL

The submitted report listed LANL, UNSW-NB15 and LogHub as data sources. Only
LANL was actually usable, and until now none had been ingested. This closes that
gap honestly.

## What we ran

**3,000,000 real authentication events** from the LANL *Comprehensive
Multi-Source Cyber-Security Events* dataset — 58 days of de-identified traffic
from Los Alamos National Laboratory's internal corporate network.

| | |
|---|---|
| Events | 3,000,000 |
| Failures | 20,036 |
| Distinct users | 14,290 |
| Distinct source computers | 5,820 |
| Span | 7.4 hours |

```bash
mkdir -p data/external
curl -s -r 0-400000000 https://lanl.ma.ic.ac.uk/data/cyber1/auth.txt.gz \
  | gunzip -c | head -3000000 > data/external/lanl_auth_sample.txt

python -m src.scripts.lanl_validate
```

## Result

| Detector | Alerts | % of events |
|---|---:|---:|
| Per-source spray | 994 | 0.0331% |
| **Distributed spray** | **0** | **0%** |

**The distributed detector fired zero times on three million events of real
enterprise traffic.** Its conditions — breadth across sources *and* shallowness
per source *and* shallowness per account — are what keep it quiet on benign
behaviour. The per-source rule, with only breadth and per-account shallowness,
fires on 0.03% of events.

## What this does and does not prove

**Does:** our detectors do not carpet-flag real enterprise authentication. A
detector that fired on 5% of a real network would be unusable regardless of its
synthetic recall, and we could not have known that from our own generator.

**Does not:** LANL's public release labels only red-team *lateral movement*, not
spraying. The 994 per-source alerts are therefore **unverified, not confirmed
false positives**. The most likely explanation is service accounts and
authentication servers legitimately touching many identities — which is the NAT
collision problem our report lists as risk #4, appearing in real data exactly as
predicted.

## Why only LANL

| Dataset | Carries what our detectors need? |
|---|---|
| **LANL auth** | ✅ user, source, success/failure, timestamps. ❌ no source IP, no geolocation, no spray labels |
| UNSW-NB15 | ❌ network flows — ports, protocols, packet counts. No usernames. Different domain. |
| LogHub OpenStack | ❌ infrastructure logs, not authentication events |

The travel detector **cannot run** on LANL — there is no geolocation — so it was
skipped rather than fed fabricated coordinates. The source computer is used as
the source key; it is not an IP and the adapter does not pretend otherwise.

This is also why the primary evaluation uses planted synthetic attacks: no
public dataset carries labelled password sprays with source IP, username and
geolocation together.

## For the panel

> "We also ran it against three million real authentication events from LANL —
> an actual enterprise network. Our distributed detector fired **zero** times.
> That tells us it doesn't carpet-flag benign traffic, which is something our
> own synthetic data could never have told us. The per-source rule fired on
> 0.03%, most likely service accounts touching many identities — the NAT
> collision case we flagged as a risk, showing up in real data exactly where we
> predicted."
