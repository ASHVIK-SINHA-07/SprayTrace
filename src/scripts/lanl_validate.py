"""Run the detectors against real LANL enterprise authentication data.

The submitted report listed LANL as a data source but never ingested it. This
closes that gap honestly: LANL carries no source IP and no geolocation, so the
travel detector cannot run, and the public release has no spray labels. What it
*can* answer is the question synthetic data cannot --

    on 3 million events of real enterprise authentication traffic, how often do
    our spray detectors fire on behaviour that is not an attack?

That is a false-positive measurement on real data, which is worth more than
another recall number on our own generator.

Schema: time,src_user@domain,dst_user@domain,src_computer,dst_computer,
        auth_type,logon_type,auth_orientation,success/fail

Mapping to canonical: src_computer -> source_ip (it is the origin identity in
this dataset), src_user -> username. Geolocation is absent, so travel is
skipped rather than fabricated.

Fetch the data first (7.3 GB full file; a streamed head is enough):
    curl -s -r 0-400000000 https://lanl.ma.ic.ac.uk/data/cyber1/auth.txt.gz \\
      | gunzip -c | head -3000000 > data/external/lanl_auth_sample.txt

Run: python -m src.scripts.lanl_validate
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from src.backend.config import ROOT, load_config
from src.backend.detection import detect_distributed_spray, detect_password_spray

LANL_COLUMNS = [
    "time", "src_user", "dst_user", "src_comp", "dst_comp",
    "auth_type", "logon_type", "orientation", "outcome",
]
DEFAULT_PATH = ROOT / "data" / "external" / "lanl_auth_sample.txt"
# LANL timestamps are seconds from an arbitrary epoch; any fixed base works
# because every detector reasons about relative windows.
EPOCH = pd.Timestamp("2026-01-01", tz="UTC")


def load_lanl(path: Path, limit: int | None = None) -> pd.DataFrame:
    """Read LANL auth events into the canonical schema."""
    df = pd.read_csv(path, names=LANL_COLUMNS, nrows=limit)

    out = pd.DataFrame({
        "event_id": range(len(df)),
        "timestamp": EPOCH + pd.to_timedelta(df["time"], unit="s"),
        "username": df["src_user"],
        # The source computer is the origin identity here. It is not an IP, and
        # we do not pretend otherwise -- the spray statistic only needs a stable
        # source key.
        "source_ip": df["src_comp"],
        "country": "unknown",
        "city": "unknown",
        "latitude": pd.NA,
        "longitude": pd.NA,
        "success": df["outcome"].eq("Success"),
        "device_id": df["dst_comp"],
        "user_agent": df["auth_type"].fillna("unknown"),
    })
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate against real LANL data")
    parser.add_argument("path", nargs="?", default=str(DEFAULT_PATH))
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args(argv)

    path = Path(args.path)
    if not path.exists():
        print(f"Not found: {path}\n\nFetch it with:\n"
              "  mkdir -p data/external && curl -s -r 0-400000000 \\\n"
              "    https://lanl.ma.ic.ac.uk/data/cyber1/auth.txt.gz \\\n"
              "    | gunzip -c | head -3000000 > data/external/lanl_auth_sample.txt")
        return 1

    events = load_lanl(path, args.limit)
    failures = events[~events["success"]]
    span_hours = (
        events["timestamp"].max() - events["timestamp"].min()
    ).total_seconds() / 3600

    print(f"LANL real enterprise authentication data")
    print(f"  events            {len(events):,}")
    print(f"  failures          {len(failures):,}")
    print(f"  distinct users    {events['username'].nunique():,}")
    print(f"  distinct sources  {events['source_ip'].nunique():,}")
    print(f"  span              {span_hours:.1f} h")

    config = load_config()
    print("\nrunning spray detectors (travel skipped: LANL has no geolocation)…")

    per_source = detect_password_spray(events, config)
    distributed = detect_distributed_spray(events, config)

    print("\n" + "─" * 66)
    print(f"{'detector':<28} {'alerts':>8} {'events flagged':>16}")
    print("─" * 66)
    print(f"{'per-source spray':<28} {len(per_source):>8} "
          f"{per_source['event_id'].nunique() if not per_source.empty else 0:>16}")
    print(f"{'distributed spray':<28} {len(distributed):>8} "
          f"{distributed['event_id'].nunique() if not distributed.empty else 0:>16}")
    print("─" * 66)

    rate = (
        per_source["event_id"].nunique() / len(events) * 100
        if not per_source.empty else 0.0
    )
    print(f"\nper-source spray flags {rate:.4f}% of all events")

    if not per_source.empty:
        print("\nwhat the per-source rule fired on (first 3):")
        for evidence in per_source["evidence"].drop_duplicates().head(3):
            print(f"  · {evidence[:110]}")
        print("\nThese have no attack label. LANL's public release labels only")
        print("red-team lateral movement, not spraying, so they are unverified")
        print("rather than confirmed false positives -- most likely service")
        print("accounts or authentication servers touching many identities.")

    if distributed.empty:
        print("\nThe distributed detector fired ZERO times on this data.")
        print("Its extra conditions -- breadth across sources AND shallowness per")
        print("source AND per account -- are what keep it quiet on benign traffic.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
